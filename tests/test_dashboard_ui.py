from __future__ import annotations

import re
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient

from rtsp_proxy.app import create_app
from rtsp_proxy.config import RuntimeRole, Settings
from rtsp_proxy.database import PostgresNodeStore
from rtsp_proxy.identifiers import PublicId
from rtsp_proxy.media import MediaPathConfig
from rtsp_proxy.nodes import (
    CameraCatalogItem,
    CameraCatalogPage,
    CameraCatalogQuery,
    CameraCatalogUnavailable,
    CameraControl,
    CameraMove,
    CameraMoveState,
    CameraState,
    InMemoryNodeStore,
    MaximumNodesReached,
    MediaNode,
    NodeCommandFence,
    NodeControl,
    NodeHealth,
    NodeManagementPortRangeExhausted,
    NodeMutationContext,
    NodePortInUse,
    NodePortOutOfRange,
    NodePortRangeExhausted,
    NodeRuntimeAction,
    NodeRuntimeFailed,
    NodeRuntimeObservation,
    NodeState,
    PlacementMode,
)
from rtsp_proxy.observability import (
    FleetSnapshot,
    InMemoryObservabilityStore,
    NodeMetricSample,
    NodeScrapeStatus,
    NodeSnapshot,
    SnapshotReader,
)
from rtsp_proxy.operator_access import (
    InMemoryOperatorSessionStore,
    OperatorAccount,
    OperatorIdentitySource,
    OperatorRole,
    OperatorSessionControl,
)
from rtsp_proxy.reconcile import (
    CameraMoveControl,
    CameraMovePreview,
    CameraMoveTarget,
    CameraMutationControl,
    CameraMutationOperation,
    CameraMutationPreview,
    CameraRuntimeObservation,
    ConfirmationTokenService,
)

NOW = datetime(2026, 8, 14, 12, 0, tzinfo=UTC)
ACCOUNT_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
NODE_ID = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
CREATED_NODE_ID = UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
CAMERA_ID = UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
CSRF_TOKEN = "c" * 43
IDEMPOTENCY_KEY = "11111111-1111-4111-8111-111111111111"


class RecordingNodeDashboardControl:
    def __init__(self, *, create_error: Exception | None = None) -> None:
        self.node = MediaNode(
            id=NODE_ID,
            name="edge-north",
            external_port=10543,
            state=NodeState.STOPPED,
            runtime_state=NodeState.STOPPED,
            health=NodeHealth.UNKNOWN,
            desired_revision=7,
            applied_revision=7,
        )
        self.created_node = MediaNode(
            id=CREATED_NODE_ID,
            name="edge-created",
            external_port=10544,
            state=(
                NodeState.FAILED
                if isinstance(create_error, NodeRuntimeFailed)
                else NodeState.PROVISIONING
            ),
            runtime_state=(
                NodeState.FAILED
                if isinstance(create_error, NodeRuntimeFailed)
                else NodeState.PROVISIONING
            ),
            health=(
                NodeHealth.UNHEALTHY
                if isinstance(create_error, NodeRuntimeFailed)
                else NodeHealth.UNKNOWN
            ),
        )
        self.create_error = create_error
        self.calls: list[tuple[str, object]] = []

    def list_nodes(self) -> tuple[MediaNode, ...]:
        return (self.node, self.created_node)

    def register_node(self, **kwargs: object) -> MediaNode:
        self.calls.append(("register", kwargs))
        if self.create_error is not None:
            raise self.create_error
        return self.created_node

    def start_node(
        self,
        node_id: UUID,
        *,
        fence: NodeCommandFence,
        mutation_context: NodeMutationContext,
    ) -> MediaNode:
        self.calls.append(("start", (node_id, fence, mutation_context)))
        return replace(
            self.node,
            state=NodeState.RUNNING,
            runtime_state=NodeState.RUNNING,
        )

    def stop_node(
        self,
        node_id: UUID,
        *,
        fence: NodeCommandFence,
        mutation_context: NodeMutationContext,
    ) -> MediaNode:
        self.calls.append(("stop", (node_id, fence, mutation_context)))
        return self.node

    def set_administrative_state(
        self,
        node_id: UUID,
        state: NodeState,
        *,
        fence: NodeCommandFence,
        mutation_context: NodeMutationContext,
    ) -> MediaNode:
        self.calls.append(
            ("administrative", (node_id, state, fence, mutation_context))
        )
        return replace(self.node, state=state, maintenance=state is NodeState.MAINTENANCE)

    def delete_node(
        self,
        node_id: UUID,
        *,
        fence: NodeCommandFence,
        mutation_context: NodeMutationContext,
    ) -> None:
        self.calls.append(("delete", (node_id, fence, mutation_context)))


class StaticCameraCatalog:
    def __init__(self) -> None:
        self.last_query: CameraCatalogQuery | None = None
        self.source_url = "rtsp://admin:secret@camera.internal/private"
        self.enabled_calls: list[tuple[UUID, bool]] = []

    def catalog(self, query: CameraCatalogQuery) -> CameraCatalogPage:
        self.last_query = query
        item = self.detail(CAMERA_ID)
        assert item is not None
        return CameraCatalogPage(items=(item,), next_after=item.id)

    def detail(self, camera_id: UUID) -> CameraCatalogItem | None:
        if camera_id != CAMERA_ID:
            return None
        return CameraCatalogItem(
            id=CAMERA_ID,
            name="Front <script>alert(1)</script>",
            public_id=PublicId.parse("a" * 25 + "a"),
            node_id=NODE_ID,
            node_name="edge <north>",
            node_port=10543,
            placement_mode=PlacementMode.AUTOMATIC,
            state=CameraState.ENABLED,
            desired_revision=3,
            applied_revision=2,
        )

    def set_camera_enabled(
        self,
        camera_id: UUID,
        *,
        enabled: bool,
        expected_revision: int | None = None,
    ) -> None:
        assert expected_revision == 3
        self.enabled_calls.append((camera_id, enabled))


class FailingCameraCatalog:
    def catalog(self, _query: CameraCatalogQuery) -> CameraCatalogPage:
        raise CameraCatalogUnavailable("postgres password must not escape")

    def detail(self, _camera_id: UUID) -> CameraCatalogItem | None:
        raise CameraCatalogUnavailable("postgres password must not escape")


class RecordingCameraMutations:
    def __init__(self, *, occupied: bool) -> None:
        self.occupied = occupied
        self.calls: list[tuple[object, ...]] = []

    def preview(
        self,
        camera_id: UUID,
        *,
        operation: CameraMutationOperation,
        expected_revision: int | None = None,
        name: str | None = None,
        source_url: str | None = None,
    ) -> CameraMutationPreview:
        self.calls.append(
            ("preview", camera_id, operation, expected_revision, name, source_url)
        )
        return CameraMutationPreview(
            camera_id=camera_id,
            operation=operation,
            desired_revision=3,
            occupied=self.occupied,
            disconnect_readers=1 if self.occupied else 0,
            mutation_sha256="d" * 64,
            confirmation_token="confirmation-token" if self.occupied else None,
        )

    def update(
        self,
        camera_id: UUID,
        *,
        name: str,
        source_url: str,
        expected_revision: int | None = None,
        confirmation_token: str | None,
    ) -> None:
        self.calls.append(
            (
                "update",
                camera_id,
                name,
                source_url,
                expected_revision,
                confirmation_token,
            )
        )

    def disable(
        self,
        camera_id: UUID,
        *,
        expected_revision: int | None = None,
        confirmation_token: str | None,
    ) -> None:
        self.calls.append(("disable", camera_id, expected_revision, confirmation_token))

    def delete(
        self,
        camera_id: UUID,
        *,
        expected_revision: int | None = None,
        confirmation_token: str | None,
    ) -> None:
        self.calls.append(("delete", camera_id, expected_revision, confirmation_token))


class RecordingCameraMoves:
    def __init__(self, *, occupied: bool) -> None:
        self.occupied = occupied
        self.calls: list[tuple[object, ...]] = []
        self.target = CameraMoveTarget(
            id=UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd"),
            name="edge <south>",
            external_port=10544,
            registered_cameras=10,
            camera_capacity=100,
        )
        self.move = CameraMove(
            id=UUID("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"),
            camera_id=CAMERA_ID,
            public_id=PublicId.parse("a" * 26),
            source_url="rtsp://camera.internal/main",
            source_node_id=NODE_ID,
            target_node_id=self.target.id,
            source_generation=1,
            target_generation=2,
            desired_revision=4,
            force=occupied,
            confirmed_disconnect_readers=1 if occupied else 0,
            source_port=10543,
            target_port=10544,
            source_endpoint="rtsp://server:10543/" + "a" * 26,
            target_endpoint="rtsp://server:10544/" + "a" * 26,
            expires_at=NOW + timedelta(minutes=5),
            state=CameraMoveState.PREPARE_TARGET,
        )

    def targets(
        self,
        camera_id: UUID,
        *,
        expected_revision: int | None = None,
    ) -> tuple[CameraMoveTarget, ...]:
        self.calls.append(("targets", camera_id, expected_revision))
        return (self.target,)

    def preview(
        self,
        camera_id: UUID,
        *,
        target_node_id: UUID,
        expected_revision: int | None = None,
    ) -> CameraMovePreview:
        self.calls.append(
            ("preview", camera_id, target_node_id, expected_revision)
        )
        return CameraMovePreview(
            camera_id=camera_id,
            source_node_id=NODE_ID,
            target_node_id=target_node_id,
            desired_revision=3,
            occupied=self.occupied,
            disconnect_readers=1 if self.occupied else 0,
            confirmation_token="move-confirmation-token" if self.occupied else None,
            source_port=10543,
            target_port=10544,
            source_endpoint="rtsp://server:10543/" + "a" * 26,
            target_endpoint="rtsp://server:10544/" + "a" * 26,
        )

    def request_move(
        self,
        camera_id: UUID,
        *,
        target_node_id: UUID,
        expected_revision: int | None = None,
        force: bool = False,
        confirmation_token: str | None = None,
    ) -> CameraMove:
        self.calls.append(
            (
                "request",
                camera_id,
                target_node_id,
                expected_revision,
                force,
                confirmation_token,
            )
        )
        return self.move

    def get_move(self, move_id: UUID) -> CameraMove | None:
        return self.move if move_id == self.move.id else None


class RuntimeMediaNode:
    def __init__(self) -> None:
        self.paths: dict[PublicId, MediaPathConfig] = {}
        self.runtime: dict[PublicId, tuple[bool, int] | None] = {}

    def put_path(self, path: MediaPathConfig) -> None:
        self.paths[path.name] = path

    def get_path(self, name: PublicId) -> MediaPathConfig | None:
        return self.paths.get(name)

    def path_runtime_status(self, name: PublicId) -> tuple[bool, int] | None:
        return self.runtime.get(name)


class RuntimeMediaNodes:
    def __init__(self, node_id: UUID) -> None:
        self.client = RuntimeMediaNode()
        self.node_id = node_id

    def for_node(self, node: MediaNode) -> RuntimeMediaNode:
        assert node.id == self.node_id
        return self.client


class RunningDashboardNodeRuntime:
    def execute(
        self,
        _action: NodeRuntimeAction,
        node: MediaNode,
    ) -> NodeRuntimeObservation:
        return NodeRuntimeObservation(
            state=NodeState.RUNNING,
            health=NodeHealth.HEALTHY,
            management_fresh=True,
            config_compatible=True,
            applied_revision=node.desired_revision,
            process_id=node.external_port,
            process_start_ticks=1,
            process_boot_id=UUID("ffffffff-ffff-4fff-8fff-ffffffffffff"),
            config_sha256="a" * 64,
            release_id=node.release_id,
        )


def _domain_camera_mutations(
    *,
    reader_count: int,
) -> tuple[CameraControl, CameraMutationControl, InMemoryNodeStore]:
    node = MediaNode(
        id=NODE_ID,
        name="edge-north",
        external_port=10543,
        state=NodeState.RUNNING,
        runtime_state=NodeState.RUNNING,
        health=NodeHealth.HEALTHY,
        management_fresh=True,
            management_observed_at=datetime.now(UTC),
        config_compatible=True,
        desired_revision=1,
        applied_revision=1,
    )
    store = InMemoryNodeStore(nodes=(node,))
    cameras = CameraControl(
        store=store,
        new_camera_id=lambda: CAMERA_ID,
        new_public_id=lambda: "a" * 26,
    )
    camera = cameras.create_camera(
        name="Front entrance",
        source_url="rtsp://camera.internal/main",
        node_id=NODE_ID,
    )
    media = RuntimeMediaNodes(NODE_ID)
    media.client.paths[camera.public_id] = MediaPathConfig(
        name=camera.public_id,
        source_url=camera.source_url,
    )
    media.client.runtime[camera.public_id] = (True, reader_count)
    mutations = CameraMutationControl(
        store=store,
        media_nodes=cast(Any, media),
        confirmations=ConfirmationTokenService(
            secret=b"dashboard-confirmation-secret-at-least-32-bytes",
            lifetime_seconds=30,
            wall_time=lambda: 1_700_000_000.0,
        ),
    )
    return cameras, mutations, store


class MutableCameraRuntime:
    def __init__(self, *, source_node_id: UUID, reader_count: int) -> None:
        self.source_node_id = source_node_id
        self.reader_count = reader_count

    def observe(self, camera_id: UUID) -> CameraRuntimeObservation:
        return CameraRuntimeObservation(
            camera_id=camera_id,
            node_id=self.source_node_id,
            ready=True,
            reader_count=self.reader_count,
            occupied=self.reader_count == 1,
            reader_limit_violated=self.reader_count > 1,
        )


def _domain_camera_moves(
    *,
    reader_count: int,
) -> tuple[CameraControl, CameraMoveControl, InMemoryNodeStore, MutableCameraRuntime]:
    target_id = UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
    observed_at = datetime.now(UTC)
    nodes = (
        MediaNode(
            id=NODE_ID,
            name="edge-north",
            external_port=10543,
            state=NodeState.RUNNING,
            runtime_state=NodeState.RUNNING,
            health=NodeHealth.HEALTHY,
            management_fresh=True,
            management_observed_at=observed_at,
            config_compatible=True,
            desired_revision=1,
            applied_revision=1,
        ),
        MediaNode(
            id=target_id,
            name="edge-south",
            external_port=10544,
            state=NodeState.RUNNING,
            runtime_state=NodeState.RUNNING,
            health=NodeHealth.HEALTHY,
            management_fresh=True,
            management_observed_at=observed_at,
            config_compatible=True,
            desired_revision=1,
            applied_revision=1,
        ),
    )
    store = InMemoryNodeStore(nodes=nodes)
    cameras = CameraControl(
        store=store,
        new_camera_id=lambda: CAMERA_ID,
        new_public_id=lambda: "a" * 26,
    )
    cameras.create_camera(
        name="Front entrance",
        source_url="rtsp://camera.internal/main",
        node_id=NODE_ID,
    )
    runtime = MutableCameraRuntime(
        source_node_id=NODE_ID,
        reader_count=reader_count,
    )
    moves = CameraMoveControl(
        store=store,
        runtime=cast(Any, runtime),
        confirmations=ConfirmationTokenService(
            secret=b"dashboard-confirmation-secret-at-least-32-bytes",
            lifetime_seconds=30,
            wall_time=lambda: 1_700_000_000.0,
        ),
        new_move_id=lambda: UUID("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"),
    )
    return cameras, moves, store, runtime


def _authenticated_dashboard(
    *,
    observations: SnapshotReader | None,
    clock: datetime = NOW,
    raise_server_exceptions: bool = True,
    camera_control: CameraControl | None = None,
    camera_mutation_control: object | None = None,
    camera_move_control: object | None = None,
    node_control: object | None = None,
    settings: Settings | None = None,
    role: OperatorRole = OperatorRole.VIEWER,
    scopes: frozenset[str] = frozenset({"server:*"}),
) -> tuple[TestClient, dict[str, str]]:
    account = OperatorAccount(
        identity_source=OperatorIdentitySource.OIDC,
        id=ACCOUNT_ID,
        subject="oidc:viewer@example.test",
        display_name="Дежурный <script>alert(1)</script>",
        roles=frozenset({role}),
        scopes=scopes,
        authz_version=1,
        enabled=True,
    )
    sessions = OperatorSessionControl(
        store=InMemoryOperatorSessionStore(accounts=(account,), clock=lambda: NOW),
        token_factory=iter(("s" * 43, "c" * 43)).__next__,
    )
    issued = sessions.issue(account_id=ACCOUNT_ID, mfa_verified=True)
    client = TestClient(
        create_app(
            settings or Settings(role=RuntimeRole.WEB),
            fleet_snapshots=observations,
            operator_sessions=sessions,
            fleet_snapshot_max_age_seconds=30,
            clock=lambda: clock,
            camera_control=camera_control,
            camera_mutation_control=cast(Any, camera_mutation_control),
            camera_move_control=cast(Any, camera_move_control),
            node_control=cast(Any, node_control),
        ),
        base_url="https://management.example.test",
        raise_server_exceptions=raise_server_exceptions,
    )
    return client, {
        "Cookie": (
            f"__Host-rtsp_proxy_session={issued.session_token}; "
            f"__Host-rtsp_proxy_csrf={issued.csrf_token}"
        )
    }


def _snapshot() -> FleetSnapshot:
    return FleetSnapshot(
        generated_at=NOW,
        configured_nodes=1,
        max_nodes=50,
        registered_cameras=80,
        external_ports_used=1,
        external_ports_free=999,
        nodes=(
            NodeSnapshot(
                node_id=NODE_ID,
                name="edge <north>",
                external_port=10543,
                desired_state=NodeState.RUNNING,
                runtime_state=NodeState.RUNNING,
                health=NodeHealth.HEALTHY,
                registered_cameras=80,
                camera_capacity=100,
                desired_revision=7,
                applied_revision=7,
                scrape_status=NodeScrapeStatus.FRESH,
                scrape_reason=None,
                metrics=NodeMetricSample(
                    active_sources=64,
                    occupied_streams=12,
                    received_bytes_total=4_000,
                    sent_bytes_total=8_000,
                ),
                metric_observed_at=NOW,
                received_bitrate_bps=1_500_000.0,
                sent_bitrate_bps=3_000_000.0,
            ),
        ),
    )


def test_dashboard_requires_operator_session_and_never_caches() -> None:
    client, _headers = _authenticated_dashboard(observations=None)

    response = client.get("/dashboard")

    assert response.status_code == 401
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-type"].startswith("text/html")
    assert "Требуется вход оператора" in response.text


def test_dashboard_authentication_failure_offers_oidc_login_when_configured() -> None:
    account = OperatorAccount(
        identity_source=OperatorIdentitySource.OIDC,
        id=ACCOUNT_ID,
        subject="oidc:viewer@example.test",
        display_name="Дежурный",
        roles=frozenset({OperatorRole.VIEWER}),
        scopes=frozenset({"server:*"}),
        authz_version=1,
        enabled=True,
    )
    sessions = OperatorSessionControl(
        store=InMemoryOperatorSessionStore(accounts=(account,), clock=lambda: NOW),
        token_factory=iter(("s" * 43, "c" * 43)).__next__,
    )
    client = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            operator_sessions=sessions,
            operator_login=cast(Any, object()),
        ),
        base_url="https://management.example.test",
    )

    response = client.get("/dashboard")

    assert response.status_code == 401
    assert '<a class="button-link" href="/auth/oidc/login">Войти через OIDC</a>' in (
        response.text
    )


def test_dashboard_exposes_csrf_protected_browser_logout() -> None:
    observations = InMemoryObservabilityStore()
    observations.save_snapshot(_snapshot())
    client, headers = _authenticated_dashboard(observations=observations)

    dashboard = client.get("/dashboard", headers=headers)
    logout_page = client.get("/dashboard/logout", headers=headers)
    missing_csrf = client.post(
        "/dashboard/logout",
        headers=headers,
        follow_redirects=False,
    )
    logged_out = client.post(
        "/dashboard/logout",
        headers=headers,
        data={"_csrf": CSRF_TOKEN},
        follow_redirects=False,
    )
    replayed = client.get("/dashboard", headers=headers)

    assert dashboard.status_code == 200
    assert '<a href="/dashboard/logout">Выйти</a>' in dashboard.text
    assert logout_page.status_code == 200
    assert '<form method="post" action="/dashboard/logout">' in logout_page.text
    assert 'name="_csrf" value="ccccccccccccccccccccccccccccccccccccccccccc"' in (
        logout_page.text
    )
    assert missing_csrf.status_code == 401
    assert logged_out.status_code == 303
    assert logged_out.headers["location"] == "/dashboard"
    assert '__Host-rtsp_proxy_session=""' in logged_out.headers["set-cookie"]
    assert "Max-Age=0" in logged_out.headers["set-cookie"]
    assert replayed.status_code == 401


def test_dashboard_renders_bounded_fleet_snapshot_with_semantic_security_contract() -> None:
    observations = InMemoryObservabilityStore()
    observations.save_snapshot(_snapshot())
    client, headers = _authenticated_dashboard(observations=observations)

    response = client.get("/dashboard", headers=headers)

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-security-policy"] == (
        "default-src 'none'; style-src 'self'; base-uri 'none'; "
        "form-action 'self'; frame-ancestors 'none'"
    )
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert '<main id="main-content">' in response.text
    assert '<table aria-label="Ноды сервера">' in response.text
    assert "1 / 50" in response.text
    assert "80 / 100" in response.text
    assert "10543" in response.text
    assert "64" in response.text
    assert "12" in response.text
    assert "edge &lt;north&gt;" in response.text
    assert "Дежурный &lt;script&gt;alert(1)&lt;/script&gt;" in response.text
    assert "edge <north>" not in response.text
    assert "Дежурный <script>" not in response.text
    assert 'href="/dashboard/nodes/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"' in response.text


def test_dashboard_exposes_pending_and_stale_snapshot_as_accessible_degraded_state() -> None:
    pending_store = InMemoryObservabilityStore()
    pending, pending_headers = _authenticated_dashboard(observations=pending_store)

    pending_response = pending.get("/dashboard", headers=pending_headers)

    assert pending_response.status_code == 503
    assert pending_response.headers["retry-after"] == "5"
    assert 'role="alert"' in pending_response.text
    assert "Снимок состояния ещё не сформирован" in pending_response.text

    stale_store = InMemoryObservabilityStore()
    stale_store.save_snapshot(_snapshot())
    stale, stale_headers = _authenticated_dashboard(
        observations=stale_store,
        clock=NOW + timedelta(seconds=31),
    )

    stale_response = stale.get("/dashboard", headers=stale_headers)

    assert stale_response.status_code == 503
    assert stale_response.headers["retry-after"] == "5"
    assert 'role="alert"' in stale_response.text
    assert "Снимок состояния устарел" in stale_response.text
    assert "edge &lt;north&gt;" not in stale_response.text


def test_dashboard_and_snapshot_api_map_snapshot_store_outage_to_typed_503() -> None:
    class FailingSnapshotReader:
        def current_snapshot(self) -> FleetSnapshot | None:
            raise RuntimeError("database password must not escape")

    reader = FailingSnapshotReader()
    dashboard, headers = _authenticated_dashboard(
        observations=reader,
        raise_server_exceptions=False,
    )

    dashboard_response = dashboard.get("/dashboard", headers=headers)

    assert dashboard_response.status_code == 503
    assert dashboard_response.headers["retry-after"] == "5"
    assert dashboard_response.headers["cache-control"] == "no-store"
    assert "content-security-policy" in dashboard_response.headers
    assert "Наблюдение недоступно" in dashboard_response.text
    assert "database password" not in dashboard_response.text

    api = TestClient(
        create_app(Settings(role=RuntimeRole.WEB), fleet_snapshots=reader),
        raise_server_exceptions=False,
    )
    api_response = api.get("/api/v1/dashboard/snapshot")
    assert api_response.status_code == 503
    assert api_response.json() == {"detail": {"code": "fleet_snapshot_unavailable"}}


def test_dashboard_suppresses_retained_stale_metrics_and_shows_observation_time() -> None:
    snapshot = _snapshot()
    stale_observed_at = NOW - timedelta(minutes=2)
    stale_node = replace(
        snapshot.nodes[0],
        scrape_status=NodeScrapeStatus.STALE,
        scrape_reason="node_metrics_gap",
        metric_observed_at=stale_observed_at,
    )
    observations = InMemoryObservabilityStore()
    observations.save_snapshot(replace(snapshot, nodes=(stale_node,)))
    client, headers = _authenticated_dashboard(observations=observations)

    response = client.get("/dashboard", headers=headers)

    assert response.status_code == 200
    assert "Метрики устарели" in response.text
    assert "14.08.2026 11:58:00 UTC" in response.text
    assert ">64<" not in response.text
    assert ">12<" not in response.text


def test_dashboard_distinguishes_confirmed_idle_zero_from_unknown_metrics() -> None:
    snapshot = _snapshot()
    idle_node = replace(
        snapshot.nodes[0],
        scrape_status=NodeScrapeStatus.IDLE,
        metrics=NodeMetricSample(
            active_sources=0,
            occupied_streams=0,
            received_bytes_total=0,
            sent_bytes_total=0,
        ),
        received_bitrate_bps=0.0,
        sent_bitrate_bps=0.0,
    )
    observations = InMemoryObservabilityStore()
    observations.save_snapshot(replace(snapshot, nodes=(idle_node,)))
    client, headers = _authenticated_dashboard(observations=observations)

    overview = client.get("/dashboard", headers=headers)
    detail = client.get(f"/dashboard/nodes/{NODE_ID}", headers=headers)

    assert overview.status_code == 200
    assert overview.text.count("<td>0</td>") == 2
    assert "running · idle" in overview.text
    assert detail.status_code == 200
    assert detail.text.count("<strong>0</strong>") == 2
    assert "0 бит/с" in detail.text  # noqa: RUF001


def test_dashboard_node_detail_is_authenticated_escaped_and_snapshot_bound() -> None:
    observations = InMemoryObservabilityStore()
    observations.save_snapshot(_snapshot())
    client, headers = _authenticated_dashboard(observations=observations)
    path = f"/dashboard/nodes/{NODE_ID}"

    anonymous = client.get(path)
    response = client.get(path, headers=headers)
    missing = client.get(
        "/dashboard/nodes/cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        headers=headers,
    )

    assert anonymous.status_code == 401
    assert anonymous.headers["content-type"].startswith("text/html")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert "content-security-policy" in response.headers
    assert "edge &lt;north&gt;" in response.text
    assert "edge <north>" not in response.text
    assert "14.08.2026 12:00:00 UTC" in response.text
    assert "1.50 Мбит/с" in response.text  # noqa: RUF001
    assert missing.status_code == 404
    assert missing.headers["cache-control"] == "no-store"
    assert "Нода не найдена" in missing.text


def test_dashboard_node_create_supports_random_and_manual_port_with_csrf() -> None:
    observations = InMemoryObservabilityStore()
    observations.save_snapshot(_snapshot())
    control = RecordingNodeDashboardControl()
    settings = Settings(
        role=RuntimeRole.WEB,
        node_port_range_start=10540,
        node_port_range_end=10549,
        node_port_reserved=(10545,),
    )
    client, headers = _authenticated_dashboard(
        observations=observations,
        node_control=control,
        settings=settings,
        role=OperatorRole.OPERATOR,
    )

    overview = client.get("/dashboard", headers=headers)
    create_page = client.get("/dashboard/nodes/new", headers=headers)
    automatic = client.post(
        "/dashboard/nodes",
        headers=headers,
        data={
            "_csrf": CSRF_TOKEN,
            "name": "edge north",
            "external_port": "",
            "idempotency_key": IDEMPOTENCY_KEY,
        },
        follow_redirects=False,
    )
    manual = client.post(
        "/dashboard/nodes",
        headers=headers,
        data={
            "_csrf": CSRF_TOKEN,
            "name": "edge east",
            "external_port": "10544",
            "idempotency_key": "22222222-2222-4222-8222-222222222222",
        },
        follow_redirects=False,
    )
    viewer, viewer_headers = _authenticated_dashboard(observations=observations)
    viewer_overview = viewer.get("/dashboard", headers=viewer_headers)
    viewer_create = viewer.get("/dashboard/nodes/new", headers=viewer_headers)

    assert overview.status_code == 200
    assert 'href="/dashboard/nodes/new"' in overview.text
    assert create_page.status_code == 200
    assert 'form method="post" action="/dashboard/nodes"' in create_page.text
    assert 'name="idempotency_key"' in create_page.text
    assert "10540–10549" in create_page.text  # noqa: RUF001
    assert automatic.status_code == manual.status_code == 303
    assert automatic.headers["location"] == (
        f"/dashboard/nodes/{CREATED_NODE_ID}/registered"
    )
    assert manual.headers["location"] == (
        f"/dashboard/nodes/{CREATED_NODE_ID}/registered"
    )
    accepted = client.get(automatic.headers["location"], headers=headers)
    assert accepted.status_code == 200
    assert "Нода зарегистрирована" in accepted.text
    assert "edge-created" in accepted.text
    assert "10544" in accepted.text
    first = cast(dict[str, object], control.calls[0][1])
    second = cast(dict[str, object], control.calls[1][1])
    assert first["name"] == "edge north"
    assert first["external_port"] is None
    assert first["reserved_ports"] == (10545,)
    automatic_context = cast(NodeMutationContext, first["mutation_context"])
    assert automatic_context.action == "node.create"
    assert automatic_context.actor_account_id == ACCOUNT_ID
    assert automatic_context.identity_source == OperatorIdentitySource.OIDC.value
    assert str(automatic_context.idempotency_key) == IDEMPOTENCY_KEY
    assert second["name"] == "edge east"
    assert second["external_port"] == 10544
    assert 'href="/dashboard/nodes/new"' not in viewer_overview.text
    assert viewer_create.status_code == 403


def test_dashboard_node_create_is_fail_closed_and_reports_port_exhaustion() -> None:
    observations = InMemoryObservabilityStore()
    observations.save_snapshot(_snapshot())
    control = RecordingNodeDashboardControl(
        create_error=NodePortRangeExhausted("node_port_range_exhausted")
    )
    client, headers = _authenticated_dashboard(
        observations=observations,
        node_control=control,
        role=OperatorRole.OPERATOR,
    )

    missing_csrf = client.post(
        "/dashboard/nodes",
        headers=headers,
        data={"name": "edge north", "external_port": ""},
        follow_redirects=False,
    )
    malformed = client.post(
        "/dashboard/nodes",
        headers=headers,
        data={
            "_csrf": CSRF_TOKEN,
            "name": "edge north",
            "external_port": "not-a-port",
            "idempotency_key": IDEMPOTENCY_KEY,
        },
        follow_redirects=False,
    )
    exhausted = client.post(
        "/dashboard/nodes",
        headers=headers,
        data={
            "_csrf": CSRF_TOKEN,
            "name": "edge north",
            "external_port": "",
            "idempotency_key": IDEMPOTENCY_KEY,
        },
        follow_redirects=False,
    )

    assert missing_csrf.status_code == 401
    assert malformed.status_code == 422
    assert exhausted.status_code == 409
    assert "нет свободных портов для регистрации новой ноды" in exhausted.text
    assert len(control.calls) == 1
    assert control.calls[0][0] == "register"


@pytest.mark.parametrize(
    ("error", "expected_status", "expected_message"),
    [
        (
            MaximumNodesReached("max_nodes_reached"),
            409,
            "Достигнут предел нод",
        ),
        (
            NodeManagementPortRangeExhausted(
                "node_management_port_range_exhausted"
            ),
            409,
            "Нет management-портов",
        ),
        (
            NodePortOutOfRange("node_port_out_of_range"),
            422,
            "Порт вне диапазона",
        ),
        (
            NodePortInUse("node_port_in_use"),
            409,
            "Порт уже занят",
        ),
    ],
)
def test_dashboard_node_create_maps_expected_registration_failures(
    error: Exception,
    expected_status: int,
    expected_message: str,
) -> None:
    control = RecordingNodeDashboardControl(create_error=error)
    client, headers = _authenticated_dashboard(
        observations=None,
        node_control=control,
        role=OperatorRole.OPERATOR,
    )

    response = client.post(
        "/dashboard/nodes",
        headers=headers,
        data={
            "_csrf": CSRF_TOKEN,
            "name": "edge north",
            "external_port": "10544",
            "idempotency_key": IDEMPOTENCY_KEY,
        },
        follow_redirects=False,
    )

    assert response.status_code == expected_status
    assert expected_message in response.text
    assert response.headers["cache-control"] == "no-store"
    assert len(control.calls) == 1


def test_dashboard_node_create_runtime_failure_redirects_to_persisted_node() -> None:
    observations = InMemoryObservabilityStore()
    observations.save_snapshot(_snapshot())
    control = RecordingNodeDashboardControl(
        create_error=NodeRuntimeFailed(
            "node_runtime_operation_failed",
            node_id=CREATED_NODE_ID,
        )
    )
    client, headers = _authenticated_dashboard(
        observations=observations,
        node_control=control,
        role=OperatorRole.OPERATOR,
    )

    response = client.post(
        "/dashboard/nodes",
        headers=headers,
        data={
            "_csrf": CSRF_TOKEN,
            "name": "edge north",
            "external_port": "",
            "idempotency_key": IDEMPOTENCY_KEY,
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == (
        f"/dashboard/nodes/{CREATED_NODE_ID}/registered"
    )
    persisted = client.get(response.headers["location"], headers=headers)
    assert persisted.status_code == 200
    assert "Регистрация сохранена, запуск не завершён" in persisted.text
    assert "Создать ноду" not in persisted.text
    assert len([call for call in control.calls if call[0] == "register"]) == 1


def test_dashboard_node_create_replays_one_session_bound_registration() -> None:
    bindable = {10544: True}
    control = NodeControl(
        store=InMemoryNodeStore(),
        choose_port=lambda ports: ports[0],
        new_node_id=iter((CREATED_NODE_ID,)).__next__,
        is_port_bindable=lambda port: bindable.get(port, True),
    )
    client, headers = _authenticated_dashboard(
        observations=None,
        node_control=control,
        role=OperatorRole.OPERATOR,
    )
    form = {
        "_csrf": CSRF_TOKEN,
        "name": "idempotent-node",
        "external_port": "10544",
        "idempotency_key": IDEMPOTENCY_KEY,
    }

    first = client.post(
        "/dashboard/nodes",
        headers=headers,
        data=form,
        follow_redirects=False,
    )
    bindable[10544] = False
    replay = client.post(
        "/dashboard/nodes",
        headers=headers,
        data=form,
        follow_redirects=False,
    )

    assert first.status_code == replay.status_code == 303
    assert first.headers["location"] == replay.headers["location"] == (
        f"/dashboard/nodes/{CREATED_NODE_ID}/registered"
    )
    assert len(control.list_nodes()) == 1


def test_authenticated_node_api_uses_the_same_idempotency_and_command_fence() -> None:
    control = RecordingNodeDashboardControl()
    client, headers = _authenticated_dashboard(
        observations=None,
        node_control=control,
        role=OperatorRole.OPERATOR,
    )
    api_headers = {**headers, "X-CSRF-Token": CSRF_TOKEN}

    missing_key = client.post(
        "/api/v1/nodes",
        headers=api_headers,
        json={"name": "api-node", "external_port": 10544},
    )
    created = client.post(
        "/api/v1/nodes",
        headers={**api_headers, "Idempotency-Key": IDEMPOTENCY_KEY},
        json={"name": "api-node", "external_port": 10544},
    )
    missing_fence = client.post(
        f"/api/v1/nodes/{NODE_ID}/start",
        headers=api_headers,
    )
    started = client.post(
        f"/api/v1/nodes/{NODE_ID}/start",
        headers={
            **api_headers,
            "X-Node-Revision": "7",
            "X-Node-State": "stopped",
        },
    )

    assert missing_key.status_code == 428
    assert missing_key.json()["detail"]["code"] == "node_idempotency_key_required"
    assert created.status_code == 201
    register_call = next(call for call in control.calls if call[0] == "register")
    context = cast(dict[str, object], register_call[1])["mutation_context"]
    assert isinstance(context, NodeMutationContext)
    assert context.idempotency_key == UUID(IDEMPOTENCY_KEY)
    assert missing_fence.status_code == 428
    assert missing_fence.json()["detail"]["code"] == "node_command_precondition_required"
    assert started.status_code == 200
    start_call = next(call for call in control.calls if call[0] == "start")
    _node_id, fence, start_context = cast(
        tuple[UUID, NodeCommandFence, NodeMutationContext], start_call[1]
    )
    assert fence == NodeCommandFence(expected_revision=7, expected_state=NodeState.STOPPED)
    assert start_context.actor_account_id == ACCOUNT_ID


def test_dashboard_node_actions_use_control_seam_and_exact_csrf_forms() -> None:
    observations = InMemoryObservabilityStore()
    observations.save_snapshot(
        replace(
            _snapshot(),
            registered_cameras=0,
            nodes=(
                replace(
                    _snapshot().nodes[0],
                    registered_cameras=0,
                    desired_state=NodeState.STOPPED,
                    runtime_state=NodeState.STOPPED,
                ),
            ),
        )
    )
    control = RecordingNodeDashboardControl()
    client, headers = _authenticated_dashboard(
        observations=observations,
        node_control=control,
        role=OperatorRole.OPERATOR,
    )
    path = f"/dashboard/nodes/{NODE_ID}"

    detail = client.get(path, headers=headers)
    assert 'name="expected_revision" value="7"' in detail.text
    assert 'name="expected_state" value="stopped"' in detail.text
    action_states = {
        "start": NodeState.STOPPED,
        "stop": NodeState.RUNNING,
        "drain": NodeState.RUNNING,
        "maintenance": NodeState.DRAINING,
        "resume": NodeState.MAINTENANCE,
        "delete": NodeState.STOPPED,
    }
    for action, expected_state in action_states.items():
        response = client.post(
            f"{path}/{action}",
            headers=headers,
            data={
                "_csrf": CSRF_TOKEN,
                "expected_revision": "7",
                "expected_state": expected_state.value,
            },
            follow_redirects=False,
        )
        assert response.status_code == 303, (action, response.text)
    viewer, viewer_headers = _authenticated_dashboard(
        observations=observations,
        node_control=RecordingNodeDashboardControl(),
    )
    denied = viewer.post(
        f"{path}/drain",
        headers=viewer_headers,
        data={
            "_csrf": CSRF_TOKEN,
            "expected_revision": "7",
            "expected_state": "stopped",
        },
        follow_redirects=False,
    )
    viewer_detail = viewer.get(path, headers=viewer_headers)

    assert detail.status_code == 200
    assert f'action="{path}/start"' in detail.text
    assert f'action="{path}/delete"' in detail.text
    assert [call[0] for call in control.calls] == [
        "start",
        "stop",
        "administrative",
        "administrative",
        "administrative",
        "delete",
    ]
    expected_actions = (
        "node.start",
        "node.stop",
        "node.drain",
        "node.maintenance",
        "node.resume",
        "node.delete",
    )
    for call, action, expected_state in zip(
        control.calls,
        expected_actions,
        action_states.values(),
        strict=True,
    ):
        arguments = cast(tuple[object, ...], call[1])
        fence = cast(NodeCommandFence, arguments[-2])
        context = cast(NodeMutationContext, arguments[-1])
        assert fence == NodeCommandFence(
            expected_revision=7,
            expected_state=expected_state,
        )
        assert context.action == action
        assert context.actor_account_id == ACCOUNT_ID
        assert context.identity_source == OperatorIdentitySource.OIDC.value
        assert context.reason == "operator_request"
        assert context.resource_id == str(NODE_ID)
        assert context.request_id is not None
    assert denied.status_code == 403
    assert viewer_detail.status_code == 200
    assert "Управление нодой" not in viewer_detail.text


def test_dashboard_node_action_rejects_missing_or_stale_fence_before_control() -> None:
    observations = InMemoryObservabilityStore()
    observations.save_snapshot(
        replace(
            _snapshot(),
            registered_cameras=0,
            nodes=(
                replace(
                    _snapshot().nodes[0],
                    registered_cameras=0,
                    desired_state=NodeState.STOPPED,
                    runtime_state=NodeState.STOPPED,
                ),
            ),
        )
    )
    control = RecordingNodeDashboardControl()
    client, headers = _authenticated_dashboard(
        observations=observations,
        node_control=control,
        role=OperatorRole.OPERATOR,
    )
    path = f"/dashboard/nodes/{NODE_ID}/start"

    missing = client.post(
        path,
        headers=headers,
        data={"_csrf": CSRF_TOKEN},
    )
    malformed = client.post(
        path,
        headers=headers,
        data={
            "_csrf": CSRF_TOKEN,
            "expected_revision": "0",
            "expected_state": "deleting",
        },
    )

    assert missing.status_code == 422
    assert malformed.status_code == 422
    assert control.calls == []


def test_dashboard_stylesheet_is_local_and_root_redirects_to_dashboard() -> None:
    client = TestClient(
        create_app(Settings(role=RuntimeRole.WEB)),
        base_url="https://management.example.test",
    )

    root = client.get("/", follow_redirects=False)
    stylesheet = client.get("/assets/dashboard.css")
    disabled_dashboard = client.get("/dashboard")

    assert root.status_code == 303
    assert root.headers["location"] == "/dashboard"
    assert stylesheet.status_code == 200
    assert stylesheet.headers["content-type"].startswith("text/css")
    assert "@media (prefers-reduced-motion: reduce)" in stylesheet.text
    assert "focus-visible" in stylesheet.text
    assert disabled_dashboard.status_code == 503
    assert disabled_dashboard.headers["content-type"].startswith("text/html")
    assert "Сессии операторов не настроены" in disabled_dashboard.text


def test_camera_catalog_is_authenticated_bounded_escaped_and_secret_free() -> None:
    catalog = StaticCameraCatalog()
    client, headers = _authenticated_dashboard(
        observations=None,
        camera_control=cast(CameraControl, catalog),
    )
    path = f"/dashboard/cameras?limit=1&q=Front&node_id={NODE_ID}&state=enabled"

    anonymous = client.get(path)
    response = client.get(path, headers=headers)

    assert anonymous.status_code == 401
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert catalog.last_query == CameraCatalogQuery(
        limit=1,
        search="Front",
        node_id=NODE_ID,
        state=CameraState.ENABLED,
    )
    assert "Front &lt;script&gt;alert(1)&lt;/script&gt;" in response.text
    assert "edge &lt;north&gt;" in response.text
    assert "/aaaaaaaaaaaaaaaaaaaaaaaaaa" in response.text
    assert "10543" in response.text
    assert "2 / 3" in response.text
    assert catalog.source_url not in response.text
    assert "admin:secret" not in response.text
    assert f'/dashboard/cameras/{CAMERA_ID}' in response.text
    assert f"after={CAMERA_ID}" in response.text
    assert "q=Front" in response.text

    browser_form_response = client.get(
        "/dashboard/cameras?q=Front&node_id=&state=&limit=50",
        headers=headers,
    )

    assert browser_form_response.status_code == 200


def test_camera_catalog_requires_control_read_and_fails_closed() -> None:
    catalog = StaticCameraCatalog()
    auditor, auditor_headers = _authenticated_dashboard(
        observations=None,
        camera_control=cast(CameraControl, catalog),
        role=OperatorRole.AUDITOR,
    )
    unavailable, unavailable_headers = _authenticated_dashboard(
        observations=None,
        camera_control=cast(CameraControl, FailingCameraCatalog()),
        raise_server_exceptions=False,
    )

    denied = auditor.get("/dashboard/cameras", headers=auditor_headers)
    failed = unavailable.get("/dashboard/cameras", headers=unavailable_headers)
    invalid = unavailable.get("/dashboard/cameras?limit=101", headers=unavailable_headers)

    assert denied.status_code == 403
    assert "Недостаточно прав" in denied.text
    assert failed.status_code == 503
    assert failed.headers["retry-after"] == "5"
    assert "Каталог камер недоступен" in failed.text
    assert "postgres password" not in failed.text
    assert invalid.status_code == 422
    assert invalid.headers["content-type"].startswith("text/html")
    assert "Некорректный запрос каталога" in invalid.text


def test_postgres_dashboard_catalog_and_detail_remain_available_on_schema_0015(
    postgres_database_url: str,
) -> None:
    migration = Config("alembic.ini")
    migration.set_main_option("sqlalchemy.url", postgres_database_url)
    command.upgrade(migration, "0015_camera_name_contract")
    store = PostgresNodeStore(postgres_database_url)
    node_control = NodeControl(
        store=store,
        choose_port=lambda ports: ports[0],
        new_node_id=lambda: NODE_ID,
        node_runtime=RunningDashboardNodeRuntime(),
        provision_on_create=True,
        is_port_bindable=lambda _port: True,
    )
    node = node_control.register_node(
        name="bridge-node",
        port_range_start=10543,
        port_range_end=10543,
        max_nodes=1,
        external_port=10543,
        api_ports=(20543,),
        metrics_ports=(30543,),
    )
    camera_control = CameraControl(
        store=store,
        new_camera_id=lambda: CAMERA_ID,
        new_public_id=lambda: "a" * 26,
    )
    camera_control.create_camera(
        name="Bridge camera",
        source_url="rtsp://camera.internal/bridge",
        node_id=node.id,
    )
    client, headers = _authenticated_dashboard(
        observations=None,
        camera_control=camera_control,
    )

    try:
        catalog = client.get("/dashboard/cameras", headers=headers)
        detail = client.get(f"/dashboard/cameras/{CAMERA_ID}", headers=headers)

        assert catalog.status_code == 200
        assert "Bridge camera" in catalog.text
        assert detail.status_code == 200
        assert "Bridge camera" in detail.text
        assert "camera.internal" not in catalog.text
        assert "camera.internal" not in detail.text
    finally:
        store.close()


def test_camera_detail_is_authenticated_escaped_and_secret_free() -> None:
    catalog = StaticCameraCatalog()
    client, headers = _authenticated_dashboard(
        observations=None,
        camera_control=cast(CameraControl, catalog),
    )
    path = f"/dashboard/cameras/{CAMERA_ID}"

    anonymous = client.get(path)
    response = client.get(path, headers=headers)
    missing = client.get(
        "/dashboard/cameras/00000000-0000-4000-8000-000000000000",
        headers=headers,
    )

    assert anonymous.status_code == 401
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert "Front &lt;script&gt;alert(1)&lt;/script&gt;" in response.text
    assert "edge &lt;north&gt;" in response.text
    assert "rtsp://&lt;server-address&gt;:10543/aaaaaaaaaaaaaaaaaaaaaaaaaa" in (
        response.text
    )
    assert catalog.source_url not in response.text
    assert "admin:secret" not in response.text
    assert missing.status_code == 404
    assert "Камера не найдена" in missing.text


def test_camera_detail_requires_control_read_and_fails_closed() -> None:
    auditor, auditor_headers = _authenticated_dashboard(
        observations=None,
        camera_control=cast(CameraControl, StaticCameraCatalog()),
        role=OperatorRole.AUDITOR,
    )
    unavailable, unavailable_headers = _authenticated_dashboard(
        observations=None,
        camera_control=cast(CameraControl, FailingCameraCatalog()),
    )
    path = f"/dashboard/cameras/{CAMERA_ID}"

    denied = auditor.get(path, headers=auditor_headers)
    failed = unavailable.get(path, headers=unavailable_headers)

    assert denied.status_code == 403
    assert failed.status_code == 503
    assert failed.headers["retry-after"] == "5"
    assert "postgres password" not in failed.text


def test_camera_detail_honors_exact_camera_scope_without_an_existence_oracle() -> None:
    own_camera, own_headers = _authenticated_dashboard(
        observations=None,
        camera_control=cast(CameraControl, StaticCameraCatalog()),
        scopes=frozenset({f"camera:{CAMERA_ID}"}),
    )
    other_camera_id = UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")

    own = own_camera.get(f"/dashboard/cameras/{CAMERA_ID}", headers=own_headers)
    cross_camera = own_camera.get(
        f"/dashboard/cameras/{other_camera_id}",
        headers=own_headers,
    )
    nonexistent = own_camera.get(
        "/dashboard/cameras/00000000-0000-4000-8000-000000000000",
        headers=own_headers,
    )

    assert own.status_code == 200
    assert cross_camera.status_code == 403
    assert nonexistent.status_code == 403
    assert cross_camera.text == nonexistent.text


def test_camera_dashboard_forms_require_bound_csrf_and_confirm_occupied_disable() -> None:
    catalog = StaticCameraCatalog()
    mutations = RecordingCameraMutations(occupied=True)
    client, headers = _authenticated_dashboard(
        observations=None,
        camera_control=cast(CameraControl, catalog),
        camera_mutation_control=mutations,
        role=OperatorRole.OPERATOR,
    )
    detail_path = f"/dashboard/cameras/{CAMERA_ID}"
    preview_path = f"{detail_path}/mutations/preview"
    apply_path = f"{detail_path}/mutations/apply"

    detail = client.get(detail_path, headers=headers)
    missing_csrf = client.post(
        preview_path,
        headers=headers,
        data={"operation": "disable"},
    )
    wrong_csrf = client.post(
        preview_path,
        headers=headers,
        data={"_csrf": "wrong", "operation": "disable"},
    )
    preview = client.post(
        preview_path,
        headers=headers,
        data={
            "_csrf": CSRF_TOKEN,
            "operation": "disable",
            "expected_revision": "3",
        },
    )
    applied = client.post(
        apply_path,
        headers=headers,
        data={
            "_csrf": CSRF_TOKEN,
            "operation": "disable",
            "expected_revision": "3",
            "confirmation_token": "confirmation-token",
        },
        follow_redirects=False,
    )

    assert detail.status_code == 200
    assert f'action="{preview_path}"' in detail.text
    assert f'value="{CSRF_TOKEN}"' in detail.text
    assert catalog.source_url not in detail.text
    assert missing_csrf.status_code == 401
    assert wrong_csrf.status_code == 401
    assert preview.status_code == 200
    assert "Будет отключён 1 downstream-клиент" in preview.text
    assert 'role="alert" aria-live="assertive"' in preview.text
    assert '<h1 tabindex="-1" autofocus>Подтвердите действие</h1>' in preview.text
    assert 'value="confirmation-token"' in preview.text
    assert applied.status_code == 303
    assert applied.headers["location"] == detail_path
    assert mutations.calls == [
        ("preview", CAMERA_ID, CameraMutationOperation.DISABLE, 3, None, None),
        ("disable", CAMERA_ID, 3, "confirmation-token"),
    ]


def test_camera_update_confirmation_never_echoes_source_url_and_requires_reentry() -> None:
    catalog = StaticCameraCatalog()
    mutations = RecordingCameraMutations(occupied=True)
    client, headers = _authenticated_dashboard(
        observations=None,
        camera_control=cast(CameraControl, catalog),
        camera_mutation_control=mutations,
        role=OperatorRole.OPERATOR,
    )
    detail_path = f"/dashboard/cameras/{CAMERA_ID}"
    edit_path = f"{detail_path}/edit"
    source_url = "rtsp://new-admin:new-secret@camera.internal/private"

    edit = client.get(edit_path, headers=headers)
    preview = client.post(
        f"{detail_path}/mutations/preview",
        headers=headers,
        data={
            "_csrf": CSRF_TOKEN,
            "operation": "update_source",
            "expected_revision": "3",
            "name": "Front updated",
            "source_url": source_url,
        },
    )
    applied = client.post(
        f"{detail_path}/mutations/apply",
        headers=headers,
        data={
            "_csrf": CSRF_TOKEN,
            "operation": "update_source",
            "expected_revision": "3",
            "name": "Front updated",
            "source_url": source_url,
            "confirmation_token": "confirmation-token",
        },
        follow_redirects=False,
    )

    assert edit.status_code == 200
    assert 'value="Front &lt;script&gt;alert(1)&lt;/script&gt;"' in edit.text
    assert catalog.source_url not in edit.text
    assert preview.status_code == 200
    assert source_url not in preview.text
    assert "Введите новый source URL ещё раз" in preview.text
    assert applied.status_code == 303
    assert applied.headers["location"] == detail_path
    assert mutations.calls == [
        (
            "preview",
            CAMERA_ID,
            CameraMutationOperation.UPDATE_SOURCE,
            3,
            "Front updated",
            source_url,
        ),
        (
            "update",
            CAMERA_ID,
            "Front updated",
            source_url,
            3,
            "confirmation-token",
        ),
    ]


def test_dashboard_update_reentry_is_bound_to_the_domain_confirmation_token() -> None:
    cameras, mutations, store = _domain_camera_mutations(reader_count=1)
    client, headers = _authenticated_dashboard(
        observations=None,
        camera_control=cameras,
        camera_mutation_control=mutations,
        role=OperatorRole.OPERATOR,
    )
    detail_path = f"/dashboard/cameras/{CAMERA_ID}"
    previewed_source = "rtsp://camera.internal/new-main"
    changed_source = "rtsp://camera.internal/other-main"
    preview = client.post(
        f"{detail_path}/mutations/preview",
        headers=headers,
        data={
            "_csrf": CSRF_TOKEN,
            "operation": "update_source",
            "expected_revision": "1",
            "name": "Front updated",
            "source_url": previewed_source,
        },
    )
    token_match = re.search(
        r'name="confirmation_token" value="([^"]+)"',
        preview.text,
    )
    assert token_match is not None
    confirmation_token = token_match.group(1)

    mismatched = client.post(
        f"{detail_path}/mutations/apply",
        headers=headers,
        data={
            "_csrf": CSRF_TOKEN,
            "operation": "update_source",
            "expected_revision": "1",
            "name": "Front updated",
            "source_url": changed_source,
            "confirmation_token": confirmation_token,
        },
        follow_redirects=False,
    )
    applied = client.post(
        f"{detail_path}/mutations/apply",
        headers=headers,
        data={
            "_csrf": CSRF_TOKEN,
            "operation": "update_source",
            "expected_revision": "1",
            "name": "Front updated",
            "source_url": previewed_source,
            "confirmation_token": confirmation_token,
        },
        follow_redirects=False,
    )

    assert preview.status_code == 200
    assert previewed_source not in preview.text
    assert mismatched.status_code == 409
    assert applied.status_code == 303
    camera = store.get_camera(CAMERA_ID)
    assert camera is not None
    assert camera.name == "Front updated"
    assert camera.source_url == previewed_source


def test_unoccupied_mutations_apply_immediately_and_enable_is_direct() -> None:
    catalog = StaticCameraCatalog()
    mutations = RecordingCameraMutations(occupied=False)
    client, headers = _authenticated_dashboard(
        observations=None,
        camera_control=cast(CameraControl, catalog),
        camera_mutation_control=mutations,
        role=OperatorRole.OPERATOR,
    )
    detail_path = f"/dashboard/cameras/{CAMERA_ID}"
    preview_path = f"{detail_path}/mutations/preview"

    deleted = client.post(
        preview_path,
        headers=headers,
        data={
            "_csrf": CSRF_TOKEN,
            "operation": "delete",
            "expected_revision": "3",
        },
        follow_redirects=False,
    )
    enabled = client.post(
        f"{detail_path}/enable",
        headers=headers,
        data={"_csrf": CSRF_TOKEN, "expected_revision": "3"},
        follow_redirects=False,
    )

    assert deleted.status_code == 303
    assert deleted.headers["location"] == detail_path
    assert enabled.status_code == 303
    assert enabled.headers["location"] == detail_path
    assert mutations.calls == [
        ("preview", CAMERA_ID, CameraMutationOperation.DELETE, 3, None, None),
        ("delete", CAMERA_ID, 3, None),
    ]
    assert catalog.enabled_calls == [(CAMERA_ID, True)]


def test_dashboard_camera_mutation_rejects_stale_revision_with_safe_diff() -> None:
    cameras, mutations, store = _domain_camera_mutations(reader_count=0)
    client, headers = _authenticated_dashboard(
        observations=None,
        camera_control=cameras,
        camera_mutation_control=mutations,
        role=OperatorRole.OPERATOR,
    )
    detail_path = f"/dashboard/cameras/{CAMERA_ID}"
    detail = client.get(detail_path, headers=headers)
    assert 'name="expected_revision" value="1"' in detail.text
    current = store.update_camera(
        CAMERA_ID,
        name="Concurrent rename",
        source_url="rtsp://camera.internal/main",
        expected_revision=1,
    )

    stale = client.post(
        f"{detail_path}/mutations/preview",
        headers=headers,
        data={
            "_csrf": CSRF_TOKEN,
            "operation": "delete",
            "expected_revision": "1",
        },
    )

    assert current.desired_revision == 2
    assert stale.status_code == 409
    assert "Ожидалась revision 1, текущая revision 2" in stale.text
    assert current.source_url not in stale.text
    assert store.get_camera(CAMERA_ID).state is CameraState.ENABLED  # type: ignore[union-attr]


def test_dashboard_camera_update_uses_domain_name_contract() -> None:
    cameras, mutations, store = _domain_camera_mutations(reader_count=0)
    client, headers = _authenticated_dashboard(
        observations=None,
        camera_control=cameras,
        camera_mutation_control=mutations,
        role=OperatorRole.OPERATOR,
    )
    path = f"/dashboard/cameras/{CAMERA_ID}/mutations/preview"

    response = client.post(
        path,
        headers=headers,
        data={
            "_csrf": CSRF_TOKEN,
            "operation": "update_source",
            "expected_revision": "1",
            "name": "bad\nname",
            "source_url": "rtsp://camera.internal/new-main",
        },
    )

    assert response.status_code == 422
    assert "Некорректное имя камеры" in response.text
    assert "rtsp://camera.internal/new-main" not in response.text
    assert store.get_camera(CAMERA_ID).name == "Front entrance"  # type: ignore[union-attr]


def test_camera_move_form_lists_only_targets_and_requires_mutation_permission() -> None:
    catalog = StaticCameraCatalog()
    moves = RecordingCameraMoves(occupied=False)
    operator, operator_headers = _authenticated_dashboard(
        observations=None,
        camera_control=cast(CameraControl, catalog),
        camera_move_control=moves,
        role=OperatorRole.OPERATOR,
    )
    viewer, viewer_headers = _authenticated_dashboard(
        observations=None,
        camera_control=cast(CameraControl, catalog),
        camera_move_control=moves,
    )
    detail_path = f"/dashboard/cameras/{CAMERA_ID}"
    move_path = f"{detail_path}/move"

    detail = operator.get(detail_path, headers=operator_headers)
    move_form = operator.get(move_path, headers=operator_headers)
    denied = viewer.get(move_path, headers=viewer_headers)

    assert detail.status_code == 200
    assert f'href="{move_path}"' in detail.text
    assert move_form.status_code == 200
    assert 'name="target_node_id"' in move_form.text
    assert f'value="{moves.target.id}"' in move_form.text
    assert "edge &lt;south&gt;" in move_form.text
    assert "10 / 100" in move_form.text
    assert 'name="expected_revision" value="3"' in move_form.text
    assert catalog.source_url not in move_form.text
    assert "admin:secret" not in move_form.text
    assert denied.status_code == 403
    assert moves.calls == [("targets", CAMERA_ID, 3)]


def test_unoccupied_camera_move_uses_submitted_revision_and_starts_immediately() -> None:
    moves = RecordingCameraMoves(occupied=False)
    client, headers = _authenticated_dashboard(
        observations=None,
        camera_control=cast(CameraControl, StaticCameraCatalog()),
        camera_move_control=moves,
        role=OperatorRole.OPERATOR,
    )
    detail_path = f"/dashboard/cameras/{CAMERA_ID}"

    response = client.post(
        f"{detail_path}/moves/preview",
        headers=headers,
        data={
            "_csrf": CSRF_TOKEN,
            "target_node_id": str(moves.target.id),
            "expected_revision": "3",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    status_path = f"{detail_path}/moves/{moves.move.id}"
    assert response.headers["location"] == status_path
    assert moves.calls == [
        ("preview", CAMERA_ID, moves.target.id, 3),
        ("request", CAMERA_ID, moves.target.id, 3, False, None),
    ]


def test_occupied_camera_move_requires_exact_blast_radius_confirmation() -> None:
    catalog = StaticCameraCatalog()
    moves = RecordingCameraMoves(occupied=True)
    client, headers = _authenticated_dashboard(
        observations=None,
        camera_control=cast(CameraControl, catalog),
        camera_move_control=moves,
        role=OperatorRole.OPERATOR,
    )
    detail_path = f"/dashboard/cameras/{CAMERA_ID}"
    preview = client.post(
        f"{detail_path}/moves/preview",
        headers=headers,
        data={
            "_csrf": CSRF_TOKEN,
            "target_node_id": str(moves.target.id),
            "expected_revision": "3",
        },
    )
    applied = client.post(
        f"{detail_path}/moves/apply",
        headers=headers,
        data={
            "_csrf": CSRF_TOKEN,
            "target_node_id": str(moves.target.id),
            "expected_revision": "3",
            "confirmation_token": "move-confirmation-token",
        },
        follow_redirects=False,
    )

    assert preview.status_code == 200
    assert "Будет отключён 1 downstream-клиент" in preview.text
    assert 'role="alert" aria-live="assertive"' in preview.text
    assert '<h1 tabindex="-1" autofocus>Подтвердите перемещение</h1>' in preview.text
    assert "rtsp://&lt;server-address&gt;:10543/aaaaaaaaaaaaaaaaaaaaaaaaaa" in preview.text
    assert "rtsp://&lt;server-address&gt;:10544/aaaaaaaaaaaaaaaaaaaaaaaaaa" in preview.text
    assert 'value="move-confirmation-token"' in preview.text
    assert catalog.source_url not in preview.text
    assert applied.status_code == 303
    status_path = f"{detail_path}/moves/{moves.move.id}"
    assert applied.headers["location"] == status_path
    accepted = client.get(applied.headers["location"], headers=headers)
    assert accepted.status_code == 200
    assert "Запрос на перемещение принят" in accepted.text
    assert "prepare_target" in accepted.text
    assert catalog.source_url not in accepted.text
    assert moves.calls == [
        ("preview", CAMERA_ID, moves.target.id, 3),
        (
            "request",
            CAMERA_ID,
            moves.target.id,
            3,
            True,
            "move-confirmation-token",
        ),
    ]


def test_camera_move_status_is_authoritative_and_camera_scoped() -> None:
    catalog = StaticCameraCatalog()
    moves = RecordingCameraMoves(occupied=False)
    client, headers = _authenticated_dashboard(
        observations=None,
        camera_control=cast(CameraControl, catalog),
        camera_move_control=moves,
        role=OperatorRole.OPERATOR,
        scopes=frozenset({f"camera:{CAMERA_ID}"}),
    )
    detail_path = f"/dashboard/cameras/{CAMERA_ID}"
    forged_query = client.get(f"{detail_path}?move=requested", headers=headers)
    missing = client.get(
        f"{detail_path}/moves/00000000-0000-4000-8000-000000000000",
        headers=headers,
    )
    moves.move = replace(
        moves.move,
        camera_id=UUID("ffffffff-ffff-4fff-8fff-ffffffffffff"),
    )
    cross_camera = client.get(
        f"{detail_path}/moves/{moves.move.id}",
        headers=headers,
    )

    assert forged_query.status_code == 200
    assert "Запрос на перемещение принят" not in forged_query.text
    assert missing.status_code == 404
    assert cross_camera.status_code == 404
    assert missing.text == cross_camera.text
    assert catalog.source_url not in cross_camera.text


def test_camera_move_rejects_a_revision_stale_since_the_rendered_form() -> None:
    cameras, moves, store, _runtime = _domain_camera_moves(reader_count=0)
    client, headers = _authenticated_dashboard(
        observations=None,
        camera_control=cameras,
        camera_move_control=moves,
        role=OperatorRole.OPERATOR,
    )
    detail_path = f"/dashboard/cameras/{CAMERA_ID}"
    target_id = UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
    rendered = client.get(f"{detail_path}/move", headers=headers)
    assert 'name="expected_revision" value="1"' in rendered.text
    store.update_camera(
        CAMERA_ID,
        name="Concurrent rename",
        source_url="rtsp://camera.internal/main",
        expected_revision=1,
    )

    stale = client.post(
        f"{detail_path}/moves/preview",
        headers=headers,
        data={
            "_csrf": CSRF_TOKEN,
            "target_node_id": str(target_id),
            "expected_revision": "1",
        },
    )

    assert stale.status_code == 409
    assert "Ожидалась revision 1, текущая revision 2" in stale.text
    assert "rtsp://camera.internal/main" not in stale.text
    assert store.list_incomplete_camera_moves() == ()


def test_camera_move_confirmation_expires_when_reader_count_changes() -> None:
    cameras, moves, store, runtime = _domain_camera_moves(reader_count=1)
    client, headers = _authenticated_dashboard(
        observations=None,
        camera_control=cameras,
        camera_move_control=moves,
        role=OperatorRole.OPERATOR,
    )
    detail_path = f"/dashboard/cameras/{CAMERA_ID}"
    target_id = UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
    preview = client.post(
        f"{detail_path}/moves/preview",
        headers=headers,
        data={
            "_csrf": CSRF_TOKEN,
            "target_node_id": str(target_id),
            "expected_revision": "1",
        },
    )
    token_match = re.search(
        r'name="confirmation_token" value="([^"]+)"',
        preview.text,
    )
    assert token_match is not None
    runtime.reader_count = 0

    stale_blast_radius = client.post(
        f"{detail_path}/moves/apply",
        headers=headers,
        data={
            "_csrf": CSRF_TOKEN,
            "target_node_id": str(target_id),
            "expected_revision": "1",
            "confirmation_token": token_match.group(1),
        },
        follow_redirects=False,
    )

    assert stale_blast_radius.status_code == 409
    assert "Состояние камеры или число читателей изменилось" in stale_blast_radius.text
    assert store.list_incomplete_camera_moves() == ()


def test_dashboard_mutation_form_is_bounded_and_requires_control_mutate() -> None:
    viewer, viewer_headers = _authenticated_dashboard(
        observations=None,
        camera_control=cast(CameraControl, StaticCameraCatalog()),
        camera_mutation_control=RecordingCameraMutations(occupied=False),
    )
    operator, operator_headers = _authenticated_dashboard(
        observations=None,
        camera_control=cast(CameraControl, StaticCameraCatalog()),
        camera_mutation_control=RecordingCameraMutations(occupied=False),
        role=OperatorRole.OPERATOR,
    )
    path = f"/dashboard/cameras/{CAMERA_ID}/mutations/preview"

    denied = viewer.post(
        path,
        headers=viewer_headers,
        data={"_csrf": CSRF_TOKEN, "operation": "delete"},
    )
    duplicate_csrf = operator.post(
        path,
        headers={**operator_headers, "Content-Type": "application/x-www-form-urlencoded"},
        content=f"_csrf={CSRF_TOKEN}&_csrf={CSRF_TOKEN}&operation=delete",
    )
    oversized = operator.post(
        path,
        headers=operator_headers,
        data={"_csrf": CSRF_TOKEN, "operation": "delete", "padding": "x" * 40000},
    )

    assert denied.status_code == 403
    assert duplicate_csrf.status_code == 401
    assert oversized.status_code == 401
