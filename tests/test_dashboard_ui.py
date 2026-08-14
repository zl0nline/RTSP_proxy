from __future__ import annotations

import re
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID

from fastapi.testclient import TestClient

from rtsp_proxy.app import create_app
from rtsp_proxy.config import RuntimeRole, Settings
from rtsp_proxy.identifiers import PublicId
from rtsp_proxy.media import MediaPathConfig
from rtsp_proxy.nodes import (
    CameraCatalogItem,
    CameraCatalogPage,
    CameraCatalogQuery,
    CameraCatalogUnavailable,
    CameraControl,
    CameraState,
    InMemoryNodeStore,
    MediaNode,
    NodeHealth,
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
    CameraMutationControl,
    CameraMutationOperation,
    CameraMutationPreview,
    ConfirmationTokenService,
)

NOW = datetime(2026, 8, 14, 12, 0, tzinfo=UTC)
ACCOUNT_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
NODE_ID = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
CAMERA_ID = UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
CSRF_TOKEN = "c" * 43


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


def _authenticated_dashboard(
    *,
    observations: SnapshotReader | None,
    clock: datetime = NOW,
    raise_server_exceptions: bool = True,
    camera_control: CameraControl | None = None,
    camera_mutation_control: object | None = None,
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
            Settings(role=RuntimeRole.WEB),
            fleet_snapshots=observations,
            operator_sessions=sessions,
            fleet_snapshot_max_age_seconds=30,
            clock=lambda: clock,
            camera_control=camera_control,
            camera_mutation_control=cast(Any, camera_mutation_control),
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
