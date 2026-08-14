from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID

from fastapi.testclient import TestClient

from rtsp_proxy.app import create_app
from rtsp_proxy.config import RuntimeRole, Settings
from rtsp_proxy.identifiers import PublicId
from rtsp_proxy.nodes import (
    CameraCatalogItem,
    CameraCatalogPage,
    CameraCatalogQuery,
    CameraCatalogUnavailable,
    CameraControl,
    CameraState,
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

NOW = datetime(2026, 8, 14, 12, 0, tzinfo=UTC)
ACCOUNT_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
NODE_ID = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
CAMERA_ID = UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")


class StaticCameraCatalog:
    def __init__(self) -> None:
        self.last_query: CameraCatalogQuery | None = None
        self.source_url = "rtsp://admin:secret@camera.internal/private"

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


class FailingCameraCatalog:
    def catalog(self, _query: CameraCatalogQuery) -> CameraCatalogPage:
        raise CameraCatalogUnavailable("postgres password must not escape")

    def detail(self, _camera_id: UUID) -> CameraCatalogItem | None:
        raise CameraCatalogUnavailable("postgres password must not escape")


def _authenticated_dashboard(
    *,
    observations: SnapshotReader | None,
    clock: datetime = NOW,
    raise_server_exceptions: bool = True,
    camera_control: CameraControl | None = None,
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
        ),
        base_url="https://management.example.test",
        raise_server_exceptions=raise_server_exceptions,
    )
    return client, {"Cookie": f"__Host-rtsp_proxy_session={issued.session_token}"}


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
