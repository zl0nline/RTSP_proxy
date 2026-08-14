from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi.testclient import TestClient

from rtsp_proxy.app import create_app
from rtsp_proxy.config import RuntimeRole, Settings
from rtsp_proxy.nodes import NodeHealth, NodeState
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


def _authenticated_dashboard(
    *,
    observations: SnapshotReader | None,
    clock: datetime = NOW,
    raise_server_exceptions: bool = True,
) -> tuple[TestClient, dict[str, str]]:
    account = OperatorAccount(
        identity_source=OperatorIdentitySource.OIDC,
        id=ACCOUNT_ID,
        subject="oidc:viewer@example.test",
        display_name="Дежурный <script>alert(1)</script>",
        roles=frozenset({OperatorRole.VIEWER}),
        scopes=frozenset({"server:*"}),
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
