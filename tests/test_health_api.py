from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from rtsp_proxy.app import create_app
from rtsp_proxy.config import RuntimeRole, Settings
from rtsp_proxy.health import DependencyResult, ReadinessProvider
from rtsp_proxy.runtime import create_app_from_environment, create_background_app, load_settings


def test_live_reports_the_running_role_without_dependency_checks() -> None:
    app = create_app(Settings(role=RuntimeRole.WEB))

    response = TestClient(app).get("/health/live")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "role": "web",
    }


class DatabaseUnavailable(ReadinessProvider):
    async def check(self, role: RuntimeRole) -> tuple[DependencyResult, ...]:
        return (
            DependencyResult(
                name="database",
                ready=False,
                reason="database_unavailable",
            ),
        )


def test_ready_reports_a_stable_reason_without_dependency_details() -> None:
    app = create_app(
        Settings(role=RuntimeRole.WEB),
        readiness=DatabaseUnavailable(),
    )

    response = TestClient(app).get("/health/ready")

    assert response.status_code == 503
    assert response.json() == {
        "status": "not_ready",
        "role": "web",
        "checks": [
            {
                "name": "database",
                "status": "fail",
                "reason": "database_unavailable",
            },
            {
                "name": "schema",
                "status": "fail",
                "reason": "readiness_check_missing",
            },
            {
                "name": "session_store",
                "status": "fail",
                "reason": "readiness_check_missing",
            },
        ],
    }


def test_ready_fails_closed_until_the_role_dependencies_are_wired() -> None:
    app = create_app(Settings(role=RuntimeRole.WEB))

    response = TestClient(app).get("/health/ready")

    assert response.status_code == 503
    assert response.json() == {
        "status": "not_ready",
        "role": "web",
        "checks": [
            {
                "name": "database",
                "status": "fail",
                "reason": "database_provider_missing",
            },
            {
                "name": "schema",
                "status": "fail",
                "reason": "schema_provider_missing",
            },
            {
                "name": "session_store",
                "status": "fail",
                "reason": "session_store_provider_missing",
            },
        ],
    }


@pytest.mark.parametrize(
    ("role", "required_checks"),
    [
        (RuntimeRole.WEB, {"database", "schema", "session_store"}),
        (RuntimeRole.WORKER, {"database", "schema", "outbox"}),
        (RuntimeRole.RECONCILER, {"database", "schema", "media_adapter"}),
        (RuntimeRole.PROBE, {"database", "schema", "probe_runtime"}),
        (RuntimeRole.COLLECTOR, {"database", "schema", "media_metrics"}),
    ],
)
def test_unwired_readiness_names_the_dependencies_required_by_each_role(
    role: RuntimeRole,
    required_checks: set[str],
) -> None:
    response = TestClient(create_app(Settings(role=role))).get("/health/ready")

    assert response.status_code == 503
    assert {check["name"] for check in response.json()["checks"]} == required_checks


@pytest.mark.parametrize(
    ("provided", "expected_reason"),
    [
        ((), "readiness_check_missing"),
        (
            (
                DependencyResult(name="database", ready=True),
                DependencyResult(name="database", ready=True),
                DependencyResult(name="schema", ready=True),
                DependencyResult(name="session_store", ready=True),
            ),
            "readiness_check_duplicate",
        ),
        (
            (
                DependencyResult(name="database", ready=True),
                DependencyResult(name="schema", ready=True),
                DependencyResult(name="session_store", ready=True),
                DependencyResult(name="unknown", ready=True),
            ),
            "readiness_check_unexpected",
        ),
    ],
)
def test_readiness_rejects_missing_duplicate_or_unexpected_provider_checks(
    provided: tuple[DependencyResult, ...],
    expected_reason: str,
) -> None:
    class InvalidProvider(ReadinessProvider):
        async def check(self, role: RuntimeRole) -> tuple[DependencyResult, ...]:
            return provided

    response = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            readiness=InvalidProvider(),
        )
    ).get("/health/ready")

    assert response.status_code == 503
    assert expected_reason in {check["reason"] for check in response.json()["checks"]}


def test_systemd_environment_selects_the_runtime_role(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RTSP_PROXY_ROLE", "web")

    app = create_app_from_environment()

    response = TestClient(app).get("/health/live")
    assert response.json() == {
        "status": "ok",
        "role": "web",
    }


def test_http_runtime_configuration_is_typed_and_environment_driven() -> None:
    settings = load_settings(
        {
            "RTSP_PROXY_ROLE": "web",
            "RTSP_PROXY_HTTP_HOST": "127.0.0.2",
            "RTSP_PROXY_HTTP_PORT": "8080",
        }
    )

    assert str(settings.http_host) == "127.0.0.2"
    assert settings.http_port == 8080


def test_node_limits_and_port_range_are_environment_driven() -> None:
    settings = load_settings(
        {
            "RTSP_PROXY_ROLE": "web",
            "RTSP_PROXY_MAX_NODES": "100",
            "RTSP_PROXY_NODE_PORT_RANGE_START": "12000",
            "RTSP_PROXY_NODE_PORT_RANGE_END": "12199",
            "RTSP_PROXY_NODE_PORT_RESERVED": "12005,12007",
            "RTSP_PROXY_NODE_MANAGEMENT_FRESHNESS_SECONDS": "45",
        }
    )

    assert settings.max_nodes == 100
    assert settings.node_port_range_start == 12000
    assert settings.node_port_range_end == 12199
    assert settings.node_port_reserved == (12005, 12007)
    assert settings.node_management_freshness_seconds == 45


def test_node_port_configuration_requires_capacity_after_exclusions() -> None:
    with pytest.raises(ValidationError):
        Settings(
            role=RuntimeRole.WEB,
            max_nodes=2,
            node_port_range_start=12000,
            node_port_range_end=12001,
            node_port_reserved=(12000, 12001),
        )


def test_external_node_ports_cannot_overlap_the_control_listener() -> None:
    with pytest.raises(ValidationError):
        Settings(
            role=RuntimeRole.WEB,
            http_port=12000,
            max_nodes=1,
            node_port_range_start=12000,
            node_port_range_end=12000,
        )


def test_invalid_http_port_fails_startup_validation() -> None:
    with pytest.raises(ValidationError):
        load_settings(
            {
                "RTSP_PROXY_ROLE": "web",
                "RTSP_PROXY_HTTP_PORT": "70000",
            }
        )


def test_environment_overrides_a_validated_json_config_file(tmp_path: Path) -> None:
    config_file = tmp_path / "rtsp-proxy.json"
    config_file.write_text(
        '{"role":"worker","http_host":"127.0.0.3","http_port":8100}',
        encoding="utf-8",
    )

    settings = load_settings(
        {
            "RTSP_PROXY_CONFIG_FILE": str(config_file),
            "RTSP_PROXY_ROLE": "web",
            "RTSP_PROXY_HTTP_PORT": "8200",
        }
    )

    assert settings.role is RuntimeRole.WEB
    assert str(settings.http_host) == "127.0.0.3"
    assert settings.http_port == 8200


def test_background_entrypoint_accepts_only_non_web_roles() -> None:
    app = create_background_app(
        Settings(role=RuntimeRole.WORKER),
        expected_role=RuntimeRole.WORKER,
    )
    assert TestClient(app).get("/health/live").json()["role"] == "worker"

    with pytest.raises(ValueError, match="background_role_required"):
        create_background_app(
            Settings(role=RuntimeRole.WEB),
            expected_role=RuntimeRole.WEB,
        )


def test_background_entrypoint_fails_closed_when_config_changes_instance_role() -> None:
    with pytest.raises(ValueError, match="background_role_mismatch"):
        create_background_app(
            Settings(role=RuntimeRole.PROBE),
            expected_role=RuntimeRole.WORKER,
        )
