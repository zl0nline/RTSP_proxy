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
            }
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
