import pytest
from fastapi.testclient import TestClient

from rtsp_proxy.app import create_app
from rtsp_proxy.config import RuntimeRole, Settings
from rtsp_proxy.health import DependencyResult, ReadinessProvider
from rtsp_proxy.runtime import create_app_from_environment


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
                "name": "readiness",
                "status": "fail",
                "reason": "readiness_provider_missing",
            }
        ],
    }


def test_systemd_environment_selects_the_runtime_role(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RTSP_PROXY_ROLE", "web")

    app = create_app_from_environment()

    response = TestClient(app).get("/health/live")
    assert response.json() == {
        "status": "ok",
        "role": "web",
    }
