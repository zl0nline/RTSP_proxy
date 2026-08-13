import json
import os
import platform
import stat
from pathlib import Path
from time import sleep
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from rtsp_proxy.app import create_app
from rtsp_proxy.config import RuntimeRole, Settings
from rtsp_proxy.health import DependencyResult, ReadinessProvider
from rtsp_proxy.release import trusted_mediamtx_identity
from rtsp_proxy.runtime import (
    ConfigurationError,
    _load_access_verifier,
    create_app_from_environment,
    create_background_app,
    load_settings,
)

TRUSTED_MEDIAMTX_SHA256 = trusted_mediamtx_identity(platform.machine())[1].root


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
        (RuntimeRole.AUTH, {"database", "schema", "pepper"}),
        (RuntimeRole.WORKER, {"database", "schema", "outbox"}),
        (RuntimeRole.RECONCILER, {"database", "schema", "media_adapter"}),
        (RuntimeRole.PROBE, {"database", "schema", "probe_runtime"}),
        (
            RuntimeRole.COLLECTOR,
            {"database", "schema", "media_metrics", "collector_store"},
        ),
    ],
)
def test_unwired_readiness_names_the_dependencies_required_by_each_role(
    role: RuntimeRole,
    required_checks: set[str],
) -> None:
    settings = Settings.model_construct(role=role)
    response = TestClient(create_app(settings)).get("/health/ready")

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
            "RTSP_PROXY_NODE_LIFECYCLE_LOCK_POOL_SIZE": "6",
            "RTSP_PROXY_NODE_LIFECYCLE_LOCK_TIMEOUT_SECONDS": "7",
        }
    )

    assert settings.max_nodes == 100
    assert settings.node_port_range_start == 12000
    assert settings.node_port_range_end == 12199
    assert settings.node_port_reserved == (12005, 12007)
    assert settings.node_management_freshness_seconds == 45
    assert settings.node_lifecycle_lock_pool_size == 6
    assert settings.node_lifecycle_lock_timeout_seconds == 7


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


def test_node_external_api_metrics_and_control_ports_must_be_disjoint() -> None:
    with pytest.raises(ValidationError, match="node_port_ranges_overlap"):
        Settings(
            role=RuntimeRole.WEB,
            node_port_range_start=12000,
            node_port_range_end=12010,
            node_api_port_range_start=12010,
            node_api_port_range_end=12109,
        )

    with pytest.raises(ValidationError, match="node_port_ranges_overlap"):
        Settings(
            role=RuntimeRole.WEB,
            node_api_port_range_start=20000,
            node_api_port_range_end=20099,
            node_metrics_port_range_start=20099,
            node_metrics_port_range_end=20199,
        )

    with pytest.raises(ValidationError, match="node_port_range_overlaps_control_port"):
        Settings(
            role=RuntimeRole.WEB,
            http_port=20000,
            node_api_port_range_start=20000,
            node_api_port_range_end=20099,
        )


def test_reserved_host_ports_cannot_remain_in_a_management_range() -> None:
    with pytest.raises(ValidationError, match="node_management_port_reserved"):
        Settings(
            role=RuntimeRole.WEB,
            node_port_reserved=(20001,),
        )


def test_smtp_configuration_requires_complete_verified_starttls_paths(tmp_path: Path) -> None:
    password = tmp_path / "smtp-password"
    configured = {
        "role": RuntimeRole.WORKER,
        "database_url": "postgresql+psycopg://db.invalid/rtsp_proxy",
        "smtp_host": "smtp.example.test",
        "smtp_username": "mailer",
        "smtp_password_file": password,
        "smtp_from_address": "proxy@example.test",
        "smtp_to_address": "operator@example.test",
    }
    with pytest.raises(ValidationError, match="smtp_configuration_incomplete"):
        Settings(
            role=RuntimeRole.WORKER,
            database_url="postgresql+psycopg://db.invalid/rtsp_proxy",
            smtp_ca_file=tmp_path / "ca.pem",
        )
    with pytest.raises(ValidationError, match="smtp_configuration_incomplete"):
        Settings(
            role=RuntimeRole.WORKER,
            database_url="postgresql+psycopg://db.invalid/rtsp_proxy",
            smtp_host="smtp.example.test",
        )
    with pytest.raises(ValidationError, match="smtp_starttls_required"):
        Settings(**configured, smtp_starttls=False)  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="smtp_password_file_must_be_absolute"):
        Settings(**(configured | {"smtp_password_file": Path("relative")}))  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="smtp_ca_file_must_be_absolute"):
        Settings(**configured, smtp_ca_file=Path("relative"))  # type: ignore[arg-type]

    settings = Settings(**configured, smtp_ca_file=tmp_path / "ca.pem")  # type: ignore[arg-type]
    assert settings.smtp_starttls


def test_enabling_the_privileged_node_runtime_requires_pinned_release_identity() -> None:
    with pytest.raises(ValidationError, match="node_release_identity_required"):
        Settings(
            role=RuntimeRole.WEB,
            node_runtime_socket=Path("/run/rtsp-proxy-node-runtime/control.sock"),
        )
    with pytest.raises(ValidationError, match="node_release_identity_untrusted"):
        Settings(
            role=RuntimeRole.RECONCILER,
            database_url="postgresql+psycopg://db.invalid/rtsp_proxy",
            node_runtime_socket=Path("/run/rtsp-proxy-node-runtime/control.sock"),
            node_mediamtx_binary_sha256="a" * 64,
        )

    settings = Settings(
        role=RuntimeRole.WEB,
        node_runtime_socket=Path("/run/rtsp-proxy-node-runtime/control.sock"),
        node_mediamtx_binary_sha256=TRUSTED_MEDIAMTX_SHA256,
        confirmation_secret="test-confirmation-secret-that-is-at-least-43-bytes",
    )

    assert settings.node_release_id == "0.2.1"

    reconciler = Settings(
        role=RuntimeRole.RECONCILER,
        database_url="postgresql+psycopg://db.invalid/rtsp_proxy",
        node_runtime_socket=Path("/run/rtsp-proxy-node-runtime/control.sock"),
        node_mediamtx_binary_sha256=TRUSTED_MEDIAMTX_SHA256,
    )
    assert reconciler.confirmation_secret is None


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


def test_access_pepper_file_is_private_bounded_and_supports_key_rotation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pepper_file = tmp_path / "access-peppers.json"
    pepper_file.write_text(
        json.dumps(
            {
                "primary_key_id": "new",
                "keys": {"new": "11" * 32, "old": "22" * 32},
            }
        ),
        encoding="utf-8",
    )
    pepper_file.chmod(0o640)
    real_fstat = __import__("os").fstat
    monkeypatch.setattr(
        "rtsp_proxy.access.os.fstat",
        lambda descriptor: _owned_by_root(real_fstat(descriptor), gid=54321),
    )
    monkeypatch.setattr(
        "rtsp_proxy.access.grp.getgrnam",
        lambda _name: SimpleNamespace(gr_gid=54321),
    )
    settings = Settings(
        role=RuntimeRole.AUTH,
        database_url="postgresql+psycopg://db.invalid/rtsp_proxy",
        access_pepper_file=pepper_file,
    )
    loaded = _load_access_verifier(settings)
    assert loaded.primary_key_id == "new"
    assert loaded.verify(
        "token",
        expected=loaded.digest("token", key_id="old"),
        key_id="old",
    )

    pepper_file.chmod(0o644)
    with pytest.raises(ConfigurationError, match="access_pepper_file_unsafe"):
        _load_access_verifier(settings)

    pepper_file.unlink()
    pepper_file.write_text(
        json.dumps({"primary_key_id": "new", "keys": {"new": "11" * 32}}),
        encoding="utf-8",
    )
    pepper_file.chmod(0o640)
    monkeypatch.setattr(
        "rtsp_proxy.access.os.fstat",
        lambda descriptor: _owned_by_root(real_fstat(descriptor), gid=99999),
    )
    with pytest.raises(ConfigurationError, match="access_pepper_file_unsafe"):
        _load_access_verifier(settings)
    monkeypatch.setattr(
        "rtsp_proxy.access.os.fstat",
        lambda descriptor: _owned_by_root(real_fstat(descriptor), gid=54321),
    )
    pepper_file.chmod(0o640)
    pepper_file.write_text("{}", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="access_pepper_file_unsafe"):
        _load_access_verifier(settings)
    pepper_file.unlink()
    pepper_file.write_bytes(b"x" * 4097)
    pepper_file.chmod(0o640)
    with pytest.raises(ConfigurationError, match="access_pepper_file_unsafe"):
        _load_access_verifier(settings)
    pepper_file.unlink()
    pepper_file.symlink_to(Path("/dev/null"))
    with pytest.raises(ConfigurationError, match="access_pepper_file_unsafe"):
        _load_access_verifier(settings)


def test_access_pepper_loader_rejects_non_regular_and_oversized_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pepper_file = tmp_path / "access-peppers.json"
    pepper_file.mkdir(mode=0o700)
    settings = Settings(
        role=RuntimeRole.AUTH,
        database_url="postgresql+psycopg://db.invalid/rtsp_proxy",
        access_pepper_file=pepper_file,
    )
    assert stat.S_ISDIR(pepper_file.stat().st_mode)
    real_fstat = __import__("os").fstat
    monkeypatch.setattr(
        "rtsp_proxy.access.os.fstat",
        lambda descriptor: _owned_by_root(real_fstat(descriptor), gid=54321),
    )
    monkeypatch.setattr(
        "rtsp_proxy.access.grp.getgrnam",
        lambda _name: SimpleNamespace(gr_gid=54321),
    )
    with pytest.raises(ConfigurationError, match="access_pepper_file_unsafe"):
        _load_access_verifier(settings)
    pepper_file.rmdir()
    pepper_file.write_bytes(b"x" * 4097)
    pepper_file.chmod(0o640)
    with pytest.raises(ConfigurationError, match="access_pepper_file_unsafe"):
        _load_access_verifier(settings)


def _owned_by_root(value: os.stat_result, *, gid: int) -> object:
    return SimpleNamespace(
        st_mode=value.st_mode,
        st_nlink=value.st_nlink,
        st_uid=0,
        st_gid=gid,
        st_size=value.st_size,
    )


def test_background_entrypoint_accepts_only_non_web_roles() -> None:
    with pytest.raises(ValidationError, match="database_url_required"):
        Settings(role=RuntimeRole.WORKER)

    with pytest.raises(ValueError, match="background_role_required"):
        create_background_app(
            Settings(role=RuntimeRole.WEB),
            expected_role=RuntimeRole.WEB,
        )


def test_background_entrypoint_fails_closed_when_config_changes_instance_role() -> None:
    with pytest.raises(ValueError, match="background_role_mismatch"):
        create_background_app(
            Settings(
                role=RuntimeRole.RECONCILER,
                database_url="postgresql+psycopg://db.invalid/rtsp_proxy",
                node_runtime_socket=Path("/run/missing.sock"),
                node_mediamtx_binary_sha256=TRUSTED_MEDIAMTX_SHA256,
            ),
            expected_role=RuntimeRole.WORKER,
        )


@pytest.mark.parametrize(
    ("role", "values", "reason"),
    [
        (RuntimeRole.COLLECTOR, {}, "database_url_required"),
        (
            RuntimeRole.COLLECTOR,
            {"database_url": "postgresql+psycopg://db/rtsp_proxy"},
            "node_runtime_socket_required",
        ),
        (
            RuntimeRole.WORKER,
            {"database_url": "postgresql+psycopg://db/rtsp_proxy"},
            "smtp_configuration_required",
        ),
    ],
)
def test_background_roles_fail_fast_when_required_dependencies_are_missing(
    role: RuntimeRole,
    values: dict[str, object],
    reason: str,
) -> None:
    with pytest.raises(ValidationError, match=reason):
        Settings.model_validate({"role": role, **values})


def test_reconciler_background_role_starts_and_stops_its_bounded_loop(
    postgres_database_url: str,
) -> None:
    from pathlib import Path

    from rtsp_proxy.migrate import upgrade_database

    upgrade_database(postgres_database_url)
    app = create_background_app(
        Settings(
            role=RuntimeRole.RECONCILER,
            database_url=postgres_database_url,
            node_runtime_socket=Path("/run/missing-helper.sock"),
            node_mediamtx_binary_sha256=TRUSTED_MEDIAMTX_SHA256,
            reconcile_interval_seconds=0.1,
        ),
        expected_role=RuntimeRole.RECONCILER,
    )

    with TestClient(app) as client:
        assert client.get("/health/live").status_code == 200


def test_collector_background_role_starts_and_persists_empty_fleet_snapshot(
    postgres_database_url: str,
) -> None:
    from rtsp_proxy.migrate import upgrade_database
    from rtsp_proxy.observability import PostgresObservabilityStore

    upgrade_database(postgres_database_url)
    app = create_background_app(
        Settings(
            role=RuntimeRole.COLLECTOR,
            database_url=postgres_database_url,
            node_runtime_socket=Path("/run/rtsp-proxy-node-metrics/metrics.sock"),
            node_runtime_timeout_seconds=2,
            node_mediamtx_binary_sha256=TRUSTED_MEDIAMTX_SHA256,
            collector_interval_seconds=1,
        ),
        expected_role=RuntimeRole.COLLECTOR,
    )

    observations = PostgresObservabilityStore(postgres_database_url)
    try:
        with TestClient(app) as client:
            assert client.get("/health/live").json()["role"] == "collector"
            snapshot = None
            for _ in range(20):
                snapshot = observations.current_snapshot()
                if snapshot is not None:
                    break
                sleep(0.05)
    finally:
        observations.close()
    assert snapshot is not None
    assert snapshot.configured_nodes == 0


def test_observability_roles_require_current_schema_after_bridge_deployment(
    postgres_database_url: str,
) -> None:
    from alembic import command
    from alembic.config import Config

    migration = Config("alembic.ini")
    migration.set_main_option("sqlalchemy.url", postgres_database_url)
    command.upgrade(migration, "0011_observability")

    with pytest.raises(RuntimeError, match="database_schema_mismatch"):
        create_background_app(
            Settings(
                role=RuntimeRole.COLLECTOR,
                database_url=postgres_database_url,
                node_runtime_socket=Path("/run/missing.sock"),
                node_mediamtx_binary_sha256=TRUSTED_MEDIAMTX_SHA256,
            ),
            expected_role=RuntimeRole.COLLECTOR,
        )


def test_notification_background_role_starts_without_plaintext_secret_env(
    postgres_database_url: str,
    tmp_path: Path,
) -> None:
    from rtsp_proxy.migrate import upgrade_database

    upgrade_database(postgres_database_url)
    app = create_background_app(
        Settings(
            role=RuntimeRole.WORKER,
            database_url=postgres_database_url,
            smtp_host="smtp.example.test",
            smtp_username="mailer",
            smtp_password_file=tmp_path / "systemd-credential-smtp-password",
            smtp_from_address="proxy@example.test",
            smtp_to_address="operator@example.test",
            smtp_timeout_seconds=1,
        ),
        expected_role=RuntimeRole.WORKER,
    )

    with TestClient(app) as client:
        assert client.get("/health/live").json()["role"] == "worker"
