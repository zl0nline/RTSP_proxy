import asyncio
import base64
import json
import os
import platform
import socket
import stat
from concurrent.futures import ThreadPoolExecutor
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from threading import Thread
from time import sleep
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from joserfc.jwk import RSAKey
from pydantic import ValidationError
from sqlalchemy import create_engine, text

from rtsp_proxy.app import create_app
from rtsp_proxy.config import RuntimeRole, Settings
from rtsp_proxy.health import DependencyResult, ReadinessProvider, RoleReadinessProvider
from rtsp_proxy.migrate import upgrade_database
from rtsp_proxy.operator_access import (
    OperatorAccount,
    OperatorIdentitySource,
    OperatorMutationContext,
    OperatorRole,
)
from rtsp_proxy.operator_identity import BreakGlassCredentials, PostgresBreakGlassStore
from rtsp_proxy.release import trusted_mediamtx_identity
from rtsp_proxy.runtime import (
    ConfigurationError,
    _dispatch_notification_fairly,
    _load_access_verifier,
    _open_operator_security,
    create_app_from_environment,
    create_background_app,
    load_settings,
    run_auth,
    run_background,
    run_web,
)

TRUSTED_MEDIAMTX_SHA256 = trusted_mediamtx_identity(platform.machine())[1].root


def test_operator_security_refuses_disabled_or_invalid_local_auth(
    tmp_path: Path,
) -> None:
    with pytest.raises(ConfigurationError, match="operator_auth_configuration_incomplete"):
        _open_operator_security(Settings(role=RuntimeRole.WEB))

    invalid_key = tmp_path / "local-auth-key"
    invalid_key.write_text("invalid-key")
    invalid_key.chmod(0o600)
    settings = Settings(
        role=RuntimeRole.WEB,
        database_url="postgresql+psycopg://unused",
        local_auth_enabled=True,
        local_auth_encryption_key_file=invalid_key,
    )
    with pytest.raises(ConfigurationError, match="operator_auth_file_invalid"):
        _open_operator_security(settings)


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
            {
                "name": "probe_observations",
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
            {
                "name": "probe_observations",
                "status": "fail",
                "reason": "probe_observations_provider_missing",
            },
        ],
    }


@pytest.mark.parametrize(
    ("role", "required_checks"),
    [
        (
            RuntimeRole.WEB,
            {"database", "schema", "session_store", "probe_observations"},
        ),
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
                DependencyResult(name="probe_observations", ready=True),
            ),
            "readiness_check_duplicate",
        ),
        (
            (
                DependencyResult(name="database", ready=True),
                DependencyResult(name="schema", ready=True),
                DependencyResult(name="session_store", ready=True),
                DependencyResult(name="probe_observations", ready=True),
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


def test_sync_readiness_probes_do_not_block_the_asgi_event_loop() -> None:
    def bounded_blocking_probe() -> None:
        with pytest.raises(RuntimeError, match="no running event loop"):
            asyncio.get_running_loop()

    response = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            readiness=RoleReadinessProvider(
                {
                    "database": bounded_blocking_probe,
                    "schema": bounded_blocking_probe,
                    "session_store": bounded_blocking_probe,
                    "probe_observations": bounded_blocking_probe,
                }
            ),
        )
    ).get("/health/ready")

    assert response.status_code == 200


def test_systemd_environment_selects_the_runtime_role(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RTSP_PROXY_ROLE", "web")

    app = create_app_from_environment()

    response = TestClient(app).get("/health/live")
    assert response.json() == {
        "status": "ok",
        "role": "web",
    }


def test_notification_worker_alternates_between_security_and_incident_queues() -> None:
    calls: list[str] = []

    class Dispatcher:
        def __init__(self, name: str) -> None:
            self.name = name

        def run_once(self) -> object:
            calls.append(self.name)
            return object()

    security = Dispatcher("security")
    incident = Dispatcher("incident")

    first, prefer_security = _dispatch_notification_fairly(
        security_dispatcher=security,
        incident_dispatcher=incident,
        prefer_security=True,
    )
    second, prefer_security = _dispatch_notification_fairly(
        security_dispatcher=security,
        incident_dispatcher=incident,
        prefer_security=prefer_security,
    )

    assert first is not None
    assert second is not None
    assert calls == ["security", "incident"]
    assert prefer_security is True


def test_web_bridge_is_ready_with_operator_authentication_disabled(
    postgres_database_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from alembic import command
    from alembic.config import Config

    migration = Config("alembic.ini")
    migration.set_main_option("sqlalchemy.url", postgres_database_url)
    command.upgrade(migration, "0012_operator_sessions")

    monkeypatch.setenv("RTSP_PROXY_ROLE", "web")
    monkeypatch.setenv("RTSP_PROXY_DATABASE_URL", postgres_database_url)
    app = create_app_from_environment()

    with TestClient(app) as client:
        response = client.get("/health/ready")

    assert response.status_code == 200
    assert {item["name"]: item["status"] for item in response.json()["checks"]} == {
        "database": "pass",
        "schema": "pass",
        "session_store": "pass",
        "probe_observations": "pass",
    }


def test_current_web_readiness_fails_closed_on_probe_schema_drift(
    postgres_database_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from rtsp_proxy.migrate import upgrade_database

    upgrade_database(postgres_database_url)
    monkeypatch.setenv("RTSP_PROXY_ROLE", "web")
    monkeypatch.setenv("RTSP_PROXY_DATABASE_URL", postgres_database_url)
    app = create_app_from_environment()

    with TestClient(app) as client:
        ready = client.get("/health/ready")
        assert ready.status_code == 200
        assert {item["name"]: item["status"] for item in ready.json()["checks"]} == {
            "database": "pass",
            "schema": "pass",
            "session_store": "pass",
            "probe_observations": "pass",
        }
        engine = create_engine(postgres_database_url)
        with engine.begin() as connection:
            connection.execute(
                text(
                    "ALTER TABLE probe_observations DROP CONSTRAINT "
                    "ck_probe_observations_result"
                )
            )
        drifted = client.get("/health/ready")

    assert drifted.status_code == 503
    assert drifted.json()["checks"][-1] == {
        "name": "probe_observations",
        "status": "fail",
        "reason": "probe_observations_unavailable",
    }


def test_http_runtime_configuration_is_typed_and_environment_driven() -> None:
    settings = load_settings(
        {
            "RTSP_PROXY_ROLE": "web",
            "RTSP_PROXY_HTTP_HOST": "127.0.0.2",
            "RTSP_PROXY_HTTP_PORT": "8080",
            "RTSP_PROXY_DASHBOARD_POLL_INTERVAL_SECONDS": "15",
            "RTSP_PROXY_PROBE_SOURCE_SITE_KEY": "moscow-a",
            "RTSP_PROXY_PROBE_SOURCE_CIDRS": "10.50.0.0/16,2001:db8:50::/48",
        }
    )

    assert str(settings.http_host) == "127.0.0.2"
    assert settings.http_port == 8080
    assert settings.dashboard_poll_interval_seconds == 15
    assert settings.probe_source_site_key == "moscow-a"
    assert tuple(str(network) for network in settings.probe_source_cidrs) == (
        "10.50.0.0/16",
        "2001:db8:50::/48",
    )


def test_probe_source_policy_defaults_to_explicit_deny_all() -> None:
    settings = Settings(role=RuntimeRole.WEB)

    assert settings.probe_source_site_key == "local"
    assert settings.probe_source_cidrs == ()


def test_probe_source_cidrs_have_one_canonical_nested_order() -> None:
    first = load_settings(
        {
            "RTSP_PROXY_ROLE": "web",
            "RTSP_PROXY_PROBE_SOURCE_CIDRS": "10.0.0.0/8,10.0.0.0/16",
        }
    )
    second = load_settings(
        {
            "RTSP_PROXY_ROLE": "web",
            "RTSP_PROXY_PROBE_SOURCE_CIDRS": "10.0.0.0/16,10.0.0.0/8",
        }
    )

    assert first.probe_source_cidrs == second.probe_source_cidrs


@pytest.mark.parametrize("poll_interval", (4, 31))
def test_dashboard_poll_interval_is_bounded(poll_interval: int) -> None:
    with pytest.raises(ValidationError):
        Settings(
            role=RuntimeRole.WEB,
            dashboard_poll_interval_seconds=poll_interval,
        )


def test_management_lan_bind_requires_a_complete_tls_identity(tmp_path: Path) -> None:
    certificate = tmp_path / "management-tls.crt"
    private_key = tmp_path / "management-tls.key"

    with pytest.raises(ValidationError, match="management_tls_required_for_non_loopback"):
        Settings(role=RuntimeRole.WEB, http_host=IPv4Address("192.0.2.10"))
    with pytest.raises(ValidationError, match="management_tls_configuration_incomplete"):
        Settings(
            role=RuntimeRole.WEB,
            management_tls_certificate_file=certificate,
        )
    with pytest.raises(ValidationError, match="management_tls_file_must_be_absolute"):
        Settings(
            role=RuntimeRole.WEB,
            management_tls_certificate_file=Path("management-tls.crt"),
            management_tls_private_key_file=Path("management-tls.key"),
        )

    settings = Settings(
        role=RuntimeRole.WEB,
        http_host=IPv4Address("192.0.2.10"),
        management_tls_certificate_file=certificate,
        management_tls_private_key_file=private_key,
    )

    assert settings.management_tls_certificate_file == certificate
    assert settings.management_tls_private_key_file == private_key


@pytest.mark.parametrize(
    "host",
    (
        IPv4Address("0.0.0.0"),
        IPv4Address("255.255.255.255"),
        IPv6Address("::"),
        IPv4Address("224.0.0.1"),
        IPv6Address("ff02::1"),
    ),
)
def test_management_listener_requires_one_specific_interface_address(
    host: IPv4Address | IPv6Address,
    tmp_path: Path,
) -> None:
    with pytest.raises(ValidationError, match="management_host_must_be_specific"):
        Settings(
            role=RuntimeRole.WEB,
            http_host=host,
            management_tls_certificate_file=tmp_path / "management-tls.crt",
            management_tls_private_key_file=tmp_path / "management-tls.key",
        )


def test_management_hsts_covers_unexpected_server_errors(tmp_path: Path) -> None:
    app = create_app(
        Settings(
            role=RuntimeRole.WEB,
            management_tls_certificate_file=tmp_path / "management-tls.crt",
            management_tls_private_key_file=tmp_path / "management-tls.key",
        )
    )

    @app.get("/unexpected-error")
    def unexpected_error() -> None:
        raise RuntimeError("operator-visible details must not escape")

    response = TestClient(app, raise_server_exceptions=False).get("/unexpected-error")

    assert response.status_code == 500
    assert response.headers["Strict-Transport-Security"] == "max-age=31536000"
    assert "operator-visible" not in response.text


def test_operator_login_configuration_is_all_or_nothing_and_https_only(
    tmp_path: Path,
) -> None:
    configured = {
        "role": RuntimeRole.WEB,
        "database_url": "postgresql+psycopg://rtsp_proxy@127.0.0.1/rtsp_proxy",
        "oidc_issuer": "https://idp.example.test",
        "oidc_client_id": "rtsp-proxy",
        "oidc_authorization_endpoint": "https://idp.example.test/oauth2/authorize",
        "oidc_token_endpoint": "https://idp.example.test/oauth2/token",
        "oidc_jwks_file": tmp_path / "oidc-jwks.json",
        "oidc_redirect_uri": "https://management.example.test/auth/oidc/callback",
        "oidc_client_secret_file": tmp_path / "oidc-client-secret",
        "oidc_derivation_key_file": tmp_path / "oidc-derivation-key",
        "oidc_group_roles_file": tmp_path / "oidc-group-roles.json",
        "oidc_mfa_acr": ("urn:example:loa:2",),
        "oidc_mfa_amr": ("otp", "pwd"),
        "break_glass_encryption_key_file": tmp_path / "break-glass-key",
    }

    settings = Settings(**configured)  # type: ignore[arg-type]

    assert settings.operator_auth_enabled is True
    with pytest.raises(ValidationError, match="operator_auth_configuration_incomplete"):
        Settings(**(configured | {"oidc_token_endpoint": None}))  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="oidc_endpoint_must_be_https"):
        Settings(
            **(configured | {"oidc_issuer": "http://idp.example.test"})  # type: ignore[arg-type]
        )
    with pytest.raises(ValidationError, match="operator_auth_requires_database"):
        Settings(**(configured | {"database_url": None}))  # type: ignore[arg-type]


def test_web_runtime_wires_oidc_sessions_readiness_and_durable_flow_from_environment(
    postgres_database_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from rtsp_proxy.migrate import upgrade_database

    upgrade_database(postgres_database_url)
    break_glass = PostgresBreakGlassStore(
        postgres_database_url,
        encryption_key=b"K" * 32,
    )
    break_glass.provision(
        account=OperatorAccount(
            id=UUID("60000000-0000-0000-0000-000000000006"),
            identity_source=OperatorIdentitySource.BREAK_GLASS,
            subject="local:emergency-admin",
            display_name="Emergency administrator",
            roles=frozenset({OperatorRole.BREAK_GLASS}),
            scopes=frozenset({"server:*"}),
            authz_version=1,
            enabled=True,
        ),
        password_scrypt=BreakGlassCredentials.hash_password(
            "correct horse battery staple",
            salt=b"S" * 16,
        ),
        totp_secret=b"B" * 20,
        context=OperatorMutationContext(
            actor="system:test-bootstrap",
            reason="test fixture provisioning",
        ),
    )
    break_glass.close()
    key = RSAKey.generate_key(2048, {"kid": "idp-key-1", "use": "sig"}, auto_kid=False)
    files = {
        "RTSP_PROXY_OIDC_JWKS_FILE": (
            tmp_path / "oidc-jwks.json",
            json.dumps({"keys": [key.as_dict(private=False)]}).encode("utf-8"),
        ),
        "RTSP_PROXY_OIDC_CLIENT_SECRET_FILE": (
            tmp_path / "oidc-client-secret",
            b"client-secret\n",
        ),
        "RTSP_PROXY_OIDC_DERIVATION_KEY_FILE": (
            tmp_path / "oidc-derivation-key",
            base64.urlsafe_b64encode(b"D" * 32).rstrip(b"=") + b"\n",
        ),
        "RTSP_PROXY_OIDC_GROUP_ROLES_FILE": (
            tmp_path / "oidc-group-roles.json",
            b'{"rtsp-operators":["operator"]}',
        ),
        "RTSP_PROXY_BREAK_GLASS_ENCRYPTION_KEY_FILE": (
            tmp_path / "break-glass-key",
            base64.urlsafe_b64encode(b"K" * 32).rstrip(b"=") + b"\n",
        ),
    }
    for environment_name, (path, payload) in files.items():
        path.write_bytes(payload)
        path.chmod(0o600)
        monkeypatch.setenv(environment_name, str(path))
    real_fstat = os.fstat
    monkeypatch.setattr(
        "rtsp_proxy.operator_identity.os.fstat",
        lambda descriptor: SimpleNamespace(
            st_mode=real_fstat(descriptor).st_mode,
            st_nlink=real_fstat(descriptor).st_nlink,
            st_uid=os.geteuid(),
            st_gid=0,
            st_size=real_fstat(descriptor).st_size,
        ),
    )
    readiness_probe_calls = {"discovery": 0, "token": 0}

    def discovery_ready(_endpoint: object) -> None:
        readiness_probe_calls["discovery"] += 1

    def token_ready(_endpoint: object) -> None:
        readiness_probe_calls["token"] += 1

    monkeypatch.setattr(
        "rtsp_proxy.operator_identity.HttpsOidcTokenEndpoint.assert_ready",
        token_ready,
    )
    monkeypatch.setattr(
        "rtsp_proxy.operator_identity.HttpsOidcDiscoveryEndpoint.assert_ready",
        discovery_ready,
    )
    environment = {
        "RTSP_PROXY_ROLE": "web",
        "RTSP_PROXY_DATABASE_URL": postgres_database_url,
        "RTSP_PROXY_OIDC_ISSUER": "https://idp.example.test",
        "RTSP_PROXY_OIDC_CLIENT_ID": "rtsp-proxy",
        "RTSP_PROXY_OIDC_AUTHORIZATION_ENDPOINT": ("https://idp.example.test/oauth2/authorize"),
        "RTSP_PROXY_OIDC_TOKEN_ENDPOINT": "https://idp.example.test/oauth2/token",
        "RTSP_PROXY_OIDC_REDIRECT_URI": ("https://management.example.test/auth/oidc/callback"),
        "RTSP_PROXY_OIDC_MFA_ACR": "urn:example:loa:2",
        "RTSP_PROXY_OIDC_MFA_AMR": "pwd,otp",
    }
    for name, value in environment.items():
        monkeypatch.setenv(name, value)

    with TestClient(
        create_app_from_environment(),
        base_url="https://management.example.test",
    ) as client:
        with ThreadPoolExecutor(max_workers=16) as executor:
            readiness_responses = tuple(
                executor.map(lambda _index: client.get("/health/ready"), range(32))
            )
        readiness = readiness_responses[0]
        redirect = client.get("/auth/oidc/login", follow_redirects=False)
        anonymous = client.get("/api/v1/nodes")

    assert all(response.status_code == 200 for response in readiness_responses)
    assert readiness_probe_calls == {"discovery": 1, "token": 1}
    assert {item["name"]: item["status"] for item in readiness.json()["checks"]} == {
        "database": "pass",
        "schema": "pass",
        "session_store": "pass",
        "probe_observations": "pass",
    }
    assert redirect.status_code == 303
    assert redirect.headers["location"].startswith("https://idp.example.test/oauth2/authorize?")
    assert anonymous.status_code == 401
    engine = create_engine(postgres_database_url, hide_parameters=True)
    with engine.connect() as connection:
        flow = connection.execute(
            text("SELECT state_sha256, consumed_at FROM oidc_login_flows")
        ).one()
        claim_transition_alerts = connection.scalar(
            text(
                "SELECT count(*) FROM operator_security_alerts "
                "WHERE event_type = 'operator.oidc_claim_contract'"
            )
        )
    engine.dispose()
    assert len(flow.state_sha256) == 64
    assert flow.consumed_at is None
    assert claim_transition_alerts == 0


def test_web_runtime_rejects_malformed_operator_credentials_before_serving(
    postgres_database_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from rtsp_proxy.migrate import upgrade_database

    upgrade_database(postgres_database_url)
    key = RSAKey.generate_key(2048, {"kid": "idp-key-1", "use": "sig"}, auto_kid=False)
    paths = {
        "client_secret": tmp_path / "oidc-client-secret",
        "derivation": tmp_path / "oidc-derivation-key",
        "encryption": tmp_path / "break-glass-key",
        "jwks": tmp_path / "oidc-jwks.json",
        "roles": tmp_path / "oidc-group-roles.json",
    }
    valid_payloads = {
        "client_secret": b"client-secret\n",
        "derivation": base64.urlsafe_b64encode(b"D" * 32).rstrip(b"=") + b"\n",
        "encryption": base64.urlsafe_b64encode(b"K" * 32).rstrip(b"=") + b"\n",
        "jwks": json.dumps({"keys": [key.as_dict(private=False)]}).encode(),
        "roles": b'{"rtsp-operators":["operator"]}',
    }
    for name, path in paths.items():
        path.write_bytes(valid_payloads[name])
        path.chmod(0o600)

    real_fstat = os.fstat
    monkeypatch.setattr(
        "rtsp_proxy.operator_identity.os.fstat",
        lambda descriptor: SimpleNamespace(
            st_mode=real_fstat(descriptor).st_mode,
            st_nlink=real_fstat(descriptor).st_nlink,
            st_uid=os.geteuid(),
            st_gid=0,
            st_size=real_fstat(descriptor).st_size,
        ),
    )
    environment = {
        "RTSP_PROXY_ROLE": "web",
        "RTSP_PROXY_DATABASE_URL": postgres_database_url,
        "RTSP_PROXY_OIDC_ISSUER": "https://idp.example.test",
        "RTSP_PROXY_OIDC_CLIENT_ID": "rtsp-proxy",
        "RTSP_PROXY_OIDC_AUTHORIZATION_ENDPOINT": "https://idp.example.test/oauth2/authorize",
        "RTSP_PROXY_OIDC_TOKEN_ENDPOINT": "https://idp.example.test/oauth2/token",
        "RTSP_PROXY_OIDC_REDIRECT_URI": "https://management.example.test/auth/oidc/callback",
        "RTSP_PROXY_OIDC_MFA_ACR": "urn:example:loa:2",
        "RTSP_PROXY_OIDC_MFA_AMR": "pwd,otp",
        "RTSP_PROXY_OIDC_CLIENT_SECRET_FILE": str(paths["client_secret"]),
        "RTSP_PROXY_OIDC_DERIVATION_KEY_FILE": str(paths["derivation"]),
        "RTSP_PROXY_BREAK_GLASS_ENCRYPTION_KEY_FILE": str(paths["encryption"]),
        "RTSP_PROXY_OIDC_JWKS_FILE": str(paths["jwks"]),
        "RTSP_PROXY_OIDC_GROUP_ROLES_FILE": str(paths["roles"]),
    }
    for name, value in environment.items():
        monkeypatch.setenv(name, value)

    invalid_files = (
        ("client_secret", b"\n"),
        ("client_secret", b"line-one\nline-two\n"),
        ("derivation", b"short\n"),
        ("derivation", b"!" * 43),
        ("jwks", b"[]"),
        ("roles", b"{}"),
        ("roles", b'{"rtsp-operators":["break_glass"]}'),
        ("roles", b'{"rtsp-operators":[]}'),
    )
    for name, payload in invalid_files:
        for reset_name, path in paths.items():
            path.write_bytes(valid_payloads[reset_name])
        paths[name].write_bytes(payload)
        with pytest.raises(ConfigurationError, match="operator_auth_file_invalid"):
            create_app_from_environment()

    for name, path in paths.items():
        path.write_bytes(valid_payloads[name])
    paths["jwks"].write_bytes(b'{"invalid":true}')
    with pytest.raises(ValueError, match="oidc_jwks_invalid"):
        create_app_from_environment()


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
            "RTSP_PROXY_OPERATOR_RECENT_MFA_SECONDS": "240",
        }
    )

    assert settings.max_nodes == 100
    assert settings.node_port_range_start == 12000
    assert settings.node_port_range_end == 12199
    assert settings.node_port_reserved == (12005, 12007)
    assert settings.node_management_freshness_seconds == 45
    assert settings.node_lifecycle_lock_pool_size == 6
    assert settings.node_lifecycle_lock_timeout_seconds == 7
    assert settings.operator_recent_mfa_seconds == 240


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


def test_local_operator_auth_is_independent_from_optional_oidc(tmp_path: Path) -> None:
    key = tmp_path / "local-auth-key"
    settings = Settings(
        role=RuntimeRole.WEB,
        database_url="postgresql+psycopg://db.invalid/rtsp_proxy",
        local_auth_enabled=True,
        local_auth_encryption_key_file=key,
    )

    assert settings.operator_auth_enabled
    assert settings.oidc_issuer is None

    with pytest.raises(ValidationError, match="local_auth_key_file_required"):
        Settings(
            role=RuntimeRole.WEB,
            database_url="postgresql+psycopg://db.invalid/rtsp_proxy",
            local_auth_enabled=True,
        )
    with pytest.raises(ValidationError, match="local_auth_web_database_required"):
        Settings(
            role=RuntimeRole.WEB,
            local_auth_enabled=True,
            local_auth_encryption_key_file=key,
        )


def test_web_runtime_exposes_local_login_without_oidc(
    postgres_database_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    upgrade_database(postgres_database_url)
    key = tmp_path / "local-auth-key"
    key.write_bytes(base64.urlsafe_b64encode(b"L" * 32).rstrip(b"=") + b"\n")
    key.chmod(0o440)
    real_fstat = os.fstat
    monkeypatch.setattr(
        "rtsp_proxy.operator_identity.os.fstat",
        lambda descriptor: _owned_by_root(real_fstat(descriptor), gid=0),
    )
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))
    environment = {
        "RTSP_PROXY_ROLE": "web",
        "RTSP_PROXY_DATABASE_URL": postgres_database_url,
        "RTSP_PROXY_LOCAL_AUTH_ENABLED": "true",
        "RTSP_PROXY_LOCAL_AUTH_ENCRYPTION_KEY_FILE": str(key),
    }
    for name, value in environment.items():
        monkeypatch.setenv(name, value)

    app = create_app_from_environment()
    with TestClient(app, base_url="https://management.example.test") as client:
        response = client.get("/auth/local/login")
        readiness = client.get("/health/ready")

    assert response.status_code == 200
    assert "/auth/oidc/login" not in response.text
    assert readiness.status_code == 200


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


def test_console_entrypoints_enforce_role_and_pass_validated_apps_to_uvicorn(
    postgres_database_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from rtsp_proxy.migrate import upgrade_database

    upgrade_database(postgres_database_url)
    uvicorn_calls: list[tuple[object, str, int, str | None, str | None]] = []

    def run_server(
        app: object,
        *,
        host: str,
        port: int,
        ssl_certfile: str | None = None,
        ssl_keyfile: str | None = None,
        **_kwargs: object,
    ) -> None:
        uvicorn_calls.append((app, host, port, ssl_certfile, ssl_keyfile))
        with TestClient(app) as client:  # type: ignore[arg-type]
            assert client.get("/health/live").status_code == 200

    monkeypatch.setattr("rtsp_proxy.runtime.uvicorn.run", run_server)
    monkeypatch.setenv("RTSP_PROXY_ROLE", "auth")
    monkeypatch.setenv("RTSP_PROXY_DATABASE_URL", postgres_database_url)
    monkeypatch.setenv(
        "RTSP_PROXY_ACCESS_PEPPER_FILE",
        str(tmp_path / "access-peppers.json"),
    )
    with pytest.raises(ConfigurationError, match="web_role_required"):
        run_web()

    monkeypatch.setenv("RTSP_PROXY_ROLE", "web")
    monkeypatch.delenv("RTSP_PROXY_ACCESS_PEPPER_FILE")
    with pytest.raises(ConfigurationError, match="auth_role_required"):
        run_auth()

    monkeypatch.setenv("RTSP_PROXY_HTTP_HOST", "127.0.0.2")
    monkeypatch.setenv("RTSP_PROXY_HTTP_PORT", "9080")
    run_web()
    assert uvicorn_calls[-1][1:] == ("127.0.0.2", 9080, None, None)

    certificate = tmp_path / "management-tls.crt"
    private_key = tmp_path / "management-tls.key"
    monkeypatch.setenv("RTSP_PROXY_HTTP_HOST", "192.0.2.10")
    monkeypatch.setenv("RTSP_PROXY_MANAGEMENT_TLS_CERTIFICATE_FILE", str(certificate))
    monkeypatch.setenv("RTSP_PROXY_MANAGEMENT_TLS_PRIVATE_KEY_FILE", str(private_key))
    run_web()
    assert uvicorn_calls[-1][1:] == (
        "192.0.2.10",
        9080,
        str(certificate),
        str(private_key),
    )

    monkeypatch.setenv(
        "RTSP_PROXY_MANAGEMENT_TLS_CERTIFICATE_FILE",
        "/tmp/operator-controlled-certificate",
    )
    monkeypatch.setenv(
        "RTSP_PROXY_MANAGEMENT_TLS_PRIVATE_KEY_FILE",
        "/tmp/operator-controlled-private-key",
    )
    trusted_certificate = Path("/run/credentials/rtsp-proxy-web/management-tls.crt")
    trusted_private_key = Path("/run/credentials/rtsp-proxy-web/management-tls.key")
    run_web(
        management_tls_certificate_file=trusted_certificate,
        management_tls_private_key_file=trusted_private_key,
    )
    assert uvicorn_calls[-1][1:] == (
        "192.0.2.10",
        9080,
        str(trusted_certificate),
        str(trusted_private_key),
    )

    monkeypatch.setenv("RTSP_PROXY_ROLE", "worker")
    monkeypatch.setenv("RTSP_PROXY_HTTP_HOST", "127.0.0.2")
    monkeypatch.delenv("RTSP_PROXY_MANAGEMENT_TLS_CERTIFICATE_FILE")
    monkeypatch.delenv("RTSP_PROXY_MANAGEMENT_TLS_PRIVATE_KEY_FILE")
    monkeypatch.setenv("RTSP_PROXY_SMTP_HOST", "smtp.example.test")
    monkeypatch.setenv("RTSP_PROXY_SMTP_USERNAME", "mailer")
    monkeypatch.setenv(
        "RTSP_PROXY_SMTP_PASSWORD_FILE",
        str(tmp_path / "systemd-credential-smtp-password"),
    )
    monkeypatch.setenv("RTSP_PROXY_SMTP_FROM_ADDRESS", "proxy@example.test")
    monkeypatch.setenv("RTSP_PROXY_SMTP_TO_ADDRESS", "operator@example.test")
    run_background(["--expected-role", "worker"])
    assert uvicorn_calls[-1][1:] == ("127.0.0.2", 9080, None, None)


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


@pytest.mark.parametrize(
    "revision",
    [
        "0012_operator_sessions",
        "0013_operator_login",
        "0014_camera_catalog_projection",
        "0015_camera_name_contract",
        "0016_node_registration_keys",
        "0017_access_grant_keys",
        "0019_dashboard_rate_limits",
        "0020_probe_observations",
    ],
)
def test_collector_remains_ready_across_declared_schema_bridge(
    revision: str,
    postgres_database_url: str,
) -> None:
    from alembic import command
    from alembic.config import Config

    migration = Config("alembic.ini")
    migration.set_main_option("sqlalchemy.url", postgres_database_url)
    command.upgrade(migration, revision)
    socket_path = Path("/tmp") / f"rtsp-proxy-{uuid4().hex}.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    listener.listen(1)
    listener.settimeout(3)

    def answer_health() -> None:
        try:
            connection, _ = listener.accept()
        except OSError:
            return
        with connection:
            connection.makefile("rb").readline(65_537)
            connection.sendall(b'{"error":null,"observation":null,"ok":true,"schema_version":1}\n')

    health_thread = Thread(target=answer_health)
    health_thread.start()
    try:
        app = create_background_app(
            Settings(
                role=RuntimeRole.COLLECTOR,
                database_url=postgres_database_url,
                node_runtime_socket=socket_path,
                node_runtime_timeout_seconds=2,
                node_mediamtx_binary_sha256=TRUSTED_MEDIAMTX_SHA256,
                collector_interval_seconds=1,
            ),
            expected_role=RuntimeRole.COLLECTOR,
        )
        with TestClient(app) as client:
            assert client.get("/health/ready").status_code == 200
    finally:
        listener.close()
        health_thread.join(timeout=4)
        socket_path.unlink(missing_ok=True)
    assert not health_thread.is_alive()


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


def test_notification_worker_keeps_incident_delivery_available_on_0012_bridge(
    postgres_database_url: str,
    tmp_path: Path,
) -> None:
    from alembic import command
    from alembic.config import Config

    migration = Config("alembic.ini")
    migration.set_main_option("sqlalchemy.url", postgres_database_url)
    command.upgrade(migration, "0012_operator_sessions")
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
        response = client.get("/health/ready")
        assert response.status_code == 200
        assert {item["name"]: item["status"] for item in response.json()["checks"]} == {
            "database": "pass",
            "schema": "pass",
            "outbox": "pass",
        }
        command.upgrade(migration, "0013_operator_login")
        response = client.get("/health/ready")
        assert response.status_code == 503
        assert response.json()["checks"][2] == {
            "name": "outbox",
            "status": "fail",
            "reason": "outbox_unavailable",
        }
