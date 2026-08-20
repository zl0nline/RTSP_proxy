from __future__ import annotations

import base64
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from contextlib import AbstractContextManager
from datetime import UTC, datetime, timedelta
from email.message import Message
from io import BytesIO
from threading import Event
from types import TracebackType
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlparse
from urllib.request import Request
from uuid import UUID

import pytest
from alembic import command
from alembic.config import Config
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.twofactor.totp import TOTP
from fastapi.testclient import TestClient
from joserfc import jwt
from joserfc.jwk import RSAKey
from sqlalchemy import create_engine, text

from rtsp_proxy.app import create_app
from rtsp_proxy.break_glass_cli import main as break_glass_cli_main
from rtsp_proxy.config import RuntimeRole, Settings
from rtsp_proxy.migrate import upgrade_database
from rtsp_proxy.observability import (
    NotificationStatus,
    OperatorSecurityAlertDispatcher,
    PostgresObservabilityStore,
)
from rtsp_proxy.operator_access import (
    InMemoryOperatorSessionStore,
    OperatorAccount,
    OperatorIdentitySource,
    OperatorMutationContext,
    OperatorRole,
    OperatorSessionControl,
    OperatorSessionUnavailable,
    PostgresOperatorSessionStore,
)
from rtsp_proxy.operator_identity import (
    BreakGlassAuthentication,
    BreakGlassControl,
    BreakGlassCredentials,
    HttpsOidcDiscoveryEndpoint,
    HttpsOidcTokenEndpoint,
    InMemoryBreakGlassStore,
    InMemoryOidcFlowStore,
    OidcFlow,
    OidcIdentity,
    OidcLoginControl,
    OidcLoginInvalid,
    OidcLoginRateLimited,
    OidcLoginUnavailable,
    OidcProvider,
    PostgresBreakGlassStore,
    PostgresOidcAccountResolver,
    PostgresOidcFlowStore,
    Rs256OidcClaimsVerifier,
)

NOW = datetime(2026, 8, 13, 20, 0, tzinfo=UTC)
ACCOUNT_ID = UUID("60000000-0000-0000-0000-000000000006")
TEST_MUTATION_CONTEXT = OperatorMutationContext(
    actor="system:test-bootstrap",
    reason="test fixture provisioning",
)


def test_operator_login_migration_preserves_existing_oidc_accounts(
    postgres_database_url: str,
) -> None:
    migration = Config("alembic.ini")
    migration.set_main_option("sqlalchemy.url", postgres_database_url)
    command.upgrade(migration, "0012_operator_sessions")
    subject = "operator-42"
    canonical_subject = (
        "oidc:" + hashlib.sha256(("https://idp.example.test" + "\0" + subject).encode()).hexdigest()
    )
    engine = create_engine(postgres_database_url, hide_parameters=True)
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO operator_accounts "
                "(id, identity_source, subject, display_name, roles, scopes, "
                "authz_version, enabled) VALUES "
                "(:id, 'oidc', :subject, 'Existing operator', "
                "ARRAY['operator']::varchar[], ARRAY['server:*']::varchar[], 1, true)"
            ),
            {"id": ACCOUNT_ID, "subject": canonical_subject},
        )

    command.upgrade(migration, "0013_operator_login")

    with engine.connect() as connection:
        assert (
            connection.scalar(
                text("SELECT subject FROM operator_accounts WHERE id = :id"),
                {"id": ACCOUNT_ID},
            )
            == canonical_subject
        )
    resolver = PostgresOidcAccountResolver(
        postgres_database_url,
        issuer="https://idp.example.test",
    )
    resolved_id = resolver.resolve(
        OidcIdentity(
            subject=subject,
            display_name="Existing operator",
            groups=frozenset({"rtsp-operators"}),
            roles=frozenset({OperatorRole.OPERATOR}),
            mfa_verified=True,
        )
    )
    resolver.close()
    assert resolved_id == ACCOUNT_ID
    engine.dispose()


def test_operator_login_migration_disables_legacy_break_glass_until_reprovisioned(
    postgres_database_url: str,
) -> None:
    migration = Config("alembic.ini")
    migration.set_main_option("sqlalchemy.url", postgres_database_url)
    command.upgrade(migration, "0012_operator_sessions")
    engine = create_engine(postgres_database_url, hide_parameters=True)
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO operator_accounts "
                "(id, identity_source, subject, display_name, roles, scopes, "
                "authz_version, enabled) VALUES "
                "(:id, 'break_glass', 'local:emergency-admin', 'Emergency administrator', "
                "ARRAY['break_glass']::varchar[], ARRAY['server:*']::varchar[], 1, true)"
            ),
            {"id": ACCOUNT_ID},
        )

    command.upgrade(migration, "0013_operator_login")

    with engine.connect() as connection:
        row = connection.execute(
            text(
                "SELECT enabled, authz_version, break_glass_password_scrypt, "
                "break_glass_totp_secret FROM operator_accounts WHERE id = :id"
            ),
            {"id": ACCOUNT_ID},
        ).one()
        audit = connection.execute(
            text(
                "SELECT id, aggregate_revision, payload FROM audit_events "
                "WHERE event_type = 'operator.break_glass_disabled_for_migration'"
            )
        ).one()
        outbox = connection.execute(
            text(
                "SELECT id, aggregate_revision, payload FROM outbox_messages "
                "WHERE event_type = 'operator.break_glass_disabled_for_migration'"
            )
        ).one()
    assert row == (False, 2, None, None)
    assert audit == outbox
    assert audit.aggregate_revision == 2
    assert audit.payload["before"] == {"authz_version": 1, "enabled": True}
    assert audit.payload["after"] == {"authz_version": 2, "enabled": False}
    engine.dispose()


def test_verified_login_never_rebinds_legacy_oidc_subject_without_issuer_mapping(
    postgres_database_url: str,
) -> None:
    migration = Config("alembic.ini")
    migration.set_main_option("sqlalchemy.url", postgres_database_url)
    command.upgrade(migration, "0012_operator_sessions")
    engine = create_engine(postgres_database_url, hide_parameters=True)
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO operator_accounts "
                "(id, identity_source, subject, display_name, roles, scopes, "
                "authz_version, enabled) VALUES "
                "(:id, 'oidc', 'legacy-unmapped-subject', 'Existing operator', "
                "ARRAY['operator']::varchar[], ARRAY['server:*']::varchar[], 1, true)"
            ),
            {"id": ACCOUNT_ID},
        )

    command.upgrade(migration, "0013_operator_login")
    resolver = PostgresOidcAccountResolver(
        postgres_database_url,
        issuer="https://idp.example.test",
    )

    with pytest.raises(OidcLoginInvalid, match="oidc_account_mapping_required"):
        resolver.resolve(
            OidcIdentity(
                subject="legacy-unmapped-subject",
                display_name="Existing operator",
                groups=frozenset({"rtsp-operators"}),
                roles=frozenset({OperatorRole.OPERATOR}),
                mfa_verified=True,
            )
        )
    different_issuer = PostgresOidcAccountResolver(
        postgres_database_url,
        issuer="https://other-idp.example.test",
    )
    with pytest.raises(OidcLoginInvalid, match="oidc_account_mapping_required"):
        different_issuer.resolve(
            OidcIdentity(
                subject="legacy-unmapped-subject",
                display_name="Different issuer user",
                groups=frozenset({"rtsp-operators"}),
                roles=frozenset({OperatorRole.OPERATOR}),
                mfa_verified=True,
            )
        )
    different_issuer.close()
    resolver.close()

    with engine.connect() as connection:
        row = connection.execute(
            text("SELECT id, subject, authz_version FROM operator_accounts WHERE id = :id"),
            {"id": ACCOUNT_ID},
        ).one()
        audit_count = connection.scalar(
            text(
                "SELECT count(*) FROM audit_events "
                "WHERE event_type = 'operator.oidc_subject_canonicalized'"
            )
        )
        outbox_count = connection.scalar(
            text(
                "SELECT count(*) FROM outbox_messages "
                "WHERE event_type = 'operator.oidc_subject_canonicalized'"
            )
        )
    assert row == (ACCOUNT_ID, "legacy-unmapped-subject", 1)
    assert audit_count == outbox_count == 0
    engine.dispose()


class _TokenResponse(AbstractContextManager["_TokenResponse"]):
    def __init__(
        self,
        payload: bytes,
        *,
        status: int = 200,
        content_type: str = "application/json",
    ) -> None:
        self.status = status
        self.headers = Message()
        self.headers["Content-Type"] = content_type
        self._body = BytesIO(payload)

    def read(self, amount: int = -1) -> bytes:
        return self._body.read(amount)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        return None


def test_oidc_token_exchange_uses_verified_tls_basic_client_auth_and_bounded_body() -> None:
    calls: list[tuple[Request, float, Any]] = []

    def open_request(
        request: Request,
        *,
        timeout: float,
        context: Any,
    ) -> _TokenResponse:
        calls.append((request, timeout, context))
        return _TokenResponse(b'{"id_token":"signed-id-token"}')

    endpoint = HttpsOidcTokenEndpoint(
        token_endpoint="https://idp.example.test/oauth2/token",
        client_id="rtsp-proxy",
        client_secret="client-secret",
        redirect_uri="https://management.example.test/auth/oidc/callback",
        timeout_seconds=3,
        maximum_response_bytes=1024,
        opener=open_request,
    )

    token = endpoint.exchange(code="authorization-code", code_verifier="V" * 43)

    assert token == "signed-id-token"
    assert len(calls) == 1
    request, timeout, context = calls[0]
    assert request.full_url == "https://idp.example.test/oauth2/token"
    assert timeout == 3
    assert context.check_hostname is True
    assert context.verify_mode.name == "CERT_REQUIRED"
    assert request.headers["Authorization"].startswith("Basic ")
    assert isinstance(request.data, bytes)
    body = parse_qs(request.data.decode("ascii"))
    assert body == {
        "code": ["authorization-code"],
        "code_verifier": ["V" * 43],
        "grant_type": ["authorization_code"],
        "redirect_uri": ["https://management.example.test/auth/oidc/callback"],
    }

    oversized = HttpsOidcTokenEndpoint(
        token_endpoint="https://idp.example.test/oauth2/token",
        client_id="rtsp-proxy",
        client_secret="client-secret",
        redirect_uri="https://management.example.test/auth/oidc/callback",
        maximum_response_bytes=1024,
        opener=lambda *_args, **_kwargs: _TokenResponse(b"x" * 1025),
    )
    with pytest.raises(Exception, match="oidc_callback_failed"):
        oversized.exchange(code="authorization-code", code_verifier="V" * 43)


def test_oidc_readiness_requires_a_bounded_authenticated_idp_response() -> None:
    calls: list[Request] = []

    def rejected_probe(
        request: Request,
        *,
        timeout: float,
        context: Any,
    ) -> _TokenResponse:
        del timeout, context
        calls.append(request)
        return _TokenResponse(b'{"error":"invalid_grant"}', status=400)

    endpoint = HttpsOidcTokenEndpoint(
        token_endpoint="https://idp.example.test/oauth2/token",
        client_id="rtsp-proxy",
        client_secret="client-secret",
        redirect_uri="https://management.example.test/auth/oidc/callback",
        opener=rejected_probe,
    )

    endpoint.assert_ready()
    endpoint.assert_ready()

    assert len(calls) == 1
    assert calls[0].headers["Authorization"].startswith("Basic ")

    for invalid_response in (
        _TokenResponse(b'{"error":"invalid_client"}', status=400),
        _TokenResponse(b"invalid request", status=400, content_type="text/html"),
    ):
        unavailable = HttpsOidcTokenEndpoint(
            token_endpoint="https://idp.example.test/oauth2/token",
            client_id="rtsp-proxy",
            client_secret="invalid-client-secret",
            redirect_uri="https://management.example.test/auth/oidc/callback",
            opener=lambda *_args, response=invalid_response, **_kwargs: response,
        )
        with pytest.raises(Exception, match="oidc_provider_unavailable"):
            unavailable.assert_ready()


def test_oidc_token_endpoint_rejects_invalid_protocol_and_transport_responses() -> None:
    def endpoint_for(response_or_error: _TokenResponse | BaseException) -> HttpsOidcTokenEndpoint:
        def open_request(*_args: Any, **_kwargs: Any) -> _TokenResponse:
            if isinstance(response_or_error, BaseException):
                raise response_or_error
            return response_or_error

        return HttpsOidcTokenEndpoint(
            token_endpoint="https://idp.example.test/oauth2/token",
            client_id="rtsp-proxy",
            client_secret="client-secret",
            redirect_uri="https://management.example.test/auth/oidc/callback",
            maximum_response_bytes=1024,
            opener=open_request,
        )

    with pytest.raises(ValueError, match="oidc_token_endpoint_configuration_invalid"):
        HttpsOidcTokenEndpoint(
            token_endpoint="http://idp.example.test/oauth2/token",
            client_id="rtsp-proxy",
            client_secret="client-secret",
            redirect_uri="https://management.example.test/auth/oidc/callback",
        )
    with pytest.raises(OidcLoginInvalid, match="oidc_callback_invalid"):
        endpoint_for(_TokenResponse(b"{}" )).exchange(code="", code_verifier="short")

    invalid_responses = (
        _TokenResponse(b'{"error":"invalid_grant"}', status=400),
        _TokenResponse(b"{}", content_type="text/plain"),
        _TokenResponse(b"not-json"),
        _TokenResponse(b"{}"),
        _TokenResponse(b'{"id_token":7}'),
    )
    for response in invalid_responses:
        with pytest.raises(OidcLoginInvalid, match="oidc_callback_failed"):
            endpoint_for(response).exchange(code="code", code_verifier="V" * 43)

    with pytest.raises(OidcLoginUnavailable, match="oidc_provider_unavailable"):
        endpoint_for(_TokenResponse(b"{}", status=503)).exchange(
            code="code",
            code_verifier="V" * 43,
        )

    for status, expected_error in (
        (400, OidcLoginInvalid),
        (503, OidcLoginUnavailable),
    ):
        headers = Message()
        headers["Content-Type"] = "application/json"
        error = HTTPError(
            "https://idp.example.test/oauth2/token",
            status,
            "token failure",
            headers,
            BytesIO(b'{"error":"invalid_grant"}'),
        )
        with pytest.raises(expected_error):
            endpoint_for(error).exchange(code="code", code_verifier="V" * 43)

    with pytest.raises(OidcLoginUnavailable, match="oidc_provider_unavailable"):
        endpoint_for(URLError("IdP unavailable")).exchange(
            code="code",
            code_verifier="V" * 43,
        )


def test_oidc_token_readiness_handles_http_errors_transport_and_cache_expiry() -> None:
    now = [0.0]
    calls: list[Request] = []
    headers = Message()
    headers["Content-Type"] = "application/json"

    def expected_http_error(request: Request, **_kwargs: Any) -> _TokenResponse:
        calls.append(request)
        raise HTTPError(
            request.full_url,
            400,
            "invalid grant",
            headers,
            BytesIO(b'{"error":"invalid_grant"}'),
        )

    endpoint = HttpsOidcTokenEndpoint(
        token_endpoint="https://idp.example.test/oauth2/token",
        client_id="rtsp-proxy",
        client_secret="client-secret",
        redirect_uri="https://management.example.test/auth/oidc/callback",
        opener=expected_http_error,
        monotonic_clock=lambda: now[0],
    )
    endpoint.assert_ready()
    endpoint.assert_ready()
    now[0] = 31
    endpoint.assert_ready()
    assert len(calls) == 2

    bad_headers = Message()
    bad_headers["Content-Type"] = "text/html"
    invalid_http_error = HTTPError(
        "https://idp.example.test/oauth2/token",
        400,
        "invalid client",
        bad_headers,
        BytesIO(b"invalid client"),
    )
    for failure in (invalid_http_error, URLError("IdP unavailable")):
        unavailable = HttpsOidcTokenEndpoint(
            token_endpoint="https://idp.example.test/oauth2/token",
            client_id="rtsp-proxy",
            client_secret="client-secret",
            redirect_uri="https://management.example.test/auth/oidc/callback",
            opener=lambda *_args, failure=failure, **_kwargs: (_ for _ in ()).throw(failure),
        )
        with pytest.raises(OidcLoginUnavailable, match="oidc_provider_unavailable"):
            unavailable.assert_ready()


def test_oidc_discovery_readiness_requires_exact_claim_and_protocol_contract() -> None:
    discovery_document = {
        "issuer": "https://idp.example.test",
        "authorization_endpoint": "https://idp.example.test/oauth2/authorize",
        "token_endpoint": "https://idp.example.test/oauth2/token",
        "claims_supported": [
            "acr",
            "amr",
            "aud",
            "exp",
            "groups",
            "iat",
            "iss",
            "name",
            "nonce",
            "sub",
        ],
        "id_token_signing_alg_values_supported": ["RS256"],
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
    }

    endpoint = HttpsOidcDiscoveryEndpoint(
        issuer="https://idp.example.test",
        authorization_endpoint="https://idp.example.test/oauth2/authorize",
        token_endpoint="https://idp.example.test/oauth2/token",
        opener=lambda *_args, **_kwargs: _TokenResponse(json.dumps(discovery_document).encode()),
    )

    endpoint.assert_ready()

    drifted = HttpsOidcDiscoveryEndpoint(
        issuer="https://idp.example.test",
        authorization_endpoint="https://idp.example.test/oauth2/authorize",
        token_endpoint="https://idp.example.test/oauth2/token",
        opener=lambda *_args, **_kwargs: _TokenResponse(
            json.dumps(discovery_document | {"claims_supported": ["sub", "groups"]}).encode()
        ),
    )
    with pytest.raises(Exception, match="oidc_claim_contract_unavailable"):
        drifted.assert_ready()


def test_oidc_discovery_rejects_invalid_configuration_and_bounded_responses() -> None:
    document = {
        "issuer": "https://idp.example.test",
        "authorization_endpoint": "https://idp.example.test/oauth2/authorize",
        "token_endpoint": "https://idp.example.test/oauth2/token",
        "claims_supported": [
            "acr",
            "amr",
            "aud",
            "exp",
            "groups",
            "iat",
            "iss",
            "name",
            "nonce",
            "sub",
        ],
        "id_token_signing_alg_values_supported": ["RS256"],
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
    }

    with pytest.raises(ValueError, match="oidc_discovery_configuration_invalid"):
        HttpsOidcDiscoveryEndpoint(
            issuer="http://idp.example.test",
            authorization_endpoint="https://idp.example.test/oauth2/authorize",
            token_endpoint="https://idp.example.test/oauth2/token",
        )

    calls = [0]

    def valid_document(*_args: Any, **_kwargs: Any) -> _TokenResponse:
        calls[0] += 1
        return _TokenResponse(json.dumps(document).encode())

    cached = HttpsOidcDiscoveryEndpoint(
        issuer="https://idp.example.test/",
        authorization_endpoint="https://idp.example.test/oauth2/authorize",
        token_endpoint="https://idp.example.test/oauth2/token",
        opener=valid_document,
    )
    cached.assert_ready()
    cached.assert_ready()
    assert calls == [1]

    invalid_responses: tuple[_TokenResponse | BaseException, ...] = (
        _TokenResponse(b"{}", status=503),
        _TokenResponse(json.dumps(document).encode(), content_type="text/plain"),
        _TokenResponse(b"x" * 1025),
        _TokenResponse(b"not-json"),
        _TokenResponse(json.dumps(document | {"response_types_supported": []}).encode()),
        URLError("IdP unavailable"),
    )
    for response_or_error in invalid_responses:
        def open_request(
            *_args: Any,
            response_or_error: _TokenResponse | BaseException = response_or_error,
            **_kwargs: Any,
        ) -> _TokenResponse:
            if isinstance(response_or_error, BaseException):
                raise response_or_error
            return response_or_error

        unavailable = HttpsOidcDiscoveryEndpoint(
            issuer="https://idp.example.test",
            authorization_endpoint="https://idp.example.test/oauth2/authorize",
            token_endpoint="https://idp.example.test/oauth2/token",
            maximum_response_bytes=1024,
            opener=open_request,
        )
        with pytest.raises(OidcLoginUnavailable, match="oidc_claim_contract_unavailable"):
            unavailable.assert_ready()


def test_oidc_login_redirect_uses_server_side_state_nonce_and_pkce_s256() -> None:
    store = InMemoryOidcFlowStore(clock=lambda: NOW)
    state_tokens = iter(("S" * 43, "B" * 43))
    login = OidcLoginControl(
        provider=OidcProvider(
            issuer="https://idp.example.test",
            client_id="rtsp-proxy",
            authorization_endpoint="https://idp.example.test/oauth2/authorize",
            token_endpoint="https://idp.example.test/oauth2/token",
            redirect_uri="https://management.example.test/auth/oidc/callback",
        ),
        flows=store,
        derivation_key=b"D" * 32,
        state_factory=state_tokens.__next__,
        clock=lambda: NOW,
    )
    client = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            operator_login=login,
        ),
        base_url="https://management.example.test",
    )

    response = client.get("/auth/oidc/login", follow_redirects=False)

    assert response.status_code == 303
    parsed = urlparse(response.headers["location"])
    assert parsed.scheme == "https"
    assert parsed.netloc == "idp.example.test"
    assert parsed.path == "/oauth2/authorize"
    query = parse_qs(parsed.query)
    assert query == {
        "client_id": ["rtsp-proxy"],
        "code_challenge": ["2t1t3pE9QTNiHD-zmfkGhKftUTbbhF5Xx7x-peI3JU8"],
        "code_challenge_method": ["S256"],
        "nonce": ["YCVKBY6uZQ46LIrUFhGSt9PHfSEO4iKtdlUgmBliixY"],
        "redirect_uri": ["https://management.example.test/auth/oidc/callback"],
        "response_type": ["code"],
        "scope": ["openid profile email"],
        "state": ["S" * 43],
    }
    assert response.headers["cache-control"] == "no-store"
    flow_cookie = response.headers["set-cookie"]
    assert flow_cookie.startswith("__Secure-rtsp_proxy_oidc_flow=" + "B" * 43)
    assert "HttpOnly" in flow_cookie
    assert "Secure" in flow_cookie
    assert "SameSite=lax" in flow_cookie
    assert "Path=/auth/oidc/callback" in flow_cookie
    flows = store.flows()
    assert len(flows) == 1
    assert flows[0].state_sha256 != "S" * 43
    assert flows[0].browser_sha256 != "B" * 43
    assert flows[0].return_to == "/"
    assert flows[0].consumed_at is None


def test_oidc_callback_consumes_flow_once_and_issues_only_opaque_cookies() -> None:
    class TestTokenEndpoint:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str]] = []

        def exchange(self, *, code: str, code_verifier: str) -> str:
            self.calls.append((code, code_verifier))
            return "signed-id-token"

    class TestClaimsVerifier:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str]] = []

        def verify(self, *, id_token: str, nonce: str) -> OidcIdentity:
            self.calls.append((id_token, nonce))
            return OidcIdentity(
                subject="operator-42",
                display_name="Оператор",
                groups=frozenset({"rtsp-operators"}),
                roles=frozenset({OperatorRole.OPERATOR}),
                mfa_verified=True,
            )

    account = OperatorAccount(
        identity_source=OperatorIdentitySource.OIDC,
        id=ACCOUNT_ID,
        subject="operator-42",
        display_name="Оператор",
        roles=frozenset({OperatorRole.OPERATOR}),
        scopes=frozenset({"server:*"}),
        authz_version=1,
        enabled=True,
    )
    sessions = OperatorSessionControl(
        store=InMemoryOperatorSessionStore(accounts=(account,), clock=lambda: NOW),
        token_factory=iter(("T" * 43, "C" * 43)).__next__,
    )
    flows = InMemoryOidcFlowStore(clock=lambda: NOW)
    tokens = TestTokenEndpoint()
    claims = TestClaimsVerifier()
    state_tokens = iter(("S" * 43, "B" * 43))
    login = OidcLoginControl(
        provider=OidcProvider(
            issuer="https://idp.example.test",
            client_id="rtsp-proxy",
            authorization_endpoint="https://idp.example.test/oauth2/authorize",
            token_endpoint="https://idp.example.test/oauth2/token",
            redirect_uri="https://management.example.test/auth/oidc/callback",
        ),
        flows=flows,
        derivation_key=b"D" * 32,
        state_factory=state_tokens.__next__,
        token_endpoint=tokens,
        claims_verifier=claims,
        account_resolver=lambda identity: (
            ACCOUNT_ID if identity.subject == account.subject else None
        ),
        sessions=sessions,
        clock=lambda: NOW,
    )
    client = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            operator_login=login,
            operator_sessions=sessions,
        ),
        base_url="https://management.example.test",
    )
    client.get("/auth/oidc/login", follow_redirects=False)

    completed = client.get(
        "/auth/oidc/callback",
        params={"state": "S" * 43, "code": "authorization-code"},
        follow_redirects=False,
    )
    replayed = client.get(
        "/auth/oidc/callback",
        params={"state": "S" * 43, "code": "authorization-code"},
        follow_redirects=False,
    )

    assert completed.status_code == 303
    assert completed.headers["location"] == "/"
    cookies = completed.headers.get_list("set-cookie")
    assert any(
        cookie.startswith("__Host-rtsp_proxy_session=")
        and "HttpOnly" in cookie
        and "Secure" in cookie
        and "SameSite=strict" in cookie
        for cookie in cookies
    )
    assert any(
        cookie.startswith("__Host-rtsp_proxy_csrf=")
        and "HttpOnly" not in cookie
        and "Secure" in cookie
        and "SameSite=strict" in cookie
        for cookie in cookies
    )
    assert all("signed-id-token" not in cookie for cookie in cookies)
    assert tokens.calls == [("authorization-code", "V6Z0EbeZdk50cvWtVYAjfMItd2kmjeB2YxoIF6ESKYk")]
    assert claims.calls == [("signed-id-token", "YCVKBY6uZQ46LIrUFhGSt9PHfSEO4iKtdlUgmBliixY")]
    assert replayed.status_code == 401
    assert replayed.json() == {"detail": {"code": "operator_login_failed"}}
    assert replayed.headers["cache-control"] == "no-store"
    assert flows.rejection_count() == 1


def test_oidc_login_control_rejects_invalid_flow_and_account_boundaries() -> None:
    provider = OidcProvider(
        issuer="https://idp.example.test",
        client_id="rtsp-proxy",
        authorization_endpoint="https://idp.example.test/oauth2/authorize",
        token_endpoint="https://idp.example.test/oauth2/token",
        redirect_uri="https://management.example.test/auth/oidc/callback",
    )
    account = OperatorAccount(
        identity_source=OperatorIdentitySource.OIDC,
        id=ACCOUNT_ID,
        subject="oidc:operator-42",
        display_name="Operator",
        roles=frozenset({OperatorRole.OPERATOR}),
        scopes=frozenset({"server:*"}),
        authz_version=1,
        enabled=True,
    )

    with pytest.raises(ValueError, match="oidc_flow_configuration_invalid"):
        OidcLoginControl(
            provider=provider,
            flows=InMemoryOidcFlowStore(clock=lambda: NOW),
            derivation_key=b"short",
            state_factory=lambda: "S" * 43,
        )

    invalid_state = OidcLoginControl(
        provider=provider,
        flows=InMemoryOidcFlowStore(clock=lambda: NOW),
        derivation_key=b"D" * 32,
        state_factory=lambda: "short",
        clock=lambda: NOW,
    )
    with pytest.raises(OidcLoginInvalid, match="oidc_state_invalid"):
        invalid_state.begin()

    naive_clock = OidcLoginControl(
        provider=provider,
        flows=InMemoryOidcFlowStore(clock=lambda: NOW),
        derivation_key=b"D" * 32,
        state_factory=iter(("S" * 43, "B" * 43)).__next__,
        clock=lambda: NOW.replace(tzinfo=None),
    )
    with pytest.raises(OidcLoginInvalid, match="oidc_clock_invalid"):
        naive_clock.begin()

    unconfigured_flows = InMemoryOidcFlowStore(clock=lambda: NOW)
    unconfigured = OidcLoginControl(
        provider=provider,
        flows=unconfigured_flows,
        derivation_key=b"D" * 32,
        state_factory=lambda: "S" * 43,
        clock=lambda: NOW,
    )
    with pytest.raises(OidcLoginInvalid, match="oidc_callback_invalid"):
        unconfigured.complete(state="é" * 43, code="code", browser_token="B" * 43)
    unconfigured.record_rejection(source_ip="x" * 129)
    assert unconfigured_flows.rejection_count() == 1

    class TokenEndpoint:
        def exchange(self, *, code: str, code_verifier: str) -> str:
            del code, code_verifier
            return "signed-id-token"

    class ClaimsVerifier:
        def __init__(self, *, mfa_verified: bool) -> None:
            self._mfa_verified = mfa_verified

        def verify(self, *, id_token: str, nonce: str) -> OidcIdentity:
            del id_token, nonce
            return OidcIdentity(
                subject="operator-42",
                display_name="Operator",
                groups=frozenset({"rtsp-operators"}),
                roles=frozenset({OperatorRole.OPERATOR}),
                mfa_verified=self._mfa_verified,
            )

    def complete_with(
        *,
        mfa_verified: bool = True,
        resolver: Any = lambda _identity: ACCOUNT_ID,
        sessions: Any = None,
    ) -> None:
        flows = InMemoryOidcFlowStore(clock=lambda: NOW)
        control = OidcLoginControl(
            provider=provider,
            flows=flows,
            derivation_key=b"D" * 32,
            state_factory=iter(("S" * 43, "B" * 43)).__next__,
            token_endpoint=TokenEndpoint(),
            claims_verifier=ClaimsVerifier(mfa_verified=mfa_verified),
            account_resolver=resolver,
            sessions=(
                OperatorSessionControl(
                    store=InMemoryOperatorSessionStore(accounts=(account,), clock=lambda: NOW),
                    token_factory=iter(("T" * 43, "C" * 43)).__next__,
                )
                if sessions is None
                else sessions
            ),
            clock=lambda: NOW,
        )
        control.begin()
        control.complete(
            state="S" * 43,
            code="authorization-code",
            browser_token="B" * 43,
        )

    with pytest.raises(OidcLoginInvalid, match="oidc_mfa_required"):
        complete_with(mfa_verified=False)
    with pytest.raises(OidcLoginInvalid, match="oidc_account_unavailable"):
        complete_with(resolver=lambda _identity: None)

    def rejected_resolver(_identity: OidcIdentity) -> UUID:
        raise OidcLoginInvalid("oidc_account_unavailable")

    with pytest.raises(OidcLoginInvalid, match="oidc_account_unavailable"):
        complete_with(resolver=rejected_resolver)

    class UnavailableSessions:
        def issue(self, *, account_id: UUID, mfa_verified: bool) -> None:
            del account_id, mfa_verified
            raise OperatorSessionUnavailable("operator_session_store_unavailable")

    with pytest.raises(OidcLoginUnavailable, match="operator_session_store_unavailable"):
        complete_with(sessions=UnavailableSessions())


def test_oidc_id_token_requires_rs256_issuer_audience_nonce_mfa_and_group_mapping() -> None:
    key = RSAKey.generate_key(
        2048,
        {"kid": "idp-key-1", "use": "sig"},
        auto_kid=False,
    )
    verifier = Rs256OidcClaimsVerifier(
        issuer="https://idp.example.test",
        client_id="rtsp-proxy",
        jwks={"keys": [key.as_dict(private=False)]},
        group_roles={
            "rtsp-operators": frozenset({OperatorRole.OPERATOR}),
            "rtsp-auditors": frozenset({OperatorRole.AUDITOR}),
        },
        accepted_mfa_acr=frozenset({"urn:example:loa:2"}),
        required_mfa_amr=frozenset({"pwd", "otp"}),
        clock=lambda: NOW,
    )
    claims = {
        "iss": "https://idp.example.test",
        "aud": "rtsp-proxy",
        "sub": "operator-42",
        "name": "Оператор",
        "groups": ["rtsp-operators", "unmapped-group"],
        "nonce": "expected-nonce",
        "acr": "urn:example:loa:2",
        "amr": ["pwd", "otp"],
        "iat": int(NOW.timestamp()),
        "exp": int(NOW.timestamp()) + 300,
    }
    signed = jwt.encode(
        {"alg": "RS256", "kid": "idp-key-1"},
        claims,
        key,
        algorithms=["RS256"],
    )

    identity = verifier.verify(id_token=signed, nonce="expected-nonce")

    assert identity.subject == "operator-42"
    assert identity.groups == frozenset({"rtsp-operators"})
    assert identity.roles == frozenset({OperatorRole.OPERATOR})
    assert identity.mfa_verified is True

    multi_audience = jwt.encode(
        {"alg": "RS256", "kid": "idp-key-1"},
        claims | {"aud": ["rtsp-proxy", "other-api"], "azp": "rtsp-proxy"},
        key,
        algorithms=["RS256"],
    )
    assert (
        verifier.verify(
            id_token=multi_audience,
            nonce="expected-nonce",
        ).subject
        == "operator-42"
    )

    invalid_claim_sets = (
        claims | {"iss": "https://attacker.example.test"},
        claims | {"aud": "another-client"},
        claims | {"aud": ["rtsp-proxy", "other-api"]},
        claims | {"aud": ["rtsp-proxy", "other-api"], "azp": "other-api"},
        claims | {"nonce": "replayed-nonce"},
        claims | {"acr": "urn:example:loa:1", "amr": ["pwd"]},
        claims | {"groups": ["unmapped-group"]},
        claims | {"exp": int(NOW.timestamp()) - 31},
    )
    for invalid_claims in invalid_claim_sets:
        invalid = jwt.encode(
            {"alg": "RS256", "kid": "idp-key-1"},
            invalid_claims,
            key,
            algorithms=["RS256"],
        )
        with pytest.raises(Exception, match="oidc_id_token_invalid"):
            verifier.verify(id_token=invalid, nonce="expected-nonce")


def test_postgres_oidc_flow_survives_restart_and_has_one_concurrent_consumer(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    first = PostgresOidcFlowStore(postgres_database_url)
    flow = first.create(
        state_sha256="a" * 64,
        browser_sha256="b" * 64,
        source_ip_sha256="c" * 64,
        return_to="/dashboard",
        lifetime=timedelta(minutes=5),
    )
    first.close()
    assert flow.return_to == "/dashboard"

    reopened = PostgresOidcFlowStore(postgres_database_url)

    def consume() -> bool:
        try:
            reopened.consume("a" * 64, browser_sha256="b" * 64)
        except Exception as error:
            assert str(error) == "oidc_flow_invalid"
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(lambda _index: consume(), range(2)))

    assert sorted(results) == [False, True]
    reopened.close()


def test_postgres_oidc_callback_limit_survives_store_restart(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    source_digest = "c" * 64
    store = PostgresOidcFlowStore(postgres_database_url)
    for _attempt in range(5):
        store.record_rejection(source_ip_sha256=source_digest)
    store.create(
        state_sha256="d" * 64,
        browser_sha256="e" * 64,
        source_ip_sha256=source_digest,
        return_to="/",
        lifetime=timedelta(minutes=5),
    )
    store.close()

    reopened = PostgresOidcFlowStore(postgres_database_url)
    with pytest.raises(OidcLoginRateLimited, match="operator_login_rate_limited"):
        reopened.consume("d" * 64, browser_sha256="e" * 64)
    reopened.close()


def test_postgres_oidc_flow_enforces_capacity_and_identity_attempt_limits(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    with pytest.raises(ValueError, match="database_statement_timeout_invalid"):
        PostgresOidcFlowStore(postgres_database_url, statement_timeout_ms=99)

    store = PostgresOidcFlowStore(postgres_database_url)
    store.assert_ready()
    source_digest = "c" * 64
    identity_digest = "f" * 64
    for index in range(10):
        store.create(
            state_sha256=f"{index:064x}",
            browser_sha256="b" * 64,
            source_ip_sha256=source_digest,
            return_to="/",
            lifetime=timedelta(minutes=5),
        )
    with pytest.raises(OidcLoginRateLimited, match="operator_login_rate_limited"):
        store.create(
            state_sha256="a" * 64,
            browser_sha256="b" * 64,
            source_ip_sha256=source_digest,
            return_to="/",
            lifetime=timedelta(minutes=5),
        )
    with pytest.raises(OidcLoginInvalid, match="oidc_flow_invalid"):
        store.consume("f" * 64, browser_sha256="b" * 64)

    store.assert_identity_allowed(identity_sha256=identity_digest)
    for _attempt in range(5):
        store.record_identity_rejection(identity_sha256=identity_digest)
    with pytest.raises(OidcLoginRateLimited, match="operator_login_rate_limited"):
        store.assert_identity_allowed(identity_sha256=identity_digest)
    store.record_success(
        source_ip_sha256=source_digest,
        identity_sha256=identity_digest,
    )
    store.assert_identity_allowed(identity_sha256=identity_digest)

    for _attempt in range(5):
        store.record_rejection(source_ip_sha256="e" * 64)
    with pytest.raises(OidcLoginRateLimited, match="operator_login_rate_limited"):
        store.record_rejection(source_ip_sha256="e" * 64)
    store.close()


def test_postgres_oidc_identity_provisions_once_with_audit_and_rejects_role_drift(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    resolver = PostgresOidcAccountResolver(
        postgres_database_url,
        issuer="https://idp.example.test",
    )
    identity = OidcIdentity(
        subject="operator-42",
        display_name="Оператор",
        groups=frozenset({"rtsp-operators"}),
        roles=frozenset({OperatorRole.OPERATOR}),
        mfa_verified=True,
    )

    account_id = resolver.resolve(identity)
    reopened_id = resolver.resolve(identity)

    assert account_id is not None
    assert reopened_id == account_id
    engine = create_engine(postgres_database_url, hide_parameters=True)
    with engine.connect() as connection:
        account = connection.execute(
            text(
                "SELECT subject, roles, scopes, authz_version FROM operator_accounts WHERE id = :id"
            ),
            {"id": account_id},
        ).one()
        audit = connection.execute(
            text(
                "SELECT id, event_type, payload FROM audit_events "
                "WHERE event_type = 'operator.oidc_account_provisioned'"
            )
        ).one()
        outbox = connection.execute(
            text(
                "SELECT id, event_type, payload FROM outbox_messages "
                "WHERE event_type = 'operator.oidc_account_provisioned'"
            )
        ).one()
    assert account.subject.startswith("oidc:")
    assert account.subject != "operator-42"
    assert account.roles == ["operator"]
    assert account.scopes == ["server:*"]
    assert account.authz_version == 1
    assert audit == outbox
    assert audit.payload["subject_sha256"] != "operator-42"

    drifted = OidcIdentity(
        subject="operator-42",
        display_name="Оператор",
        groups=frozenset({"rtsp-admins"}),
        roles=frozenset({OperatorRole.ADMIN}),
        mfa_verified=True,
    )
    with pytest.raises(Exception, match="oidc_account_unavailable"):
        resolver.resolve(drifted)

    renamed = OidcIdentity(
        subject="operator-42",
        display_name="Оператор смены",
        groups=frozenset({"rtsp-operators"}),
        roles=frozenset({OperatorRole.OPERATOR}),
        mfa_verified=True,
    )
    assert resolver.resolve(renamed) == account_id
    with engine.connect() as connection:
        assert connection.scalar(
            text("SELECT display_name FROM operator_accounts WHERE id = :id"),
            {"id": account_id},
        ) == "Оператор смены"
    engine.dispose()
    resolver.close()


def test_break_glass_requires_password_and_non_replayed_totp_and_emits_alert() -> None:
    totp_secret = b"B" * 20
    current_step = int(NOW.timestamp()) // 30
    password_verifier = BreakGlassCredentials.hash_password(
        "correct horse battery staple",
        salt=b"S" * 16,
    )
    account = OperatorAccount(
        identity_source=OperatorIdentitySource.BREAK_GLASS,
        id=ACCOUNT_ID,
        subject="local:emergency-admin",
        display_name="Emergency administrator",
        roles=frozenset({OperatorRole.BREAK_GLASS}),
        scopes=frozenset({"server:*"}),
        authz_version=1,
        enabled=True,
    )
    store = InMemoryBreakGlassStore(
        account=account,
        credentials=BreakGlassCredentials(
            password_scrypt=password_verifier,
            totp_secret=totp_secret,
            last_totp_step=None,
        ),
    )
    sessions = OperatorSessionControl(
        store=InMemoryOperatorSessionStore(accounts=(account,), clock=lambda: NOW),
        token_factory=iter(("T" * 43, "C" * 43)).__next__,
    )
    control = BreakGlassControl(
        store=store,
        sessions=sessions,
        clock=lambda: NOW,
    )
    code = TOTP(totp_secret, 6, hashes.SHA1(), 30).generate(int(NOW.timestamp())).decode("ascii")
    client = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            break_glass=control,
        ),
        base_url="https://management.example.test",
    )

    invalid_password = client.post(
        "/auth/break-glass/login",
        json={
            "username": "emergency-admin",
            "password": "wrong password",
            "totp": code,
        },
    )
    completed = client.post(
        "/auth/break-glass/login",
        json={
            "username": "emergency-admin",
            "password": "correct horse battery staple",
            "totp": code,
        },
        follow_redirects=False,
    )
    replayed = client.post(
        "/auth/break-glass/login",
        json={
            "username": "emergency-admin",
            "password": "correct horse battery staple",
            "totp": code,
        },
    )

    assert invalid_password.status_code == 401
    assert invalid_password.json() == {"detail": {"code": "operator_login_failed"}}
    assert completed.status_code == 303
    assert completed.headers["location"] == "/"
    assert "__Host-rtsp_proxy_session=" in completed.headers["set-cookie"]
    assert replayed.status_code == 401
    assert replayed.json() == {"detail": {"code": "operator_login_failed"}}
    assert store.last_totp_step() == current_step
    assert len(store.security_events()) == 3
    assert all(
        event.event_type == "operator.break_glass_login" and event.severity == "critical"
        for event in store.security_events()
    )
    assert tuple(event.outcome for event in store.security_events()) == (
        "rejected",
        "accepted",
        "rejected",
    )


def test_postgres_break_glass_consumes_totp_and_appends_security_event_atomically(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    encryption_key = b"K" * 32
    totp_secret = b"B" * 20
    password_scrypt = BreakGlassCredentials.hash_password(
        "correct horse battery staple",
        salt=b"S" * 16,
    )
    account = OperatorAccount(
        identity_source=OperatorIdentitySource.BREAK_GLASS,
        id=ACCOUNT_ID,
        subject="local:emergency-admin",
        display_name="Emergency administrator",
        roles=frozenset({OperatorRole.BREAK_GLASS}),
        scopes=frozenset({"server:*"}),
        authz_version=1,
        enabled=True,
    )
    store = PostgresBreakGlassStore(
        postgres_database_url,
        encryption_key=encryption_key,
    )
    store.provision(
        account=account,
        password_scrypt=password_scrypt,
        totp_secret=totp_secret,
        context=TEST_MUTATION_CONTEXT,
    )
    assert store.existing_break_glass_account_id() == ACCOUNT_ID
    store.assert_ready()
    code = TOTP(totp_secret, 6, hashes.SHA1(), 30).generate(int(NOW.timestamp())).decode("ascii")

    authentication = store.authenticate(
        username="emergency-admin",
        password="correct horse battery staple",
        totp=code,
        source_ip="192.0.2.10",
        now=NOW,
    )

    assert authentication == BreakGlassAuthentication(ACCOUNT_ID, 1)
    engine = create_engine(postgres_database_url, hide_parameters=True)
    with engine.connect() as connection:
        row = connection.execute(
            text(
                "SELECT break_glass_password_scrypt, break_glass_totp_secret, "
                "break_glass_last_totp_step FROM operator_accounts WHERE id = :id"
            ),
            {"id": ACCOUNT_ID},
        ).one()
        audit = connection.execute(
            text(
                "SELECT id, event_type, payload FROM audit_events "
                "WHERE aggregate_type = 'operator_account' "
                "AND event_type = 'operator.break_glass_login'"
            )
        ).one()
        outbox = connection.execute(
            text(
                "SELECT id, event_type, payload FROM outbox_messages "
                "WHERE aggregate_type = 'operator_account' "
                "AND event_type = 'operator.break_glass_login'"
            )
        ).one()
    assert row.break_glass_password_scrypt == password_scrypt
    assert row.break_glass_totp_secret != totp_secret
    nonce = row.break_glass_totp_secret[:12]
    ciphertext = row.break_glass_totp_secret[12:]
    assert (
        AESGCM(encryption_key).decrypt(
            nonce,
            ciphertext,
            ACCOUNT_ID.bytes,
        )
        == totp_secret
    )
    assert row.break_glass_last_totp_step == int(NOW.timestamp()) // 30
    assert audit == outbox
    assert audit.event_type == "operator.break_glass_login"
    assert audit.payload == {
        "account_id": str(ACCOUNT_ID),
        "auth_method": "break_glass_password_totp",
        "outcome": "accepted",
        "reason_code": "authenticated",
        "severity": "critical",
    }
    with pytest.raises(Exception, match="break_glass_login_failed"):
        store.authenticate(
            username="emergency-admin",
            password="correct horse battery staple",
            totp=code,
            source_ip="192.0.2.10",
            now=NOW,
        )
    engine.dispose()
    store.close()


def test_operator_identity_public_models_and_controls_reject_invalid_boundaries() -> None:
    verifier = BreakGlassCredentials.hash_password(
        "correct horse battery staple",
        salt=b"S" * 16,
    )
    credentials = BreakGlassCredentials(
        password_scrypt=verifier,
        totp_secret=b"B" * 20,
        last_totp_step=None,
    )
    assert credentials.verifies_password("wrong password") is False
    assert credentials.verifies_password("x" * 1025) is False
    invalid_credentials = (
        {
            "password_scrypt": b"short",
            "totp_secret": b"B" * 20,
            "last_totp_step": None,
        },
        {
            "password_scrypt": verifier,
            "totp_secret": b"short",
            "last_totp_step": None,
        },
        {
            "password_scrypt": verifier,
            "totp_secret": b"B" * 20,
            "last_totp_step": -1,
        },
    )
    for invalid in invalid_credentials:
        with pytest.raises(ValueError, match="break_glass_credentials_invalid"):
            BreakGlassCredentials(**invalid)
    for password, salt in (("short", b"S" * 16), ("valid password length", b"short")):
        with pytest.raises(ValueError, match="break_glass_password_invalid"):
            BreakGlassCredentials.hash_password(password, salt=salt)

    oidc_account = OperatorAccount(
        identity_source=OperatorIdentitySource.OIDC,
        id=ACCOUNT_ID,
        subject="oidc:operator",
        display_name="Operator",
        roles=frozenset({OperatorRole.OPERATOR}),
        scopes=frozenset({"server:*"}),
        authz_version=1,
        enabled=True,
    )
    with pytest.raises(ValueError, match="break_glass_account_invalid"):
        InMemoryBreakGlassStore(account=oidc_account, credentials=credentials)
    valid_identity = {
        "subject": "operator-42",
        "display_name": "Operator",
        "groups": frozenset({"rtsp-operators"}),
        "roles": frozenset({OperatorRole.OPERATOR}),
        "mfa_verified": True,
    }
    for field, invalid_value in (
        ("subject", ""),
        ("display_name", ""),
        ("groups", frozenset()),
        ("roles", frozenset()),
    ):
        with pytest.raises(ValueError, match="oidc_identity_invalid"):
            OidcIdentity(**(valid_identity | {field: invalid_value}))  # type: ignore[arg-type]
    valid_provider = {
        "issuer": "https://idp.example.test",
        "client_id": "rtsp-proxy",
        "authorization_endpoint": "https://idp.example.test/oauth2/authorize",
        "token_endpoint": "https://idp.example.test/oauth2/token",
        "redirect_uri": "https://management.example.test/auth/oidc/callback",
    }
    for field, invalid_value in (
        ("issuer", "http://idp.example.test"),
        ("client_id", ""),
        ("authorization_endpoint", "https://other-idp.example.test/authorize"),
        ("token_endpoint", "https://other-idp.example.test/token"),
        ("redirect_uri", "http://management.example.test/auth/oidc/callback"),
    ):
        with pytest.raises(ValueError, match="oidc_provider_invalid"):
            OidcProvider(**(valid_provider | {field: invalid_value}))

    break_glass_account = OperatorAccount(
        identity_source=OperatorIdentitySource.BREAK_GLASS,
        id=ACCOUNT_ID,
        subject="local:emergency-admin",
        display_name="Emergency administrator",
        roles=frozenset({OperatorRole.BREAK_GLASS}),
        scopes=frozenset({"server:*"}),
        authz_version=1,
        enabled=True,
    )
    control = BreakGlassControl(
        store=InMemoryBreakGlassStore(
            account=break_glass_account,
            credentials=credentials,
        ),
        sessions=OperatorSessionControl(
            store=InMemoryOperatorSessionStore(accounts=(break_glass_account,), clock=lambda: NOW),
            token_factory=iter(("T" * 43, "C" * 43)).__next__,
        ),
        clock=lambda: NOW.replace(tzinfo=None),
    )
    valid_code = TOTP(b"B" * 20, 6, hashes.SHA1(), 30).generate(
        int(NOW.timestamp())
    ).decode("ascii")
    with pytest.raises(OidcLoginInvalid, match="break_glass_login_failed"):
        control.login(
            username="emergency-admin",
            password="correct horse battery staple",
            totp=valid_code,
            source_ip="192.0.2.10",
        )


def test_break_glass_cli_provisions_exact_identity_without_exposing_secrets(
    postgres_database_url: str,
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    migration = Config("alembic.ini")
    migration.set_main_option("sqlalchemy.url", postgres_database_url)
    command.upgrade(migration, "0012_operator_sessions")
    legacy_engine = create_engine(postgres_database_url, hide_parameters=True)
    with legacy_engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO operator_accounts "
                "(id, identity_source, subject, display_name, roles, scopes, "
                "authz_version, enabled) VALUES "
                "(:id, 'break_glass', 'local:emergency-admin', 'Legacy emergency', "
                "ARRAY['break_glass']::varchar[], ARRAY['camera:legacy']::varchar[], "
                "1, true)"
            ),
            {"id": ACCOUNT_ID},
        )
    legacy_engine.dispose()
    command.upgrade(migration, "0013_operator_login")
    capsys.readouterr()
    encryption_key_file = tmp_path / "break-glass-encryption-key"
    totp_file = tmp_path / "break-glass-totp"
    encryption_key_file.write_bytes(base64.urlsafe_b64encode(b"K" * 32))
    totp_file.write_bytes(base64.urlsafe_b64encode(b"B" * 20))
    encryption_key_file.chmod(0o600)
    totp_file.chmod(0o600)
    monkeypatch.setenv("RTSP_PROXY_DATABASE_URL", postgres_database_url)
    monkeypatch.setenv(
        "RTSP_PROXY_BREAK_GLASS_ENCRYPTION_KEY_FILE",
        str(encryption_key_file),
    )
    monkeypatch.setenv("RTSP_PROXY_BREAK_GLASS_TOTP_FILE", str(totp_file))
    passwords = iter(("correct horse battery staple", "correct horse battery staple"))

    exit_code = break_glass_cli_main(
        [
            "--account-id",
            str(ACCOUNT_ID),
            "--username",
            "emergency-admin",
            "--actor",
            "operator:alice",
            "--reason",
            "scheduled emergency credential rotation",
        ],
        password_reader=lambda _prompt: next(passwords),
    )

    assert exit_code == 0
    output = capsys.readouterr()
    assert output.err == ""
    assert output.out == f"provisioned break-glass account {ACCOUNT_ID} at revision 3\n"
    assert "correct horse" not in output.out
    engine = create_engine(postgres_database_url, hide_parameters=True)
    with engine.connect() as connection:
        account = connection.execute(
            text(
                "SELECT id, subject, enabled, authz_version FROM operator_accounts "
                "WHERE identity_source = 'break_glass'"
            )
        ).one()
        audit = connection.execute(
            text(
                "SELECT id, aggregate_revision, payload FROM audit_events "
                "WHERE event_type = 'operator.break_glass_provisioned'"
            )
        ).one()
        outbox = connection.execute(
            text(
                "SELECT id, aggregate_revision, payload FROM outbox_messages "
                "WHERE event_type = 'operator.break_glass_provisioned'"
            )
        ).one()
    engine.dispose()
    assert account == (ACCOUNT_ID, "local:emergency-admin", True, 3)
    assert audit == outbox
    assert audit.aggregate_revision == 3
    assert audit.payload == {
        "action": "operator.break_glass_provision",
        "account_id": str(ACCOUNT_ID),
        "actor": "operator:alice",
        "after": {
            "authz_version": 3,
            "display_name": "Emergency administrator",
            "enabled": True,
            "roles": ["break_glass"],
            "scopes": ["server:*"],
        },
        "auth_method": "privileged_local_cli",
        "before": {
            "authz_version": 2,
            "display_name": "Legacy emergency",
            "enabled": False,
            "roles": ["break_glass"],
            "scopes": ["camera:legacy"],
        },
        "effective_roles": ["break_glass"],
        "effective_scopes": ["server:*"],
        "identity_source": "break_glass",
        "object_type": "operator_account",
        "outcome": "provisioned",
        "reason": "scheduled emergency credential rotation",
    }

    second_passwords = iter(("another correct password", "another correct password"))
    assert (
        break_glass_cli_main(
            [
                "--account-id",
                "70000000-0000-4000-8000-000000000007",
                "--username",
                "emergency-admin",
                "--actor",
                "operator:alice",
                "--reason",
                "unexpected identity replacement",
            ],
            password_reader=lambda _prompt: next(second_passwords),
        )
        == 1
    )
    assert capsys.readouterr().err == (
        "break-glass provisioning failed: break_glass_account_conflict\n"
    )


def test_break_glass_cli_rotates_with_revision_fence_and_revokes_sessions(
    postgres_database_url: str,
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    upgrade_database(postgres_database_url)
    capsys.readouterr()
    initial = PostgresBreakGlassStore(
        postgres_database_url,
        encryption_key=b"K" * 32,
    )
    initial.provision(
        account=OperatorAccount(
            identity_source=OperatorIdentitySource.BREAK_GLASS,
            id=ACCOUNT_ID,
            subject="local:emergency-admin",
            display_name="Emergency administrator",
            roles=frozenset({OperatorRole.BREAK_GLASS}),
            scopes=frozenset({"server:*"}),
            authz_version=1,
            enabled=True,
        ),
        password_scrypt=BreakGlassCredentials.hash_password(
            "old correct horse battery staple",
            salt=b"S" * 16,
        ),
        totp_secret=b"B" * 20,
        context=TEST_MUTATION_CONTEXT,
    )
    initial.close()
    engine = create_engine(postgres_database_url, hide_parameters=True)
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO operator_sessions "
                "(id, account_id, token_sha256, csrf_sha256, authz_version, issued_at, "
                "last_seen_at, idle_expires_at, absolute_expires_at, mfa_verified_at) "
                "VALUES (:id, :account_id, :token, :csrf, 1, clock_timestamp(), "
                "clock_timestamp(), clock_timestamp() + interval '30 minutes', "
                "clock_timestamp() + interval '12 hours', clock_timestamp())"
            ),
            {
                "id": UUID("80000000-0000-4000-8000-000000000008"),
                "account_id": ACCOUNT_ID,
                "token": "a" * 64,
                "csrf": "b" * 64,
            },
        )
    encryption_key_file = tmp_path / "break-glass-encryption-key"
    totp_file = tmp_path / "break-glass-totp"
    encryption_key_file.write_bytes(base64.urlsafe_b64encode(b"K" * 32))
    totp_file.write_bytes(base64.urlsafe_b64encode(b"C" * 20))
    encryption_key_file.chmod(0o600)
    totp_file.chmod(0o600)
    monkeypatch.setenv("RTSP_PROXY_DATABASE_URL", postgres_database_url)
    monkeypatch.setenv(
        "RTSP_PROXY_BREAK_GLASS_ENCRYPTION_KEY_FILE",
        str(encryption_key_file),
    )
    monkeypatch.setenv("RTSP_PROXY_BREAK_GLASS_TOTP_FILE", str(totp_file))
    passwords = iter(("new correct horse battery staple",) * 2)

    assert (
        break_glass_cli_main(
            [
                "--account-id",
                str(ACCOUNT_ID),
                "--username",
                "emergency-admin",
                "--actor",
                "operator:alice",
                "--reason",
                "scheduled emergency credential rotation",
                "--rotate",
                "--expected-authz-version",
                "1",
            ],
            password_reader=lambda _prompt: next(passwords),
        )
        == 0
    )
    output = capsys.readouterr()
    assert output.err == ""
    assert output.out == f"rotated break-glass account {ACCOUNT_ID} to revision 2\n"
    assert "correct horse" not in output.out
    with engine.connect() as connection:
        account = connection.execute(
            text(
                "SELECT authz_version, enabled FROM operator_accounts WHERE id = :id"
            ),
            {"id": ACCOUNT_ID},
        ).one()
        revoked_at = connection.scalar(
            text("SELECT revoked_at FROM operator_sessions WHERE account_id = :id"),
            {"id": ACCOUNT_ID},
        )
        audit = connection.execute(
            text(
                "SELECT id, aggregate_revision, payload FROM audit_events "
                "WHERE event_type = 'operator.break_glass_rotated'"
            )
        ).one()
        outbox = connection.execute(
            text(
                "SELECT id, aggregate_revision, payload FROM outbox_messages "
                "WHERE event_type = 'operator.break_glass_rotated'"
            )
        ).one()
    assert account == (2, True)
    assert revoked_at is not None
    assert audit == outbox
    assert audit.aggregate_revision == 2
    assert audit.payload == {
        "account_id": str(ACCOUNT_ID),
        "action": "operator.break_glass_rotate",
        "actor": "operator:alice",
        "after": {"authz_version": 2, "enabled": True},
        "auth_method": "privileged_local_cli",
        "before": {"authz_version": 1, "enabled": True},
        "identity_source": "break_glass",
        "object_type": "operator_account",
        "outcome": "rotated",
        "reason": "scheduled emergency credential rotation",
        "revoked_sessions": 1,
    }
    stale_passwords = iter(("stale replacement password",) * 2)
    assert (
        break_glass_cli_main(
            [
                "--account-id",
                str(ACCOUNT_ID),
                "--username",
                "emergency-admin",
                "--actor",
                "operator:alice",
                "--reason",
                "stale retry",
                "--rotate",
                "--expected-authz-version",
                "1",
            ],
            password_reader=lambda _prompt: next(stale_passwords),
        )
        == 1
    )
    stale_output = capsys.readouterr()
    assert stale_output.out == ""
    assert stale_output.err == (
        "break-glass provisioning failed: break_glass_account_conflict\n"
    )
    with engine.connect() as connection:
        assert (
            connection.scalar(
                text(
                    "SELECT count(*) FROM audit_events "
                    "WHERE event_type = 'operator.break_glass_rotated'"
                )
            )
            == 1
        )
        rejection = connection.execute(
            text(
                "SELECT payload FROM audit_events "
                "WHERE event_type = 'operator.break_glass_rotation_rejected'"
            )
        ).one()
        rejection_outbox = connection.execute(
            text(
                "SELECT payload FROM outbox_messages "
                "WHERE event_type = 'operator.break_glass_rotation_rejected'"
            )
        ).one()
    assert rejection == rejection_outbox
    assert rejection.payload == {
        "account_id": str(ACCOUNT_ID),
        "action": "operator.break_glass_rotate",
        "actor": "operator:alice",
        "auth_method": "privileged_local_cli",
        "expected_authz_version": 1,
        "identity_source": "break_glass",
        "object_type": "operator_account",
        "outcome": "rejected",
        "reason": "stale retry",
        "reason_code": "identity_or_revision_conflict",
        "requested_account_id": str(ACCOUNT_ID),
    }
    rotated = PostgresBreakGlassStore(
        postgres_database_url,
        encryption_key=b"K" * 32,
    )
    old_code = TOTP(b"B" * 20, 6, hashes.SHA1(), 30).generate(int(NOW.timestamp())).decode()
    with pytest.raises(OidcLoginInvalid, match="break_glass_login_failed"):
        rotated.authenticate(
            username="emergency-admin",
            password="old correct horse battery staple",
            totp=old_code,
            source_ip="192.0.2.10",
            now=NOW,
        )
    new_code = TOTP(b"C" * 20, 6, hashes.SHA1(), 30).generate(int(NOW.timestamp())).decode()
    assert (
        rotated.authenticate(
            username="emergency-admin",
            password="new correct horse battery staple",
            totp=new_code,
            source_ip="192.0.2.10",
            now=NOW,
        )
        == BreakGlassAuthentication(ACCOUNT_ID, 2)
    )
    observability = PostgresObservabilityStore(postgres_database_url)

    class RecordingSecurityTransport:
        def __init__(self) -> None:
            self.outcomes: list[str] = []

        def send(self, message: Any) -> None:
            self.outcomes.append(message.outcome)

    transport = RecordingSecurityTransport()
    dispatcher = OperatorSecurityAlertDispatcher(
        store=observability,
        transport=transport,
        clock=lambda: datetime.now(UTC) + timedelta(seconds=1),
    )
    assert dispatcher.run_once() is not None
    assert dispatcher.run_once() is not None
    assert dispatcher.run_once() is None
    assert transport.outcomes == ["rejected", "accepted"]
    observability.close()
    rotated.close()
    engine.dispose()


def test_break_glass_cli_audits_rotation_with_wrong_account_id(
    postgres_database_url: str,
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    upgrade_database(postgres_database_url)
    capsys.readouterr()
    existing = PostgresBreakGlassStore(
        postgres_database_url,
        encryption_key=b"K" * 32,
    )
    existing.provision(
        account=OperatorAccount(
            identity_source=OperatorIdentitySource.BREAK_GLASS,
            id=ACCOUNT_ID,
            subject="local:emergency-admin",
            display_name="Emergency administrator",
            roles=frozenset({OperatorRole.BREAK_GLASS}),
            scopes=frozenset({"server:*"}),
            authz_version=1,
            enabled=True,
        ),
        password_scrypt=BreakGlassCredentials.hash_password(
            "old correct horse battery staple",
            salt=b"S" * 16,
        ),
        totp_secret=b"B" * 20,
        context=TEST_MUTATION_CONTEXT,
    )
    existing.close()
    encryption_key_file = tmp_path / "break-glass-encryption-key"
    totp_file = tmp_path / "break-glass-totp"
    encryption_key_file.write_bytes(base64.urlsafe_b64encode(b"K" * 32))
    totp_file.write_bytes(base64.urlsafe_b64encode(b"C" * 20))
    encryption_key_file.chmod(0o600)
    totp_file.chmod(0o600)
    monkeypatch.setenv("RTSP_PROXY_DATABASE_URL", postgres_database_url)
    monkeypatch.setenv(
        "RTSP_PROXY_BREAK_GLASS_ENCRYPTION_KEY_FILE",
        str(encryption_key_file),
    )
    monkeypatch.setenv("RTSP_PROXY_BREAK_GLASS_TOTP_FILE", str(totp_file))
    wrong_account_id = UUID("90000000-0000-4000-8000-000000000009")
    passwords = iter(("new correct horse battery staple",) * 2)

    assert (
        break_glass_cli_main(
            [
                "--account-id",
                str(wrong_account_id),
                "--username",
                "emergency-admin",
                "--actor",
                "operator:alice",
                "--reason",
                "wrong account retry",
                "--rotate",
                "--expected-authz-version",
                "1",
            ],
            password_reader=lambda _prompt: next(passwords),
        )
        == 1
    )
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == (
        "break-glass provisioning failed: break_glass_account_conflict\n"
    )
    engine = create_engine(postgres_database_url, hide_parameters=True)
    with engine.connect() as connection:
        audit = connection.execute(
            text(
                "SELECT aggregate_id, aggregate_revision, payload FROM audit_events "
                "WHERE event_type = 'operator.break_glass_rotation_rejected'"
            )
        ).one()
        outbox = connection.execute(
            text(
                "SELECT aggregate_id, aggregate_revision, payload FROM outbox_messages "
                "WHERE event_type = 'operator.break_glass_rotation_rejected'"
            )
        ).one()
    assert audit == outbox
    assert audit.aggregate_id == ACCOUNT_ID
    assert audit.aggregate_revision == 1
    assert audit.payload == {
        "account_id": str(ACCOUNT_ID),
        "action": "operator.break_glass_rotate",
        "actor": "operator:alice",
        "auth_method": "privileged_local_cli",
        "expected_authz_version": 1,
        "identity_source": "break_glass",
        "object_type": "operator_account",
        "outcome": "rejected",
        "reason": "wrong account retry",
        "reason_code": "identity_or_revision_conflict",
        "requested_account_id": str(wrong_account_id),
    }
    engine.dispose()


def test_break_glass_cli_rejects_noncanonical_secrets_and_bad_database_url(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    key_file = tmp_path / "key"
    totp_file = tmp_path / "totp"
    key_file.write_bytes(b"!" + base64.urlsafe_b64encode(b"K" * 32))
    totp_file.write_bytes(base64.urlsafe_b64encode(b"B" * 20))
    key_file.chmod(0o600)
    totp_file.chmod(0o600)
    monkeypatch.setenv("RTSP_PROXY_DATABASE_URL", "not-a-database-url")
    monkeypatch.setenv("RTSP_PROXY_BREAK_GLASS_ENCRYPTION_KEY_FILE", str(key_file))
    monkeypatch.setenv("RTSP_PROXY_BREAK_GLASS_TOTP_FILE", str(totp_file))
    arguments = [
        "--account-id",
        str(ACCOUNT_ID),
        "--actor",
        "operator:alice",
        "--reason",
        "scheduled rotation",
    ]

    assert (
        break_glass_cli_main(
            arguments,
            password_reader=lambda _prompt: "correct horse battery staple",
        )
        == 1
    )
    first_error = capsys.readouterr().err
    assert first_error == "break-glass provisioning failed: break_glass_secret_invalid\n"
    assert "Traceback" not in first_error

    key_file.write_bytes(base64.urlsafe_b64encode(b"K" * 32))
    assert (
        break_glass_cli_main(
            arguments,
            password_reader=lambda _prompt: "correct horse battery staple",
        )
        == 1
    )
    second_error = capsys.readouterr().err
    assert second_error == "break-glass provisioning failed: break_glass_configuration_invalid\n"
    assert "Traceback" not in second_error


def test_break_glass_rotation_compare_and_swap_allows_one_concurrent_writer(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    first = PostgresBreakGlassStore(postgres_database_url, encryption_key=b"K" * 32)
    second = PostgresBreakGlassStore(postgres_database_url, encryption_key=b"K" * 32)
    first.provision(
        account=OperatorAccount(
            identity_source=OperatorIdentitySource.BREAK_GLASS,
            id=ACCOUNT_ID,
            subject="local:emergency-admin",
            display_name="Emergency administrator",
            roles=frozenset({OperatorRole.BREAK_GLASS}),
            scopes=frozenset({"server:*"}),
            authz_version=1,
            enabled=True,
        ),
        password_scrypt=BreakGlassCredentials.hash_password(
            "old correct horse battery staple",
            salt=b"S" * 16,
        ),
        totp_secret=b"B" * 20,
        context=TEST_MUTATION_CONTEXT,
    )

    def rotate(store: PostgresBreakGlassStore, marker: bytes) -> int | str:
        try:
            return store.rotate(
                account_id=ACCOUNT_ID,
                subject="local:emergency-admin",
                expected_authz_version=1,
                password_scrypt=BreakGlassCredentials.hash_password(
                    "new correct horse battery staple",
                    salt=marker * 16,
                ),
                totp_secret=marker * 20,
                context=OperatorMutationContext(
                    actor="operator:alice",
                    reason=f"concurrent rotation {marker.decode()}",
                ),
            )
        except OidcLoginInvalid as error:
            return str(error)

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = tuple(
            pool.map(
                lambda arguments: rotate(*arguments),
                ((first, b"C"), (second, b"D")),
            )
        )

    assert sorted(outcomes, key=str) == [2, "break_glass_account_conflict"]
    engine = create_engine(postgres_database_url, hide_parameters=True)
    with engine.connect() as connection:
        counts = {
            str(row[0]): int(row[1])
            for row in connection.execute(
                text(
                    "SELECT event_type, count(*) FROM audit_events "
                    "WHERE event_type IN ('operator.break_glass_rotated', "
                    "'operator.break_glass_rotation_rejected') GROUP BY event_type"
                )
            ).all()
        }
        assert counts == {
            "operator.break_glass_rotated": 1,
            "operator.break_glass_rotation_rejected": 1,
        }
        assert connection.scalar(
            text("SELECT authz_version FROM operator_accounts WHERE id = :id"),
            {"id": ACCOUNT_ID},
        ) == 2
    engine.dispose()
    second.close()
    first.close()


def test_break_glass_rotation_fences_session_issuance_after_old_authentication(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    break_glass = PostgresBreakGlassStore(
        postgres_database_url,
        encryption_key=b"K" * 32,
    )
    break_glass.provision(
        account=OperatorAccount(
            identity_source=OperatorIdentitySource.BREAK_GLASS,
            id=ACCOUNT_ID,
            subject="local:emergency-admin",
            display_name="Emergency administrator",
            roles=frozenset({OperatorRole.BREAK_GLASS}),
            scopes=frozenset({"server:*"}),
            authz_version=1,
            enabled=True,
        ),
        password_scrypt=BreakGlassCredentials.hash_password(
            "old correct horse battery staple",
            salt=b"S" * 16,
        ),
        totp_secret=b"B" * 20,
        context=TEST_MUTATION_CONTEXT,
    )
    authenticated = Event()
    release = Event()

    class PausingAuthenticator:
        def authenticate(
            self,
            *,
            username: str,
            password: str,
            totp: str,
            source_ip: str,
            now: datetime,
        ) -> BreakGlassAuthentication:
            result = break_glass.authenticate(
                username=username,
                password=password,
                totp=totp,
                source_ip=source_ip,
                now=now,
            )
            authenticated.set()
            assert release.wait(timeout=5)
            return result

    sessions_store = PostgresOperatorSessionStore(postgres_database_url)
    control = BreakGlassControl(
        store=PausingAuthenticator(),
        sessions=OperatorSessionControl(
            store=sessions_store,
            token_factory=iter(("T" * 43, "C" * 43)).__next__,
        ),
        clock=lambda: NOW,
    )
    code = TOTP(b"B" * 20, 6, hashes.SHA1(), 30).generate(int(NOW.timestamp())).decode()
    with ThreadPoolExecutor(max_workers=1) as pool:
        login = pool.submit(
            control.login,
            username="emergency-admin",
            password="old correct horse battery staple",
            totp=code,
            source_ip="192.0.2.10",
        )
        assert authenticated.wait(timeout=5)
        assert (
            break_glass.rotate(
                account_id=ACCOUNT_ID,
                subject="local:emergency-admin",
                expected_authz_version=1,
                password_scrypt=BreakGlassCredentials.hash_password(
                    "new correct horse battery staple",
                    salt=b"N" * 16,
                ),
                totp_secret=b"C" * 20,
                context=OperatorMutationContext(
                    actor="operator:alice",
                    reason="race regression",
                ),
            )
            == 2
        )
        release.set()
        with pytest.raises(OidcLoginInvalid, match="break_glass_login_failed"):
            login.result(timeout=5)
    engine = create_engine(postgres_database_url, hide_parameters=True)
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT count(*) FROM operator_sessions")) == 0
    engine.dispose()
    sessions_store.close()
    break_glass.close()


@pytest.mark.parametrize(
    "extra_arguments",
    (
        ("--rotate",),
        ("--expected-authz-version", "1"),
        ("--rotate", "--expected-authz-version", str((1 << 63) - 1)),
    ),
)
def test_break_glass_cli_requires_revision_only_for_explicit_rotation(
    extra_arguments: tuple[str, ...],
    capsys: pytest.CaptureFixture[str],
) -> None:
    prompted = False

    def password_reader(_prompt: str) -> str:
        nonlocal prompted
        prompted = True
        return "should not be read"

    assert (
        break_glass_cli_main(
            [
                "--account-id",
                str(ACCOUNT_ID),
                "--actor",
                "operator:alice",
                "--reason",
                "invalid mode",
                *extra_arguments,
            ],
            password_reader=password_reader,
        )
        == 1
    )
    assert not prompted
    assert capsys.readouterr().err == (
        "break-glass provisioning failed: break_glass_configuration_invalid\n"
    )


def test_break_glass_alert_is_claimed_once_and_completed_by_notification_worker(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    account = OperatorAccount(
        identity_source=OperatorIdentitySource.BREAK_GLASS,
        id=ACCOUNT_ID,
        subject="local:emergency-admin",
        display_name="Emergency administrator",
        roles=frozenset({OperatorRole.BREAK_GLASS}),
        scopes=frozenset({"server:*"}),
        authz_version=1,
        enabled=True,
    )
    store = PostgresBreakGlassStore(
        postgres_database_url,
        encryption_key=b"K" * 32,
    )
    store.provision(
        account=account,
        password_scrypt=BreakGlassCredentials.hash_password(
            "correct horse battery staple",
            salt=b"S" * 16,
        ),
        totp_secret=b"B" * 20,
        context=TEST_MUTATION_CONTEXT,
    )
    code = TOTP(b"B" * 20, 6, hashes.SHA1(), 30).generate(int(NOW.timestamp())).decode()
    store.authenticate(
        username="emergency-admin",
        password="correct horse battery staple",
        totp=code,
        source_ip="192.0.2.10",
        now=NOW,
    )
    observability = PostgresObservabilityStore(postgres_database_url)

    class RecordingSecurityTransport:
        def __init__(self) -> None:
            self.outcomes: list[str] = []

        def send(self, message: Any) -> None:
            self.outcomes.append(message.outcome)

    transport = RecordingSecurityTransport()
    dispatcher = OperatorSecurityAlertDispatcher(
        store=observability,
        transport=transport,
        clock=lambda: datetime.now(UTC) + timedelta(seconds=1),
    )

    completed = dispatcher.run_once()

    assert completed is not None
    assert completed.status is NotificationStatus.SENT
    assert transport.outcomes == ["accepted"]
    assert dispatcher.run_once() is None
    observability.close()
    store.close()


def test_oidc_claim_contract_alert_records_only_failure_and_recovery_transitions(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresBreakGlassStore(
        postgres_database_url,
        encryption_key=b"K" * 32,
    )
    store.provision(
        account=OperatorAccount(
            identity_source=OperatorIdentitySource.BREAK_GLASS,
            id=ACCOUNT_ID,
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
        context=TEST_MUTATION_CONTEXT,
    )

    store.record_claim_contract_health(healthy=True)
    store.record_claim_contract_health(healthy=False)
    store.record_claim_contract_health(healthy=False)
    store.record_claim_contract_health(healthy=True)
    store.record_claim_contract_health(healthy=True)

    engine = create_engine(postgres_database_url, hide_parameters=True)
    with engine.connect() as connection:
        alerts = connection.execute(
            text(
                "SELECT outcome, reason_code FROM operator_security_alerts "
                "WHERE event_type = 'operator.oidc_claim_contract' ORDER BY created_at, id"
            )
        ).all()
    engine.dispose()
    store.close()
    assert tuple(tuple(alert) for alert in alerts) == (
        ("failed", "claim_contract_changed"),
        ("recovered", "claim_contract_restored"),
    )


def test_break_glass_progressive_limit_is_durable_and_counts_only_failures(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresBreakGlassStore(
        postgres_database_url,
        encryption_key=b"K" * 32,
    )
    store.provision(
        account=OperatorAccount(
            identity_source=OperatorIdentitySource.BREAK_GLASS,
            id=ACCOUNT_ID,
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
        context=TEST_MUTATION_CONTEXT,
    )
    code = TOTP(b"B" * 20, 6, hashes.SHA1(), 30).generate(int(NOW.timestamp())).decode()
    for _attempt in range(4):
        with pytest.raises(Exception, match="break_glass_login_failed"):
            store.authenticate(
                username="emergency-admin",
                password="wrong password",
                totp=code,
                source_ip="192.0.2.10",
                now=NOW,
            )

    authentication = store.authenticate(
        username="emergency-admin",
        password="correct horse battery staple",
        totp=code,
        source_ip="192.0.2.10",
        now=NOW,
    )

    assert authentication == BreakGlassAuthentication(ACCOUNT_ID, 1)
    engine = create_engine(postgres_database_url, hide_parameters=True)
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT count(*) FROM operator_login_attempts")) == 0
        assert (
            connection.scalar(
                text("SELECT count(*) FROM operator_security_alerts WHERE outcome = 'rejected'")
            )
            == 4
        )
    engine.dispose()
    store.close()


def test_break_glass_failures_do_not_globally_lock_the_emergency_account(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresBreakGlassStore(
        postgres_database_url,
        encryption_key=b"K" * 32,
    )
    store.provision(
        account=OperatorAccount(
            identity_source=OperatorIdentitySource.BREAK_GLASS,
            id=ACCOUNT_ID,
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
        context=TEST_MUTATION_CONTEXT,
    )
    code = TOTP(b"B" * 20, 6, hashes.SHA1(), 30).generate(int(NOW.timestamp())).decode()
    for _attempt in range(5):
        with pytest.raises((OidcLoginInvalid, OidcLoginRateLimited)):
            store.authenticate(
                username="emergency-admin",
                password="wrong password",
                totp=code,
                source_ip="198.51.100.10",
                now=NOW,
            )

    authentication = store.authenticate(
        username="emergency-admin",
        password="correct horse battery staple",
        totp=code,
        source_ip="198.51.100.11",
        now=NOW,
    )

    assert authentication == BreakGlassAuthentication(ACCOUNT_ID, 1)
    store.close()


def test_operator_identity_postgres_adapters_normalize_database_outage() -> None:
    database_url = "postgresql+psycopg://invalid:invalid@127.0.0.1:1/invalid"
    account = OperatorAccount(
        identity_source=OperatorIdentitySource.BREAK_GLASS,
        id=ACCOUNT_ID,
        subject="local:emergency-admin",
        display_name="Emergency administrator",
        roles=frozenset({OperatorRole.BREAK_GLASS}),
        scopes=frozenset({"server:*"}),
        authz_version=1,
        enabled=True,
    )
    with pytest.raises(ValueError, match="break_glass_store_configuration_invalid"):
        PostgresBreakGlassStore(database_url, encryption_key=b"short")
    break_glass = PostgresBreakGlassStore(
        database_url,
        encryption_key=b"K" * 32,
        statement_timeout_ms=100,
    )
    break_glass_operations = (
        break_glass.existing_break_glass_account_id,
        break_glass.assert_ready,
        lambda: break_glass.record_claim_contract_health(healthy=False),
        lambda: break_glass.provision(
            account=account,
            password_scrypt=BreakGlassCredentials.hash_password(
                "correct horse battery staple",
                salt=b"S" * 16,
            ),
            totp_secret=b"B" * 20,
            context=TEST_MUTATION_CONTEXT,
        ),
        lambda: break_glass.authenticate(
            username="emergency-admin",
            password="correct horse battery staple",
            totp="000000",
            source_ip="192.0.2.10",
            now=NOW,
        ),
    )
    for operation in break_glass_operations:
        with pytest.raises(OidcLoginUnavailable):
            operation()
    break_glass.close()

    flows = PostgresOidcFlowStore(database_url, statement_timeout_ms=100)
    flow_operations = (
        flows.assert_ready,
        lambda: flows.create(
            state_sha256="a" * 64,
            browser_sha256="b" * 64,
            source_ip_sha256="c" * 64,
            return_to="/",
            lifetime=timedelta(minutes=5),
        ),
        lambda: flows.consume("a" * 64, browser_sha256="b" * 64),
        lambda: flows.record_rejection(source_ip_sha256="c" * 64),
        lambda: flows.assert_identity_allowed(identity_sha256="d" * 64),
        lambda: flows.record_identity_rejection(identity_sha256="d" * 64),
        lambda: flows.record_success(
            source_ip_sha256="c" * 64,
            identity_sha256="d" * 64,
        ),
    )
    for flow_operation in flow_operations:
        with pytest.raises(OidcLoginUnavailable):
            flow_operation()
    flows.close()

    with pytest.raises(ValueError, match="database_statement_timeout_invalid"):
        PostgresOidcAccountResolver(database_url, issuer="http://idp.example.test")
    resolver = PostgresOidcAccountResolver(
        database_url,
        issuer="https://idp.example.test",
        statement_timeout_ms=100,
    )
    with pytest.raises(OidcLoginUnavailable, match="oidc_account_store_unavailable"):
        resolver.resolve(
            OidcIdentity(
                subject="operator-42",
                display_name="Operator",
                groups=frozenset({"rtsp-operators"}),
                roles=frozenset({OperatorRole.OPERATOR}),
                mfa_verified=True,
            )
        )
    resolver.close()


def test_in_memory_oidc_flow_rejects_invalid_duplicate_and_expired_state() -> None:
    valid_flow = {
        "state_sha256": "a" * 64,
        "browser_sha256": "b" * 64,
        "source_ip_sha256": "c" * 64,
        "return_to": "/",
        "created_at": NOW,
        "expires_at": NOW + timedelta(minutes=5),
    }
    for field, invalid_value in (
        ("state_sha256", "short"),
        ("browser_sha256", "short"),
        ("source_ip_sha256", "short"),
        ("return_to", "//attacker.example.test"),
        ("created_at", NOW.replace(tzinfo=None)),
        ("expires_at", NOW),
    ):
        with pytest.raises(ValueError, match="oidc_flow_invalid"):
            OidcFlow(**(valid_flow | {field: invalid_value}))  # type: ignore[arg-type]

    current_time = [NOW]
    flows = InMemoryOidcFlowStore(clock=lambda: current_time[0])
    flows.create(
        state_sha256="a" * 64,
        browser_sha256="b" * 64,
        source_ip_sha256="c" * 64,
        return_to="/",
        lifetime=timedelta(seconds=1),
    )
    with pytest.raises(OidcLoginInvalid, match="oidc_flow_conflict"):
        flows.create(
            state_sha256="a" * 64,
            browser_sha256="b" * 64,
            source_ip_sha256="c" * 64,
            return_to="/",
            lifetime=timedelta(seconds=1),
        )
    current_time[0] = NOW + timedelta(seconds=1)
    with pytest.raises(OidcLoginInvalid, match="oidc_flow_invalid"):
        flows.consume("a" * 64, browser_sha256="b" * 64)
    flows.assert_identity_allowed(identity_sha256="d" * 64)
    flows.record_identity_rejection(identity_sha256="d" * 64)
    flows.record_success(source_ip_sha256="c" * 64, identity_sha256="d" * 64)
