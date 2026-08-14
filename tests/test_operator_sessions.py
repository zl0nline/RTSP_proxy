from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

from rtsp_proxy.app import create_app
from rtsp_proxy.config import RuntimeRole, Settings
from rtsp_proxy.migrate import upgrade_database
from rtsp_proxy.operator_access import (
    MAX_AUTHZ_VERSION,
    InMemoryOperatorSessionStore,
    OperatorAccount,
    OperatorAuthenticationRequired,
    OperatorAuthorizationDenied,
    OperatorConflict,
    OperatorIdentitySource,
    OperatorMutationContext,
    OperatorPermission,
    OperatorRole,
    OperatorSession,
    OperatorSessionControl,
    OperatorSessionFailure,
    OperatorSessionUnavailable,
    PostgresOperatorSessionStore,
)

NOW = datetime(2026, 8, 13, 18, 0, tzinfo=UTC)
ACCOUNT_ID = UUID("60000000-0000-0000-0000-000000000006")
MUTATION_CONTEXT = OperatorMutationContext(
    actor="oidc:admin@example.test",
    reason="operator authorization test",
)


def test_operator_session_public_contract_rejects_invalid_boundary_states() -> None:
    with pytest.raises(ValueError, match="operator_mutation_context_invalid"):
        OperatorMutationContext(actor="", reason="invalid fixture")
    valid_session = OperatorSession(
        id=UUID("70000000-0000-0000-0000-000000000007"),
        account_id=ACCOUNT_ID,
        token_sha256="a" * 64,
        csrf_sha256="b" * 64,
        authz_version=1,
        issued_at=NOW,
        last_seen_at=NOW,
        idle_expires_at=NOW + timedelta(minutes=30),
        absolute_expires_at=NOW + timedelta(hours=12),
        mfa_verified_at=NOW,
    )
    for changes in (
        {"token_sha256": "short"},
        {"csrf_sha256": "short"},
        {"authz_version": 0},
        {"issued_at": NOW.replace(tzinfo=None)},
        {"last_seen_at": NOW.replace(tzinfo=None)},
        {"idle_expires_at": NOW},
        {"absolute_expires_at": NOW},
    ):
        with pytest.raises(ValueError, match="operator_session_invalid"):
            replace(valid_session, **changes)

    account = OperatorAccount(
        identity_source=OperatorIdentitySource.OIDC,
        id=ACCOUNT_ID,
        subject="oidc:operator@example.test",
        display_name="Оператор",
        roles=frozenset({OperatorRole.VIEWER}),
        scopes=frozenset({"server:*"}),
        authz_version=1,
        enabled=True,
    )
    store = InMemoryOperatorSessionStore(accounts=(account,), clock=lambda: NOW)
    with pytest.raises(ValueError, match="operator_authz_initial_version_invalid"):
        store.create_account(
            OperatorAccount(
                identity_source=OperatorIdentitySource.OIDC,
                id=UUID("61000000-0000-0000-0000-000000000006"),
                subject="oidc:second@example.test",
                display_name="Second operator",
                roles=frozenset({OperatorRole.VIEWER}),
                scopes=frozenset({"server:*"}),
                authz_version=2,
                enabled=True,
            )
        )
    with pytest.raises(OperatorConflict, match="operator_account_exists"):
        store.create_account(account)
    with pytest.raises(OperatorAuthenticationRequired, match="operator_account_unavailable"):
        store.issue_session(
            session_id=UUID("70000000-0000-0000-0000-000000000007"),
            account_id=UUID("62000000-0000-0000-0000-000000000006"),
            token_sha256="a" * 64,
            csrf_sha256="b" * 64,
            idle_timeout=timedelta(minutes=30),
            absolute_timeout=timedelta(hours=12),
            mfa_verified=True,
        )

    session = store.issue_session(
        session_id=UUID("70000000-0000-0000-0000-000000000007"),
        account_id=ACCOUNT_ID,
        token_sha256="a" * 64,
        csrf_sha256="b" * 64,
        idle_timeout=timedelta(minutes=30),
        absolute_timeout=timedelta(hours=12),
        mfa_verified=True,
    )
    with pytest.raises(ValueError, match="operator_session_token_conflict"):
        store.issue_session(
            session_id=UUID("71000000-0000-0000-0000-000000000007"),
            account_id=ACCOUNT_ID,
            token_sha256="a" * 64,
            csrf_sha256="c" * 64,
            idle_timeout=timedelta(minutes=30),
            absolute_timeout=timedelta(hours=12),
            mfa_verified=True,
        )
    assert store.read_session("z" * 64) is OperatorSessionFailure.INVALID
    assert (
        store.touch_authorized_session(
            session.id,
            token_sha256="z" * 64,
            expected_authz_version=1,
            idle_timeout=timedelta(minutes=30),
        )
        is OperatorSessionFailure.CHANGED
    )
    assert store.revoke_session("z" * 64) is False

    disabled = store.update_authorization(
        account_id=ACCOUNT_ID,
        expected_authz_version=1,
        roles=account.roles,
        scopes=account.scopes,
        enabled=False,
        context=MUTATION_CONTEXT,
    )
    assert disabled.enabled is False
    assert store.read_session("a" * 64) is OperatorSessionFailure.ACCOUNT_UNAVAILABLE

    naive_clock_store = InMemoryOperatorSessionStore(clock=lambda: NOW.replace(tzinfo=None))
    with pytest.raises(ValueError, match="operator_session_clock_invalid"):
        naive_clock_store.read_session("a" * 64)

    with pytest.raises(ValueError, match="operator_session_timing_invalid"):
        OperatorSessionControl(
            store=store,
            token_factory=lambda: "t" * 43,
            idle_timeout=timedelta(hours=2),
            absolute_timeout=timedelta(hours=1),
        )
    no_mfa = OperatorSessionControl(store=store, token_factory=lambda: "t" * 43)
    with pytest.raises(OperatorAuthenticationRequired, match="operator_mfa_required"):
        no_mfa.issue(account_id=ACCOUNT_ID, mfa_verified=False)
    bad_token = OperatorSessionControl(store=store, token_factory=lambda: "short")
    with pytest.raises(ValueError, match="operator_session_token_invalid"):
        bad_token.issue(account_id=ACCOUNT_ID, mfa_verified=True)
    with pytest.raises(OperatorAuthenticationRequired, match="operator_session_invalid"):
        no_mfa.authenticate(
            session_token="x" * 1025,
            permission=OperatorPermission.DASHBOARD_READ,
        )
    with pytest.raises(OperatorAuthenticationRequired, match="operator_session_invalid"):
        no_mfa.revoke("missing")


def test_opaque_session_authenticates_dashboard_and_mutation_with_csrf() -> None:
    store = InMemoryOperatorSessionStore(
        accounts=(
            OperatorAccount(
                identity_source=OperatorIdentitySource.OIDC,
                id=ACCOUNT_ID,
                subject="oidc:operator@example.test",
                display_name="Оператор",
                roles=frozenset({OperatorRole.OPERATOR}),
                scopes=frozenset({"server:*"}),
                authz_version=1,
                enabled=True,
            ),
        ),
        clock=lambda: NOW,
    )
    control = OperatorSessionControl(
        store=store,
        token_factory=iter(("s" * 43, "c" * 43)).__next__,
    )

    issued = control.issue(account_id=ACCOUNT_ID, mfa_verified=True)
    read_principal = control.authenticate(
        session_token=issued.session_token,
        permission=OperatorPermission.DASHBOARD_READ,
    )
    mutation_principal = control.authenticate(
        session_token=issued.session_token,
        permission=OperatorPermission.CONTROL_MUTATE,
        csrf_token=issued.csrf_token,
        require_csrf=True,
    )

    assert read_principal.account_id == ACCOUNT_ID
    assert mutation_principal.roles == frozenset({OperatorRole.OPERATOR})
    assert issued.session_token not in repr(issued.session)
    assert issued.csrf_token not in repr(issued.session)


def test_role_downgrade_invalidates_existing_session_authoritatively() -> None:
    account = OperatorAccount(
        identity_source=OperatorIdentitySource.OIDC,
        id=ACCOUNT_ID,
        subject="oidc:operator@example.test",
        display_name="Оператор",
        roles=frozenset({OperatorRole.OPERATOR}),
        scopes=frozenset({"server:*"}),
        authz_version=1,
        enabled=True,
    )
    store = InMemoryOperatorSessionStore(accounts=(account,), clock=lambda: NOW)
    control = OperatorSessionControl(
        store=store,
        token_factory=iter(("s" * 43, "c" * 43)).__next__,
    )
    issued = control.issue(account_id=ACCOUNT_ID, mfa_verified=True)
    store.update_authorization(
        account_id=account.id,
        expected_authz_version=1,
        roles=frozenset({OperatorRole.VIEWER}),
        scopes=account.scopes,
        enabled=True,
        context=MUTATION_CONTEXT,
    )

    with pytest.raises(OperatorAuthenticationRequired, match="operator_session_stale"):
        control.authenticate(
            session_token=issued.session_token,
            permission=OperatorPermission.CONTROL_MUTATE,
            csrf_token=issued.csrf_token,
            require_csrf=True,
        )


def test_csrf_role_scope_idle_absolute_and_revocation_fail_closed() -> None:
    account = OperatorAccount(
        identity_source=OperatorIdentitySource.OIDC,
        id=ACCOUNT_ID,
        subject="oidc:viewer@example.test",
        display_name="Наблюдатель",
        roles=frozenset({OperatorRole.VIEWER}),
        scopes=frozenset({"server:*"}),
        authz_version=1,
        enabled=True,
    )
    store = InMemoryOperatorSessionStore(accounts=(account,), clock=lambda: current)
    current = NOW
    tokens = iter(("s" * 43, "c" * 43, "t" * 43, "d" * 43, "u" * 43, "e" * 43))
    control = OperatorSessionControl(
        store=store,
        token_factory=tokens.__next__,
        idle_timeout=timedelta(minutes=30),
        absolute_timeout=timedelta(hours=12),
    )
    issued = control.issue(account_id=ACCOUNT_ID, mfa_verified=True)

    with pytest.raises(OperatorAuthorizationDenied, match="operator_permission_denied"):
        control.authenticate(
            session_token=issued.session_token,
            permission=OperatorPermission.CONTROL_MUTATE,
            csrf_token=issued.csrf_token,
            require_csrf=True,
        )
    with pytest.raises(OperatorAuthenticationRequired, match="operator_csrf_invalid"):
        control.authenticate(
            session_token=issued.session_token,
            permission=OperatorPermission.DASHBOARD_READ,
            csrf_token="wrong",
            require_csrf=True,
        )
    assert tuple(event.reason_code for event in store.request_security_events()) == (
        "operator_permission_denied",
        "operator_csrf_invalid",
    )

    current = NOW + timedelta(minutes=31)
    with pytest.raises(OperatorAuthenticationRequired, match="operator_session_expired"):
        control.authenticate(
            session_token=issued.session_token,
            permission=OperatorPermission.DASHBOARD_READ,
        )

    current = NOW
    revoked = control.issue(account_id=ACCOUNT_ID, mfa_verified=True)
    control.revoke(revoked.session_token)
    assert store.request_security_events()[-1].event_type == "operator.session_logout"
    with pytest.raises(OperatorAuthenticationRequired, match="operator_session_revoked"):
        control.authenticate(
            session_token=revoked.session_token,
            permission=OperatorPermission.DASHBOARD_READ,
        )

    absolute = control.issue(account_id=ACCOUNT_ID, mfa_verified=True)
    current = NOW + timedelta(hours=12, seconds=1)
    with pytest.raises(OperatorAuthenticationRequired, match="operator_session_expired"):
        control.authenticate(
            session_token=absolute.session_token,
            permission=OperatorPermission.DASHBOARD_READ,
        )


def test_parallel_safe_requests_share_one_session_without_spurious_logout() -> None:
    store = InMemoryOperatorSessionStore(
        accounts=(
            OperatorAccount(
                identity_source=OperatorIdentitySource.OIDC,
                id=ACCOUNT_ID,
                subject="oidc:viewer@example.test",
                display_name="Наблюдатель",
                roles=frozenset({OperatorRole.VIEWER}),
                scopes=frozenset({"server:*"}),
                authz_version=1,
                enabled=True,
            ),
        )
    )
    control = OperatorSessionControl(
        store=store,
        token_factory=iter(("s" * 43, "c" * 43)).__next__,
    )
    issued = control.issue(account_id=ACCOUNT_ID, mfa_verified=True)

    with ThreadPoolExecutor(max_workers=8) as executor:
        principals = tuple(
            executor.map(
                lambda _index: control.authenticate(
                    session_token=issued.session_token,
                    permission=OperatorPermission.DASHBOARD_READ,
                ),
                range(32),
            )
        )

    assert len(principals) == 32
    assert {principal.session_id for principal in principals} == {issued.session.id}


def test_postgres_session_is_opaque_durable_and_authoritatively_fenced(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    account = OperatorAccount(
        identity_source=OperatorIdentitySource.OIDC,
        id=ACCOUNT_ID,
        subject="oidc:operator@example.test",
        display_name="Оператор",
        roles=frozenset({OperatorRole.OPERATOR}),
        scopes=frozenset({"server:*"}),
        authz_version=1,
        enabled=True,
    )
    first_store = PostgresOperatorSessionStore(postgres_database_url)
    first_store.create_account(account)
    issued = OperatorSessionControl(
        store=first_store,
        token_factory=iter(("s" * 43, "c" * 43)).__next__,
        session_id_factory=lambda: UUID("70000000-0000-0000-0000-000000000007"),
    ).issue(account_id=ACCOUNT_ID, mfa_verified=True)
    first_store.close()

    engine = create_engine(postgres_database_url, hide_parameters=True)
    with engine.connect() as connection:
        row = connection.execute(
            text(
                "SELECT token_sha256, csrf_sha256, issued_at, "
                "idle_expires_at - issued_at AS idle_timeout, "
                "absolute_expires_at - issued_at AS absolute_timeout "
                "FROM operator_sessions"
            )
        ).one()
        session_audit = connection.execute(
            text(
                "SELECT id, event_type, payload FROM audit_events "
                "WHERE event_type = 'operator.session_issued'"
            )
        ).one()
        session_outbox = connection.execute(
            text(
                "SELECT id, event_type, payload FROM outbox_messages "
                "WHERE event_type = 'operator.session_issued'"
            )
        ).one()
    engine.dispose()
    assert row.token_sha256 != issued.session_token
    assert row.csrf_sha256 != issued.csrf_token
    assert row.idle_timeout == timedelta(minutes=30)
    assert row.absolute_timeout == timedelta(hours=12)
    assert session_audit == session_outbox
    assert session_audit.payload["account_id"] == str(ACCOUNT_ID)
    assert session_audit.payload["mfa_verified"] is True

    reopened = PostgresOperatorSessionStore(postgres_database_url)
    principal = OperatorSessionControl(
        store=reopened,
        token_factory=lambda: "unused" * 8,
    ).authenticate(
        session_token=issued.session_token,
        permission=OperatorPermission.CONTROL_MUTATE,
        csrf_token=issued.csrf_token,
        require_csrf=True,
    )
    assert principal.account_id == ACCOUNT_ID

    updated = reopened.update_authorization(
        account_id=account.id,
        expected_authz_version=1,
        roles=frozenset({OperatorRole.VIEWER}),
        scopes=account.scopes,
        enabled=True,
        context=MUTATION_CONTEXT,
    )
    assert updated.authz_version == 2
    with pytest.raises(OperatorAuthenticationRequired, match="operator_session_stale"):
        OperatorSessionControl(
            store=reopened,
            token_factory=lambda: "unused" * 8,
        ).authenticate(
            session_token=issued.session_token,
            permission=OperatorPermission.DASHBOARD_READ,
        )
    reopened.close()


def test_postgres_logout_is_idempotent_and_appends_one_normative_event(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    account = OperatorAccount(
        identity_source=OperatorIdentitySource.OIDC,
        id=ACCOUNT_ID,
        subject="oidc:operator@example.test",
        display_name="Оператор",
        roles=frozenset({OperatorRole.OPERATOR}),
        scopes=frozenset({"server:*"}),
        authz_version=1,
        enabled=True,
    )
    store = PostgresOperatorSessionStore(postgres_database_url)
    store.create_account(account)
    control = OperatorSessionControl(
        store=store,
        token_factory=iter(("s" * 43, "c" * 43)).__next__,
    )
    issued = control.issue(account_id=ACCOUNT_ID, mfa_verified=True)

    control.revoke(issued.session_token)
    with pytest.raises(OperatorAuthenticationRequired, match="operator_session_invalid"):
        control.revoke(issued.session_token)

    engine = create_engine(postgres_database_url, hide_parameters=True)
    with engine.connect() as connection:
        audit = connection.execute(
            text(
                "SELECT id, event_type, payload FROM audit_events "
                "WHERE event_type = 'operator.session_logout'"
            )
        ).one()
        outbox = connection.execute(
            text(
                "SELECT id, event_type, payload FROM outbox_messages "
                "WHERE event_type = 'operator.session_logout'"
            )
        ).one()
    engine.dispose()
    store.close()
    assert audit == outbox
    assert audit.payload == {
        "account_id": str(ACCOUNT_ID),
        "outcome": "accepted",
        "reason_code": "operator_initiated",
        "session_id": str(issued.session.id),
    }


def test_control_api_requires_secure_cookie_rbac_and_csrf() -> None:
    account = OperatorAccount(
        identity_source=OperatorIdentitySource.OIDC,
        id=ACCOUNT_ID,
        subject="oidc:operator@example.test",
        display_name="Оператор",
        roles=frozenset({OperatorRole.OPERATOR}),
        scopes=frozenset({"server:*"}),
        authz_version=1,
        enabled=True,
    )
    store = InMemoryOperatorSessionStore(accounts=(account,), clock=lambda: NOW)
    sessions = OperatorSessionControl(
        store=store,
        token_factory=iter(("s" * 43, "c" * 43)).__next__,
    )
    issued = sessions.issue(account_id=ACCOUNT_ID, mfa_verified=True)
    client = TestClient(
        create_app(Settings(role=RuntimeRole.WEB), operator_sessions=sessions),
        base_url="https://management.example.test",
    )

    anonymous = client.get("/api/v1/operator/session")
    assert anonymous.status_code == 401
    assert anonymous.json() == {"detail": {"code": "operator_authentication_required"}}
    assert anonymous.headers["cache-control"] == "no-store"

    cookie = {"Cookie": f"__Host-rtsp_proxy_session={issued.session_token}"}
    authenticated = client.get("/api/v1/operator/session", headers=cookie)
    assert authenticated.status_code == 200
    assert authenticated.json() == {
        "account_id": str(ACCOUNT_ID),
        "subject": "oidc:operator@example.test",
        "display_name": "Оператор",
        "roles": ["operator"],
        "scopes": ["server:*"],
        "authz_version": 1,
        "mfa_verified_at": NOW.isoformat().replace("+00:00", "Z"),
    }
    assert authenticated.headers["cache-control"] == "no-store"

    missing_csrf = client.delete("/api/v1/operator/session", headers=cookie)
    assert missing_csrf.status_code == 401
    assert missing_csrf.json() == {"detail": {"code": "operator_authentication_required"}}
    logged_out = client.delete(
        "/api/v1/operator/session",
        headers={**cookie, "X-CSRF-Token": issued.csrf_token},
    )
    assert logged_out.status_code == 204
    assert '__Host-rtsp_proxy_session=""' in logged_out.headers["set-cookie"]
    assert "Max-Age=0" in logged_out.headers["set-cookie"]
    assert "HttpOnly" in logged_out.headers["set-cookie"]
    assert "Secure" in logged_out.headers["set-cookie"]
    assert "SameSite=strict" in logged_out.headers["set-cookie"]


def test_mutating_control_endpoint_is_fenced_before_handler() -> None:
    account = OperatorAccount(
        identity_source=OperatorIdentitySource.OIDC,
        id=ACCOUNT_ID,
        subject="oidc:viewer@example.test",
        display_name="Наблюдатель",
        roles=frozenset({OperatorRole.VIEWER}),
        scopes=frozenset({"server:*"}),
        authz_version=1,
        enabled=True,
    )
    store = InMemoryOperatorSessionStore(accounts=(account,), clock=lambda: NOW)
    sessions = OperatorSessionControl(
        store=store,
        token_factory=iter(("s" * 43, "c" * 43)).__next__,
    )
    issued = sessions.issue(account_id=ACCOUNT_ID, mfa_verified=True)
    client = TestClient(
        create_app(Settings(role=RuntimeRole.WEB), operator_sessions=sessions),
        base_url="https://management.example.test",
    )
    cookie = {"Cookie": f"__Host-rtsp_proxy_session={issued.session_token}"}

    denied = client.post(
        "/api/v1/nodes",
        json={"name": "must-not-run"},
        headers={**cookie, "X-CSRF-Token": issued.csrf_token},
    )
    assert denied.status_code == 403
    assert denied.json() == {"detail": {"code": "operator_permission_denied"}}
    assert denied.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("persistent", [False, True])
def test_sixth_login_revokes_only_the_oldest_active_session(
    persistent: bool,
    postgres_database_url: str,
) -> None:
    account = OperatorAccount(
        identity_source=OperatorIdentitySource.OIDC,
        id=ACCOUNT_ID,
        subject="oidc:operator@example.test",
        display_name="Оператор",
        roles=frozenset({OperatorRole.OPERATOR}),
        scopes=frozenset({"server:*"}),
        authz_version=1,
        enabled=True,
    )
    if persistent:
        upgrade_database(postgres_database_url)
        store: InMemoryOperatorSessionStore | PostgresOperatorSessionStore = (
            PostgresOperatorSessionStore(postgres_database_url)
        )
        store.create_account(account)
    else:
        store = InMemoryOperatorSessionStore(accounts=(account,), clock=lambda: NOW)
    raw_tokens = tuple(chr(ord("a") + index) * 43 for index in range(12))
    control = OperatorSessionControl(store=store, token_factory=iter(raw_tokens).__next__)

    issued = tuple(control.issue(account_id=ACCOUNT_ID, mfa_verified=True) for _index in range(6))

    with pytest.raises(OperatorAuthenticationRequired, match="operator_session_revoked"):
        control.authenticate(
            session_token=issued[0].session_token,
            permission=OperatorPermission.DASHBOARD_READ,
        )
    for active in issued[1:]:
        assert (
            control.authenticate(
                session_token=active.session_token,
                permission=OperatorPermission.DASHBOARD_READ,
            ).account_id
            == ACCOUNT_ID
        )
    if isinstance(store, PostgresOperatorSessionStore):
        store.close()


@pytest.mark.parametrize("persistent", [False, True])
def test_authorization_update_is_server_versioned_and_compare_and_swap(
    persistent: bool,
    postgres_database_url: str,
) -> None:
    account = OperatorAccount(
        identity_source=OperatorIdentitySource.OIDC,
        id=ACCOUNT_ID,
        subject="oidc:operator@example.test",
        display_name="Оператор",
        roles=frozenset({OperatorRole.OPERATOR}),
        scopes=frozenset({"server:*"}),
        authz_version=1,
        enabled=True,
    )
    if persistent:
        upgrade_database(postgres_database_url)
        store: InMemoryOperatorSessionStore | PostgresOperatorSessionStore = (
            PostgresOperatorSessionStore(postgres_database_url)
        )
        store.create_account(account)
    else:
        store = InMemoryOperatorSessionStore(accounts=(account,), clock=lambda: NOW)

    updated = store.update_authorization(
        account_id=ACCOUNT_ID,
        expected_authz_version=1,
        roles=frozenset({OperatorRole.VIEWER}),
        scopes=frozenset({"server:*"}),
        enabled=True,
        context=MUTATION_CONTEXT,
    )
    assert updated.authz_version == 2
    assert updated.roles == frozenset({OperatorRole.VIEWER})
    if isinstance(store, InMemoryOperatorSessionStore):
        assert store.authorization_events() == (store.authorization_events()[0],)
        event = store.authorization_events()[0]
        assert event.account_id == ACCOUNT_ID
        assert event.actor == MUTATION_CONTEXT.actor
        assert event.reason == MUTATION_CONTEXT.reason
        assert event.authz_version == 2
        assert event.roles == frozenset({OperatorRole.VIEWER})
    with pytest.raises(OperatorConflict, match="operator_authz_conflict"):
        store.update_authorization(
            account_id=ACCOUNT_ID,
            expected_authz_version=1,
            roles=frozenset({OperatorRole.ADMIN}),
            scopes=frozenset({"server:*"}),
            enabled=True,
            context=MUTATION_CONTEXT,
        )
    if isinstance(store, PostgresOperatorSessionStore):
        store.close()


def test_postgres_authorization_change_is_atomic_with_audit_and_outbox(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    account = OperatorAccount(
        identity_source=OperatorIdentitySource.OIDC,
        id=ACCOUNT_ID,
        subject="oidc:operator@example.test",
        display_name="Оператор",
        roles=frozenset({OperatorRole.OPERATOR}),
        scopes=frozenset({"server:*"}),
        authz_version=1,
        enabled=True,
    )
    store = PostgresOperatorSessionStore(postgres_database_url)
    store.create_account(account)

    updated = store.update_authorization(
        account_id=ACCOUNT_ID,
        expected_authz_version=1,
        roles=frozenset({OperatorRole.VIEWER}),
        scopes=frozenset({"server:*"}),
        enabled=True,
        context=MUTATION_CONTEXT,
    )

    engine = create_engine(postgres_database_url, hide_parameters=True)
    with engine.connect() as connection:
        audit = (
            connection.execute(
                text(
                    "SELECT id, aggregate_revision, payload FROM audit_events "
                    "WHERE aggregate_type = 'operator_account'"
                )
            )
            .mappings()
            .one()
        )
        outbox = (
            connection.execute(
                text(
                    "SELECT id, aggregate_revision, payload FROM outbox_messages "
                    "WHERE aggregate_type = 'operator_account'"
                )
            )
            .mappings()
            .one()
        )
    assert audit == outbox
    assert audit["aggregate_revision"] == updated.authz_version == 2
    assert audit["payload"] == {
        "account_id": str(ACCOUNT_ID),
        "actor": MUTATION_CONTEXT.actor,
        "reason": MUTATION_CONTEXT.reason,
        "roles": ["viewer"],
        "scopes": ["server:*"],
        "enabled": True,
        "authz_version": 2,
    }
    engine.dispose()
    store.close()


@pytest.mark.parametrize("rejected_table", ["audit_events", "outbox_messages"])
def test_postgres_authorization_change_rolls_back_when_normative_append_fails(
    postgres_database_url: str,
    rejected_table: str,
) -> None:
    upgrade_database(postgres_database_url)
    account = OperatorAccount(
        identity_source=OperatorIdentitySource.OIDC,
        id=ACCOUNT_ID,
        subject="oidc:operator@example.test",
        display_name="Оператор",
        roles=frozenset({OperatorRole.OPERATOR}),
        scopes=frozenset({"server:*"}),
        authz_version=1,
        enabled=True,
    )
    store = PostgresOperatorSessionStore(postgres_database_url)
    store.create_account(account)
    engine = create_engine(postgres_database_url, hide_parameters=True)
    trigger_name = f"reject_operator_{rejected_table}"
    with engine.begin() as connection:
        connection.execute(
            text(
                f"CREATE FUNCTION {trigger_name}() RETURNS trigger AS $$ "
                "BEGIN RAISE EXCEPTION 'reject operator event'; END; $$ LANGUAGE plpgsql"
            )
        )
        connection.execute(
            text(
                f"CREATE TRIGGER {trigger_name} BEFORE INSERT ON {rejected_table} "
                "FOR EACH ROW WHEN (NEW.aggregate_type = 'operator_account') "
                f"EXECUTE FUNCTION {trigger_name}()"
            )
        )

    with pytest.raises(
        OperatorSessionUnavailable,
        match="operator_session_store_unavailable",
    ):
        store.update_authorization(
            account_id=ACCOUNT_ID,
            expected_authz_version=1,
            roles=frozenset({OperatorRole.ADMIN}),
            scopes=frozenset({"server:*"}),
            enabled=True,
            context=MUTATION_CONTEXT,
        )

    assert store.get_account(ACCOUNT_ID) == account
    with engine.connect() as connection:
        assert (
            connection.scalar(
                text("SELECT count(*) FROM audit_events WHERE aggregate_type = 'operator_account'")
            )
            == 0
        )
        assert (
            connection.scalar(
                text(
                    "SELECT count(*) FROM outbox_messages WHERE aggregate_type = 'operator_account'"
                )
            )
            == 0
        )
    engine.dispose()
    store.close()


@pytest.mark.parametrize(
    "scopes",
    [
        frozenset(),
        frozenset({"unknown:*"}),
        frozenset({"camera:bad/path"}),
        frozenset(f"camera:{index}" for index in range(129)),
    ],
)
def test_operator_scope_contract_rejects_invalid_values_before_any_adapter(
    scopes: frozenset[str],
) -> None:
    with pytest.raises(ValueError, match="operator_account_invalid"):
        OperatorAccount(
            identity_source=OperatorIdentitySource.OIDC,
            id=ACCOUNT_ID,
            subject="oidc:operator@example.test",
            display_name="Оператор",
            roles=frozenset({OperatorRole.OPERATOR}),
            scopes=scopes,
            authz_version=1,
            enabled=True,
        )


@pytest.mark.parametrize("persistent", [False, True])
def test_concurrent_authorization_updates_have_one_monotonic_winner(
    persistent: bool,
    postgres_database_url: str,
) -> None:
    account = OperatorAccount(
        identity_source=OperatorIdentitySource.OIDC,
        id=ACCOUNT_ID,
        subject="oidc:operator@example.test",
        display_name="Оператор",
        roles=frozenset({OperatorRole.OPERATOR}),
        scopes=frozenset({"server:*"}),
        authz_version=1,
        enabled=True,
    )
    if persistent:
        upgrade_database(postgres_database_url)
        store: InMemoryOperatorSessionStore | PostgresOperatorSessionStore = (
            PostgresOperatorSessionStore(postgres_database_url)
        )
        store.create_account(account)
    else:
        store = InMemoryOperatorSessionStore(accounts=(account,), clock=lambda: NOW)

    def mutate(role: OperatorRole) -> OperatorAccount | OperatorConflict:
        try:
            return store.update_authorization(
                account_id=ACCOUNT_ID,
                expected_authz_version=1,
                roles=frozenset({role}),
                scopes=frozenset({"server:*"}),
                enabled=True,
                context=MUTATION_CONTEXT,
            )
        except OperatorConflict as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(mutate, (OperatorRole.VIEWER, OperatorRole.ADMIN)))

    winners = tuple(result for result in results if isinstance(result, OperatorAccount))
    conflicts = tuple(result for result in results if isinstance(result, OperatorConflict))
    assert len(winners) == 1
    assert winners[0].authz_version == 2
    assert len(conflicts) == 1
    assert str(conflicts[0]) == "operator_authz_conflict"
    assert store.get_account(ACCOUNT_ID) == winners[0]
    if isinstance(store, PostgresOperatorSessionStore):
        store.close()


def test_authorization_version_cannot_overflow_postgres_bigint() -> None:
    account = OperatorAccount(
        identity_source=OperatorIdentitySource.OIDC,
        id=ACCOUNT_ID,
        subject="oidc:operator@example.test",
        display_name="Оператор",
        roles=frozenset({OperatorRole.OPERATOR}),
        scopes=frozenset({"server:*"}),
        authz_version=MAX_AUTHZ_VERSION,
        enabled=True,
    )
    store = InMemoryOperatorSessionStore(accounts=(account,), clock=lambda: NOW)

    with pytest.raises(OperatorConflict, match="operator_authz_conflict"):
        store.update_authorization(
            account_id=ACCOUNT_ID,
            expected_authz_version=MAX_AUTHZ_VERSION,
            roles=frozenset({OperatorRole.VIEWER}),
            scopes=account.scopes,
            enabled=True,
            context=MUTATION_CONTEXT,
        )


def test_postgres_public_operations_normalize_database_outage() -> None:
    store = PostgresOperatorSessionStore(
        "postgresql+psycopg://invalid:invalid@127.0.0.1:1/invalid",
        statement_timeout_ms=100,
    )
    account = OperatorAccount(
        identity_source=OperatorIdentitySource.OIDC,
        id=ACCOUNT_ID,
        subject="oidc:operator@example.test",
        display_name="Оператор",
        roles=frozenset({OperatorRole.OPERATOR}),
        scopes=frozenset({"server:*"}),
        authz_version=1,
        enabled=True,
    )
    operations = (
        lambda: store.get_account(ACCOUNT_ID),
        lambda: store.create_account(account),
        lambda: store.update_authorization(
            account_id=ACCOUNT_ID,
            expected_authz_version=1,
            roles=frozenset({OperatorRole.VIEWER}),
            scopes=account.scopes,
            enabled=True,
            context=MUTATION_CONTEXT,
        ),
        lambda: store.issue_session(
            session_id=UUID("70000000-0000-0000-0000-000000000007"),
            account_id=ACCOUNT_ID,
            token_sha256="a" * 64,
            csrf_sha256="b" * 64,
            idle_timeout=timedelta(minutes=30),
            absolute_timeout=timedelta(hours=12),
            mfa_verified=True,
        ),
        lambda: store.read_session("a" * 64),
        lambda: store.touch_authorized_session(
            UUID("70000000-0000-0000-0000-000000000007"),
            token_sha256="a" * 64,
            expected_authz_version=1,
            idle_timeout=timedelta(minutes=30),
        ),
        lambda: store.revoke_session("a" * 64),
    )

    for operation in operations:
        with pytest.raises(
            OperatorSessionUnavailable,
            match="operator_session_store_unavailable",
        ):
            operation()
    store.close()


def test_operator_authentication_runs_outside_the_asgi_event_loop() -> None:
    class EventLoopDetectingControl(OperatorSessionControl):
        def authenticate(  # type: ignore[override]
            self,
            **_kwargs: object,
        ) -> object:
            with pytest.raises(RuntimeError, match="no running event loop"):
                asyncio.get_running_loop()
            raise OperatorAuthenticationRequired("expected")

    control = EventLoopDetectingControl(
        store=InMemoryOperatorSessionStore(),
        token_factory=lambda: "x" * 43,
    )
    response = TestClient(
        create_app(Settings(role=RuntimeRole.WEB), operator_sessions=control),
        base_url="https://management.example.test",
    ).get("/api/v1/operator/session")

    assert response.status_code == 401


def test_logout_normalizes_authoritative_store_outage_to_retryable_503() -> None:
    class RevokeUnavailableStore(InMemoryOperatorSessionStore):
        def revoke_session(self, token_sha256: str) -> bool:
            del token_sha256
            raise OperatorSessionUnavailable("operator_session_store_unavailable")

    account = OperatorAccount(
        identity_source=OperatorIdentitySource.OIDC,
        id=ACCOUNT_ID,
        subject="oidc:operator@example.test",
        display_name="Оператор",
        roles=frozenset({OperatorRole.OPERATOR}),
        scopes=frozenset({"server:*"}),
        authz_version=1,
        enabled=True,
    )
    store = RevokeUnavailableStore(accounts=(account,), clock=lambda: NOW)
    control = OperatorSessionControl(
        store=store,
        token_factory=iter(("s" * 43, "c" * 43)).__next__,
    )
    issued = control.issue(account_id=ACCOUNT_ID, mfa_verified=True)

    response = TestClient(
        create_app(Settings(role=RuntimeRole.WEB), operator_sessions=control),
        base_url="https://management.example.test",
    ).delete(
        "/api/v1/operator/session",
        headers={
            "Cookie": f"__Host-rtsp_proxy_session={issued.session_token}",
            "X-CSRF-Token": issued.csrf_token,
        },
    )

    assert response.status_code == 503
    assert response.json() == {"detail": {"code": "operator_session_unavailable"}}
    assert response.headers["retry-after"] == "1"
    assert response.headers["cache-control"] == "no-store"
