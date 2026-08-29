from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier
from uuid import UUID

import pytest
from alembic import command
from alembic.config import Config
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

from rtsp_proxy.app import create_app
from rtsp_proxy.config import RuntimeRole, Settings
from rtsp_proxy.migrate import upgrade_database
from rtsp_proxy.operator_access import (
    MAX_AUTHZ_VERSION,
    InMemoryOperatorSessionStore,
    OperatorAccount,
    OperatorActionBucket,
    OperatorAuthenticationRequired,
    OperatorAuthorizationDenied,
    OperatorConflict,
    OperatorIdentitySource,
    OperatorMutationContext,
    OperatorPermission,
    OperatorPrincipal,
    OperatorRequestAuditContext,
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


def test_operator_principal_recent_mfa_uses_authoritative_authentication_time() -> None:
    principal = OperatorPrincipal(
        account_id=ACCOUNT_ID,
        session_id=UUID("61000000-0000-4000-8000-000000000006"),
        identity_source=OperatorIdentitySource.OIDC,
        subject="oidc:operator@example.test",
        display_name="Operator",
        roles=frozenset({OperatorRole.OPERATOR}),
        scopes=frozenset({"server:*"}),
        authz_version=1,
        mfa_verified_at=NOW,
        authenticated_at=NOW + timedelta(minutes=5),
    )

    assert principal.has_recent_mfa(max_age_seconds=300)
    assert not replace(
        principal,
        authenticated_at=NOW + timedelta(minutes=5, seconds=1),
    ).has_recent_mfa(max_age_seconds=300)
    assert not replace(principal, mfa_verified_at=None).has_recent_mfa(max_age_seconds=300)
    assert not replace(
        principal,
        authenticated_at=NOW - timedelta(seconds=1),
    ).has_recent_mfa(max_age_seconds=300)


READ_AUDIT_CONTEXT = OperatorRequestAuditContext.capture(
    request_id=UUID("80000000-0000-0000-0000-000000000008"),
    action="dashboard.read",
    http_method="GET",
    resource_scope="server:*",
    source_ip="198.51.100.10",
    user_agent="security-audit-test/1.0",
)
MUTATION_AUDIT_CONTEXT = OperatorRequestAuditContext.capture(
    request_id=UUID("81000000-0000-0000-0000-000000000008"),
    action="control.mutate",
    http_method="POST",
    resource_scope="server:*",
    source_ip="198.51.100.10",
    user_agent="security-audit-test/1.0",
)
LOGOUT_AUDIT_CONTEXT = OperatorRequestAuditContext.capture(
    request_id=UUID("82000000-0000-0000-0000-000000000008"),
    action="operator.session_logout",
    http_method="DELETE",
    resource_scope="server:*",
    source_ip="198.51.100.10",
    user_agent="security-audit-test/1.0",
)
LOGIN_AUDIT_CONTEXT = OperatorRequestAuditContext.capture(
    request_id=UUID("85000000-0000-0000-0000-000000000008"),
    action="operator.login",
    http_method="GET",
    resource_scope="server:*",
    source_ip="198.51.100.10",
    user_agent="security-audit-test/1.0",
)


def test_postgres_operator_action_rate_buckets_are_durable_and_independent(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    engine = create_engine(postgres_database_url)
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO operator_accounts "
                "(id, identity_source, subject, display_name, roles, scopes, "
                "authz_version, enabled) VALUES "
                "(:id, 'oidc', 'rate-admin@example.test', 'Rate admin', "
                "ARRAY['admin']::varchar[], ARRAY['server:*']::varchar[], 1, true)"
            ),
            {"id": ACCOUNT_ID},
        )
    store = PostgresOperatorSessionStore(postgres_database_url)

    first_secret = store.claim_operator_action(
        account_id=ACCOUNT_ID,
        bucket=OperatorActionBucket.SECRET_ISSUE,
        limit=1,
        window_seconds=60,
    )
    limited_secret = store.claim_operator_action(
        account_id=ACCOUNT_ID,
        bucket=OperatorActionBucket.SECRET_ISSUE,
        limit=1,
        window_seconds=60,
    )
    first_mutation = store.claim_operator_action(
        account_id=ACCOUNT_ID,
        bucket=OperatorActionBucket.ACCESS_MUTATION,
        limit=1,
        window_seconds=60,
    )
    first_camera_mutation = store.claim_operator_action(
        account_id=ACCOUNT_ID,
        bucket=OperatorActionBucket.CAMERA_MUTATION,
        limit=1,
        window_seconds=60,
    )
    first_dashboard_read = store.claim_operator_action(
        account_id=ACCOUNT_ID,
        bucket=OperatorActionBucket.DASHBOARD_READ,
        limit=1,
        window_seconds=60,
    )
    first_live_reconnect = store.claim_operator_action(
        account_id=ACCOUNT_ID,
        bucket=OperatorActionBucket.LIVE_RECONNECT,
        limit=1,
        window_seconds=5,
    )
    limited_live_reconnect = store.claim_operator_action(
        account_id=ACCOUNT_ID,
        bucket=OperatorActionBucket.LIVE_RECONNECT,
        limit=1,
        window_seconds=5,
    )

    with engine.connect() as connection:
        persisted = [
            (str(row.bucket), int(row.used))
            for row in connection.execute(
                text(
                    "SELECT bucket, used FROM operator_action_rate_limits "
                    "WHERE account_id=:account_id ORDER BY bucket"
                ),
                {"account_id": ACCOUNT_ID},
            ).all()
        ]
    store.close()
    engine.dispose()

    assert (
        first_secret
        == first_mutation
        == first_camera_mutation
        == first_dashboard_read
        == first_live_reconnect
        == 0
    )
    assert 1 <= limited_secret <= 60
    assert 1 <= limited_live_reconnect <= 5
    assert persisted == [
        ("access_mutation", 1),
        ("camera_mutation", 1),
        ("dashboard_read", 1),
        ("live_reconnect", 1),
        ("secret_issue", 1),
    ]


def test_dashboard_rate_limit_bridge_keeps_reads_available_before_0019(
    postgres_database_url: str,
) -> None:
    migration = Config("alembic.ini")
    migration.set_main_option("sqlalchemy.url", postgres_database_url)
    command.upgrade(migration, "0018_camera_registration_keys")
    engine = create_engine(postgres_database_url)
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO operator_accounts "
                "(id, identity_source, subject, display_name, roles, scopes, "
                "authz_version, enabled) VALUES "
                "(:id, 'oidc', 'bridge@example.test', 'Bridge operator', "
                "ARRAY['viewer']::varchar[], ARRAY['server:*']::varchar[], 1, true)"
            ),
            {"id": ACCOUNT_ID},
        )
    principal = OperatorPrincipal(
        account_id=ACCOUNT_ID,
        session_id=UUID("62000000-0000-4000-8000-000000000006"),
        identity_source=OperatorIdentitySource.OIDC,
        subject="bridge@example.test",
        display_name="Bridge operator",
        roles=frozenset({OperatorRole.VIEWER}),
        scopes=frozenset({"server:*"}),
        authz_version=1,
        mfa_verified_at=NOW,
        authenticated_at=NOW,
    )
    old_schema_store = PostgresOperatorSessionStore(postgres_database_url)
    old_schema_control = OperatorSessionControl(
        store=old_schema_store,
        token_factory=lambda: "t" * 43,
    )
    try:
        old_schema_control.admit_action(
            principal=principal,
            bucket=OperatorActionBucket.DASHBOARD_READ,
        )
        with pytest.raises(OperatorSessionUnavailable):
            old_schema_control.admit_action(
                principal=principal,
                bucket=OperatorActionBucket.LIVE_RECONNECT,
            )
    finally:
        old_schema_store.close()

    command.upgrade(migration, "head")
    current_store = PostgresOperatorSessionStore(postgres_database_url)
    current_control = OperatorSessionControl(
        store=current_store,
        token_factory=lambda: "t" * 43,
    )
    try:
        current_control.admit_action(
            principal=principal,
            bucket=OperatorActionBucket.DASHBOARD_READ,
        )
        with engine.connect() as connection:
            assert connection.scalar(
                text(
                    "SELECT used FROM operator_action_rate_limits "
                    "WHERE account_id=:account_id AND bucket='dashboard_read'"
                ),
                {"account_id": ACCOUNT_ID},
            ) == 1
    finally:
        current_store.close()
        engine.dispose()


def test_postgres_first_operator_action_bucket_claim_is_concurrency_safe(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    engine = create_engine(postgres_database_url)
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO operator_accounts "
                "(id, identity_source, subject, display_name, roles, scopes, "
                "authz_version, enabled) VALUES "
                "(:id, 'oidc', 'concurrent-rate@example.test', 'Concurrent rate', "
                "ARRAY['admin']::varchar[], ARRAY['server:*']::varchar[], 1, true)"
            ),
            {"id": ACCOUNT_ID},
        )
    stores = tuple(
        PostgresOperatorSessionStore(postgres_database_url) for _index in range(8)
    )
    barrier = Barrier(len(stores))

    def claim(store: PostgresOperatorSessionStore) -> int:
        barrier.wait(timeout=5)
        return store.claim_operator_action(
            account_id=ACCOUNT_ID,
            bucket=OperatorActionBucket.SECRET_ISSUE,
            limit=10,
            window_seconds=60,
        )

    with ThreadPoolExecutor(max_workers=len(stores)) as executor:
        results = list(executor.map(claim, stores))
    with engine.connect() as connection:
        used = connection.scalar(
            text(
                "SELECT used FROM operator_action_rate_limits "
                "WHERE account_id=:account_id AND bucket='secret_issue'"
            ),
            {"account_id": ACCOUNT_ID},
        )
    for store in stores:
        store.close()
    engine.dispose()

    assert results == [0] * len(stores)
    assert used == len(stores)


def test_postgres_rejected_access_mutation_is_a_durable_sanitized_pair(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    camera_id = UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
    grant_id = UUID("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")
    request_id = UUID("83000000-0000-4000-8000-000000000008")
    idempotency_key = UUID("66666666-6666-4666-8666-666666666666")
    account = OperatorAccount(
        identity_source=OperatorIdentitySource.OIDC,
        id=ACCOUNT_ID,
        subject="oidc:access-admin@example.test",
        display_name="Access admin",
        roles=frozenset({OperatorRole.ADMIN}),
        scopes=frozenset({"server:*"}),
        authz_version=1,
        enabled=True,
    )
    store = PostgresOperatorSessionStore(postgres_database_url)
    store.create_account(account)
    control = OperatorSessionControl(
        store=store,
        token_factory=iter(("s" * 43, "c" * 43)).__next__,
        session_id_factory=lambda: UUID("70000000-0000-4000-8000-000000000007"),
    )
    issued = control.issue(account_id=ACCOUNT_ID, mfa_verified=True)
    context = OperatorRequestAuditContext.capture(
        request_id=request_id,
        action="camera.grant_rotate",
        http_method="POST",
        resource_scope=f"camera:{camera_id}",
        resource_type="access_grant",
        resource_id=str(grant_id),
        source_ip="198.51.100.10",
        user_agent="security-audit-test/1.0",
    )
    principal = control.authenticate(
        session_token=issued.session_token,
        permission=OperatorPermission.SECRET_ISSUE,
        required_scope=f"camera:{camera_id}",
        audit_context=context,
    )

    control.record_mutation_rejection(
        principal=principal,
        reason_code="access_grant_revision_conflict",
        audit_context=context,
        target_grant_id=grant_id,
        expected_revision=3,
        idempotency_key=idempotency_key,
    )

    engine = create_engine(postgres_database_url, hide_parameters=True)
    with engine.connect() as connection:
        audit = connection.execute(
            text(
                "SELECT id, payload FROM audit_events "
                "WHERE event_type='operator.mutation_rejected'"
            )
        ).one()
        outbox = connection.execute(
            text(
                "SELECT id, payload FROM outbox_messages "
                "WHERE event_type='operator.mutation_rejected'"
            )
        ).one()
    store.close()
    engine.dispose()

    assert audit.id == outbox.id
    assert audit.payload == outbox.payload
    assert audit.payload == {
        "account_id": str(ACCOUNT_ID),
        "action": "camera.grant_rotate",
        "auth_method": "oidc",
        "authz_version": 1,
        "expected_revision": 3,
        "http_method": "POST",
        "idempotency_key": str(idempotency_key),
        "outcome": "rejected",
        "reason_code": "access_grant_revision_conflict",
        "request_id": str(request_id),
        "resource_id": str(grant_id),
        "resource_scope": f"camera:{camera_id}",
        "resource_type": "access_grant",
        "roles": ["admin"],
        "scopes": ["server:*"],
        "session_id": str(issued.session.id),
        "source_ip_sha256": context.source_ip_sha256,
        "target_grant_id": str(grant_id),
        "user_agent_sha256": context.user_agent_sha256,
    }


def _protected_route_method_matrix(
    routes: Iterable[object],
    *,
    prefix: str = "",
) -> tuple[tuple[str, str], ...]:
    route_methods: list[tuple[str, str]] = []
    for route in routes:
        original_router = getattr(route, "original_router", None)
        if original_router is not None:
            include_context = getattr(route, "include_context", None)
            included_prefix = getattr(include_context, "prefix", None)
            nested_routes = getattr(original_router, "routes", None)
            assert isinstance(included_prefix, str)
            assert isinstance(nested_routes, list)
            route_methods.extend(
                _protected_route_method_matrix(
                    nested_routes,
                    prefix=f"{prefix}{included_prefix}",
                )
            )
            continue

        path = getattr(route, "path", "")
        if not isinstance(path, str):
            continue
        effective_path = f"{prefix}{path}"
        if not (
            effective_path.startswith("/api/v1/")
            or effective_path == "/dashboard"
            or effective_path.startswith("/dashboard/")
        ):
            continue
        route_methods.extend(
            (method, effective_path) for method in sorted(getattr(route, "methods", set()))
        )
    return tuple(route_methods)


def test_operator_request_audit_context_is_bounded_and_secret_free() -> None:
    assert READ_AUDIT_CONTEXT.source_ip_sha256 == hashlib.sha256(b"198.51.100.10").hexdigest()
    assert (
        READ_AUDIT_CONTEXT.user_agent_sha256
        == hashlib.sha256(b"security-audit-test/1.0").hexdigest()
    )
    assert "198.51.100.10" not in repr(READ_AUDIT_CONTEXT)
    assert "security-audit-test/1.0" not in repr(READ_AUDIT_CONTEXT)

    for changes in (
        {"action": "GET /api/v1/cameras/secret"},
        {"http_method": "TRACE"},
        {"resource_scope": "camera:not/a/canonical/scope"},
        {"source_ip": ""},
        {"user_agent": "x" * 4097},
    ):
        values: dict[str, object] = {
            "request_id": UUID("83000000-0000-0000-0000-000000000008"),
            "action": "control.read",
            "http_method": "GET",
            "resource_scope": "server:*",
            "source_ip": "198.51.100.11",
            "user_agent": "test-agent",
        }
        values.update(changes)
        with pytest.raises(ValueError, match="operator_request_audit_context_invalid"):
            OperatorRequestAuditContext.capture(**values)  # type: ignore[arg-type]


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
    event = store.request_security_events()[0]
    assert event.event_type == "operator.authentication_denied"
    assert event.reason_code == "operator_session_stale"
    assert event.account_id == ACCOUNT_ID
    assert event.session_id == issued.session.id


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


def test_session_denial_and_logout_audit_matrix_keeps_only_safe_request_metadata() -> None:
    account = OperatorAccount(
        identity_source=OperatorIdentitySource.OIDC,
        id=ACCOUNT_ID,
        subject="oidc:viewer@example.test",
        display_name="Наблюдатель",
        roles=frozenset({OperatorRole.VIEWER}),
        scopes=frozenset({"camera:allowed-camera"}),
        authz_version=1,
        enabled=True,
    )
    store = InMemoryOperatorSessionStore(accounts=(account,), clock=lambda: NOW)
    control = OperatorSessionControl(
        store=store,
        token_factory=iter(("s" * 43, "c" * 43)).__next__,
    )
    issued = control.issue(account_id=ACCOUNT_ID, mfa_verified=True)

    with pytest.raises(OperatorAuthenticationRequired, match="operator_session_invalid"):
        control.authenticate(
            session_token="unknown-session-token",
            permission=OperatorPermission.DASHBOARD_READ,
            audit_context=READ_AUDIT_CONTEXT,
        )
    with pytest.raises(OperatorAuthenticationRequired, match="operator_csrf_invalid"):
        control.authenticate(
            session_token=issued.session_token,
            permission=OperatorPermission.DASHBOARD_READ,
            require_csrf=True,
            csrf_token="wrong-csrf-token",
            audit_context=READ_AUDIT_CONTEXT,
        )
    with pytest.raises(OperatorAuthorizationDenied, match="operator_permission_denied"):
        control.authenticate(
            session_token=issued.session_token,
            permission=OperatorPermission.CONTROL_MUTATE,
            csrf_token=issued.csrf_token,
            require_csrf=True,
            audit_context=MUTATION_AUDIT_CONTEXT,
        )
    with pytest.raises(OperatorAuthorizationDenied, match="operator_scope_denied"):
        control.authenticate(
            session_token=issued.session_token,
            permission=OperatorPermission.CONTROL_READ,
            required_scope="camera:other-camera",
            audit_context=replace(
                READ_AUDIT_CONTEXT,
                resource_scope="camera:other-camera",
            ),
        )

    control.revoke(issued.session_token, audit_context=LOGOUT_AUDIT_CONTEXT)
    with pytest.raises(OperatorAuthenticationRequired, match="operator_session_revoked"):
        control.authenticate(
            session_token=issued.session_token,
            permission=OperatorPermission.DASHBOARD_READ,
            audit_context=replace(
                LOGOUT_AUDIT_CONTEXT,
                request_id=UUID("84000000-0000-0000-0000-000000000008"),
            ),
        )

    events = store.request_security_events()
    assert tuple((event.event_type, event.reason_code) for event in events) == (
        ("operator.authentication_denied", "operator_session_invalid"),
        ("operator.authorization_denied", "operator_csrf_invalid"),
        ("operator.authorization_denied", "operator_permission_denied"),
        ("operator.authorization_denied", "operator_scope_denied"),
        ("operator.session_logout", "operator_initiated"),
        ("operator.authentication_denied", "operator_session_revoked"),
    )
    assert events[0].account_id is None
    assert events[0].session_id is None
    assert events[0].roles == frozenset()
    assert events[0].scopes == frozenset()
    assert all(event.outcome == "rejected" for event in events[:4])
    assert events[4].outcome == "accepted"
    assert events[1].account_id == ACCOUNT_ID
    assert events[1].session_id == issued.session.id
    assert events[1].roles == frozenset({OperatorRole.VIEWER})
    assert events[1].scopes == frozenset({"camera:allowed-camera"})
    assert events[1].audit_context == READ_AUDIT_CONTEXT
    serialized = repr(events)
    assert issued.session_token not in serialized
    assert issued.csrf_token not in serialized
    assert "198.51.100.10" not in serialized
    assert "security-audit-test/1.0" not in serialized


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

    assert control.live_authorization_epochs((issued.session.id,)) == {
        issued.session.id: 1
    }
    control.revoke(issued.session_token)
    assert control.live_authorization_epochs((issued.session.id,)) == {}


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
    ).issue(
        account_id=ACCOUNT_ID,
        mfa_verified=True,
        audit_context=LOGIN_AUDIT_CONTEXT,
    )
    first_store.record_request_security_event(
        account_id=ACCOUNT_ID,
        session_id=issued.session.id,
        authz_version=1,
        event_type="operator.authorization_denied",
        reason_code="operator_permission_denied",
    )
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
        denial_audit = connection.execute(
            text(
                "SELECT id, event_type, payload FROM audit_events "
                "WHERE event_type = 'operator.authorization_denied'"
            )
        ).one()
        denial_outbox = connection.execute(
            text(
                "SELECT id, event_type, payload FROM outbox_messages "
                "WHERE event_type = 'operator.authorization_denied'"
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
    assert session_audit.payload["action"] == "operator.login"
    assert session_audit.payload["auth_method"] == "oidc"
    assert session_audit.payload["http_method"] == "GET"
    assert session_audit.payload["source_ip_sha256"] == LOGIN_AUDIT_CONTEXT.source_ip_sha256
    assert session_audit.payload["user_agent_sha256"] == LOGIN_AUDIT_CONTEXT.user_agent_sha256
    assert denial_audit == denial_outbox
    assert denial_audit.payload["account_id"] == str(ACCOUNT_ID)
    assert denial_audit.payload["outcome"] == "rejected"
    assert denial_audit.payload["reason_code"] == "operator_permission_denied"
    assert denial_audit.payload["session_id"] == str(issued.session.id)
    assert denial_audit.payload["action"] == "dashboard.read"
    assert denial_audit.payload["http_method"] == "INTERNAL"

    reopened = PostgresOperatorSessionStore(postgres_database_url)
    assert reopened.read_authorization_epochs((issued.session.id,)) == {
        issued.session.id: 1
    }
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
    assert reopened.read_authorization_epochs((issued.session.id,)) == {}
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
    assert audit.payload["account_id"] == str(ACCOUNT_ID)
    assert audit.payload["outcome"] == "accepted"
    assert audit.payload["reason_code"] == "operator_initiated"
    assert audit.payload["session_id"] == str(issued.session.id)
    assert audit.payload["action"] == "operator.session_logout"
    assert audit.payload["http_method"] == "INTERNAL"


def test_postgres_denial_logout_matrix_is_durable_redacted_and_fail_closed(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    account = OperatorAccount(
        identity_source=OperatorIdentitySource.OIDC,
        id=ACCOUNT_ID,
        subject="oidc:viewer@example.test",
        display_name="Viewer",
        roles=frozenset({OperatorRole.VIEWER}),
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

    with pytest.raises(OperatorAuthenticationRequired, match="operator_session_invalid"):
        control.authenticate(
            session_token="unknown-session-token",
            permission=OperatorPermission.DASHBOARD_READ,
            audit_context=READ_AUDIT_CONTEXT,
        )
    with pytest.raises(OperatorAuthorizationDenied, match="operator_permission_denied"):
        control.authenticate(
            session_token=issued.session_token,
            permission=OperatorPermission.CONTROL_MUTATE,
            csrf_token=issued.csrf_token,
            require_csrf=True,
            audit_context=MUTATION_AUDIT_CONTEXT,
        )
    control.revoke(issued.session_token, audit_context=LOGOUT_AUDIT_CONTEXT)

    engine = create_engine(postgres_database_url, hide_parameters=True)
    with engine.connect() as connection:
        audit = tuple(
            connection.execute(
                text(
                    "SELECT id, aggregate_type, aggregate_id, event_type, payload "
                    "FROM audit_events WHERE event_type IN ("
                    "'operator.authentication_denied', "
                    "'operator.authorization_denied', "
                    "'operator.session_logout') ORDER BY occurred_at, id"
                )
            ).mappings()
        )
        outbox = tuple(
            connection.execute(
                text(
                    "SELECT id, aggregate_type, aggregate_id, event_type, payload "
                    "FROM outbox_messages WHERE event_type IN ("
                    "'operator.authentication_denied', "
                    "'operator.authorization_denied', "
                    "'operator.session_logout') ORDER BY occurred_at, id"
                )
            ).mappings()
        )
    engine.dispose()
    store.close()

    assert audit == outbox
    assert {row["event_type"] for row in audit} == {
        "operator.authentication_denied",
        "operator.authorization_denied",
        "operator.session_logout",
    }
    anonymous = next(row for row in audit if row["event_type"] == "operator.authentication_denied")
    assert anonymous["aggregate_type"] == "operator_security_request"
    assert anonymous["aggregate_id"] == READ_AUDIT_CONTEXT.request_id
    assert anonymous["payload"]["account_id"] is None
    assert anonymous["payload"]["session_id"] is None
    assert anonymous["payload"]["roles"] == []
    assert anonymous["payload"]["scopes"] == []
    assert anonymous["payload"]["auth_method"] is None
    denial = next(row for row in audit if row["event_type"] == "operator.authorization_denied")
    assert denial["aggregate_type"] == "operator_account"
    assert denial["aggregate_id"] == ACCOUNT_ID
    assert denial["payload"]["roles"] == ["viewer"]
    assert denial["payload"]["scopes"] == ["server:*"]
    assert denial["payload"]["auth_method"] == "oidc"
    assert denial["payload"]["resource_type"] == "server"
    assert denial["payload"]["resource_id"] == "server"
    logout = next(row for row in audit if row["event_type"] == "operator.session_logout")
    assert logout["payload"]["outcome"] == "accepted"
    assert logout["payload"]["action"] == "operator.session_logout"
    assert logout["payload"]["auth_method"] == "oidc"
    serialized = json.dumps([dict(row) for row in audit], default=str, sort_keys=True)
    assert issued.session_token not in serialized
    assert issued.csrf_token not in serialized
    assert "198.51.100.10" not in serialized
    assert "security-audit-test/1.0" not in serialized


def test_postgres_http_denial_logout_matrix_is_complete_and_pairwise_durable(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    camera_id = UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
    account = OperatorAccount(
        identity_source=OperatorIdentitySource.OIDC,
        id=ACCOUNT_ID,
        subject="oidc:camera-operator@example.test",
        display_name="Camera operator",
        roles=frozenset({OperatorRole.OPERATOR}),
        scopes=frozenset({f"camera:{camera_id}"}),
        authz_version=1,
        enabled=True,
    )
    store = PostgresOperatorSessionStore(postgres_database_url)
    store.create_account(account)
    tokens = iter(tuple(f"{index:02d}-" + "x" * 40 for index in range(24)))
    control = OperatorSessionControl(store=store, token_factory=tokens.__next__)
    client = TestClient(
        create_app(Settings(role=RuntimeRole.WEB), operator_sessions=control),
        base_url="https://management.example.test",
    )
    agent = "matrix-secret-agent/1.0"

    anonymous = client.get(
        "/api/v1/operator/session",
        headers={"User-Agent": agent},
    )
    csrf_session = control.issue(account_id=ACCOUNT_ID, mfa_verified=True)
    csrf = client.delete(
        "/api/v1/operator/session",
        headers={
            "Cookie": f"__Host-rtsp_proxy_session={csrf_session.session_token}",
            "User-Agent": agent,
        },
    )
    scope_session = control.issue(account_id=ACCOUNT_ID, mfa_verified=True)
    scope = client.get(
        "/api/v1/cameras/dddddddd-dddd-4ddd-8ddd-dddddddddddd/runtime",
        headers={
            "Cookie": f"__Host-rtsp_proxy_session={scope_session.session_token}",
            "User-Agent": agent,
        },
    )
    expired_session = control.issue(account_id=ACCOUNT_ID, mfa_verified=True)
    stale_session = control.issue(account_id=ACCOUNT_ID, mfa_verified=True)
    engine = create_engine(postgres_database_url, hide_parameters=True)
    with engine.begin() as connection:
        connection.execute(
            text(
                "UPDATE operator_sessions SET "
                "issued_at = clock_timestamp() - INTERVAL '2 seconds', "
                "last_seen_at = clock_timestamp() - INTERVAL '2 seconds', "
                "idle_expires_at = clock_timestamp() - INTERVAL '1 second' "
                "WHERE id = :id"
            ),
            {"id": expired_session.session.id},
        )
    expired = client.get(
        "/api/v1/operator/session",
        headers={
            "Cookie": f"__Host-rtsp_proxy_session={expired_session.session_token}",
            "User-Agent": agent,
        },
    )
    with engine.begin() as connection:
        connection.execute(
            text("UPDATE operator_accounts SET authz_version = 2 WHERE id = :id"),
            {"id": ACCOUNT_ID},
        )
    stale = client.get(
        "/api/v1/operator/session",
        headers={
            "Cookie": f"__Host-rtsp_proxy_session={stale_session.session_token}",
            "User-Agent": agent,
        },
    )
    revoked_session = control.issue(account_id=ACCOUNT_ID, mfa_verified=True)
    malformed_session = control.issue(account_id=ACCOUNT_ID, mfa_verified=True)
    repeated_session = control.issue(account_id=ACCOUNT_ID, mfa_verified=True)
    with engine.begin() as connection:
        connection.execute(
            text("UPDATE operator_sessions SET revoked_at = clock_timestamp() WHERE id = :id"),
            {"id": revoked_session.session.id},
        )
    revoked = client.get(
        "/api/v1/operator/session",
        headers={
            "Cookie": f"__Host-rtsp_proxy_session={revoked_session.session_token}",
            "User-Agent": agent,
        },
    )
    malformed = client.post(
        "/dashboard/logout",
        content="_csrf=first&_csrf=second",
        headers={
            "Cookie": f"__Host-rtsp_proxy_session={malformed_session.session_token}",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": agent,
        },
    )
    repeated_headers = {
        "Cookie": f"__Host-rtsp_proxy_session={repeated_session.session_token}",
        "X-CSRF-Token": repeated_session.csrf_token,
        "User-Agent": agent,
    }
    logout = client.delete("/api/v1/operator/session", headers=repeated_headers)
    repeated = client.delete("/api/v1/operator/session", headers=repeated_headers)

    responses = (
        anonymous,
        csrf,
        scope,
        expired,
        stale,
        revoked,
        malformed,
        logout,
        repeated,
    )
    assert tuple(response.status_code for response in responses) == (
        401,
        401,
        403,
        401,
        401,
        401,
        401,
        204,
        401,
    )
    with engine.connect() as connection:
        audit = tuple(
            connection.execute(
                text(
                    "SELECT id, aggregate_type, aggregate_id, event_type, payload "
                    "FROM audit_events WHERE event_type IN ("
                    "'operator.authentication_denied', "
                    "'operator.authorization_denied', "
                    "'operator.session_logout') ORDER BY occurred_at, id"
                )
            ).mappings()
        )
        outbox = tuple(
            connection.execute(
                text(
                    "SELECT id, aggregate_type, aggregate_id, event_type, payload "
                    "FROM outbox_messages WHERE event_type IN ("
                    "'operator.authentication_denied', "
                    "'operator.authorization_denied', "
                    "'operator.session_logout') ORDER BY occurred_at, id"
                )
            ).mappings()
        )
    engine.dispose()
    store.close()

    assert audit == outbox
    assert len(audit) == len(responses)
    assert tuple(row["payload"]["reason_code"] for row in audit) == (
        "operator_session_invalid",
        "operator_csrf_invalid",
        "operator_scope_denied",
        "operator_session_expired",
        "operator_session_stale",
        "operator_session_revoked",
        "operator_csrf_invalid",
        "operator_initiated",
        "operator_session_revoked",
    )
    assert tuple(row["payload"]["request_id"] for row in audit) == tuple(
        response.headers["x-request-id"] for response in responses
    )
    assert len({row["payload"]["request_id"] for row in audit}) == len(audit)
    assert audit[0]["payload"]["auth_method"] is None
    assert all(row["payload"]["auth_method"] == "oidc" for row in audit[1:])
    assert audit[2]["payload"]["action"] == "camera.runtime_read"
    assert audit[2]["payload"]["resource_type"] == "camera"
    assert audit[2]["payload"]["resource_id"] == ("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
    serialized = json.dumps([dict(row) for row in audit], default=str, sort_keys=True)
    for issued in (
        csrf_session,
        scope_session,
        expired_session,
        stale_session,
        revoked_session,
        malformed_session,
        repeated_session,
    ):
        assert issued.session_token not in serialized
        assert issued.csrf_token not in serialized
    assert agent not in serialized
    assert "testclient" not in serialized


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

    malformed_dashboard_logout = client.post(
        "/dashboard/logout",
        content="_csrf=first&_csrf=second",
        headers={
            **cookie,
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    assert malformed_dashboard_logout.status_code == 401

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

    repeated_logout = client.delete(
        "/api/v1/operator/session",
        headers={**cookie, "X-CSRF-Token": issued.csrf_token},
    )
    assert repeated_logout.status_code == 401
    events = store.request_security_events()
    assert tuple((event.event_type, event.reason_code) for event in events) == (
        ("operator.authentication_denied", "operator_session_invalid"),
        ("operator.authorization_denied", "operator_csrf_invalid"),
        ("operator.authorization_denied", "operator_csrf_invalid"),
        ("operator.session_logout", "operator_initiated"),
        ("operator.authentication_denied", "operator_session_revoked"),
    )
    assert events[0].audit_context.action == "operator.session_read"
    assert events[0].audit_context.http_method == "GET"
    assert events[0].audit_context.resource_type == "session"
    assert events[0].audit_context.resource_id == "self"
    assert events[0].identity_source is None
    assert events[1].audit_context.action == "operator.session_logout"
    assert events[1].audit_context.http_method == "POST"
    assert events[2].audit_context.action == "operator.session_logout"
    assert events[2].audit_context.http_method == "DELETE"
    assert events[3].audit_context.action == "operator.session_logout"
    assert events[4].account_id == ACCOUNT_ID
    assert events[4].session_id == issued.session.id
    assert anonymous.headers["x-request-id"] == str(events[0].audit_context.request_id)
    assert malformed_dashboard_logout.headers["x-request-id"] == str(
        events[1].audit_context.request_id
    )
    assert missing_csrf.headers["x-request-id"] == str(events[2].audit_context.request_id)
    assert logged_out.headers["x-request-id"] == str(events[3].audit_context.request_id)
    assert repeated_logout.headers["x-request-id"] == str(events[4].audit_context.request_id)


def test_management_hsts_covers_authentication_and_authorization_rejections() -> None:
    account = OperatorAccount(
        identity_source=OperatorIdentitySource.OIDC,
        id=ACCOUNT_ID,
        subject="oidc:viewer@example.test",
        display_name="Viewer",
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
        create_app(
            Settings(
                role=RuntimeRole.WEB,
                management_tls_certificate_file=Path("/run/credentials/management-tls.crt"),
                management_tls_private_key_file=Path("/run/credentials/management-tls.key"),
            ),
            operator_sessions=sessions,
        ),
        base_url="https://management.example.test",
    )

    anonymous = client.get("/api/v1/nodes")
    denied = client.get(
        "/api/v1/operators",
        headers={"Cookie": f"__Host-rtsp_proxy_session={issued.session_token}"},
    )

    assert anonymous.status_code == 401
    assert denied.status_code == 403
    assert anonymous.headers["strict-transport-security"] == "max-age=31536000"
    assert denied.headers["strict-transport-security"] == "max-age=31536000"


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
    event = store.request_security_events()[0]
    assert event.event_type == "operator.authorization_denied"
    assert event.reason_code == "operator_permission_denied"
    assert event.audit_context.action == "node.create"
    assert event.audit_context.resource_scope == "server:*"
    assert event.audit_context.resource_type == "node"
    assert event.audit_context.resource_id == "collection"
    assert event.identity_source is OperatorIdentitySource.OIDC

    node_id = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
    restarted = client.post(
        f"/api/v1/nodes/{node_id}/restart",
        headers={**cookie, "X-CSRF-Token": issued.csrf_token},
    )
    deleted = client.delete(
        f"/api/v1/nodes/{node_id}",
        headers={**cookie, "X-CSRF-Token": issued.csrf_token},
    )
    assert restarted.status_code == deleted.status_code == 403
    restart_event, delete_event = store.request_security_events()[-2:]
    assert restart_event.audit_context.action == "node.restart"
    assert delete_event.audit_context.action == "node.delete"
    assert restart_event.audit_context.resource_type == "node"
    assert delete_event.audit_context.resource_type == "node"
    assert restart_event.audit_context.resource_id == str(node_id)
    assert delete_event.audit_context.resource_id == str(node_id)


def test_camera_scoped_session_reaches_only_its_exact_api_resource() -> None:
    camera_id = UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
    account = OperatorAccount(
        identity_source=OperatorIdentitySource.OIDC,
        id=ACCOUNT_ID,
        subject="oidc:camera-operator@example.test",
        display_name="Оператор камеры",
        roles=frozenset({OperatorRole.OPERATOR}),
        scopes=frozenset({f"camera:{camera_id}"}),
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

    own = client.get(f"/api/v1/cameras/{camera_id}/runtime", headers=cookie)
    cross_camera = client.get(
        "/api/v1/cameras/dddddddd-dddd-4ddd-8ddd-dddddddddddd/runtime",
        headers=cookie,
    )
    global_catalog = client.get("/api/v1/cameras", headers=cookie)
    own_session = client.get("/api/v1/operator/session", headers=cookie)
    logout_page = client.get("/dashboard/logout", headers=cookie)
    logged_out = client.post(
        "/dashboard/logout",
        headers=cookie,
        data={"_csrf": issued.csrf_token},
        follow_redirects=False,
    )

    assert own.status_code == 503
    assert own.json() == {"detail": {"code": "camera_runtime_unavailable"}}
    assert cross_camera.status_code == 403
    assert global_catalog.status_code == 403
    assert own_session.status_code == 200
    assert logout_page.status_code == 200
    assert logged_out.status_code == 303
    denials = tuple(
        event
        for event in store.request_security_events()
        if event.event_type == "operator.authorization_denied"
    )
    assert tuple(event.reason_code for event in denials) == (
        "operator_scope_denied",
        "operator_scope_denied",
    )
    assert denials[0].audit_context.action == "camera.runtime_read"
    assert denials[0].audit_context.resource_scope == (
        "camera:dddddddd-dddd-4ddd-8ddd-dddddddddddd"
    )
    assert denials[1].audit_context.action == "camera.list"
    assert denials[1].audit_context.resource_scope == "server:*"
    logout = store.request_security_events()[-1]
    assert logout.audit_context.resource_scope == "session:self"
    assert logout.audit_context.resource_type == "session"
    assert logout.audit_context.resource_id == "self"


@pytest.mark.parametrize("method", ["TRACE", "CONNECT", "PROPFIND"])
def test_unsupported_operator_http_methods_are_normalized_and_audited(method: str) -> None:
    store = InMemoryOperatorSessionStore(clock=lambda: NOW)
    client = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            operator_sessions=OperatorSessionControl(
                store=store,
                token_factory=lambda: "x" * 43,
            ),
        ),
        base_url="https://management.example.test",
    )

    response = client.request(method, "/api/v1/operator/session")

    assert response.status_code == 401
    event = store.request_security_events()[0]
    assert response.headers["x-request-id"] == str(event.audit_context.request_id)
    assert event.audit_context.action == "request.unsupported"
    assert event.audit_context.http_method == "OTHER"
    assert event.reason_code == "operator_session_invalid"


def test_generated_protected_route_method_matrix_is_fail_closed_and_semantic() -> None:
    anonymous_store = InMemoryOperatorSessionStore(clock=lambda: NOW)
    anonymous_app = create_app(
        Settings(role=RuntimeRole.WEB),
        operator_sessions=OperatorSessionControl(
            store=anonymous_store,
            token_factory=lambda: "x" * 43,
        ),
    )
    route_methods = _protected_route_method_matrix(anonymous_app.routes)
    assert len(route_methods) == 75

    node_id = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
    camera_id = UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
    move_id = UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
    grant_id = UUID("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")

    def concrete_path(template: str) -> str:
        return (
            template.replace("{node_id}", str(node_id))
            .replace("{camera_id}", str(camera_id))
            .replace("{move_id}", str(move_id))
            .replace("{grant_id}", str(grant_id))
        )

    anonymous_client = TestClient(
        anonymous_app,
        base_url="https://management.example.test",
    )
    for method, template in route_methods:
        before = len(anonymous_store.request_security_events())
        response = anonymous_client.request(
            method,
            concrete_path(template),
            follow_redirects=False,
        )
        assert response.status_code == 401, (method, template, response.text)
        events = anonymous_store.request_security_events()
        assert len(events) == before + 1, (method, template)
        event = events[-1]
        assert response.headers["x-request-id"] == str(event.audit_context.request_id)
        assert event.audit_context.action != "request.unsupported", (method, template)
        assert event.audit_context.resource_id != "invalid", (method, template)
        assert event.reason_code == "operator_session_invalid"

    scoped_account = OperatorAccount(
        identity_source=OperatorIdentitySource.OIDC,
        id=ACCOUNT_ID,
        subject="oidc:matrix-viewer@example.test",
        display_name="Matrix viewer",
        roles=frozenset({OperatorRole.VIEWER}),
        scopes=frozenset({"camera:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}),
        authz_version=1,
        enabled=True,
    )
    scoped_store = InMemoryOperatorSessionStore(
        accounts=(scoped_account,),
        clock=lambda: NOW,
    )
    scoped_control = OperatorSessionControl(
        store=scoped_store,
        token_factory=iter(("s" * 43, "c" * 43)).__next__,
    )
    issued = scoped_control.issue(account_id=ACCOUNT_ID, mfa_verified=True)
    scoped_client = TestClient(
        create_app(Settings(role=RuntimeRole.WEB), operator_sessions=scoped_control),
        base_url="https://management.example.test",
    )
    self_routes = {
        ("GET", "/dashboard/logout"),
        ("POST", "/dashboard/logout"),
        ("GET", "/api/v1/operator/session"),
        ("DELETE", "/api/v1/operator/session"),
    }
    for method, template in route_methods:
        if (method, template) in self_routes:
            continue
        headers = {
            "Cookie": f"__Host-rtsp_proxy_session={issued.session_token}",
            "X-CSRF-Token": issued.csrf_token,
        }
        before = len(scoped_store.request_security_events())
        if method == "POST" and template.startswith("/dashboard/"):
            response = scoped_client.request(
                method,
                concrete_path(template),
                headers=headers,
                data={"_csrf": issued.csrf_token},
                follow_redirects=False,
            )
        else:
            response = scoped_client.request(
                method,
                concrete_path(template),
                headers=headers,
                follow_redirects=False,
            )
        assert response.status_code == 403, (method, template, response.text)
        events = scoped_store.request_security_events()
        assert len(events) == before + 1, (method, template)
        event = events[-1]
        assert event.reason_code in {
            "operator_permission_denied",
            "operator_scope_denied",
        }
        assert event.audit_context.action != "request.unsupported", (method, template)
        assert response.headers["x-request-id"] == str(event.audit_context.request_id)


def test_protected_route_method_matrix_composes_nested_router_prefixes() -> None:
    nested_router = APIRouter()

    @nested_router.get("/future")
    def future_route() -> None:
        return None

    parent_router = APIRouter()
    parent_router.include_router(nested_router, prefix="/nested")
    app = FastAPI()
    app.include_router(parent_router, prefix="/api/v1")

    assert _protected_route_method_matrix(app.routes) == (("GET", "/api/v1/nested/future"),)


def test_dashboard_form_and_move_status_denials_keep_exact_semantic_targets() -> None:
    camera_id = UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
    other_camera_id = UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
    move_id = UUID("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")
    account = OperatorAccount(
        identity_source=OperatorIdentitySource.OIDC,
        id=ACCOUNT_ID,
        subject="oidc:camera-viewer@example.test",
        display_name="Camera viewer",
        roles=frozenset({OperatorRole.VIEWER}),
        scopes=frozenset({f"camera:{camera_id}"}),
        authz_version=1,
        enabled=True,
    )
    store = InMemoryOperatorSessionStore(accounts=(account,), clock=lambda: NOW)
    control = OperatorSessionControl(
        store=store,
        token_factory=iter(("s" * 43, "c" * 43)).__next__,
    )
    issued = control.issue(account_id=ACCOUNT_ID, mfa_verified=True)
    client = TestClient(
        create_app(Settings(role=RuntimeRole.WEB), operator_sessions=control),
        base_url="https://management.example.test",
    )
    headers = {"Cookie": f"__Host-rtsp_proxy_session={issued.session_token}"}

    edit = client.get(f"/dashboard/cameras/{camera_id}/edit", headers=headers)
    move = client.get(f"/dashboard/cameras/{camera_id}/move", headers=headers)
    move_status = client.get(
        f"/dashboard/cameras/{other_camera_id}/moves/{move_id}",
        headers=headers,
    )

    assert edit.status_code == move.status_code == move_status.status_code == 403
    edit_event, move_event, status_event = store.request_security_events()
    assert edit_event.audit_context.action == "camera.update"
    assert edit_event.audit_context.resource_type == "camera"
    assert edit_event.audit_context.resource_id == str(camera_id)
    assert move_event.audit_context.action == "camera.move"
    assert move_event.audit_context.resource_type == "camera"
    assert move_event.audit_context.resource_id == str(camera_id)
    assert status_event.audit_context.action == "camera.move_read"
    assert status_event.audit_context.resource_scope == f"camera:{other_camera_id}"
    assert status_event.audit_context.resource_type == "camera_move"
    assert status_event.audit_context.resource_id == str(move_id)


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


@pytest.mark.parametrize("rejected_table", ["audit_events", "outbox_messages"])
@pytest.mark.parametrize(
    "operation",
    ["authentication_denial", "authorization_denial", "logout"],
)
def test_postgres_http_security_event_transaction_fails_closed_without_half_pair(
    postgres_database_url: str,
    rejected_table: str,
    operation: str,
) -> None:
    upgrade_database(postgres_database_url)
    account = OperatorAccount(
        identity_source=OperatorIdentitySource.OIDC,
        id=ACCOUNT_ID,
        subject="oidc:operator@example.test",
        display_name="Operator",
        roles=frozenset({OperatorRole.VIEWER}),
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
    engine = create_engine(postgres_database_url, hide_parameters=True)
    trigger_name = f"reject_security_{rejected_table}_{operation}"
    event_type = (
        "operator.authentication_denied"
        if operation == "authentication_denial"
        else (
            "operator.authorization_denied"
            if operation == "authorization_denial"
            else "operator.session_logout"
        )
    )
    with engine.begin() as connection:
        connection.execute(
            text(
                f"CREATE FUNCTION {trigger_name}() RETURNS trigger AS $$ "
                "BEGIN RAISE EXCEPTION 'reject security event'; END; $$ LANGUAGE plpgsql"
            )
        )
        connection.execute(
            text(
                f"CREATE TRIGGER {trigger_name} BEFORE INSERT ON {rejected_table} "
                f"FOR EACH ROW WHEN (NEW.event_type = '{event_type}') "
                f"EXECUTE FUNCTION {trigger_name}()"
            )
        )
    client = TestClient(
        create_app(Settings(role=RuntimeRole.WEB), operator_sessions=control),
        base_url="https://management.example.test",
    )

    if operation == "authentication_denial":
        response = client.get("/api/v1/operator/session")
    elif operation == "authorization_denial":
        response = client.post(
            "/api/v1/nodes",
            json={"name": "must-not-run"},
            headers={
                "Cookie": f"__Host-rtsp_proxy_session={issued.session_token}",
                "X-CSRF-Token": issued.csrf_token,
            },
        )
    else:
        response = client.delete(
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
    with engine.connect() as connection:
        assert (
            connection.scalar(
                text("SELECT count(*) FROM audit_events WHERE event_type = :event_type"),
                {"event_type": event_type},
            )
            == 0
        )
        assert (
            connection.scalar(
                text("SELECT count(*) FROM outbox_messages WHERE event_type = :event_type"),
                {"event_type": event_type},
            )
            == 0
        )
        if operation == "logout":
            assert (
                connection.scalar(
                    text("SELECT revoked_at IS NULL FROM operator_sessions WHERE id = :id"),
                    {"id": issued.session.id},
                )
                is True
            )
    engine.dispose()
    store.close()
