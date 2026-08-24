from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from threading import RLock
from typing import Protocol
from uuid import UUID, uuid4

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import SQLAlchemyError


class OperatorRole(StrEnum):
    VIEWER = "viewer"
    OPERATOR = "operator"
    ADMIN = "admin"
    AUDITOR = "auditor"
    BREAK_GLASS = "break_glass"


class OperatorIdentitySource(StrEnum):
    OIDC = "oidc"
    BREAK_GLASS = "break_glass"


class OperatorPermission(StrEnum):
    DASHBOARD_READ = "dashboard.read"
    CONTROL_READ = "control.read"
    CONTROL_MUTATE = "control.mutate"
    ACCESS_ADMIN = "access.admin"
    OPERATOR_ADMIN = "operator.admin"
    AUDIT_READ = "audit.read"
    SECRET_ISSUE = "secret.issue"


_ROLE_PERMISSIONS: dict[OperatorRole, frozenset[OperatorPermission]] = {
    OperatorRole.VIEWER: frozenset(
        {OperatorPermission.DASHBOARD_READ, OperatorPermission.CONTROL_READ}
    ),
    OperatorRole.OPERATOR: frozenset(
        {
            OperatorPermission.DASHBOARD_READ,
            OperatorPermission.CONTROL_READ,
            OperatorPermission.CONTROL_MUTATE,
            OperatorPermission.SECRET_ISSUE,
        }
    ),
    OperatorRole.ADMIN: frozenset(OperatorPermission),
    OperatorRole.AUDITOR: frozenset(
        {OperatorPermission.DASHBOARD_READ, OperatorPermission.AUDIT_READ}
    ),
    OperatorRole.BREAK_GLASS: frozenset(OperatorPermission),
}

MAX_AUTHZ_VERSION = (1 << 63) - 1
_SCOPE_PATTERN = re.compile(r"^(?:server:\*|(?:group|camera):[A-Za-z0-9][A-Za-z0-9._-]{0,127})$")
_AUDIT_SCOPE_PATTERN = re.compile(
    r"^(?:server:\*|session:self|(?:group|camera):[A-Za-z0-9][A-Za-z0-9._-]{0,127})$"
)
_AUDIT_ACTIONS = frozenset(
    {permission.value for permission in OperatorPermission}
    | {
        "audit.read",
        "camera.access_policy_read",
        "camera.access_policy_update",
        "camera.create",
        "camera.delete",
        "camera.disable",
        "camera.enable",
        "camera.grant_issue",
        "camera.grant_revoke",
        "camera.grant_rotate",
        "camera.list",
        "camera.move",
        "camera.move_preview",
        "camera.move_read",
        "camera.mutation_preview",
        "camera.read",
        "camera.runtime_read",
        "camera.update",
        "dashboard.read",
        "node.create",
        "node.delete",
        "node.drain",
        "node.list",
        "node.maintenance",
        "node.observe",
        "node.port_change",
        "node.port_change_preview",
        "node.read",
        "node.reconfigure",
        "node.reconfigure_preview",
        "node.release_update",
        "node.restart",
        "node.resume",
        "node.start",
        "node.stop",
        "operator.admin",
        "operator.login",
        "operator.session_logout",
        "operator.session_read",
        "request.unsupported",
    }
)
_AUDIT_HTTP_METHODS = frozenset(
    {
        "GET",
        "HEAD",
        "OPTIONS",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "INTERNAL",
        "OTHER",
    }
)
_AUDIT_RESOURCE_TYPES = frozenset(
    {
        "access_grant",
        "access_policy",
        "audit",
        "camera",
        "camera_move",
        "dashboard",
        "node",
        "operator_account",
        "server",
        "session",
    }
)
_AUDIT_RESOURCE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class OperatorAuthenticationRequired(RuntimeError):
    """An opaque operator session cannot be authenticated safely."""


class OperatorAuthorizationDenied(RuntimeError):
    """The authenticated principal does not have the required permission."""


class OperatorSessionUnavailable(RuntimeError):
    """The authoritative operator session store is unavailable."""


class OperatorConflict(RuntimeError):
    """An operator account mutation lost its revision fence."""


@dataclass(frozen=True, slots=True)
class OperatorRequestAuditContext:
    request_id: UUID
    action: str
    http_method: str
    resource_scope: str
    source_ip_sha256: str
    user_agent_sha256: str
    resource_type: str = "server"
    resource_id: str = "server"

    def __post_init__(self) -> None:
        if (
            self.action not in _AUDIT_ACTIONS
            or self.http_method not in _AUDIT_HTTP_METHODS
            or _AUDIT_SCOPE_PATTERN.fullmatch(self.resource_scope) is None
            or self.resource_type not in _AUDIT_RESOURCE_TYPES
            or _AUDIT_RESOURCE_ID_PATTERN.fullmatch(self.resource_id) is None
            or re.fullmatch(r"[0-9a-f]{64}", self.source_ip_sha256) is None
            or re.fullmatch(r"[0-9a-f]{64}", self.user_agent_sha256) is None
        ):
            raise ValueError("operator_request_audit_context_invalid")

    @classmethod
    def capture(
        cls,
        *,
        request_id: UUID,
        action: str,
        http_method: str,
        resource_scope: str,
        source_ip: str,
        user_agent: str,
        resource_type: str = "server",
        resource_id: str = "server",
    ) -> OperatorRequestAuditContext:
        if (
            not source_ip
            or len(source_ip) > 128
            or len(user_agent) > 4096
            or any(ord(character) < 32 for character in source_ip)
        ):
            raise ValueError("operator_request_audit_context_invalid")
        return cls(
            request_id=request_id,
            action=action,
            http_method=http_method,
            resource_scope=resource_scope,
            source_ip_sha256=hashlib.sha256(source_ip.encode("utf-8")).hexdigest(),
            user_agent_sha256=hashlib.sha256(user_agent.encode("utf-8")).hexdigest(),
            resource_type=resource_type,
            resource_id=resource_id,
        )

    @classmethod
    def internal(
        cls,
        *,
        action: str,
        resource_scope: str = "server:*",
        resource_type: str = "server",
        resource_id: str = "server",
    ) -> OperatorRequestAuditContext:
        return cls.capture(
            request_id=uuid4(),
            action=action,
            http_method="INTERNAL",
            resource_scope=resource_scope,
            source_ip="internal",
            user_agent="",
            resource_type=resource_type,
            resource_id=resource_id,
        )


@dataclass(frozen=True, slots=True)
class OperatorMutationContext:
    actor: str
    reason: str

    def __post_init__(self) -> None:
        if (
            not 1 <= len(self.actor) <= 128
            or not 1 <= len(self.reason) <= 256
            or any(ord(character) < 32 for character in self.actor + self.reason)
        ):
            raise ValueError("operator_mutation_context_invalid")


@dataclass(frozen=True, slots=True)
class OperatorAuthorizationEvent:
    id: UUID
    account_id: UUID
    actor: str
    reason: str
    roles: frozenset[OperatorRole]
    scopes: frozenset[str]
    enabled: bool
    authz_version: int


@dataclass(frozen=True, slots=True)
class OperatorRequestSecurityEvent:
    account_id: UUID | None
    session_id: UUID | None
    event_type: str
    reason_code: str
    outcome: str
    roles: frozenset[OperatorRole]
    scopes: frozenset[str]
    audit_context: OperatorRequestAuditContext
    identity_source: OperatorIdentitySource | None


class OperatorSessionFailure(StrEnum):
    INVALID = "operator_session_invalid"
    REVOKED = "operator_session_revoked"
    EXPIRED = "operator_session_expired"
    ACCOUNT_UNAVAILABLE = "operator_account_unavailable"
    STALE = "operator_session_stale"
    CHANGED = "operator_session_changed"


@dataclass(frozen=True, slots=True)
class OperatorAccount:
    id: UUID
    identity_source: OperatorIdentitySource
    subject: str
    display_name: str
    roles: frozenset[OperatorRole]
    scopes: frozenset[str]
    authz_version: int
    enabled: bool

    def __post_init__(self) -> None:
        if (
            not self.subject
            or len(self.subject) > 512
            or not self.display_name
            or len(self.display_name) > 256
            or not self.roles
            or not self.scopes
            or len(self.scopes) > 128
            or any(_SCOPE_PATTERN.fullmatch(scope) is None for scope in self.scopes)
            or not 1 <= self.authz_version <= MAX_AUTHZ_VERSION
            or (
                self.identity_source is OperatorIdentitySource.BREAK_GLASS
                and self.roles != frozenset({OperatorRole.BREAK_GLASS})
            )
            or (
                self.identity_source is OperatorIdentitySource.OIDC
                and OperatorRole.BREAK_GLASS in self.roles
            )
        ):
            raise ValueError("operator_account_invalid")


@dataclass(frozen=True, slots=True)
class OperatorSession:
    id: UUID
    account_id: UUID
    token_sha256: str
    csrf_sha256: str
    authz_version: int
    issued_at: datetime
    last_seen_at: datetime
    idle_expires_at: datetime
    absolute_expires_at: datetime
    mfa_verified_at: datetime | None
    revoked_at: datetime | None = None

    def __post_init__(self) -> None:
        if (
            len(self.token_sha256) != 64
            or len(self.csrf_sha256) != 64
            or self.authz_version < 1
            or any(
                value.tzinfo is None
                for value in (
                    self.issued_at,
                    self.last_seen_at,
                    self.idle_expires_at,
                    self.absolute_expires_at,
                )
            )
            or self.idle_expires_at <= self.issued_at
            or self.absolute_expires_at <= self.issued_at
        ):
            raise ValueError("operator_session_invalid")


@dataclass(frozen=True, slots=True)
class OperatorPrincipal:
    account_id: UUID
    session_id: UUID
    identity_source: OperatorIdentitySource
    subject: str
    display_name: str
    roles: frozenset[OperatorRole]
    scopes: frozenset[str]
    authz_version: int
    mfa_verified_at: datetime | None

    def allows(self, permission: OperatorPermission) -> bool:
        return any(permission in _ROLE_PERMISSIONS[role] for role in self.roles)


@dataclass(frozen=True, slots=True)
class IssuedOperatorSession:
    session_token: str
    csrf_token: str
    session: OperatorSession


@dataclass(frozen=True, slots=True)
class AuthenticatedOperatorSession:
    session: OperatorSession
    account: OperatorAccount


class OperatorSessionStore(Protocol):
    def get_account(self, account_id: UUID) -> OperatorAccount | None: ...

    def create_account(self, account: OperatorAccount) -> None: ...

    def update_authorization(
        self,
        *,
        account_id: UUID,
        expected_authz_version: int,
        roles: frozenset[OperatorRole],
        scopes: frozenset[str],
        enabled: bool,
        context: OperatorMutationContext,
    ) -> OperatorAccount: ...

    def issue_session(
        self,
        *,
        session_id: UUID,
        account_id: UUID,
        token_sha256: str,
        csrf_sha256: str,
        idle_timeout: timedelta,
        absolute_timeout: timedelta,
        mfa_verified: bool,
        expected_authz_version: int | None = None,
        audit_context: OperatorRequestAuditContext | None = None,
    ) -> OperatorSession: ...

    def read_session(
        self,
        token_sha256: str,
    ) -> AuthenticatedOperatorSession | OperatorSessionFailure: ...

    def touch_authorized_session(
        self,
        session_id: UUID,
        *,
        token_sha256: str,
        expected_authz_version: int,
        idle_timeout: timedelta,
    ) -> AuthenticatedOperatorSession | OperatorSessionFailure: ...

    def revoke_session(
        self,
        token_sha256: str,
        *,
        audit_context: OperatorRequestAuditContext | None = None,
    ) -> bool: ...

    def record_authentication_failure(
        self,
        *,
        token_sha256: str | None,
        reason_code: str,
        audit_context: OperatorRequestAuditContext,
    ) -> None: ...

    def record_request_security_event(
        self,
        *,
        account_id: UUID,
        session_id: UUID,
        authz_version: int,
        event_type: str,
        reason_code: str,
        roles: frozenset[OperatorRole] = frozenset(),
        scopes: frozenset[str] = frozenset(),
        audit_context: OperatorRequestAuditContext | None = None,
    ) -> None: ...


class InMemoryOperatorSessionStore:
    def __init__(
        self,
        *,
        accounts: tuple[OperatorAccount, ...] = (),
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._accounts = {account.id: account for account in accounts}
        self._sessions: dict[UUID, OperatorSession] = {}
        self._authorization_events: list[OperatorAuthorizationEvent] = []
        self._request_security_events: list[OperatorRequestSecurityEvent] = []
        self._lock = RLock()
        self._clock = clock

    def get_account(self, account_id: UUID) -> OperatorAccount | None:
        with self._lock:
            return self._accounts.get(account_id)

    def create_account(self, account: OperatorAccount) -> None:
        if account.authz_version != 1:
            raise ValueError("operator_authz_initial_version_invalid")
        with self._lock:
            if account.id in self._accounts:
                raise OperatorConflict("operator_account_exists")
            self._accounts[account.id] = account

    def update_authorization(
        self,
        *,
        account_id: UUID,
        expected_authz_version: int,
        roles: frozenset[OperatorRole],
        scopes: frozenset[str],
        enabled: bool,
        context: OperatorMutationContext,
    ) -> OperatorAccount:
        with self._lock:
            current = self._accounts.get(account_id)
            if (
                current is None
                or current.authz_version != expected_authz_version
                or current.authz_version == MAX_AUTHZ_VERSION
            ):
                raise OperatorConflict("operator_authz_conflict")
            updated = replace(
                current,
                roles=roles,
                scopes=scopes,
                authz_version=current.authz_version + 1,
                enabled=enabled,
            )
            self._accounts[account_id] = updated
            self._authorization_events.append(_authorization_event(updated, context=context))
            return updated

    def authorization_events(self) -> tuple[OperatorAuthorizationEvent, ...]:
        with self._lock:
            return tuple(self._authorization_events)

    def issue_session(
        self,
        *,
        session_id: UUID,
        account_id: UUID,
        token_sha256: str,
        csrf_sha256: str,
        idle_timeout: timedelta,
        absolute_timeout: timedelta,
        mfa_verified: bool,
        expected_authz_version: int | None = None,
        audit_context: OperatorRequestAuditContext | None = None,
    ) -> OperatorSession:
        del audit_context
        with self._lock:
            account = self._accounts.get(account_id)
            if (
                account is None
                or not account.enabled
                or (
                    expected_authz_version is not None
                    and account.authz_version != expected_authz_version
                )
            ):
                raise OperatorAuthenticationRequired("operator_account_unavailable")
            if any(existing.token_sha256 == token_sha256 for existing in self._sessions.values()):
                raise ValueError("operator_session_token_conflict")
            issued_at = self._now()
            session = OperatorSession(
                id=session_id,
                account_id=account.id,
                token_sha256=token_sha256,
                csrf_sha256=csrf_sha256,
                authz_version=account.authz_version,
                issued_at=issued_at,
                last_seen_at=issued_at,
                idle_expires_at=issued_at + idle_timeout,
                absolute_expires_at=issued_at + absolute_timeout,
                mfa_verified_at=issued_at if mfa_verified else None,
            )
            self._sessions[session.id] = session
            active = tuple(
                current
                for current in self._sessions.values()
                if current.account_id == account_id and current.revoked_at is None
            )
            for expired in active[:-5]:
                self._sessions[expired.id] = replace(expired, revoked_at=issued_at)
            return session

    def read_session(
        self,
        token_sha256: str,
    ) -> AuthenticatedOperatorSession | OperatorSessionFailure:
        with self._lock:
            session = next(
                (
                    session
                    for session in self._sessions.values()
                    if hmac.compare_digest(session.token_sha256, token_sha256)
                ),
                None,
            )
            return self._evaluate(session, now=self._now())

    def touch_authorized_session(
        self,
        session_id: UUID,
        *,
        token_sha256: str,
        expected_authz_version: int,
        idle_timeout: timedelta,
    ) -> AuthenticatedOperatorSession | OperatorSessionFailure:
        with self._lock:
            current = self._sessions.get(session_id)
            if current is None or not hmac.compare_digest(
                current.token_sha256,
                token_sha256,
            ):
                return OperatorSessionFailure.CHANGED
            now = self._now()
            evaluated = self._evaluate(current, now=now)
            if isinstance(evaluated, OperatorSessionFailure):
                return evaluated
            if evaluated.account.authz_version != expected_authz_version:
                return OperatorSessionFailure.STALE
            updated = replace(
                current,
                last_seen_at=max(current.last_seen_at, now),
                idle_expires_at=max(
                    current.idle_expires_at,
                    min(now + idle_timeout, current.absolute_expires_at),
                ),
            )
            self._sessions[session_id] = updated
            return AuthenticatedOperatorSession(updated, evaluated.account)

    def revoke_session(
        self,
        token_sha256: str,
        *,
        audit_context: OperatorRequestAuditContext | None = None,
    ) -> bool:
        context = audit_context or OperatorRequestAuditContext.internal(
            action="operator.session_logout"
        )
        with self._lock:
            session = next(
                (
                    current
                    for current in self._sessions.values()
                    if hmac.compare_digest(current.token_sha256, token_sha256)
                ),
                None,
            )
            if session is None or session.revoked_at is not None:
                return False
            self._sessions[session.id] = replace(session, revoked_at=self._now())
            account = self._accounts.get(session.account_id)
            self._request_security_events.append(
                OperatorRequestSecurityEvent(
                    account_id=session.account_id,
                    session_id=session.id,
                    event_type="operator.session_logout",
                    reason_code="operator_initiated",
                    outcome="accepted",
                    roles=frozenset() if account is None else account.roles,
                    scopes=frozenset() if account is None else account.scopes,
                    audit_context=context,
                    identity_source=None if account is None else account.identity_source,
                )
            )
            return True

    def record_authentication_failure(
        self,
        *,
        token_sha256: str | None,
        reason_code: str,
        audit_context: OperatorRequestAuditContext,
    ) -> None:
        _validate_authentication_failure_reason(reason_code)
        with self._lock:
            session = next(
                (
                    current
                    for current in self._sessions.values()
                    if token_sha256 is not None
                    and hmac.compare_digest(current.token_sha256, token_sha256)
                ),
                None,
            )
            account = None if session is None else self._accounts.get(session.account_id)
            self._request_security_events.append(
                OperatorRequestSecurityEvent(
                    account_id=None if session is None else session.account_id,
                    session_id=None if session is None else session.id,
                    event_type="operator.authentication_denied",
                    reason_code=reason_code,
                    outcome="rejected",
                    roles=frozenset() if account is None else account.roles,
                    scopes=frozenset() if account is None else account.scopes,
                    audit_context=audit_context,
                    identity_source=None if account is None else account.identity_source,
                )
            )

    def record_request_security_event(
        self,
        *,
        account_id: UUID,
        session_id: UUID,
        authz_version: int,
        event_type: str,
        reason_code: str,
        roles: frozenset[OperatorRole] = frozenset(),
        scopes: frozenset[str] = frozenset(),
        audit_context: OperatorRequestAuditContext | None = None,
    ) -> None:
        del authz_version
        context = audit_context or OperatorRequestAuditContext.internal(
            action=(
                "operator.session_logout"
                if event_type == "operator.session_logout"
                else "dashboard.read"
            )
        )
        with self._lock:
            account = self._accounts.get(account_id)
            self._request_security_events.append(
                OperatorRequestSecurityEvent(
                    account_id=account_id,
                    session_id=session_id,
                    event_type=event_type,
                    reason_code=reason_code,
                    outcome="accepted" if event_type.endswith("logout") else "rejected",
                    roles=roles,
                    scopes=scopes,
                    audit_context=context,
                    identity_source=None if account is None else account.identity_source,
                )
            )

    def request_security_events(self) -> tuple[OperatorRequestSecurityEvent, ...]:
        with self._lock:
            return tuple(self._request_security_events)

    def _evaluate(
        self,
        session: OperatorSession | None,
        *,
        now: datetime,
    ) -> AuthenticatedOperatorSession | OperatorSessionFailure:
        if session is None:
            return OperatorSessionFailure.INVALID
        if session.revoked_at is not None:
            return OperatorSessionFailure.REVOKED
        if now >= session.idle_expires_at or now >= session.absolute_expires_at:
            return OperatorSessionFailure.EXPIRED
        account = self._accounts.get(session.account_id)
        if account is None or not account.enabled:
            return OperatorSessionFailure.ACCOUNT_UNAVAILABLE
        if account.authz_version != session.authz_version:
            return OperatorSessionFailure.STALE
        return AuthenticatedOperatorSession(session, account)

    def _now(self) -> datetime:
        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise ValueError("operator_session_clock_invalid")
        return now


class PostgresOperatorSessionStore:
    def __init__(
        self,
        database_url: str,
        *,
        statement_timeout_ms: int = 1000,
    ) -> None:
        if not 100 <= statement_timeout_ms <= 5000:
            raise ValueError("database_statement_timeout_invalid")
        self._engine = create_engine(
            database_url,
            pool_pre_ping=True,
            hide_parameters=True,
            pool_size=1,
            max_overflow=0,
            pool_timeout=statement_timeout_ms / 1000,
            connect_args={
                "connect_timeout": max(1, math.ceil(statement_timeout_ms / 1000)),
                "options": f"-c statement_timeout={statement_timeout_ms}",
            },
        )

    def close(self) -> None:
        self._engine.dispose()

    def assert_ready(self) -> None:
        try:
            with self._engine.connect() as connection:
                connection.execute(text("SELECT id FROM operator_accounts LIMIT 0"))
                connection.execute(text("SELECT id FROM operator_sessions LIMIT 0"))
        except SQLAlchemyError:
            raise OperatorSessionUnavailable("operator_session_store_unavailable") from None

    def get_account(self, account_id: UUID) -> OperatorAccount | None:
        try:
            with self._engine.connect() as connection:
                row = (
                    connection.execute(
                        text(
                            "SELECT id, identity_source, subject, display_name, roles, "
                            "scopes, authz_version, enabled FROM operator_accounts "
                            "WHERE id = :id"
                        ),
                        {"id": account_id},
                    )
                    .mappings()
                    .one_or_none()
                )
        except SQLAlchemyError:
            raise OperatorSessionUnavailable("operator_session_store_unavailable") from None
        return None if row is None else _account_from_row(row)

    def create_account(self, account: OperatorAccount) -> None:
        if account.authz_version != 1:
            raise ValueError("operator_authz_initial_version_invalid")
        try:
            with self._engine.begin() as connection:
                connection.execute(text("SET LOCAL synchronous_commit = on"))
                row = connection.execute(
                    text(
                        "INSERT INTO operator_accounts "
                        "(id, identity_source, subject, display_name, roles, scopes, "
                        "authz_version, enabled) VALUES "
                        "(:id, :identity_source, :subject, :display_name, :roles, :scopes, "
                        ":authz_version, :enabled) ON CONFLICT DO NOTHING RETURNING id"
                    ),
                    {
                        "id": account.id,
                        "identity_source": account.identity_source.value,
                        "subject": account.subject,
                        "display_name": account.display_name,
                        "roles": sorted(role.value for role in account.roles),
                        "scopes": sorted(account.scopes),
                        "authz_version": account.authz_version,
                        "enabled": account.enabled,
                    },
                ).one_or_none()
                if row is None:
                    raise OperatorConflict("operator_account_exists")
        except OperatorConflict:
            raise
        except SQLAlchemyError:
            raise OperatorSessionUnavailable("operator_session_store_unavailable") from None

    def update_authorization(
        self,
        *,
        account_id: UUID,
        expected_authz_version: int,
        roles: frozenset[OperatorRole],
        scopes: frozenset[str],
        enabled: bool,
        context: OperatorMutationContext,
    ) -> OperatorAccount:
        try:
            with self._engine.begin() as connection:
                connection.execute(text("SET LOCAL synchronous_commit = on"))
                current_row = (
                    connection.execute(
                        text(
                            "SELECT id, identity_source, subject, display_name, roles, "
                            "scopes, authz_version, enabled FROM operator_accounts "
                            "WHERE id = :id AND authz_version = :expected_authz_version "
                            "FOR UPDATE"
                        ),
                        {
                            "id": account_id,
                            "expected_authz_version": expected_authz_version,
                        },
                    )
                    .mappings()
                    .one_or_none()
                )
                if current_row is None:
                    raise OperatorConflict("operator_authz_conflict")
                current = _account_from_row(current_row)
                if current.authz_version == MAX_AUTHZ_VERSION:
                    raise OperatorConflict("operator_authz_version_exhausted")
                updated = replace(
                    current,
                    roles=roles,
                    scopes=scopes,
                    authz_version=current.authz_version + 1,
                    enabled=enabled,
                )
                row = (
                    connection.execute(
                        text(
                            "UPDATE operator_accounts SET roles = :roles, scopes = :scopes, "
                            "enabled = :enabled, authz_version = :authz_version, "
                            "updated_at = clock_timestamp() WHERE id = :id "
                            "AND authz_version = :expected_authz_version "
                            "RETURNING id, identity_source, subject, display_name, roles, "
                            "scopes, authz_version, enabled"
                        ),
                        {
                            "id": account_id,
                            "expected_authz_version": expected_authz_version,
                            "roles": sorted(role.value for role in updated.roles),
                            "scopes": sorted(updated.scopes),
                            "authz_version": updated.authz_version,
                            "enabled": updated.enabled,
                        },
                    )
                    .mappings()
                    .one()
                )
                _record_authorization_event(
                    connection,
                    event=_authorization_event(
                        _account_from_row(row),
                        context=context,
                    ),
                )
                return _account_from_row(row)
        except OperatorConflict:
            raise
        except SQLAlchemyError:
            raise OperatorSessionUnavailable("operator_session_store_unavailable") from None

    def issue_session(
        self,
        *,
        session_id: UUID,
        account_id: UUID,
        token_sha256: str,
        csrf_sha256: str,
        idle_timeout: timedelta,
        absolute_timeout: timedelta,
        mfa_verified: bool,
        expected_authz_version: int | None = None,
        audit_context: OperatorRequestAuditContext | None = None,
    ) -> OperatorSession:
        context = audit_context or OperatorRequestAuditContext.internal(
            action="operator.login"
        )
        try:
            with self._engine.begin() as connection:
                connection.execute(text("SET LOCAL synchronous_commit = on"))
                row = (
                    connection.execute(
                        text(
                            "WITH account AS ("
                            "SELECT id, authz_version FROM operator_accounts "
                            "WHERE id = :account_id AND enabled AND "
                            "(CAST(:expected_authz_version AS bigint) IS NULL OR "
                            "authz_version = :expected_authz_version) FOR UPDATE"
                            ") INSERT INTO operator_sessions "
                            "(id, account_id, token_sha256, csrf_sha256, authz_version, "
                            "issued_at, last_seen_at, idle_expires_at, absolute_expires_at, "
                            "mfa_verified_at) "
                            "SELECT :id, account.id, :token_sha256, :csrf_sha256, "
                            "account.authz_version, now_at, now_at, "
                            "now_at + :idle_timeout, now_at + :absolute_timeout, "
                            "CASE WHEN :mfa_verified THEN now_at ELSE NULL END "
                            "FROM account CROSS JOIN LATERAL "
                            "(SELECT clock_timestamp() now_at) n RETURNING *"
                        ),
                        {
                            "id": session_id,
                            "account_id": account_id,
                            "token_sha256": token_sha256,
                            "csrf_sha256": csrf_sha256,
                            "idle_timeout": idle_timeout,
                            "absolute_timeout": absolute_timeout,
                            "mfa_verified": mfa_verified,
                            "expected_authz_version": expected_authz_version,
                        },
                    )
                    .mappings()
                    .one_or_none()
                )
                if row is None:
                    raise OperatorAuthenticationRequired("operator_account_unavailable")
                connection.execute(
                    text(
                        "WITH excess AS ("
                        "SELECT id FROM operator_sessions WHERE account_id = :account_id "
                        "AND revoked_at IS NULL AND id <> :new_session_id "
                        "ORDER BY issued_at DESC, id DESC OFFSET 4"
                        ") UPDATE operator_sessions AS session "
                        "SET revoked_at = clock_timestamp() FROM excess "
                        "WHERE session.id = excess.id"
                    ),
                    {"account_id": account_id, "new_session_id": session_id},
                )
                _record_session_issued_event(
                    connection,
                    account_id=account_id,
                    session_id=session_id,
                    authz_version=int(row["authz_version"]),
                    mfa_verified=mfa_verified,
                    audit_context=context,
                )
        except OperatorAuthenticationRequired:
            raise
        except SQLAlchemyError:
            raise OperatorSessionUnavailable("operator_session_store_unavailable") from None
        return _session_from_row(row)

    def read_session(
        self,
        token_sha256: str,
    ) -> AuthenticatedOperatorSession | OperatorSessionFailure:
        try:
            with self._engine.connect() as connection:
                row = (
                    connection.execute(
                        text(
                            "SELECT s.*, a.identity_source, a.subject, a.display_name, "
                            "a.roles, a.scopes, "
                            "a.authz_version AS account_authz_version, a.enabled "
                            "FROM operator_sessions s JOIN operator_accounts a "
                            "ON a.id = s.account_id WHERE s.token_sha256 = :token_sha256"
                        ),
                        {"token_sha256": token_sha256},
                    )
                    .mappings()
                    .one_or_none()
                )
                if row is None:
                    return OperatorSessionFailure.INVALID
                now = connection.scalar(text("SELECT clock_timestamp()"))
        except SQLAlchemyError:
            raise OperatorSessionUnavailable("operator_session_store_unavailable") from None
        assert isinstance(now, datetime)
        return _evaluate_joined_row(row, now=now)

    def touch_authorized_session(
        self,
        session_id: UUID,
        *,
        token_sha256: str,
        expected_authz_version: int,
        idle_timeout: timedelta,
    ) -> AuthenticatedOperatorSession | OperatorSessionFailure:
        try:
            with self._engine.begin() as connection:
                row = (
                    connection.execute(
                        text(
                            "UPDATE operator_sessions AS s SET "
                            "last_seen_at = clock_timestamp(), "
                            "idle_expires_at = LEAST(clock_timestamp() + :idle_timeout, "
                            "s.absolute_expires_at) FROM operator_accounts AS a "
                            "WHERE s.id = :session_id AND s.account_id = a.id "
                            "AND s.token_sha256 = :token_sha256 AND s.revoked_at IS NULL "
                            "AND clock_timestamp() < s.idle_expires_at "
                            "AND clock_timestamp() < s.absolute_expires_at "
                            "AND a.enabled AND a.authz_version = s.authz_version "
                            "AND a.authz_version = :expected_authz_version "
                            "RETURNING s.*, a.identity_source, a.subject, a.display_name, "
                            "a.roles, a.scopes, "
                            "a.authz_version AS account_authz_version, a.enabled"
                        ),
                        {
                            "session_id": session_id,
                            "token_sha256": token_sha256,
                            "expected_authz_version": expected_authz_version,
                            "idle_timeout": idle_timeout,
                        },
                    )
                    .mappings()
                    .one_or_none()
                )
                if row is not None:
                    evaluated = _evaluate_joined_row(row, now=row["last_seen_at"])
                    assert isinstance(evaluated, AuthenticatedOperatorSession)
                    return evaluated
        except SQLAlchemyError:
            raise OperatorSessionUnavailable("operator_session_store_unavailable") from None
        latest = self.read_session(token_sha256)
        return (
            OperatorSessionFailure.CHANGED
            if not isinstance(
                latest,
                OperatorSessionFailure,
            )
            else latest
        )

    def revoke_session(
        self,
        token_sha256: str,
        *,
        audit_context: OperatorRequestAuditContext | None = None,
    ) -> bool:
        context = audit_context or OperatorRequestAuditContext.internal(
            action="operator.session_logout"
        )
        try:
            with self._engine.begin() as connection:
                connection.execute(text("SET LOCAL synchronous_commit = on"))
                row = (
                    connection.execute(
                        text(
                            "UPDATE operator_sessions AS session SET "
                            "revoked_at = clock_timestamp() FROM operator_accounts AS account "
                            "WHERE session.token_sha256 = :token_sha256 "
                            "AND session.revoked_at IS NULL "
                            "AND account.id = session.account_id RETURNING session.id, "
                            "session.account_id, account.authz_version, "
                            "account.identity_source, account.roles, account.scopes"
                        ),
                        {"token_sha256": token_sha256},
                    )
                    .mappings()
                    .one_or_none()
                )
                if row is None:
                    return False
                _record_request_security_event(
                    connection,
                    account_id=row["account_id"],
                    session_id=row["id"],
                    authz_version=row["authz_version"],
                    identity_source=OperatorIdentitySource(row["identity_source"]),
                    event_type="operator.session_logout",
                    reason_code="operator_initiated",
                    roles=frozenset(OperatorRole(value) for value in row["roles"]),
                    scopes=frozenset(row["scopes"]),
                    audit_context=context,
                )
                return True
        except SQLAlchemyError:
            raise OperatorSessionUnavailable("operator_session_store_unavailable") from None

    def record_authentication_failure(
        self,
        *,
        token_sha256: str | None,
        reason_code: str,
        audit_context: OperatorRequestAuditContext,
    ) -> None:
        _validate_authentication_failure_reason(reason_code)
        try:
            with self._engine.begin() as connection:
                connection.execute(text("SET LOCAL synchronous_commit = on"))
                row = None
                if token_sha256 is not None:
                    row = (
                        connection.execute(
                            text(
                                "SELECT session.id AS session_id, session.account_id, "
                                "GREATEST(session.authz_version, account.authz_version) "
                                "AS aggregate_revision, account.identity_source, "
                                "account.roles, account.scopes "
                                "FROM operator_sessions AS session "
                                "JOIN operator_accounts AS account "
                                "ON account.id = session.account_id "
                                "WHERE session.token_sha256 = :token_sha256"
                            ),
                            {"token_sha256": token_sha256},
                        )
                        .mappings()
                        .one_or_none()
                    )
                _record_request_security_event(
                    connection,
                    account_id=None if row is None else row["account_id"],
                    session_id=None if row is None else row["session_id"],
                    authz_version=1 if row is None else int(row["aggregate_revision"]),
                    identity_source=(
                        None
                        if row is None
                        else OperatorIdentitySource(row["identity_source"])
                    ),
                    event_type="operator.authentication_denied",
                    reason_code=reason_code,
                    roles=(
                        frozenset()
                        if row is None
                        else frozenset(OperatorRole(value) for value in row["roles"])
                    ),
                    scopes=frozenset() if row is None else frozenset(row["scopes"]),
                    audit_context=audit_context,
                )
        except SQLAlchemyError:
            raise OperatorSessionUnavailable("operator_session_store_unavailable") from None

    def record_request_security_event(
        self,
        *,
        account_id: UUID,
        session_id: UUID,
        authz_version: int,
        event_type: str,
        reason_code: str,
        roles: frozenset[OperatorRole] = frozenset(),
        scopes: frozenset[str] = frozenset(),
        audit_context: OperatorRequestAuditContext | None = None,
    ) -> None:
        context = audit_context or OperatorRequestAuditContext.internal(
            action=(
                "operator.session_logout"
                if event_type == "operator.session_logout"
                else "dashboard.read"
            )
        )
        try:
            with self._engine.begin() as connection:
                connection.execute(text("SET LOCAL synchronous_commit = on"))
                identity_source = connection.scalar(
                    text("SELECT identity_source FROM operator_accounts WHERE id = :id"),
                    {"id": account_id},
                )
                if identity_source is None:
                    raise ValueError("operator_security_event_invalid")
                _record_request_security_event(
                    connection,
                    account_id=account_id,
                    session_id=session_id,
                    authz_version=authz_version,
                    identity_source=OperatorIdentitySource(identity_source),
                    event_type=event_type,
                    reason_code=reason_code,
                    roles=roles,
                    scopes=scopes,
                    audit_context=context,
                )
        except SQLAlchemyError:
            raise OperatorSessionUnavailable("operator_session_store_unavailable") from None


class OperatorSessionControl:
    def __init__(
        self,
        *,
        store: OperatorSessionStore,
        token_factory: Callable[[], str],
        session_id_factory: Callable[[], UUID] = uuid4,
        idle_timeout: timedelta = timedelta(minutes=30),
        absolute_timeout: timedelta = timedelta(hours=12),
    ) -> None:
        if (
            idle_timeout <= timedelta(0)
            or absolute_timeout <= idle_timeout
            or absolute_timeout > timedelta(hours=24)
        ):
            raise ValueError("operator_session_timing_invalid")
        self._store = store
        self._token_factory = token_factory
        self._session_id_factory = session_id_factory
        self._idle_timeout = idle_timeout
        self._absolute_timeout = absolute_timeout

    def issue(
        self,
        *,
        account_id: UUID,
        mfa_verified: bool,
        expected_authz_version: int | None = None,
        audit_context: OperatorRequestAuditContext | None = None,
    ) -> IssuedOperatorSession:
        if not mfa_verified:
            raise OperatorAuthenticationRequired("operator_mfa_required")
        session_token = self._token()
        csrf_token = self._token()
        session = self._store.issue_session(
            session_id=self._session_id_factory(),
            account_id=account_id,
            token_sha256=_digest(session_token),
            csrf_sha256=_digest(csrf_token),
            idle_timeout=self._idle_timeout,
            absolute_timeout=self._absolute_timeout,
            mfa_verified=mfa_verified,
            expected_authz_version=expected_authz_version,
            audit_context=(
                audit_context
                or OperatorRequestAuditContext.internal(action="operator.login")
            ),
        )
        return IssuedOperatorSession(session_token, csrf_token, session)

    def authenticate(
        self,
        *,
        session_token: str,
        permission: OperatorPermission,
        csrf_token: str | None = None,
        require_csrf: bool = False,
        required_scope: str | None = "server:*",
        audit_context: OperatorRequestAuditContext | None = None,
    ) -> OperatorPrincipal:
        context = audit_context or OperatorRequestAuditContext.internal(
            action=permission.value,
            resource_scope="session:self" if required_scope is None else required_scope,
            resource_type="session" if required_scope is None else "server",
            resource_id="self" if required_scope is None else "server",
        )
        if not session_token or len(session_token) > 1024:
            self._store.record_authentication_failure(
                token_sha256=None,
                reason_code=OperatorSessionFailure.INVALID.value,
                audit_context=context,
            )
            raise OperatorAuthenticationRequired("operator_session_invalid")
        token_sha256 = _digest(session_token)
        authentication = self._store.read_session(token_sha256)
        if isinstance(authentication, OperatorSessionFailure):
            self._store.record_authentication_failure(
                token_sha256=token_sha256,
                reason_code=authentication.value,
                audit_context=context,
            )
            raise OperatorAuthenticationRequired(authentication.value)
        session = authentication.session
        account = authentication.account
        if require_csrf and (
            csrf_token is None or not hmac.compare_digest(session.csrf_sha256, _digest(csrf_token))
        ):
            self._record_denial(
                authentication,
                "operator_csrf_invalid",
                audit_context=context,
            )
            raise OperatorAuthenticationRequired("operator_csrf_invalid")
        allowed = frozenset(
            permission_value
            for role in account.roles
            for permission_value in _ROLE_PERMISSIONS[role]
        )
        if permission not in allowed:
            self._record_denial(
                authentication,
                "operator_permission_denied",
                audit_context=context,
            )
            raise OperatorAuthorizationDenied("operator_permission_denied")
        if (
            required_scope is not None
            and required_scope not in account.scopes
            and "server:*" not in account.scopes
        ):
            self._record_denial(
                authentication,
                "operator_scope_denied",
                audit_context=context,
            )
            raise OperatorAuthorizationDenied("operator_scope_denied")
        touched = self._store.touch_authorized_session(
            session.id,
            token_sha256=token_sha256,
            expected_authz_version=account.authz_version,
            idle_timeout=self._idle_timeout,
        )
        if isinstance(touched, OperatorSessionFailure):
            self._record_denial(
                authentication,
                touched.value,
                event_type="operator.authentication_denied",
                audit_context=context,
            )
            raise OperatorAuthenticationRequired(touched.value)
        account = touched.account
        session = touched.session
        return OperatorPrincipal(
            account_id=account.id,
            session_id=session.id,
            identity_source=account.identity_source,
            subject=account.subject,
            display_name=account.display_name,
            roles=account.roles,
            scopes=account.scopes,
            authz_version=account.authz_version,
            mfa_verified_at=session.mfa_verified_at,
        )

    def revoke(
        self,
        session_token: str,
        *,
        audit_context: OperatorRequestAuditContext | None = None,
    ) -> None:
        context = audit_context or OperatorRequestAuditContext.internal(
            action="operator.session_logout"
        )
        token_sha256 = _digest(session_token)
        if not self._store.revoke_session(
            token_sha256,
            audit_context=context,
        ):
            self._store.record_authentication_failure(
                token_sha256=token_sha256,
                reason_code=OperatorSessionFailure.INVALID.value,
                audit_context=context,
            )
            raise OperatorAuthenticationRequired("operator_session_invalid")

    def record_denied_request(
        self,
        *,
        session_token: str,
        reason_code: str,
        audit_context: OperatorRequestAuditContext,
    ) -> None:
        if not session_token or len(session_token) > 1024:
            self._store.record_authentication_failure(
                token_sha256=None,
                reason_code=OperatorSessionFailure.INVALID.value,
                audit_context=audit_context,
            )
            return
        token_sha256 = _digest(session_token)
        authentication = self._store.read_session(token_sha256)
        if isinstance(authentication, OperatorSessionFailure):
            self._store.record_authentication_failure(
                token_sha256=token_sha256,
                reason_code=authentication.value,
                audit_context=audit_context,
            )
            return
        self._record_denial(
            authentication,
            reason_code,
            audit_context=audit_context,
        )

    def _record_denial(
        self,
        authentication: AuthenticatedOperatorSession,
        reason_code: str,
        *,
        event_type: str = "operator.authorization_denied",
        audit_context: OperatorRequestAuditContext,
    ) -> None:
        self._store.record_request_security_event(
            account_id=authentication.account.id,
            session_id=authentication.session.id,
            authz_version=authentication.account.authz_version,
            event_type=event_type,
            reason_code=reason_code,
            roles=authentication.account.roles,
            scopes=authentication.account.scopes,
            audit_context=audit_context,
        )

    def _token(self) -> str:
        token = self._token_factory()
        if not isinstance(token, str) or len(token) < 43 or len(token) > 1024:
            raise ValueError("operator_session_token_invalid")
        return token


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _authorization_event(
    account: OperatorAccount,
    *,
    context: OperatorMutationContext,
) -> OperatorAuthorizationEvent:
    return OperatorAuthorizationEvent(
        id=uuid4(),
        account_id=account.id,
        actor=context.actor,
        reason=context.reason,
        roles=account.roles,
        scopes=account.scopes,
        enabled=account.enabled,
        authz_version=account.authz_version,
    )


def _record_authorization_event(
    connection: Connection,
    *,
    event: OperatorAuthorizationEvent,
) -> None:
    payload = json.dumps(
        {
            "account_id": str(event.account_id),
            "actor": event.actor,
            "reason": event.reason,
            "roles": sorted(role.value for role in event.roles),
            "scopes": sorted(event.scopes),
            "enabled": event.enabled,
            "authz_version": event.authz_version,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    parameters = {
        "id": event.id,
        "aggregate_type": "operator_account",
        "aggregate_id": event.account_id,
        "event_type": "operator_account.authorization_changed",
        "aggregate_revision": event.authz_version,
        "payload": payload,
    }
    audit_statement = text(
        "INSERT INTO audit_events "
        "(id, aggregate_type, aggregate_id, event_type, aggregate_revision, payload) "
        "VALUES (:id, :aggregate_type, :aggregate_id, :event_type, "
        ":aggregate_revision, CAST(:payload AS jsonb))"
    )
    outbox_statement = text(
        "INSERT INTO outbox_messages "
        "(id, aggregate_type, aggregate_id, event_type, aggregate_revision, payload) "
        "VALUES (:id, :aggregate_type, :aggregate_id, :event_type, "
        ":aggregate_revision, CAST(:payload AS jsonb))"
    )
    connection.execute(audit_statement, parameters)
    connection.execute(outbox_statement, parameters)


def _record_session_issued_event(
    connection: Connection,
    *,
    account_id: UUID,
    session_id: UUID,
    authz_version: int,
    mfa_verified: bool,
    audit_context: OperatorRequestAuditContext,
) -> None:
    account = (
        connection.execute(
            text(
                "SELECT identity_source, roles, scopes FROM operator_accounts "
                "WHERE id = :account_id"
            ),
            {"account_id": account_id},
        )
        .mappings()
        .one()
    )
    payload = json.dumps(
        {
            "account_id": str(account_id),
            "action": audit_context.action,
            "auth_method": str(account["identity_source"]),
            "authz_version": authz_version,
            "http_method": audit_context.http_method,
            "mfa_verified": mfa_verified,
            "outcome": "accepted",
            "request_id": str(audit_context.request_id),
            "resource_id": audit_context.resource_id,
            "resource_scope": audit_context.resource_scope,
            "resource_type": audit_context.resource_type,
            "roles": sorted(account["roles"]),
            "scopes": sorted(account["scopes"]),
            "session_id": str(session_id),
            "source_ip_sha256": audit_context.source_ip_sha256,
            "user_agent_sha256": audit_context.user_agent_sha256,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    event_id = uuid4()
    parameters = {
        "id": event_id,
        "aggregate_id": account_id,
        "aggregate_revision": authz_version,
        "payload": payload,
    }
    for table in ("audit_events", "outbox_messages"):
        connection.execute(
            text(
                f"INSERT INTO {table} "
                "(id, aggregate_type, aggregate_id, event_type, aggregate_revision, payload) "
                "VALUES (:id, 'operator_account', :aggregate_id, "
                "'operator.session_issued', :aggregate_revision, CAST(:payload AS jsonb))"
            ),
            parameters,
        )


def _record_request_security_event(
    connection: Connection,
    *,
    account_id: UUID | None,
    session_id: UUID | None,
    authz_version: int,
    identity_source: OperatorIdentitySource | None,
    event_type: str,
    reason_code: str,
    roles: frozenset[OperatorRole],
    scopes: frozenset[str],
    audit_context: OperatorRequestAuditContext,
) -> None:
    accepted_reasons = {
        "operator.session_logout": {"operator_initiated"},
        "operator.authorization_denied": {
            "operator_csrf_invalid",
            "operator_permission_denied",
            "operator_scope_denied",
        },
        "operator.authentication_denied": {
            failure.value for failure in OperatorSessionFailure
        },
    }
    if reason_code not in accepted_reasons.get(event_type, set()):
        raise ValueError("operator_security_event_invalid")
    if (account_id is None) != (session_id is None):
        raise ValueError("operator_security_event_invalid")
    payload = json.dumps(
        {
            "account_id": None if account_id is None else str(account_id),
            "action": audit_context.action,
            "auth_method": None if identity_source is None else identity_source.value,
            "authz_version": None if account_id is None else authz_version,
            "http_method": audit_context.http_method,
            "outcome": "accepted" if event_type.endswith("logout") else "rejected",
            "reason_code": reason_code,
            "request_id": str(audit_context.request_id),
            "resource_id": audit_context.resource_id,
            "resource_scope": audit_context.resource_scope,
            "resource_type": audit_context.resource_type,
            "roles": sorted(role.value for role in roles),
            "scopes": sorted(scopes),
            "session_id": None if session_id is None else str(session_id),
            "source_ip_sha256": audit_context.source_ip_sha256,
            "user_agent_sha256": audit_context.user_agent_sha256,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    event_id = uuid4()
    aggregate_id = audit_context.request_id if account_id is None else account_id
    parameters = {
        "id": event_id,
        "aggregate_id": aggregate_id,
        "aggregate_type": (
            "operator_security_request" if account_id is None else "operator_account"
        ),
        "event_type": event_type,
        "aggregate_revision": authz_version,
        "payload": payload,
    }
    for table in ("audit_events", "outbox_messages"):
        connection.execute(
            text(
                f"INSERT INTO {table} "
                "(id, aggregate_type, aggregate_id, event_type, aggregate_revision, payload) "
                "VALUES (:id, :aggregate_type, :aggregate_id, :event_type, "
                ":aggregate_revision, CAST(:payload AS jsonb))"
            ),
            parameters,
        )


def _validate_authentication_failure_reason(reason_code: str) -> None:
    if reason_code not in {failure.value for failure in OperatorSessionFailure}:
        raise ValueError("operator_security_event_invalid")


def _account_from_row(row: RowMapping) -> OperatorAccount:
    return OperatorAccount(
        id=row["id"],
        identity_source=OperatorIdentitySource(row["identity_source"]),
        subject=row["subject"],
        display_name=row["display_name"],
        roles=frozenset(OperatorRole(role) for role in row["roles"]),
        scopes=frozenset(row["scopes"]),
        authz_version=row["authz_version"],
        enabled=row["enabled"],
    )


def _session_from_row(row: RowMapping) -> OperatorSession:
    return OperatorSession(
        id=row["id"],
        account_id=row["account_id"],
        token_sha256=row["token_sha256"],
        csrf_sha256=row["csrf_sha256"],
        authz_version=row["authz_version"],
        issued_at=row["issued_at"],
        last_seen_at=row["last_seen_at"],
        idle_expires_at=row["idle_expires_at"],
        absolute_expires_at=row["absolute_expires_at"],
        mfa_verified_at=row["mfa_verified_at"],
        revoked_at=row["revoked_at"],
    )


def _evaluate_joined_row(
    row: RowMapping,
    *,
    now: datetime,
) -> AuthenticatedOperatorSession | OperatorSessionFailure:
    session = _session_from_row(row)
    if session.revoked_at is not None:
        return OperatorSessionFailure.REVOKED
    if now >= session.idle_expires_at or now >= session.absolute_expires_at:
        return OperatorSessionFailure.EXPIRED
    account = OperatorAccount(
        id=session.account_id,
        identity_source=OperatorIdentitySource(row["identity_source"]),
        subject=row["subject"],
        display_name=row["display_name"],
        roles=frozenset(OperatorRole(role) for role in row["roles"]),
        scopes=frozenset(row["scopes"]),
        authz_version=row["account_authz_version"],
        enabled=row["enabled"],
    )
    if not account.enabled:
        return OperatorSessionFailure.ACCOUNT_UNAVAILABLE
    if account.authz_version != session.authz_version:
        return OperatorSessionFailure.STALE
    return AuthenticatedOperatorSession(session, account)
