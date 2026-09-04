from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import secrets
import ssl
import stat
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import BoundedSemaphore, RLock
from time import monotonic
from typing import Any, Protocol, cast
from urllib.error import HTTPError, URLError
from urllib.parse import quote_plus, urlencode
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidKey, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.twofactor.totp import TOTP
from joserfc import jwt
from joserfc.jwk import KeySet
from joserfc.jwt import JWTClaimsRegistry
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import SQLAlchemyError

from rtsp_proxy.operator_access import (
    IssuedOperatorSession,
    OperatorAccount,
    OperatorAuthenticationRequired,
    OperatorMutationContext,
    OperatorRequestAuditContext,
    OperatorRole,
    OperatorSessionControl,
)


class OidcLoginInvalid(RuntimeError):
    """An OIDC login flow cannot be created or consumed safely."""


class OidcLoginUnavailable(RuntimeError):
    """The durable OIDC login-flow store is unavailable."""


class OidcLoginRateLimited(RuntimeError):
    """An unauthenticated login surface exhausted its bounded admission budget."""

    def __init__(self, retry_after_seconds: int = 60) -> None:
        super().__init__("operator_login_rate_limited")
        self.retry_after_seconds = retry_after_seconds


@dataclass(frozen=True, slots=True)
class OperatorSecurityEvent:
    event_type: str
    severity: str
    account_id: UUID
    occurred_at: datetime
    outcome: str
    reason_code: str


@dataclass(frozen=True, slots=True)
class BreakGlassCredentials:
    password_scrypt: bytes
    totp_secret: bytes
    last_totp_step: int | None

    def __post_init__(self) -> None:
        if (
            len(self.password_scrypt) != 80
            or len(self.totp_secret) < 20
            or (self.last_totp_step is not None and self.last_totp_step < 0)
        ):
            raise ValueError("break_glass_credentials_invalid")

    @classmethod
    def hash_password(cls, password: str, *, salt: bytes | None = None) -> bytes:
        if not 16 <= len(password) <= 1024:
            raise ValueError("break_glass_password_invalid")
        actual_salt = secrets.token_bytes(16) if salt is None else salt
        if len(actual_salt) != 16:
            raise ValueError("break_glass_password_invalid")
        digest = Scrypt(salt=actual_salt, length=64, n=2**15, r=8, p=1).derive(
            password.encode("utf-8")
        )
        return actual_salt + digest

    def verifies_password(self, password: str) -> bool:
        if len(password) > 1024:
            return False
        salt, digest = self.password_scrypt[:16], self.password_scrypt[16:]
        try:
            Scrypt(salt=salt, length=64, n=2**15, r=8, p=1).verify(
                password.encode("utf-8"),
                digest,
            )
        except InvalidKey:
            return False
        return True


@dataclass(frozen=True, slots=True)
class BreakGlassAuthentication:
    account_id: UUID
    authz_version: int

    def __post_init__(self) -> None:
        if not 1 <= self.authz_version < (1 << 63):
            raise ValueError("break_glass_authentication_invalid")


@dataclass(frozen=True, slots=True)
class LocalOperatorCredentials:
    password_scrypt: bytes
    totp_secret: bytes | None = None
    last_totp_step: int | None = None

    def __post_init__(self) -> None:
        if (
            len(self.password_scrypt) != 80
            or (self.totp_secret is not None and len(self.totp_secret) < 20)
            or (self.totp_secret is None and self.last_totp_step is not None)
            or (self.last_totp_step is not None and self.last_totp_step < 0)
        ):
            raise ValueError("local_operator_credentials_invalid")

    @classmethod
    def hash_password(cls, password: str, *, salt: bytes | None = None) -> bytes:
        if not 12 <= len(password) <= 1024:
            raise ValueError("local_operator_password_invalid")
        actual_salt = secrets.token_bytes(16) if salt is None else salt
        if len(actual_salt) != 16:
            raise ValueError("local_operator_password_invalid")
        digest = Scrypt(salt=actual_salt, length=64, n=2**15, r=8, p=1).derive(
            password.encode("utf-8")
        )
        return actual_salt + digest

    def verifies_password(self, password: str) -> bool:
        if len(password) > 1024:
            return False
        salt, digest = self.password_scrypt[:16], self.password_scrypt[16:]
        try:
            Scrypt(salt=salt, length=64, n=2**15, r=8, p=1).verify(
                password.encode("utf-8"),
                digest,
            )
        except InvalidKey:
            return False
        return True


@dataclass(frozen=True, slots=True)
class LocalOperatorAuthentication:
    account_id: UUID
    authz_version: int
    mfa_verified: bool

    def __post_init__(self) -> None:
        if not 1 <= self.authz_version < (1 << 63):
            raise ValueError("local_operator_authentication_invalid")


def validate_local_operator_password(password: str) -> str:
    """Apply the local-account policy without retaining or logging the secret."""

    if not 12 <= len(password) <= 1024:
        raise ValueError("local_operator_password_policy_failed")
    categories = sum(
        (
            any(character.islower() for character in password),
            any(character.isupper() for character in password),
            any(character.isdigit() for character in password),
            any(not character.isalnum() for character in password),
        )
    )
    if len(password) < 20 and categories < 3:
        raise ValueError("local_operator_password_policy_failed")
    return password


class InMemoryLocalOperatorStore:
    def __init__(
        self,
        *,
        account: OperatorAccount,
        credentials: LocalOperatorCredentials,
    ) -> None:
        if account.identity_source.value != "local":
            raise ValueError("local_operator_account_invalid")
        self._account = account
        self._credentials = credentials
        self._lock = RLock()

    def authenticate(
        self,
        *,
        username: str,
        password: str,
        totp: str,
        source_ip: str,
        now: datetime,
    ) -> LocalOperatorAuthentication:
        del source_ip
        with self._lock:
            expected_username = self._account.subject.removeprefix("local:")
            rejected = (
                not self._account.enabled
                or not hmac.compare_digest(username, expected_username)
                or not self._credentials.verifies_password(password)
            )
            mfa_verified = False
            secret = self._credentials.totp_secret
            if not rejected and totp:
                step = int(now.timestamp()) // 30
                try:
                    if (
                        secret is None
                        or (
                            self._credentials.last_totp_step is not None
                            and step <= self._credentials.last_totp_step
                        )
                    ):
                        raise ValueError
                    TOTP(secret, 6, hashes.SHA1(), 30).verify(
                        totp.encode("ascii"),
                        int(now.timestamp()),
                    )
                except Exception:
                    rejected = True
                else:
                    mfa_verified = True
                    self._credentials = replace(self._credentials, last_totp_step=step)
            if rejected:
                raise OidcLoginInvalid("local_operator_login_failed")
            return LocalOperatorAuthentication(
                account_id=self._account.id,
                authz_version=self._account.authz_version,
                mfa_verified=mfa_verified,
            )

    def change_password(
        self,
        *,
        account_id: UUID,
        current_password: str,
        new_password: str,
        totp: str,
        current_session_id: UUID | None,
        context: OperatorRequestAuditContext,
        now: datetime,
    ) -> int:
        del current_session_id, context
        validate_local_operator_password(new_password)
        with self._lock:
            if (
                account_id != self._account.id
                or not self._account.enabled
                or not self._credentials.verifies_password(current_password)
                or self._credentials.verifies_password(new_password)
            ):
                raise OidcLoginInvalid("local_operator_password_change_denied")
            last_totp_step = self._credentials.last_totp_step
            if self._credentials.totp_secret is not None:
                try:
                    step = int(now.timestamp()) // 30
                    if not totp or (last_totp_step is not None and step <= last_totp_step):
                        raise ValueError
                    TOTP(self._credentials.totp_secret, 6, hashes.SHA1(), 30).verify(
                        totp.encode("ascii"), int(now.timestamp())
                    )
                except Exception:
                    raise OidcLoginInvalid("local_operator_password_change_denied") from None
                last_totp_step = step
            self._credentials = LocalOperatorCredentials(
                password_scrypt=LocalOperatorCredentials.hash_password(new_password),
                totp_secret=self._credentials.totp_secret,
                last_totp_step=last_totp_step,
            )
            self._account = replace(
                self._account,
                authz_version=self._account.authz_version + 1,
            )
            return self._account.authz_version


class PostgresLocalOperatorStore:
    def __init__(
        self,
        database_url: str,
        *,
        encryption_key: bytes,
        statement_timeout_ms: int = 1000,
    ) -> None:
        if len(encryption_key) != 32 or not 100 <= statement_timeout_ms <= 5000:
            raise ValueError("local_operator_store_configuration_invalid")
        self._key = encryption_key
        self._admission = BoundedSemaphore(8)
        self._dummy_password = LocalOperatorCredentials.hash_password(
            "local-login-dummy-password",
            salt=b"\0" * 16,
        )
        self._engine = create_engine(
            database_url,
            pool_pre_ping=True,
            hide_parameters=True,
            pool_size=2,
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
                connection.execute(
                    text("SELECT account_id FROM operator_local_credentials LIMIT 0")
                )
        except SQLAlchemyError:
            raise OidcLoginUnavailable("local_operator_store_unavailable") from None

    def account_id_for_username(self, username: str) -> UUID | None:
        if not 1 <= len(username) <= 256 or any(character.isspace() for character in username):
            return None
        try:
            with self._engine.connect() as connection:
                value = connection.scalar(
                    text(
                        "SELECT account_id FROM operator_local_credentials "
                        "WHERE username=:username"
                    ),
                    {"username": username},
                )
        except SQLAlchemyError:
            raise OidcLoginUnavailable("local_operator_store_unavailable") from None
        return None if value is None else UUID(str(value))

    def provision(
        self,
        *,
        account: OperatorAccount,
        credentials: LocalOperatorCredentials,
        context: OperatorMutationContext,
    ) -> int:
        username = account.subject.removeprefix("local:")
        if (
            account.identity_source.value != "local"
            or not account.subject.startswith("local:")
            or not 1 <= len(username) <= 256
            or any(character.isspace() for character in username)
            or account.authz_version != 1
            or not account.enabled
        ):
            raise ValueError("local_operator_provision_invalid")
        encrypted_totp: bytes | None = None
        if credentials.totp_secret is not None:
            nonce = secrets.token_bytes(12)
            encrypted_totp = nonce + AESGCM(self._key).encrypt(
                nonce,
                credentials.totp_secret,
                account.id.bytes,
            )
        try:
            with self._engine.begin() as connection:
                connection.execute(text("SET LOCAL synchronous_commit = on"))
                connection.execute(
                    text(
                        "INSERT INTO operator_accounts "
                        "(id, identity_source, subject, display_name, roles, scopes, "
                        "authz_version, enabled) VALUES "
                        "(:id, 'local', :subject, :display_name, :roles, :scopes, 1, true)"
                    ),
                    {
                        "id": account.id,
                        "subject": account.subject,
                        "display_name": account.display_name,
                        "roles": sorted(role.value for role in account.roles),
                        "scopes": sorted(account.scopes),
                    },
                )
                connection.execute(
                    text(
                        "INSERT INTO operator_local_credentials "
                        "(account_id, username, password_scrypt, totp_secret) VALUES "
                        "(:account_id, :username, :password_scrypt, :totp_secret)"
                    ),
                    {
                        "account_id": account.id,
                        "username": username,
                        "password_scrypt": credentials.password_scrypt,
                        "totp_secret": encrypted_totp,
                    },
                )
                _record_local_account_event(
                    connection,
                    account=account,
                    username=username,
                    context=context,
                )
            return 1
        except SQLAlchemyError:
            raise OidcLoginUnavailable("local_operator_store_unavailable") from None

    def authenticate(
        self,
        *,
        username: str,
        password: str,
        totp: str,
        source_ip: str,
        now: datetime,
    ) -> LocalOperatorAuthentication:
        if (
            not 1 <= len(username) <= 256
            or any(character.isspace() for character in username)
            or not 1 <= len(password) <= 1024
            or (totp and (len(totp) != 6 or not totp.isascii() or not totp.isdigit()))
            or not source_ip
            or now.tzinfo is None
        ):
            raise OidcLoginInvalid("local_operator_login_failed")
        if not self._admission.acquire(blocking=False):
            raise OidcLoginRateLimited()
        try:
            rejected = True
            rate_limited = False
            account_id: UUID | None = None
            authz_version = 0
            mfa_verified = False
            with self._engine.begin() as connection:
                connection.execute(text("SET LOCAL synchronous_commit = on"))
                rate_limited = _local_attempt_is_locked(
                    connection,
                    source_ip=source_ip,
                    username=username,
                )
                row = (
                    connection.execute(
                        text(
                            "SELECT a.id, a.enabled, a.authz_version, c.password_scrypt, "
                            "c.totp_secret, c.last_totp_step FROM operator_local_credentials c "
                            "JOIN operator_accounts a ON a.id=c.account_id "
                            "WHERE c.username=:username AND a.identity_source='local' "
                            "FOR UPDATE OF c"
                        ),
                        {"username": username},
                    )
                    .mappings()
                    .one_or_none()
                )
                password_credentials = LocalOperatorCredentials(
                    password_scrypt=(
                        self._dummy_password if row is None else bytes(row["password_scrypt"])
                    )
                )
                password_valid = password_credentials.verifies_password(password)
                if row is not None:
                    account_id = UUID(str(row["id"]))
                    authz_version = int(row["authz_version"])
                rejected = (
                    rate_limited
                    or row is None
                    or not bool(row["enabled"])
                    or not password_valid
                )
                if not rejected and totp:
                    assert row is not None
                    assert account_id is not None
                    encrypted = row["totp_secret"]
                    try:
                        if encrypted is None:
                            raise ValueError
                        encrypted_bytes = bytes(encrypted)
                        secret = AESGCM(self._key).decrypt(
                            encrypted_bytes[:12],
                            encrypted_bytes[12:],
                            account_id.bytes,
                        )
                        step = int(now.timestamp()) // 30
                        last_step = row["last_totp_step"]
                        if last_step is not None and step <= int(last_step):
                            raise ValueError
                        TOTP(secret, 6, hashes.SHA1(), 30).verify(
                            totp.encode("ascii"),
                            int(now.timestamp()),
                        )
                    except Exception:
                        rejected = True
                    else:
                        mfa_verified = True
                        connection.execute(
                            text(
                                "UPDATE operator_local_credentials SET last_totp_step=:step, "
                                "updated_at=clock_timestamp() WHERE account_id=:account_id"
                            ),
                            {"account_id": account_id, "step": step},
                        )
                if rejected and not rate_limited:
                    rate_limited = _record_local_failure(
                        connection,
                        source_ip=source_ip,
                        username=username,
                    )
                elif not rejected:
                    _clear_local_attempts(
                        connection,
                        source_ip=source_ip,
                        username=username,
                    )
                _record_local_login_attempt(
                    connection,
                    source_ip=source_ip,
                    outcome="rejected" if rejected else "accepted",
                    reason_code=(
                        "rate_limited"
                        if rate_limited
                        else "operator_login_failed"
                        if rejected
                        else "authenticated"
                    ),
                )
            if rate_limited:
                raise OidcLoginRateLimited()
            if rejected or account_id is None:
                raise OidcLoginInvalid("local_operator_login_failed")
            return LocalOperatorAuthentication(
                account_id=account_id,
                authz_version=authz_version,
                mfa_verified=mfa_verified,
            )
        except (OidcLoginInvalid, OidcLoginRateLimited):
            raise
        except SQLAlchemyError:
            raise OidcLoginUnavailable("local_operator_store_unavailable") from None
        except Exception:
            raise OidcLoginInvalid("local_operator_login_failed") from None
        finally:
            self._admission.release()

    def change_password(
        self,
        *,
        account_id: UUID,
        current_password: str,
        new_password: str,
        totp: str,
        current_session_id: UUID | None,
        context: OperatorRequestAuditContext,
        now: datetime,
    ) -> int:
        validate_local_operator_password(new_password)
        if now.tzinfo is None or not 1 <= len(current_password) <= 1024:
            raise OidcLoginInvalid("local_operator_password_change_denied")
        try:
            with self._engine.begin() as connection:
                connection.execute(text("SET LOCAL synchronous_commit = on"))
                row = (
                    connection.execute(
                        text(
                            "SELECT a.id, a.enabled, a.authz_version, c.password_scrypt, "
                            "c.totp_secret, c.last_totp_step "
                            "FROM operator_local_credentials c "
                            "JOIN operator_accounts a ON a.id=c.account_id "
                            "WHERE a.id=:account_id AND a.identity_source='local' "
                            "FOR UPDATE OF a, c"
                        ),
                        {"account_id": account_id},
                    )
                    .mappings()
                    .one_or_none()
                )
                credentials = LocalOperatorCredentials(
                    password_scrypt=(
                        self._dummy_password if row is None else bytes(row["password_scrypt"])
                    )
                )
                rejected = (
                    row is None
                    or not bool(row["enabled"])
                    or not credentials.verifies_password(current_password)
                    or credentials.verifies_password(new_password)
                )
                last_totp_step = None if row is None else row["last_totp_step"]
                if not rejected and row is not None and row["totp_secret"] is not None:
                    try:
                        encrypted = bytes(row["totp_secret"])
                        secret = AESGCM(self._key).decrypt(
                            encrypted[:12], encrypted[12:], account_id.bytes
                        )
                        step = int(now.timestamp()) // 30
                        if (
                            not totp
                            or (last_totp_step is not None and step <= int(last_totp_step))
                        ):
                            raise ValueError
                        TOTP(secret, 6, hashes.SHA1(), 30).verify(
                            totp.encode("ascii"), int(now.timestamp())
                        )
                    except Exception:
                        rejected = True
                    else:
                        last_totp_step = step
                if rejected:
                    raise OidcLoginInvalid("local_operator_password_change_denied")
                assert row is not None
                previous_version = int(row["authz_version"])
                if previous_version >= (1 << 63) - 1:
                    raise OidcLoginInvalid("local_operator_password_change_denied")
                authz_version = previous_version + 1
                connection.execute(
                    text(
                        "UPDATE operator_local_credentials SET password_scrypt=:password, "
                        "last_totp_step=:last_totp_step, updated_at=clock_timestamp() "
                        "WHERE account_id=:account_id"
                    ),
                    {
                        "account_id": account_id,
                        "password": LocalOperatorCredentials.hash_password(new_password),
                        "last_totp_step": last_totp_step,
                    },
                )
                connection.execute(
                    text(
                        "UPDATE operator_accounts SET authz_version=:authz_version, "
                        "updated_at=clock_timestamp() WHERE id=:account_id"
                    ),
                    {"account_id": account_id, "authz_version": authz_version},
                )
                revoked_sessions = len(
                    connection.execute(
                        text(
                            "UPDATE operator_sessions SET revoked_at=clock_timestamp() "
                            "WHERE account_id=:account_id AND revoked_at IS NULL "
                            "AND (:session_id IS NULL OR id<>:session_id) RETURNING id"
                        ),
                        {"account_id": account_id, "session_id": current_session_id},
                    ).all()
                )
                if current_session_id is not None:
                    updated = connection.execute(
                        text(
                            "UPDATE operator_sessions SET authz_version=:authz_version "
                            "WHERE id=:session_id AND account_id=:account_id "
                            "AND revoked_at IS NULL RETURNING id"
                        ),
                        {
                            "account_id": account_id,
                            "session_id": current_session_id,
                            "authz_version": authz_version,
                        },
                    ).one_or_none()
                    if updated is None:
                        raise OidcLoginInvalid("local_operator_password_change_denied")
                _record_local_password_change_event(
                    connection,
                    account_id=account_id,
                    authz_version=authz_version,
                    revoked_sessions=revoked_sessions,
                    context=context,
                )
                return authz_version
        except OidcLoginInvalid:
            raise
        except SQLAlchemyError:
            raise OidcLoginUnavailable("local_operator_store_unavailable") from None


class LocalOperatorPasswordStore(Protocol):
    def change_password(
        self,
        *,
        account_id: UUID,
        current_password: str,
        new_password: str,
        totp: str,
        current_session_id: UUID | None,
        context: OperatorRequestAuditContext,
        now: datetime,
    ) -> int: ...


class LocalOperatorPasswordControl:
    def __init__(
        self,
        *,
        store: LocalOperatorPasswordStore,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._store = store
        self._clock = clock

    def change(
        self,
        *,
        account_id: UUID,
        current_session_id: UUID | None,
        current_password: str,
        new_password: str,
        totp: str,
        context: OperatorRequestAuditContext,
    ) -> int:
        return self._store.change_password(
            account_id=account_id,
            current_password=current_password,
            new_password=new_password,
            totp=totp,
            current_session_id=current_session_id,
            context=context,
            now=self._clock(),
        )


class LocalOperatorAuthenticator(Protocol):
    def authenticate(
        self,
        *,
        username: str,
        password: str,
        totp: str,
        source_ip: str,
        now: datetime,
    ) -> LocalOperatorAuthentication: ...


class LocalOperatorLoginControl:
    def __init__(
        self,
        *,
        store: LocalOperatorAuthenticator,
        sessions: OperatorSessionControl,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._store = store
        self._sessions = sessions
        self._clock = clock

    def login(
        self,
        *,
        username: str,
        password: str,
        totp: str = "",
        source_ip: str,
        audit_context: OperatorRequestAuditContext | None = None,
    ) -> IssuedOperatorSession:
        now = self._clock()
        if now.tzinfo is None:
            raise OidcLoginInvalid("local_operator_login_failed")
        authentication = self._store.authenticate(
            username=username,
            password=password,
            totp=totp,
            source_ip=source_ip,
            now=now,
        )
        try:
            return self._sessions.issue(
                account_id=authentication.account_id,
                mfa_verified=authentication.mfa_verified,
                expected_authz_version=authentication.authz_version,
                audit_context=audit_context,
            )
        except OperatorAuthenticationRequired:
            raise OidcLoginInvalid("local_operator_login_failed") from None


class InMemoryBreakGlassStore:
    def __init__(
        self,
        *,
        account: OperatorAccount,
        credentials: BreakGlassCredentials,
    ) -> None:
        if account.identity_source.value != "break_glass":
            raise ValueError("break_glass_account_invalid")
        self._account = account
        self._credentials = credentials
        self._events: list[OperatorSecurityEvent] = []
        self._lock = RLock()

    def authenticate(
        self,
        *,
        username: str,
        password: str,
        totp: str,
        source_ip: str,
        now: datetime,
    ) -> BreakGlassAuthentication:
        with self._lock:
            expected_username = self._account.subject.removeprefix("local:")
            step = int(now.timestamp()) // 30
            rejected = (
                not self._account.enabled
                or not hmac.compare_digest(username, expected_username)
                or not self._credentials.verifies_password(password)
                or (
                    self._credentials.last_totp_step is not None
                    and step <= self._credentials.last_totp_step
                )
            )
            if not rejected:
                try:
                    TOTP(
                        self._credentials.totp_secret,
                        6,
                        hashes.SHA1(),
                        30,
                    ).verify(totp.encode("ascii"), int(now.timestamp()))
                except Exception:
                    rejected = True
            outcome = "rejected" if rejected else "accepted"
            reason_code = "invalid_credentials" if rejected else "authenticated"
            self._events.append(
                OperatorSecurityEvent(
                    event_type="operator.break_glass_login",
                    severity="critical",
                    account_id=self._account.id,
                    occurred_at=now,
                    outcome=outcome,
                    reason_code=reason_code,
                )
            )
            if rejected:
                raise OidcLoginInvalid("break_glass_login_failed")
            self._credentials = replace(self._credentials, last_totp_step=step)
            return BreakGlassAuthentication(
                account_id=self._account.id,
                authz_version=self._account.authz_version,
            )

    def last_totp_step(self) -> int | None:
        with self._lock:
            return self._credentials.last_totp_step

    def security_events(self) -> tuple[OperatorSecurityEvent, ...]:
        with self._lock:
            return tuple(self._events)


class PostgresBreakGlassStore:
    def __init__(
        self,
        database_url: str,
        *,
        encryption_key: bytes,
        statement_timeout_ms: int = 1000,
    ) -> None:
        if len(encryption_key) != 32 or not 100 <= statement_timeout_ms <= 5000:
            raise ValueError("break_glass_store_configuration_invalid")
        self._key = encryption_key
        self._admission = BoundedSemaphore(2)
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

    def existing_break_glass_account_id(self) -> UUID | None:
        try:
            with self._engine.connect() as connection:
                account_id = connection.scalar(
                    text("SELECT id FROM operator_accounts WHERE identity_source = 'break_glass'")
                )
        except SQLAlchemyError:
            raise OidcLoginUnavailable("break_glass_store_unavailable") from None
        return None if account_id is None else UUID(str(account_id))

    def rotate(
        self,
        *,
        account_id: UUID,
        subject: str,
        expected_authz_version: int,
        password_scrypt: bytes,
        totp_secret: bytes,
        context: OperatorMutationContext,
    ) -> int:
        credentials = BreakGlassCredentials(
            password_scrypt=password_scrypt,
            totp_secret=totp_secret,
            last_totp_step=None,
        )
        username = subject.removeprefix("local:")
        if (
            not subject.startswith("local:")
            or not 1 <= len(username) <= 256
            or any(character.isspace() for character in username)
            or not 1 <= expected_authz_version < (1 << 63) - 1
        ):
            raise ValueError("break_glass_rotation_invalid")
        nonce = secrets.token_bytes(12)
        encrypted_secret = nonce + AESGCM(self._key).encrypt(
            nonce,
            credentials.totp_secret,
            account_id.bytes,
        )
        try:
            with self._engine.begin() as connection:
                connection.execute(text("SET LOCAL synchronous_commit = on"))
                current = (
                    connection.execute(
                        text(
                            "SELECT id, subject, enabled, authz_version, "
                            "break_glass_password_scrypt, break_glass_totp_secret "
                            "FROM operator_accounts WHERE identity_source = 'break_glass' "
                            "FOR UPDATE"
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if (
                    current is None
                    or UUID(str(current["id"])) != account_id
                    or str(current["subject"]) != subject
                    or not bool(current["enabled"])
                    or current["break_glass_password_scrypt"] is None
                    or current["break_glass_totp_secret"] is None
                    or int(current["authz_version"]) != expected_authz_version
                ):
                    raise OidcLoginInvalid("break_glass_account_conflict")
                authz_version = expected_authz_version + 1
                connection.execute(
                    text(
                        "UPDATE operator_accounts SET authz_version = :authz_version, "
                        "break_glass_password_scrypt = :password_scrypt, "
                        "break_glass_totp_secret = :totp_secret, "
                        "break_glass_last_totp_step = NULL, updated_at = clock_timestamp() "
                        "WHERE id = :id AND authz_version = :expected_authz_version"
                    ),
                    {
                        "id": account_id,
                        "expected_authz_version": expected_authz_version,
                        "authz_version": authz_version,
                        "password_scrypt": credentials.password_scrypt,
                        "totp_secret": encrypted_secret,
                    },
                )
                revoked_sessions = len(
                    connection.execute(
                        text(
                            "UPDATE operator_sessions SET revoked_at = clock_timestamp() "
                            "WHERE account_id = :account_id AND revoked_at IS NULL "
                            "RETURNING id"
                        ),
                        {"account_id": account_id},
                    ).all()
                )
                _record_break_glass_rotation_event(
                    connection,
                    account_id=account_id,
                    before_authz_version=expected_authz_version,
                    after_authz_version=authz_version,
                    revoked_sessions=revoked_sessions,
                    context=context,
                )
                return authz_version
        except OidcLoginInvalid:
            self._record_rotation_rejection(
                account_id=account_id,
                expected_authz_version=expected_authz_version,
                context=context,
            )
            raise
        except SQLAlchemyError:
            raise OidcLoginUnavailable("break_glass_store_unavailable") from None

    def _record_rotation_rejection(
        self,
        *,
        account_id: UUID,
        expected_authz_version: int,
        context: OperatorMutationContext,
    ) -> None:
        try:
            with self._engine.begin() as connection:
                connection.execute(text("SET LOCAL synchronous_commit = on"))
                current = (
                    connection.execute(
                        text(
                            "SELECT id, authz_version FROM operator_accounts "
                            "WHERE identity_source = 'break_glass'"
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                _record_break_glass_rotation_rejection_event(
                    connection,
                    account_id=(
                        account_id if current is None else UUID(str(current["id"]))
                    ),
                    requested_account_id=account_id,
                    aggregate_revision=(
                        expected_authz_version
                        if current is None
                        else int(current["authz_version"])
                    ),
                    expected_authz_version=expected_authz_version,
                    context=context,
                )
        except SQLAlchemyError:
            raise OidcLoginUnavailable("break_glass_store_unavailable") from None

    def record_claim_contract_health(self, *, healthy: bool) -> None:
        """Persist only health transitions and enqueue one failure/recovery alert."""

        try:
            with self._engine.begin() as connection:
                connection.execute(text("SET LOCAL synchronous_commit = on"))
                inserted = connection.execute(
                    text(
                        "INSERT INTO oidc_claim_contract_state (singleton, healthy) "
                        "VALUES (true, :healthy) ON CONFLICT (singleton) DO NOTHING "
                        "RETURNING healthy"
                    ),
                    {"healthy": healthy},
                ).one_or_none()
                current = (
                    None
                    if inserted is not None
                    else (
                        connection.execute(
                            text(
                                "SELECT healthy FROM oidc_claim_contract_state "
                                "WHERE singleton FOR UPDATE"
                            )
                        )
                        .mappings()
                        .one_or_none()
                    )
                )
                if inserted is not None:
                    changed = not healthy
                else:
                    if current is None:
                        raise OidcLoginUnavailable("oidc_claim_contract_store_unavailable")
                    changed = bool(current["healthy"]) != healthy
                    connection.execute(
                        text(
                            "UPDATE oidc_claim_contract_state SET healthy = :healthy, "
                            "last_checked_at = clock_timestamp(), "
                            "last_changed_at = CASE WHEN healthy <> :healthy "
                            "THEN clock_timestamp() ELSE last_changed_at END "
                            "WHERE singleton"
                        ),
                        {"healthy": healthy},
                    )
                if not changed:
                    return
                account_id = connection.scalar(
                    text(
                        "SELECT id FROM operator_accounts "
                        "WHERE identity_source = 'break_glass' AND enabled"
                    )
                )
                if account_id is None:
                    raise OidcLoginUnavailable("break_glass_account_unavailable")
                connection.execute(
                    text(
                        "INSERT INTO operator_security_alerts "
                        "(id, account_id, event_type, outcome, reason_code, status, "
                        "attempts, available_at) VALUES "
                        "(:id, :account_id, 'operator.oidc_claim_contract', :outcome, "
                        ":reason_code, 'pending', 0, clock_timestamp())"
                    ),
                    {
                        "id": uuid4(),
                        "account_id": account_id,
                        "outcome": "recovered" if healthy else "failed",
                        "reason_code": (
                            "claim_contract_restored" if healthy else "claim_contract_changed"
                        ),
                    },
                )
        except OidcLoginUnavailable:
            raise
        except SQLAlchemyError:
            raise OidcLoginUnavailable("oidc_claim_contract_store_unavailable") from None

    def assert_ready(self) -> None:
        try:
            with self._engine.connect() as connection:
                rows = (
                    connection.execute(
                        text(
                            "SELECT id, enabled, break_glass_password_scrypt, "
                            "break_glass_totp_secret FROM operator_accounts "
                            "WHERE identity_source = 'break_glass'"
                        )
                    )
                    .mappings()
                    .all()
                )
                if len(rows) != 1 or not rows[0]["enabled"]:
                    raise OidcLoginUnavailable("break_glass_account_unavailable")
                account_id = UUID(str(rows[0]["id"]))
                encrypted = bytes(rows[0]["break_glass_totp_secret"])
                if len(bytes(rows[0]["break_glass_password_scrypt"])) != 80:
                    raise ValueError
                secret = AESGCM(self._key).decrypt(
                    encrypted[:12],
                    encrypted[12:],
                    account_id.bytes,
                )
                if len(secret) < 20:
                    raise ValueError
                transaction = connection.begin_nested()
                connection.execute(
                    text(
                        "INSERT INTO operator_security_alerts "
                        "(id, account_id, event_type, outcome, reason_code, status, "
                        "attempts, available_at) VALUES "
                        "(:id, :account_id, 'operator.break_glass_login', 'rejected', "
                        "'invalid_credentials', 'pending', 0, clock_timestamp())"
                    ),
                    {"id": uuid4(), "account_id": account_id},
                )
                transaction.rollback()
        except OidcLoginUnavailable:
            raise
        except (SQLAlchemyError, ValueError, InvalidTag):
            raise OidcLoginUnavailable("break_glass_account_unavailable") from None

    def provision(
        self,
        *,
        account: OperatorAccount,
        password_scrypt: bytes,
        totp_secret: bytes,
        context: OperatorMutationContext,
    ) -> int:
        if account.identity_source.value != "break_glass":
            raise ValueError("break_glass_account_invalid")
        credentials = BreakGlassCredentials(
            password_scrypt=password_scrypt,
            totp_secret=totp_secret,
            last_totp_step=None,
        )
        nonce = secrets.token_bytes(12)
        encrypted_secret = nonce + AESGCM(self._key).encrypt(
            nonce,
            credentials.totp_secret,
            account.id.bytes,
        )
        try:
            with self._engine.begin() as connection:
                connection.execute(text("SET LOCAL synchronous_commit = on"))
                current = (
                    connection.execute(
                        text(
                            "SELECT id, subject, display_name, roles, scopes, enabled, "
                            "authz_version, "
                            "break_glass_password_scrypt, break_glass_totp_secret "
                            "FROM operator_accounts WHERE identity_source = 'break_glass' "
                            "FOR UPDATE"
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                parameters = {
                    "id": account.id,
                    "subject": account.subject,
                    "display_name": account.display_name,
                    "roles": sorted(role.value for role in account.roles),
                    "scopes": sorted(account.scopes),
                    "password_scrypt": credentials.password_scrypt,
                    "totp_secret": encrypted_secret,
                }
                before_authz_version: int | None
                before_enabled: bool | None
                before_display_name: str | None
                before_roles: list[str] | None
                before_scopes: list[str] | None
                if current is None:
                    before_authz_version = None
                    before_enabled = None
                    before_display_name = None
                    before_roles = None
                    before_scopes = None
                    authz_version = 1
                    connection.execute(
                        text(
                            "INSERT INTO operator_accounts "
                            "(id, identity_source, subject, display_name, roles, scopes, "
                            "authz_version, enabled, break_glass_password_scrypt, "
                            "break_glass_totp_secret) VALUES "
                            "(:id, 'break_glass', :subject, :display_name, :roles, :scopes, "
                            "1, true, :password_scrypt, :totp_secret)"
                        ),
                        parameters,
                    )
                else:
                    before_authz_version = int(current["authz_version"])
                    before_enabled = bool(current["enabled"])
                    before_display_name = str(current["display_name"])
                    before_roles = sorted(str(role) for role in current["roles"])
                    before_scopes = sorted(str(scope) for scope in current["scopes"])
                    if (
                        UUID(str(current["id"])) != account.id
                        or current["subject"] != account.subject
                        or before_enabled
                        or current["break_glass_password_scrypt"] is not None
                        or current["break_glass_totp_secret"] is not None
                        or before_authz_version >= (1 << 63) - 1
                    ):
                        raise OidcLoginInvalid("break_glass_account_conflict")
                    authz_version = before_authz_version + 1
                    connection.execute(
                        text(
                            "UPDATE operator_accounts SET display_name = :display_name, "
                            "roles = :roles, scopes = :scopes, authz_version = :authz_version, "
                            "enabled = true, break_glass_password_scrypt = :password_scrypt, "
                            "break_glass_totp_secret = :totp_secret, "
                            "break_glass_last_totp_step = NULL, updated_at = clock_timestamp() "
                            "WHERE id = :id"
                        ),
                        parameters | {"authz_version": authz_version},
                    )
                _record_break_glass_provision_event(
                    connection,
                    account_id=account.id,
                    authz_version=authz_version,
                    before_authz_version=before_authz_version,
                    before_enabled=before_enabled,
                    before_display_name=before_display_name,
                    before_roles=before_roles,
                    before_scopes=before_scopes,
                    after_display_name=account.display_name,
                    after_roles=sorted(role.value for role in account.roles),
                    after_scopes=sorted(account.scopes),
                    context=context,
                )
                return authz_version
        except OidcLoginInvalid:
            raise
        except SQLAlchemyError:
            raise OidcLoginUnavailable("break_glass_store_unavailable") from None

    def authenticate(
        self,
        *,
        username: str,
        password: str,
        totp: str,
        source_ip: str,
        now: datetime,
    ) -> BreakGlassAuthentication:
        if not self._admission.acquire(blocking=False):
            self._record_admission_rejection(source_ip=source_ip)
            raise OidcLoginRateLimited(1)
        rejected = False
        account_id: UUID | None = None
        try:
            with self._engine.begin() as connection:
                connection.execute(text("SET LOCAL synchronous_commit = on"))
                row = (
                    connection.execute(
                        text(
                            "SELECT id, subject, enabled, break_glass_password_scrypt, "
                            "break_glass_totp_secret, break_glass_last_totp_step, "
                            "authz_version FROM operator_accounts "
                            "WHERE identity_source = 'break_glass' FOR UPDATE"
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if row is None:
                    raise OidcLoginUnavailable("break_glass_account_unavailable")
                account_id = UUID(str(row["id"]))
                rate_limited = _break_glass_attempt_is_locked(
                    connection,
                    source_ip=source_ip,
                    username=username,
                )
                encrypted_secret = bytes(row["break_glass_totp_secret"])
                nonce, ciphertext = encrypted_secret[:12], encrypted_secret[12:]
                credentials = BreakGlassCredentials(
                    password_scrypt=bytes(row["break_glass_password_scrypt"]),
                    totp_secret=AESGCM(self._key).decrypt(
                        nonce,
                        ciphertext,
                        account_id.bytes,
                    ),
                    last_totp_step=row["break_glass_last_totp_step"],
                )
                step = int(now.timestamp()) // 30
                rejected = rate_limited or (
                    not row["enabled"]
                    or not hmac.compare_digest(
                        username,
                        str(row["subject"]).removeprefix("local:"),
                    )
                    or not credentials.verifies_password(password)
                    or (
                        credentials.last_totp_step is not None
                        and step <= credentials.last_totp_step
                    )
                )
                try:
                    if rejected:
                        raise ValueError
                    TOTP(credentials.totp_secret, 6, hashes.SHA1(), 30).verify(
                        totp.encode("ascii"),
                        int(now.timestamp()),
                    )
                except Exception:
                    rejected = True
                if rejected and not rate_limited:
                    rate_limited = _record_break_glass_failure(
                        connection,
                        source_ip=source_ip,
                        username=username,
                    )
                elif not rejected:
                    connection.execute(
                        text(
                            "UPDATE operator_accounts SET "
                            "break_glass_last_totp_step = :step, "
                            "updated_at = clock_timestamp() WHERE id = :id"
                        ),
                        {"id": account_id, "step": step},
                    )
                    _clear_break_glass_attempts(
                        connection,
                        source_ip=source_ip,
                        username=username,
                    )
                _record_break_glass_event(
                    connection,
                    account_id=account_id,
                    authz_version=int(row["authz_version"]),
                    outcome="rejected" if rejected else "accepted",
                    reason_code=(
                        "rate_limited"
                        if rate_limited
                        else "invalid_credentials"
                        if rejected
                        else "authenticated"
                    ),
                )
            if rate_limited:
                raise OidcLoginRateLimited()
            if rejected:
                raise OidcLoginInvalid("break_glass_login_failed")
            assert account_id is not None
            return BreakGlassAuthentication(
                account_id=account_id,
                authz_version=int(row["authz_version"]),
            )
        except (OidcLoginInvalid, OidcLoginRateLimited):
            raise
        except SQLAlchemyError:
            raise OidcLoginUnavailable("break_glass_store_unavailable") from None
        except Exception:
            if account_id is not None:
                self._record_rejection_after_failure(account_id=account_id)
            raise OidcLoginInvalid("break_glass_login_failed") from None
        finally:
            self._admission.release()

    def _record_admission_rejection(self, *, source_ip: str) -> None:
        try:
            with self._engine.begin() as connection:
                connection.execute(text("SET LOCAL synchronous_commit = on"))
                row = connection.execute(
                    text(
                        "SELECT id, authz_version FROM operator_accounts "
                        "WHERE identity_source = 'break_glass' FOR UPDATE"
                    )
                ).one_or_none()
                if row is None:
                    raise OidcLoginUnavailable("break_glass_account_unavailable")
                _record_break_glass_event(
                    connection,
                    account_id=UUID(str(row.id)),
                    authz_version=int(row.authz_version),
                    outcome="rejected",
                    reason_code="rate_limited",
                )
                _record_progressive_failure(
                    connection,
                    key_sha256=_break_glass_source_attempt_key(source_ip),
                )
        except OidcLoginUnavailable:
            raise
        except SQLAlchemyError:
            raise OidcLoginUnavailable("break_glass_store_unavailable") from None

    def _record_rejection_after_failure(self, *, account_id: UUID) -> None:
        try:
            with self._engine.begin() as connection:
                connection.execute(text("SET LOCAL synchronous_commit = on"))
                row = connection.execute(
                    text("SELECT authz_version FROM operator_accounts WHERE id = :id FOR UPDATE"),
                    {"id": account_id},
                ).one_or_none()
                if row is not None:
                    _record_break_glass_event(
                        connection,
                        account_id=account_id,
                        authz_version=int(row.authz_version),
                        outcome="rejected",
                        reason_code="invalid_credentials",
                    )
        except SQLAlchemyError:
            raise OidcLoginUnavailable("break_glass_store_unavailable") from None


class BreakGlassAuthenticator(Protocol):
    def authenticate(
        self,
        *,
        username: str,
        password: str,
        totp: str,
        source_ip: str,
        now: datetime,
    ) -> BreakGlassAuthentication: ...


class BreakGlassControl:
    def __init__(
        self,
        *,
        store: BreakGlassAuthenticator,
        sessions: OperatorSessionControl,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._store = store
        self._sessions = sessions
        self._clock = clock

    def login(
        self,
        *,
        username: str,
        password: str,
        totp: str,
        source_ip: str,
        audit_context: OperatorRequestAuditContext | None = None,
    ) -> IssuedOperatorSession:
        now = self._clock()
        if now.tzinfo is None:
            raise OidcLoginInvalid("break_glass_login_failed")
        authentication = self._store.authenticate(
            username=username,
            password=password,
            totp=totp,
            source_ip=source_ip,
            now=now,
        )
        try:
            return self._sessions.issue(
                account_id=authentication.account_id,
                mfa_verified=True,
                expected_authz_version=authentication.authz_version,
                audit_context=audit_context,
            )
        except OperatorAuthenticationRequired:
            raise OidcLoginInvalid("break_glass_login_failed") from None


@dataclass(frozen=True, slots=True)
class OidcIdentity:
    subject: str
    display_name: str
    groups: frozenset[str]
    roles: frozenset[OperatorRole]
    mfa_verified: bool

    def __post_init__(self) -> None:
        if (
            not 1 <= len(self.subject) <= 512
            or not 1 <= len(self.display_name) <= 256
            or not self.groups
            or not self.roles
            or len(self.groups) > 128
            or any(not 1 <= len(group) <= 256 for group in self.groups)
        ):
            raise ValueError("oidc_identity_invalid")


class OidcTokenEndpoint(Protocol):
    def exchange(self, *, code: str, code_verifier: str) -> str: ...


class OidcClaimsVerifier(Protocol):
    def verify(self, *, id_token: str, nonce: str) -> OidcIdentity: ...


class OidcFlowStore(Protocol):
    def create(
        self,
        *,
        state_sha256: str,
        browser_sha256: str,
        source_ip_sha256: str,
        return_to: str,
        lifetime: timedelta,
    ) -> OidcFlow: ...

    def consume(self, state_sha256: str, *, browser_sha256: str) -> OidcFlow: ...

    def record_rejection(self, *, source_ip_sha256: str) -> None: ...

    def assert_identity_allowed(self, *, identity_sha256: str) -> None: ...

    def record_identity_rejection(self, *, identity_sha256: str) -> None: ...

    def record_success(
        self,
        *,
        source_ip_sha256: str,
        identity_sha256: str,
    ) -> None: ...


class _HttpsResponse(Protocol):
    status: int
    headers: Any

    def read(self, amount: int = -1) -> bytes: ...


class _HttpsOpener(Protocol):
    def __call__(
        self,
        request: Request,
        *,
        timeout: float,
        context: ssl.SSLContext,
    ) -> AbstractContextManager[_HttpsResponse]: ...


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


def _open_https_without_redirects(
    request: Request,
    *,
    timeout: float,
    context: ssl.SSLContext,
) -> AbstractContextManager[_HttpsResponse]:
    opener = build_opener(HTTPSHandler(context=context), _RejectRedirects())
    return cast(AbstractContextManager[_HttpsResponse], opener.open(request, timeout=timeout))


_DEFAULT_HTTPS_OPENER: _HttpsOpener = _open_https_without_redirects


class HttpsOidcTokenEndpoint:
    """Exchange one authorization code over a bounded verified-TLS request."""

    def __init__(
        self,
        *,
        token_endpoint: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        timeout_seconds: float = 5,
        maximum_response_bytes: int = 65_536,
        ca_file: Path | None = None,
        opener: _HttpsOpener = _DEFAULT_HTTPS_OPENER,
        monotonic_clock: Callable[[], float] = monotonic,
    ) -> None:
        if (
            not token_endpoint.startswith("https://")
            or not client_id
            or not client_secret
            or not redirect_uri.startswith("https://")
            or not 0 < timeout_seconds <= 10
            or not 1024 <= maximum_response_bytes <= 1_048_576
        ):
            raise ValueError("oidc_token_endpoint_configuration_invalid")
        self._token_endpoint = token_endpoint
        self._client_id = client_id
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri
        self._timeout_seconds = timeout_seconds
        self._maximum_response_bytes = maximum_response_bytes
        self._context = ssl.create_default_context(cafile=None if ca_file is None else str(ca_file))
        self._opener = opener
        self._monotonic = monotonic_clock
        self._readiness_lock = RLock()
        self._readiness_succeeded_at: float | None = None

    def exchange(self, *, code: str, code_verifier: str) -> str:
        if not 1 <= len(code) <= 2048 or not 43 <= len(code_verifier) <= 128:
            raise OidcLoginInvalid("oidc_callback_invalid")
        request = self._token_request(code=code, code_verifier=code_verifier)
        try:
            with self._opener(
                request,
                timeout=self._timeout_seconds,
                context=self._context,
            ) as response:
                if response.status != 200:
                    if 400 <= response.status < 500:
                        raise OidcLoginInvalid("oidc_callback_failed")
                    raise OidcLoginUnavailable("oidc_provider_unavailable")
                content_type = str(response.headers.get("Content-Type", ""))
                if content_type.partition(";")[0].strip().lower() != "application/json":
                    raise OidcLoginInvalid("oidc_callback_failed")
                payload = response.read(self._maximum_response_bytes + 1)
        except HTTPError as error:
            if 400 <= error.code < 500:
                raise OidcLoginInvalid("oidc_callback_failed") from None
            raise OidcLoginUnavailable("oidc_provider_unavailable") from None
        except (TimeoutError, URLError, OSError, ssl.SSLError):
            raise OidcLoginUnavailable("oidc_provider_unavailable") from None
        if len(payload) > self._maximum_response_bytes:
            raise OidcLoginInvalid("oidc_callback_failed")
        try:
            parsed = json.loads(payload)
            id_token = parsed["id_token"]
        except (UnicodeError, json.JSONDecodeError, KeyError, TypeError):
            raise OidcLoginInvalid("oidc_callback_failed") from None
        if not isinstance(id_token, str) or not 1 <= len(id_token) <= 32_768:
            raise OidcLoginInvalid("oidc_callback_failed")
        return id_token

    def assert_ready(self) -> None:
        """Prove the pinned IdP token endpoint is reachable without issuing a token."""

        now = self._monotonic()
        if self._readiness_succeeded_at is not None and now - self._readiness_succeeded_at <= 30:
            return
        if not self._readiness_lock.acquire(blocking=False):
            raise OidcLoginUnavailable("oidc_provider_unavailable")
        try:
            now = self._monotonic()
            if (
                self._readiness_succeeded_at is not None
                and now - self._readiness_succeeded_at <= 30
            ):
                return
            request = self._token_request(
                code="rtsp-proxy-readiness-invalid-code",
                code_verifier="R" * 43,
            )
            try:
                with self._opener(
                    request,
                    timeout=self._timeout_seconds,
                    context=self._context,
                ) as response:
                    payload = response.read(self._maximum_response_bytes + 1)
                    if not _is_expected_oauth_rejection(
                        status=response.status,
                        content_type=str(response.headers.get("Content-Type", "")),
                        payload=payload,
                        maximum_bytes=self._maximum_response_bytes,
                    ):
                        raise OidcLoginUnavailable("oidc_provider_unavailable")
            except HTTPError as error:
                payload = error.read(self._maximum_response_bytes + 1)
                if not _is_expected_oauth_rejection(
                    status=error.code,
                    content_type=str(error.headers.get("Content-Type", "")),
                    payload=payload,
                    maximum_bytes=self._maximum_response_bytes,
                ):
                    raise OidcLoginUnavailable("oidc_provider_unavailable") from None
            except (TimeoutError, URLError, OSError, ssl.SSLError):
                raise OidcLoginUnavailable("oidc_provider_unavailable") from None
            self._readiness_succeeded_at = self._monotonic()
        finally:
            self._readiness_lock.release()

    def _token_request(self, *, code: str, code_verifier: str) -> Request:
        authorization = base64.b64encode(
            (
                f"{quote_plus(self._client_id, safe='')}:{quote_plus(self._client_secret, safe='')}"
            ).encode("ascii")
        ).decode("ascii")
        body = urlencode(
            {
                "code": code,
                "code_verifier": code_verifier,
                "grant_type": "authorization_code",
                "redirect_uri": self._redirect_uri,
            }
        ).encode("ascii")
        return Request(
            self._token_endpoint,
            data=body,
            headers={
                "Accept": "application/json",
                "Authorization": f"Basic {authorization}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            method="POST",
        )


class HttpsOidcDiscoveryEndpoint:
    """Verify the live IdP protocol and claim contract over bounded verified TLS."""

    _REQUIRED_CLAIMS = frozenset(
        {"acr", "amr", "aud", "exp", "groups", "iat", "iss", "nonce", "sub"}
    )

    def __init__(
        self,
        *,
        issuer: str,
        authorization_endpoint: str,
        token_endpoint: str,
        timeout_seconds: float = 5,
        maximum_response_bytes: int = 65_536,
        ca_file: Path | None = None,
        opener: _HttpsOpener = _DEFAULT_HTTPS_OPENER,
        monotonic_clock: Callable[[], float] = monotonic,
    ) -> None:
        if (
            not issuer.startswith("https://")
            or not authorization_endpoint.startswith("https://")
            or not token_endpoint.startswith("https://")
            or not 0 < timeout_seconds <= 10
            or not 1024 <= maximum_response_bytes <= 1_048_576
        ):
            raise ValueError("oidc_discovery_configuration_invalid")
        self._issuer = issuer.rstrip("/")
        self._authorization_endpoint = authorization_endpoint
        self._token_endpoint = token_endpoint
        self._timeout_seconds = timeout_seconds
        self._maximum_response_bytes = maximum_response_bytes
        self._context = ssl.create_default_context(cafile=None if ca_file is None else str(ca_file))
        self._opener = opener
        self._monotonic = monotonic_clock
        self._readiness_lock = RLock()
        self._readiness_succeeded_at: float | None = None

    def assert_ready(self) -> None:
        now = self._monotonic()
        if self._readiness_succeeded_at is not None and now - self._readiness_succeeded_at <= 30:
            return
        if not self._readiness_lock.acquire(blocking=False):
            raise OidcLoginUnavailable("oidc_claim_contract_unavailable")
        try:
            now = self._monotonic()
            if (
                self._readiness_succeeded_at is not None
                and now - self._readiness_succeeded_at <= 30
            ):
                return
            request = Request(
                self._issuer + "/.well-known/openid-configuration",
                headers={"Accept": "application/json"},
                method="GET",
            )
            try:
                with self._opener(
                    request,
                    timeout=self._timeout_seconds,
                    context=self._context,
                ) as response:
                    content_type = str(response.headers.get("Content-Type", ""))
                    payload = response.read(self._maximum_response_bytes + 1)
                    if response.status != 200:
                        raise ValueError
            except (HTTPError, TimeoutError, URLError, OSError, ssl.SSLError, ValueError):
                raise OidcLoginUnavailable("oidc_claim_contract_unavailable") from None
            if (
                content_type.partition(";")[0].strip().lower() != "application/json"
                or len(payload) > self._maximum_response_bytes
            ):
                raise OidcLoginUnavailable("oidc_claim_contract_unavailable")
            try:
                document = json.loads(payload)
                claims = frozenset(document["claims_supported"])
                signing_algorithms = frozenset(document["id_token_signing_alg_values_supported"])
                response_types = frozenset(document["response_types_supported"])
                pkce_methods = frozenset(document["code_challenge_methods_supported"])
                valid = (
                    document["issuer"] == self._issuer
                    and document["authorization_endpoint"] == self._authorization_endpoint
                    and document["token_endpoint"] == self._token_endpoint
                    and claims >= self._REQUIRED_CLAIMS
                    and bool({"name", "preferred_username", "email"} & claims)
                    and "RS256" in signing_algorithms
                    and "code" in response_types
                    and "S256" in pkce_methods
                )
            except (KeyError, TypeError, UnicodeError, json.JSONDecodeError):
                valid = False
            if not valid:
                raise OidcLoginUnavailable("oidc_claim_contract_unavailable")
            self._readiness_succeeded_at = self._monotonic()
        finally:
            self._readiness_lock.release()


def _is_expected_oauth_rejection(
    *,
    status: int,
    content_type: str,
    payload: bytes,
    maximum_bytes: int,
) -> bool:
    if (
        status != 400
        or content_type.partition(";")[0].strip().lower() != "application/json"
        or not payload
        or len(payload) > maximum_bytes
    ):
        return False
    try:
        parsed = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError):
        return False
    return (
        isinstance(parsed, dict)
        and parsed.get("error") == "invalid_grant"
        and all(isinstance(key, str) for key in parsed)
    )


class Rs256OidcClaimsVerifier:
    def __init__(
        self,
        *,
        issuer: str,
        client_id: str,
        jwks: dict[str, object],
        group_roles: dict[str, frozenset[OperatorRole]],
        accepted_mfa_acr: frozenset[str],
        required_mfa_amr: frozenset[str],
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if (
            not issuer.startswith("https://")
            or not client_id
            or not group_roles
            or not accepted_mfa_acr
            or len(required_mfa_amr) < 2
        ):
            raise ValueError("oidc_claims_configuration_invalid")
        try:
            self._keys = KeySet.import_key_set(cast(Any, jwks))
        except Exception:
            raise ValueError("oidc_jwks_invalid") from None
        self._issuer = issuer
        self._client_id = client_id
        self._group_roles = dict(group_roles)
        self._accepted_mfa_acr = accepted_mfa_acr
        self._required_mfa_amr = required_mfa_amr
        self._clock = clock

    def assert_ready(self) -> None:
        if not self._keys or not self._group_roles:
            raise OidcLoginUnavailable("oidc_claim_mapping_unavailable")

    def verify(self, *, id_token: str, nonce: str) -> OidcIdentity:
        try:
            now = self._clock()
            if now.tzinfo is None:
                raise ValueError
            token = jwt.decode(
                id_token,
                self._keys,
                algorithms=["RS256"],
            )
            registry = JWTClaimsRegistry(
                now=int(now.timestamp()),
                leeway=30,
                iss={"essential": True, "value": self._issuer},
                aud={"essential": True, "value": self._client_id},
                sub={"essential": True},
                exp={"essential": True},
                iat={"essential": True},
                nonce={"essential": True, "value": nonce},
                name={"essential": True},
                groups={"essential": True},
            )
            registry.validate(token.claims)
            subject = token.claims["sub"]
            display_name = token.claims["name"]
            raw_groups = token.claims["groups"]
            acr = token.claims.get("acr")
            amr = token.claims.get("amr")
            audience = token.claims["aud"]
            authorized_party = token.claims.get("azp")
            if isinstance(audience, str):
                audiences = (audience,)
            elif (
                isinstance(audience, list)
                and 1 <= len(audience) <= 8
                and all(isinstance(value, str) for value in audience)
                and len(audience) == len(set(audience))
            ):
                audiences = tuple(audience)
            else:
                raise ValueError
            if (
                not isinstance(subject, str)
                or not isinstance(display_name, str)
                or not isinstance(raw_groups, list)
                or not all(isinstance(group, str) for group in raw_groups)
                or not isinstance(acr, str)
                or not isinstance(amr, list)
                or not all(isinstance(method, str) for method in amr)
                or acr not in self._accepted_mfa_acr
                or len(amr) != len(set(amr))
                or frozenset(amr) != self._required_mfa_amr
                or self._client_id not in audiences
                or (len(audiences) > 1 and authorized_party != self._client_id)
                or (
                    len(audiences) == 1
                    and authorized_party is not None
                    and authorized_party != self._client_id
                )
            ):
                raise ValueError
            groups = frozenset(group for group in raw_groups if group in self._group_roles)
            roles = frozenset(role for group in groups for role in self._group_roles[group])
            if not groups or not roles:
                raise ValueError
            return OidcIdentity(
                subject=subject,
                display_name=display_name,
                groups=groups,
                roles=roles,
                mfa_verified=True,
            )
        except Exception:
            raise OidcLoginInvalid("oidc_id_token_invalid") from None


@dataclass(frozen=True, slots=True)
class OidcProvider:
    issuer: str
    client_id: str
    authorization_endpoint: str
    token_endpoint: str
    redirect_uri: str

    def __post_init__(self) -> None:
        if (
            not self.issuer.startswith("https://")
            or not self.authorization_endpoint.startswith(self.issuer + "/")
            or not self.token_endpoint.startswith(self.issuer + "/")
            or not self.redirect_uri.startswith("https://")
            or not 1 <= len(self.client_id) <= 256
        ):
            raise ValueError("oidc_provider_invalid")


@dataclass(frozen=True, slots=True)
class OidcFlow:
    state_sha256: str
    browser_sha256: str
    source_ip_sha256: str
    return_to: str
    created_at: datetime
    expires_at: datetime
    consumed_at: datetime | None = None

    def __post_init__(self) -> None:
        if (
            len(self.state_sha256) != 64
            or len(self.browser_sha256) != 64
            or len(self.source_ip_sha256) != 64
            or not self.return_to.startswith("/")
            or self.return_to.startswith("//")
            or self.created_at.tzinfo is None
            or self.expires_at <= self.created_at
        ):
            raise ValueError("oidc_flow_invalid")


class InMemoryOidcFlowStore:
    def __init__(
        self,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._clock = clock
        self._flows: dict[str, OidcFlow] = {}
        self._rejected_source_digests: list[str] = []
        self._lock = RLock()

    def create(
        self,
        *,
        state_sha256: str,
        browser_sha256: str,
        source_ip_sha256: str,
        return_to: str,
        lifetime: timedelta,
    ) -> OidcFlow:
        with self._lock:
            if state_sha256 in self._flows:
                raise OidcLoginInvalid("oidc_flow_conflict")
            now = self._clock()
            flow = OidcFlow(
                state_sha256=state_sha256,
                browser_sha256=browser_sha256,
                source_ip_sha256=source_ip_sha256,
                return_to=return_to,
                created_at=now,
                expires_at=now + lifetime,
            )
            self._flows[state_sha256] = flow
            return flow

    def flows(self) -> tuple[OidcFlow, ...]:
        with self._lock:
            return tuple(self._flows.values())

    def consume(self, state_sha256: str, *, browser_sha256: str) -> OidcFlow:
        with self._lock:
            current = self._flows.get(state_sha256)
            now = self._clock()
            if (
                current is None
                or not hmac.compare_digest(current.browser_sha256, browser_sha256)
                or current.consumed_at is not None
                or now.tzinfo is None
                or now >= current.expires_at
            ):
                raise OidcLoginInvalid("oidc_flow_invalid")
            consumed = replace(current, consumed_at=now)
            self._flows[state_sha256] = consumed
            return consumed

    def record_rejection(self, *, source_ip_sha256: str) -> None:
        with self._lock:
            self._rejected_source_digests.append(source_ip_sha256)

    def assert_identity_allowed(self, *, identity_sha256: str) -> None:
        del identity_sha256

    def record_identity_rejection(self, *, identity_sha256: str) -> None:
        del identity_sha256

    def record_success(
        self,
        *,
        source_ip_sha256: str,
        identity_sha256: str,
    ) -> None:
        del source_ip_sha256, identity_sha256

    def rejection_count(self) -> int:
        with self._lock:
            return len(self._rejected_source_digests)


class PostgresOidcFlowStore:
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
                connection.execute(text("SELECT state_sha256 FROM oidc_login_flows LIMIT 0"))
                connection.execute(text("SELECT key_sha256 FROM operator_login_attempts LIMIT 0"))
                connection.execute(text("SELECT id FROM operator_security_alerts LIMIT 0"))
        except SQLAlchemyError:
            raise OidcLoginUnavailable("oidc_flow_store_unavailable") from None

    def create(
        self,
        *,
        state_sha256: str,
        browser_sha256: str,
        source_ip_sha256: str,
        return_to: str,
        lifetime: timedelta,
    ) -> OidcFlow:
        try:
            with self._engine.begin() as connection:
                connection.execute(text("SET LOCAL synchronous_commit = on"))
                connection.execute(
                    text("SELECT pg_advisory_xact_lock(hashtextextended(:source, 91371))"),
                    {"source": source_ip_sha256},
                )
                connection.execute(text("SELECT pg_advisory_xact_lock(91372)"))
                connection.execute(
                    text(
                        "DELETE FROM oidc_login_flows WHERE "
                        "expires_at <= clock_timestamp() OR "
                        "consumed_at < clock_timestamp() - interval '15 minutes'"
                    )
                )
                counts = connection.execute(
                    text(
                        "SELECT count(*) AS total, count(*) FILTER "
                        "(WHERE source_ip_sha256 = :source) AS source_total "
                        "FROM oidc_login_flows WHERE consumed_at IS NULL "
                        "AND expires_at > clock_timestamp()"
                    ),
                    {"source": source_ip_sha256},
                ).one()
                if counts.total >= 1024 or counts.source_total >= 10:
                    raise OidcLoginRateLimited()
                row = (
                    connection.execute(
                        text(
                            "INSERT INTO oidc_login_flows "
                            "(state_sha256, browser_sha256, source_ip_sha256, "
                            "return_to, created_at, expires_at) VALUES "
                            "(:state_sha256, :browser_sha256, :source_ip_sha256, :return_to, "
                            "clock_timestamp(), "
                            "clock_timestamp() + :lifetime) RETURNING *"
                        ),
                        {
                            "state_sha256": state_sha256,
                            "browser_sha256": browser_sha256,
                            "source_ip_sha256": source_ip_sha256,
                            "return_to": return_to,
                            "lifetime": lifetime,
                        },
                    )
                    .mappings()
                    .one()
                )
        except OidcLoginRateLimited:
            raise
        except SQLAlchemyError:
            raise OidcLoginUnavailable("oidc_flow_store_unavailable") from None
        return _flow_from_row(row)

    def consume(self, state_sha256: str, *, browser_sha256: str) -> OidcFlow:
        try:
            with self._engine.begin() as connection:
                connection.execute(text("SET LOCAL synchronous_commit = on"))
                current = (
                    connection.execute(
                        text(
                            "SELECT * FROM oidc_login_flows "
                            "WHERE state_sha256 = :state_sha256 FOR UPDATE"
                        ),
                        {"state_sha256": state_sha256},
                    )
                    .mappings()
                    .one_or_none()
                )
                if current is None:
                    raise OidcLoginInvalid("oidc_flow_invalid")
                source_key = _oidc_source_attempt_key(str(current["source_ip_sha256"]))
                _lock_attempt_keys(connection, (source_key,))
                if connection.scalar(
                    text(
                        "SELECT EXISTS (SELECT 1 FROM operator_login_attempts "
                        "WHERE key_sha256 = :key AND locked_until > clock_timestamp())"
                    ),
                    {"key": source_key},
                ):
                    raise OidcLoginRateLimited()
                row = (
                    connection.execute(
                        text(
                            "UPDATE oidc_login_flows SET consumed_at = clock_timestamp() "
                            "WHERE state_sha256 = :state_sha256 AND consumed_at IS NULL "
                            "AND browser_sha256 = :browser_sha256 "
                            "AND clock_timestamp() < expires_at RETURNING *"
                        ),
                        {
                            "state_sha256": state_sha256,
                            "browser_sha256": browser_sha256,
                        },
                    )
                    .mappings()
                    .one_or_none()
                )
        except (OidcLoginInvalid, OidcLoginRateLimited):
            raise
        except SQLAlchemyError:
            raise OidcLoginUnavailable("oidc_flow_store_unavailable") from None
        if row is None:
            raise OidcLoginInvalid("oidc_flow_invalid")
        return _flow_from_row(row)

    def record_rejection(self, *, source_ip_sha256: str) -> None:
        try:
            with self._engine.begin() as connection:
                connection.execute(text("SET LOCAL synchronous_commit = on"))
                key = _oidc_source_attempt_key(source_ip_sha256)
                _lock_attempt_keys(connection, (key,))
                if connection.scalar(
                    text(
                        "SELECT EXISTS (SELECT 1 FROM operator_login_attempts "
                        "WHERE key_sha256 = :key AND locked_until > clock_timestamp())"
                    ),
                    {"key": key},
                ):
                    raise OidcLoginRateLimited()
                connection.execute(
                    text(
                        "INSERT INTO operator_login_audit "
                        "(id, auth_method, outcome, reason_code, source_ip_sha256) "
                        "VALUES (:id, 'oidc_code_pkce', 'rejected', "
                        "'operator_login_failed', :source)"
                    ),
                    {"id": uuid4(), "source": source_ip_sha256},
                )
                _record_progressive_failure(connection, key_sha256=key)
        except OidcLoginRateLimited:
            raise
        except SQLAlchemyError:
            raise OidcLoginUnavailable("oidc_login_audit_unavailable") from None

    def assert_identity_allowed(self, *, identity_sha256: str) -> None:
        key = _oidc_identity_attempt_key(identity_sha256)
        try:
            with self._engine.begin() as connection:
                _lock_attempt_keys(connection, (key,))
                if connection.scalar(
                    text(
                        "SELECT EXISTS (SELECT 1 FROM operator_login_attempts "
                        "WHERE key_sha256 = :key AND locked_until > clock_timestamp())"
                    ),
                    {"key": key},
                ):
                    raise OidcLoginRateLimited()
        except OidcLoginRateLimited:
            raise
        except SQLAlchemyError:
            raise OidcLoginUnavailable("oidc_login_attempt_store_unavailable") from None

    def record_identity_rejection(self, *, identity_sha256: str) -> None:
        key = _oidc_identity_attempt_key(identity_sha256)
        try:
            with self._engine.begin() as connection:
                connection.execute(text("SET LOCAL synchronous_commit = on"))
                _lock_attempt_keys(connection, (key,))
                _record_progressive_failure(connection, key_sha256=key)
        except SQLAlchemyError:
            raise OidcLoginUnavailable("oidc_login_attempt_store_unavailable") from None

    def record_success(
        self,
        *,
        source_ip_sha256: str,
        identity_sha256: str,
    ) -> None:
        try:
            with self._engine.begin() as connection:
                connection.execute(text("SET LOCAL synchronous_commit = on"))
                keys = (
                    _oidc_source_attempt_key(source_ip_sha256),
                    _oidc_identity_attempt_key(identity_sha256),
                )
                _lock_attempt_keys(connection, keys)
                connection.execute(
                    text("DELETE FROM operator_login_attempts WHERE key_sha256 = ANY(:keys)"),
                    {"keys": list(keys)},
                )
        except SQLAlchemyError:
            raise OidcLoginUnavailable("oidc_login_attempt_store_unavailable") from None


class PostgresOidcAccountResolver:
    """Provision an explicitly mapped OIDC subject and reject role drift."""

    def __init__(
        self,
        database_url: str,
        *,
        issuer: str,
        statement_timeout_ms: int = 1000,
    ) -> None:
        if not issuer.startswith("https://") or not 100 <= statement_timeout_ms <= 5000:
            raise ValueError("database_statement_timeout_invalid")
        self._issuer = issuer
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

    def resolve(self, identity: OidcIdentity) -> UUID | None:
        canonical_subject = (
            "oidc:"
            + hashlib.sha256((self._issuer + "\0" + identity.subject).encode("utf-8")).hexdigest()
        )
        try:
            with self._engine.begin() as connection:
                connection.execute(text("SET LOCAL synchronous_commit = on"))
                row = (
                    connection.execute(
                        text(
                            "SELECT id, display_name, roles, enabled FROM operator_accounts "
                            "WHERE identity_source = 'oidc' AND subject = :subject FOR UPDATE"
                        ),
                        {"subject": canonical_subject},
                    )
                    .mappings()
                    .one_or_none()
                )
                if row is None:
                    if connection.scalar(
                        text(
                            "SELECT EXISTS (SELECT 1 FROM operator_accounts "
                            "WHERE identity_source = 'oidc' "
                            "AND subject !~ '^oidc:[0-9a-f]{64}$')"
                        )
                    ):
                        raise OidcLoginInvalid("oidc_account_mapping_required")
                    account_id = uuid4()
                    inserted = connection.execute(
                        text(
                            "INSERT INTO operator_accounts "
                            "(id, identity_source, subject, display_name, roles, scopes, "
                            "authz_version, enabled) VALUES "
                            "(:id, 'oidc', :subject, :display_name, :roles, "
                            "ARRAY['server:*']::varchar[], 1, true) "
                            "ON CONFLICT (identity_source, subject) DO NOTHING RETURNING id"
                        ),
                        {
                            "id": account_id,
                            "subject": canonical_subject,
                            "display_name": identity.display_name,
                            "roles": sorted(role.value for role in identity.roles),
                        },
                    ).one_or_none()
                    if inserted is None:
                        raise OidcLoginInvalid("oidc_account_conflict")
                    _record_oidc_account_event(
                        connection,
                        account_id=account_id,
                        subject=canonical_subject,
                    )
                    return account_id
                roles = frozenset(OperatorRole(value) for value in row["roles"])
                if not row["enabled"] or roles != identity.roles:
                    raise OidcLoginInvalid("oidc_account_unavailable")
                account_id = UUID(str(row["id"]))
                if row["display_name"] != identity.display_name:
                    connection.execute(
                        text(
                            "UPDATE operator_accounts SET display_name = :display_name, "
                            "updated_at = clock_timestamp() WHERE id = :id"
                        ),
                        {"id": account_id, "display_name": identity.display_name},
                    )
                return account_id
        except OidcLoginInvalid:
            raise
        except SQLAlchemyError:
            raise OidcLoginUnavailable("oidc_account_store_unavailable") from None


@dataclass(frozen=True, slots=True)
class OidcLoginRedirect:
    location: str
    browser_token: str


@dataclass(frozen=True, slots=True)
class CompletedOidcLogin:
    return_to: str
    session: IssuedOperatorSession


class OidcLoginControl:
    def __init__(
        self,
        *,
        provider: OidcProvider,
        flows: OidcFlowStore,
        derivation_key: bytes,
        state_factory: Callable[[], str],
        token_endpoint: OidcTokenEndpoint | None = None,
        claims_verifier: OidcClaimsVerifier | None = None,
        account_resolver: Callable[[OidcIdentity], UUID | None] | None = None,
        sessions: OperatorSessionControl | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        flow_lifetime: timedelta = timedelta(minutes=5),
    ) -> None:
        if len(derivation_key) < 32 or not timedelta(0) < flow_lifetime <= timedelta(minutes=10):
            raise ValueError("oidc_flow_configuration_invalid")
        self._provider = provider
        self._flows = flows
        self._derivation_key = derivation_key
        self._state_factory = state_factory
        self._token_endpoint = token_endpoint
        self._claims_verifier = claims_verifier
        self._account_resolver = account_resolver
        self._sessions = sessions
        self._clock = clock
        self._flow_lifetime = flow_lifetime
        self._callback_admission = BoundedSemaphore(8)

    def begin(
        self,
        *,
        return_to: str = "/",
        source_ip: str = "127.0.0.1",
    ) -> OidcLoginRedirect:
        state = self._state_factory()
        browser_token = self._state_factory()
        if len(state) < 43 or len(state) > 256 or any(character.isspace() for character in state):
            raise OidcLoginInvalid("oidc_state_invalid")
        created_at = self._clock()
        if created_at.tzinfo is None:
            raise OidcLoginInvalid("oidc_clock_invalid")
        nonce = _derive(self._derivation_key, "nonce", state)
        verifier = _derive(self._derivation_key, "pkce", state)
        challenge = _base64url(hashlib.sha256(verifier.encode("ascii")).digest())
        self._flows.create(
            state_sha256=hashlib.sha256(state.encode("ascii")).hexdigest(),
            browser_sha256=hashlib.sha256(browser_token.encode("ascii")).hexdigest(),
            source_ip_sha256=hashlib.sha256(source_ip.encode("utf-8")).hexdigest(),
            return_to=return_to,
            lifetime=self._flow_lifetime,
        )
        query = urlencode(
            {
                "client_id": self._provider.client_id,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "nonce": nonce,
                "redirect_uri": self._provider.redirect_uri,
                "response_type": "code",
                "scope": "openid profile email",
                "state": state,
            }
        )
        return OidcLoginRedirect(
            location=f"{self._provider.authorization_endpoint}?{query}",
            browser_token=browser_token,
        )

    def complete(
        self,
        *,
        state: str,
        code: str,
        browser_token: str,
        audit_context: OperatorRequestAuditContext | None = None,
    ) -> CompletedOidcLogin:
        if not self._callback_admission.acquire(blocking=False):
            raise OidcLoginRateLimited(1)
        try:
            if (
                len(state) < 43
                or len(state) > 256
                or not 1 <= len(code) <= 2048
                or not 43 <= len(browser_token) <= 256
                or any(character.isspace() for character in state)
                or any(character.isspace() for character in browser_token)
                or self._token_endpoint is None
                or self._claims_verifier is None
                or self._account_resolver is None
                or self._sessions is None
            ):
                raise OidcLoginInvalid("oidc_callback_invalid")
            try:
                state_digest = hashlib.sha256(state.encode("ascii")).hexdigest()
                browser_digest = hashlib.sha256(browser_token.encode("ascii")).hexdigest()
            except UnicodeEncodeError:
                raise OidcLoginInvalid("oidc_callback_invalid") from None
            flow = self._flows.consume(
                state_digest,
                browser_sha256=browser_digest,
            )
            verifier = _derive(self._derivation_key, "pkce", state)
            nonce = _derive(self._derivation_key, "nonce", state)
            id_token = self._token_endpoint.exchange(
                code=code,
                code_verifier=verifier,
            )
            identity = self._claims_verifier.verify(
                id_token=id_token,
                nonce=nonce,
            )
            if not identity.mfa_verified:
                raise OidcLoginInvalid("oidc_mfa_required")
            identity_digest = hashlib.sha256(
                (self._provider.issuer + "\0" + identity.subject).encode("utf-8")
            ).hexdigest()
            self._flows.assert_identity_allowed(identity_sha256=identity_digest)
            try:
                account_id = self._account_resolver(identity)
            except OidcLoginInvalid:
                self._flows.record_identity_rejection(identity_sha256=identity_digest)
                raise
            if account_id is None:
                self._flows.record_identity_rejection(identity_sha256=identity_digest)
                raise OidcLoginInvalid("oidc_account_unavailable")
            self._flows.record_success(
                source_ip_sha256=flow.source_ip_sha256,
                identity_sha256=identity_digest,
            )
            session = self._sessions.issue(
                account_id=account_id,
                mfa_verified=True,
                audit_context=audit_context,
            )
        except OidcLoginInvalid:
            raise
        except OidcLoginUnavailable:
            raise
        except Exception as error:
            from rtsp_proxy.operator_access import OperatorSessionUnavailable

            if isinstance(error, OperatorSessionUnavailable):
                raise OidcLoginUnavailable("operator_session_store_unavailable") from None
            raise OidcLoginInvalid("oidc_callback_failed") from None
        finally:
            self._callback_admission.release()
        return CompletedOidcLogin(return_to=flow.return_to, session=session)

    def record_rejection(self, *, source_ip: str) -> None:
        if not source_ip or len(source_ip) > 128:
            source_ip = "unknown"
        self._flows.record_rejection(
            source_ip_sha256=hashlib.sha256(source_ip.encode()).hexdigest()
        )


def _derive(key: bytes, label: str, state: str) -> str:
    return _base64url(hmac.digest(key, f"{label}:{state}".encode("ascii"), "sha256"))


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _flow_from_row(row: RowMapping) -> OidcFlow:
    return OidcFlow(
        state_sha256=str(row["state_sha256"]),
        browser_sha256=str(row["browser_sha256"]),
        source_ip_sha256=str(row["source_ip_sha256"]),
        return_to=str(row["return_to"]),
        created_at=row["created_at"],
        expires_at=row["expires_at"],
        consumed_at=row["consumed_at"],
    )


def _record_break_glass_event(
    connection: Connection,
    *,
    account_id: UUID,
    authz_version: int,
    outcome: str,
    reason_code: str,
) -> None:
    payload = json.dumps(
        {
            "account_id": str(account_id),
            "auth_method": "break_glass_password_totp",
            "outcome": outcome,
            "reason_code": reason_code,
            "severity": "critical",
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
    audit_statement = text(
        "INSERT INTO audit_events "
        "(id, aggregate_type, aggregate_id, event_type, aggregate_revision, payload) "
        "VALUES (:id, 'operator_account', :aggregate_id, "
        "'operator.break_glass_login', :aggregate_revision, CAST(:payload AS jsonb))"
    )
    outbox_statement = text(
        "INSERT INTO outbox_messages "
        "(id, aggregate_type, aggregate_id, event_type, aggregate_revision, payload) "
        "VALUES (:id, 'operator_account', :aggregate_id, "
        "'operator.break_glass_login', :aggregate_revision, CAST(:payload AS jsonb))"
    )
    connection.execute(audit_statement, parameters)
    connection.execute(outbox_statement, parameters)
    connection.execute(
        text(
            "INSERT INTO operator_security_alerts "
            "(id, account_id, event_type, outcome, reason_code, status, "
            "attempts, available_at) VALUES "
            "(:id, :account_id, 'operator.break_glass_login', :outcome, "
            ":reason_code, 'pending', 0, clock_timestamp())"
        ),
        {
            "id": uuid4(),
            "account_id": account_id,
            "outcome": outcome,
            "reason_code": reason_code,
        },
    )


def _record_local_password_change_event(
    connection: Connection,
    *,
    account_id: UUID,
    authz_version: int,
    revoked_sessions: int,
    context: OperatorRequestAuditContext,
) -> None:
    payload = json.dumps(
        {
            "account_id": str(account_id),
            "action": "operator.password_change",
            "outcome": "changed",
            "revoked_sessions": revoked_sessions,
            "request_id": str(context.request_id),
            "source_ip_sha256": context.source_ip_sha256,
            "user_agent_sha256": context.user_agent_sha256,
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
                "'operator.password_changed', :aggregate_revision, CAST(:payload AS jsonb))"
            ),
            parameters,
        )


def _record_break_glass_provision_event(
    connection: Connection,
    *,
    account_id: UUID,
    authz_version: int,
    before_authz_version: int | None,
    before_enabled: bool | None,
    before_display_name: str | None,
    before_roles: list[str] | None,
    before_scopes: list[str] | None,
    after_display_name: str,
    after_roles: list[str],
    after_scopes: list[str],
    context: OperatorMutationContext,
) -> None:
    payload = json.dumps(
        {
            "account_id": str(account_id),
            "identity_source": "break_glass",
            "actor": context.actor,
            "auth_method": "privileged_local_cli",
            "action": "operator.break_glass_provision",
            "object_type": "operator_account",
            "outcome": "provisioned",
            "reason": context.reason,
            "effective_roles": after_roles,
            "effective_scopes": after_scopes,
            "before": {
                "display_name": before_display_name,
                "roles": before_roles,
                "scopes": before_scopes,
                "authz_version": before_authz_version,
                "enabled": before_enabled,
            },
            "after": {
                "display_name": after_display_name,
                "roles": after_roles,
                "scopes": after_scopes,
                "authz_version": authz_version,
                "enabled": True,
            },
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
                "'operator.break_glass_provisioned', :aggregate_revision, "
                "CAST(:payload AS jsonb))"
            ),
            parameters,
        )


def _record_break_glass_rotation_event(
    connection: Connection,
    *,
    account_id: UUID,
    before_authz_version: int,
    after_authz_version: int,
    revoked_sessions: int,
    context: OperatorMutationContext,
) -> None:
    payload = json.dumps(
        {
            "account_id": str(account_id),
            "identity_source": "break_glass",
            "actor": context.actor,
            "auth_method": "privileged_local_cli",
            "action": "operator.break_glass_rotate",
            "object_type": "operator_account",
            "outcome": "rotated",
            "reason": context.reason,
            "before": {
                "authz_version": before_authz_version,
                "enabled": True,
            },
            "after": {
                "authz_version": after_authz_version,
                "enabled": True,
            },
            "revoked_sessions": revoked_sessions,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    event_id = uuid4()
    parameters = {
        "id": event_id,
        "aggregate_id": account_id,
        "aggregate_revision": after_authz_version,
        "payload": payload,
    }
    for table in ("audit_events", "outbox_messages"):
        connection.execute(
            text(
                f"INSERT INTO {table} "
                "(id, aggregate_type, aggregate_id, event_type, aggregate_revision, payload) "
                "VALUES (:id, 'operator_account', :aggregate_id, "
                "'operator.break_glass_rotated', :aggregate_revision, CAST(:payload AS jsonb))"
            ),
            parameters,
        )


def _record_break_glass_rotation_rejection_event(
    connection: Connection,
    *,
    account_id: UUID,
    requested_account_id: UUID,
    aggregate_revision: int,
    expected_authz_version: int,
    context: OperatorMutationContext,
) -> None:
    payload = json.dumps(
        {
            "account_id": str(account_id),
            "requested_account_id": str(requested_account_id),
            "identity_source": "break_glass",
            "actor": context.actor,
            "auth_method": "privileged_local_cli",
            "action": "operator.break_glass_rotate",
            "object_type": "operator_account",
            "outcome": "rejected",
            "reason": context.reason,
            "reason_code": "identity_or_revision_conflict",
            "expected_authz_version": expected_authz_version,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    event_id = uuid4()
    parameters = {
        "id": event_id,
        "aggregate_id": account_id,
        "aggregate_revision": aggregate_revision,
        "payload": payload,
    }
    for table in ("audit_events", "outbox_messages"):
        connection.execute(
            text(
                f"INSERT INTO {table} "
                "(id, aggregate_type, aggregate_id, event_type, aggregate_revision, payload) "
                "VALUES (:id, 'operator_account', :aggregate_id, "
                "'operator.break_glass_rotation_rejected', :aggregate_revision, "
                "CAST(:payload AS jsonb))"
            ),
            parameters,
        )


def _attempt_digest(*, source_ip: str, username: str) -> str:
    if not source_ip or len(source_ip) > 128 or not username or len(username) > 256:
        raise OidcLoginInvalid("break_glass_login_failed")
    return hashlib.sha256((source_ip + "\0" + username.casefold()).encode()).hexdigest()


def _local_attempt_keys(*, source_ip: str, username: str) -> tuple[str, str]:
    if not source_ip or len(source_ip) > 128 or not username or len(username) > 256:
        raise OidcLoginInvalid("local_operator_login_failed")
    return (
        hashlib.sha256(("local-ip\0" + source_ip).encode()).hexdigest(),
        hashlib.sha256(
            ("local-pair\0" + source_ip + "\0" + username).encode("utf-8")
        ).hexdigest(),
    )


def _local_attempt_is_locked(
    connection: Connection,
    *,
    source_ip: str,
    username: str,
) -> bool:
    keys = _local_attempt_keys(source_ip=source_ip, username=username)
    _lock_attempt_keys(connection, keys)
    connection.execute(
        text(
            "DELETE FROM operator_login_attempts "
            "WHERE last_attempt_at < clock_timestamp() - interval '24 hours'"
        )
    )
    return bool(
        connection.scalar(
            text(
                "SELECT EXISTS (SELECT 1 FROM operator_login_attempts "
                "WHERE key_sha256 = ANY(:keys) AND locked_until > clock_timestamp())"
            ),
            {"keys": list(keys)},
        )
    )


def _record_local_failure(
    connection: Connection,
    *,
    source_ip: str,
    username: str,
) -> bool:
    rate_limited = False
    for key_sha256 in _local_attempt_keys(source_ip=source_ip, username=username):
        row = _record_progressive_failure(connection, key_sha256=key_sha256)
        rate_limited = rate_limited or bool(
            row["locked_until"] is not None and row["failure_count"] >= 5
        )
    return rate_limited


def _clear_local_attempts(
    connection: Connection,
    *,
    source_ip: str,
    username: str,
) -> None:
    connection.execute(
        text("DELETE FROM operator_login_attempts WHERE key_sha256 = ANY(:keys)"),
        {"keys": list(_local_attempt_keys(source_ip=source_ip, username=username))},
    )


def _record_local_login_attempt(
    connection: Connection,
    *,
    source_ip: str,
    outcome: str,
    reason_code: str,
) -> None:
    connection.execute(
        text(
            "INSERT INTO operator_login_audit "
            "(id, auth_method, outcome, reason_code, source_ip_sha256) VALUES "
            "(:id, 'local_password', :outcome, :reason_code, :source_ip_sha256)"
        ),
        {
            "id": uuid4(),
            "outcome": outcome,
            "reason_code": reason_code,
            "source_ip_sha256": hashlib.sha256(source_ip.encode("utf-8")).hexdigest(),
        },
    )


def _record_local_account_event(
    connection: Connection,
    *,
    account: OperatorAccount,
    username: str,
    context: OperatorMutationContext,
) -> None:
    payload = json.dumps(
        {
            "account_id": str(account.id),
            "action": "operator.local_account_provision",
            "actor": context.actor,
            "display_name": account.display_name,
            "identity_source": "local",
            "outcome": "completed",
            "reason": context.reason,
            "roles": sorted(role.value for role in account.roles),
            "scopes": sorted(account.scopes),
            "username_sha256": hashlib.sha256(username.encode("utf-8")).hexdigest(),
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    event_id = uuid4()
    parameters = {
        "id": event_id,
        "aggregate_id": account.id,
        "payload": payload,
    }
    for table in ("audit_events", "outbox_messages"):
        connection.execute(
            text(
                f"INSERT INTO {table} "
                "(id, aggregate_type, aggregate_id, event_type, aggregate_revision, payload) "
                "VALUES (:id, 'operator_account', :aggregate_id, "
                "'operator.local_account_provisioned', 1, CAST(:payload AS jsonb))"
            ),
            parameters,
        )


def _attempt_keys(*, source_ip: str, username: str) -> tuple[str, str]:
    _attempt_digest(source_ip=source_ip, username=username)
    return (
        _break_glass_source_attempt_key(source_ip),
        hashlib.sha256(("pair\0" + source_ip + "\0" + username.casefold()).encode()).hexdigest(),
    )


def _break_glass_source_attempt_key(source_ip: str) -> str:
    return hashlib.sha256(("break-glass-ip\0" + source_ip).encode()).hexdigest()


def _oidc_source_attempt_key(source_ip_sha256: str) -> str:
    if len(source_ip_sha256) != 64:
        raise OidcLoginInvalid("oidc_flow_invalid")
    return hashlib.sha256(("oidc-ip\0" + source_ip_sha256).encode()).hexdigest()


def _oidc_identity_attempt_key(identity_sha256: str) -> str:
    if len(identity_sha256) != 64:
        raise OidcLoginInvalid("oidc_identity_invalid")
    return hashlib.sha256(("oidc-account\0" + identity_sha256).encode()).hexdigest()


def _lock_attempt_keys(
    connection: Connection,
    keys: tuple[str, ...],
) -> None:
    for key in sorted(keys):
        connection.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 91373))"),
            {"key": key},
        )


def _break_glass_attempt_is_locked(
    connection: Connection,
    *,
    source_ip: str,
    username: str,
) -> bool:
    keys = _attempt_keys(source_ip=source_ip, username=username)
    _lock_attempt_keys(connection, keys)
    connection.execute(
        text(
            "DELETE FROM operator_login_attempts "
            "WHERE last_attempt_at < clock_timestamp() - interval '24 hours'"
        )
    )
    return bool(
        connection.scalar(
            text(
                "SELECT EXISTS (SELECT 1 FROM operator_login_attempts "
                "WHERE key_sha256 = ANY(:keys) AND locked_until > clock_timestamp())"
            ),
            {"keys": list(keys)},
        )
    )


def _record_break_glass_failure(
    connection: Connection,
    *,
    source_ip: str,
    username: str,
) -> bool:
    keys = _attempt_keys(source_ip=source_ip, username=username)
    rate_limited = False
    for key_sha256 in keys:
        row = _record_progressive_failure(connection, key_sha256=key_sha256)
        rate_limited = rate_limited or bool(
            row["locked_until"] is not None and row["failure_count"] >= 5
        )
    return rate_limited


def _record_progressive_failure(
    connection: Connection,
    *,
    key_sha256: str,
) -> RowMapping:
    return (
        connection.execute(
            text(
                "INSERT INTO operator_login_attempts "
                "(key_sha256, failure_count, first_attempt_at, last_attempt_at, "
                "locked_until) VALUES "
                "(:key, 1, clock_timestamp(), clock_timestamp(), NULL) "
                "ON CONFLICT (key_sha256) DO UPDATE SET "
                "failure_count = CASE WHEN operator_login_attempts.last_attempt_at < "
                "clock_timestamp() - interval '15 minutes' THEN 1 "
                "ELSE operator_login_attempts.failure_count + 1 END, "
                "first_attempt_at = CASE WHEN operator_login_attempts.last_attempt_at < "
                "clock_timestamp() - interval '15 minutes' THEN clock_timestamp() "
                "ELSE operator_login_attempts.first_attempt_at END, "
                "last_attempt_at = clock_timestamp(), "
                "locked_until = CASE "
                "WHEN operator_login_attempts.locked_until > clock_timestamp() "
                "THEN operator_login_attempts.locked_until "
                "WHEN operator_login_attempts.failure_count + 1 >= 5 "
                "THEN clock_timestamp() + interval '15 minutes' ELSE NULL END "
                "RETURNING failure_count, locked_until"
            ),
            {"key": key_sha256},
        )
        .mappings()
        .one()
    )


def _clear_break_glass_attempts(
    connection: Connection,
    *,
    source_ip: str,
    username: str,
) -> None:
    connection.execute(
        text("DELETE FROM operator_login_attempts WHERE key_sha256 = ANY(:keys)"),
        {"keys": list(_attempt_keys(source_ip=source_ip, username=username))},
    )


def _record_oidc_account_event(
    connection: Connection,
    *,
    account_id: UUID,
    subject: str,
) -> None:
    payload = json.dumps(
        {
            "account_id": str(account_id),
            "identity_source": "oidc",
            "outcome": "provisioned",
            "subject_sha256": hashlib.sha256(subject.encode("utf-8")).hexdigest(),
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    event_id = uuid4()
    parameters = {
        "id": event_id,
        "aggregate_id": account_id,
        "payload": payload,
    }
    for table in ("audit_events", "outbox_messages"):
        connection.execute(
            text(
                f"INSERT INTO {table} "
                "(id, aggregate_type, aggregate_id, event_type, aggregate_revision, payload) "
                "VALUES (:id, 'operator_account', :aggregate_id, "
                "'operator.oidc_account_provisioned', 1, CAST(:payload AS jsonb))"
            ),
            parameters,
        )


def read_operator_secret_file(
    path: Path,
    *,
    trusted_owner_uid: int = 0,
    maximum_bytes: int = 65_536,
) -> bytes:
    """Read a private or systemd-provided secret without following links."""

    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
        file_stat = os.fstat(descriptor)
        mode = stat.S_IMODE(file_stat.st_mode)
        private_mode = mode in {0o400, 0o600}
        systemd_credential_mode = (
            mode == 0o440 and file_stat.st_uid == 0 and file_stat.st_gid == 0
        )
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or file_stat.st_uid != trusted_owner_uid
            or file_stat.st_nlink != 1
            or not (private_mode or systemd_credential_mode)
        ):
            raise ValueError
        payload = os.read(descriptor, maximum_bytes + 1)
        if not payload or len(payload) > maximum_bytes:
            raise ValueError
        return payload
    except (OSError, ValueError):
        raise ValueError("operator_auth_file_unsafe") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
