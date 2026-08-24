from __future__ import annotations

import base64
import grp
import hashlib
import hmac
import json
import os
import secrets
import stat
import threading
import time
from collections import Counter, OrderedDict, deque
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    collapse_addresses,
    ip_address,
    ip_network,
)
from typing import Protocol
from uuid import UUID

from rtsp_proxy.identifiers import PublicId
from rtsp_proxy.nodes import NodeMutationContext

MAX_ACCESS_POLICY_CIDRS = 128
MIN_GRANT_LIFETIME = timedelta(seconds=1)
MAX_GRANT_LIFETIME = timedelta(days=366)
MAX_ROTATION_OVERLAP = timedelta(hours=24)
MAX_ACCESS_PEPPER_KEYS = 2


class AccessPepperFileError(ValueError):
    """The shared callback/grant pepper file violates its Linux boundary."""


class AccessGrantIssueReplayed(RuntimeError):
    """A secret-bearing issue/rotate request was already committed."""


class AccessGrantIdempotencyConflict(RuntimeError):
    """An idempotency key was reused for a different grant request."""


class AccessGrantSchemaUnavailable(RuntimeError):
    """The schema cannot yet persist an authenticated secret-bearing request."""


def canonicalize_cidrs(values: Sequence[str]) -> tuple[str, ...]:
    if len(values) > MAX_ACCESS_POLICY_CIDRS:
        raise ValueError("access_policy_cidr_limit")
    networks = []
    try:
        for value in values:
            if not value or "%" in value or value != value.strip():
                raise ValueError
            networks.append(ip_network(value, strict=False))
    except ValueError as error:
        raise ValueError("access_policy_cidr_invalid") from error
    ipv4 = [network for network in networks if isinstance(network, IPv4Network)]
    ipv6 = [network for network in networks if isinstance(network, IPv6Network)]
    collapsed: list[IPv4Network | IPv6Network] = [
        *collapse_addresses(ipv4),
        *collapse_addresses(ipv6),
    ]
    return tuple(str(network) for network in collapsed)


@dataclass(frozen=True, slots=True)
class AccessPolicy:
    camera_id: UUID
    revision: int
    internet_cidrs: tuple[str, ...] = ()
    local_cidrs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.revision < 1:
            raise ValueError("access_policy_revision_invalid")
        object.__setattr__(self, "internet_cidrs", canonicalize_cidrs(self.internet_cidrs))
        object.__setattr__(self, "local_cidrs", canonicalize_cidrs(self.local_cidrs))

    def permits(self, peer_ip: str) -> bool:
        address = _peer_address(peer_ip)
        networks = self.internet_cidrs + self.local_cidrs
        if not networks:
            return True
        return any(address in ip_network(network) for network in networks)


@dataclass(frozen=True, slots=True)
class AccessGrant:
    id: UUID
    camera_id: UUID
    username: str
    token_verifier: str
    pepper_key_id: str
    not_before: datetime
    expires_at: datetime
    revoked_at: datetime | None
    revision: int
    kind: str = "temporary"
    created_by: str = "bootstrap-operator"
    last_used_at: datetime | None = None

    def __post_init__(self) -> None:
        if self.username != f"grant-{self.id.hex}":
            raise ValueError("access_grant_username_invalid")
        if len(self.token_verifier) != 64 or any(
            character not in "0123456789abcdef" for character in self.token_verifier
        ):
            raise ValueError("access_grant_verifier_invalid")
        if not self.pepper_key_id or len(self.pepper_key_id) > 64:
            raise ValueError("access_grant_pepper_key_invalid")
        if self.not_before.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("access_grant_timezone_required")
        if self.not_before >= self.expires_at:
            raise ValueError("access_grant_window_invalid")
        if self.revoked_at is not None and self.revoked_at.tzinfo is None:
            raise ValueError("access_grant_timezone_required")
        if self.revision < 1:
            raise ValueError("access_grant_revision_invalid")
        if self.kind not in {"temporary", "service"}:
            raise ValueError("access_grant_kind_invalid")
        if not self.created_by or len(self.created_by) > 128:
            raise ValueError("access_grant_creator_invalid")
        if self.last_used_at is not None and self.last_used_at.tzinfo is None:
            raise ValueError("access_grant_timezone_required")

    def active_at(self, moment: datetime) -> bool:
        return bool(
            self.not_before <= moment < self.expires_at
            and (self.revoked_at is None or moment < self.revoked_at)
        )


@dataclass(frozen=True, slots=True)
class AccessGrantSummary:
    """Secret-free grant metadata safe for operator lists and confirmations."""

    id: UUID
    camera_id: UUID
    username: str
    not_before: datetime
    expires_at: datetime
    revoked_at: datetime | None
    revision: int
    kind: str
    created_by: str
    last_used_at: datetime | None

    @classmethod
    def from_grant(cls, grant: AccessGrant) -> AccessGrantSummary:
        return cls(
            id=grant.id,
            camera_id=grant.camera_id,
            username=grant.username,
            not_before=grant.not_before,
            expires_at=grant.expires_at,
            revoked_at=grant.revoked_at,
            revision=grant.revision,
            kind=grant.kind,
            created_by=grant.created_by,
            last_used_at=grant.last_used_at,
        )


@dataclass(frozen=True, slots=True)
class AccessGrantPage:
    items: tuple[AccessGrantSummary, ...]
    truncated: bool


@dataclass(frozen=True, slots=True)
class AccessGrantIdempotency:
    key: UUID
    actor_account_id: UUID
    actor_session_id: UUID
    operation: str
    camera_id: UUID
    source_grant_id: UUID | None
    replacement_grant_id: UUID
    request_sha256: str

    def __post_init__(self) -> None:
        if (
            self.key.version != 4
            or self.operation not in {"issue", "rotate"}
            or (self.operation == "issue") != (self.source_grant_id is None)
            or len(self.request_sha256) != 64
            or set(self.request_sha256) - set("0123456789abcdef")
        ):
            raise ValueError("access_grant_idempotency_invalid")


@dataclass(frozen=True, slots=True)
class AccessTarget:
    camera_id: UUID
    node_id: UUID
    public_id: PublicId
    enabled: bool
    policy: AccessPolicy

    def __post_init__(self) -> None:
        if self.policy.camera_id != self.camera_id:
            raise ValueError("access_target_policy_mismatch")


@dataclass(frozen=True, slots=True)
class AuthorizeRequest:
    node_id: UUID
    public_id: PublicId
    peer_ip: str
    username: str
    password: str
    action: str
    protocol: str

    def __post_init__(self) -> None:
        _peer_address(self.peer_ip)
        if len(self.username) > 64 or len(self.password) > 256:
            raise ValueError("access_request_credentials_invalid")


class AccessDecisionReason(StrEnum):
    ALLOWED = "allowed"
    REQUEST_DENIED = "request_denied"
    TARGET_DENIED = "target_denied"
    IP_DENIED = "ip_denied"
    CREDENTIAL_DENIED = "credential_denied"
    GRANT_INACTIVE = "grant_inactive"


@dataclass(frozen=True, slots=True)
class AccessDecision:
    allowed: bool
    reason: AccessDecisionReason
    camera_id: UUID | None = None
    grant_id: UUID | None = None
    last_use_persisted: bool | None = None

    def __post_init__(self) -> None:
        if self.allowed != (self.reason is AccessDecisionReason.ALLOWED):
            raise ValueError("access_decision_invalid")
        if self.allowed and (self.camera_id is None or self.grant_id is None):
            raise ValueError("access_decision_identity_missing")
        if self.allowed != (self.last_use_persisted is not None):
            raise ValueError("access_decision_metadata_invalid")


@dataclass(frozen=True, slots=True)
class AccessDecisionEvent:
    reason: AccessDecisionReason
    allowed: bool
    node_id: UUID
    action: str
    protocol: str
    peer_family: str
    peer_ip: str
    public_id: PublicId
    camera_id: UUID | None
    grant_id: UUID | None
    last_use_persisted: bool | None = None


class AccessDecisionSink(Protocol):
    def record(self, event: AccessDecisionEvent) -> None: ...


@dataclass(frozen=True, slots=True)
class AccessDecisionSnapshot:
    counters: Mapping[tuple[str, bool, str, str, str], int]
    recent_audit: tuple[AccessDecisionEvent, ...]
    dropped_audit: int
    last_use_persistence_failures: int


class AccessDecisionTelemetry:
    """Bounded reason counters plus a bounded, secret-free audit handoff."""

    def __init__(self, *, maximum_audit_events: int = 8192) -> None:
        if maximum_audit_events < 1:
            raise ValueError("access_decision_telemetry_invalid")
        self._maximum_audit_events = maximum_audit_events
        self._counters: Counter[tuple[str, bool, str, str, str]] = Counter()
        self._audit: deque[AccessDecisionEvent] = deque(maxlen=maximum_audit_events)
        self._dropped_audit = 0
        self._last_use_persistence_failures = 0
        self._lock = threading.Lock()

    def record(self, event: AccessDecisionEvent) -> None:
        metric_key = (
            event.reason.value,
            event.allowed,
            event.action,
            event.protocol,
            event.peer_family,
        )
        with self._lock:
            self._counters[metric_key] += 1
            if event.last_use_persisted is False:
                self._last_use_persistence_failures += 1
            if len(self._audit) == self._maximum_audit_events:
                self._dropped_audit += 1
            self._audit.append(event)

    def snapshot(self) -> AccessDecisionSnapshot:
        with self._lock:
            return AccessDecisionSnapshot(
                counters=dict(self._counters),
                recent_audit=tuple(self._audit),
                dropped_audit=self._dropped_audit,
                last_use_persistence_failures=self._last_use_persistence_failures,
            )


class AccessAuthorizerStore(Protocol):
    def get_access_target(
        self,
        *,
        node_id: UUID,
        public_id: PublicId,
    ) -> AccessTarget | None: ...

    def get_access_grant(
        self,
        *,
        camera_id: UUID,
        username: str,
    ) -> AccessGrant | None: ...

    def rehash_access_grant(
        self,
        grant_id: UUID,
        *,
        token_verifier: str,
        pepper_key_id: str,
        expected_revision: int,
    ) -> bool: ...

    def mark_access_grant_used(self, grant_id: UUID) -> bool: ...


class AccessGrantStore(Protocol):
    def check_access_grant_request(self, request: AccessGrantIdempotency) -> None: ...

    def create_access_grant(
        self,
        grant: AccessGrant,
        *,
        mutation_context: NodeMutationContext | None = None,
        idempotency: AccessGrantIdempotency | None = None,
    ) -> AccessGrant: ...

    def get_access_grant_by_id(self, grant_id: UUID) -> AccessGrant | None: ...

    def list_access_grants(
        self,
        camera_id: UUID,
        *,
        limit: int,
    ) -> tuple[AccessGrantSummary, ...]: ...

    def revoke_access_grant(
        self,
        grant_id: UUID,
        *,
        revoked_at: datetime,
        expected_revision: int,
        mutation_context: NodeMutationContext | None = None,
    ) -> AccessGrant: ...

    def rotate_access_grant(
        self,
        grant_id: UUID,
        *,
        replacement: AccessGrant,
        old_expires_at: datetime,
        expected_revision: int,
        mutation_context: NodeMutationContext | None = None,
        idempotency: AccessGrantIdempotency | None = None,
    ) -> tuple[AccessGrant, AccessGrant]: ...


class AccessPolicyStore(Protocol):
    def get_access_policy(self, camera_id: UUID) -> AccessPolicy | None: ...

    def set_access_policy(
        self,
        policy: AccessPolicy,
        *,
        expected_revision: int,
        mutation_context: NodeMutationContext | None = None,
    ) -> AccessPolicy: ...


class AccessPolicyControl:
    def __init__(self, *, store: AccessPolicyStore) -> None:
        self._store = store

    def get(self, camera_id: UUID) -> AccessPolicy:
        policy = self._store.get_access_policy(camera_id)
        if policy is None:
            raise LookupError("access_policy_not_found")
        return policy

    def update(
        self,
        camera_id: UUID,
        *,
        internet_cidrs: Sequence[str],
        local_cidrs: Sequence[str],
        expected_revision: int,
        mutation_context: NodeMutationContext | None = None,
    ) -> AccessPolicy:
        if expected_revision < 1:
            raise ValueError("access_policy_revision_invalid")
        policy = AccessPolicy(
            camera_id=camera_id,
            revision=expected_revision + 1,
            internet_cidrs=tuple(internet_cidrs),
            local_cidrs=tuple(local_cidrs),
        )
        if mutation_context is None:
            return self._store.set_access_policy(
                policy,
                expected_revision=expected_revision,
            )
        return self._store.set_access_policy(
            policy,
            expected_revision=expected_revision,
            mutation_context=mutation_context,
        )


class PepperVerifier:
    def __init__(self, *, primary_key_id: str, keys: Mapping[str, bytes]) -> None:
        copied = dict(keys)
        if (
            not primary_key_id
            or primary_key_id not in copied
            or not 1 <= len(copied) <= MAX_ACCESS_PEPPER_KEYS
            or any(not key_id or len(key_id) > 64 for key_id in copied)
            or any(len(key) < 32 for key in copied.values())
        ):
            raise ValueError("access_pepper_configuration_invalid")
        self._primary_key_id = primary_key_id
        self._keys = copied

    @property
    def primary_key_id(self) -> str:
        return self._primary_key_id

    def digest(self, secret: str, *, key_id: str | None = None) -> str:
        selected = self._primary_key_id if key_id is None else key_id
        key = self._keys.get(selected)
        if key is None:
            raise ValueError("access_pepper_key_unavailable")
        return hmac.new(key, secret.encode("utf-8"), hashlib.sha256).hexdigest()

    def verify(self, secret: str, *, expected: str, key_id: str) -> bool:
        if len(secret) > 256:
            return False
        try:
            actual = self.digest(secret, key_id=key_id)
        except ValueError:
            return False
        return hmac.compare_digest(actual, expected)

    def callback_credentials(self, node_id: UUID) -> tuple[str, str]:
        return (
            f"callback-{node_id}",
            self.digest(f"rtsp-proxy-media-callback:{node_id}"),
        )

    def callback_authorization(self, node_id: UUID) -> str:
        username, password = self.callback_credentials(node_id)
        encoded = base64.b64encode(f"{username}:{password}".encode("ascii")).decode("ascii")
        return f"Basic {encoded}"

    def verify_callback_authorization(self, node_id: UUID, value: str | None) -> bool:
        if value is None or not value.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(value[6:], validate=True).decode("ascii")
            username, password = decoded.split(":", 1)
        except (ValueError, UnicodeError):
            return False
        if not hmac.compare_digest(username, f"callback-{node_id}"):
            return False
        message = f"rtsp-proxy-media-callback:{node_id}"
        return any(
            hmac.compare_digest(
                password,
                hmac.new(key, message.encode("ascii"), hashlib.sha256).hexdigest(),
            )
            for key in self._keys.values()
        )


def load_pepper_verifier(
    path: str | os.PathLike[str],
    *,
    group_name: str = "rtsp-proxy-access",
) -> PepperVerifier:
    try:
        expected_gid = grp.getgrnam(group_name).gr_gid
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            file_stat = os.fstat(descriptor)
            if (
                not stat.S_ISREG(file_stat.st_mode)
                or file_stat.st_nlink != 1
                or file_stat.st_uid != 0
                or file_stat.st_gid != expected_gid
                or stat.S_IMODE(file_stat.st_mode) != 0o640
                or not 1 <= file_stat.st_size <= 4096
            ):
                raise AccessPepperFileError("access_pepper_file_unsafe")
            raw = os.read(descriptor, 4097)
        finally:
            os.close(descriptor)
        payload = json.loads(raw)
        if not isinstance(payload, dict) or set(payload) != {"primary_key_id", "keys"}:
            raise ValueError
        key_id = payload["primary_key_id"]
        keys = payload["keys"]
        if not isinstance(key_id, str) or not isinstance(keys, dict):
            raise ValueError
        return PepperVerifier(
            primary_key_id=key_id,
            keys={str(candidate): bytes.fromhex(str(value)) for candidate, value in keys.items()},
        )
    except AccessPepperFileError:
        raise
    except (KeyError, OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise AccessPepperFileError("access_pepper_file_unsafe") from error


class AccessAuthorizer:
    def __init__(
        self,
        *,
        store: AccessAuthorizerStore,
        verifier: PepperVerifier,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        attempts: AccessAttemptLimiter | None = None,
        decision_sink: AccessDecisionSink | None = None,
    ) -> None:
        self._store = store
        self._verifier = verifier
        self._clock = clock
        self._attempts = attempts
        self._decision_sink = decision_sink

    def authorize(self, request: AuthorizeRequest) -> AccessDecision:
        if self._attempts is not None and not self._attempts.begin_peer(request.peer_ip):
            decision = AccessDecision(False, AccessDecisionReason.REQUEST_DENIED)
            self._record_decision(request, decision)
            return decision
        try:
            decision = self._authorize_started(request)
            self._record_decision(request, decision)
            return decision
        finally:
            if self._attempts is not None:
                self._attempts.end_peer(request.peer_ip)

    def _record_decision(
        self,
        request: AuthorizeRequest,
        decision: AccessDecision,
    ) -> None:
        if self._decision_sink is None:
            return
        address = _peer_address(request.peer_ip)
        event = AccessDecisionEvent(
            reason=decision.reason,
            allowed=decision.allowed,
            node_id=request.node_id,
            action=request.action if request.action == "read" else "other",
            protocol=request.protocol if request.protocol == "rtsp" else "other",
            peer_family="ipv4" if isinstance(address, IPv4Address) else "ipv6",
            peer_ip=str(address),
            public_id=request.public_id,
            camera_id=decision.camera_id,
            grant_id=decision.grant_id,
            last_use_persisted=decision.last_use_persisted,
        )
        with suppress(Exception):
            self._decision_sink.record(event)

    def _authorize_started(self, request: AuthorizeRequest) -> AccessDecision:
        if request.action != "read" or request.protocol != "rtsp":
            return AccessDecision(False, AccessDecisionReason.REQUEST_DENIED)
        if self._attempts is not None and not self._attempts.allow_peer(request.peer_ip):
            return AccessDecision(False, AccessDecisionReason.REQUEST_DENIED)
        target = self._store.get_access_target(
            node_id=request.node_id,
            public_id=request.public_id,
        )
        if target is None or not target.enabled:
            return AccessDecision(False, AccessDecisionReason.TARGET_DENIED)
        if not target.policy.permits(request.peer_ip):
            return AccessDecision(False, AccessDecisionReason.IP_DENIED)
        grant = self._store.get_access_grant(
            camera_id=target.camera_id,
            username=request.username,
        )
        if grant is None:
            return AccessDecision(False, AccessDecisionReason.CREDENTIAL_DENIED)
        if self._attempts is not None and not self._attempts.allow_grant(
            camera_id=target.camera_id,
            grant_id=grant.id,
        ):
            return AccessDecision(False, AccessDecisionReason.REQUEST_DENIED)
        now = self._clock()
        if not grant.active_at(now):
            return AccessDecision(False, AccessDecisionReason.GRANT_INACTIVE)
        if not self._verifier.verify(
            request.password,
            expected=grant.token_verifier,
            key_id=grant.pepper_key_id,
        ):
            return AccessDecision(False, AccessDecisionReason.CREDENTIAL_DENIED)
        if (
            grant.pepper_key_id != self._verifier.primary_key_id
            and not self._store.rehash_access_grant(
                grant.id,
                token_verifier=self._verifier.digest(request.password),
                pepper_key_id=self._verifier.primary_key_id,
                expected_revision=grant.revision,
            )
        ):
            return AccessDecision(False, AccessDecisionReason.CREDENTIAL_DENIED)
        try:
            last_use_persisted = self._store.mark_access_grant_used(grant.id)
        except Exception:
            last_use_persisted = False
        return AccessDecision(
            True,
            AccessDecisionReason.ALLOWED,
            camera_id=target.camera_id,
            grant_id=grant.id,
            last_use_persisted=last_use_persisted,
        )


@dataclass(slots=True)
class _RateBucket:
    tokens: float
    updated: float


class AccessAttemptLimiter:
    """Bounded token buckets for coarse peer and precise grant/camera defense."""

    def __init__(
        self,
        *,
        peer_rate: int = 100,
        peer_burst: int = 200,
        grant_rate: int = 20,
        grant_burst: int = 40,
        maximum_pending_per_peer: int = 32,
        maximum_keys: int = 65_536,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if (
            min(
                peer_rate,
                peer_burst,
                grant_rate,
                grant_burst,
                maximum_pending_per_peer,
                maximum_keys,
            )
            < 1
            or peer_burst < peer_rate
            or grant_burst < grant_rate
        ):
            raise ValueError("access_attempt_limiter_invalid")
        self._peer_rate = float(peer_rate)
        self._peer_burst = float(peer_burst)
        self._grant_rate = float(grant_rate)
        self._grant_burst = float(grant_burst)
        self._maximum_keys = maximum_keys
        self._maximum_pending_per_peer = maximum_pending_per_peer
        self._monotonic = monotonic
        self._buckets: OrderedDict[str, _RateBucket] = OrderedDict()
        self._pending: dict[str, int] = {}
        self._lock = threading.Lock()

    def begin_peer(self, peer_ip: str) -> bool:
        key = str(_peer_address(peer_ip))
        with self._lock:
            current = self._pending.get(key, 0)
            if current >= self._maximum_pending_per_peer:
                return False
            if current == 0 and len(self._pending) >= self._maximum_keys:
                return False
            self._pending[key] = current + 1
            return True

    def end_peer(self, peer_ip: str) -> None:
        key = str(_peer_address(peer_ip))
        with self._lock:
            current = self._pending.get(key)
            if current is None:
                raise RuntimeError("access_attempt_pending_missing")
            if current == 1:
                del self._pending[key]
            else:
                self._pending[key] = current - 1

    def allow_peer(self, peer_ip: str) -> bool:
        return self._allow(
            f"peer:{_peer_address(peer_ip)}",
            rate=self._peer_rate,
            burst=self._peer_burst,
        )

    def allow_grant(self, *, camera_id: UUID, grant_id: UUID) -> bool:
        return self._allow(
            f"grant:{camera_id}:{grant_id}",
            rate=self._grant_rate,
            burst=self._grant_burst,
        )

    def _allow(self, key: str, *, rate: float, burst: float) -> bool:
        now = self._monotonic()
        with self._lock:
            bucket = self._buckets.pop(key, None)
            if bucket is None:
                if len(self._buckets) >= self._maximum_keys:
                    self._buckets.popitem(last=False)
                bucket = _RateBucket(tokens=burst, updated=now)
            bucket.tokens = min(burst, bucket.tokens + max(0.0, now - bucket.updated) * rate)
            bucket.updated = now
            allowed = bucket.tokens >= 1.0
            if allowed:
                bucket.tokens -= 1.0
            self._buckets[key] = bucket
            return allowed


@dataclass(frozen=True, slots=True)
class IssuedAccessGrant:
    grant: AccessGrant
    secret: str

    def __repr__(self) -> str:
        return f"IssuedAccessGrant(grant={self.grant!r}, secret=<redacted>)"


class AccessGrantControl:
    def __init__(
        self,
        *,
        store: AccessGrantStore,
        verifier: PepperVerifier,
        new_grant_id: Callable[[], UUID],
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        new_secret: Callable[[], str] = lambda: secrets.token_urlsafe(32),
    ) -> None:
        self._store = store
        self._verifier = verifier
        self._new_grant_id = new_grant_id
        self._clock = clock
        self._new_secret = new_secret

    def create(
        self,
        *,
        camera_id: UUID,
        lifetime: timedelta,
        kind: str = "temporary",
        created_by: str = "bootstrap-operator",
        mutation_context: NodeMutationContext | None = None,
        idempotency_key: UUID | None = None,
    ) -> IssuedAccessGrant:
        now = self._clock()
        grant_id = self._new_grant_id()
        idempotency = self._idempotency(
            key=idempotency_key,
            mutation_context=mutation_context,
            operation="issue",
            camera_id=camera_id,
            source_grant_id=None,
            replacement_grant_id=grant_id,
            request={
                "camera_id": str(camera_id),
                "kind": kind,
                "lifetime_seconds": int(lifetime.total_seconds()),
            },
        )
        if idempotency is not None:
            self._store.check_access_grant_request(idempotency)
        issued = self._issue(
            camera_id=camera_id,
            grant_id=grant_id,
            now=now,
            lifetime=lifetime,
            kind=kind,
            created_by=created_by,
        )
        if mutation_context is None and idempotency is None:
            persisted = self._store.create_access_grant(issued.grant)
        else:
            persisted = self._store.create_access_grant(
                issued.grant,
                mutation_context=mutation_context,
                idempotency=idempotency,
            )
        return IssuedAccessGrant(grant=persisted, secret=issued.secret)

    def get(
        self,
        grant_id: UUID,
        *,
        camera_id: UUID | None = None,
    ) -> AccessGrantSummary:
        grant = self._store.get_access_grant_by_id(grant_id)
        if grant is None or (camera_id is not None and grant.camera_id != camera_id):
            raise LookupError("access_grant_not_found")
        return AccessGrantSummary.from_grant(grant)

    def list_for_camera(self, camera_id: UUID, *, limit: int = 100) -> AccessGrantPage:
        if not 1 <= limit <= 100:
            raise ValueError("access_grant_list_limit_invalid")
        grants = self._store.list_access_grants(camera_id, limit=limit + 1)
        return AccessGrantPage(items=grants[:limit], truncated=len(grants) > limit)

    def revoke(
        self,
        grant_id: UUID,
        *,
        camera_id: UUID | None = None,
        expected_revision: int | None = None,
        mutation_context: NodeMutationContext | None = None,
    ) -> AccessGrant:
        if mutation_context is not None and expected_revision is None:
            raise ValueError("access_grant_revision_required")
        current = self._store.get_access_grant_by_id(grant_id)
        if current is None or (camera_id is not None and current.camera_id != camera_id):
            raise LookupError("access_grant_not_found")
        revision = current.revision if expected_revision is None else expected_revision
        if current.revoked_at is not None:
            if revision != current.revision:
                raise LookupError("access_grant_not_found")
            return current
        if mutation_context is None:
            return self._store.revoke_access_grant(
                grant_id,
                revoked_at=self._clock(),
                expected_revision=revision,
            )
        return self._store.revoke_access_grant(
            grant_id,
            revoked_at=self._clock(),
            expected_revision=revision,
            mutation_context=mutation_context,
        )

    def rotate(
        self,
        grant_id: UUID,
        *,
        overlap: timedelta,
        lifetime: timedelta,
        camera_id: UUID | None = None,
        expected_revision: int | None = None,
        created_by: str | None = None,
        mutation_context: NodeMutationContext | None = None,
        idempotency_key: UUID | None = None,
    ) -> IssuedAccessGrant:
        if overlap < timedelta(0) or overlap > MAX_ROTATION_OVERLAP:
            raise ValueError("access_grant_overlap_invalid")
        if mutation_context is not None and (
            camera_id is None or expected_revision is None
        ):
            raise ValueError("access_grant_revision_required")
        replacement_grant_id = self._new_grant_id()
        idempotency = self._idempotency(
            key=idempotency_key,
            mutation_context=mutation_context,
            operation="rotate",
            camera_id=camera_id if camera_id is not None else UUID(int=0),
            source_grant_id=grant_id,
            replacement_grant_id=replacement_grant_id,
            request={
                "camera_id": None if camera_id is None else str(camera_id),
                "grant_id": str(grant_id),
                "expected_revision": expected_revision,
                "overlap_seconds": int(overlap.total_seconds()),
                "lifetime_seconds": int(lifetime.total_seconds()),
            },
        )
        if idempotency is not None:
            self._store.check_access_grant_request(idempotency)
        current = self._store.get_access_grant_by_id(grant_id)
        if (
            current is None
            or current.revoked_at is not None
            or (camera_id is not None and current.camera_id != camera_id)
        ):
            raise LookupError("access_grant_not_found")
        revision = current.revision if expected_revision is None else expected_revision
        now = self._clock()
        if not current.active_at(now):
            raise LookupError("access_grant_not_found")
        issued = self._issue(
            camera_id=current.camera_id,
            grant_id=replacement_grant_id,
            now=now,
            lifetime=lifetime,
            kind=current.kind,
            created_by=current.created_by if created_by is None else created_by,
        )
        old_expires_at = min(current.expires_at, now + overlap)
        if mutation_context is None and idempotency is None:
            _old, replacement = self._store.rotate_access_grant(
                grant_id,
                replacement=issued.grant,
                old_expires_at=old_expires_at,
                expected_revision=revision,
            )
        else:
            _old, replacement = self._store.rotate_access_grant(
                grant_id,
                replacement=issued.grant,
                old_expires_at=old_expires_at,
                expected_revision=revision,
                mutation_context=mutation_context,
                idempotency=idempotency,
            )
        return IssuedAccessGrant(grant=replacement, secret=issued.secret)

    @staticmethod
    def _idempotency(
        *,
        key: UUID | None,
        mutation_context: NodeMutationContext | None,
        operation: str,
        camera_id: UUID,
        source_grant_id: UUID | None,
        replacement_grant_id: UUID,
        request: Mapping[str, object],
    ) -> AccessGrantIdempotency | None:
        if key is None and mutation_context is None:
            return None
        if (
            key is None
            or mutation_context is None
            or mutation_context.idempotency_key != key
        ):
            raise ValueError("access_grant_idempotency_invalid")
        encoded = json.dumps(
            {"request_schema": 1, "operation": operation, **request},
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return AccessGrantIdempotency(
            key=key,
            actor_account_id=mutation_context.actor_account_id,
            actor_session_id=mutation_context.actor_session_id,
            operation=operation,
            camera_id=camera_id,
            source_grant_id=source_grant_id,
            replacement_grant_id=replacement_grant_id,
            request_sha256=hashlib.sha256(encoded).hexdigest(),
        )

    def _issue(
        self,
        *,
        camera_id: UUID,
        grant_id: UUID,
        now: datetime,
        lifetime: timedelta,
        kind: str,
        created_by: str,
    ) -> IssuedAccessGrant:
        if lifetime < MIN_GRANT_LIFETIME or lifetime > MAX_GRANT_LIFETIME:
            raise ValueError("access_grant_lifetime_invalid")
        secret = self._new_secret()
        if len(secret) < 43 or any(
            not (character.isalnum() or character in "-_") for character in secret
        ):
            raise ValueError("access_grant_secret_invalid")
        grant = AccessGrant(
            id=grant_id,
            camera_id=camera_id,
            username=f"grant-{grant_id.hex}",
            token_verifier=self._verifier.digest(secret),
            pepper_key_id=self._verifier.primary_key_id,
            not_before=now,
            expires_at=now + lifetime,
            revoked_at=None,
            revision=1,
            kind=kind,
            created_by=created_by,
        )
        return IssuedAccessGrant(grant=grant, secret=secret)


def _peer_address(value: str) -> IPv4Address | IPv6Address:
    try:
        address = ip_address(value)
    except ValueError as error:
        raise ValueError("access_peer_ip_invalid") from error
    if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address
