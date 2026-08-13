from __future__ import annotations

import subprocess
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, Thread
from time import monotonic
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ProgrammingError

from rtsp_proxy.access import (
    AccessAttemptLimiter,
    AccessAuthorizer,
    AccessDecision,
    AccessDecisionEvent,
    AccessDecisionReason,
    AccessDecisionTelemetry,
    AccessGrant,
    AccessGrantControl,
    AccessPolicy,
    AccessPolicyControl,
    AccessTarget,
    AuthorizeRequest,
    PepperVerifier,
    canonicalize_cidrs,
)
from rtsp_proxy.app import create_app, create_media_auth_app
from rtsp_proxy.config import RuntimeRole, Settings
from rtsp_proxy.database import PostgresNodeStore
from rtsp_proxy.identifiers import PublicId
from rtsp_proxy.migrate import upgrade_database
from rtsp_proxy.node_runtime import (
    MediaNodeConfigRenderer,
    NodeManagementCredentials,
    NodeRuntimeSpec,
)
from rtsp_proxy.nodes import (
    CameraControl,
    CameraLifecycleConflict,
    CameraNotFound,
    NodeControl,
    NodeHealth,
    NodeRuntimeObservation,
    NodeState,
)

CAMERA_ID = UUID("10000000-0000-0000-0000-000000000001")
NODE_ID = UUID("20000000-0000-0000-0000-000000000002")
GRANT_ID = UUID("30000000-0000-0000-0000-000000000003")
PUBLIC_ID = PublicId.parse("a" * 26)
NOW = datetime(2026, 8, 13, 1, 0, tzinfo=UTC)


class RecordingAccessStore:
    def __init__(self, *, policy: AccessPolicy, grant: AccessGrant | None) -> None:
        self.target = AccessTarget(
            camera_id=CAMERA_ID,
            node_id=NODE_ID,
            public_id=PUBLIC_ID,
            enabled=True,
            policy=policy,
        )
        self.grant = grant
        self.calls: list[str] = []
        self.created: list[AccessGrant] = []

    def get_access_target(
        self, *, node_id: UUID, public_id: PublicId
    ) -> AccessTarget | None:
        self.calls.append("target")
        if node_id != NODE_ID or public_id != PUBLIC_ID:
            return None
        return self.target

    def get_access_grant(self, *, camera_id: UUID, username: str) -> AccessGrant | None:
        self.calls.append("grant")
        if (
            self.grant is None
            or self.grant.camera_id != camera_id
            or self.grant.username != username
        ):
            return None
        return self.grant

    def create_access_grant(self, grant: AccessGrant) -> AccessGrant:
        self.created.append(grant)
        self.grant = grant
        return grant

    def get_access_grant_by_id(self, grant_id: UUID) -> AccessGrant | None:
        return self.grant if self.grant is not None and self.grant.id == grant_id else None

    def rehash_access_grant(
        self,
        grant_id: UUID,
        *,
        token_verifier: str,
        pepper_key_id: str,
        expected_revision: int,
    ) -> bool:
        assert self.grant is not None
        if self.grant.id != grant_id or self.grant.revision != expected_revision:
            return False
        self.grant = replace(
            self.grant,
            token_verifier=token_verifier,
            pepper_key_id=pepper_key_id,
            revision=expected_revision + 1,
        )
        return True

    def mark_access_grant_used(self, grant_id: UUID) -> bool:
        assert self.grant is not None
        assert self.grant.id == grant_id
        self.grant = replace(self.grant, last_used_at=NOW)
        return True

    def get_access_policy(self, camera_id: UUID) -> AccessPolicy | None:
        return self.target.policy if self.target.camera_id == camera_id else None

    def set_access_policy(
        self,
        policy: AccessPolicy,
        *,
        expected_revision: int,
    ) -> AccessPolicy:
        assert self.target.policy.revision == expected_revision
        self.target = replace(self.target, policy=policy)
        return policy

    def revoke_access_grant(
        self,
        grant_id: UUID,
        *,
        revoked_at: datetime,
        expected_revision: int,
    ) -> AccessGrant:
        assert self.grant is not None
        assert self.grant.id == grant_id
        assert self.grant.revision == expected_revision
        self.grant = replace(
            self.grant,
            revoked_at=revoked_at,
            revision=expected_revision + 1,
        )
        return self.grant

    def rotate_access_grant(
        self,
        grant_id: UUID,
        *,
        replacement: AccessGrant,
        old_expires_at: datetime,
        expected_revision: int,
    ) -> tuple[AccessGrant, AccessGrant]:
        assert self.grant is not None
        assert self.grant.id == grant_id
        assert self.grant.revision == expected_revision
        old = replace(
            self.grant,
            expires_at=old_expires_at,
            revision=expected_revision + 1,
        )
        self.created.append(replacement)
        self.grant = replacement
        return old, replacement


def policy(*, internet: tuple[str, ...] = (), local: tuple[str, ...] = ()) -> AccessPolicy:
    return AccessPolicy(
        camera_id=CAMERA_ID,
        revision=1,
        internet_cidrs=internet,
        local_cidrs=local,
    )


def verifier() -> PepperVerifier:
    return PepperVerifier(primary_key_id="pepper-2026-08", keys={"pepper-2026-08": b"x" * 32})


def callback_headers(node_id: UUID = NODE_ID) -> dict[str, str]:
    return {"authorization": verifier().callback_authorization(node_id)}


def grant_for(password: str = "token") -> AccessGrant:
    secret_verifier = verifier()
    return AccessGrant(
        id=GRANT_ID,
        camera_id=CAMERA_ID,
        username=f"grant-{GRANT_ID.hex}",
        token_verifier=secret_verifier.digest(password),
        pepper_key_id=secret_verifier.primary_key_id,
        not_before=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(hours=1),
        revoked_at=None,
        revision=1,
    )


def request(
    *,
    ip: str = "198.51.100.5",
    password: str = "token",
    action: str = "read",
    protocol: str = "rtsp",
) -> AuthorizeRequest:
    return AuthorizeRequest(
        node_id=NODE_ID,
        public_id=PUBLIC_ID,
        peer_ip=ip,
        username=f"grant-{GRANT_ID.hex}",
        password=password,
        action=action,
        protocol=protocol,
    )


def test_cidrs_are_canonical_collapsed_and_bounded() -> None:
    assert canonicalize_cidrs(
        ("198.51.100.10/24", "198.51.100.0/25", "2001:db8::1/64")
    ) == ("198.51.100.0/24", "2001:db8::/64")
    with pytest.raises(ValueError, match="access_policy_cidr_invalid"):
        canonicalize_cidrs(("198.51.100.0/24%eth0",))
    with pytest.raises(ValueError, match="access_policy_cidr_limit"):
        canonicalize_cidrs(tuple(f"10.0.{index}.0/24" for index in range(129)))


@pytest.mark.parametrize(
    ("changes", "reason"),
    (
        ({"token_verifier": "z" * 64}, "access_grant_verifier_invalid"),
        ({"pepper_key_id": ""}, "access_grant_pepper_key_invalid"),
        ({"not_before": NOW + timedelta(hours=2)}, "access_grant_window_invalid"),
        ({"revision": 0}, "access_grant_revision_invalid"),
        ({"kind": "interactive"}, "access_grant_kind_invalid"),
        ({"created_by": ""}, "access_grant_creator_invalid"),
    ),
)
def test_access_grant_rejects_invalid_persisted_contract(
    changes: dict[str, object],
    reason: str,
) -> None:
    with pytest.raises(ValueError, match=reason):
        replace(grant_for(), **cast(Any, changes))


def test_access_decision_rejects_inconsistent_metadata() -> None:
    with pytest.raises(ValueError, match="access_decision_invalid"):
        AccessDecision(True, AccessDecisionReason.CREDENTIAL_DENIED)
    with pytest.raises(ValueError, match="access_decision_identity_missing"):
        AccessDecision(
            True,
            AccessDecisionReason.ALLOWED,
            last_use_persisted=True,
        )
    with pytest.raises(ValueError, match="access_decision_metadata_invalid"):
        AccessDecision(
            False,
            AccessDecisionReason.REQUEST_DENIED,
            last_use_persisted=False,
        )


def test_callback_authorization_rejects_malformed_values() -> None:
    assert verifier().verify_callback_authorization(NODE_ID, "Basic not-base64") is False
    assert verifier().verify_callback_authorization(NODE_ID, "Bearer token") is False


def test_decision_telemetry_requires_positive_retention() -> None:
    with pytest.raises(ValueError, match="access_decision_telemetry_invalid"):
        AccessDecisionTelemetry(maximum_audit_events=0)


def test_empty_policy_allows_ip_then_verifies_credentials() -> None:
    store = RecordingAccessStore(policy=policy(), grant=grant_for())
    decision = AccessAuthorizer(store=store, verifier=verifier(), clock=lambda: NOW).authorize(
        request()
    )
    assert decision.allowed is True
    assert decision.reason is AccessDecisionReason.ALLOWED
    assert store.calls == ["target", "grant"]


def test_acl_denial_happens_before_grant_lookup_and_password_hmac() -> None:
    store = RecordingAccessStore(
        policy=policy(internet=("203.0.113.0/24",), local=("10.0.0.0/8",)),
        grant=grant_for(),
    )
    decision = AccessAuthorizer(store=store, verifier=verifier(), clock=lambda: NOW).authorize(
        request(ip="198.51.100.5")
    )
    assert decision.allowed is False
    assert decision.reason is AccessDecisionReason.IP_DENIED
    assert store.calls == ["target"]


def test_attempt_limits_are_bounded_per_peer_then_per_grant() -> None:
    ticks = iter((0.0, 0.0, 0.0, 0.0, 0.0, 0.0))
    limiter = AccessAttemptLimiter(
        peer_rate=1,
        peer_burst=1,
        grant_rate=1,
        grant_burst=1,
        maximum_keys=4,
        monotonic=lambda: next(ticks),
    )
    store = RecordingAccessStore(policy=policy(), grant=grant_for())
    authorizer = AccessAuthorizer(
        store=store,
        verifier=verifier(),
        clock=lambda: NOW,
        attempts=limiter,
    )
    assert authorizer.authorize(request()).allowed is True
    assert authorizer.authorize(request()).reason is AccessDecisionReason.REQUEST_DENIED


def test_peer_limit_happens_before_target_database_lookup() -> None:
    limiter = AccessAttemptLimiter(
        peer_rate=1,
        peer_burst=1,
        grant_rate=10,
        grant_burst=10,
        monotonic=lambda: 0.0,
    )
    store = RecordingAccessStore(policy=policy(), grant=grant_for())
    authorizer = AccessAuthorizer(
        store=store,
        verifier=verifier(),
        clock=lambda: NOW,
        attempts=limiter,
    )
    assert authorizer.authorize(request()).allowed is True
    calls_after_first = list(store.calls)
    assert authorizer.authorize(request()).reason is AccessDecisionReason.REQUEST_DENIED
    assert store.calls == calls_after_first


def test_peer_pending_cap_is_bounded_and_released() -> None:
    limiter = AccessAttemptLimiter(
        maximum_pending_per_peer=1,
        maximum_keys=1,
    )
    assert limiter.begin_peer("127.0.0.1") is True
    assert limiter.begin_peer("127.0.0.1") is False
    assert limiter.begin_peer("127.0.0.2") is False
    limiter.end_peer("127.0.0.1")
    assert limiter.begin_peer("127.0.0.2") is True
    limiter.end_peer("127.0.0.2")
    with pytest.raises(RuntimeError, match="access_attempt_pending_missing"):
        limiter.end_peer("127.0.0.2")


def test_ipv4_mapped_peer_matches_ipv4_policy_and_bad_password_is_denied() -> None:
    store = RecordingAccessStore(
        policy=policy(internet=("198.51.100.0/24",)),
        grant=grant_for(),
    )
    decision = AccessAuthorizer(store=store, verifier=verifier(), clock=lambda: NOW).authorize(
        request(ip="::ffff:198.51.100.5", password="wrong")
    )
    assert decision.allowed is False
    assert decision.reason is AccessDecisionReason.CREDENTIAL_DENIED


def test_authorizer_emits_bounded_redacted_decision_telemetry() -> None:
    events: list[AccessDecisionEvent] = []

    class Sink:
        def record(self, event: AccessDecisionEvent) -> None:
            events.append(event)

    store = RecordingAccessStore(policy=policy(), grant=grant_for())
    decision = AccessAuthorizer(
        store=store,
        verifier=verifier(),
        clock=lambda: NOW,
        decision_sink=Sink(),
    ).authorize(request(password="wrong-secret"))

    assert decision.reason is AccessDecisionReason.CREDENTIAL_DENIED
    assert events == [
        AccessDecisionEvent(
            reason=AccessDecisionReason.CREDENTIAL_DENIED,
            allowed=False,
            node_id=NODE_ID,
            action="read",
            protocol="rtsp",
            peer_family="ipv4",
            peer_ip="198.51.100.5",
            public_id=PUBLIC_ID,
            camera_id=None,
            grant_id=None,
        )
    ]
    assert "wrong-secret" not in repr(events)
    assert "198.51.100.5" in repr(events)


def test_decision_telemetry_has_bounded_metrics_and_audit_retention() -> None:
    telemetry = AccessDecisionTelemetry(maximum_audit_events=1)
    store = RecordingAccessStore(policy=policy(), grant=grant_for())
    authorizer = AccessAuthorizer(
        store=store,
        verifier=verifier(),
        clock=lambda: NOW,
        decision_sink=telemetry,
    )

    authorizer.authorize(request(password="wrong-one"))
    authorizer.authorize(request(password="wrong-two", action="publish", protocol="srt"))
    snapshot = telemetry.snapshot()

    assert snapshot.counters == {
        ("credential_denied", False, "read", "rtsp", "ipv4"): 1,
        ("request_denied", False, "other", "other", "ipv4"): 1,
    }
    assert len(snapshot.recent_audit) == 1
    assert snapshot.dropped_audit == 1
    assert "wrong-one" not in repr(snapshot)
    assert "wrong-two" not in repr(snapshot)


def test_successful_authorization_updates_last_used_metadata() -> None:
    store = RecordingAccessStore(policy=policy(), grant=grant_for())

    decision = AccessAuthorizer(
        store=store,
        verifier=verifier(),
        clock=lambda: NOW,
    ).authorize(request())

    assert decision.allowed is True
    assert store.grant is not None
    assert store.grant.last_used_at == NOW


def test_last_use_persistence_failure_is_visible_without_leaking_credentials() -> None:
    class FailingLastUseStore(RecordingAccessStore):
        def mark_access_grant_used(self, grant_id: UUID) -> bool:
            raise RuntimeError("database password must not escape")

    telemetry = AccessDecisionTelemetry()
    decision = AccessAuthorizer(
        store=FailingLastUseStore(policy=policy(), grant=grant_for()),
        verifier=verifier(),
        clock=lambda: NOW,
        decision_sink=telemetry,
    ).authorize(request())

    snapshot = telemetry.snapshot()
    assert decision.allowed is True
    assert decision.last_use_persisted is False
    assert snapshot.last_use_persistence_failures == 1
    assert snapshot.recent_audit[0].last_use_persisted is False
    assert "database password" not in repr(snapshot)


def test_decision_telemetry_failure_never_changes_fail_closed_result() -> None:
    class FailedSink:
        def record(self, _event: AccessDecisionEvent) -> None:
            raise RuntimeError("telemetry unavailable")

    store = RecordingAccessStore(policy=policy(), grant=grant_for())
    decision = AccessAuthorizer(
        store=store,
        verifier=verifier(),
        clock=lambda: NOW,
        decision_sink=FailedSink(),
    ).authorize(request(password="wrong-secret"))

    assert decision.reason is AccessDecisionReason.CREDENTIAL_DENIED
    assert store.calls == ["target", "grant"]


def test_successful_previous_pepper_verification_rehashes_to_primary_key() -> None:
    previous = PepperVerifier(primary_key_id="previous", keys={"previous": b"o" * 32})
    rotating = PepperVerifier(
        primary_key_id="primary",
        keys={"primary": b"n" * 32, "previous": b"o" * 32},
    )
    old = replace(
        grant_for(),
        token_verifier=previous.digest("token"),
        pepper_key_id="previous",
    )
    store = RecordingAccessStore(policy=policy(), grant=old)

    decision = AccessAuthorizer(
        store=store,
        verifier=rotating,
        clock=lambda: NOW,
    ).authorize(request())

    assert decision.allowed is True
    assert store.grant is not None
    assert store.grant.pepper_key_id == "primary"
    assert store.grant.token_verifier == rotating.digest("token")
    assert store.grant.revision == old.revision + 1


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda item: replace(item, not_before=NOW + timedelta(seconds=1)), "grant_inactive"),
        (lambda item: replace(item, expires_at=NOW), "grant_inactive"),
        (lambda item: replace(item, revoked_at=NOW), "grant_inactive"),
    ],
)
def test_inactive_grants_fail_closed(mutate: object, reason: str) -> None:
    changed = mutate(grant_for())  # type: ignore[operator]
    store = RecordingAccessStore(policy=policy(), grant=changed)
    decision = AccessAuthorizer(store=store, verifier=verifier(), clock=lambda: NOW).authorize(
        request()
    )
    assert decision.allowed is False
    assert decision.reason.value == reason


def test_grant_creation_stores_only_verifier_and_returns_url_safe_secret_once() -> None:
    store = RecordingAccessStore(policy=policy(), grant=None)
    control = AccessGrantControl(
        store=store,
        verifier=verifier(),
        new_grant_id=lambda: GRANT_ID,
        clock=lambda: NOW,
    )
    issued = control.create(camera_id=CAMERA_ID, lifetime=timedelta(days=30))

    assert issued.grant == store.created[0]
    assert issued.secret not in repr(issued.grant)
    assert len(issued.secret) >= 43
    assert all(character.isalnum() or character in "-_" for character in issued.secret)
    assert issued.grant.token_verifier == verifier().digest(issued.secret)
    assert issued.grant.expires_at == NOW + timedelta(days=30)


def test_rotation_issues_a_new_secret_and_bounds_old_grant_overlap() -> None:
    old = grant_for()
    store = RecordingAccessStore(policy=policy(), grant=old)
    next_id = UUID("40000000-0000-0000-0000-000000000004")
    control = AccessGrantControl(
        store=store,
        verifier=verifier(),
        new_grant_id=lambda: next_id,
        clock=lambda: NOW,
    )

    issued = control.rotate(
        old.id,
        overlap=timedelta(seconds=30),
        lifetime=timedelta(days=7),
    )

    assert issued.grant.id == next_id
    assert issued.grant.camera_id == CAMERA_ID
    assert len(store.created) == 1
    assert old.revoked_at is None
    assert store.grant == issued.grant


def test_grant_control_rejects_missing_inactive_or_invalid_rotation() -> None:
    store = RecordingAccessStore(policy=policy(), grant=None)
    control = AccessGrantControl(
        store=store,
        verifier=verifier(),
        new_grant_id=lambda: GRANT_ID,
        clock=lambda: NOW,
    )
    with pytest.raises(LookupError, match="access_grant_not_found"):
        control.revoke(GRANT_ID)
    with pytest.raises(LookupError, match="access_grant_not_found"):
        control.rotate(GRANT_ID, overlap=timedelta(), lifetime=timedelta(hours=1))
    store.grant = replace(grant_for(), expires_at=NOW)
    with pytest.raises(LookupError, match="access_grant_not_found"):
        control.rotate(GRANT_ID, overlap=timedelta(), lifetime=timedelta(hours=1))
    store.grant = grant_for()
    with pytest.raises(ValueError, match="access_grant_overlap_invalid"):
        control.rotate(GRANT_ID, overlap=timedelta(days=2), lifetime=timedelta(hours=1))


def test_access_domain_rejects_invalid_security_invariants() -> None:
    with pytest.raises(ValueError, match="access_policy_revision_invalid"):
        AccessPolicy(camera_id=CAMERA_ID, revision=0)
    with pytest.raises(ValueError, match="access_target_policy_mismatch"):
        AccessTarget(
            camera_id=CAMERA_ID,
            node_id=NODE_ID,
            public_id=PUBLIC_ID,
            enabled=True,
            policy=AccessPolicy(camera_id=UUID(int=9), revision=1),
        )
    with pytest.raises(ValueError, match="access_peer_ip_invalid"):
        request(ip="not-an-ip")
    with pytest.raises(ValueError, match="access_request_credentials_invalid"):
        AuthorizeRequest(
            node_id=NODE_ID,
            public_id=PUBLIC_ID,
            peer_ip="127.0.0.1",
            username="u" * 65,
            password="token",
            action="read",
            protocol="rtsp",
        )
    with pytest.raises(ValueError, match="access_pepper_configuration_invalid"):
        PepperVerifier(primary_key_id="missing", keys={"other": b"x" * 32})
    with pytest.raises(ValueError, match="access_pepper_configuration_invalid"):
        PepperVerifier(
            primary_key_id="current",
            keys={
                "current": b"x" * 32,
                "previous": b"y" * 32,
                "unbounded": b"z" * 32,
            },
        )
    with pytest.raises(ValueError, match="access_grant_username_invalid"):
        replace(grant_for(), username="grant-00000000000000000000000000000000")
    with pytest.raises(ValueError, match="access_attempt_limiter_invalid"):
        AccessAttemptLimiter(peer_rate=2, peer_burst=1)


class ReadyNodeRuntime:
    def execute(self, action: object, node: object) -> NodeRuntimeObservation:
        return NodeRuntimeObservation(
            state=NodeState.RUNNING,
            health=NodeHealth.HEALTHY,
            management_fresh=True,
            config_compatible=True,
            applied_revision=node.desired_revision,  # type: ignore[attr-defined]
            process_id=100,
            process_start_ticks=200,
            process_boot_id=UUID("50000000-0000-0000-0000-000000000005"),
            config_sha256="a" * 64,
            release_id=node.release_id,  # type: ignore[attr-defined]
        )


def test_postgres_access_policy_grant_rotation_and_authorization_are_durable(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresNodeStore(postgres_database_url)
    node = NodeControl(
        store=store,
        choose_port=lambda ports: ports[0],
        new_node_id=lambda: NODE_ID,
        node_runtime=ReadyNodeRuntime(),
    ).register_node(
        name="node-access",
        port_range_start=12000,
        port_range_end=12000,
        max_nodes=1,
    )
    node = NodeControl(
        store=store,
        choose_port=lambda ports: ports[0],
        new_node_id=lambda: NODE_ID,
        node_runtime=ReadyNodeRuntime(),
    ).start_node(node.id)
    camera = CameraControl(
        store=store,
        new_camera_id=lambda: CAMERA_ID,
        new_public_id=lambda: str(PUBLIC_ID),
    ).create_camera(
        name="camera-access",
        source_url="rtsp://camera.invalid/main",
        node_id=node.id,
    )
    initial = store.get_access_policy(camera.id)
    assert initial == policy()
    configured = store.set_access_policy(
        AccessPolicy(
            camera_id=camera.id,
            revision=2,
            internet_cidrs=("198.51.100.0/24",),
            local_cidrs=("10.0.0.0/8",),
        ),
        expected_revision=1,
    )
    assert configured.revision == 2

    control = AccessGrantControl(
        store=store,
        verifier=verifier(),
        new_grant_id=lambda: GRANT_ID,
        clock=lambda: NOW,
        new_secret=lambda: "A" * 43,
    )
    issued = control.create(camera_id=camera.id, lifetime=timedelta(days=30))
    decision = AccessAuthorizer(store=store, verifier=verifier(), clock=lambda: NOW).authorize(
        AuthorizeRequest(
            node_id=node.id,
            public_id=camera.public_id,
            peer_ip="198.51.100.7",
            username=issued.grant.username,
            password=issued.secret,
            action="read",
            protocol="rtsp",
        )
    )
    assert decision.allowed is True
    NodeControl(
        store=store,
        choose_port=lambda ports: ports[0],
        new_node_id=lambda: NODE_ID,
    ).set_administrative_state(node.id, NodeState.DRAINING)
    drained = AccessAuthorizer(store=store, verifier=verifier(), clock=lambda: NOW).authorize(
        AuthorizeRequest(
            node_id=node.id,
            public_id=camera.public_id,
            peer_ip="198.51.100.7",
            username=issued.grant.username,
            password=issued.secret,
            action="read",
            protocol="rtsp",
        )
    )
    assert drained.reason is AccessDecisionReason.TARGET_DENIED
    NodeControl(
        store=store,
        choose_port=lambda ports: ports[0],
        new_node_id=lambda: NODE_ID,
    ).set_administrative_state(node.id, NodeState.RUNNING)
    replacement_id = UUID("40000000-0000-0000-0000-000000000004")
    rotating = AccessGrantControl(
        store=store,
        verifier=verifier(),
        new_grant_id=lambda: replacement_id,
        clock=lambda: NOW,
        new_secret=lambda: "B" * 43,
    )
    rotated = rotating.rotate(
        issued.grant.id,
        overlap=timedelta(seconds=30),
        lifetime=timedelta(hours=1),
    )
    assert rotated.grant.id == replacement_id
    old_grant = store.get_access_grant_by_id(issued.grant.id)
    assert old_grant is not None
    assert old_grant.expires_at == NOW + timedelta(seconds=30)
    with pytest.raises(CameraLifecycleConflict, match="access_grant_revision_conflict"):
        store.revoke_access_grant(
            old_grant.id,
            revoked_at=NOW,
            expected_revision=1,
        )
    issued = rotated
    control.revoke(issued.grant.id)
    denied = AccessAuthorizer(store=store, verifier=verifier(), clock=lambda: NOW).authorize(
        AuthorizeRequest(
            node_id=node.id,
            public_id=camera.public_id,
            peer_ip="198.51.100.7",
            username=issued.grant.username,
            password=issued.secret,
            action="read",
            protocol="rtsp",
        )
    )
    assert denied.reason is AccessDecisionReason.GRANT_INACTIVE
    store.close()


def test_postgres_previous_pepper_rehash_is_revisioned_and_audited(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresNodeStore(postgres_database_url)
    node = NodeControl(
        store=store,
        choose_port=lambda ports: ports[0],
        new_node_id=lambda: NODE_ID,
        node_runtime=ReadyNodeRuntime(),
    ).register_node(
        name="node-pepper-rotation",
        port_range_start=12000,
        port_range_end=12000,
        max_nodes=1,
    )
    node = NodeControl(
        store=store,
        choose_port=lambda ports: ports[0],
        new_node_id=lambda: NODE_ID,
        node_runtime=ReadyNodeRuntime(),
    ).start_node(node.id)
    camera = CameraControl(
        store=store,
        new_camera_id=lambda: CAMERA_ID,
        new_public_id=lambda: str(PUBLIC_ID),
    ).create_camera(
        name="camera-pepper-rotation",
        source_url="rtsp://camera.invalid/main",
        node_id=node.id,
    )
    previous = PepperVerifier(primary_key_id="previous", keys={"previous": b"o" * 32})
    old = store.create_access_grant(
        replace(
            grant_for(),
            camera_id=camera.id,
            token_verifier=previous.digest("token"),
            pepper_key_id="previous",
        )
    )
    rotating = PepperVerifier(
        primary_key_id="primary",
        keys={"primary": b"n" * 32, "previous": b"o" * 32},
    )

    decision = AccessAuthorizer(
        store=store,
        verifier=rotating,
        clock=lambda: NOW,
    ).authorize(request())
    persisted = store.get_access_grant_by_id(old.id)
    engine = create_engine(postgres_database_url)
    with engine.connect() as connection:
        audit_count = connection.scalar(
            text(
                "SELECT count(*) FROM audit_events "
                "WHERE aggregate_id=:grant_id "
                "AND event_type='camera.access_grant_rehashed'"
            ),
            {"grant_id": old.id},
        )
    engine.dispose()
    store.close()

    assert decision.allowed is True
    assert persisted is not None
    assert persisted.pepper_key_id == "primary"
    assert persisted.revision == old.revision + 1
    assert audit_count == 1


def test_postgres_auth_role_has_only_callback_permissions(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    admin_store = PostgresNodeStore(postgres_database_url)
    node = NodeControl(
        store=admin_store,
        choose_port=lambda ports: ports[0],
        new_node_id=lambda: NODE_ID,
        node_runtime=ReadyNodeRuntime(),
    ).register_node(
        name="node-auth-role",
        port_range_start=12000,
        port_range_end=12000,
        max_nodes=1,
    )
    node = NodeControl(
        store=admin_store,
        choose_port=lambda ports: ports[0],
        new_node_id=lambda: NODE_ID,
        node_runtime=ReadyNodeRuntime(),
    ).start_node(node.id)
    camera = CameraControl(
        store=admin_store,
        new_camera_id=lambda: CAMERA_ID,
        new_public_id=lambda: str(PUBLIC_ID),
    ).create_camera(
        name="camera-auth-role",
        source_url="rtsp://camera.invalid/main",
        node_id=node.id,
    )
    previous = PepperVerifier(primary_key_id="old", keys={"old": b"o" * 32})
    admin_store.create_access_grant(
        replace(
            grant_for(),
            camera_id=camera.id,
            token_verifier=previous.digest("token"),
            pepper_key_id="old",
        )
    )
    parsed = make_url(postgres_database_url)
    assert parsed.database is not None and parsed.host is not None and parsed.port is not None
    subprocess.run(
        (
            "psql",
            "--host",
            parsed.host,
            "--port",
            str(parsed.port),
            "--username",
            parsed.username or "postgres",
            "--dbname",
            parsed.database,
            "--set",
            f"DBNAME={parsed.database}",
            "--file",
            str(Path("deploy/postgresql/rtsp_proxy_auth.sql").resolve()),
        ),
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        (
            "psql",
            "--host",
            parsed.host,
            "--port",
            str(parsed.port),
            "--username",
            parsed.username or "postgres",
            "--dbname",
            parsed.database,
            "--set",
            f"DBNAME={parsed.database}",
            "--file",
            str(Path("deploy/postgresql/rtsp_proxy_auth.sql").resolve()),
        ),
        check=True,
        capture_output=True,
        text=True,
    )
    auth_url = str(parsed.set(username="rtsp_proxy_auth", password=None))
    auth_store = PostgresNodeStore(auth_url)
    rotating = PepperVerifier(
        primary_key_id="current",
        keys={"current": b"n" * 32, "old": b"o" * 32},
    )

    decision = AccessAuthorizer(
        store=auth_store,
        verifier=rotating,
        clock=lambda: NOW,
    ).authorize(request())
    persisted = admin_store.get_access_grant_by_id(GRANT_ID)

    assert decision.allowed is True
    assert decision.last_use_persisted is True
    assert persisted is not None
    assert persisted.pepper_key_id == "current"
    assert persisted.last_used_at is not None
    auth_engine = create_engine(auth_url)
    with pytest.raises(ProgrammingError), auth_engine.begin() as connection:
        connection.execute(
            text("UPDATE cameras SET name='forbidden' WHERE id=:camera_id"),
            {"camera_id": CAMERA_ID},
        )
    with pytest.raises(ProgrammingError), auth_engine.begin() as connection:
        connection.execute(
            text(
                "UPDATE camera_access_grants SET token_verifier=:verifier "
                "WHERE id=:grant_id"
            ),
            {"verifier": "0" * 64, "grant_id": GRANT_ID},
        )
    with pytest.raises(ProgrammingError), auth_engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO audit_events "
                "(id, aggregate_type, aggregate_id, event_type, "
                "aggregate_revision, payload) VALUES "
                "(:id, 'camera_access_grant', :grant_id, 'forged', 99, '{}')"
            ),
            {"id": uuid4(), "grant_id": GRANT_ID},
        )
    auth_engine.dispose()
    auth_store.close()
    admin_store.close()


def test_postgres_access_mutations_fail_closed_on_missing_or_stale_state(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresNodeStore(postgres_database_url)
    missing = UUID("90000000-0000-0000-0000-000000000009")
    with pytest.raises(ValueError, match="access_policy_revision_invalid"):
        store.set_access_policy(
            AccessPolicy(camera_id=missing, revision=2),
            expected_revision=2,
        )
    with pytest.raises(CameraNotFound, match="camera_not_found"):
        store.set_access_policy(
            AccessPolicy(camera_id=missing, revision=2),
            expected_revision=1,
        )
    with pytest.raises(CameraNotFound, match="camera_not_found"):
        store.create_access_grant(
            replace(grant_for(), camera_id=missing)
        )
    with pytest.raises(LookupError, match="access_grant_not_found"):
        store.revoke_access_grant(missing, revoked_at=NOW, expected_revision=1)
    assert store.get_access_target(node_id=NODE_ID, public_id=PUBLIC_ID) is None
    store.close()


def test_access_http_contract_reveals_secret_once_and_denials_have_one_shape() -> None:
    created = grant_for()
    store = RecordingAccessStore(policy=policy(), grant=created)
    control = AccessGrantControl(
        store=store,
        verifier=verifier(),
        new_grant_id=lambda: GRANT_ID,
        clock=lambda: NOW,
        new_secret=lambda: "Z" * 43,
    )
    app = create_app(
        Settings(role=RuntimeRole.WEB),
        access_policy_control=AccessPolicyControl(store=store),
        access_grant_control=control,
    )
    client = TestClient(app)

    updated = client.put(
        f"/api/v1/cameras/{CAMERA_ID}/access-policy",
        json={
            "internet_cidrs": ["198.51.100.10/24"],
            "local_cidrs": ["10.0.0.0/8"],
            "expected_revision": 1,
        },
    )
    assert updated.status_code == 200
    assert updated.json()["internet_cidrs"] == ["198.51.100.0/24"]

    store.grant = None
    issued = client.post(
        f"/api/v1/cameras/{CAMERA_ID}/access-grants",
        json={
            "kind": "temporary",
            "lifetime_seconds": 3600,
        },
    )
    assert issued.status_code == 201
    assert issued.headers["cache-control"] == "no-store"
    assert issued.headers["pragma"] == "no-cache"
    assert issued.json()["password"] == "Z" * 43
    assert issued.json()["kind"] == "temporary"
    assert issued.json()["created_by"] == "bootstrap-control-plane"
    assert "token_verifier" not in issued.text

    denied_payloads = (
        {
            "user": issued.json()["username"],
            "password": "wrong",
            "action": "read",
            "path": str(PUBLIC_ID),
            "protocol": "rtsp",
            "ip": "198.51.100.7",
        },
        {
            "user": "unknown",
            "password": "wrong",
            "action": "read",
            "path": str(PUBLIC_ID),
            "protocol": "rtsp",
            "ip": "198.51.100.7",
        },
        {
            "user": issued.json()["username"],
            "password": issued.json()["password"],
            "action": "read",
            "path": str(PUBLIC_ID),
            "protocol": "rtsp",
            "ip": "203.0.113.7",
        },
        {
            "user": issued.json()["username"],
            "password": issued.json()["password"],
            "action": "read",
            "path": "unknown",
            "protocol": "rtsp",
            "ip": "198.51.100.7",
        },
    )
    auth_client = TestClient(
        create_media_auth_app(
            authorizer=AccessAuthorizer(
                store=store,
                verifier=verifier(),
                clock=lambda: NOW,
            ),
            callback_verifier=verifier(),
        )
    )
    denied = [
        auth_client.post(
            f"/internal/v1/media-auth/{NODE_ID}",
            json=payload,
            headers=callback_headers(),
        )
        for payload in denied_payloads
    ]
    assert {(response.status_code, response.content) for response in denied} == {(401, b"")}

    allowed = auth_client.post(
        f"/internal/v1/media-auth/{NODE_ID}",
        json={
            "user": issued.json()["username"],
            "password": issued.json()["password"],
            "action": "read",
            "path": str(PUBLIC_ID),
            "protocol": "rtsp",
            "ip": "198.51.100.7",
        },
        headers=callback_headers(),
    )
    assert allowed.status_code == 204
    assert allowed.content == b""

    malformed = auth_client.post(
        f"/internal/v1/media-auth/{NODE_ID}",
        content=b"{",
        headers={"content-type": "application/json", **callback_headers()},
    )
    oversized = auth_client.post(
        f"/internal/v1/media-auth/{NODE_ID}",
        content=b"x" * 2049,
        headers={"content-type": "application/json", **callback_headers()},
    )
    assert (malformed.status_code, malformed.content) == (401, b"")
    assert (oversized.status_code, oversized.content) == (401, b"")


def test_access_http_endpoints_fail_closed_when_controls_or_records_are_missing() -> None:
    client = TestClient(create_app(Settings(role=RuntimeRole.WEB)))
    assert client.get(f"/api/v1/cameras/{CAMERA_ID}/access-policy").status_code == 503
    assert client.put(
        f"/api/v1/cameras/{CAMERA_ID}/access-policy",
        json={"internet_cidrs": [], "local_cidrs": [], "expected_revision": 1},
    ).status_code == 503
    assert client.post(
        f"/api/v1/cameras/{CAMERA_ID}/access-grants",
        json={
            "kind": "temporary",
            "lifetime_seconds": 3600,
        },
    ).status_code == 503
    assert client.post(
        f"/api/v1/access-grants/{GRANT_ID}/rotate",
        json={"lifetime_seconds": 3600},
    ).status_code == 503
    assert client.delete(f"/api/v1/access-grants/{GRANT_ID}").status_code == 503

    store = RecordingAccessStore(policy=policy(), grant=None)
    configured = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            access_policy_control=AccessPolicyControl(store=store),
            access_grant_control=AccessGrantControl(
                store=store,
                verifier=verifier(),
                new_grant_id=lambda: GRANT_ID,
                clock=lambda: NOW,
                new_secret=lambda: "S" * 43,
            ),
        )
    )
    assert configured.get(
        f"/api/v1/cameras/{UUID(int=99)}/access-policy"
    ).status_code == 404
    assert configured.post(
        f"/api/v1/access-grants/{GRANT_ID}/rotate",
        json={},
    ).status_code == 422
    assert configured.delete(f"/api/v1/access-grants/{GRANT_ID}").status_code == 404
    invalid = configured.put(
        f"/api/v1/cameras/{CAMERA_ID}/access-policy",
        json={
            "internet_cidrs": ["not-a-cidr"],
            "local_cidrs": [],
            "expected_revision": 1,
        },
    )
    assert invalid.status_code == 422
    assert invalid.json()["detail"]["code"] == "access_policy_cidr_invalid"


def test_access_grant_revoke_revision_race_is_a_typed_conflict() -> None:
    class ConflictingStore(RecordingAccessStore):
        def revoke_access_grant(
            self,
            grant_id: UUID,
            *,
            revoked_at: datetime,
            expected_revision: int,
        ) -> AccessGrant:
            raise CameraLifecycleConflict("access_grant_revision_conflict")

    store = ConflictingStore(policy=policy(), grant=grant_for())
    client = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            access_grant_control=AccessGrantControl(
                store=store,
                verifier=verifier(),
                new_grant_id=lambda: GRANT_ID,
                clock=lambda: NOW,
            ),
        )
    )

    response = client.delete(f"/api/v1/access-grants/{GRANT_ID}")

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "access_grant_revision_conflict"


def test_media_auth_admission_rate_limit_fails_closed_with_same_shape() -> None:
    store = RecordingAccessStore(policy=policy(), grant=grant_for())
    client = TestClient(
        create_media_auth_app(
            authorizer=AccessAuthorizer(
                store=store,
                verifier=verifier(),
                clock=lambda: NOW,
            ),
            callback_verifier=verifier(),
            rate_per_second=1,
            burst=1,
        )
    )
    payload = {
        "user": f"grant-{GRANT_ID.hex}",
        "password": "token",
        "action": "read",
        "path": str(PUBLIC_ID),
        "protocol": "rtsp",
        "ip": "198.51.100.7",
    }
    assert client.post(
        f"/internal/v1/media-auth/{NODE_ID}",
        json=payload,
        headers=callback_headers(),
    ).status_code == 204
    limited = client.post(
        f"/internal/v1/media-auth/{NODE_ID}",
        json=payload,
        headers=callback_headers(),
    )
    assert (limited.status_code, limited.content) == (401, b"")


def test_media_auth_rejects_missing_and_cross_node_callback_identity() -> None:
    store = RecordingAccessStore(policy=policy(), grant=grant_for())
    client = TestClient(
        create_media_auth_app(
            authorizer=AccessAuthorizer(store=store, verifier=verifier()),
            callback_verifier=verifier(),
        )
    )
    payload = {
        "user": f"grant-{GRANT_ID.hex}",
        "password": "token",
        "action": "read",
        "path": str(PUBLIC_ID),
        "protocol": "rtsp",
        "ip": "198.51.100.7",
    }
    other_node_id = UUID("20000000-0000-0000-0000-000000000099")

    missing = client.post(f"/internal/v1/media-auth/{NODE_ID}", json=payload)
    cross_node = client.post(
        f"/internal/v1/media-auth/{NODE_ID}",
        json=payload,
        headers=callback_headers(other_node_id),
    )

    assert (missing.status_code, missing.content) == (401, b"")
    assert (cross_node.status_code, cross_node.content) == (401, b"")
    assert store.calls == []


def test_media_auth_body_timeout_is_bounded_before_admission() -> None:
    import asyncio

    app = create_media_auth_app(
        authorizer=AccessAuthorizer(
            store=RecordingAccessStore(policy=policy(), grant=grant_for()),
            verifier=verifier(),
        ),
        callback_verifier=verifier(),
        body_timeout_seconds=0.01,
        max_inflight=1,
    )
    response_started: list[dict[str, object]] = []
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": f"/internal/v1/media-auth/{NODE_ID}",
        "raw_path": f"/internal/v1/media-auth/{NODE_ID}".encode("ascii"),
        "query_string": b"",
        "root_path": "",
        "server": ("127.0.0.1", 8010),
        "client": ("127.0.0.1", 30000),
        "headers": [
            (b"content-length", b"1"),
            (b"content-type", b"application/json"),
            (b"authorization", callback_headers()["authorization"].encode("ascii")),
        ],
    }

    async def stalled_receive() -> dict[str, object]:
        await asyncio.sleep(1)
        return {"type": "http.request", "body": b"{", "more_body": False}

    async def send(message: dict[str, object]) -> None:
        response_started.append(message)

    asyncio.run(app(scope, stalled_receive, cast(Any, send)))

    assert response_started[0]["type"] == "http.response.start"
    assert response_started[0]["status"] == 401


@pytest.mark.parametrize(
    ("headers", "path"),
    (
        ([(b"content-length", b"1")], "/wrong-route"),
        ([(b"content-length", b"invalid")], f"/internal/v1/media-auth/{NODE_ID}"),
        (
            [(b"content-length", b"1"), (b"content-length", b"1")],
            f"/internal/v1/media-auth/{NODE_ID}",
        ),
    ),
)
def test_media_auth_raw_middleware_rejects_ambiguous_request_metadata(
    headers: list[tuple[bytes, bytes]],
    path: str,
) -> None:
    import asyncio

    app = create_media_auth_app(
        authorizer=AccessAuthorizer(
            store=RecordingAccessStore(policy=policy(), grant=grant_for()),
            verifier=verifier(),
        ),
        callback_verifier=verifier(),
    )
    response_started: list[dict[str, object]] = []
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "root_path": "",
        "server": ("127.0.0.1", 8010),
        "client": ("127.0.0.1", 30000),
        "headers": [
            *headers,
            (b"authorization", callback_headers()["authorization"].encode("ascii")),
        ],
    }

    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": b"{", "more_body": False}

    async def send(message: dict[str, object]) -> None:
        response_started.append(message)

    asyncio.run(app(scope, cast(Any, receive), cast(Any, send)))

    assert response_started[0]["status"] == 401


def test_media_auth_raw_middleware_rejects_incomplete_and_oversized_body_frames() -> None:
    import asyncio

    app = create_media_auth_app(
        authorizer=AccessAuthorizer(
            store=RecordingAccessStore(policy=policy(), grant=grant_for()),
            verifier=verifier(),
        ),
        callback_verifier=verifier(),
    )
    base_scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": f"/internal/v1/media-auth/{NODE_ID}",
        "raw_path": f"/internal/v1/media-auth/{NODE_ID}".encode("ascii"),
        "query_string": b"",
        "root_path": "",
        "server": ("127.0.0.1", 8010),
        "client": ("127.0.0.1", 30000),
        "headers": [
            (b"content-length", b"1"),
            (b"authorization", callback_headers()["authorization"].encode("ascii")),
        ],
    }

    frames: tuple[dict[str, object], ...] = (
        {"type": "http.disconnect"},
        {"type": "http.request", "body": b"{}", "more_body": False},
        {"type": "http.request", "body": b"", "more_body": False},
    )
    for message in frames:
        response_started: list[dict[str, object]] = []

        async def receive(frame: dict[str, object] = message) -> dict[str, object]:
            return frame

        async def send(
            response: dict[str, object],
            observed: list[dict[str, object]] = response_started,
        ) -> None:
            observed.append(response)

        asyncio.run(app(base_scope, cast(Any, receive), cast(Any, send)))
        assert response_started[0]["status"] == 401


def test_media_auth_readiness_checks_database_schema_without_exposing_errors() -> None:
    store = RecordingAccessStore(policy=policy(), grant=grant_for())
    healthy = TestClient(
        create_media_auth_app(
            authorizer=AccessAuthorizer(store=store, verifier=verifier()),
            callback_verifier=verifier(),
            readiness=lambda: None,
        )
    ).get("/health/ready")
    failed = TestClient(
        create_media_auth_app(
            authorizer=AccessAuthorizer(store=store, verifier=verifier()),
            callback_verifier=verifier(),
            readiness=lambda: (_ for _ in ()).throw(RuntimeError("secret database detail")),
        )
    ).get("/health/ready")
    assert healthy.status_code == 200
    assert healthy.json()["status"] == "ready"
    assert failed.status_code == 503
    assert failed.json()["status"] == "not_ready"
    assert "secret database detail" not in failed.text


def test_media_auth_exposes_only_bounded_internal_telemetry() -> None:
    store = RecordingAccessStore(policy=policy(), grant=grant_for())
    telemetry = AccessDecisionTelemetry(maximum_audit_events=1)
    authorizer = AccessAuthorizer(
        store=store,
        verifier=verifier(),
        decision_sink=telemetry,
    )
    authorizer.authorize(request(password="wrong"))
    app = create_media_auth_app(
        authorizer=authorizer,
        callback_verifier=verifier(),
        telemetry=telemetry,
    )

    response = TestClient(app).get("/internal/v1/metrics")

    assert response.status_code == 200
    assert "rtsp_proxy_access_telemetry_available 1" in response.text
    assert "rtsp_proxy_access_decisions_total{" in response.text
    assert "rtsp_proxy_access_last_use_persistence_failures_total 0" in response.text
    assert str(CAMERA_ID) not in response.text
    assert str(PUBLIC_ID) not in response.text
    assert "wrong" not in response.text


def test_media_auth_postgresql_deadline_fails_closed_under_a_blocked_policy_lookup(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresNodeStore(postgres_database_url, statement_timeout_ms=200)
    blocker = create_engine(postgres_database_url)
    locked = Event()
    release = Event()

    def hold_policy_lock() -> None:
        with blocker.begin() as connection:
            connection.execute(text("LOCK TABLE camera_access_policies IN ACCESS EXCLUSIVE MODE"))
            locked.set()
            assert release.wait(timeout=5)

    thread = Thread(target=hold_policy_lock)
    thread.start()
    assert locked.wait(timeout=2)
    client = TestClient(
        create_media_auth_app(
            authorizer=AccessAuthorizer(store=store, verifier=verifier()),
            callback_verifier=verifier(),
        ),
        raise_server_exceptions=False,
    )
    started = monotonic()
    response = client.post(
        f"/internal/v1/media-auth/{NODE_ID}",
        json={
            "user": f"grant-{GRANT_ID.hex}",
            "password": "token",
            "action": "read",
            "path": str(PUBLIC_ID),
            "protocol": "rtsp",
            "ip": "198.51.100.7",
        },
        headers=callback_headers(),
    )
    elapsed = monotonic() - started
    release.set()
    thread.join(timeout=2)
    blocker.dispose()
    store.close()

    assert not thread.is_alive()
    assert (response.status_code, response.content) == (401, b"")
    assert elapsed < 1.5


def test_node_config_binds_http_auth_to_exact_loopback_node_route() -> None:
    rendered = MediaNodeConfigRenderer(
        auth_callback_port=8010,
        auth_callback_verifier=verifier(),
    ).render(
        NodeRuntimeSpec(
            node_id=NODE_ID,
            external_port=12000,
            api_port=13000,
            metrics_port=14000,
            desired_revision=1,
            release_id="0.1.0",
            mediamtx_binary_sha256="a" * 64,
        ),
        NodeManagementCredentials(username=f"node-{NODE_ID}", password="M" * 32),
    )

    assert "authMethod: http" in rendered.content
    assert "# rtsp-proxy-auth-primary-key-id: pepper-2026-08" in rendered.content
    assert (
        "authHTTPAddress: "
        f"http://callback-{NODE_ID}:{verifier().callback_credentials(NODE_ID)[1]}"
        f"@127.0.0.1:8010/internal/v1/media-auth/{NODE_ID}"
    ) in rendered.content
    assert "      - action: api\n      - action: metrics" in rendered.content
    assert "action: read" not in rendered.content
    assert f"pass: {'M' * 32}" in rendered.content
    assert "authHTTPExclude: []" in rendered.content
    assert '"~^[a-z2-7]{25}[aeimquy4]$": {}' in rendered.content
