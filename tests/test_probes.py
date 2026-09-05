from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from ipaddress import ip_network
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

from rtsp_proxy.app import create_app
from rtsp_proxy.config import RuntimeRole, Settings
from rtsp_proxy.database import PostgresNodeStore
from rtsp_proxy.identifiers import PublicId
from rtsp_proxy.migrate import upgrade_database
from rtsp_proxy.nodes import CameraControl, NodeState, ProbeEndpointSchemaUnavailable
from rtsp_proxy.probe_routine import CameraProbeProfile
from rtsp_proxy.probe_security import ProbeEndpointAdmission
from rtsp_proxy.probes import (
    BoundedProbeScheduler,
    InMemoryProbeObservationStore,
    PostgresProbeObservationStore,
    ProbeExecutionResult,
    ProbeFailureClass,
    ProbeHealthRecord,
    ProbeHealthState,
    ProbeIneligible,
    ProbeLease,
    ProbeMethod,
    ProbeNodeRuntimeGeneration,
    ProbeObservation,
    ProbeObservationState,
    ProbeObservationUnavailable,
    ProbeOutcome,
    ProbePriority,
    ProbeQueueFull,
    ProbeSingleFlightConflict,
    ProbeTarget,
    _health_generation_sha256,
)
from rtsp_proxy.reconcile import CameraMutationControl, ConfirmationTokenService

NOW = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)
NODE_A = UUID("10000000-0000-4000-8000-000000000001")
NODE_B = UUID("10000000-0000-4000-8000-000000000002")
NODE_RUNTIME = ProbeNodeRuntimeGeneration(
    node_applied_revision=1,
    process_id=1234,
    process_start_ticks=5678,
    process_boot_id=UUID("60000000-0000-4000-8000-000000000001"),
    release_id="0.2.1",
)
SOURCE_ENDPOINT_GENERATION = UUID("70000000-0000-4000-8000-000000000001")
SOURCE_POLICY_SHA256 = "b" * 64


def _target(
    number: int,
    *,
    node_id: UUID = NODE_A,
    site_key: str = "site-a",
    desired_revision: int = 1,
    placement_generation: int = 1,
    enabled: bool = True,
    maintenance: bool = False,
    occupied: bool = False,
    source_pull_active: bool = False,
    max_source_sessions: int = 2,
    node_state: NodeState = NodeState.RUNNING,
    node_runtime: ProbeNodeRuntimeGeneration | None = None,
) -> ProbeTarget:
    return ProbeTarget(
        camera_id=UUID(f"20000000-0000-4000-8000-{number:012d}"),
        public_id=PublicId.parse("a" * 25 + "a"),
        node_id=node_id,
        site_key=site_key,
        desired_revision=desired_revision,
        placement_generation=placement_generation,
        node_state=node_state,
        node_runtime=node_runtime,
        enabled=enabled,
        maintenance=maintenance,
        occupied=occupied,
        source_pull_active=source_pull_active,
        max_source_sessions=max_source_sessions,
        source_endpoint_generation=SOURCE_ENDPOINT_GENERATION,
    )


def _scheduler(**changes: object) -> BoundedProbeScheduler:
    values: dict[str, object] = {
        "global_limit": 3,
        "per_node_limit": 2,
        "per_site_limit": 1,
        "source_limit": 3,
        "path_limit": 2,
        "queue_limit": 32,
        "lease_seconds": 5,
        "retry_delay_seconds": 2,
        "max_attempts": 2,
        "new_request_id": iter(
            UUID(f"30000000-0000-4000-8000-{number:012d}") for number in range(1, 100)
        ).__next__,
        "new_lease_token": iter(
            UUID(f"40000000-0000-4000-8000-{number:012d}") for number in range(1, 100)
        ).__next__,
        "new_observation_id": iter(
            UUID(f"50000000-0000-4000-8000-{number:012d}") for number in range(1, 100)
        ).__next__,
    }
    values.update(changes)
    configured_global_limit = values["global_limit"]
    assert isinstance(configured_global_limit, int)
    if "source_limit" not in changes:
        values["source_limit"] = min(3, configured_global_limit)
    if "path_limit" not in changes:
        values["path_limit"] = min(2, configured_global_limit)
    return BoundedProbeScheduler(**values)  # type: ignore[arg-type]


def _claim(
    scheduler: BoundedProbeScheduler,
    now: datetime,
    *targets: ProbeTarget,
) -> tuple[ProbeLease, ...]:
    return scheduler.claim_available(
        now,
        {target.camera_id: target for target in targets},
    )


def test_probe_target_rejects_unsafe_or_ambiguous_identity() -> None:
    with pytest.raises(ValueError, match="probe_site_key_invalid"):
        _target(1, site_key="camera.local/secret")
    with pytest.raises(ValueError, match="probe_source_session_limit_invalid"):
        _target(1, max_source_sessions=0)
    with pytest.raises(ValueError, match="probe_target_state_invalid"):
        _target(1, enabled=False, maintenance=True)
    with pytest.raises(ValueError, match="probe_target_identity_invalid"):
        ProbeTarget(
            camera_id=UUID("20000000-0000-4000-8000-000000000001"),
            public_id="a" * 26,  # type: ignore[arg-type]
            node_id=NODE_A,
            site_key="site-a",
            desired_revision=1,
            placement_generation=1,
            node_state=NodeState.RUNNING,
            enabled=True,
            maintenance=False,
            occupied=False,
            source_pull_active=False,
            max_source_sessions=1,
        )


@pytest.mark.parametrize(
    ("target", "method", "reason"),
    [
        (_target(1, enabled=False), ProbeMethod.SOURCE, "camera_disabled"),
        (_target(2, maintenance=True), ProbeMethod.SOURCE, "camera_maintenance"),
        (_target(3, occupied=True), ProbeMethod.PATH, "camera_occupied"),
        (
            _target(4, source_pull_active=True, max_source_sessions=1),
            ProbeMethod.SOURCE,
            "source_session_budget",
        ),
        (
            _target(5, node_state=NodeState.DRAINING),
            ProbeMethod.PATH,
            "node_path_unavailable",
        ),
        (
            _target(6, source_pull_active=True, node_runtime=NODE_RUNTIME),
            ProbeMethod.PATH,
            "path_source_pull_active",
        ),
    ],
)
def test_scheduler_never_bypasses_camera_or_reader_admission(
    target: ProbeTarget,
    method: ProbeMethod,
    reason: str,
) -> None:
    scheduler = _scheduler()
    with pytest.raises(ProbeIneligible, match=reason):
        scheduler.submit(
            target=target,
            method=method,
            priority=ProbePriority.MANUAL,
            requested_at=NOW,
            deadline_at=NOW + timedelta(minutes=1),
        )
    assert scheduler.diagnostics().queued == 0


def test_scheduler_is_single_flight_bounded_and_generation_aware() -> None:
    scheduler = _scheduler(queue_limit=1)
    request = scheduler.submit(
        target=_target(1),
        method=ProbeMethod.SOURCE,
        priority=ProbePriority.ROUTINE,
        requested_at=NOW,
        deadline_at=NOW + timedelta(minutes=1),
    )
    assert (
        scheduler.submit(
            target=_target(1),
            method=ProbeMethod.SOURCE,
            priority=ProbePriority.ROUTINE,
            requested_at=NOW,
            deadline_at=NOW + timedelta(minutes=1),
        )
        == request
    )
    with pytest.raises(ProbeSingleFlightConflict, match="probe_single_flight_conflict"):
        scheduler.submit(
            target=_target(1, desired_revision=2),
            method=ProbeMethod.SOURCE,
            priority=ProbePriority.MANUAL,
            requested_at=NOW,
            deadline_at=NOW + timedelta(minutes=1),
        )
    with pytest.raises(ProbeQueueFull, match="probe_queue_full"):
        scheduler.submit(
            target=_target(2),
            method=ProbeMethod.SOURCE,
            priority=ProbePriority.ROUTINE,
            requested_at=NOW,
            deadline_at=NOW + timedelta(minutes=1),
        )


def test_scheduler_enforces_global_node_site_caps_and_uses_spare_capacity() -> None:
    scheduler = _scheduler()
    targets = tuple(
        _target(number, node_id=node_id, site_key=site_key)
        for number, node_id, site_key in (
            (1, NODE_A, "site-a"),
            (2, NODE_A, "site-a"),
            (3, NODE_A, "site-b"),
            (4, NODE_B, "site-c"),
        )
    )
    for target in targets:
        scheduler.submit(
            target=target,
            method=ProbeMethod.SOURCE,
            priority=ProbePriority.ROUTINE,
            requested_at=NOW,
            deadline_at=NOW + timedelta(minutes=1),
        )

    leases = _claim(scheduler, NOW, *targets)
    assert [(lease.target.node_id, lease.target.site_key) for lease in leases] == [
        (NODE_A, "site-a"),
        (NODE_A, "site-b"),
        (NODE_B, "site-c"),
    ]
    assert scheduler.diagnostics().active == 3
    assert scheduler.diagnostics().queued == 1


def test_weighted_fair_queue_never_starves_routine_work() -> None:
    scheduler = _scheduler(global_limit=1, per_node_limit=1, per_site_limit=1)
    priorities = (
        ProbePriority.MANUAL,
        ProbePriority.MANUAL,
        ProbePriority.MANUAL,
        ProbePriority.MANUAL,
        ProbePriority.CONFIRMATION,
        ProbePriority.CONFIRMATION,
        ProbePriority.CONFIRMATION,
        ProbePriority.ROUTINE,
        ProbePriority.ROUTINE,
        ProbePriority.ROUTINE,
    )
    targets = tuple(
        _target(number, site_key=f"site-{number}")
        for number in range(1, len(priorities) + 1)
    )
    for target, priority in zip(targets, priorities, strict=True):
        scheduler.submit(
            target=target,
            method=ProbeMethod.SOURCE,
            priority=priority,
            requested_at=NOW,
            deadline_at=NOW + timedelta(minutes=1),
        )

    observed: list[ProbePriority] = []
    for offset in range(10):
        lease = _claim(scheduler, NOW + timedelta(milliseconds=offset), *targets)[0]
        observed.append(lease.priority)
        scheduler.complete(
            lease,
            ProbeExecutionResult(
                outcome=ProbeOutcome.HEALTHY,
                completed_at=NOW + timedelta(milliseconds=offset + 1),
                video_codec="h264",
            ),
        )

    assert observed.count(ProbePriority.MANUAL) == 4
    assert observed.count(ProbePriority.CONFIRMATION) == 3
    assert observed.count(ProbePriority.ROUTINE) == 3
    assert ProbePriority.ROUTINE in observed[:10]


def test_near_deadline_routine_work_ages_ahead_of_nonurgent_manual_work() -> None:
    scheduler = _scheduler(global_limit=1, per_node_limit=1, per_site_limit=1)
    manual_target = _target(1, site_key="manual-site")
    routine_target = _target(2, site_key="routine-site")
    scheduler.submit(
        target=manual_target,
        method=ProbeMethod.SOURCE,
        priority=ProbePriority.MANUAL,
        requested_at=NOW,
        deadline_at=NOW + timedelta(minutes=1),
    )
    routine = scheduler.submit(
        target=routine_target,
        method=ProbeMethod.SOURCE,
        priority=ProbePriority.ROUTINE,
        requested_at=NOW,
        deadline_at=NOW + timedelta(seconds=5),
    )

    assert _claim(scheduler, NOW, manual_target, routine_target)[0].request_id == routine.request_id


def test_concurrent_pool_reserves_each_priority_and_borrows_unused_slots() -> None:
    scheduler = _scheduler(global_limit=3, per_node_limit=3, per_site_limit=3)
    targets = tuple(_target(number, site_key=f"site-{number}") for number in range(1, 6))
    priorities = (
        ProbePriority.MANUAL,
        ProbePriority.MANUAL,
        ProbePriority.MANUAL,
        ProbePriority.CONFIRMATION,
        ProbePriority.ROUTINE,
    )
    for target, priority in zip(targets, priorities, strict=True):
        scheduler.submit(
            target=target,
            method=ProbeMethod.SOURCE,
            priority=priority,
            requested_at=NOW,
            deadline_at=NOW + timedelta(minutes=1),
        )

    leases = _claim(scheduler, NOW, *targets)
    assert {lease.priority for lease in leases} == set(ProbePriority)

    routine_only = _scheduler(global_limit=3, per_node_limit=3, per_site_limit=3)
    for target in targets[:3]:
        routine_only.submit(
            target=target,
            method=ProbeMethod.SOURCE,
            priority=ProbePriority.ROUTINE,
            requested_at=NOW,
            deadline_at=NOW + timedelta(minutes=1),
        )
    assert len(_claim(routine_only, NOW, *targets[:3])) == 3


def test_urgent_manual_work_does_not_bypass_priority_reservations() -> None:
    scheduler = _scheduler(global_limit=3, per_node_limit=3, per_site_limit=3)
    targets = tuple(_target(number, site_key=f"site-{number}") for number in range(1, 6))
    priorities = (
        ProbePriority.MANUAL,
        ProbePriority.MANUAL,
        ProbePriority.MANUAL,
        ProbePriority.CONFIRMATION,
        ProbePriority.ROUTINE,
    )
    for target, priority in zip(targets, priorities, strict=True):
        scheduler.submit(
            target=target,
            method=ProbeMethod.SOURCE,
            priority=priority,
            requested_at=NOW,
            deadline_at=(
                NOW + timedelta(seconds=4)
                if priority is ProbePriority.MANUAL
                else NOW + timedelta(minutes=1)
            ),
        )

    assert {lease.priority for lease in _claim(scheduler, NOW, *targets)} == set(
        ProbePriority
    )


def test_scheduler_enforces_and_reports_separate_source_and_path_budgets() -> None:
    scheduler = _scheduler(
        global_limit=4,
        per_node_limit=4,
        per_site_limit=4,
        source_limit=1,
        path_limit=2,
    )
    source_targets = tuple(_target(number, site_key=f"source-{number}") for number in (1, 2))
    path_targets = tuple(
        _target(number, site_key=f"path-{number}", node_runtime=NODE_RUNTIME)
        for number in (3, 4, 5)
    )
    for target in source_targets:
        scheduler.submit(
            target=target,
            method=ProbeMethod.SOURCE,
            priority=ProbePriority.ROUTINE,
            requested_at=NOW,
            deadline_at=NOW + timedelta(minutes=1),
        )
    for target in path_targets:
        scheduler.submit(
            target=target,
            method=ProbeMethod.PATH,
            priority=ProbePriority.MANUAL,
            requested_at=NOW,
            deadline_at=NOW + timedelta(minutes=1),
        )

    leases = _claim(scheduler, NOW, *source_targets, *path_targets)
    assert sum(lease.method is ProbeMethod.SOURCE for lease in leases) == 1
    assert sum(lease.method is ProbeMethod.PATH for lease in leases) == 2
    diagnostics = scheduler.diagnostics()
    assert (diagnostics.source_active, diagnostics.path_active) == (1, 2)
    assert (diagnostics.source_queued, diagnostics.path_queued) == (1, 1)


def test_manual_join_promotes_a_pending_routine_single_flight() -> None:
    scheduler = _scheduler(global_limit=1, per_node_limit=1, per_site_limit=1)
    target = _target(1)
    routine = scheduler.submit(
        target=target,
        method=ProbeMethod.SOURCE,
        priority=ProbePriority.ROUTINE,
        requested_at=NOW,
        deadline_at=NOW + timedelta(minutes=2),
    )
    promoted = scheduler.submit(
        target=target,
        method=ProbeMethod.SOURCE,
        priority=ProbePriority.MANUAL,
        requested_at=NOW + timedelta(seconds=1),
        deadline_at=NOW + timedelta(minutes=1),
    )

    assert promoted.request_id == routine.request_id
    assert promoted.priority is ProbePriority.MANUAL
    assert promoted.deadline_at == NOW + timedelta(minutes=1)
    assert _claim(scheduler, NOW + timedelta(seconds=1), target)[0].priority is ProbePriority.MANUAL


def test_manual_join_refreshes_dynamic_target_state_before_promotion() -> None:
    scheduler = _scheduler(global_limit=1, per_node_limit=1, per_site_limit=1)
    target = _target(1, node_runtime=NODE_RUNTIME)
    routine = scheduler.submit(
        target=target,
        method=ProbeMethod.SOURCE,
        priority=ProbePriority.ROUTINE,
        requested_at=NOW,
        deadline_at=NOW + timedelta(minutes=2),
    )
    refreshed = replace(
        target,
        node_runtime=replace(NODE_RUNTIME, process_start_ticks=9_999),
        occupied=True,
    )

    promoted = scheduler.submit(
        target=refreshed,
        method=ProbeMethod.SOURCE,
        priority=ProbePriority.MANUAL,
        requested_at=NOW + timedelta(seconds=1),
        deadline_at=NOW + timedelta(minutes=1),
    )

    assert promoted.request_id == routine.request_id
    assert promoted.target == refreshed
    assert _claim(scheduler, NOW + timedelta(seconds=1), refreshed)[0].target == refreshed


def test_claim_rechecks_runtime_occupancy_and_source_session_admission() -> None:
    scheduler = _scheduler(global_limit=1, per_node_limit=1, per_site_limit=1)
    queued_path = _target(1, node_runtime=NODE_RUNTIME)
    scheduler.submit(
        target=queued_path,
        method=ProbeMethod.PATH,
        priority=ProbePriority.MANUAL,
        requested_at=NOW,
        deadline_at=NOW + timedelta(minutes=1),
    )
    assert _claim(scheduler, NOW, replace(queued_path, occupied=True)) == ()
    assert scheduler.diagnostics().queued == 0

    queued_source = _target(2)
    scheduler.submit(
        target=queued_source,
        method=ProbeMethod.SOURCE,
        priority=ProbePriority.ROUTINE,
        requested_at=NOW,
        deadline_at=NOW + timedelta(minutes=1),
    )
    assert _claim(scheduler, NOW) == ()
    assert scheduler.diagnostics().queued == 1
    assert (
        _claim(
            scheduler,
            NOW + timedelta(seconds=1),
            replace(queued_source, source_pull_active=True, max_source_sessions=1),
        )
        == ()
    )
    assert scheduler.diagnostics().queued == 0


def test_path_probe_requires_an_exact_node_runtime_generation() -> None:
    scheduler = _scheduler(global_limit=1, per_node_limit=1, per_site_limit=1)
    with pytest.raises(ProbeIneligible, match="node_runtime_unavailable"):
        scheduler.submit(
            target=_target(1),
            method=ProbeMethod.PATH,
            priority=ProbePriority.MANUAL,
            requested_at=NOW,
            deadline_at=NOW + timedelta(minutes=1),
        )


def test_submit_discards_an_expired_single_flight_before_deduplication() -> None:
    scheduler = _scheduler(global_limit=1, per_node_limit=1, per_site_limit=1)
    expired = scheduler.submit(
        target=_target(1),
        method=ProbeMethod.SOURCE,
        priority=ProbePriority.ROUTINE,
        requested_at=NOW,
        deadline_at=NOW + timedelta(seconds=1),
    )
    replacement = scheduler.submit(
        target=_target(1),
        method=ProbeMethod.SOURCE,
        priority=ProbePriority.MANUAL,
        requested_at=NOW + timedelta(seconds=2),
        deadline_at=NOW + timedelta(minutes=1),
    )

    assert replacement.request_id != expired.request_id
    assert replacement.priority is ProbePriority.MANUAL


def test_expired_lease_retries_with_backoff_then_fails_boundedly() -> None:
    scheduler = _scheduler(global_limit=1, per_node_limit=1, per_site_limit=1)
    target = _target(1)
    scheduler.submit(
        target=target,
        method=ProbeMethod.SOURCE,
        priority=ProbePriority.CONFIRMATION,
        requested_at=NOW,
        deadline_at=NOW + timedelta(seconds=20),
    )
    first = _claim(scheduler, NOW, target)[0]
    assert _claim(scheduler, NOW + timedelta(seconds=5), target) == ()
    assert scheduler.diagnostics().queued == 1
    assert _claim(scheduler, NOW + timedelta(seconds=6), target) == ()
    second = _claim(scheduler, NOW + timedelta(seconds=7), target)[0]
    assert second.request_id == first.request_id
    assert second.attempt == 2
    assert _claim(scheduler, NOW + timedelta(seconds=12), target) == ()
    diagnostics = scheduler.diagnostics()
    assert diagnostics.active == 0
    assert diagnostics.queued == 0
    assert diagnostics.expired_total == 2


def test_completion_token_and_result_contract_are_fail_closed() -> None:
    scheduler = _scheduler(global_limit=1, per_node_limit=1, per_site_limit=1)
    target = _target(1)
    scheduler.submit(
        target=target,
        method=ProbeMethod.SOURCE,
        priority=ProbePriority.MANUAL,
        requested_at=NOW,
        deadline_at=NOW + timedelta(minutes=1),
    )
    lease = _claim(scheduler, NOW, target)[0]
    with pytest.raises(ValueError, match="probe_result_contract_invalid"):
        ProbeExecutionResult(
            outcome=ProbeOutcome.HEALTHY,
            completed_at=NOW + timedelta(seconds=1),
            failure_class=ProbeFailureClass.TRANSPORT,
        )
    with pytest.raises(ValueError, match="probe_result_contract_invalid"):
        ProbeExecutionResult(
            outcome=ProbeOutcome.UNHEALTHY,
            completed_at=NOW + timedelta(seconds=1),
            failure_class=ProbeFailureClass.EXECUTOR,
        )
    inconclusive = ProbeExecutionResult(
        outcome=ProbeOutcome.INCONCLUSIVE,
        completed_at=NOW + timedelta(seconds=1),
        failure_class=ProbeFailureClass.EXECUTOR,
    )
    assert inconclusive.outcome is ProbeOutcome.INCONCLUSIVE
    with pytest.raises(ValueError, match="probe_lease_invalid"):
        scheduler.complete(
            lease.__class__(
                request_id=lease.request_id,
                lease_token=UUID("40000000-0000-4000-8000-999999999999"),
                target=lease.target,
                method=lease.method,
                priority=lease.priority,
                started_at=lease.started_at,
                lease_expires_at=lease.lease_expires_at,
                attempt=lease.attempt,
            ),
            ProbeExecutionResult(
                outcome=ProbeOutcome.HEALTHY,
                completed_at=NOW + timedelta(seconds=1),
                video_codec="h264",
            ),
        )

    observation = scheduler.complete(
        lease,
        ProbeExecutionResult(
            outcome=ProbeOutcome.UNHEALTHY,
            completed_at=NOW + timedelta(seconds=1),
            failure_class=ProbeFailureClass.TRANSPORT,
        ),
    )
    assert observation.target == lease.target
    assert observation.failure_class is ProbeFailureClass.TRANSPORT
    assert scheduler.diagnostics().active == 0


def test_observation_store_applies_only_exact_current_generation() -> None:
    current = _target(1)
    scheduler = _scheduler(global_limit=1, per_node_limit=1, per_site_limit=1)
    scheduler.submit(
        target=current,
        method=ProbeMethod.SOURCE,
        priority=ProbePriority.MANUAL,
        requested_at=NOW,
        deadline_at=NOW + timedelta(minutes=1),
    )
    observation = scheduler.complete(
        _claim(scheduler, NOW, current)[0],
        ProbeExecutionResult(
            outcome=ProbeOutcome.HEALTHY,
            completed_at=NOW + timedelta(seconds=1),
            video_codec="h264",
            audio_codec="opus",
        ),
    )
    store = InMemoryProbeObservationStore({current.camera_id: current})
    assert store.record_if_current(observation) is True
    assert store.latest_for((current.camera_id,))[current.camera_id] == observation

    store.set_current_target(_target(1, placement_generation=2))
    assert store.record_if_current(observation) is False
    assert store.latest_for((current.camera_id,)) == {}
    with pytest.raises(ValueError, match="probe_result_batch_invalid"):
        store.latest_for(tuple(_target(number).camera_id for number in range(1, 258)))


def test_observation_replay_is_immutable_in_memory() -> None:
    target = _target(1)
    observation = _observation(target)
    changed = replace(observation, video_codec="h265")
    store = InMemoryProbeObservationStore({target.camera_id: target})

    assert store.record_if_current(observation) is True
    assert store.record_if_current(changed) is False
    assert store.latest_for((target.camera_id,)) == {target.camera_id: observation}


def test_source_observation_remains_current_across_node_runtime_incarnations() -> None:
    current = _target(1, node_runtime=NODE_RUNTIME)
    source_target = replace(current, node_runtime=None)
    observation = _observation(source_target)
    store = InMemoryProbeObservationStore({current.camera_id: current})

    assert store.record_if_current(observation) is True
    assert store.latest_for((current.camera_id,)) == {current.camera_id: observation}
    store.set_current_target(
        replace(
            current,
            node_runtime=replace(NODE_RUNTIME, process_start_ticks=9_999),
        )
    )
    assert store.latest_for((current.camera_id,)) == {current.camera_id: observation}


def test_observation_visibility_ignores_dynamic_admission_snapshot_in_both_adapters() -> None:
    target = _target(1)
    observation = _observation(target)
    store = InMemoryProbeObservationStore({target.camera_id: target})
    assert store.record_if_current(observation) is True

    store.set_current_target(replace(target, occupied=True, source_pull_active=True))

    assert store.latest_for((target.camera_id,)) == {target.camera_id: observation}


def test_observation_store_rejects_a_result_that_was_never_probe_eligible() -> None:
    occupied = _target(1, occupied=True)
    observation = replace(
        _observation(_target(1)),
        target=occupied,
        method=ProbeMethod.PATH,
    )
    store = InMemoryProbeObservationStore({occupied.camera_id: occupied})

    with pytest.raises(ProbeIneligible, match="camera_occupied"):
        store.record_if_current(observation)

    assert store.latest_for((occupied.camera_id,)) == {}


def test_health_state_uses_hysteresis_without_treating_overload_as_failure() -> None:
    target = _target(1)
    health = ProbeHealthRecord.for_target(target, method=ProbeMethod.SOURCE)
    assert health.health_state is ProbeHealthState.UNKNOWN
    assert (
        health.observation_state(
            now=NOW,
            configured_interval=timedelta(minutes=5),
        )
        is ProbeObservationState.OVERDUE
    )

    first_failure = replace(
        _observation(target),
        outcome=ProbeOutcome.UNHEALTHY,
        failure_class=ProbeFailureClass.TRANSPORT,
        video_codec=None,
        audio_codec=None,
    )
    health = health.observe_deep(first_failure, confirmation_spacing=timedelta(seconds=30))
    assert health.health_state is ProbeHealthState.SUSPECT
    assert health.consecutive_failures == 1

    inconclusive = replace(
        first_failure,
        observation_id=UUID("50000000-0000-4000-8000-000000000098"),
        request_id=UUID("30000000-0000-4000-8000-000000000098"),
        outcome=ProbeOutcome.INCONCLUSIVE,
        failure_class=ProbeFailureClass.EXECUTOR,
        started_at=NOW + timedelta(seconds=10),
        completed_at=NOW + timedelta(seconds=11),
    )
    assert (
        health.observe_deep(inconclusive, confirmation_spacing=timedelta(seconds=30))
        == health
    )
    with pytest.raises(ValueError, match="probe_health_observation_invalid"):
        health.observe_deep(
            replace(inconclusive, method=ProbeMethod.PATH),
            confirmation_spacing=timedelta(seconds=30),
        )

    second_failure = replace(
        first_failure,
        observation_id=UUID("50000000-0000-4000-8000-000000000099"),
        request_id=UUID("30000000-0000-4000-8000-000000000099"),
        started_at=NOW + timedelta(seconds=31),
        completed_at=NOW + timedelta(seconds=32),
    )
    health = health.observe_deep(second_failure, confirmation_spacing=timedelta(seconds=30))
    assert health.health_state is ProbeHealthState.UNHEALTHY

    first_recovery = replace(
        second_failure,
        observation_id=UUID("50000000-0000-4000-8000-000000000100"),
        request_id=UUID("30000000-0000-4000-8000-000000000100"),
        outcome=ProbeOutcome.HEALTHY,
        failure_class=None,
        video_codec="h264",
        started_at=NOW + timedelta(seconds=62),
        completed_at=NOW + timedelta(seconds=63),
    )
    health = health.observe_deep(first_recovery, confirmation_spacing=timedelta(seconds=30))
    assert health.health_state is ProbeHealthState.RECOVERING

    second_recovery = replace(
        first_recovery,
        observation_id=UUID("50000000-0000-4000-8000-000000000101"),
        request_id=UUID("30000000-0000-4000-8000-000000000101"),
        started_at=NOW + timedelta(seconds=93),
        completed_at=NOW + timedelta(seconds=94),
    )
    health = health.observe_deep(second_recovery, confirmation_spacing=timedelta(seconds=30))
    assert health.health_state is ProbeHealthState.HEALTHY
    assert (
        health.observation_state(
            now=NOW + timedelta(minutes=12),
            configured_interval=timedelta(minutes=5),
        )
        is ProbeObservationState.OVERDUE
    )
    assert health.health_state is ProbeHealthState.HEALTHY

    reset = health.for_current_target(_target(1, desired_revision=2))
    assert reset.health_state is ProbeHealthState.UNKNOWN
    assert reset.last_observation_id is None

    path_target = _target(2, node_runtime=NODE_RUNTIME)
    path_health = ProbeHealthRecord.for_target(path_target, method=ProbeMethod.PATH)
    path_health = path_health.observe_deep(
        _observation(path_target, method=ProbeMethod.PATH),
        confirmation_spacing=timedelta(seconds=30),
    )
    assert path_health.health_state is ProbeHealthState.HEALTHY
    restarted = replace(
        path_target,
        node_runtime=replace(NODE_RUNTIME, process_start_ticks=9_999),
    )
    assert path_health.for_current_target(restarted).health_state is ProbeHealthState.UNKNOWN


def test_postgres_observation_store_round_trips_only_current_generation(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    target = _target(1)
    _seed_probe_target(postgres_database_url, target)
    observation = _observation(
        target,
        started_at=_database_now(postgres_database_url) - timedelta(seconds=2),
    )
    store = _postgres_store(postgres_database_url)
    try:
        assert store.record_if_current(observation) is True
        assert store.record_if_current(observation) is True
        assert store.latest_for((target.camera_id,)) == {target.camera_id: observation}

        engine = create_engine(postgres_database_url)
        with engine.begin() as connection:
            connection.execute(
                text(
                    "UPDATE camera_placements SET generation=generation+1 "
                    "WHERE camera_id=:camera_id"
                ),
                {"camera_id": target.camera_id},
            )
        assert store.record_if_current(observation) is False
        assert store.latest_for((target.camera_id,)) == {}
    finally:
        store.close()


def test_postgres_endpoint_remains_admitted_across_non_source_revisions(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    first_target = _target(1)
    _seed_probe_target(postgres_database_url, first_target)
    engine = create_engine(postgres_database_url)
    with engine.begin() as connection:
        connection.execute(
            text(
                "UPDATE cameras SET name='renamed', desired_revision=2, "
                "applied_revision=2 WHERE id=:camera_id"
            ),
            {"camera_id": first_target.camera_id},
        )
    revised_target = replace(first_target, desired_revision=2)
    revised_observation = _observation(
        revised_target,
        started_at=_database_now(postgres_database_url) - timedelta(seconds=2),
    )
    store = _postgres_store(postgres_database_url)
    try:
        assert store.record_if_current(revised_observation) is True
        assert store.latest_for((first_target.camera_id,)) == {
            first_target.camera_id: revised_observation
        }

        with engine.begin() as connection:
            connection.execute(
                text(
                    "UPDATE cameras SET desired_revision=3, applied_revision=3 "
                    "WHERE id=:camera_id"
                ),
                {"camera_id": first_target.camera_id},
            )
            connection.execute(
                text(
                    "UPDATE camera_placements SET generation=2 "
                    "WHERE camera_id=:camera_id"
                ),
                {"camera_id": first_target.camera_id},
            )
        moved_target = replace(
            first_target,
            desired_revision=3,
            placement_generation=2,
        )
        moved_observation = replace(
            _observation(
                moved_target,
                started_at=_database_now(postgres_database_url) - timedelta(seconds=2),
            ),
            observation_id=UUID("50000000-0000-4000-8000-000000000121"),
            request_id=UUID("30000000-0000-4000-8000-000000000121"),
        )
        assert store.record_if_current(moved_observation) is True
        assert store.latest_for((first_target.camera_id,)) == {
            first_target.camera_id: moved_observation
        }
    finally:
        store.close()


def test_postgres_endpoint_policy_change_invalidates_existing_admission(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    target = _target(1)
    _seed_probe_target(postgres_database_url, target)
    observation = _observation(
        target,
        started_at=_database_now(postgres_database_url) - timedelta(seconds=2),
    )
    changed_policy = PostgresProbeObservationStore(
        postgres_database_url,
        source_policy_sha256="c" * 64,
    )
    try:
        assert changed_policy.record_if_current(observation) is False
        assert changed_policy.latest_for((target.camera_id,)) == {}
    finally:
        changed_policy.close()


def test_postgres_observation_replay_is_immutable_and_future_time_is_rejected(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    target = _target(1)
    _seed_probe_target(postgres_database_url, target)
    database_now = _database_now(postgres_database_url)
    observation = _observation(target, started_at=database_now - timedelta(seconds=2))
    store = _postgres_store(postgres_database_url)
    try:
        assert store.record_if_current(observation) is True
        assert store.record_if_current(replace(observation, video_codec="h265")) is False
        future = replace(
            observation,
            observation_id=UUID("50000000-0000-4000-8000-000000000088"),
            request_id=UUID("30000000-0000-4000-8000-000000000088"),
            started_at=database_now + timedelta(days=1),
            completed_at=database_now + timedelta(days=1, seconds=1),
        )
        assert store.record_if_current(future) is False
        assert store.latest_for((target.camera_id,)) == {target.camera_id: observation}
    finally:
        store.close()


def test_postgres_exact_replay_remains_idempotent_after_timestamp_window(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    target = _target(1)
    _seed_probe_target(postgres_database_url, target)
    observation = _observation(
        target,
        started_at=_database_now(postgres_database_url) - timedelta(seconds=2),
    )
    store = _postgres_store(postgres_database_url)
    try:
        assert store.record_if_current(observation) is True
        engine = create_engine(postgres_database_url)
        with engine.begin() as connection:
            connection.execute(
                text(
                    "UPDATE probe_observations SET started_at=started_at-INTERVAL '10 minutes', "
                    "completed_at=completed_at-INTERVAL '10 minutes' "
                    "WHERE observation_id=:observation_id"
                ),
                {"observation_id": observation.observation_id},
            )
        stale_replay = replace(
            observation,
            started_at=observation.started_at - timedelta(minutes=10),
            completed_at=observation.completed_at - timedelta(minutes=10),
        )
        assert store.record_if_current(stale_replay) is True
    finally:
        store.close()


def test_probe_store_readiness_rejects_schema_drift(postgres_database_url: str) -> None:
    upgrade_database(postgres_database_url)
    store = _postgres_store(postgres_database_url)
    try:
        store.assert_ready()
        engine = create_engine(postgres_database_url)
        with engine.begin() as connection:
            connection.execute(
                text(
                    "ALTER TABLE probe_observations DROP CONSTRAINT "
                    "ck_probe_observations_result"
                )
            )
        with pytest.raises(
            RuntimeError,
            match="probe_observation_schema_incompatible",
        ):
            store.assert_ready()
        with engine.begin() as connection:
            connection.execute(
                text(
                    "ALTER TABLE probe_observations ADD CONSTRAINT "
                    "ck_probe_observations_result CHECK (true)"
                )
            )
        with pytest.raises(
            RuntimeError,
            match="probe_observation_schema_incompatible",
        ):
            store.assert_ready()
    finally:
        store.close()


def test_probe_store_readiness_rejects_same_named_wrong_index(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    engine = create_engine(postgres_database_url)
    with engine.begin() as connection:
        connection.execute(text("DROP INDEX ix_probe_observations_camera_completed"))
        connection.execute(
            text(
                "CREATE INDEX ix_probe_observations_camera_completed "
                "ON probe_observations (started_at)"
            )
        )
    store = _postgres_store(postgres_database_url)
    try:
        with pytest.raises(
            RuntimeError,
            match="probe_observation_schema_incompatible",
        ):
            store.assert_ready()
    finally:
        store.close()


def test_health_generation_uses_pinned_primitive_encoding() -> None:
    expected = (
        b'["probe-health-v1","20000000000040008000000000000001",'
        b'"aaaaaaaaaaaaaaaaaaaaaaaaaa","10000000000040008000000000000001",'
        b'1,1,"70000000000040008000000000000001"]'
    )
    assert _health_generation_sha256(_target(1), ProbeMethod.SOURCE) == (
        hashlib.sha256(expected).hexdigest()
    )


def test_maximum_profile_confirmation_interval_is_accepted_by_health_persistence(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    target = _target(1)
    _seed_probe_target(postgres_database_url, target)
    profile = CameraProbeProfile(
        enabled=True, routine_interval=timedelta(hours=2),
        confirmation_interval=timedelta(hours=1),
    )
    observation = _observation(
        target, started_at=_database_now(postgres_database_url) - timedelta(seconds=2),
    )
    store = _postgres_store(postgres_database_url)
    try:
        assert store.record_if_current(
            observation, confirmation_spacing=profile.confirmation_interval,
        )
        assert store.health_for(target, method=ProbeMethod.SOURCE).health_state is (
            ProbeHealthState.HEALTHY
        )
    finally:
        store.close()


def test_health_state_is_atomic_durable_idempotent_and_ignores_inconclusive(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    target = _target(1)
    _seed_probe_target(postgres_database_url, target)
    started = _database_now(postgres_database_url) - timedelta(seconds=120)
    failed = replace(
        _observation(target, started_at=started),
        outcome=ProbeOutcome.UNHEALTHY,
        failure_class=ProbeFailureClass.AUTHENTICATION,
        video_codec=None,
        audio_codec=None,
    )
    second = replace(
        failed,
        observation_id=uuid4(),
        request_id=uuid4(),
        started_at=failed.started_at + timedelta(seconds=31),
        completed_at=failed.completed_at + timedelta(seconds=31),
    )
    spacing = timedelta(seconds=30)
    store = _postgres_store(postgres_database_url)
    try:
        store.assert_health_ready()
        assert store.record_if_current(failed, confirmation_spacing=spacing)
        assert store.health_for(target, method=ProbeMethod.SOURCE).health_state is (
            ProbeHealthState.SUSPECT
        )
        assert store.record_if_current(second, confirmation_spacing=spacing)
        confirmed = store.health_for(target, method=ProbeMethod.SOURCE)
        assert confirmed.health_state is ProbeHealthState.UNHEALTHY
        assert confirmed.consecutive_failures == 2
        assert store.record_if_current(second, confirmation_spacing=spacing)
        assert store.health_for(target, method=ProbeMethod.SOURCE) == confirmed
        inconclusive = replace(
            second,
            observation_id=uuid4(),
            request_id=uuid4(),
            started_at=second.started_at + timedelta(seconds=31),
            completed_at=second.completed_at + timedelta(seconds=31),
            outcome=ProbeOutcome.INCONCLUSIVE,
            failure_class=ProbeFailureClass.EXECUTOR,
        )
        assert store.record_if_current(inconclusive, confirmation_spacing=spacing)
        assert store.health_for(target, method=ProbeMethod.SOURCE) == confirmed
    finally:
        store.close()
    restarted = _postgres_store(postgres_database_url)
    try:
        assert restarted.health_for(target, method=ProbeMethod.SOURCE) == confirmed
        assert restarted.health_for(target, method=ProbeMethod.PATH).health_state is (
            ProbeHealthState.UNKNOWN
        )
        changed = replace(target, desired_revision=target.desired_revision + 1)
        assert restarted.health_for(changed, method=ProbeMethod.SOURCE).health_state is (
            ProbeHealthState.UNKNOWN
        )
    finally:
        restarted.close()


def test_health_readiness_rejects_weakened_constraints(postgres_database_url: str) -> None:
    upgrade_database(postgres_database_url)
    engine = create_engine(postgres_database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text("ALTER TABLE probe_health_states DROP CONSTRAINT ck_probe_health_counters")
            )
            connection.execute(
                text(
                    "ALTER TABLE probe_health_states "
                    "ADD CONSTRAINT ck_probe_health_counters CHECK (true)"
                )
            )
    finally:
        engine.dispose()
    store = _postgres_store(postgres_database_url)
    try:
        with pytest.raises(ProbeObservationUnavailable, match="probe_health_schema_incompatible"):
            store.assert_health_ready()
    finally:
        store.close()


def test_health_write_failure_rolls_back_observation_in_same_transaction(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    target = _target(1)
    _seed_probe_target(postgres_database_url, target)
    observation = _observation(
        target,
        started_at=_database_now(postgres_database_url) - timedelta(seconds=2),
    )
    engine = create_engine(postgres_database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "ALTER TABLE probe_health_states ADD CONSTRAINT test_reject_write CHECK (false)"
                )
            )
    finally:
        engine.dispose()
    store = _postgres_store(postgres_database_url)
    try:
        with pytest.raises(
            ProbeObservationUnavailable, match="probe_observation_store_unavailable"
        ):
            store.record_if_current(observation, confirmation_spacing=timedelta(seconds=30))
        assert store.latest_for((target.camera_id,)) == {}
        assert store.health_for(target, method=ProbeMethod.SOURCE).health_state is (
            ProbeHealthState.UNKNOWN
        )
    finally:
        store.close()


def test_inconclusive_executor_result_is_persisted_without_camera_failure_claim(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    target = _target(1)
    _seed_probe_target(postgres_database_url, target)
    observation = replace(
        _observation(
            target,
            started_at=_database_now(postgres_database_url) - timedelta(seconds=2),
        ),
        outcome=ProbeOutcome.INCONCLUSIVE,
        failure_class=ProbeFailureClass.EXECUTOR,
        video_codec=None,
        audio_codec=None,
    )
    store = _postgres_store(postgres_database_url)
    try:
        assert store.record_if_current(observation) is True
        assert store.latest_for((target.camera_id,)) == {target.camera_id: observation}
    finally:
        store.close()


def test_path_observation_is_fenced_by_exact_node_runtime_generation(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    target = _target(1, node_runtime=NODE_RUNTIME)
    _seed_probe_target(postgres_database_url, target)
    observation = _observation(
        target,
        method=ProbeMethod.PATH,
        started_at=_database_now(postgres_database_url) - timedelta(seconds=2),
    )
    store = _postgres_store(postgres_database_url)
    try:
        assert store.record_if_current(observation) is True
        assert store.latest_for((target.camera_id,)) == {target.camera_id: observation}

        engine = create_engine(postgres_database_url)
        with engine.begin() as connection:
            connection.execute(
                text(
                    "UPDATE media_nodes SET process_start_ticks=process_start_ticks+1 "
                    "WHERE id=:node_id"
                ),
                {"node_id": target.node_id},
            )
        assert store.record_if_current(observation) is False
        assert store.latest_for((target.camera_id,)) == {}
    finally:
        store.close()


def test_probe_observation_schema_never_persists_source_or_secret_material(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    engine = create_engine(postgres_database_url)
    with engine.connect() as connection:
        columns = set(
            connection.scalars(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema='public' AND table_name='probe_observations'"
                )
            )
        )
    assert columns
    assert not columns.intersection({"source_url", "password", "secret", "username", "source_ip"})


def test_camera_create_and_update_atomically_persist_new_endpoint_generations(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    _seed_probe_target(postgres_database_url, _target(1))
    engine = create_engine(postgres_database_url)
    with engine.begin() as connection:
        connection.execute(
            text(
                "UPDATE media_nodes SET management_observed_at=clock_timestamp() "
                "WHERE id=:node_id"
            ),
            {"node_id": NODE_A},
        )
    generations = iter(
        (
            UUID("70000000-0000-4000-8000-000000000010"),
            UUID("70000000-0000-4000-8000-000000000011"),
            UUID("70000000-0000-4000-8000-000000000012"),
        )
    )
    admission = ProbeEndpointAdmission(
        site_key="site-a",
        allowed_networks=(ip_network("10.40.0.0/24"),),
        resolve=lambda hostname: {
            "camera-a.example": ("10.40.0.11",),
            "camera-b.example": ("10.40.0.12",),
        }[hostname],
        new_generation=generations.__next__,
    )
    store = PostgresNodeStore(postgres_database_url)
    camera_id = UUID("20000000-0000-4000-8000-000000000010")
    try:
        source_url = "rtsp://camera-a.example/live"
        created = store.place_camera_manually(
            camera_id=camera_id,
            name="endpoint-camera",
            source_url=source_url,
            public_id=PublicId.parse("b" * 25 + "a"),
            node_id=NODE_A,
            probe_endpoint=admission.admit(source_url),
        )
        assert created.probe_endpoint is not None
        assert created.probe_endpoint.generation == UUID(
            "70000000-0000-4000-8000-000000000010"
        )
        assert str(created.probe_endpoint.address) == "10.40.0.11"
        assert created.probe_endpoint.site_key == "site-a"
        assert created.probe_endpoint.policy_sha256 == admission.policy_sha256

        replacement_url = "rtsp://camera-b.example/live"
        updated = store.update_camera(
            camera_id,
            name=created.name,
            source_url=replacement_url,
            expected_revision=created.desired_revision,
            probe_endpoint=admission.admit(replacement_url),
        )
        assert updated.probe_endpoint is not None
        assert updated.probe_endpoint.generation == UUID(
            "70000000-0000-4000-8000-000000000011"
        )
        assert str(updated.probe_endpoint.address) == "10.40.0.12"

        rotated_admission = ProbeEndpointAdmission(
            site_key="site-b",
            allowed_networks=(ip_network("10.40.0.0/24"),),
            resolve=lambda _hostname: ("10.40.0.12",),
            new_generation=generations.__next__,
        )
        control = CameraControl(
            store=store,
            new_camera_id=lambda: UUID("20000000-0000-4000-8000-000000000011"),
            new_public_id=lambda: "d" * 25 + "e",
            probe_endpoint_admission=rotated_admission,
        )
        readmitted = control.update_camera(
            camera_id,
            name=updated.name,
            source_url=updated.source_url,
            expected_revision=updated.desired_revision,
        )
        assert readmitted.desired_revision == updated.desired_revision + 1
        assert readmitted.probe_endpoint is not None
        assert readmitted.probe_endpoint.generation == UUID(
            "70000000-0000-4000-8000-000000000012"
        )
        assert readmitted.probe_endpoint.site_key == "site-b"
        assert readmitted.probe_endpoint.policy_sha256 == rotated_admission.policy_sha256
    finally:
        store.close()


def test_previous_schema_rejects_validated_endpoint_writes_without_partial_camera(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    target = _target(1)
    _seed_probe_target(postgres_database_url, target)
    engine = create_engine(postgres_database_url)
    with engine.begin() as connection:
        connection.execute(
            text(
                "UPDATE media_nodes SET management_observed_at=clock_timestamp() "
                "WHERE id=:node_id"
            ),
            {"node_id": target.node_id},
        )
        connection.execute(
            text(
                "UPDATE cameras SET source_url='rtsp://10.40.0.10/live' "
                "WHERE id=:camera_id"
            ),
            {"camera_id": target.camera_id},
        )
    migration = Config("alembic.ini")
    migration.set_main_option("sqlalchemy.url", postgres_database_url)
    command.downgrade(migration, "0019_dashboard_rate_limits")
    admission = ProbeEndpointAdmission(
        site_key="site-a",
        allowed_networks=(ip_network("192.0.2.0/24"),),
        resolve=lambda _hostname: ("192.0.2.11",),
    )
    source_url = "rtsp://camera-new.example/live"
    store = PostgresNodeStore(postgres_database_url)
    try:
        with pytest.raises(
            ProbeEndpointSchemaUnavailable,
            match="probe_endpoint_schema_unavailable",
        ):
            store.place_camera_manually(
                camera_id=UUID("20000000-0000-4000-8000-000000000099"),
                name="must-not-persist",
                source_url=source_url,
                public_id=PublicId.parse("c" * 25 + "e"),
                node_id=target.node_id,
                probe_endpoint=admission.admit(source_url),
            )
        with engine.connect() as connection:
            assert connection.scalar(
                text("SELECT count(*) FROM cameras WHERE name='must-not-persist'")
            ) == 0

        command.upgrade(migration, "head")
        recovery_admission = ProbeEndpointAdmission(
            site_key="site-a",
            allowed_networks=(ip_network("10.40.0.0/24"),),
            resolve=lambda _hostname: (),
        )
        control = CameraControl(
            store=store,
            new_camera_id=lambda: UUID("20000000-0000-4000-8000-000000000098"),
            new_public_id=lambda: "e" * 25 + "e",
            probe_endpoint_admission=recovery_admission,
        )
        recovered = control.update_camera(
            target.camera_id,
            name="probe-camera",
            source_url="rtsp://10.40.0.10/live",
            expected_revision=target.desired_revision,
        )
        assert recovered.desired_revision == target.desired_revision + 1
        assert recovered.probe_endpoint is not None
        assert recovered.probe_endpoint.site_key == "site-a"
    finally:
        store.close()


def test_previous_schema_public_name_update_does_not_require_endpoint_readmission(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    target = _target(1)
    _seed_probe_target(postgres_database_url, target)
    migration = Config("alembic.ini")
    migration.set_main_option("sqlalchemy.url", postgres_database_url)
    command.downgrade(migration, "0019_dashboard_rate_limits")
    admission = ProbeEndpointAdmission(
        site_key="site-a",
        allowed_networks=(),
        resolve=lambda _hostname: (),
    )
    store = PostgresNodeStore(postgres_database_url)
    camera_control = CameraControl(
        store=store,
        new_camera_id=lambda: UUID("20000000-0000-4000-8000-000000000099"),
        new_public_id=lambda: "e" * 25 + "e",
        probe_endpoint_admission=admission,
    )
    mutations = CameraMutationControl(
        store=store,
        media_nodes=cast(Any, object()),
        confirmations=ConfirmationTokenService(
            secret=b"test-confirmation-secret-that-is-at-least-32-bytes",
            lifetime_seconds=30,
        ),
        probe_endpoint_admission=admission,
    )
    try:
        with TestClient(
            create_app(
                Settings(role=RuntimeRole.WEB),
                camera_control=camera_control,
                camera_mutation_control=mutations,
            )
        ) as client:
            response = client.put(
                f"/api/v1/cameras/{target.camera_id}",
                json={
                    "name": "renamed-during-bridge",
                    "source_url": "rtsp://192.0.2.10/live",
                    "expected_revision": target.desired_revision,
                },
            )

        assert response.status_code == 200
        assert response.json()["name"] == "renamed-during-bridge"
        assert response.json()["desired_revision"] == target.desired_revision + 1
    finally:
        store.close()


def test_probe_observation_schema_rejects_a_result_longer_than_executor_budget(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    target = _target(1)
    _seed_probe_target(postgres_database_url, target)
    observation = _observation(
        target,
        started_at=_database_now(postgres_database_url) - timedelta(seconds=2),
    )
    store = _postgres_store(postgres_database_url)
    try:
        assert store.record_if_current(observation) is True
    finally:
        store.close()

    engine = create_engine(postgres_database_url)
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(
            text(
                "UPDATE probe_observations "
                "SET completed_at=started_at + INTERVAL '61 seconds' "
                "WHERE observation_id=:observation_id"
            ),
            {"observation_id": observation.observation_id},
        )


def test_probe_observation_schema_rejects_an_ineligible_path_snapshot(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    target = _target(1)
    _seed_probe_target(postgres_database_url, target)
    observation = _observation(
        target,
        started_at=_database_now(postgres_database_url) - timedelta(seconds=2),
    )
    store = _postgres_store(postgres_database_url)
    try:
        assert store.record_if_current(observation) is True
    finally:
        store.close()

    engine = create_engine(postgres_database_url)
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(
            text(
                "UPDATE probe_observations "
                "SET method='path', target_occupied=true "
                "WHERE observation_id=:observation_id"
            ),
            {"observation_id": observation.observation_id},
        )


def _observation(
    target: ProbeTarget,
    *,
    method: ProbeMethod = ProbeMethod.SOURCE,
    started_at: datetime = NOW,
) -> ProbeObservation:
    scheduler = _scheduler(global_limit=1, per_node_limit=1, per_site_limit=1)
    scheduler.submit(
        target=target,
        method=method,
        priority=ProbePriority.MANUAL,
        requested_at=started_at,
        deadline_at=started_at + timedelta(minutes=1),
    )
    return scheduler.complete(
        _claim(scheduler, started_at, target)[0],
        ProbeExecutionResult(
            outcome=ProbeOutcome.HEALTHY,
            completed_at=started_at + timedelta(seconds=1),
            video_codec="h264",
            audio_codec="opus",
        ),
    )


def _database_now(database_url: str) -> datetime:
    engine = create_engine(database_url)
    with engine.connect() as connection:
        observed = connection.scalar(text("SELECT clock_timestamp()"))
    assert isinstance(observed, datetime)
    assert observed.tzinfo is not None
    return observed


def _postgres_store(database_url: str) -> PostgresProbeObservationStore:
    return PostgresProbeObservationStore(
        database_url,
        source_policy_sha256=SOURCE_POLICY_SHA256,
    )


def _seed_probe_target(database_url: str, target: ProbeTarget) -> None:
    engine = create_engine(database_url)
    runtime = target.node_runtime
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO media_nodes "
                "(id, name, external_port, api_port, metrics_port, state, runtime_state, "
                "health, camera_capacity, registered_cameras, active_sources, maintenance, "
                "management_fresh, config_compatible, release_id, mediamtx_binary_sha256, "
                "desired_revision, applied_revision, process_id, process_start_ticks, "
                "process_boot_id) "
                "VALUES (:id, 'probe-node', 12000, 13000, 14000, 'running', 'running', "
                "'healthy', 100, 1, 0, :maintenance, true, true, :release_id, :digest, "
                "1, :applied_revision, :process_id, :process_start_ticks, :process_boot_id)"
            ),
            {
                "id": target.node_id,
                "maintenance": target.maintenance,
                "digest": "a" * 64,
                "release_id": "0.2.1" if runtime is None else runtime.release_id,
                "applied_revision": (
                    1 if runtime is None else runtime.node_applied_revision
                ),
                "process_id": None if runtime is None else runtime.process_id,
                "process_start_ticks": (
                    None if runtime is None else runtime.process_start_ticks
                ),
                "process_boot_id": None if runtime is None else runtime.process_boot_id,
            },
        )
        connection.execute(
            text(
                "INSERT INTO cameras "
                "(id, name, source_url, public_id, state, desired_revision, applied_revision) "
                "VALUES (:id, 'probe-camera', 'rtsp://192.0.2.10/live', :public_id, "
                "'enabled', :revision, :revision)"
            ),
            {
                "id": target.camera_id,
                "public_id": str(target.public_id),
                "revision": target.desired_revision,
            },
        )
        connection.execute(
            text(
                "INSERT INTO camera_probe_endpoints "
                "(camera_id, admitted_revision, endpoint_generation, endpoint_address, "
                "endpoint_port, site_key, policy_sha256, source_sha256) "
                "VALUES (:camera_id, :revision, :endpoint_generation, '192.0.2.10', 554, "
                ":site_key, :policy_sha256, "
                "'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')"
            ),
            {
                "camera_id": target.camera_id,
                "revision": target.desired_revision,
                "endpoint_generation": target.source_endpoint_generation,
                "site_key": target.site_key,
                "policy_sha256": SOURCE_POLICY_SHA256,
            },
        )
        connection.execute(
            text("INSERT INTO public_id_tombstones (public_id) VALUES (:public_id)"),
            {"public_id": str(target.public_id)},
        )
        connection.execute(
            text(
                "INSERT INTO camera_placements "
                "(camera_id, node_id, placement_mode, generation) "
                "VALUES (:camera_id, :node_id, 'automatic', :generation)"
            ),
            {
                "camera_id": target.camera_id,
                "node_id": target.node_id,
                "generation": target.placement_generation,
            },
        )
