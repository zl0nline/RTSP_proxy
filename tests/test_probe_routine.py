from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from rtsp_proxy.identifiers import PublicId
from rtsp_proxy.nodes import NodeState
from rtsp_proxy.probe_routine import CameraProbeProfile, RoutineProbeCandidate, RoutineProbeProducer
from rtsp_proxy.probes import (
    BoundedProbeScheduler,
    ProbeExecutionResult,
    ProbeFailureClass,
    ProbeHealthRecord,
    ProbeHealthState,
    ProbeMethod,
    ProbeOutcome,
    ProbePriority,
    ProbeTarget,
)

NOW = datetime(2026, 9, 5, tzinfo=UTC)


def _candidate(*, max_source_sessions: int = 2, **profile: object) -> RoutineProbeCandidate:
    target = ProbeTarget(
        camera_id=uuid4(),
        public_id=PublicId("a" * 26),
        node_id=uuid4(),
        site_key="test",
        desired_revision=1,
        placement_generation=1,
        node_state=NodeState.RUNNING,
        enabled=True,
        maintenance=False,
        occupied=False,
        source_pull_active=False,
        max_source_sessions=max_source_sessions,
        source_endpoint_generation=uuid4(),
    )
    return RoutineProbeCandidate(
        target=target,
        profile=CameraProbeProfile(
            enabled=True, max_source_sessions=max_source_sessions, **profile,
        ),
        health=ProbeHealthRecord.for_target(target, method=ProbeMethod.SOURCE),
        last_attempt_at=None,
        registered_at=NOW - timedelta(hours=1),
    )


def _scheduler(*, queue_limit: int = 10) -> BoundedProbeScheduler:
    return BoundedProbeScheduler(
        global_limit=1,
        per_node_limit=1,
        per_site_limit=1,
        source_limit=1,
        path_limit=1,
        queue_limit=queue_limit,
        lease_seconds=15,
        retry_delay_seconds=5,
        max_attempts=1,
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"enabled": 1},
        {"max_source_sessions": True},
        {"max_source_sessions": 0},
        {"max_source_sessions": 17},
        {"require_video": False, "require_audio": False},
        {"require_audio": 1},
        {"routine_interval": timedelta(seconds=29)},
        {"routine_interval": timedelta(days=2)},
        {"confirmation_interval": timedelta(0)},
        {"confirmation_interval": timedelta(minutes=6)},
        {"routine_interval": timedelta(hours=2), "confirmation_interval": timedelta(hours=2)},
        {"execution_timeout": timedelta(0)},
        {"execution_timeout": timedelta(seconds=31)},
    ],
)
def test_camera_profile_rejects_invalid_configuration(changes: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="camera_probe_profile_invalid"):
        CameraProbeProfile(**changes)


def test_profile_defaults_to_disabled_and_one_upstream_session() -> None:
    profile = CameraProbeProfile()
    assert profile.enabled is False
    assert profile.max_source_sessions == 1


def test_profile_classifies_missing_required_media_without_reclassifying_infrastructure() -> None:
    profile = CameraProbeProfile(require_video=True)
    audio = ProbeExecutionResult(outcome=ProbeOutcome.HEALTHY, completed_at=NOW, audio_codec="opus")
    assert profile.classify(audio) == ProbeExecutionResult(
        outcome=ProbeOutcome.UNHEALTHY,
        completed_at=NOW,
        failure_class=ProbeFailureClass.CODEC,
    )
    audio_profile = replace(profile, require_video=False, require_audio=True)
    assert audio_profile.classify(audio) is audio
    inconclusive = ProbeExecutionResult(
        outcome=ProbeOutcome.INCONCLUSIVE,
        completed_at=NOW,
        failure_class=ProbeFailureClass.EXECUTOR,
    )
    assert profile.classify(inconclusive) is inconclusive


def test_due_time_uses_stable_positive_jitter_and_survives_producer_restart() -> None:
    candidate = replace(_candidate(), last_attempt_at=NOW)
    interval = candidate.profile.routine_interval
    assert NOW + interval <= candidate.due_at < NOW + interval * 1.2
    assert replace(candidate).due_at == candidate.due_at
    scheduler = _scheduler()
    assert (
        RoutineProbeProducer(scheduler).enqueue(
            {candidate.target.camera_id: candidate},
            now=NOW,
        )
        == ()
    )
    (request,) = RoutineProbeProducer(scheduler).enqueue(
        {candidate.target.camera_id: candidate},
        now=candidate.due_at,
    )
    assert request.priority is ProbePriority.ROUTINE


@pytest.mark.parametrize("state", [ProbeHealthState.SUSPECT, ProbeHealthState.RECOVERING])
def test_unconfirmed_transition_gets_confirmation_priority_with_minimum_spacing(
    state: ProbeHealthState,
) -> None:
    candidate = _candidate()
    candidate = replace(
        candidate,
        last_attempt_at=NOW,
        health=replace(
            candidate.health,
            health_state=state,
        ),
    )
    interval = candidate.profile.confirmation_interval
    assert NOW + interval <= candidate.due_at < NOW + interval * 1.2
    (request,) = RoutineProbeProducer(_scheduler()).enqueue(
        {candidate.target.camera_id: candidate},
        now=candidate.due_at,
    )
    assert request.priority is ProbePriority.CONFIRMATION


@pytest.mark.parametrize("state", [NodeState.FAILED, NodeState.STOPPED])
def test_unavailable_node_suppresses_routine_probe_storms(state: NodeState) -> None:
    candidate = _candidate()
    target = replace(candidate.target, node_state=state)
    candidate = replace(candidate, target=target, health=replace(candidate.health, target=target))
    assert (
        RoutineProbeProducer(_scheduler()).enqueue(
            {target.camera_id: candidate},
            now=NOW,
        )
        == ()
    )


def test_disabled_profile_and_active_single_session_source_do_not_submit() -> None:
    candidate = _candidate(max_source_sessions=1)
    target = replace(candidate.target, source_pull_active=True, occupied=True)
    candidate = replace(candidate, target=target, health=replace(candidate.health, target=target))
    producer = RoutineProbeProducer(_scheduler())
    assert producer.enqueue({target.camera_id: candidate}, now=NOW) == ()
    candidate = replace(candidate, profile=replace(candidate.profile, enabled=False))
    assert producer.enqueue({target.camera_id: candidate}, now=NOW) == ()


@pytest.mark.parametrize("active", [False, True])
def test_single_session_profile_never_queues_a_routine_probe(active: bool) -> None:
    candidate = _candidate(max_source_sessions=1)
    target = replace(candidate.target, source_pull_active=active, occupied=active)
    candidate = replace(candidate, target=target, health=replace(candidate.health, target=target))
    scheduler = _scheduler()
    assert RoutineProbeProducer(scheduler).enqueue({target.camera_id: candidate}, now=NOW) == ()
    assert scheduler.diagnostics().queued == 0
    assert candidate.health.health_state is ProbeHealthState.UNKNOWN
    assert candidate.last_attempt_at is None


def test_producer_preserves_scheduler_single_flight_and_bounded_queue() -> None:
    first, second = _candidate(), _candidate()
    candidates = {item.target.camera_id: item for item in (first, second)}
    scheduler = _scheduler(queue_limit=1)
    producer = RoutineProbeProducer(scheduler)
    requests = producer.enqueue(candidates, now=NOW)
    assert len(requests) == 1
    assert producer.enqueue(candidates, now=NOW) == requests
    selected = requests[0].target
    (lease,) = scheduler.claim_available(NOW, {selected.camera_id: selected})
    assert lease.target == selected


def test_candidate_rejects_mismatched_health_and_producer_rejects_unbounded_input() -> None:
    candidate, another = _candidate(), _candidate()
    with pytest.raises(ValueError, match="routine_probe_candidate_invalid"):
        replace(candidate, health=another.health)
    with pytest.raises(ValueError, match="routine_probe_candidate_invalid"):
        replace(candidate, registered_at=NOW.replace(tzinfo=None))
    with pytest.raises(ValueError, match="routine_probe_batch_invalid"):
        RoutineProbeProducer(_scheduler(), batch_limit=1).enqueue(
            {candidate.target.camera_id: candidate, another.target.camera_id: another},
            now=NOW,
        )
