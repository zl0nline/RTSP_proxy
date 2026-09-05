"""Bounded routine admission from authoritative camera and health snapshots."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from uuid import UUID

from rtsp_proxy.nodes import NodeState
from rtsp_proxy.probes import (
    BoundedProbeScheduler,
    ProbeExecutionResult,
    ProbeFailureClass,
    ProbeHealthRecord,
    ProbeHealthState,
    ProbeIneligible,
    ProbeMethod,
    ProbeOutcome,
    ProbePriority,
    ProbeQueueFull,
    ProbeRequest,
    ProbeSingleFlightConflict,
    ProbeTarget,
)


@dataclass(frozen=True, slots=True)
class CameraProbeProfile:
    """Operator-owned source capacity and required decoded media, not observations."""

    enabled: bool = False
    max_source_sessions: int = 1
    require_video: bool = True
    require_audio: bool = False
    routine_interval: timedelta = timedelta(minutes=5)
    confirmation_interval: timedelta = timedelta(seconds=30)
    execution_timeout: timedelta = timedelta(seconds=15)

    def __post_init__(self) -> None:
        if (
            any(
                type(value) is not bool
                for value in (
                    self.enabled,
                    self.require_video,
                    self.require_audio,
                )
            )
            or type(self.max_source_sessions) is not int
            or not 1 <= self.max_source_sessions <= 16
            or not (self.require_video or self.require_audio)
            or not isinstance(self.routine_interval, timedelta)
            or not timedelta(seconds=30) <= self.routine_interval <= timedelta(days=1)
            or not isinstance(self.confirmation_interval, timedelta)
            or not timedelta(seconds=1) <= self.confirmation_interval <= min(
                self.routine_interval, timedelta(hours=1)
            )
            or not isinstance(self.execution_timeout, timedelta)
            or not timedelta(seconds=1) <= self.execution_timeout <= timedelta(seconds=30)
        ):
            raise ValueError("camera_probe_profile_invalid")

    def classify(self, result: ProbeExecutionResult) -> ProbeExecutionResult:
        """Apply media requirements only to successfully decoded executor results."""
        if result.outcome is not ProbeOutcome.HEALTHY:
            return result
        if (self.require_video and result.video_codec is None) or (
            self.require_audio and result.audio_codec is None
        ):
            return ProbeExecutionResult(
                outcome=ProbeOutcome.UNHEALTHY,
                completed_at=result.completed_at,
                failure_class=ProbeFailureClass.CODEC,
            )
        return result


@dataclass(frozen=True, slots=True)
class RoutineProbeCandidate:
    """One current profile/target plus its generation-checked persisted health."""

    target: ProbeTarget
    profile: CameraProbeProfile
    health: ProbeHealthRecord
    last_attempt_at: datetime | None
    registered_at: datetime

    def __post_init__(self) -> None:
        if (
            not isinstance(self.target, ProbeTarget)
            or not isinstance(self.profile, CameraProbeProfile)
            or not isinstance(self.health, ProbeHealthRecord)
            or self.health.target != self.target
            or self.health.method is not ProbeMethod.SOURCE
            or not isinstance(self.registered_at, datetime)
            or self.registered_at.tzinfo is None
            or (
                self.last_attempt_at is not None
                and (
                    not isinstance(self.last_attempt_at, datetime)
                    or self.last_attempt_at.tzinfo is None
                    or self.last_attempt_at < self.registered_at
                )
            )
        ):
            raise ValueError("routine_probe_candidate_invalid")

    @property
    def priority(self) -> ProbePriority:
        if self.health.health_state in {ProbeHealthState.SUSPECT, ProbeHealthState.RECOVERING}:
            return ProbePriority.CONFIRMATION
        return ProbePriority.ROUTINE

    @property
    def due_at(self) -> datetime:
        interval = (
            self.profile.confirmation_interval
            if self.priority is ProbePriority.CONFIRMATION
            else self.profile.routine_interval
        )
        # Positive, stable jitter: never shorten confirmation spacing or reset
        # every camera's due time when a worker restarts.
        digest = hashlib.sha256(self.target.camera_id.bytes).digest()
        jitter = interval * (int.from_bytes(digest[:4], "big") / (2**32) * 0.2)
        if self.last_attempt_at is None:
            return self.registered_at + jitter
        return self.last_attempt_at + interval + jitter


class RoutineProbeProducer:
    """Feed due SOURCE work to the existing bounded/single-flight scheduler."""

    def __init__(self, scheduler: BoundedProbeScheduler, *, batch_limit: int = 256) -> None:
        if type(batch_limit) is not int or not 1 <= batch_limit <= 256:
            raise ValueError("routine_probe_batch_limit_invalid")
        self._scheduler = scheduler
        self._batch_limit = batch_limit

    def enqueue(
        self,
        candidates: Mapping[UUID, RoutineProbeCandidate],
        *,
        now: datetime,
    ) -> tuple[ProbeRequest, ...]:
        if (
            now.tzinfo is None
            or len(candidates) > self._batch_limit
            or any(camera_id != item.target.camera_id for camera_id, item in candidates.items())
        ):
            raise ValueError("routine_probe_batch_invalid")
        accepted: list[ProbeRequest] = []
        for candidate in sorted(
            candidates.values(),
            key=lambda item: (
                item.due_at,
                item.target.camera_id.int,
            ),
        ):
            if (
                not candidate.profile.enabled
                or candidate.target.node_state is not NodeState.RUNNING
                or now < candidate.due_at
            ):
                continue
            # Never infer spare upstream sessions from an observed successful pull.
            target = replace(
                candidate.target,
                max_source_sessions=candidate.profile.max_source_sessions,
            )
            try:
                accepted.append(
                    self._scheduler.submit(
                        target=target,
                        method=ProbeMethod.SOURCE,
                        priority=candidate.priority,
                        requested_at=now,
                        deadline_at=now + candidate.profile.execution_timeout,
                    )
                )
            except ProbeQueueFull:
                break
            except (ProbeIneligible, ProbeSingleFlightConflict):
                continue
        return tuple(accepted)
