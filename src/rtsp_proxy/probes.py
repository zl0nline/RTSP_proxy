from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import StrEnum
from threading import RLock
from typing import Protocol
from uuid import UUID, uuid4

from sqlalchemy import bindparam, create_engine, text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import SQLAlchemyError

from rtsp_proxy.identifiers import PublicId
from rtsp_proxy.nodes import NodeState

_SITE_KEY = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_CODEC_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")
_RELEASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class ProbeMethod(StrEnum):
    SOURCE = "source"
    PATH = "path"


class ProbePriority(StrEnum):
    MANUAL = "manual"
    CONFIRMATION = "confirmation"
    ROUTINE = "routine"


_FAIR_PRIORITIES = (
    *(ProbePriority.MANUAL for _ in range(4)),
    *(ProbePriority.CONFIRMATION for _ in range(3)),
    *(ProbePriority.ROUTINE for _ in range(3)),
)
_PRIORITY_WEIGHTS = {
    ProbePriority.MANUAL: 4,
    ProbePriority.CONFIRMATION: 3,
    ProbePriority.ROUTINE: 3,
}
_PRIORITY_RANK = {
    ProbePriority.MANUAL: 3,
    ProbePriority.CONFIRMATION: 2,
    ProbePriority.ROUTINE: 1,
}


class ProbeOutcome(StrEnum):
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    INCONCLUSIVE = "inconclusive"


class ProbeHealthState(StrEnum):
    UNKNOWN = "unknown"
    HEALTHY = "healthy"
    SUSPECT = "suspect"
    UNHEALTHY = "unhealthy"
    RECOVERING = "recovering"


class ProbeObservationState(StrEnum):
    FRESH = "fresh"
    STALE = "stale"
    OVERDUE = "overdue"


class ProbeFailureClass(StrEnum):
    AUTHENTICATION = "authentication"
    CODEC = "codec"
    CONNECT_TIMEOUT = "connect_timeout"
    EXECUTOR = "executor"
    OUTPUT = "output"
    TRANSPORT = "transport"


_CAMERA_FAILURE_CLASSES = frozenset(
    {
        ProbeFailureClass.AUTHENTICATION,
        ProbeFailureClass.CODEC,
        ProbeFailureClass.CONNECT_TIMEOUT,
        ProbeFailureClass.TRANSPORT,
    }
)
_INFRASTRUCTURE_FAILURE_CLASSES = frozenset(
    {ProbeFailureClass.EXECUTOR, ProbeFailureClass.OUTPUT}
)


class ProbeIneligible(RuntimeError):
    """The authoritative camera state forbids this probe."""


class ProbeQueueFull(RuntimeError):
    """The bounded server probe queue has no admission capacity."""


class ProbeSingleFlightConflict(RuntimeError):
    """Another generation or method is already queued/running for the camera."""


class ProbeObservationUnavailable(RuntimeError):
    """The durable latest-result store is unavailable or inconsistent."""


@dataclass(frozen=True, slots=True)
class ProbeNodeRuntimeGeneration:
    node_applied_revision: int
    process_id: int
    process_start_ticks: int
    process_boot_id: UUID
    release_id: str

    def __post_init__(self) -> None:
        if (
            self.node_applied_revision < 1
            or self.process_id < 1
            or self.process_start_ticks < 1
            or not isinstance(self.process_boot_id, UUID)
            or not _RELEASE_ID.fullmatch(self.release_id)
        ):
            raise ValueError("probe_node_runtime_generation_invalid")


@dataclass(frozen=True, slots=True)
class ProbeTarget:
    camera_id: UUID
    public_id: PublicId
    node_id: UUID
    site_key: str
    desired_revision: int
    placement_generation: int
    node_state: NodeState
    enabled: bool
    maintenance: bool
    occupied: bool
    source_pull_active: bool
    max_source_sessions: int
    node_runtime: ProbeNodeRuntimeGeneration | None = None
    source_endpoint_generation: UUID | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.camera_id, UUID)
            or not isinstance(self.node_id, UUID)
            or not isinstance(self.public_id, PublicId)
            or not isinstance(self.node_state, NodeState)
            or self.camera_id.version != 4
            or self.node_id.version != 4
        ):
            raise ValueError("probe_target_identity_invalid")
        if not _SITE_KEY.fullmatch(self.site_key):
            raise ValueError("probe_site_key_invalid")
        if self.desired_revision < 1 or self.placement_generation < 1:
            raise ValueError("probe_target_generation_invalid")
        if any(
            type(value) is not bool
            for value in (
                self.enabled,
                self.maintenance,
                self.occupied,
                self.source_pull_active,
            )
        ) or (not self.enabled and self.maintenance):
            raise ValueError("probe_target_state_invalid")
        if not 1 <= self.max_source_sessions <= 16:
            raise ValueError("probe_source_session_limit_invalid")
        if self.node_runtime is not None and not isinstance(
            self.node_runtime, ProbeNodeRuntimeGeneration
        ):
            raise ValueError("probe_node_runtime_generation_invalid")
        if self.source_endpoint_generation is not None and (
            not isinstance(self.source_endpoint_generation, UUID)
            or self.source_endpoint_generation.version != 4
        ):
            raise ValueError("probe_source_endpoint_generation_invalid")


@dataclass(frozen=True, slots=True)
class ProbeRequest:
    request_id: UUID
    target: ProbeTarget
    method: ProbeMethod
    priority: ProbePriority
    requested_at: datetime
    deadline_at: datetime
    available_at: datetime

    def __post_init__(self) -> None:
        if self.request_id.version != 4:
            raise ValueError("probe_request_identity_invalid")
        if (
            self.requested_at.tzinfo is None
            or self.deadline_at.tzinfo is None
            or self.available_at.tzinfo is None
            or not self.requested_at <= self.available_at < self.deadline_at
            or self.deadline_at - self.requested_at > timedelta(days=1)
        ):
            raise ValueError("probe_request_window_invalid")


@dataclass(frozen=True, slots=True)
class ProbeLease:
    request_id: UUID
    lease_token: UUID
    target: ProbeTarget
    method: ProbeMethod
    priority: ProbePriority
    started_at: datetime
    lease_expires_at: datetime
    attempt: int

    def __post_init__(self) -> None:
        if (
            self.request_id.version != 4
            or self.lease_token.version != 4
            or self.started_at.tzinfo is None
            or self.lease_expires_at.tzinfo is None
            or self.lease_expires_at <= self.started_at
            or not 1 <= self.attempt <= 10
        ):
            raise ValueError("probe_lease_invalid")


@dataclass(frozen=True, slots=True)
class ProbeExecutionResult:
    outcome: ProbeOutcome
    completed_at: datetime
    failure_class: ProbeFailureClass | None = None
    video_codec: str | None = None
    audio_codec: str | None = None

    def __post_init__(self) -> None:
        codecs = (self.video_codec, self.audio_codec)
        if (
            not isinstance(self.outcome, ProbeOutcome)
            or (
                self.failure_class is not None
                and not isinstance(self.failure_class, ProbeFailureClass)
            )
            or self.completed_at.tzinfo is None
            or any(codec is not None and not _CODEC_NAME.fullmatch(codec) for codec in codecs)
            or (
                self.outcome is ProbeOutcome.HEALTHY
                and (self.failure_class is not None or not any(codecs))
            )
            or (
                self.outcome is ProbeOutcome.UNHEALTHY
                and (self.failure_class not in _CAMERA_FAILURE_CLASSES or any(codecs))
            )
            or (
                self.outcome is ProbeOutcome.INCONCLUSIVE
                and (self.failure_class not in _INFRASTRUCTURE_FAILURE_CLASSES or any(codecs))
            )
        ):
            raise ValueError("probe_result_contract_invalid")


@dataclass(frozen=True, slots=True)
class ProbeObservation:
    observation_id: UUID
    request_id: UUID
    target: ProbeTarget
    method: ProbeMethod
    priority: ProbePriority
    outcome: ProbeOutcome
    started_at: datetime
    completed_at: datetime
    attempt: int
    failure_class: ProbeFailureClass | None = None
    video_codec: str | None = None
    audio_codec: str | None = None

    def __post_init__(self) -> None:
        if (
            self.observation_id.version != 4
            or self.request_id.version != 4
            or self.started_at.tzinfo is None
            or self.completed_at.tzinfo is None
            or self.completed_at < self.started_at
            or self.completed_at - self.started_at > timedelta(seconds=60)
            or not 1 <= self.attempt <= 10
        ):
            raise ValueError("probe_observation_invalid")
        ProbeExecutionResult(
            outcome=self.outcome,
            completed_at=self.completed_at,
            failure_class=self.failure_class,
            video_codec=self.video_codec,
            audio_codec=self.audio_codec,
        )


class ProbeObservationReader(Protocol):
    def latest_for(
        self,
        camera_ids: tuple[UUID, ...],
    ) -> Mapping[UUID, ProbeObservation]: ...


@dataclass(frozen=True, slots=True)
class ProbeHealthRecord:
    target: ProbeTarget
    method: ProbeMethod
    health_state: ProbeHealthState
    consecutive_failures: int
    consecutive_successes: int
    last_observation_id: UUID | None
    last_deep_at: datetime | None
    last_success_at: datetime | None

    def __post_init__(self) -> None:
        timestamps = (self.last_deep_at, self.last_success_at)
        if (
            not isinstance(self.method, ProbeMethod)
            or not isinstance(self.health_state, ProbeHealthState)
            or not 0 <= self.consecutive_failures <= 2
            or not 0 <= self.consecutive_successes <= 2
            or any(value is not None and value.tzinfo is None for value in timestamps)
            or (
                self.last_success_at is not None
                and self.last_deep_at is not None
                and self.last_success_at > self.last_deep_at
            )
            or (self.last_observation_id is None) != (self.last_deep_at is None)
        ):
            raise ValueError("probe_health_record_invalid")

    @classmethod
    def for_target(cls, target: ProbeTarget, *, method: ProbeMethod) -> ProbeHealthRecord:
        return cls(
            target=target,
            method=method,
            health_state=ProbeHealthState.UNKNOWN,
            consecutive_failures=0,
            consecutive_successes=0,
            last_observation_id=None,
            last_deep_at=None,
            last_success_at=None,
        )

    def for_current_target(self, target: ProbeTarget) -> ProbeHealthRecord:
        if _same_health_generation(self.target, target, self.method):
            return replace(self, target=target)
        return self.for_target(target, method=self.method)

    def observe_deep(
        self,
        observation: ProbeObservation,
        *,
        confirmation_spacing: timedelta,
    ) -> ProbeHealthRecord:
        if not timedelta(seconds=1) <= confirmation_spacing <= timedelta(hours=1):
            raise ValueError("probe_confirmation_spacing_invalid")
        if (
            not _same_health_generation(self.target, observation.target, self.method)
            or observation.method is not self.method
            or (self.last_deep_at is not None and observation.completed_at <= self.last_deep_at)
            or observation.observation_id == self.last_observation_id
        ):
            raise ValueError("probe_health_observation_invalid")
        if observation.outcome is ProbeOutcome.INCONCLUSIVE:
            return self
        spaced = self.last_deep_at is None or (
            observation.completed_at - self.last_deep_at >= confirmation_spacing
        )
        if observation.outcome is ProbeOutcome.UNHEALTHY:
            failures = min(2, self.consecutive_failures + int(spaced))
            state = (
                ProbeHealthState.UNHEALTHY
                if self.health_state in {ProbeHealthState.UNHEALTHY, ProbeHealthState.RECOVERING}
                or failures >= 2
                else ProbeHealthState.SUSPECT
            )
            return replace(
                self,
                target=observation.target,
                health_state=state,
                consecutive_failures=failures,
                consecutive_successes=0,
                last_observation_id=observation.observation_id,
                last_deep_at=observation.completed_at,
            )
        successes = min(2, self.consecutive_successes + int(spaced))
        if self.health_state in {ProbeHealthState.UNHEALTHY, ProbeHealthState.RECOVERING}:
            state = (
                ProbeHealthState.HEALTHY
                if self.health_state is ProbeHealthState.RECOVERING and successes >= 2
                else ProbeHealthState.RECOVERING
            )
        else:
            state = ProbeHealthState.HEALTHY
            successes = max(1, successes)
        return replace(
            self,
            target=observation.target,
            health_state=state,
            consecutive_failures=0,
            consecutive_successes=successes,
            last_observation_id=observation.observation_id,
            last_deep_at=observation.completed_at,
            last_success_at=observation.completed_at,
        )

    def observation_state(
        self,
        *,
        now: datetime,
        configured_interval: timedelta,
    ) -> ProbeObservationState:
        if now.tzinfo is None or not timedelta(seconds=1) <= configured_interval <= timedelta(
            days=1
        ):
            raise ValueError("probe_freshness_window_invalid")
        if self.last_success_at is None or now < self.last_success_at:
            return ProbeObservationState.OVERDUE
        age = now - self.last_success_at
        if age <= configured_interval:
            return ProbeObservationState.FRESH
        if age <= 2 * configured_interval:
            return ProbeObservationState.STALE
        return ProbeObservationState.OVERDUE


@dataclass(frozen=True, slots=True)
class ProbeSchedulerDiagnostics:
    queued: int
    active: int
    source_queued: int
    source_active: int
    path_queued: int
    path_active: int
    submitted_total: int
    completed_total: int
    expired_total: int
    rejected_total: int


class BoundedProbeScheduler:
    """One-server weighted-fair scheduler with hard node/site/session budgets."""

    def __init__(
        self,
        *,
        global_limit: int,
        per_node_limit: int,
        per_site_limit: int,
        source_limit: int,
        path_limit: int,
        queue_limit: int,
        lease_seconds: float,
        retry_delay_seconds: float,
        max_attempts: int,
        new_request_id: Callable[[], UUID] = uuid4,
        new_lease_token: Callable[[], UUID] = uuid4,
        new_observation_id: Callable[[], UUID] = uuid4,
    ) -> None:
        if not 1 <= global_limit <= 256:
            raise ValueError("probe_global_limit_invalid")
        if not 1 <= per_node_limit <= global_limit:
            raise ValueError("probe_node_limit_invalid")
        if not 1 <= per_site_limit <= global_limit:
            raise ValueError("probe_site_limit_invalid")
        if not 1 <= source_limit <= global_limit or not 1 <= path_limit <= global_limit:
            raise ValueError("probe_method_limit_invalid")
        if not 1 <= queue_limit <= 10_000:
            raise ValueError("probe_queue_limit_invalid")
        if not 0.1 <= lease_seconds <= 60:
            raise ValueError("probe_lease_seconds_invalid")
        if not 0.1 <= retry_delay_seconds <= 300:
            raise ValueError("probe_retry_delay_invalid")
        if not 1 <= max_attempts <= 10:
            raise ValueError("probe_attempt_limit_invalid")
        self._global_limit = global_limit
        self._per_node_limit = per_node_limit
        self._per_site_limit = per_site_limit
        self._method_limits = {
            ProbeMethod.SOURCE: source_limit,
            ProbeMethod.PATH: path_limit,
        }
        self._queue_limit = queue_limit
        self._lease = timedelta(seconds=lease_seconds)
        self._retry_delay = timedelta(seconds=retry_delay_seconds)
        self._max_attempts = max_attempts
        self._priority_reservations = _priority_reservations(global_limit)
        self._new_request_id = new_request_id
        self._new_lease_token = new_lease_token
        self._new_observation_id = new_observation_id
        self._requests_by_camera: dict[UUID, ProbeRequest] = {}
        self._pending: dict[ProbePriority, list[ProbeRequest]] = {
            priority: [] for priority in ProbePriority
        }
        self._active: dict[UUID, ProbeLease] = {}
        self._attempts: dict[UUID, int] = {}
        self._fair_index = 0
        self._submitted_total = 0
        self._completed_total = 0
        self._expired_total = 0
        self._rejected_total = 0
        self._lock = RLock()

    def submit(
        self,
        *,
        target: ProbeTarget,
        method: ProbeMethod,
        priority: ProbePriority,
        requested_at: datetime,
        deadline_at: datetime,
    ) -> ProbeRequest:
        _require_probe_eligible(target, method)
        if (
            requested_at.tzinfo is None
            or deadline_at.tzinfo is None
            or deadline_at <= requested_at
            or deadline_at - requested_at > timedelta(days=1)
        ):
            raise ValueError("probe_request_window_invalid")
        with self._lock:
            self._expire_active(requested_at)
            self._drop_expired_pending(requested_at)
            current = self._requests_by_camera.get(target.camera_id)
            if current is not None:
                if _same_probe_generation(current.target, target) and current.method is method:
                    if current.request_id in self._active:
                        return current
                    promoted_priority = max(
                        (current.priority, priority),
                        key=_PRIORITY_RANK.__getitem__,
                    )
                    promoted_deadline = min(current.deadline_at, deadline_at)
                    if (
                        promoted_priority is current.priority
                        and promoted_deadline == current.deadline_at
                    ):
                        return current
                    promoted = replace(
                        current,
                        target=target,
                        priority=promoted_priority,
                        deadline_at=promoted_deadline,
                    )
                    if promoted_priority is not current.priority:
                        self._pending[current.priority].remove(current)
                        self._pending[promoted_priority].append(promoted)
                    else:
                        queue = self._pending[current.priority]
                        queue[queue.index(current)] = promoted
                    self._requests_by_camera[target.camera_id] = promoted
                    return promoted
                self._rejected_total += 1
                raise ProbeSingleFlightConflict("probe_single_flight_conflict")
            if len(self._requests_by_camera) >= self._queue_limit:
                self._rejected_total += 1
                raise ProbeQueueFull("probe_queue_full")
            request = ProbeRequest(
                request_id=self._new_request_id(),
                target=target,
                method=method,
                priority=priority,
                requested_at=requested_at,
                deadline_at=deadline_at,
                available_at=requested_at,
            )
            self._requests_by_camera[target.camera_id] = request
            self._pending[priority].append(request)
            self._attempts[request.request_id] = 0
            self._submitted_total += 1
            return request

    def claim_available(
        self,
        now: datetime,
        current_targets: Mapping[UUID, ProbeTarget],
    ) -> tuple[ProbeLease, ...]:
        if now.tzinfo is None:
            raise ValueError("probe_scheduler_time_invalid")
        if (
            len(current_targets) > self._queue_limit
            or any(camera_id != target.camera_id for camera_id, target in current_targets.items())
        ):
            raise ValueError("probe_current_target_batch_invalid")
        with self._lock:
            self._expire_active(now)
            self._drop_expired_pending(now)
            admitted_camera_ids = self._refresh_pending_targets(current_targets)
            leases: list[ProbeLease] = []
            while len(self._active) < self._global_limit:
                request = self._next_eligible_request(now, admitted_camera_ids)
                if request is None:
                    break
                self._pending[request.priority].remove(request)
                attempt = self._attempts[request.request_id] + 1
                self._attempts[request.request_id] = attempt
                lease = ProbeLease(
                    request_id=request.request_id,
                    lease_token=self._new_lease_token(),
                    target=request.target,
                    method=request.method,
                    priority=request.priority,
                    started_at=now,
                    lease_expires_at=min(request.deadline_at, now + self._lease),
                    attempt=attempt,
                )
                self._active[request.request_id] = lease
                leases.append(lease)
            return tuple(leases)

    def complete(
        self,
        lease: ProbeLease,
        result: ProbeExecutionResult,
    ) -> ProbeObservation:
        with self._lock:
            current = self._active.get(lease.request_id)
            if (
                current != lease
                or result.completed_at < lease.started_at
                or result.completed_at > lease.lease_expires_at
            ):
                raise ValueError("probe_lease_invalid")
            request = self._requests_by_camera.get(lease.target.camera_id)
            if request is None or request.request_id != lease.request_id:
                raise ValueError("probe_lease_invalid")
            self._active.pop(lease.request_id)
            self._requests_by_camera.pop(lease.target.camera_id)
            self._attempts.pop(lease.request_id, None)
            self._completed_total += 1
            return ProbeObservation(
                observation_id=self._new_observation_id(),
                request_id=lease.request_id,
                target=lease.target,
                method=lease.method,
                priority=lease.priority,
                outcome=result.outcome,
                started_at=lease.started_at,
                completed_at=result.completed_at,
                attempt=lease.attempt,
                failure_class=result.failure_class,
                video_codec=result.video_codec,
                audio_codec=result.audio_codec,
            )

    def diagnostics(self) -> ProbeSchedulerDiagnostics:
        with self._lock:
            queued_by_method = {
                method: sum(
                    request.method is method
                    for queue in self._pending.values()
                    for request in queue
                )
                for method in ProbeMethod
            }
            active_by_method = {
                method: sum(lease.method is method for lease in self._active.values())
                for method in ProbeMethod
            }
            return ProbeSchedulerDiagnostics(
                queued=sum(queued_by_method.values()),
                active=sum(active_by_method.values()),
                source_queued=queued_by_method[ProbeMethod.SOURCE],
                source_active=active_by_method[ProbeMethod.SOURCE],
                path_queued=queued_by_method[ProbeMethod.PATH],
                path_active=active_by_method[ProbeMethod.PATH],
                submitted_total=self._submitted_total,
                completed_total=self._completed_total,
                expired_total=self._expired_total,
                rejected_total=self._rejected_total,
            )

    def _expire_active(self, now: datetime) -> None:
        for request_id, lease in tuple(self._active.items()):
            if lease.lease_expires_at > now:
                continue
            self._active.pop(request_id)
            self._expired_total += 1
            request = self._requests_by_camera.get(lease.target.camera_id)
            if request is None or request.request_id != request_id:
                continue
            available_at = now + self._retry_delay
            if lease.attempt >= self._max_attempts or available_at >= request.deadline_at:
                self._requests_by_camera.pop(lease.target.camera_id)
                self._attempts.pop(request_id, None)
                continue
            request = replace(request, available_at=available_at)
            self._requests_by_camera[lease.target.camera_id] = request
            self._pending[request.priority].append(request)

    def _drop_expired_pending(self, now: datetime) -> None:
        for priority, queue in self._pending.items():
            retained: list[ProbeRequest] = []
            for request in queue:
                if request.deadline_at <= now:
                    self._requests_by_camera.pop(request.target.camera_id, None)
                    self._attempts.pop(request.request_id, None)
                    self._expired_total += 1
                else:
                    retained.append(request)
            self._pending[priority] = retained

    def _refresh_pending_targets(
        self,
        current_targets: Mapping[UUID, ProbeTarget],
    ) -> frozenset[UUID]:
        admitted: set[UUID] = set()
        for priority, queue in self._pending.items():
            retained: list[ProbeRequest] = []
            for request in queue:
                current = current_targets.get(request.target.camera_id)
                if current is None:
                    retained.append(request)
                    continue
                if not _same_probe_generation(request.target, current):
                    self._requests_by_camera.pop(request.target.camera_id, None)
                    self._attempts.pop(request.request_id, None)
                    self._rejected_total += 1
                    continue
                try:
                    _require_probe_eligible(current, request.method)
                except ProbeIneligible:
                    self._requests_by_camera.pop(request.target.camera_id, None)
                    self._attempts.pop(request.request_id, None)
                    self._rejected_total += 1
                    continue
                refreshed = replace(request, target=current)
                retained.append(refreshed)
                self._requests_by_camera[current.camera_id] = refreshed
                admitted.add(current.camera_id)
            self._pending[priority] = retained
        return frozenset(admitted)

    def _next_eligible_request(
        self,
        now: datetime,
        admitted_camera_ids: frozenset[UUID],
    ) -> ProbeRequest | None:
        active_nodes: dict[UUID, int] = {}
        active_sites: dict[str, int] = {}
        active_priorities = {priority: 0 for priority in ProbePriority}
        active_methods = {method: 0 for method in ProbeMethod}
        for lease in self._active.values():
            active_nodes[lease.target.node_id] = active_nodes.get(lease.target.node_id, 0) + 1
            active_sites[lease.target.site_key] = active_sites.get(lease.target.site_key, 0) + 1
            active_priorities[lease.priority] += 1
            active_methods[lease.method] += 1

        def eligible(request: ProbeRequest) -> bool:
            return (
                request.target.camera_id in admitted_camera_ids
                and request.available_at <= now
                and active_nodes.get(request.target.node_id, 0) < self._per_node_limit
                and active_sites.get(request.target.site_key, 0) < self._per_site_limit
                and active_methods[request.method] < self._method_limits[request.method]
            )

        candidates_by_priority = {
            priority: [request for request in self._pending[priority] if eligible(request)]
            for priority in ProbePriority
        }
        for _ in _FAIR_PRIORITIES:
            priority = _FAIR_PRIORITIES[self._fair_index]
            self._fair_index = (self._fair_index + 1) % len(_FAIR_PRIORITIES)
            candidates = candidates_by_priority[priority]
            if active_priorities[priority] < self._priority_reservations[priority] and candidates:
                return min(
                    candidates,
                    key=lambda request: (
                        request.deadline_at,
                        request.requested_at,
                        request.request_id.int,
                    ),
                )
        urgent = [
            request
            for candidates in candidates_by_priority.values()
            for request in candidates
            if request.deadline_at - now <= self._lease
        ]
        if urgent:
            return min(
                urgent,
                key=lambda request: (
                    request.deadline_at,
                    request.requested_at,
                    request.request_id.int,
                ),
            )
        for _ in _FAIR_PRIORITIES:
            priority = _FAIR_PRIORITIES[self._fair_index]
            self._fair_index = (self._fair_index + 1) % len(_FAIR_PRIORITIES)
            candidates = candidates_by_priority[priority]
            if candidates:
                return min(
                    candidates,
                    key=lambda request: (
                        request.deadline_at,
                        request.requested_at,
                        request.request_id.int,
                    ),
                )
        return None


class InMemoryProbeObservationStore:
    """Generation-fenced latest-result store used by tests and local composition."""

    def __init__(self, current_targets: Mapping[UUID, ProbeTarget] | None = None) -> None:
        self._targets = dict(current_targets or {})
        self._observations: dict[tuple[UUID, ProbeMethod], ProbeObservation] = {}
        self._lock = RLock()

    def set_current_target(self, target: ProbeTarget) -> None:
        with self._lock:
            self._targets[target.camera_id] = target

    def record_if_current(self, observation: ProbeObservation) -> bool:
        _require_probe_eligible(observation.target, observation.method)
        with self._lock:
            current_target = self._targets.get(observation.target.camera_id)
            if current_target is None or not _observation_target_is_current(
                observation.target,
                current_target,
                observation.method,
            ):
                return False
            key = (observation.target.camera_id, observation.method)
            current = self._observations.get(key)
            if current is not None:
                if current.observation_id == observation.observation_id:
                    return current == observation
                if current.completed_at >= observation.completed_at:
                    return False
            self._observations[key] = observation
            return True

    def latest_for(self, camera_ids: tuple[UUID, ...]) -> Mapping[UUID, ProbeObservation]:
        if (
            len(camera_ids) > 256
            or len(camera_ids) != len(set(camera_ids))
            or any(camera_id.version != 4 for camera_id in camera_ids)
        ):
            raise ValueError("probe_result_batch_invalid")
        with self._lock:
            result: dict[UUID, ProbeObservation] = {}
            for camera_id in camera_ids:
                target = self._targets.get(camera_id)
                candidates = (
                    observation
                    for (observed_camera_id, _), observation in self._observations.items()
                    if observed_camera_id == camera_id
                    and target is not None
                    and _observation_target_is_current(
                        observation.target,
                        target,
                        observation.method,
                    )
                )
                latest = max(
                    candidates,
                    key=lambda observation: (
                        observation.completed_at,
                        observation.observation_id.int,
                    ),
                    default=None,
                )
                if latest is not None:
                    result[camera_id] = latest
            return result


class PostgresProbeObservationStore:
    """Durable latest result store fenced by current camera placement identity."""

    def __init__(
        self,
        database_url: str,
        *,
        source_policy_sha256: str,
        statement_timeout_ms: int = 1000,
    ) -> None:
        if not 100 <= statement_timeout_ms <= 5000:
            raise ValueError("database_statement_timeout_invalid")
        if not _sha256_field_valid(source_policy_sha256):
            raise ValueError("probe_source_policy_invalid")
        self._source_policy_sha256 = source_policy_sha256
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
                columns = _schema_rows(connection, _PROBE_OBSERVATION_COLUMNS)
                constraints = _schema_rows(connection, _PROBE_OBSERVATION_CONSTRAINTS)
                index_definition = connection.execute(
                    text(_PROBE_OBSERVATION_INDEX)
                ).one_or_none()
                privileges = connection.scalar(text(_PROBE_OBSERVATION_PRIVILEGES))
                endpoint_columns = _schema_rows(connection, _PROBE_ENDPOINT_COLUMNS)
                endpoint_constraints = _schema_rows(connection, _PROBE_ENDPOINT_CONSTRAINTS)
                endpoint_privileges = connection.scalar(text(_PROBE_ENDPOINT_PRIVILEGES))
        except SQLAlchemyError:
            raise ProbeObservationUnavailable("probe_observation_store_unavailable") from None
        if (
            columns != _EXPECTED_PROBE_OBSERVATION_COLUMNS
            or constraints != _EXPECTED_PROBE_OBSERVATION_CONSTRAINTS
            or index_definition is None
            or tuple(index_definition) != _EXPECTED_PROBE_OBSERVATION_INDEX
            or privileges is not True
            or endpoint_columns != _EXPECTED_PROBE_ENDPOINT_COLUMNS
            or endpoint_constraints != _EXPECTED_PROBE_ENDPOINT_CONSTRAINTS
            or endpoint_privileges is not True
        ):
            raise ProbeObservationUnavailable("probe_observation_schema_incompatible")

    def record_if_current(
        self, observation: ProbeObservation, *, confirmation_spacing: timedelta | None = None,
    ) -> bool:
        if confirmation_spacing is not None and not (
            timedelta(seconds=1) <= confirmation_spacing <= timedelta(hours=1)
        ):
            raise ValueError("probe_confirmation_spacing_invalid")
        _require_probe_eligible(observation.target, observation.method)
        target = observation.target
        runtime = target.node_runtime
        parameters = {
            "observation_id": observation.observation_id,
            "request_id": observation.request_id,
            "camera_id": target.camera_id,
            "public_id": str(target.public_id),
            "node_id": target.node_id,
            "site_key": target.site_key,
            "desired_revision": target.desired_revision,
            "placement_generation": target.placement_generation,
            "target_node_state": target.node_state.value,
            "node_applied_revision": (
                None if runtime is None else runtime.node_applied_revision
            ),
            "node_process_id": None if runtime is None else runtime.process_id,
            "node_process_start_ticks": (
                None if runtime is None else runtime.process_start_ticks
            ),
            "node_process_boot_id": None if runtime is None else runtime.process_boot_id,
            "node_release_id": None if runtime is None else runtime.release_id,
            "source_endpoint_generation": target.source_endpoint_generation,
            "source_policy_sha256": self._source_policy_sha256,
            "maintenance": target.maintenance,
            "target_occupied": target.occupied,
            "target_source_pull_active": target.source_pull_active,
            "target_max_source_sessions": target.max_source_sessions,
            "method": observation.method.value,
            "priority": observation.priority.value,
            "outcome": observation.outcome.value,
            "started_at": observation.started_at,
            "completed_at": observation.completed_at,
            "attempt": observation.attempt,
            "failure_class": (
                None if observation.failure_class is None else observation.failure_class.value
            ),
            "video_codec": observation.video_codec,
            "audio_codec": observation.audio_codec,
        }
        try:
            with self._engine.begin() as connection:
                connection.execute(text("SET LOCAL synchronous_commit = on"))
                inserted = connection.scalar(text(_UPSERT_OBSERVATION), parameters)
                if inserted == observation.observation_id and confirmation_spacing is not None:
                    self._advance_health(connection, observation, confirmation_spacing)
        except SQLAlchemyError:
            raise ProbeObservationUnavailable("probe_observation_store_unavailable") from None
        return isinstance(inserted, UUID) and inserted == observation.observation_id

    def health_for(self, target: ProbeTarget, *, method: ProbeMethod) -> ProbeHealthRecord:
        """Read one durable generation-bound health projection; mismatch resets it."""
        try:
            with self._engine.connect() as connection:
                row = (
                    connection.execute(
                        text(
                            "SELECT * FROM probe_health_states WHERE camera_id=:camera_id "
                            "AND method=:method"
                        ),
                        {"camera_id": target.camera_id, "method": method.value},
                    )
                    .mappings()
                    .one_or_none()
                )
                return _health_record_from_row(target, method, None if row is None else dict(row))
        except (SQLAlchemyError, ValueError):
            raise ProbeObservationUnavailable("probe_health_store_unavailable") from None

    def assert_health_ready(self) -> None:
        """Require the exact additive health schema before enabling a producer."""
        try:
            with self._engine.connect() as connection:
                columns = _schema_rows(
                    connection,
                    _PROBE_OBSERVATION_COLUMNS.replace(
                        "probe_observations",
                        "probe_health_states",
                    ),
                )
                constraints = _schema_rows(
                    connection,
                    _PROBE_OBSERVATION_CONSTRAINTS.replace(
                        "probe_observations",
                        "probe_health_states",
                    ),
                )
                privileges = connection.scalar(
                    text(
                        "SELECT has_table_privilege(current_user, "
                        "'public.probe_health_states', 'SELECT') "
                        "AND has_table_privilege(current_user, "
                        "'public.probe_health_states', 'INSERT') "
                        "AND has_table_privilege(current_user, "
                        "'public.probe_health_states', 'UPDATE')"
                    )
                )
        except SQLAlchemyError:
            raise ProbeObservationUnavailable("probe_health_store_unavailable") from None
        if (
            columns != _EXPECTED_HEALTH_COLUMNS
            or constraints != _EXPECTED_HEALTH_CONSTRAINTS
            or privileges is not True
        ):
            raise ProbeObservationUnavailable("probe_health_schema_incompatible")

    @staticmethod
    def _advance_health(
        connection: Connection,
        observation: ProbeObservation,
        confirmation_spacing: timedelta,
    ) -> None:
        target = observation.target
        method = observation.method
        row = (
            connection.execute(
                text(
                    "SELECT * FROM probe_health_states WHERE camera_id=:camera_id "
                    "AND method=:method FOR UPDATE"
                ),
                {"camera_id": target.camera_id, "method": method.value},
            )
            .mappings()
            .one_or_none()
        )
        previous = _health_record_from_row(target, method, None if row is None else dict(row))
        if previous.last_observation_id == observation.observation_id:
            return
        current = previous.observe_deep(observation, confirmation_spacing=confirmation_spacing)
        connection.execute(
            text(_UPSERT_HEALTH),
            {
                "camera_id": target.camera_id,
                "method": method.value,
                "generation_sha256": _health_generation_sha256(target, method),
                "health_state": current.health_state.value,
                "consecutive_failures": current.consecutive_failures,
                "consecutive_successes": current.consecutive_successes,
                "last_observation_id": current.last_observation_id,
                "last_deep_at": current.last_deep_at,
                "last_success_at": current.last_success_at,
            },
        )

    def latest_for(self, camera_ids: tuple[UUID, ...]) -> Mapping[UUID, ProbeObservation]:
        if (
            len(camera_ids) > 256
            or len(camera_ids) != len(set(camera_ids))
            or any(camera_id.version != 4 for camera_id in camera_ids)
        ):
            raise ValueError("probe_result_batch_invalid")
        if not camera_ids:
            return {}
        query = text(_LATEST_OBSERVATIONS).bindparams(bindparam("camera_ids", expanding=True))
        try:
            with self._engine.connect() as connection:
                rows = tuple(
                    connection.execute(
                        query,
                        {
                            "camera_ids": camera_ids,
                            "source_policy_sha256": self._source_policy_sha256,
                        },
                    ).mappings()
                )
        except SQLAlchemyError:
            raise ProbeObservationUnavailable("probe_observation_store_unavailable") from None
        try:
            observations = tuple(_observation_from_row(dict(row)) for row in rows)
            return {observation.target.camera_id: observation for observation in observations}
        except (KeyError, TypeError, ValueError):
            raise ProbeObservationUnavailable("probe_observation_store_invalid") from None


_UPSERT_OBSERVATION = """
WITH input AS (
    SELECT
        CAST(:observation_id AS uuid) AS observation_id,
        CAST(:request_id AS uuid) AS request_id,
        CAST(:camera_id AS uuid) AS camera_id,
        CAST(:public_id AS varchar(26)) AS public_id,
        CAST(:node_id AS uuid) AS node_id,
        CAST(:site_key AS varchar(64)) AS site_key,
        CAST(:desired_revision AS bigint) AS desired_revision,
        CAST(:placement_generation AS bigint) AS placement_generation,
        CAST(:target_node_state AS varchar(16)) AS target_node_state,
        CAST(:node_applied_revision AS bigint) AS node_applied_revision,
        CAST(:node_process_id AS integer) AS node_process_id,
        CAST(:node_process_start_ticks AS bigint) AS node_process_start_ticks,
        CAST(:node_process_boot_id AS uuid) AS node_process_boot_id,
        CAST(:node_release_id AS varchar(128)) AS node_release_id,
        CAST(:source_endpoint_generation AS uuid) AS source_endpoint_generation,
        CAST(:source_policy_sha256 AS varchar(64)) AS source_policy_sha256,
        CAST(:maintenance AS boolean) AS maintenance,
        CAST(:target_occupied AS boolean) AS target_occupied,
        CAST(:target_source_pull_active AS boolean) AS target_source_pull_active,
        CAST(:target_max_source_sessions AS integer) AS target_max_source_sessions,
        CAST(:method AS varchar(16)) AS method,
        CAST(:priority AS varchar(16)) AS priority,
        CAST(:outcome AS varchar(16)) AS outcome,
        CAST(:started_at AS timestamptz) AS started_at,
        CAST(:completed_at AS timestamptz) AS completed_at,
        CAST(:attempt AS integer) AS attempt,
        CAST(:failure_class AS varchar(32)) AS failure_class,
        CAST(:video_codec AS varchar(32)) AS video_codec,
        CAST(:audio_codec AS varchar(32)) AS audio_codec
),
existing_replay AS (
    SELECT 1
    FROM probe_observations AS existing
    JOIN input
      ON existing.observation_id = input.observation_id
     AND existing.camera_id = input.camera_id
     AND existing.method = input.method
)
INSERT INTO probe_observations (
    observation_id, request_id, camera_id, public_id, node_id,
    site_key, desired_revision, placement_generation, target_node_state,
    node_applied_revision, node_process_id, node_process_start_ticks,
    node_process_boot_id, node_release_id, source_endpoint_generation,
    target_occupied, target_source_pull_active, target_max_source_sessions,
    method, priority, outcome, started_at, completed_at, attempt,
    failure_class, video_codec, audio_codec
)
SELECT
    input.observation_id, input.request_id, input.camera_id, input.public_id,
    input.node_id, input.site_key, input.desired_revision,
    input.placement_generation, input.target_node_state,
    input.node_applied_revision, input.node_process_id,
    input.node_process_start_ticks, input.node_process_boot_id,
    input.node_release_id, input.source_endpoint_generation, input.target_occupied,
    input.target_source_pull_active, input.target_max_source_sessions,
    input.method, input.priority, input.outcome, input.started_at,
    input.completed_at, input.attempt, input.failure_class,
    input.video_codec, input.audio_codec
FROM input
WHERE EXISTS (
    SELECT 1
    FROM cameras AS camera
    JOIN camera_probe_endpoints AS endpoint ON endpoint.camera_id = camera.id
    JOIN camera_placements AS placement ON placement.camera_id = camera.id
    JOIN media_nodes AS node ON node.id = placement.node_id
    WHERE camera.id = input.camera_id
      AND camera.public_id = input.public_id
      AND camera.state = 'enabled'
      AND camera.desired_revision = input.desired_revision
      AND endpoint.endpoint_generation = input.source_endpoint_generation
      AND endpoint.site_key = input.site_key
      AND endpoint.policy_sha256 = input.source_policy_sha256
      AND placement.node_id = input.node_id
      AND placement.generation = input.placement_generation
      AND node.state = input.target_node_state
      AND node.maintenance = input.maintenance
      AND (
          (
              input.completed_at >= statement_timestamp() - INTERVAL '5 minutes'
              AND input.completed_at <= statement_timestamp() + INTERVAL '1 second'
          )
          OR EXISTS (SELECT 1 FROM existing_replay)
      )
      AND (
          input.method <> 'path'
          OR (
              node.runtime_state = 'running'
              AND node.applied_revision = input.node_applied_revision
              AND node.process_id = input.node_process_id
              AND node.process_start_ticks = input.node_process_start_ticks
              AND node.process_boot_id = input.node_process_boot_id
              AND node.release_id = input.node_release_id
          )
      )
)
ON CONFLICT (camera_id, method) DO UPDATE SET
    observation_id=EXCLUDED.observation_id,
    request_id=EXCLUDED.request_id,
    public_id=EXCLUDED.public_id,
    node_id=EXCLUDED.node_id,
    site_key=EXCLUDED.site_key,
    desired_revision=EXCLUDED.desired_revision,
    placement_generation=EXCLUDED.placement_generation,
    target_node_state=EXCLUDED.target_node_state,
    node_applied_revision=EXCLUDED.node_applied_revision,
    node_process_id=EXCLUDED.node_process_id,
    node_process_start_ticks=EXCLUDED.node_process_start_ticks,
    node_process_boot_id=EXCLUDED.node_process_boot_id,
    node_release_id=EXCLUDED.node_release_id,
    source_endpoint_generation=EXCLUDED.source_endpoint_generation,
    target_occupied=EXCLUDED.target_occupied,
    target_source_pull_active=EXCLUDED.target_source_pull_active,
    target_max_source_sessions=EXCLUDED.target_max_source_sessions,
    priority=EXCLUDED.priority,
    outcome=EXCLUDED.outcome,
    started_at=EXCLUDED.started_at,
    completed_at=EXCLUDED.completed_at,
    attempt=EXCLUDED.attempt,
    failure_class=EXCLUDED.failure_class,
    video_codec=EXCLUDED.video_codec,
    audio_codec=EXCLUDED.audio_codec
WHERE (
    probe_observations.observation_id = EXCLUDED.observation_id
    AND probe_observations.request_id = EXCLUDED.request_id
    AND probe_observations.public_id = EXCLUDED.public_id
    AND probe_observations.node_id = EXCLUDED.node_id
    AND probe_observations.site_key = EXCLUDED.site_key
    AND probe_observations.desired_revision = EXCLUDED.desired_revision
    AND probe_observations.placement_generation = EXCLUDED.placement_generation
    AND probe_observations.target_node_state = EXCLUDED.target_node_state
    AND probe_observations.node_applied_revision
        IS NOT DISTINCT FROM EXCLUDED.node_applied_revision
    AND probe_observations.node_process_id
        IS NOT DISTINCT FROM EXCLUDED.node_process_id
    AND probe_observations.node_process_start_ticks
        IS NOT DISTINCT FROM EXCLUDED.node_process_start_ticks
    AND probe_observations.node_process_boot_id
        IS NOT DISTINCT FROM EXCLUDED.node_process_boot_id
    AND probe_observations.node_release_id
        IS NOT DISTINCT FROM EXCLUDED.node_release_id
    AND probe_observations.source_endpoint_generation
        = EXCLUDED.source_endpoint_generation
    AND probe_observations.target_occupied = EXCLUDED.target_occupied
    AND probe_observations.target_source_pull_active
        = EXCLUDED.target_source_pull_active
    AND probe_observations.target_max_source_sessions
        = EXCLUDED.target_max_source_sessions
    AND probe_observations.priority = EXCLUDED.priority
    AND probe_observations.outcome = EXCLUDED.outcome
    AND probe_observations.started_at = EXCLUDED.started_at
    AND probe_observations.completed_at = EXCLUDED.completed_at
    AND probe_observations.attempt = EXCLUDED.attempt
    AND probe_observations.failure_class IS NOT DISTINCT FROM EXCLUDED.failure_class
    AND probe_observations.video_codec IS NOT DISTINCT FROM EXCLUDED.video_codec
    AND probe_observations.audio_codec IS NOT DISTINCT FROM EXCLUDED.audio_codec
)
OR (
    probe_observations.observation_id <> EXCLUDED.observation_id
    AND EXCLUDED.completed_at > probe_observations.completed_at
)
RETURNING observation_id
"""

_EXPECTED_PROBE_OBSERVATION_COLUMNS = {
    "observation_id": ("uuid", True, ""),
    "request_id": ("uuid", True, ""),
    "camera_id": ("uuid", True, ""),
    "public_id": ("character varying(26)", True, ""),
    "node_id": ("uuid", True, ""),
    "site_key": ("character varying(64)", True, ""),
    "desired_revision": ("bigint", True, ""),
    "placement_generation": ("bigint", True, ""),
    "target_node_state": ("character varying(16)", True, ""),
    "node_applied_revision": ("bigint", False, ""),
    "node_process_id": ("integer", False, ""),
    "node_process_start_ticks": ("bigint", False, ""),
    "node_process_boot_id": ("uuid", False, ""),
    "node_release_id": ("character varying(128)", False, ""),
    "source_endpoint_generation": ("uuid", True, ""),
    "target_occupied": ("boolean", True, ""),
    "target_source_pull_active": ("boolean", True, ""),
    "target_max_source_sessions": ("integer", True, ""),
    "method": ("character varying(16)", True, ""),
    "priority": ("character varying(16)", True, ""),
    "outcome": ("character varying(16)", True, ""),
    "started_at": ("timestamp with time zone", True, ""),
    "completed_at": ("timestamp with time zone", True, ""),
    "attempt": ("integer", True, ""),
    "failure_class": ("character varying(32)", False, ""),
    "video_codec": ("character varying(32)", False, ""),
    "audio_codec": ("character varying(32)", False, ""),
}
_EXPECTED_PROBE_OBSERVATION_CONSTRAINTS = {
    "probe_observations_pkey": ("p", True, "PRIMARY KEY (observation_id)"),
    "probe_observations_request_id_key": ("u", True, "UNIQUE (request_id)"),
    "probe_observations_camera_id_fkey": (
        "f",
        True,
        "FOREIGN KEY (camera_id) REFERENCES cameras(id) ON DELETE CASCADE",
    ),
    "probe_observations_node_id_fkey": (
        "f",
        True,
        "FOREIGN KEY (node_id) REFERENCES media_nodes(id) ON DELETE CASCADE",
    ),
    "uq_probe_observations_camera_method": ("u", True, "UNIQUE (camera_id, method)"),
    "ck_probe_observations_public_id": (
        "c",
        True,
        "CHECK (public_id::text ~ '^[a-z2-7]{25}[aeimquy4]$'::text)",
    ),
    "ck_probe_observations_site_key": (
        "c",
        True,
        "CHECK (site_key::text ~ '^[a-z0-9][a-z0-9._-]{0,63}$'::text)",
    ),
    "ck_probe_observations_generation": (
        "c",
        True,
        "CHECK (desired_revision >= 1 AND placement_generation >= 1)",
    ),
    "ck_probe_observations_source_sessions": (
        "c",
        True,
        "CHECK (target_max_source_sessions >= 1 AND target_max_source_sessions <= 16)",
    ),
    "ck_probe_observations_node_state": (
        "c",
        True,
        "CHECK (target_node_state::text = ANY (ARRAY['provisioning'::character varying, "
        "'stopped'::character varying, 'stopping'::character varying, "
        "'starting'::character varying, 'running'::character varying, "
        "'draining'::character varying, 'maintenance'::character varying, "
        "'failed'::character varying, 'deleting'::character varying]::text[]))",
    ),
    "ck_probe_observations_node_generation": (
        "c",
        True,
        "CHECK (node_applied_revision IS NULL AND node_process_id IS NULL AND "
        "node_process_start_ticks IS NULL AND node_process_boot_id IS NULL AND "
        "node_release_id IS NULL OR node_applied_revision >= 1 AND node_process_id >= 1 "
        "AND node_process_start_ticks >= 1 AND node_process_boot_id IS NOT NULL AND "
        "node_release_id::text ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'::text)",
    ),
    "ck_probe_observations_method": (
        "c",
        True,
        "CHECK (method::text = ANY (ARRAY['source'::character varying, "
        "'path'::character varying]::text[]))",
    ),
    "ck_probe_observations_eligibility": (
        "c",
        True,
        "CHECK ((method::text <> 'path'::text OR target_node_state::text = "
        "'running'::text AND NOT target_occupied AND NOT target_source_pull_active "
        "AND node_applied_revision IS NOT NULL) AND (method::text <> 'source'::text "
        "OR NOT target_source_pull_active OR target_max_source_sessions > 1))",
    ),
    "ck_probe_observations_priority": (
        "c",
        True,
        "CHECK (priority::text = ANY (ARRAY['manual'::character varying, "
        "'confirmation'::character varying, 'routine'::character varying]::text[]))",
    ),
    "ck_probe_observations_outcome": (
        "c",
        True,
        "CHECK (outcome::text = ANY (ARRAY['healthy'::character varying, "
        "'unhealthy'::character varying, 'inconclusive'::character varying]::text[]))",
    ),
    "ck_probe_observations_window": (
        "c",
        True,
        "CHECK (completed_at >= started_at AND completed_at <= "
        "(started_at + '00:01:00'::interval))",
    ),
    "ck_probe_observations_attempt": (
        "c",
        True,
        "CHECK (attempt >= 1 AND attempt <= 10)",
    ),
    "ck_probe_observations_failure_class": (
        "c",
        True,
        "CHECK (failure_class IS NULL OR (failure_class::text = ANY "
        "(ARRAY['authentication'::character varying, 'codec'::character varying, "
        "'connect_timeout'::character varying, 'executor'::character varying, "
        "'output'::character varying, 'transport'::character varying]::text[])))",
    ),
    "ck_probe_observations_result": (
        "c",
        True,
        "CHECK (outcome::text = 'healthy'::text AND failure_class IS NULL AND "
        "(video_codec IS NOT NULL OR audio_codec IS NOT NULL) OR outcome::text = "
        "'unhealthy'::text AND (failure_class::text = ANY "
        "(ARRAY['authentication'::character varying, 'codec'::character varying, "
        "'connect_timeout'::character varying, 'transport'::character varying]::text[])) "
        "AND video_codec IS NULL AND audio_codec IS NULL OR outcome::text = "
        "'inconclusive'::text AND (failure_class::text = ANY "
        "(ARRAY['executor'::character varying, 'output'::character varying]::text[])) "
        "AND video_codec IS NULL AND audio_codec IS NULL)",
    ),
    "ck_probe_observations_video_codec": (
        "c",
        True,
        "CHECK (video_codec IS NULL OR video_codec::text ~ "
        "'^[a-z0-9][a-z0-9._-]{0,31}$'::text)",
    ),
    "ck_probe_observations_audio_codec": (
        "c",
        True,
        "CHECK (audio_codec IS NULL OR audio_codec::text ~ "
        "'^[a-z0-9][a-z0-9._-]{0,31}$'::text)",
    ),
}
_PROBE_OBSERVATION_COLUMNS = """
SELECT attribute.attname, format_type(attribute.atttypid, attribute.atttypmod),
       attribute.attnotnull, COALESCE(pg_get_expr(default_entry.adbin, default_entry.adrelid), '')
FROM pg_attribute AS attribute
JOIN pg_class AS table_entry ON table_entry.oid = attribute.attrelid
JOIN pg_namespace AS namespace_entry ON namespace_entry.oid = table_entry.relnamespace
LEFT JOIN pg_attrdef AS default_entry
  ON default_entry.adrelid = attribute.attrelid
 AND default_entry.adnum = attribute.attnum
WHERE namespace_entry.nspname = 'public'
  AND table_entry.relname = 'probe_observations'
  AND attribute.attnum > 0
  AND NOT attribute.attisdropped
"""
_PROBE_OBSERVATION_CONSTRAINTS = """
SELECT constraint_entry.conname, constraint_entry.contype,
       constraint_entry.convalidated,
       pg_get_constraintdef(constraint_entry.oid, true)
FROM pg_constraint AS constraint_entry
JOIN pg_class AS table_entry ON table_entry.oid = constraint_entry.conrelid
JOIN pg_namespace AS namespace_entry ON namespace_entry.oid = table_entry.relnamespace
WHERE namespace_entry.nspname = 'public'
  AND table_entry.relname = 'probe_observations'
  AND constraint_entry.contype <> 'n'
"""
_PROBE_OBSERVATION_INDEX = """
SELECT access_method.amname, index_entry.indisunique, index_entry.indisvalid,
       index_entry.indisready, index_entry.indislive,
       index_entry.indpred IS NULL, index_entry.indexprs IS NULL,
       ARRAY(
           SELECT attribute.attname
           FROM unnest(index_entry.indkey::smallint[]) WITH ORDINALITY
                AS key_entry(attnum, ordinal)
           JOIN pg_attribute AS attribute
             ON attribute.attrelid = index_entry.indrelid
            AND attribute.attnum = key_entry.attnum
           ORDER BY key_entry.ordinal
       )
FROM pg_index AS index_entry
JOIN pg_class AS index_class ON index_class.oid = index_entry.indexrelid
JOIN pg_namespace AS namespace_entry ON namespace_entry.oid = index_class.relnamespace
JOIN pg_am AS access_method ON access_method.oid = index_class.relam
WHERE namespace_entry.nspname = 'public'
  AND index_class.relname = 'ix_probe_observations_camera_completed'
"""
_EXPECTED_PROBE_OBSERVATION_INDEX = (
    "btree",
    False,
    True,
    True,
    True,
    True,
    True,
    ["camera_id", "completed_at"],
)
_PROBE_OBSERVATION_PRIVILEGES = """
SELECT has_table_privilege(
    current_user,
    'public.probe_observations',
    'SELECT, INSERT, UPDATE'
)
"""
_EXPECTED_PROBE_ENDPOINT_COLUMNS = {
    "camera_id": ("uuid", True, ""),
    "admitted_revision": ("bigint", True, ""),
    "endpoint_generation": ("uuid", True, ""),
    "endpoint_address": ("inet", True, ""),
    "endpoint_port": ("integer", True, ""),
    "site_key": ("character varying(64)", True, ""),
    "policy_sha256": ("character varying(64)", True, ""),
    "source_sha256": ("character varying(64)", True, ""),
    "created_at": ("timestamp with time zone", True, "clock_timestamp()"),
}
_EXPECTED_PROBE_ENDPOINT_CONSTRAINTS = {
    "camera_probe_endpoints_pkey": ("p", True, "PRIMARY KEY (camera_id)"),
    "camera_probe_endpoints_camera_id_fkey": (
        "f",
        True,
        "FOREIGN KEY (camera_id) REFERENCES cameras(id) ON DELETE CASCADE",
    ),
    "camera_probe_endpoints_endpoint_generation_key": (
        "u",
        True,
        "UNIQUE (endpoint_generation)",
    ),
    "ck_camera_probe_endpoints_revision": (
        "c",
        True,
        "CHECK (admitted_revision >= 1)",
    ),
    "ck_camera_probe_endpoints_port": (
        "c",
        True,
        "CHECK (endpoint_port >= 1 AND endpoint_port <= 65535)",
    ),
    "ck_camera_probe_endpoints_site_key": (
        "c",
        True,
        "CHECK (site_key::text ~ '^[a-z0-9][a-z0-9._-]{0,63}$'::text)",
    ),
    "ck_camera_probe_endpoints_policy_sha256": (
        "c",
        True,
        "CHECK (policy_sha256::text ~ '^[0-9a-f]{64}$'::text)",
    ),
    "ck_camera_probe_endpoints_sha256": (
        "c",
        True,
        "CHECK (source_sha256::text ~ '^[0-9a-f]{64}$'::text)",
    ),
}
_PROBE_ENDPOINT_COLUMNS = """
SELECT attribute.attname, format_type(attribute.atttypid, attribute.atttypmod),
       attribute.attnotnull, COALESCE(pg_get_expr(default_entry.adbin, default_entry.adrelid), '')
FROM pg_attribute AS attribute
JOIN pg_class AS table_entry ON table_entry.oid = attribute.attrelid
JOIN pg_namespace AS namespace_entry ON namespace_entry.oid = table_entry.relnamespace
LEFT JOIN pg_attrdef AS default_entry
  ON default_entry.adrelid = attribute.attrelid
 AND default_entry.adnum = attribute.attnum
WHERE namespace_entry.nspname = 'public'
  AND table_entry.relname = 'camera_probe_endpoints'
  AND attribute.attnum > 0
  AND NOT attribute.attisdropped
"""
_PROBE_ENDPOINT_CONSTRAINTS = """
SELECT constraint_entry.conname, constraint_entry.contype,
       constraint_entry.convalidated,
       pg_get_constraintdef(constraint_entry.oid, true)
FROM pg_constraint AS constraint_entry
JOIN pg_class AS table_entry ON table_entry.oid = constraint_entry.conrelid
JOIN pg_namespace AS namespace_entry ON namespace_entry.oid = table_entry.relnamespace
WHERE namespace_entry.nspname = 'public'
  AND table_entry.relname = 'camera_probe_endpoints'
  AND constraint_entry.contype <> 'n'
"""
_PROBE_ENDPOINT_PRIVILEGES = """
SELECT has_table_privilege(
    current_user,
    'public.camera_probe_endpoints',
    'SELECT, INSERT, UPDATE, DELETE'
)
"""

_LATEST_OBSERVATIONS = """
SELECT DISTINCT ON (observation.camera_id) observation.*
FROM probe_observations AS observation
JOIN cameras AS camera ON camera.id = observation.camera_id
JOIN camera_probe_endpoints AS endpoint ON endpoint.camera_id = camera.id
JOIN camera_placements AS placement ON placement.camera_id = camera.id
JOIN media_nodes AS node ON node.id = placement.node_id
WHERE observation.camera_id IN :camera_ids
  AND camera.state = 'enabled'
  AND camera.public_id = observation.public_id
  AND camera.desired_revision = observation.desired_revision
  AND endpoint.endpoint_generation = observation.source_endpoint_generation
  AND endpoint.site_key = observation.site_key
  AND endpoint.policy_sha256 = CAST(:source_policy_sha256 AS varchar(64))
  AND placement.node_id = observation.node_id
  AND placement.generation = observation.placement_generation
  AND node.state = observation.target_node_state
  AND node.maintenance = false
  AND (
      observation.method <> 'path'
      OR (
          node.runtime_state = 'running'
          AND node.applied_revision = observation.node_applied_revision
          AND node.process_id = observation.node_process_id
          AND node.process_start_ticks = observation.node_process_start_ticks
          AND node.process_boot_id = observation.node_process_boot_id
          AND node.release_id = observation.node_release_id
      )
  )
ORDER BY observation.camera_id, observation.completed_at DESC,
         observation.observation_id DESC
"""


def _observation_from_row(row: Mapping[str, object]) -> ProbeObservation:
    node_applied_revision = row["node_applied_revision"]
    runtime = (
        None
        if node_applied_revision is None
        else ProbeNodeRuntimeGeneration(
            node_applied_revision=_int_field(row, "node_applied_revision"),
            process_id=_int_field(row, "node_process_id"),
            process_start_ticks=_int_field(row, "node_process_start_ticks"),
            process_boot_id=_uuid_field(row, "node_process_boot_id"),
            release_id=_str_field(row, "node_release_id"),
        )
    )
    target = ProbeTarget(
        camera_id=_uuid_field(row, "camera_id"),
        public_id=PublicId.parse(_str_field(row, "public_id")),
        node_id=_uuid_field(row, "node_id"),
        site_key=_str_field(row, "site_key"),
        desired_revision=_int_field(row, "desired_revision"),
        placement_generation=_int_field(row, "placement_generation"),
        node_state=NodeState(_str_field(row, "target_node_state")),
        node_runtime=runtime,
        enabled=True,
        maintenance=False,
        occupied=_bool_field(row, "target_occupied"),
        source_pull_active=_bool_field(row, "target_source_pull_active"),
        max_source_sessions=_int_field(row, "target_max_source_sessions"),
        source_endpoint_generation=_uuid_field(row, "source_endpoint_generation"),
    )
    failure = row["failure_class"]
    return ProbeObservation(
        observation_id=_uuid_field(row, "observation_id"),
        request_id=_uuid_field(row, "request_id"),
        target=target,
        method=ProbeMethod(_str_field(row, "method")),
        priority=ProbePriority(_str_field(row, "priority")),
        outcome=ProbeOutcome(_str_field(row, "outcome")),
        started_at=_datetime_field(row, "started_at"),
        completed_at=_datetime_field(row, "completed_at"),
        attempt=_int_field(row, "attempt"),
        failure_class=None if failure is None else ProbeFailureClass(str(failure)),
        video_codec=_optional_str_field(row, "video_codec"),
        audio_codec=_optional_str_field(row, "audio_codec"),
    )


def _uuid_field(row: Mapping[str, object], name: str) -> UUID:
    value = row[name]
    if not isinstance(value, UUID):
        raise TypeError(name)
    return value


def _str_field(row: Mapping[str, object], name: str) -> str:
    value = row[name]
    if not isinstance(value, str):
        raise TypeError(name)
    return value


def _optional_str_field(row: Mapping[str, object], name: str) -> str | None:
    value = row[name]
    if value is not None and not isinstance(value, str):
        raise TypeError(name)
    return value


def _int_field(row: Mapping[str, object], name: str) -> int:
    value = row[name]
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(name)
    return value


def _bool_field(row: Mapping[str, object], name: str) -> bool:
    value = row[name]
    if not isinstance(value, bool):
        raise TypeError(name)
    return value


def _sha256_field_valid(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _schema_rows(connection: Connection, query: str) -> dict[str, tuple[object, ...]]:
    return {
        str(row[0]): tuple(row[1:])
        for row in connection.execute(text(query)).tuples()
    }


def _datetime_field(row: Mapping[str, object], name: str) -> datetime:
    value = row[name]
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise TypeError(name)
    return value


_EXPECTED_HEALTH_COLUMNS = {
    "camera_id": ("uuid", True, ""),
    "method": ("character varying(16)", True, ""),
    "generation_sha256": ("character varying(64)", True, ""),
    "health_state": ("character varying(16)", True, ""),
    "consecutive_failures": ("integer", True, ""),
    "consecutive_successes": ("integer", True, ""),
    "last_observation_id": ("uuid", False, ""),
    "last_deep_at": ("timestamp with time zone", False, ""),
    "last_success_at": ("timestamp with time zone", False, ""),
}
_EXPECTED_HEALTH_CONSTRAINTS = {
    "probe_health_states_pkey": ("p", True, "PRIMARY KEY (camera_id, method)"),
    "probe_health_states_camera_id_fkey": (
        "f",
        True,
        "FOREIGN KEY (camera_id) REFERENCES cameras(id) ON DELETE CASCADE",
    ),
    "ck_probe_health_method": (
        "c",
        True,
        "CHECK (method::text = ANY (ARRAY['source'::character varying, "
        "'path'::character varying]::text[]))",
    ),
    "ck_probe_health_generation": (
        "c",
        True,
        "CHECK (generation_sha256::text ~ '^[0-9a-f]{64}$'::text)",
    ),
    "ck_probe_health_state": (
        "c",
        True,
        "CHECK (health_state::text = ANY (ARRAY['unknown'::character varying, "
        "'healthy'::character varying, 'suspect'::character varying, "
        "'unhealthy'::character varying, 'recovering'::character varying]::text[]))",
    ),
    "ck_probe_health_counters": (
        "c",
        True,
        "CHECK (consecutive_failures >= 0 AND consecutive_failures <= 2 "
        "AND consecutive_successes >= 0 AND consecutive_successes <= 2)",
    ),
    "ck_probe_health_times": (
        "c",
        True,
        "CHECK ((last_observation_id IS NULL) = (last_deep_at IS NULL) AND "
        "(last_success_at IS NULL OR last_deep_at IS NOT NULL "
        "AND last_success_at <= last_deep_at))",
    ),
}

_UPSERT_HEALTH = """
INSERT INTO probe_health_states (
    camera_id, method, generation_sha256, health_state, consecutive_failures,
    consecutive_successes, last_observation_id, last_deep_at, last_success_at
) VALUES (
    :camera_id, :method, :generation_sha256, :health_state, :consecutive_failures,
    :consecutive_successes, :last_observation_id, :last_deep_at, :last_success_at
)
ON CONFLICT (camera_id, method) DO UPDATE SET
    generation_sha256=EXCLUDED.generation_sha256,
    health_state=EXCLUDED.health_state,
    consecutive_failures=EXCLUDED.consecutive_failures,
    consecutive_successes=EXCLUDED.consecutive_successes,
    last_observation_id=EXCLUDED.last_observation_id,
    last_deep_at=EXCLUDED.last_deep_at,
    last_success_at=EXCLUDED.last_success_at
"""


def _health_generation_sha256(target: ProbeTarget, method: ProbeMethod) -> str:
    identity = (
        target.camera_id,
        target.public_id,
        target.node_id,
        target.desired_revision,
        target.placement_generation,
        target.source_endpoint_generation,
        target.node_runtime if method is ProbeMethod.PATH else None,
    )
    return hashlib.sha256(repr(identity).encode("utf-8")).hexdigest()


def _health_record_from_row(
    target: ProbeTarget,
    method: ProbeMethod,
    row: Mapping[str, object] | None,
) -> ProbeHealthRecord:
    if row is None or row["generation_sha256"] != _health_generation_sha256(target, method):
        return ProbeHealthRecord.for_target(target, method=method)
    return ProbeHealthRecord(
        target=target,
        method=method,
        health_state=ProbeHealthState(_str_field(row, "health_state")),
        consecutive_failures=_int_field(row, "consecutive_failures"),
        consecutive_successes=_int_field(row, "consecutive_successes"),
        last_observation_id=(
            None if row["last_observation_id"] is None else _uuid_field(row, "last_observation_id")
        ),
        last_deep_at=(
            None if row["last_deep_at"] is None else _datetime_field(row, "last_deep_at")
        ),
        last_success_at=(
            None if row["last_success_at"] is None else _datetime_field(row, "last_success_at")
        ),
    )


def _same_probe_generation(left: ProbeTarget, right: ProbeTarget) -> bool:
    return (
        left.camera_id == right.camera_id
        and left.public_id == right.public_id
        and left.node_id == right.node_id
        and left.desired_revision == right.desired_revision
        and left.placement_generation == right.placement_generation
        and left.source_endpoint_generation == right.source_endpoint_generation
    )


def _same_health_generation(
    left: ProbeTarget,
    right: ProbeTarget,
    method: ProbeMethod,
) -> bool:
    return _same_probe_generation(left, right) and (
        method is ProbeMethod.SOURCE or left.node_runtime == right.node_runtime
    )


def _require_probe_eligible(target: ProbeTarget, method: ProbeMethod) -> None:
    if not target.enabled:
        raise ProbeIneligible("camera_disabled")
    if target.maintenance:
        raise ProbeIneligible("camera_maintenance")
    if target.source_endpoint_generation is None:
        raise ProbeIneligible("source_endpoint_unavailable")
    if method is ProbeMethod.PATH and target.node_state is not NodeState.RUNNING:
        raise ProbeIneligible("node_path_unavailable")
    if method is ProbeMethod.PATH and target.occupied:
        raise ProbeIneligible("camera_occupied")
    if method is ProbeMethod.PATH and target.source_pull_active:
        raise ProbeIneligible("path_source_pull_active")
    if method is ProbeMethod.PATH and target.node_runtime is None:
        raise ProbeIneligible("node_runtime_unavailable")
    if (
        method is ProbeMethod.SOURCE
        and target.source_pull_active
        and target.max_source_sessions <= 1
    ):
        raise ProbeIneligible("source_session_budget")


def _priority_reservations(global_limit: int) -> Mapping[ProbePriority, int]:
    if global_limit < len(ProbePriority):
        return {priority: 0 for priority in ProbePriority}
    reservations = {
        priority: max(1, global_limit * weight // sum(_PRIORITY_WEIGHTS.values()))
        for priority, weight in _PRIORITY_WEIGHTS.items()
    }
    while sum(reservations.values()) < global_limit:
        priority = max(
            ProbePriority,
            key=lambda candidate: (
                global_limit * _PRIORITY_WEIGHTS[candidate]
                - reservations[candidate] * sum(_PRIORITY_WEIGHTS.values()),
                _PRIORITY_RANK[candidate],
            ),
        )
        reservations[priority] += 1
    return reservations


def _observation_target_is_current(
    observed: ProbeTarget,
    current: ProbeTarget,
    method: ProbeMethod,
) -> bool:
    return (
        _same_probe_generation(observed, current)
        and observed.enabled == current.enabled
        and observed.maintenance == current.maintenance
        and observed.node_state == current.node_state
        and (method is ProbeMethod.SOURCE or observed.node_runtime == current.node_runtime)
    )
