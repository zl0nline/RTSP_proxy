from __future__ import annotations

import math
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock
from typing import Literal, Protocol
from uuid import UUID

from rtsp_proxy.probe_broker import ProbeBrokerRequest, ReceivedProbeInput
from rtsp_proxy.probe_connect_guard import ProbeConnectGuardLease
from rtsp_proxy.probe_executor import ProbeConnectGuardTarget
from rtsp_proxy.probe_ownership import OwnershipLedger
from rtsp_proxy.probe_systemd import ProbeTransientDescriptors, ProbeTransientLease
from rtsp_proxy.probes import ProbeExecutionResult

_MAX_EXECUTION_SECONDS = 60.0
_MAX_OUTPUT_BYTES = 65_536
_CLEANUP_RESERVE_SECONDS = 5.0
_MAX_EXECUTION_RECORDS = 128


class ProbeExecutionError(RuntimeError):
    """One admitted probe could not complete through the isolated executor."""


class ProbeExecutionChannels(Protocol):
    """Idempotently closable parent/child descriptor ownership bundle."""

    @property
    def descriptors(self) -> ProbeTransientDescriptors: ...

    @property
    def output_fd(self) -> int: ...

    def close_child_ends(self) -> None: ...

    def release_gate(self) -> None: ...

    def close(self) -> None: ...


@dataclass(slots=True)
class _OwnerSlot[Owned]:
    """Pre-published destination for an interrupt-safe ownership handoff."""

    value: Owned | None = None

    def publish(self, value: Owned) -> None:
        if self.value is not None:
            raise ProbeExecutionError("probe_execution_ownership_invalid")
        self.value = value

    def release(self, value: Owned) -> None:
        if self.value is not value:
            raise ProbeExecutionError("probe_execution_ownership_invalid")
        self.value = None

    def owns(self, value: Owned) -> bool:
        return self.value is value


class ProbeExecutionChannelFactory(Protocol):
    def create_owned(
        self,
        received: ReceivedProbeInput,
        *,
        publish: Callable[[ProbeExecutionChannels], None],
    ) -> None:
        """Duplicate the sealed input and publish every new descriptor owner."""


class _SystemdController(Protocol):
    def start_owned(
        self,
        request: ProbeBrokerRequest,
        *,
        descriptors: ProbeTransientDescriptors,
        timeout_seconds: float,
        ownership: OwnershipLedger[ProbeTransientLease],
    ) -> None:
        """Publish the lease before a committed unit can escape this call."""

    def read_output(
        self,
        lease: ProbeTransientLease,
        *,
        output_fd: int,
        timeout_seconds: float,
        ownership: OwnershipLedger[ProbeTransientLease],
    ) -> bytes:
        """Call collected only after the exact unit is definitively gone."""

    def ensure_collected(
        self,
        lease: ProbeTransientLease,
        *,
        timeout_seconds: float,
        ownership: OwnershipLedger[ProbeTransientLease],
    ) -> None:
        """Idempotently collect the exact unit and then call collected."""


class _CgroupResolver(Protocol):
    def resolve(self, *, unit_name: str, timeout_seconds: float) -> Path: ...


class _GuardController(Protocol):
    def install_owned(
        self,
        *,
        request_id: UUID,
        unit_name: str,
        cgroup_path: Path,
        target: ProbeConnectGuardTarget,
        timeout_seconds: float,
        ownership: OwnershipLedger[ProbeConnectGuardLease],
    ) -> None:
        """Publish the lease before a committed guard can escape this call."""

    def ensure_released(
        self,
        lease: ProbeConnectGuardLease,
        *,
        timeout_seconds: float,
        ownership: OwnershipLedger[ProbeConnectGuardLease],
    ) -> None:
        """Idempotently remove the exact guard and then call released."""


class _StartupRecovery(Protocol):
    def reconcile_units(self, *, timeout_seconds: float) -> int:
        """Stop and collect every receipt-owned transient unit first."""

    def reconcile_guards(self, *, timeout_seconds: float) -> int:
        """Remove receipt-owned guards only after every unit is gone."""


class _UnitStartupReconciler(Protocol):
    def reconcile_owned(self, *, timeout_seconds: float) -> int: ...


class _GuardStartupReconciler(Protocol):
    def reconcile_startup(self, *, timeout_seconds: float) -> int: ...


@dataclass(frozen=True, slots=True)
class ProbeExecutionStartupRecovery:
    """Bind reserved systemd inventory to receipt-owned guard reconciliation."""

    units: _UnitStartupReconciler
    guards: _GuardStartupReconciler

    def reconcile_units(self, *, timeout_seconds: float) -> int:
        return self.units.reconcile_owned(timeout_seconds=timeout_seconds)

    def reconcile_guards(self, *, timeout_seconds: float) -> int:
        return self.guards.reconcile_startup(timeout_seconds=timeout_seconds)


class _ResultDecoder(Protocol):
    def decode(self, payload: bytes) -> ProbeExecutionResult:
        """Return only a bounded, typed, secret-free probe result."""


@dataclass(slots=True)
class _ExecutionOwnership:
    received: ReceivedProbeInput
    channels: _OwnerSlot[ProbeExecutionChannels] = field(default_factory=_OwnerSlot)
    systemd: _OwnerSlot[ProbeTransientLease] = field(default_factory=_OwnerSlot)
    guard: _OwnerSlot[ProbeConnectGuardLease] = field(default_factory=_OwnerSlot)
    received_closed: bool = False
    state: Literal["executing", "cleaning", "cleanup_pending"] = "executing"
    operation_lock: Lock = field(default_factory=Lock, repr=False)

    @property
    def collected(self) -> bool:
        return (
            self.channels.value is None
            and self.systemd.value is None
            and self.guard.value is None
            and self.received_closed
        )


class ProbeExecutionBroker:
    """Execute one authenticated request behind systemd and an exact guard."""

    def __init__(
        self,
        *,
        systemd: _SystemdController,
        guard: _GuardController,
        cgroups: _CgroupResolver,
        channels: ProbeExecutionChannelFactory,
        decoder: _ResultDecoder,
        recovery: _StartupRecovery,
        monotonic: Callable[[], float] = time.monotonic,
        wall_clock_ms: Callable[[], int] = lambda: int(time.time() * 1_000),
    ) -> None:
        self._systemd = systemd
        self._guard = guard
        self._cgroups = cgroups
        self._channels = channels
        self._decoder = decoder
        self._recovery = recovery
        self._monotonic = monotonic
        self._wall_clock_ms = wall_clock_ms
        self._active: dict[UUID, _ExecutionOwnership] = {}
        self._active_lock = Lock()
        self._recovery_lock = Lock()
        self._retry_lock = Lock()
        self._recovery_ready = False

    def reconcile_startup(self, *, timeout_seconds: float) -> int:
        timeout = self._validate_timeout(timeout_seconds)
        with self._recovery_lock:
            with self._active_lock:
                if self._active:
                    raise ProbeExecutionError("probe_execution_recovery_busy")
                self._recovery_ready = False
            deadline = self._monotonic_deadline(timeout)
            try:
                unresolved_units = self._recovery.reconcile_units(
                    timeout_seconds=self._remaining(deadline)
                )
            except Exception:
                raise ProbeExecutionError("probe_execution_recovery_failed") from None
            self._validate_recovery_count(unresolved_units)
            if unresolved_units:
                return unresolved_units
            try:
                unresolved_guards = self._recovery.reconcile_guards(
                    timeout_seconds=self._remaining(deadline)
                )
            except Exception:
                raise ProbeExecutionError("probe_execution_recovery_failed") from None
            self._validate_recovery_count(unresolved_guards)
            with self._active_lock:
                self._recovery_ready = unresolved_guards == 0
            return unresolved_guards

    @staticmethod
    def _validate_recovery_count(unresolved: int) -> None:
        if (
            isinstance(unresolved, bool)
            or not isinstance(unresolved, int)
            or unresolved < 0
        ):
            raise ProbeExecutionError("probe_execution_recovery_failed")

    def execute(
        self,
        received: ReceivedProbeInput,
        *,
        timeout_seconds: float,
    ) -> ProbeExecutionResult:
        if not isinstance(received, ReceivedProbeInput):
            raise ProbeExecutionError("probe_execution_request_invalid")
        timeout = self._validate_timeout(timeout_seconds)
        request = received.request
        ownership = _ExecutionOwnership(received=received)
        ownership.operation_lock.acquire()
        try:
            return self._execute_claimed(
                request,
                ownership,
                timeout_seconds=timeout,
            )
        finally:
            try:
                self._finalize_ownership(request.request_id, ownership)
            finally:
                ownership.operation_lock.release()

    def _execute_claimed(
        self,
        request: ProbeBrokerRequest,
        ownership: _ExecutionOwnership,
        *,
        timeout_seconds: float,
    ) -> ProbeExecutionResult:
        received = ownership.received
        primary_error: BaseException | None = None
        result: ProbeExecutionResult | None = None
        try:
            with self._active_lock:
                if not self._recovery_ready:
                    raise ProbeExecutionError("probe_execution_recovery_required")
                if request.request_id in self._active:
                    raise ProbeExecutionError("probe_execution_already_active")
                if len(self._active) >= _MAX_EXECUTION_RECORDS:
                    raise ProbeExecutionError("probe_execution_capacity_exhausted")
                self._active[request.request_id] = ownership
            deadline = self._execution_deadline(
                request,
                timeout_seconds=timeout_seconds,
            )
            self._channels.create_owned(
                received,
                publish=ownership.channels.publish,
            )
            execution_channels = self._require_channels(ownership)
            self._systemd.start_owned(
                request,
                descriptors=execution_channels.descriptors,
                timeout_seconds=self._remaining(deadline),
                ownership=ownership.systemd,
            )
            execution_channels.close_child_ends()
            unit_name = f"rtsp-probe-{request.request_id.hex}.service"
            cgroup_path = self._cgroups.resolve(
                unit_name=unit_name,
                timeout_seconds=self._remaining(deadline),
            )
            self._guard.install_owned(
                request_id=request.request_id,
                unit_name=unit_name,
                cgroup_path=cgroup_path,
                target=request.target,
                timeout_seconds=self._remaining(deadline),
                ownership=ownership.guard,
            )
            self._require_request_live(request)
            _ = self._remaining(deadline)
            execution_channels.release_gate()
            systemd_lease = self._require_systemd_lease(ownership)
            raw_result = self._systemd.read_output(
                systemd_lease,
                output_fd=execution_channels.output_fd,
                timeout_seconds=self._remaining(deadline),
                ownership=ownership.systemd,
            )
            result = self._decode_result(raw_result)
        except BaseException as error:
            primary_error = error

        with self._active_lock:
            owns_record = self._active.get(request.request_id) is ownership
        if not owns_record:
            cleanup_errors: list[BaseException] = []
            if not ownership.received_closed:
                try:
                    ownership.received.close()
                    ownership.received_closed = True
                except BaseException as error:
                    cleanup_errors.append(error)
            self._raise_failures(primary_error, cleanup_errors)
            raise ProbeExecutionError("probe_execution_failed")
        with self._active_lock:
            if self._active.get(request.request_id) is ownership:
                ownership.state = "cleaning"
        cleanup_deadline = self._cleanup_deadline()
        cleanup_errors = self._cleanup_ownership(ownership, deadline=cleanup_deadline)

        self._raise_failures(primary_error, cleanup_errors)
        if not ownership.collected:
            raise ProbeExecutionError("probe_execution_cleanup_pending")
        if not isinstance(result, ProbeExecutionResult):
            raise ProbeExecutionError("probe_execution_result_invalid")
        return result

    def retry_pending_cleanup(self, *, timeout_seconds: float) -> int:
        timeout = self._validate_timeout(timeout_seconds)
        if not self._retry_lock.acquire(blocking=False):
            return self._unresolved_cleanup_count()
        try:
            deadline = self._monotonic_deadline(timeout)
            with self._active_lock:
                pending = tuple(
                    (request_id, ownership)
                    for request_id, ownership in self._active.items()
                    if ownership.state != "executing"
                )
            interruptions: list[BaseException] = []
            for request_id, ownership in pending:
                if self._remaining_or_none(deadline) is None:
                    break
                if not ownership.operation_lock.acquire(blocking=False):
                    continue
                claimed = False
                try:
                    with self._active_lock:
                        if (
                            self._active.get(request_id) is not ownership
                            or ownership.state == "executing"
                        ):
                            continue
                        ownership.state = "cleaning"
                        claimed = True
                    errors = self._cleanup_ownership(ownership, deadline=deadline)
                    interruptions.extend(
                        error for error in errors if not isinstance(error, Exception)
                    )
                except BaseException as error:
                    interruptions.append(error)
                finally:
                    try:
                        if claimed:
                            self._finalize_ownership(request_id, ownership)
                    finally:
                        ownership.operation_lock.release()
            if interruptions:
                raise BaseExceptionGroup(
                    "probe execution cleanup retry was interrupted",
                    [_sanitize_interruption(error) for error in interruptions],
                ) from None
            return self._unresolved_cleanup_count()
        finally:
            self._retry_lock.release()

    def _cleanup_ownership(
        self,
        ownership: _ExecutionOwnership,
        *,
        deadline: float,
    ) -> list[BaseException]:
        errors: list[BaseException] = []
        systemd_lease = ownership.systemd.value
        if systemd_lease is not None:
            remaining = self._remaining_or_none(deadline)
            if remaining is not None:
                try:
                    self._systemd.ensure_collected(
                        systemd_lease,
                        timeout_seconds=remaining,
                        ownership=ownership.systemd,
                    )
                except BaseException as error:
                    errors.append(error)

        if ownership.systemd.value is not None:
            return errors

        guard_lease = ownership.guard.value
        if guard_lease is not None:
            remaining = self._remaining_or_none(deadline)
            if remaining is not None:
                try:
                    self._guard.ensure_released(
                        guard_lease,
                        timeout_seconds=remaining,
                        ownership=ownership.guard,
                    )
                except BaseException as error:
                    errors.append(error)

        if ownership.guard.value is not None:
            return errors

        execution_channels = ownership.channels.value
        if execution_channels is not None:
            try:
                execution_channels.close()
                ownership.channels.release(execution_channels)
            except BaseException as error:
                errors.append(error)
        if ownership.channels.value is not None:
            return errors

        if not ownership.received_closed:
            try:
                ownership.received.close()
                ownership.received_closed = True
            except BaseException as error:
                errors.append(error)
        return errors

    def _execution_deadline(
        self,
        request: ProbeBrokerRequest,
        *,
        timeout_seconds: float,
    ) -> float:
        remaining_request = self._request_remaining_seconds(request)
        return self._monotonic_deadline(min(timeout_seconds, remaining_request))

    def _request_remaining_seconds(self, request: ProbeBrokerRequest) -> float:
        try:
            observed_at = self._wall_clock_ms()
        except (ArithmeticError, OSError, TypeError, ValueError):
            raise ProbeExecutionError("probe_execution_timeout") from None
        if isinstance(observed_at, bool) or not isinstance(observed_at, int):
            raise ProbeExecutionError("probe_execution_timeout")
        remaining_ms = request.deadline_unix_ms - observed_at
        if remaining_ms <= 0:
            raise ProbeExecutionError("probe_execution_timeout")
        if remaining_ms > int(_MAX_EXECUTION_SECONDS * 1_000):
            raise ProbeExecutionError("probe_execution_request_invalid")
        return remaining_ms / 1_000

    def _require_request_live(self, request: ProbeBrokerRequest) -> None:
        _ = self._request_remaining_seconds(request)

    def _monotonic_deadline(self, timeout_seconds: float) -> float:
        try:
            deadline = self._monotonic() + timeout_seconds
        except (ArithmeticError, OSError, TypeError, ValueError):
            raise ProbeExecutionError("probe_execution_timeout_invalid") from None
        if not math.isfinite(deadline):
            raise ProbeExecutionError("probe_execution_timeout_invalid")
        return deadline

    def _cleanup_deadline(self) -> float:
        try:
            return self._monotonic_deadline(_CLEANUP_RESERVE_SECONDS)
        except ProbeExecutionError:
            return 0.0

    def _remaining(self, deadline: float) -> float:
        remaining = self._remaining_or_none(deadline)
        if remaining is None:
            raise ProbeExecutionError("probe_execution_timeout")
        return remaining

    def _remaining_or_none(self, deadline: float) -> float | None:
        try:
            remaining = deadline - self._monotonic()
        except (ArithmeticError, OSError, TypeError, ValueError):
            return None
        if not math.isfinite(remaining) or remaining <= 0:
            return None
        return remaining

    @staticmethod
    def _validate_timeout(timeout_seconds: float) -> float:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= _MAX_EXECUTION_SECONDS
        ):
            raise ProbeExecutionError("probe_execution_timeout_invalid")
        return float(timeout_seconds)

    def _decode_result(self, payload: bytes) -> ProbeExecutionResult:
        if not isinstance(payload, bytes) or not 1 <= len(payload) <= _MAX_OUTPUT_BYTES:
            raise ProbeExecutionError("probe_execution_result_invalid")
        try:
            result = self._decoder.decode(payload)
        except Exception:
            raise ProbeExecutionError("probe_execution_result_invalid") from None
        if not isinstance(result, ProbeExecutionResult):
            raise ProbeExecutionError("probe_execution_result_invalid")
        return result

    @staticmethod
    def _require_channels(ownership: _ExecutionOwnership) -> ProbeExecutionChannels:
        channels = ownership.channels.value
        if channels is None:
            raise ProbeExecutionError("probe_execution_ownership_invalid")
        return channels

    @staticmethod
    def _require_systemd_lease(
        ownership: _ExecutionOwnership,
    ) -> ProbeTransientLease:
        lease = ownership.systemd.value
        if lease is None:
            raise ProbeExecutionError("probe_execution_ownership_invalid")
        return lease

    def _finalize_ownership(
        self,
        request_id: UUID,
        ownership: _ExecutionOwnership,
    ) -> None:
        with self._active_lock:
            if self._active.get(request_id) is ownership:
                if ownership.collected:
                    self._active.pop(request_id)
                else:
                    ownership.state = "cleanup_pending"

    def _unresolved_cleanup_count(self) -> int:
        with self._active_lock:
            return sum(
                ownership.state == "cleanup_pending"
                for ownership in self._active.values()
            )

    @staticmethod
    def _raise_failures(
        primary: BaseException | None,
        cleanup: list[BaseException],
    ) -> None:
        if primary is None and not cleanup:
            return
        sanitized_cleanup = [_sanitize_cleanup(error) for error in cleanup]
        if primary is not None and not isinstance(primary, Exception):
            interrupted = _sanitize_interruption(primary)
            if sanitized_cleanup:
                raise BaseExceptionGroup(
                    "probe execution and cleanup were interrupted",
                    [interrupted, *sanitized_cleanup],
                ) from None
            raise interrupted from None
        if any(not isinstance(error, Exception) for error in cleanup):
            failures: list[BaseException] = []
            if primary is not None:
                failures.append(ProbeExecutionError("probe_execution_failed"))
            failures.extend(sanitized_cleanup)
            raise BaseExceptionGroup(
                "probe execution cleanup was interrupted",
                failures,
            ) from None
        if primary is not None and cleanup:
            raise ProbeExecutionError("probe_execution_and_cleanup_failed") from None
        if primary is not None:
            if isinstance(primary, ProbeExecutionError):
                raise primary from None
            raise ProbeExecutionError("probe_execution_failed") from None
        raise ProbeExecutionError("probe_execution_cleanup_failed") from None


def _sanitize_cleanup(error: BaseException) -> BaseException:
    if isinstance(error, Exception):
        return ProbeExecutionError("probe_execution_cleanup_failed")
    return _sanitize_interruption(error)


def _sanitize_interruption(error: BaseException) -> BaseException:
    if isinstance(error, BaseExceptionGroup):
        return BaseExceptionGroup(
            "probe execution was interrupted",
            [_sanitize_interruption(item) for item in error.exceptions],
        )
    if isinstance(error, KeyboardInterrupt):
        return KeyboardInterrupt("probe_execution_interrupted")
    if isinstance(error, SystemExit):
        return SystemExit(1)
    return BaseException("probe_execution_interrupted")
