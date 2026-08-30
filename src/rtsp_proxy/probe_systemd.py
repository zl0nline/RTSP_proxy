from __future__ import annotations

import fcntl
import os
import select
import stat
import sys
from dataclasses import dataclass, field
from ipaddress import IPv4Address
from math import isfinite
from threading import Lock
from time import monotonic
from typing import Literal, NoReturn, Protocol
from uuid import UUID

from rtsp_proxy.probe_broker import ProbeBrokerRequest
from rtsp_proxy.probe_executor import ProbeConnectGuardTarget
from rtsp_proxy.probe_ownership import OwnershipLedger

_PROBE_LAUNCHER = "/opt/rtsp-proxy/current/.venv/bin/rtsp-proxy-probe-launcher"
_PROBE_SLICE = "rtsp-probe.slice"
_LINUX_AF_UNSPEC = 0
_LINUX_AF_INET = 2
_LINUX_AF_INET6 = 10
_IP_PROTOCOL_ANY = 0
_PROBE_OUTPUT_MAX_BYTES = 65_536
_PROBE_RECOVERY_TIMEOUT_SECONDS = 7.0
_PROBE_CLEANUP_RETRY_TIMEOUT_SECONDS = 7.0
_PROBE_CLEANUP_RETRY_MAX_UNITS = 8

type _ExecStartValue = tuple[tuple[str, tuple[str, ...], bool], ...]
type _AddressFamilyFilterValue = tuple[bool, tuple[str, ...]]
type _IpAddressFilterValue = tuple[tuple[int, bytes, int], ...]
type _SocketBindFilterValue = tuple[tuple[int, int, int, int], ...]
type ProbeSystemdValue = (
    str
    | bool
    | int
    | _ExecStartValue
    | _AddressFamilyFilterValue
    | _IpAddressFilterValue
    | _SocketBindFilterValue
)
type ProbeSystemdSignature = Literal[
    "s",
    "b",
    "t",
    "u",
    "h",
    "a(sasb)",
    "(bas)",
    "a(iayu)",
    "a(iiqq)",
]
type ProbeSystemdPropertyEntry = tuple[str, ProbeSystemdSignature, ProbeSystemdValue]
type ProbeSystemdCallBody = tuple[
    str,
    Literal["fail"],
    tuple[ProbeSystemdPropertyEntry, ...],
    tuple[()],
]


class ProbeSystemdError(RuntimeError):
    """A transient probe unit could not be represented by the fixed policy."""


class ProbeSystemdStartRejected(ProbeSystemdError):
    """systemd definitively rejected StartTransientUnit before creating it."""


class ProbeSystemdStartRejectedInterruption(BaseException):
    """A definitive rejection was followed by a process-level interruption."""

    def __init__(self, interruption: BaseException) -> None:
        super().__init__("probe_transient_start_rejected_interrupted")
        self.interruption = interruption


@dataclass(frozen=True, slots=True)
class ProbeSystemdProperty:
    """One typed value in systemd's StartTransientUnit ``a(sv)`` array."""

    name: str
    signature: ProbeSystemdSignature
    value: ProbeSystemdValue


@dataclass(frozen=True, slots=True)
class ProbeTransientDescriptors:
    """Broker-owned run gate, sealed input and bounded output handles."""

    run_gate_fd: int
    sealed_input_fd: int
    output_read_fd: int
    output_write_fd: int


@dataclass(frozen=True, slots=True)
class ProbeTransientUnit:
    """Secret-free immutable request for one direct StartTransientUnit call."""

    unit_name: str
    start_mode: Literal["fail"]
    properties: tuple[ProbeSystemdProperty, ...]
    guard_target: ProbeConnectGuardTarget


@dataclass(frozen=True, slots=True)
class ProbeSystemdCall:
    """One direct system-manager method call with indexed Unix descriptors."""

    destination: str
    object_path: str
    interface: str
    member: str
    signature: str
    body: ProbeSystemdCallBody
    unix_fds: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class ProbeSystemdReply:
    """Secret-free result of accepting one transient start job."""

    job_path: str


@dataclass(frozen=True, slots=True, eq=False)
class ProbeTransientLease:
    """Opaque ownership capability for one accepted transient probe unit."""

    unit_name: str
    job_path: str
    request_id: UUID
    endpoint_generation: UUID
    guard_target: ProbeConnectGuardTarget
    deadline_unix_ms: int


@dataclass(slots=True)
class _UnitRecord:
    state: Literal[
        "starting",
        "active",
        "cleaning",
        "cleanup_pending",
        "collected",
    ]
    output_read_fd: int
    output_pipe_identity: tuple[int, int]
    lease: ProbeTransientLease | None = None
    ownership: OwnershipLedger[ProbeTransientLease] | None = field(
        default=None,
        repr=False,
    )
    operation_lock: Lock = field(default_factory=Lock, repr=False)
    cleanup_attempt_order: int = 0
    start_may_exist: bool = False


@dataclass(frozen=True, slots=True)
class _RecoveryOutcome:
    collected: bool
    interruption: BaseException | None = None


class ProbeSystemdTransport(Protocol):
    """Adapter seam for one bounded call to the system manager."""

    def call(
        self,
        request: ProbeSystemdCall,
        *,
        timeout_seconds: float,
    ) -> ProbeSystemdReply: ...

    def recover(self, unit_name: str, *, timeout_seconds: float) -> None: ...


class SystemdProbeManager:
    """Translate the fixed policy into one bounded StartTransientUnit call."""

    def __init__(self, *, transport: ProbeSystemdTransport) -> None:
        self._transport = transport
        self._units: dict[str, _UnitRecord] = {}
        self._units_lock = Lock()
        self._cleanup_retry_lock = Lock()
        self._cleanup_attempt_sequence = 0

    def start(
        self,
        request: ProbeBrokerRequest,
        *,
        descriptors: ProbeTransientDescriptors,
        timeout_seconds: float,
    ) -> ProbeTransientLease:
        lease = self._start(
            request,
            descriptors=descriptors,
            timeout_seconds=timeout_seconds,
            ownership=None,
        )
        assert lease is not None
        return lease

    def start_owned(
        self,
        request: ProbeBrokerRequest,
        *,
        descriptors: ProbeTransientDescriptors,
        timeout_seconds: float,
        ownership: OwnershipLedger[ProbeTransientLease],
    ) -> None:
        """Publish an accepted lease or recover it before returning failure."""

        _ = self._start(
            request,
            descriptors=descriptors,
            timeout_seconds=timeout_seconds,
            ownership=ownership,
        )

    def _start(
        self,
        request: ProbeBrokerRequest,
        *,
        descriptors: ProbeTransientDescriptors,
        timeout_seconds: float,
        ownership: OwnershipLedger[ProbeTransientLease] | None,
    ) -> ProbeTransientLease | None:
        if not isfinite(timeout_seconds) or timeout_seconds <= 0 or timeout_seconds > 60:
            raise ProbeSystemdError("probe_transient_timeout_invalid")
        unit = build_probe_transient_unit(request, descriptors=descriptors)
        call = _build_systemd_call(unit)
        output_pipe_identity = _pipe_identity(descriptors.output_read_fd, write_end=False)
        output_write_identity = _pipe_identity(descriptors.output_write_fd, write_end=True)
        if sys.platform == "linux" and output_pipe_identity != output_write_identity:
            raise ProbeSystemdError("probe_transient_output_mismatch")
        record = _UnitRecord(
            state="starting",
            output_read_fd=descriptors.output_read_fd,
            output_pipe_identity=output_pipe_identity,
        )
        record.operation_lock.acquire()
        lease: ProbeTransientLease | None = None
        published_owned = False
        try:
            with self._units_lock:
                if unit.unit_name in self._units:
                    raise ProbeSystemdError("probe_transient_already_active")
                self._units[unit.unit_name] = record
            lease = self._start_reserved(
                request,
                unit=unit,
                call=call,
                record=record,
                timeout_seconds=timeout_seconds,
            )
            if ownership is None:
                return lease
            record.ownership = ownership
            try:
                ownership.publish(lease)
            except BaseException as error:
                try:
                    published_owned = ownership.owns(lease)
                except BaseException as ownership_error:
                    raise BaseExceptionGroup(
                        "probe lease publication ownership is uncertain",
                        [
                            _sanitize_interruption(error),
                            _sanitize_interruption(ownership_error),
                        ],
                    ) from None
                if published_owned:
                    raise _sanitize_interruption(error) from None
                self._recover_reserved_start(
                    unit.unit_name,
                    record,
                    failure=(
                        "probe_transient_start_failed"
                        if isinstance(error, Exception)
                        else None
                    ),
                    interruption=(
                        None
                        if isinstance(error, Exception)
                        else _sanitize_interruption(error)
                    ),
                )
            published_owned = True
            return None
        finally:
            preserve_active = False
            try:
                preserve_active = published_owned or (
                    ownership is None
                    and lease is not None
                    and sys.exc_info()[0] is None
                )
            finally:
                self._release_operation(
                    unit.unit_name,
                    record,
                    preserve_active=preserve_active,
                )

    def ensure_collected(
        self,
        lease: ProbeTransientLease,
        *,
        timeout_seconds: float,
        ownership: OwnershipLedger[ProbeTransientLease],
    ) -> None:
        """Collect one exact owned unit and release its caller ledger slot."""

        _ = self._cleanup_lease(
            lease,
            output_fd=None,
            timeout_seconds=timeout_seconds,
            ownership=ownership,
        )

    def _start_reserved(
        self,
        request: ProbeBrokerRequest,
        *,
        unit: ProbeTransientUnit,
        call: ProbeSystemdCall,
        record: _UnitRecord,
        timeout_seconds: float,
    ) -> ProbeTransientLease:
        reply: ProbeSystemdReply | None = None
        failure: str | None = None
        interruption: BaseException | None = None
        try:
            record.start_may_exist = True
            reply = self._transport.call(call, timeout_seconds=timeout_seconds)
        except ProbeSystemdStartRejected:
            self._remove_record(unit.unit_name, record)
            raise ProbeSystemdStartRejected("probe_transient_start_rejected") from None
        except ProbeSystemdStartRejectedInterruption as error:
            self._remove_record(unit.unit_name, record)
            raise _sanitize_interruption(error.interruption) from None
        except Exception:
            failure = "probe_transient_start_failed"
        except BaseException as error:
            interruption = _sanitize_interruption(error)
        if failure is not None or interruption is not None:
            self._recover_reserved_start(
                unit.unit_name,
                record,
                failure=failure,
                interruption=interruption,
            )
        response_valid = False
        failure = None
        interruption = None
        try:
            response_valid = (
                isinstance(reply, ProbeSystemdReply)
                and reply.job_path.startswith("/org/freedesktop/systemd1/job/")
                and reply.job_path.removeprefix(
                    "/org/freedesktop/systemd1/job/"
                ).isdigit()
            )
        except Exception:
            failure = "probe_transient_response_invalid"
        except BaseException as error:
            interruption = _sanitize_interruption(error)
        if not response_valid and failure is None and interruption is None:
            failure = "probe_transient_response_invalid"
        if failure is not None or interruption is not None:
            self._recover_reserved_start(
                unit.unit_name,
                record,
                failure=failure,
                interruption=interruption,
            )
        assert isinstance(reply, ProbeSystemdReply)
        lease: ProbeTransientLease | None = None
        failure = None
        interruption = None
        try:
            lease = ProbeTransientLease(
                unit_name=unit.unit_name,
                job_path=reply.job_path,
                request_id=request.request_id,
                endpoint_generation=request.endpoint_generation,
                guard_target=request.target,
                deadline_unix_ms=request.deadline_unix_ms,
            )
            with self._units_lock:
                if (
                    self._units.get(unit.unit_name) is not record
                    or record.state != "starting"
                ):
                    raise ProbeSystemdError("probe_transient_state_invalid")
                record.lease = lease
                record.state = "active"
        except Exception:
            failure = "probe_transient_start_failed"
        except BaseException as error:
            interruption = _sanitize_interruption(error)
        if failure is not None or interruption is not None:
            self._recover_reserved_start(
                unit.unit_name,
                record,
                failure=failure,
                interruption=interruption,
            )
        assert lease is not None
        return lease

    def read_output(
        self,
        lease: ProbeTransientLease,
        *,
        output_fd: int,
        timeout_seconds: float,
        ownership: OwnershipLedger[ProbeTransientLease] | None = None,
    ) -> bytes:
        """Read one bounded result and always collect its exact transient unit."""

        output = self._cleanup_lease(
            lease,
            output_fd=output_fd,
            timeout_seconds=timeout_seconds,
            ownership=ownership,
        )
        if output is None:
            raise ProbeSystemdError("probe_transient_output_failed")
        return output

    def cancel(self, lease: ProbeTransientLease) -> None:
        """Stop and collect one exact active probe unit."""

        self._cleanup_lease(lease, output_fd=None, timeout_seconds=None)

    def retry_pending_cleanup(self) -> int:
        """Retry one bounded batch without waiting behind another cleanup sweep."""

        if not self._cleanup_retry_lock.acquire(blocking=False):
            return self._unresolved_cleanup_count()
        try:
            deadline = monotonic() + _PROBE_CLEANUP_RETRY_TIMEOUT_SECONDS
            with self._units_lock:
                pending = sorted(
                    (
                        (unit_name, record)
                        for unit_name, record in self._units.items()
                        if record.state in {"cleanup_pending", "collected"}
                    ),
                    key=lambda item: item[1].cleanup_attempt_order,
                )[:_PROBE_CLEANUP_RETRY_MAX_UNITS]
            interruptions: list[BaseException] = []
            for unit_name, record in pending:
                remaining = deadline - monotonic()
                if remaining <= 0:
                    break
                recovery = self._retry_pending_record(
                    unit_name,
                    record,
                    timeout_seconds=min(_PROBE_RECOVERY_TIMEOUT_SECONDS, remaining),
                )
                if recovery is not None and recovery.interruption is not None:
                    interruptions.append(recovery.interruption)
            if interruptions:
                raise BaseExceptionGroup(
                    "probe cleanup retry was interrupted",
                    interruptions,
                ) from None
            return self._unresolved_cleanup_count()
        finally:
            self._cleanup_retry_lock.release()

    def _cleanup_lease(
        self,
        lease: ProbeTransientLease,
        *,
        output_fd: int | None,
        timeout_seconds: float | None,
        ownership: OwnershipLedger[ProbeTransientLease] | None = None,
    ) -> bytes | None:
        deadline = self._cleanup_deadline(timeout_seconds)
        if not isinstance(lease, ProbeTransientLease):
            raise ProbeSystemdError("probe_transient_lease_invalid")
        with self._units_lock:
            record = self._units.get(lease.unit_name)
            if (
                record is None
                or record.lease is not lease
                or (
                    ownership is not None
                    and record.ownership is not ownership
                )
            ):
                raise ProbeSystemdError("probe_transient_lease_invalid")
        acquired = False
        try:
            acquired = record.operation_lock.acquire(blocking=False)
            if not acquired:
                raise ProbeSystemdError("probe_transient_cleanup_in_progress")
            with self._units_lock:
                if self._units.get(lease.unit_name) is not record:
                    raise ProbeSystemdError("probe_transient_lease_invalid")
                if record.lease is not lease:
                    raise ProbeSystemdError("probe_transient_lease_invalid")
                if ownership is not None and record.ownership is not ownership:
                    raise ProbeSystemdError("probe_transient_lease_invalid")
                if record.state == "collected" and ownership is not None:
                    release_collected = True
                elif record.state == "cleanup_pending" and ownership is not None:
                    record.state = "cleaning"
                    release_collected = False
                elif record.state != "active":
                    raise ProbeSystemdError("probe_transient_cleanup_in_progress")
                else:
                    record.state = "cleaning"
                    release_collected = False
            if release_collected:
                assert ownership is not None
                self._release_collected_ownership(
                    lease.unit_name,
                    record,
                    lease,
                    ownership,
                )
                return None
            output: bytes | None = None
            failure: str | None = None
            interruption: BaseException | None = None
            if output_fd is not None:
                try:
                    if (
                        output_fd != record.output_read_fd
                        or _pipe_identity(output_fd, write_end=False)
                        != record.output_pipe_identity
                    ):
                        raise ProbeSystemdError("probe_transient_output_mismatch")
                    if timeout_seconds is None:
                        raise ProbeSystemdError("probe_transient_timeout_invalid")
                    output = _read_bounded_output(
                        output_fd,
                        timeout_seconds=self._remaining_cleanup(deadline),
                    )
                except ProbeSystemdError as error:
                    failure = str(error)
                except Exception:
                    failure = "probe_transient_output_failed"
                except BaseException as error:
                    interruption = _sanitize_interruption(error)
            try:
                recovery_timeout = self._remaining_cleanup(deadline)
            except ProbeSystemdError:
                recovery = _RecoveryOutcome(collected=False)
                self._finish_recovery(
                    lease.unit_name,
                    record,
                    recovery,
                    retain_collected=ownership is not None,
                )
            else:
                recovery = self._recover_cleaning_record(
                    lease.unit_name,
                    record,
                    timeout_seconds=recovery_timeout,
                    retain_collected=ownership is not None,
                )
            _raise_after_recovery(
                failure=failure,
                interruption=interruption,
                recovery=recovery,
            )
            if ownership is not None:
                self._release_collected_ownership(
                    lease.unit_name,
                    record,
                    lease,
                    ownership,
                )
            return output
        finally:
            if acquired:
                self._release_operation(lease.unit_name, record)

    @staticmethod
    def _cleanup_deadline(timeout_seconds: float | None) -> float | None:
        if timeout_seconds is None:
            return None
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= 60
        ):
            raise ProbeSystemdError("probe_transient_timeout_invalid")
        try:
            deadline = monotonic() + timeout_seconds
        except (ArithmeticError, OSError, TypeError, ValueError):
            raise ProbeSystemdError("probe_transient_timeout_invalid") from None
        if not isfinite(deadline):
            raise ProbeSystemdError("probe_transient_timeout_invalid")
        return deadline

    @staticmethod
    def _remaining_cleanup(deadline: float | None) -> float:
        if deadline is None:
            return _PROBE_RECOVERY_TIMEOUT_SECONDS
        try:
            remaining = deadline - monotonic()
        except (ArithmeticError, OSError, TypeError, ValueError):
            raise ProbeSystemdError("probe_transient_timeout_invalid") from None
        if not isfinite(remaining) or remaining <= 0:
            raise ProbeSystemdError("probe_transient_timeout")
        return remaining

    def _retry_pending_record(
        self,
        unit_name: str,
        record: _UnitRecord,
        *,
        timeout_seconds: float,
    ) -> _RecoveryOutcome | None:
        acquired = False
        try:
            acquired = record.operation_lock.acquire(blocking=False)
            if not acquired:
                return None
            with self._units_lock:
                if (
                    self._units.get(unit_name) is not record
                    or record.state not in {"cleanup_pending", "collected"}
                ):
                    return None
                if record.ownership is not None and record.lease is not None:
                    try:
                        caller_owns = record.ownership.owns(record.lease)
                    except BaseException as error:
                        return _RecoveryOutcome(
                            collected=False,
                            interruption=_sanitize_interruption(error),
                        )
                    if caller_owns:
                        return None
                if record.state == "collected":
                    del self._units[unit_name]
                    return _RecoveryOutcome(collected=True)
                record.state = "cleaning"
            return self._recover_cleaning_record(
                unit_name,
                record,
                timeout_seconds=timeout_seconds,
            )
        finally:
            if acquired:
                self._release_operation(unit_name, record)

    def _attempt_recovery(
        self,
        unit_name: str,
        *,
        timeout_seconds: float = _PROBE_RECOVERY_TIMEOUT_SECONDS,
    ) -> _RecoveryOutcome:
        try:
            self._transport.recover(
                unit_name,
                timeout_seconds=timeout_seconds,
            )
        except Exception:
            return _RecoveryOutcome(collected=False)
        except BaseException as error:
            return _RecoveryOutcome(
                collected=False,
                interruption=_sanitize_interruption(error),
            )
        return _RecoveryOutcome(collected=True)

    def _recover_reserved_start(
        self,
        unit_name: str,
        record: _UnitRecord,
        *,
        failure: str | None,
        interruption: BaseException | None,
    ) -> NoReturn:
        self._mark_cleaning(unit_name, record)
        recovery = self._recover_cleaning_record(unit_name, record)
        _raise_after_recovery(
            failure=failure,
            interruption=interruption,
            recovery=recovery,
        )
        raise ProbeSystemdError("probe_transient_start_failed")

    def _recover_cleaning_record(
        self,
        unit_name: str,
        record: _UnitRecord,
        *,
        timeout_seconds: float = _PROBE_RECOVERY_TIMEOUT_SECONDS,
        retain_collected: bool = False,
    ) -> _RecoveryOutcome:
        try:
            recovery = self._attempt_recovery(
                unit_name,
                timeout_seconds=timeout_seconds,
            )
        except Exception:
            recovery = _RecoveryOutcome(collected=False)
        except BaseException as error:
            recovery = _RecoveryOutcome(
                collected=False,
                interruption=_sanitize_interruption(error),
            )
        self._finish_recovery(
            unit_name,
            record,
            recovery,
            retain_collected=retain_collected,
        )
        return recovery

    def _release_collected_ownership(
        self,
        unit_name: str,
        record: _UnitRecord,
        lease: ProbeTransientLease,
        ownership: OwnershipLedger[ProbeTransientLease],
    ) -> None:
        try:
            ownership.release(lease)
        except BaseException:
            if not ownership.owns(lease):
                self._remove_record(unit_name, record)
            raise
        self._remove_record(unit_name, record)

    def _mark_cleaning(self, unit_name: str, record: _UnitRecord) -> None:
        with self._units_lock:
            if self._units.get(unit_name) is not record or record.state not in {
                "starting",
                "active",
            }:
                raise ProbeSystemdError("probe_transient_state_invalid")
            record.state = "cleaning"

    def _unresolved_cleanup_count(self) -> int:
        with self._units_lock:
            return sum(
                record.state in {"cleaning", "cleanup_pending", "collected"}
                for record in self._units.values()
            )

    def _finish_recovery(
        self,
        unit_name: str,
        record: _UnitRecord,
        recovery: _RecoveryOutcome,
        *,
        retain_collected: bool = False,
    ) -> None:
        with self._units_lock:
            if self._units.get(unit_name) is not record or record.state != "cleaning":
                raise ProbeSystemdError("probe_transient_state_invalid")
            if recovery.collected:
                if retain_collected:
                    record.state = "collected"
                else:
                    del self._units[unit_name]
            else:
                self._mark_cleanup_pending_locked(record)

    def _release_operation(
        self,
        unit_name: str,
        record: _UnitRecord,
        *,
        preserve_active: bool = False,
    ) -> None:
        try:
            with self._units_lock:
                if self._units.get(unit_name) is record:
                    if record.state == "starting" and not record.start_may_exist:
                        del self._units[unit_name]
                    elif record.state in {"starting", "cleaning"} or (
                        record.state == "active" and not preserve_active
                    ):
                        self._mark_cleanup_pending_locked(record)
        finally:
            record.operation_lock.release()

    def _mark_cleanup_pending_locked(self, record: _UnitRecord) -> None:
        self._cleanup_attempt_sequence += 1
        record.cleanup_attempt_order = self._cleanup_attempt_sequence
        record.state = "cleanup_pending"

    def _remove_record(self, unit_name: str, record: _UnitRecord) -> None:
        with self._units_lock:
            if self._units.get(unit_name) is not record:
                raise ProbeSystemdError("probe_transient_state_invalid")
            del self._units[unit_name]


def _property(
    name: str,
    signature: ProbeSystemdSignature,
    value: ProbeSystemdValue,
) -> ProbeSystemdProperty:
    return ProbeSystemdProperty(name=name, signature=signature, value=value)


def _probe_unit_name(request: ProbeBrokerRequest) -> str:
    if not isinstance(request, ProbeBrokerRequest):
        raise ProbeSystemdError("probe_transient_request_invalid")
    return f"rtsp-probe-{request.request_id.hex}.service"


def _pipe_identity(descriptor: int, *, write_end: bool) -> tuple[int, int]:
    if isinstance(descriptor, bool) or not isinstance(descriptor, int) or descriptor < 0:
        raise ProbeSystemdError("probe_transient_output_invalid")
    try:
        metadata = os.fstat(descriptor)
        descriptor_flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
        inheritable = os.get_inheritable(descriptor)
    except (OSError, ValueError):
        raise ProbeSystemdError("probe_transient_output_invalid") from None
    expected_access = os.O_WRONLY if write_end else os.O_RDONLY
    if (
        not stat.S_ISFIFO(metadata.st_mode)
        or descriptor_flags & os.O_ACCMODE != expected_access
        or inheritable
    ):
        raise ProbeSystemdError("probe_transient_output_invalid")
    return metadata.st_dev, metadata.st_ino


def _sanitize_interruption(error: BaseException) -> BaseException:
    if isinstance(error, BaseExceptionGroup):
        return error.derive(tuple(_sanitize_interruption(item) for item in error.exceptions))
    if isinstance(error, Exception):
        return ProbeSystemdError("probe_transient_operation_failed")
    return error


def _raise_after_recovery(
    *,
    failure: str | None,
    interruption: BaseException | None,
    recovery: _RecoveryOutcome,
) -> None:
    if recovery.interruption is not None:
        errors: list[BaseException] = []
        if interruption is not None:
            errors.append(interruption)
        elif failure is not None:
            errors.append(ProbeSystemdError(failure))
        errors.append(recovery.interruption)
        raise BaseExceptionGroup(
            "probe operation and recovery were interrupted",
            errors,
        ) from None
    if not recovery.collected:
        cleanup_error = ProbeSystemdError("probe_transient_cleanup_pending")
        if interruption is not None:
            raise BaseExceptionGroup(
                "probe operation was interrupted and cleanup remains pending",
                [interruption, cleanup_error],
            ) from None
        raise cleanup_error from None
    if interruption is not None:
        raise interruption from None
    if failure is not None:
        raise ProbeSystemdError(failure) from None


def _read_bounded_output(descriptor: int, *, timeout_seconds: float) -> bytes:
    if (
        isinstance(descriptor, bool)
        or not isinstance(descriptor, int)
        or descriptor < 0
        or not isfinite(timeout_seconds)
        or timeout_seconds <= 0
        or timeout_seconds > 60
    ):
        raise ProbeSystemdError("probe_transient_output_invalid")
    _pipe_identity(descriptor, write_end=False)
    deadline = monotonic() + timeout_seconds
    output = bytearray()
    while True:
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise ProbeSystemdError("probe_transient_output_timeout")
        try:
            ready, _, _ = select.select([descriptor], [], [], remaining)
            if not ready:
                raise ProbeSystemdError("probe_transient_output_timeout")
            chunk = os.read(descriptor, min(16_384, _PROBE_OUTPUT_MAX_BYTES + 1 - len(output)))
        except ProbeSystemdError:
            raise
        except OSError:
            raise ProbeSystemdError("probe_transient_output_invalid") from None
        if not chunk:
            if not output:
                raise ProbeSystemdError("probe_transient_output_invalid")
            return bytes(output)
        output.extend(chunk)
        if len(output) > _PROBE_OUTPUT_MAX_BYTES:
            raise ProbeSystemdError("probe_transient_output_overflow")


def _build_systemd_call(unit: ProbeTransientUnit) -> ProbeSystemdCall:
    if not isinstance(unit, ProbeTransientUnit):
        raise ProbeSystemdError("probe_transient_policy_invalid")
    unix_fds: list[int] = []
    properties: list[ProbeSystemdPropertyEntry] = []
    for property_ in unit.properties:
        value = property_.value
        if property_.signature == "h":
            if isinstance(value, bool) or not isinstance(value, int):
                raise ProbeSystemdError("probe_transient_policy_invalid")
            descriptor = value
            value = len(unix_fds)
            unix_fds.append(descriptor)
        properties.append((property_.name, property_.signature, value))
    if len(unix_fds) != 3 or len(set(unix_fds)) != len(unix_fds):
        raise ProbeSystemdError("probe_transient_policy_invalid")
    return ProbeSystemdCall(
        destination="org.freedesktop.systemd1",
        object_path="/org/freedesktop/systemd1",
        interface="org.freedesktop.systemd1.Manager",
        member="StartTransientUnit",
        signature="ssa(sv)a(sa(sv))",
        body=(unit.unit_name, unit.start_mode, tuple(properties), ()),
        unix_fds=tuple(unix_fds),
    )


def _fixed_properties(descriptors: ProbeTransientDescriptors) -> tuple[ProbeSystemdProperty, ...]:
    return (
        _property("Type", "s", "exec"),
        _property("Slice", "s", _PROBE_SLICE),
        _property("CollectMode", "s", "inactive-or-failed"),
        _property("ExecStart", "a(sasb)", ((_PROBE_LAUNCHER, (_PROBE_LAUNCHER,), False),)),
        _property("StandardInputFileDescriptor", "h", descriptors.run_gate_fd),
        # systemd 255 has no ExtraFileDescriptors= transient property. The
        # quiet launcher treats fd 2 exclusively as immutable input.
        _property("StandardErrorFileDescriptor", "h", descriptors.sealed_input_fd),
        _property("StandardOutputFileDescriptor", "h", descriptors.output_write_fd),
        _property("DynamicUser", "b", True),
        _property("NoNewPrivileges", "b", True),
        _property("ProtectProc", "s", "invisible"),
        _property("PrivateTmp", "b", True),
        _property("PrivateDevices", "b", True),
        _property("ProtectSystem", "s", "strict"),
        _property("ProtectHome", "s", "yes"),
        _property("ProtectClock", "b", True),
        _property("ProtectControlGroups", "b", True),
        _property("ProtectKernelLogs", "b", True),
        _property("ProtectKernelModules", "b", True),
        _property("ProtectKernelTunables", "b", True),
        _property("RestrictSUIDSGID", "b", True),
        _property("LockPersonality", "b", True),
        _property("RestrictRealtime", "b", True),
        _property("CapabilityBoundingSet", "t", 0),
        _property("AmbientCapabilities", "t", 0),
        _property(
            "RestrictAddressFamilies",
            "(bas)",
            (True, ("AF_UNIX", "AF_INET", "AF_INET6")),
        ),
        _property(
            "SocketBindDeny",
            "a(iiqq)",
            ((_LINUX_AF_UNSPEC, _IP_PROTOCOL_ANY, 0, 0),),
        ),
        _property(
            "IPAddressDeny",
            "a(iayu)",
            (
                (_LINUX_AF_INET, bytes(4), 0),
                (_LINUX_AF_INET6, bytes(16), 0),
            ),
        ),
        _property("MemoryMax", "t", 134_217_728),
        _property("MemorySwapMax", "t", 0),
        _property("TasksMax", "t", 8),
        _property("LimitNOFILE", "t", 64),
        _property("CPUQuotaPerSecUSec", "t", 500_000),
        _property("RuntimeMaxUSec", "t", 35_000_000),
        _property("TimeoutStopUSec", "t", 5_000_000),
        _property("KillMode", "s", "control-group"),
        _property("SendSIGKILL", "b", True),
        _property("UMask", "u", 0o077),
    )


def build_probe_transient_unit(
    request: ProbeBrokerRequest,
    *,
    descriptors: ProbeTransientDescriptors,
) -> ProbeTransientUnit:
    """Build the only StartTransientUnit policy admitted by the root broker."""

    if not isinstance(request, ProbeBrokerRequest):
        raise ProbeSystemdError("probe_transient_request_invalid")
    descriptor_values = (
        descriptors.run_gate_fd,
        descriptors.sealed_input_fd,
        descriptors.output_read_fd,
        descriptors.output_write_fd,
    )
    if (
        any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in descriptor_values
        )
        or len(set(descriptor_values)) != len(descriptor_values)
    ):
        raise ProbeSystemdError("probe_transient_descriptors_invalid")

    family = _LINUX_AF_INET if isinstance(request.target.address, IPv4Address) else _LINUX_AF_INET6
    prefix_length = 32 if family == _LINUX_AF_INET else 128
    properties = (
        *_fixed_properties(descriptors),
        _property(
            "IPAddressAllow",
            "a(iayu)",
            ((family, request.target.address.packed, prefix_length),),
        ),
    )
    return ProbeTransientUnit(
        unit_name=_probe_unit_name(request),
        start_mode="fail",
        properties=properties,
        guard_target=request.target,
    )
