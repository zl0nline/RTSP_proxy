from __future__ import annotations

import math
import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

from rtsp_proxy.probe_broker import ReceivedProbeInput
from rtsp_proxy.probe_executor import ProbeConnectGuardTarget
from rtsp_proxy.probe_systemd import ProbeTransientDescriptors


class ProbeExecutionError(RuntimeError):
    """One admitted probe could not complete through the isolated executor."""


class _ExecutionChannels(Protocol):
    descriptors: ProbeTransientDescriptors
    output_fd: int

    def close_child_ends(self) -> None: ...

    def release_gate(self) -> None: ...

    def close(self) -> None: ...


class _ExecutionChannelFactory(Protocol):
    def create(self, *, sealed_input_fd: int) -> _ExecutionChannels: ...


class _SystemdController(Protocol):
    def start(
        self,
        request: Any,
        *,
        descriptors: ProbeTransientDescriptors,
        timeout_seconds: float,
    ) -> Any: ...

    def read_output(
        self,
        lease: Any,
        *,
        output_fd: int,
        timeout_seconds: float,
    ) -> bytes: ...

    def cancel(self, lease: Any) -> None: ...


class _CgroupResolver(Protocol):
    def resolve(self, *, unit_name: str, timeout_seconds: float) -> Path: ...


class _GuardController(Protocol):
    def install(
        self,
        *,
        request_id: Any,
        unit_name: str,
        cgroup_path: Path,
        target: ProbeConnectGuardTarget,
        timeout_seconds: float,
    ) -> Any: ...

    def release(self, lease: Any, *, timeout_seconds: float) -> None: ...


class ProbeExecutionBroker:
    """Execute one authenticated request behind systemd and an exact guard."""

    def __init__(
        self,
        *,
        systemd: _SystemdController,
        guard: _GuardController,
        cgroups: _CgroupResolver,
        channels: _ExecutionChannelFactory,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._systemd = systemd
        self._guard = guard
        self._cgroups = cgroups
        self._channels = channels
        self._monotonic = monotonic

    def execute(
        self,
        received: ReceivedProbeInput,
        *,
        timeout_seconds: float,
    ) -> bytes:
        if not isinstance(received, ReceivedProbeInput):
            raise ProbeExecutionError("probe_execution_request_invalid")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= 60
        ):
            raise ProbeExecutionError("probe_execution_timeout_invalid")
        try:
            deadline = self._monotonic() + timeout_seconds
        except (ArithmeticError, OSError, TypeError, ValueError):
            raise ProbeExecutionError("probe_execution_timeout_invalid") from None
        if not math.isfinite(deadline):
            raise ProbeExecutionError("probe_execution_timeout_invalid")

        request = received.request
        sealed_input_fd = received.detach()
        execution_channels: _ExecutionChannels | None = None
        systemd_lease: Any = None
        guard_lease: Any = None
        primary_error: BaseException | None = None
        result: bytes | None = None
        try:
            execution_channels = self._channels.create(
                sealed_input_fd=sealed_input_fd,
            )
            systemd_lease = self._systemd.start(
                request,
                descriptors=execution_channels.descriptors,
                timeout_seconds=self._remaining(deadline),
            )
            execution_channels.close_child_ends()
            unit_name = f"rtsp-probe-{request.request_id.hex}.service"
            cgroup_path = self._cgroups.resolve(
                unit_name=unit_name,
                timeout_seconds=self._remaining(deadline),
            )
            guard_lease = self._guard.install(
                request_id=request.request_id,
                unit_name=unit_name,
                cgroup_path=cgroup_path,
                target=request.target,
                timeout_seconds=self._remaining(deadline),
            )
            execution_channels.release_gate()
            consumed_systemd_lease = systemd_lease
            systemd_lease = None
            result = self._systemd.read_output(
                consumed_systemd_lease,
                output_fd=execution_channels.output_fd,
                timeout_seconds=self._remaining(deadline),
            )
        except BaseException as error:
            primary_error = error

        cleanup_errors: list[BaseException] = []
        if guard_lease is not None:
            consumed_guard_lease = guard_lease
            guard_lease = None
            try:
                self._guard.release(
                    consumed_guard_lease,
                    timeout_seconds=self._cleanup_timeout(deadline),
                )
            except BaseException as error:
                cleanup_errors.append(error)
        if systemd_lease is not None:
            consumed_systemd_lease = systemd_lease
            systemd_lease = None
            try:
                self._systemd.cancel(consumed_systemd_lease)
            except BaseException as error:
                cleanup_errors.append(error)
        if execution_channels is not None:
            try:
                execution_channels.close()
            except BaseException as error:
                cleanup_errors.append(error)
        else:
            try:
                os.close(sealed_input_fd)
            except BaseException as error:
                cleanup_errors.append(error)

        if primary_error is not None:
            if cleanup_errors and (
                not isinstance(primary_error, Exception)
                or any(not isinstance(error, Exception) for error in cleanup_errors)
            ):
                raise BaseExceptionGroup(
                    "probe execution and cleanup were interrupted",
                    [primary_error, *cleanup_errors],
                ) from None
            if not isinstance(primary_error, Exception):
                raise primary_error from None
            raise ProbeExecutionError("probe_execution_failed") from None
        if cleanup_errors:
            if any(not isinstance(error, Exception) for error in cleanup_errors):
                raise BaseExceptionGroup(
                    "probe execution cleanup was interrupted",
                    cleanup_errors,
                ) from None
            raise ProbeExecutionError("probe_execution_cleanup_failed") from None
        if not isinstance(result, bytes) or not result:
            raise ProbeExecutionError("probe_execution_result_invalid")
        return result

    def _remaining(self, deadline: float) -> float:
        try:
            remaining = deadline - self._monotonic()
        except (ArithmeticError, OSError, TypeError, ValueError):
            raise ProbeExecutionError("probe_execution_timeout") from None
        if not math.isfinite(remaining) or remaining <= 0:
            raise ProbeExecutionError("probe_execution_timeout")
        return remaining

    def _cleanup_timeout(self, deadline: float) -> float:
        try:
            remaining = deadline - self._monotonic()
        except (ArithmeticError, OSError, TypeError, ValueError):
            remaining = 0.0
        if not math.isfinite(remaining):
            remaining = 0.0
        return min(5.0, max(0.1, remaining))
