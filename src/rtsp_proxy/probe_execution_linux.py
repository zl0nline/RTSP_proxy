from __future__ import annotations

import ctypes
import io
import os
import re
import stat
import sys
import time
from collections.abc import Callable
from math import isfinite
from pathlib import Path
from typing import TYPE_CHECKING

from rtsp_proxy.probe_broker import ReceivedProbeInput
from rtsp_proxy.probe_executor import validate_sealed_probe_input
from rtsp_proxy.probe_systemd import ProbeTransientDescriptors

if TYPE_CHECKING:
    from rtsp_proxy.probe_execution import ProbeExecutionChannels


class ProbeExecutionLinuxError(RuntimeError):
    """The Linux probe-execution descriptor boundary failed closed."""


class _OwnedPipe:
    """Two native pipe slots transferred into object-owned file handles."""

    def __init__(self) -> None:
        self._raw_descriptors = (ctypes.c_int * 2)(-1, -1)
        self._endpoints = (
            _OwnedFileDescriptor("rb"),
            _OwnedFileDescriptor("wb"),
        )

    def acquire(self) -> None:
        if self._raw_descriptors[0] >= 0 or self._raw_descriptors[1] >= 0:
            raise ProbeExecutionLinuxError("probe_execution_channels_invalid")
        libc = ctypes.CDLL(None, use_errno=True)
        try:
            pipe2 = libc.pipe2
        except AttributeError:
            raise ProbeExecutionLinuxError("probe_execution_linux_required") from None
        pipe2.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.c_int]
        pipe2.restype = ctypes.c_int
        if pipe2(self._raw_descriptors, os.O_CLOEXEC) != 0:
            raise ProbeExecutionLinuxError("probe_execution_channel_allocation_failed")
        self._settle_raw_descriptor(0)
        self._settle_raw_descriptor(1)

    @property
    def read_descriptor(self) -> int:
        return self._endpoints[0].descriptor

    @property
    def write_descriptor(self) -> int:
        return self._endpoints[1].descriptor

    def close_read(self) -> None:
        self._close(0)

    def close_write(self) -> None:
        self._close(1)

    def close(self) -> list[BaseException]:
        errors: list[BaseException] = []
        for index in (1, 0):
            try:
                self._settle_raw_descriptor(index)
            except BaseException as error:
                errors.append(_sanitize_cleanup_error(error))
                continue
            try:
                self._endpoints[index].close()
            except BaseException as error:
                errors.append(_sanitize_cleanup_error(error))
        return errors

    def _close(self, index: int) -> None:
        self._settle_raw_descriptor(index)
        self._endpoints[index].close()

    def _settle_raw_descriptor(self, index: int) -> None:
        descriptor = int(self._raw_descriptors[index])
        if descriptor < 0:
            return
        endpoint = self._endpoints[index]
        if not endpoint.owns(descriptor):
            endpoint.adopt(descriptor)
        if not endpoint.owns(descriptor):
            raise ProbeExecutionLinuxError("probe_execution_channel_allocation_failed")
        self._raw_descriptors[index] = -1


class _OwnedFileDescriptor:
    """A pre-created C owner whose close state is not reconstructed from fd metadata."""

    def __init__(self, mode: str) -> None:
        self._mode = mode
        self._stream = io.FileIO.__new__(io.FileIO)

    @property
    def descriptor(self) -> int:
        try:
            return self._stream.fileno()
        except (OSError, ValueError):
            raise ProbeExecutionLinuxError("probe_execution_channels_closed") from None

    def owns(self, descriptor: int) -> bool:
        try:
            return self._stream.fileno() == descriptor
        except (OSError, ValueError):
            return False

    def adopt(self, descriptor: int) -> None:
        if self._initialized():
            raise ProbeExecutionLinuxError("probe_execution_channel_allocation_failed")
        io.FileIO.__init__(self._stream, descriptor, mode=self._mode, closefd=True)

    def close(self) -> None:
        self._stream.close()

    def _initialized(self) -> bool:
        try:
            _ = self._stream.name
        except AttributeError:
            return False
        return True


class LinuxProbeExecutionChannels:
    """Own the parent and transient-service ends of one probe's channels."""

    def __init__(self) -> None:
        self._gate = _OwnedPipe()
        self._sealed_input = _OwnedPipe()
        self._output = _OwnedPipe()
        self._allocated = False

    def allocate(self, sealed_input_fd: int) -> None:
        if self._allocated or sys.platform != "linux":
            raise ProbeExecutionLinuxError("probe_execution_channels_invalid")
        if (
            isinstance(sealed_input_fd, bool)
            or not isinstance(sealed_input_fd, int)
            or sealed_input_fd < 0
        ):
            raise ProbeExecutionLinuxError("probe_execution_input_invalid")
        self._gate.acquire()
        self._sealed_input.acquire()
        self._output.acquire()
        self._sealed_input.close_write()
        try:
            os.dup2(
                sealed_input_fd,
                self._sealed_input.read_descriptor,
                inheritable=False,
            )
            validate_sealed_probe_input(self._sealed_input.read_descriptor)
        except (OSError, ValueError):
            raise ProbeExecutionLinuxError("probe_execution_input_invalid") from None
        self._allocated = True

    @property
    def descriptors(self) -> ProbeTransientDescriptors:
        if not self._allocated:
            raise ProbeExecutionLinuxError("probe_execution_channels_invalid")
        return ProbeTransientDescriptors(
            run_gate_fd=self._gate.read_descriptor,
            sealed_input_fd=self._sealed_input.read_descriptor,
            output_read_fd=self._output.read_descriptor,
            output_write_fd=self._output.write_descriptor,
        )

    @property
    def output_fd(self) -> int:
        if not self._allocated:
            raise ProbeExecutionLinuxError("probe_execution_channels_invalid")
        return self._output.read_descriptor

    def close_child_ends(self) -> None:
        errors = _close_operations(
            self._gate.close_read,
            self._sealed_input.close_read,
            self._output.close_write,
        )
        _raise_cleanup_errors(errors)

    def release_gate(self) -> None:
        descriptor = self._gate.write_descriptor
        primary: BaseException | None = None
        try:
            if os.write(descriptor, b"R") != 1:
                raise ProbeExecutionLinuxError("probe_execution_gate_failed")
        except BaseException as error:
            primary = _sanitize_operation_error(error, "probe_execution_gate_failed")
        cleanup_errors = _close_operations(self._gate.close_write)
        if primary is not None and cleanup_errors:
            raise BaseExceptionGroup(
                "probe execution gate and cleanup failed",
                [primary, *cleanup_errors],
            ) from None
        if primary is not None:
            raise primary from None
        _raise_cleanup_errors(cleanup_errors)

    def close(self) -> None:
        errors = [
            *self._output.close(),
            *self._sealed_input.close(),
            *self._gate.close(),
        ]
        _raise_cleanup_errors(errors)


class LinuxProbeExecutionChannelFactory:
    """Publish an empty owner before allocating any Linux descriptors."""

    def create_owned(
        self,
        received: ReceivedProbeInput,
        *,
        publish: Callable[[ProbeExecutionChannels], None],
    ) -> None:
        if not isinstance(received, ReceivedProbeInput) or not callable(publish):
            raise ProbeExecutionLinuxError("probe_execution_channels_invalid")
        channels = LinuxProbeExecutionChannels()
        publish(channels)
        try:
            sealed_input_fd = received.descriptor
        except Exception:
            raise ProbeExecutionLinuxError("probe_execution_input_invalid") from None
        channels.allocate(sealed_input_fd)


class LinuxSystemdCgroupResolver:
    """Resolve only the fixed cgroup-v2 path of an accepted probe unit."""

    _UNIT_NAME = re.compile(r"rtsp-probe-[0-9a-f]{32}\.service")

    def __init__(
        self,
        *,
        cgroup_root: Path = Path("/sys/fs/cgroup"),
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._cgroup_root = cgroup_root
        self._monotonic = monotonic
        self._sleep = sleep

    def resolve(self, *, unit_name: str, timeout_seconds: float) -> Path:
        if (
            not isinstance(unit_name, str)
            or self._UNIT_NAME.fullmatch(unit_name) is None
            or isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= 60
        ):
            raise ProbeExecutionLinuxError("probe_execution_cgroup_invalid")
        root = self._cgroup_root
        slice_path = root / "rtsp-probe.slice"
        expected = slice_path / unit_name
        if not (
            isinstance(root, Path)
            and root.is_absolute()
            and _directory_without_symlink(root)
            and _regular_file_without_symlink(root / "cgroup.controllers")
            and _directory_without_symlink(slice_path)
        ):
            raise ProbeExecutionLinuxError("probe_execution_cgroup_invalid")
        deadline = self._clock_sample() + float(timeout_seconds)
        while True:
            if _directory_without_symlink(expected) and _regular_file_without_symlink(
                expected / "cgroup.procs"
            ):
                return expected
            remaining = deadline - self._clock_sample()
            if not isfinite(remaining):
                raise ProbeExecutionLinuxError("probe_execution_cgroup_unavailable")
            if remaining <= 0:
                raise ProbeExecutionLinuxError("probe_execution_cgroup_unavailable")
            try:
                self._sleep(min(0.01, remaining))
            except Exception:
                raise ProbeExecutionLinuxError(
                    "probe_execution_cgroup_unavailable"
                ) from None

    def _clock_sample(self) -> float:
        try:
            sample = self._monotonic()
        except Exception:
            raise ProbeExecutionLinuxError("probe_execution_cgroup_unavailable") from None
        if (
            isinstance(sample, bool)
            or not isinstance(sample, (int, float))
            or not isfinite(sample)
        ):
            raise ProbeExecutionLinuxError("probe_execution_cgroup_unavailable")
        return float(sample)


def _close_operations(*operations: Callable[[], None]) -> list[BaseException]:
    errors: list[BaseException] = []
    for operation in operations:
        try:
            operation()
        except BaseException as error:
            errors.append(_sanitize_cleanup_error(error))
    return errors


def _sanitize_operation_error(error: BaseException, message: str) -> BaseException:
    if isinstance(error, BaseExceptionGroup):
        return error.derive(
            tuple(_sanitize_operation_error(item, message) for item in error.exceptions)
        )
    if isinstance(error, Exception):
        return ProbeExecutionLinuxError(message)
    return error


def _sanitize_cleanup_error(error: BaseException) -> BaseException:
    return _sanitize_operation_error(error, "probe_execution_channel_close_failed")


def _raise_cleanup_errors(errors: list[BaseException]) -> None:
    if not errors:
        return
    if len(errors) == 1:
        raise errors[0]
    raise BaseExceptionGroup("probe execution channel cleanup failed", errors)


def _directory_without_symlink(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return stat.S_ISDIR(metadata.st_mode) and not path.is_symlink()


def _regular_file_without_symlink(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return stat.S_ISREG(metadata.st_mode) and not path.is_symlink()
