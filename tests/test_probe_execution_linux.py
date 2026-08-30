from __future__ import annotations

import os
import sys
from contextlib import suppress
from ipaddress import ip_address
from pathlib import Path
from types import FrameType
from typing import TYPE_CHECKING
from uuid import uuid4

import pytest

from rtsp_proxy.probe_broker import ProbeBrokerRequest, ReceivedProbeInput
from rtsp_proxy.probe_execution_linux import (
    LinuxProbeExecutionChannelFactory,
    LinuxSystemdCgroupResolver,
    ProbeExecutionLinuxError,
)
from rtsp_proxy.probe_executor import (
    ProbeConnectGuardTarget,
    create_sealed_probe_input,
    validate_sealed_probe_input,
)

if TYPE_CHECKING:
    from rtsp_proxy.probe_execution import (
        ProbeExecutionChannelFactory,
        ProbeExecutionChannels,
    )


@pytest.mark.skipif(sys.platform != "linux", reason="Linux descriptor contract")
def test_linux_execution_channels_transfer_gate_input_and_output_without_leaks() -> None:
    before = set(os.listdir("/proc/self/fd"))
    payload = (
        b"ffconcat version 1.0\n"
        b"file 'rtsp://camera:secret@192.0.2.10:8554/live'\n"
        b"option rtsp_transport tcp\n"
        b"option rtsp_flags no_redirect\n"
        b"option rw_timeout 5000000\n"
    )
    received = ReceivedProbeInput(
        request=ProbeBrokerRequest(
            request_id=uuid4(),
            endpoint_generation=uuid4(),
            target=ProbeConnectGuardTarget(
                address=ip_address("192.0.2.10"),
                port=8554,
            ),
            deadline_unix_ms=4_000_000_000_000,
        ),
        _descriptor=create_sealed_probe_input(payload),
    )
    factory: ProbeExecutionChannelFactory = LinuxProbeExecutionChannelFactory()
    published: list[ProbeExecutionChannels] = []

    try:
        factory.create_owned(
            received,
            publish=published.append,
        )
        assert len(published) == 1
        channels = published[0]
        descriptors = channels.descriptors
        child_gate = os.dup(descriptors.run_gate_fd)
        child_output = os.dup(descriptors.output_write_fd)
        try:
            assert len(
                {
                    descriptors.run_gate_fd,
                    descriptors.sealed_input_fd,
                    descriptors.output_read_fd,
                    descriptors.output_write_fd,
                }
            ) == 4
            assert all(
                not os.get_inheritable(descriptor)
                for descriptor in (
                    descriptors.run_gate_fd,
                    descriptors.sealed_input_fd,
                    descriptors.output_read_fd,
                    descriptors.output_write_fd,
                )
            )
            assert descriptors.sealed_input_fd != received.descriptor
            assert validate_sealed_probe_input(descriptors.sealed_input_fd) == len(payload)

            channels.close_child_ends()
            for descriptor in (
                descriptors.run_gate_fd,
                descriptors.sealed_input_fd,
                descriptors.output_write_fd,
            ):
                with pytest.raises(OSError):
                    os.fstat(descriptor)

            channels.release_gate()
            assert os.read(child_gate, 1) == b"R"
            os.write(child_output, b'{"status":"ok"}\n')
            os.close(child_output)
            child_output = -1
            assert os.read(channels.output_fd, 128) == b'{"status":"ok"}\n'
        finally:
            os.close(child_gate)
            if child_output >= 0:
                os.close(child_output)

        channels.close()
        channels.close()
        assert received.descriptor >= 0
    finally:
        if published:
            published[0].close()
        received.close()

    assert set(os.listdir("/proc/self/fd")) == before


def test_linux_channel_factory_publishes_owner_before_reading_input() -> None:
    received = ReceivedProbeInput(
        request=ProbeBrokerRequest(
            request_id=uuid4(),
            endpoint_generation=uuid4(),
            target=ProbeConnectGuardTarget(
                address=ip_address("192.0.2.10"),
                port=8554,
            ),
            deadline_unix_ms=4_000_000_000_000,
        ),
        _descriptor=-1,
    )
    published: list[ProbeExecutionChannels] = []

    with pytest.raises(ProbeExecutionLinuxError, match="probe_execution_input_invalid"):
        LinuxProbeExecutionChannelFactory().create_owned(
            received,
            publish=published.append,
        )

    assert len(published) == 1
    published[0].close()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux descriptor contract")
def test_linux_execution_channel_close_cannot_close_a_reused_descriptor(
) -> None:
    before = set(os.listdir("/proc/self/fd"))
    received = ReceivedProbeInput(
        request=ProbeBrokerRequest(
            request_id=uuid4(),
            endpoint_generation=uuid4(),
            target=ProbeConnectGuardTarget(
                address=ip_address("192.0.2.10"),
                port=8554,
            ),
            deadline_unix_ms=4_000_000_000_000,
        ),
        _descriptor=create_sealed_probe_input(
            b"ffconcat version 1.0\n"
            b"file 'rtsp://192.0.2.10:8554/live'\n"
            b"option rtsp_transport tcp\n"
            b"option rtsp_flags no_redirect\n"
            b"option rw_timeout 5000000\n"
        ),
    )
    published: list[ProbeExecutionChannels] = []
    LinuxProbeExecutionChannelFactory().create_owned(received, publish=published.append)
    channels = published[0]
    victim = channels.output_fd
    replacement_source = os.dup(victim)
    target_owner: object | None = None

    def interrupt_after_close(
        _frame: FrameType,
        event: str,
        argument: object,
    ) -> None:
        nonlocal target_owner
        owner = getattr(argument, "__self__", None)
        if event == "c_call" and getattr(argument, "__name__", None) == "close":
            if owner is None:
                return
            try:
                descriptor = owner.fileno()
            except (AttributeError, OSError, ValueError):
                return
            if descriptor == victim:
                target_owner = owner
        elif event == "c_return" and owner is target_owner:
            sys.setprofile(None)
            os.dup2(replacement_source, victim, inheritable=False)
            raise KeyboardInterrupt("close interrupted")

    sys.setprofile(interrupt_after_close)
    try:
        with pytest.raises(KeyboardInterrupt, match="close interrupted"):
            channels.close()
        channels.close()
        os.fstat(victim)
    finally:
        sys.setprofile(None)
        received.close()
        with suppress(OSError):
            os.close(victim)
        os.close(replacement_source)

    # Coverage/profiling may retire unrelated descriptors while this test owns
    # ``sys.setprofile``. The assertion is leak-oriented; the foreign victim is
    # checked alive above before its explicit close.
    assert not (set(os.listdir("/proc/self/fd")) - before)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux descriptor contract")
def test_linux_execution_channel_retries_a_close_interrupted_before_syscall(
) -> None:
    before = set(os.listdir("/proc/self/fd"))
    received = ReceivedProbeInput(
        request=ProbeBrokerRequest(
            request_id=uuid4(),
            endpoint_generation=uuid4(),
            target=ProbeConnectGuardTarget(
                address=ip_address("192.0.2.10"),
                port=8554,
            ),
            deadline_unix_ms=4_000_000_000_000,
        ),
        _descriptor=create_sealed_probe_input(
            b"ffconcat version 1.0\n"
            b"file 'rtsp://192.0.2.10:8554/live'\n"
            b"option rtsp_transport tcp\n"
            b"option rtsp_flags no_redirect\n"
            b"option rw_timeout 5000000\n"
        ),
    )
    published: list[ProbeExecutionChannels] = []
    LinuxProbeExecutionChannelFactory().create_owned(received, publish=published.append)
    channels = published[0]
    victim = channels.output_fd

    def interrupt_before_close(
        _frame: FrameType,
        event: str,
        argument: object,
    ) -> None:
        if event != "c_call" or getattr(argument, "__name__", None) != "close":
            return
        owner = getattr(argument, "__self__", None)
        if owner is None:
            return
        try:
            descriptor = owner.fileno()
        except (AttributeError, OSError, ValueError):
            return
        if descriptor == victim:
            sys.setprofile(None)
            raise KeyboardInterrupt("close interrupted")

    sys.setprofile(interrupt_before_close)
    try:
        with pytest.raises(KeyboardInterrupt, match="close interrupted"):
            channels.close()
        os.fstat(victim)
        channels.close()
        with pytest.raises(OSError):
            os.fstat(victim)
    finally:
        sys.setprofile(None)
        received.close()
        with suppress(OSError):
            os.close(victim)

    assert set(os.listdir("/proc/self/fd")) == before


def test_linux_cgroup_resolver_returns_only_the_exact_transient_unit(
    tmp_path: Path,
) -> None:
    cgroup_root = tmp_path / "cgroup"
    unit_name = f"rtsp-probe-{uuid4().hex}.service"
    expected = cgroup_root / "rtsp-probe.slice" / unit_name
    expected.mkdir(parents=True)
    (cgroup_root / "cgroup.controllers").write_text("cpu memory pids\n", encoding="ascii")
    (expected / "cgroup.procs").write_text("123\n", encoding="ascii")

    resolver = LinuxSystemdCgroupResolver(cgroup_root=cgroup_root)

    assert resolver.resolve(unit_name=unit_name, timeout_seconds=1.0) == expected

    foreign = cgroup_root / "rtsp-probe.slice" / "foreign.service"
    foreign.mkdir()
    with pytest.raises(RuntimeError, match="probe_execution_cgroup_invalid"):
        resolver.resolve(unit_name="foreign.service", timeout_seconds=1.0)


def test_linux_cgroup_resolver_waits_for_the_transient_slice_and_unit(
    tmp_path: Path,
) -> None:
    cgroup_root = tmp_path / "cgroup"
    unit_name = f"rtsp-probe-{uuid4().hex}.service"
    expected = cgroup_root / "rtsp-probe.slice" / unit_name
    cgroup_root.mkdir()
    (cgroup_root / "cgroup.controllers").write_text(
        "cpu memory pids\n",
        encoding="ascii",
    )
    samples = iter((0.0, 0.1))

    def create_transient_cgroup(_seconds: float) -> None:
        expected.mkdir(parents=True)
        (expected / "cgroup.procs").write_text("123\n", encoding="ascii")

    resolver = LinuxSystemdCgroupResolver(
        cgroup_root=cgroup_root,
        monotonic=lambda: next(samples),
        sleep=create_transient_cgroup,
    )

    assert resolver.resolve(unit_name=unit_name, timeout_seconds=1.0) == expected


@pytest.mark.parametrize("linked_component", ["slice", "unit", "cgroup.procs"])
def test_linux_cgroup_resolver_rejects_transient_cgroup_symlinks(
    tmp_path: Path,
    linked_component: str,
) -> None:
    cgroup_root = tmp_path / "cgroup"
    slice_path = cgroup_root / "rtsp-probe.slice"
    unit_name = f"rtsp-probe-{uuid4().hex}.service"
    expected = slice_path / unit_name
    cgroup_root.mkdir()
    (cgroup_root / "cgroup.controllers").write_text(
        "cpu memory pids\n",
        encoding="ascii",
    )
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    if linked_component == "slice":
        slice_path.symlink_to(foreign, target_is_directory=True)
    else:
        slice_path.mkdir()
        if linked_component == "unit":
            expected.symlink_to(foreign, target_is_directory=True)
        else:
            expected.mkdir()
            foreign_file = tmp_path / "foreign-procs"
            foreign_file.write_text("123\n", encoding="ascii")
            (expected / "cgroup.procs").symlink_to(foreign_file)

    resolver = LinuxSystemdCgroupResolver(
        cgroup_root=cgroup_root,
        monotonic=lambda: 0.0,
    )

    with pytest.raises(
        ProbeExecutionLinuxError,
        match="probe_execution_cgroup_invalid",
    ):
        resolver.resolve(unit_name=unit_name, timeout_seconds=1.0)


@pytest.mark.parametrize("failed_component", ["slice", "unit", "cgroup.procs"])
def test_linux_cgroup_resolver_fails_closed_on_transient_cgroup_io_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failed_component: str,
) -> None:
    cgroup_root = tmp_path / "cgroup"
    slice_path = cgroup_root / "rtsp-probe.slice"
    unit_name = f"rtsp-probe-{uuid4().hex}.service"
    expected = slice_path / unit_name
    expected.mkdir(parents=True)
    (cgroup_root / "cgroup.controllers").write_text(
        "cpu memory pids\n",
        encoding="ascii",
    )
    procs_path = expected / "cgroup.procs"
    procs_path.write_text("123\n", encoding="ascii")
    failed_path = {
        "slice": slice_path,
        "unit": expected,
        "cgroup.procs": procs_path,
    }[failed_component]
    original_lstat = Path.lstat

    def failing_lstat(path: Path) -> os.stat_result:
        if path == failed_path:
            raise OSError("simulated cgroup inventory failure")
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", failing_lstat)
    resolver = LinuxSystemdCgroupResolver(
        cgroup_root=cgroup_root,
        monotonic=lambda: 0.0,
    )

    with pytest.raises(
        ProbeExecutionLinuxError,
        match="probe_execution_cgroup_unavailable",
    ):
        resolver.resolve(unit_name=unit_name, timeout_seconds=1.0)


@pytest.mark.parametrize(
    "invalid_sample",
    [float("nan"), float("inf"), float("-inf"), RuntimeError()],
)
def test_linux_cgroup_resolver_rejects_an_invalid_clock_without_sleeping(
    tmp_path: Path,
    invalid_sample: object,
) -> None:
    cgroup_root = tmp_path / "cgroup"
    (cgroup_root / "rtsp-probe.slice").mkdir(parents=True)
    (cgroup_root / "cgroup.controllers").write_text("cpu memory pids\n", encoding="ascii")
    samples = iter((0.0, invalid_sample))

    def monotonic() -> float:
        sample = next(samples)
        if isinstance(sample, BaseException):
            raise sample
        assert isinstance(sample, float)
        return sample

    def unexpected_sleep(_seconds: float) -> None:
        raise AssertionError("invalid clocks must fail before sleeping")

    resolver = LinuxSystemdCgroupResolver(
        cgroup_root=cgroup_root,
        monotonic=monotonic,
        sleep=unexpected_sleep,
    )

    with pytest.raises(
        ProbeExecutionLinuxError,
        match="probe_execution_cgroup_unavailable",
    ):
        resolver.resolve(
            unit_name=f"rtsp-probe-{uuid4().hex}.service",
            timeout_seconds=1.0,
        )
