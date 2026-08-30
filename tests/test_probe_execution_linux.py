from __future__ import annotations

import os
import sys
from contextlib import suppress
from ipaddress import ip_address
from pathlib import Path
from uuid import uuid4

import pytest

from rtsp_proxy.probe_broker import ProbeBrokerRequest, ReceivedProbeInput
from rtsp_proxy.probe_execution_linux import (
    LinuxProbeExecutionChannelFactory,
    LinuxProbeExecutionChannels,
    LinuxSystemdCgroupResolver,
    ProbeExecutionLinuxError,
)
from rtsp_proxy.probe_executor import (
    ProbeConnectGuardTarget,
    create_sealed_probe_input,
    validate_sealed_probe_input,
)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux descriptor contract")
def test_linux_execution_channels_transfer_gate_input_and_output_without_leaks() -> None:
    before = set(os.listdir("/proc/self/fd"))
    payload = (
        b"ffconcat version 1.0\n"
        b"file 'rtsp://camera:secret@192.0.2.10:8554/live'\n"
        b"option rtsp_transport tcp\n"
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
    published: list[LinuxProbeExecutionChannels] = []

    try:
        LinuxProbeExecutionChannelFactory().create_owned(
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
    published: list[LinuxProbeExecutionChannels] = []

    with pytest.raises(ProbeExecutionLinuxError, match="probe_execution_input_invalid"):
        LinuxProbeExecutionChannelFactory().create_owned(
            received,
            publish=published.append,
        )

    assert len(published) == 1
    published[0].close()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux descriptor contract")
def test_linux_execution_channel_close_cannot_close_a_reused_descriptor(
    monkeypatch: pytest.MonkeyPatch,
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
            b"option rw_timeout 5000000\n"
        ),
    )
    published: list[LinuxProbeExecutionChannels] = []
    LinuxProbeExecutionChannelFactory().create_owned(received, publish=published.append)
    channels = published[0]
    victim = channels.output_fd
    native_close = os.close
    replacement = -1

    def close_then_interrupt(descriptor: int) -> None:
        nonlocal replacement
        native_close(descriptor)
        if descriptor == victim and replacement < 0:
            candidate = os.open(os.devnull, os.O_RDONLY)
            if candidate != victim:
                os.dup2(candidate, victim)
                native_close(candidate)
            replacement = victim
            raise KeyboardInterrupt("close interrupted")

    monkeypatch.setattr(os, "close", close_then_interrupt)
    try:
        with pytest.raises(KeyboardInterrupt, match="close interrupted"):
            channels.close()
        channels.close()
        os.fstat(replacement)
    finally:
        monkeypatch.undo()
        received.close()
        with suppress(OSError):
            native_close(replacement)

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
