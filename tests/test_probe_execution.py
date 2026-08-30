from __future__ import annotations

import os
from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest

from rtsp_proxy.probe_broker import ProbeBrokerRequest, ReceivedProbeInput
from rtsp_proxy.probe_execution import ProbeExecutionBroker, ProbeExecutionError
from rtsp_proxy.probe_executor import ProbeConnectGuardTarget
from rtsp_proxy.probe_systemd import ProbeTransientDescriptors


@dataclass(frozen=True, slots=True)
class _Lease:
    name: str


class _Channels:
    def __init__(self, events: list[str], sealed_input_fd: int) -> None:
        self.events = events
        self.sealed_input_fd = sealed_input_fd
        self.descriptors = ProbeTransientDescriptors(
            run_gate_fd=101,
            sealed_input_fd=sealed_input_fd,
            output_read_fd=102,
            output_write_fd=103,
        )
        self.output_fd = 102

    def close_child_ends(self) -> None:
        self.events.append("channels.close_child_ends")

    def release_gate(self) -> None:
        self.events.append("channels.release_gate")

    def close(self) -> None:
        self.events.append("channels.close")
        if self.sealed_input_fd >= 0:
            os.close(self.sealed_input_fd)
            self.sealed_input_fd = -1


class _ChannelFactory:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def create(self, *, sealed_input_fd: int) -> _Channels:
        self.events.append("channels.create")
        return _Channels(self.events, sealed_input_fd)


class _Systemd:
    def __init__(
        self,
        events: list[str],
        *,
        start_error: BaseException | None = None,
        read_error: BaseException | None = None,
    ) -> None:
        self.events = events
        self.start_error = start_error
        self.read_error = read_error
        self.lease = _Lease("systemd")

    def start(
        self,
        request: ProbeBrokerRequest,
        *,
        descriptors: ProbeTransientDescriptors,
        timeout_seconds: float,
    ) -> Any:
        del request, descriptors
        assert timeout_seconds > 0
        self.events.append("systemd.start")
        if self.start_error is not None:
            raise self.start_error
        return self.lease

    def read_output(
        self,
        lease: Any,
        *,
        output_fd: int,
        timeout_seconds: float,
    ) -> bytes:
        assert lease is self.lease
        assert output_fd == 102
        assert timeout_seconds > 0
        self.events.append("systemd.read_output")
        if self.read_error is not None:
            raise self.read_error
        return b'{"streams":[]}'

    def cancel(self, lease: Any) -> None:
        assert lease is self.lease
        self.events.append("systemd.cancel")


class _Cgroups:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def resolve(self, *, unit_name: str, timeout_seconds: float) -> Path:
        assert unit_name.startswith("rtsp-probe-")
        assert timeout_seconds > 0
        self.events.append("cgroup.resolve")
        return Path("/sys/fs/cgroup/rtsp-probe.slice") / unit_name


class _Guard:
    def __init__(
        self,
        events: list[str],
        *,
        install_error: BaseException | None = None,
    ) -> None:
        self.events = events
        self.install_error = install_error
        self.lease = _Lease("guard")

    def install(self, **kwargs: Any) -> Any:
        assert kwargs["timeout_seconds"] > 0
        self.events.append("guard.install")
        if self.install_error is not None:
            raise self.install_error
        return self.lease

    def release(self, lease: Any, *, timeout_seconds: float) -> None:
        assert lease is self.lease
        assert timeout_seconds > 0
        self.events.append("guard.release")


def _received_request() -> ReceivedProbeInput:
    descriptor = os.open(os.devnull, os.O_RDONLY)
    return ReceivedProbeInput(
        request=ProbeBrokerRequest(
            request_id=uuid4(),
            endpoint_generation=UUID("329f624b-3234-40e4-a194-0e6dd722f0de"),
            target=ProbeConnectGuardTarget(ip_address("192.0.2.10"), 8554),
            deadline_unix_ms=1_800_000_000_000,
        ),
        _descriptor=descriptor,
    )


def _broker(
    events: list[str],
    *,
    systemd: _Systemd | None = None,
    guard: _Guard | None = None,
) -> ProbeExecutionBroker:
    return ProbeExecutionBroker(
        systemd=systemd or _Systemd(events),
        guard=guard or _Guard(events),
        cgroups=_Cgroups(events),
        channels=_ChannelFactory(events),
    )


def test_probe_execution_orders_guard_before_release_and_collects_everything() -> None:
    events: list[str] = []
    received = _received_request()

    output = _broker(events).execute(received, timeout_seconds=5.0)

    assert output == b'{"streams":[]}'
    assert events == [
        "channels.create",
        "systemd.start",
        "channels.close_child_ends",
        "cgroup.resolve",
        "guard.install",
        "channels.release_gate",
        "systemd.read_output",
        "guard.release",
        "channels.close",
    ]
    with pytest.raises(RuntimeError, match="probe_broker_descriptor_closed"):
        _ = received.descriptor


def test_probe_execution_cancels_transient_when_guard_install_fails() -> None:
    events: list[str] = []
    received = _received_request()
    guard = _Guard(events, install_error=RuntimeError("guard failed"))

    with pytest.raises(ProbeExecutionError, match="probe_execution_failed"):
        _broker(events, guard=guard).execute(received, timeout_seconds=5.0)

    assert events == [
        "channels.create",
        "systemd.start",
        "channels.close_child_ends",
        "cgroup.resolve",
        "guard.install",
        "systemd.cancel",
        "channels.close",
    ]


def test_probe_execution_releases_guard_after_output_failure_without_double_cancel() -> None:
    events: list[str] = []
    received = _received_request()
    systemd = _Systemd(events, read_error=RuntimeError("output failed"))

    with pytest.raises(ProbeExecutionError, match="probe_execution_failed"):
        _broker(events, systemd=systemd).execute(received, timeout_seconds=5.0)

    assert events == [
        "channels.create",
        "systemd.start",
        "channels.close_child_ends",
        "cgroup.resolve",
        "guard.install",
        "channels.release_gate",
        "systemd.read_output",
        "guard.release",
        "channels.close",
    ]


def test_probe_execution_preserves_interruption_and_runs_reverse_cleanup() -> None:
    events: list[str] = []
    received = _received_request()
    guard = _Guard(events, install_error=KeyboardInterrupt("interrupted"))

    with pytest.raises(KeyboardInterrupt, match="interrupted"):
        _broker(events, guard=guard).execute(received, timeout_seconds=5.0)

    assert events[-2:] == ["systemd.cancel", "channels.close"]
