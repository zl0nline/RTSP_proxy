from __future__ import annotations

import os
import sys
import traceback
from dataclasses import replace
from ipaddress import ip_address
from threading import Event, Thread
from typing import Never, SupportsIndex, cast
from uuid import UUID, uuid4

import pytest

from rtsp_proxy.probe_broker import ProbeBrokerRequest
from rtsp_proxy.probe_executor import ProbeConnectGuardTarget
from rtsp_proxy.probe_systemd import (
    ProbeSystemdCall,
    ProbeSystemdError,
    ProbeSystemdReply,
    ProbeSystemdStartRejected,
    ProbeSystemdTransport,
    ProbeTransientDescriptors,
    ProbeTransientLease,
    ProbeTransientUnit,
    SystemdProbeManager,
    build_probe_transient_unit,
)

_REQUEST_ID = UUID("447a1c4e-4c79-4c50-8e51-42c4dfa5fb19")
_GENERATION = UUID("d7cbf9ca-5328-4ed2-a5eb-b9e1b0ca9914")
_NOW_MS = 1_800_000_000_000
_LAUNCHER = "/opt/rtsp-proxy/current/.venv/bin/rtsp-proxy-probe-launcher"


class _RecordingTransport(ProbeSystemdTransport):
    def __init__(
        self,
        reply: ProbeSystemdReply | BaseException,
        *,
        recovery: BaseException | None = None,
    ) -> None:
        self._reply = reply
        self.recovery = recovery
        self.calls: list[tuple[ProbeSystemdCall, float]] = []
        self.recoveries: list[tuple[str, float]] = []

    def call(self, request: ProbeSystemdCall, *, timeout_seconds: float) -> ProbeSystemdReply:
        self.calls.append((request, timeout_seconds))
        if isinstance(self._reply, BaseException):
            raise self._reply
        return self._reply

    def recover(self, unit_name: str, *, timeout_seconds: float) -> None:
        self.recoveries.append((unit_name, timeout_seconds))
        if self.recovery is not None:
            raise self.recovery


class _LeaseLedger:
    def __init__(
        self,
        *,
        interrupt: str | None = None,
        release_interrupt: str | None = None,
        owns_interrupt: bool = False,
    ) -> None:
        self.value: ProbeTransientLease | None = None
        self.interrupt = interrupt
        self.release_interrupt = release_interrupt
        self.owns_interrupt = owns_interrupt

    def publish(self, value: ProbeTransientLease) -> None:
        if self.interrupt == "before_publish":
            raise KeyboardInterrupt("publish interrupted before ownership")
        self.value = value
        if self.interrupt == "after_publish":
            raise KeyboardInterrupt("publish interrupted after ownership")

    def owns(self, value: ProbeTransientLease) -> bool:
        if self.owns_interrupt:
            self.owns_interrupt = False
            raise KeyboardInterrupt("ownership inspection interrupted")
        return self.value is value

    def release(self, value: ProbeTransientLease) -> None:
        if self.value is not value:
            raise RuntimeError("lease ownership mismatch")
        if self.release_interrupt == "before_release":
            raise KeyboardInterrupt("release interrupted before ownership")
        self.value = None
        if self.release_interrupt == "after_release":
            raise KeyboardInterrupt("release interrupted after ownership")


class _InterruptingJobPath(str):
    def startswith(
        self,
        prefix: str | tuple[str, ...],
        start: SupportsIndex | None = 0,
        end: SupportsIndex | None = None,
    ) -> bool:
        del prefix, start, end
        raise KeyboardInterrupt


class _FailingJobPath(str):
    def startswith(
        self,
        prefix: str | tuple[str, ...],
        start: SupportsIndex | None = 0,
        end: SupportsIndex | None = None,
    ) -> bool:
        del prefix, start, end
        raise RuntimeError("injected response inspection failure")


def _request(*, address: str = "192.0.2.10") -> ProbeBrokerRequest:
    return ProbeBrokerRequest(
        request_id=_REQUEST_ID,
        endpoint_generation=_GENERATION,
        target=ProbeConnectGuardTarget(address=ip_address(address), port=8554),
        deadline_unix_ms=_NOW_MS + 10_000,
    )


def _properties(unit: ProbeTransientUnit) -> dict[str, tuple[str, object]]:
    properties = unit.properties
    assert len(properties) == len({item.name for item in properties})
    return {item.name: (item.signature, item.value) for item in properties}


def test_transient_unit_is_an_exact_typed_start_transient_unit_request() -> None:
    unit = build_probe_transient_unit(
        _request(),
        descriptors=ProbeTransientDescriptors(
            run_gate_fd=7,
            sealed_input_fd=8,
            output_read_fd=6,
            output_write_fd=9,
        ),
    )

    assert unit.unit_name == "rtsp-probe-447a1c4e4c794c508e5142c4dfa5fb19.service"
    assert unit.start_mode == "fail"
    assert unit.guard_target == _request().target
    assert _properties(unit) == {
        "Type": ("s", "exec"),
        "Slice": ("s", "rtsp-probe.slice"),
        "CollectMode": ("s", "inactive-or-failed"),
        "ExecStart": ("a(sasb)", ((_LAUNCHER, (_LAUNCHER,), False),)),
        "StandardInputFileDescriptor": ("h", 7),
        "StandardErrorFileDescriptor": ("h", 8),
        "StandardOutputFileDescriptor": ("h", 9),
        "DynamicUser": ("b", True),
        "NoNewPrivileges": ("b", True),
        "ProtectProc": ("s", "invisible"),
        "PrivateTmp": ("b", True),
        "PrivateDevices": ("b", True),
        "ProtectSystem": ("s", "strict"),
        "ProtectHome": ("s", "yes"),
        "ProtectClock": ("b", True),
        "ProtectControlGroups": ("b", True),
        "ProtectKernelLogs": ("b", True),
        "ProtectKernelModules": ("b", True),
        "ProtectKernelTunables": ("b", True),
        "RestrictSUIDSGID": ("b", True),
        "LockPersonality": ("b", True),
        "RestrictRealtime": ("b", True),
        "CapabilityBoundingSet": ("t", 0),
        "AmbientCapabilities": ("t", 0),
        "RestrictAddressFamilies": ("(bas)", (True, ("AF_UNIX", "AF_INET", "AF_INET6"))),
        "SocketBindDeny": ("a(iiqq)", ((0, 0, 0, 0),)),
        "IPAddressDeny": (
            "a(iayu)",
            ((2, b"\x00" * 4, 0), (10, b"\x00" * 16, 0)),
        ),
        "IPAddressAllow": ("a(iayu)", ((2, b"\xc0\x00\x02\x0a", 32),)),
        "MemoryMax": ("t", 134_217_728),
        "MemorySwapMax": ("t", 0),
        "TasksMax": ("t", 8),
        "LimitNOFILE": ("t", 64),
        "CPUQuotaPerSecUSec": ("t", 500_000),
        "RuntimeMaxUSec": ("t", 35_000_000),
        "TimeoutStopUSec": ("t", 5_000_000),
        "KillMode": ("s", "control-group"),
        "SendSIGKILL": ("b", True),
        "UMask": ("u", 0o077),
    }

    rendered = repr((unit.unit_name, unit.start_mode, unit.properties))
    assert "systemd-run" not in rendered
    assert "--pipe" not in rendered
    assert "camera" not in rendered
    assert "secret" not in rendered
    assert "8554" not in rendered


def test_transient_unit_uses_linux_ipv6_abi_and_an_exact_host_prefix() -> None:
    unit = build_probe_transient_unit(
        _request(address="2001:db8::10"),
        descriptors=ProbeTransientDescriptors(
            run_gate_fd=7,
            sealed_input_fd=8,
            output_read_fd=6,
            output_write_fd=9,
        ),
    )

    assert _properties(unit)["IPAddressAllow"] == (
        "a(iayu)",
        ((10, ip_address("2001:db8::10").packed, 128),),
    )
    assert unit.guard_target == _request(address="2001:db8::10").target


@pytest.mark.parametrize(
    ("run_gate_fd", "sealed_input_fd", "output_read_fd", "output_write_fd"),
    [
        (-1, 8, 6, 9),
        (7, -1, 6, 9),
        (7, 8, -1, 9),
        (7, 8, 6, -1),
        (7, 7, 6, 9),
        (7, 8, 8, 9),
        (7, 8, 6, 6),
        (7, 8, 6, 7),
        (True, 8, 6, 9),
        (7, False, 6, 9),
        (7, 8, False, 9),
        (7, 8, 6, False),
    ],
)
def test_transient_unit_rejects_invalid_broker_owned_descriptors(
    run_gate_fd: int,
    sealed_input_fd: int,
    output_read_fd: int,
    output_write_fd: int,
) -> None:
    with pytest.raises(ProbeSystemdError, match="probe_transient_descriptors_invalid"):
        build_probe_transient_unit(
            _request(),
            descriptors=ProbeTransientDescriptors(
                run_gate_fd=run_gate_fd,
                sealed_input_fd=sealed_input_fd,
                output_read_fd=output_read_fd,
                output_write_fd=output_write_fd,
            ),
        )


def test_transient_unit_rejects_a_non_request_without_rendering_a_policy() -> None:
    with pytest.raises(ProbeSystemdError, match="probe_transient_request_invalid"):
        build_probe_transient_unit(
            cast(ProbeBrokerRequest, object()),
            descriptors=ProbeTransientDescriptors(
                run_gate_fd=7,
                sealed_input_fd=8,
                output_read_fd=6,
                output_write_fd=9,
            ),
        )


def test_systemd_manager_sends_the_exact_start_transient_unit_message() -> None:
    output_read_fd, output_write_fd = os.pipe()
    descriptors = ProbeTransientDescriptors(
        run_gate_fd=7,
        sealed_input_fd=8,
        output_read_fd=output_read_fd,
        output_write_fd=output_write_fd,
    )
    transport = _RecordingTransport(
        ProbeSystemdReply(job_path="/org/freedesktop/systemd1/job/42")
    )
    manager = SystemdProbeManager(transport=transport)
    try:
        result = manager.start(
            _request(),
            descriptors=descriptors,
            timeout_seconds=2.5,
        )
    finally:
        os.close(output_read_fd)
        os.close(output_write_fd)

    assert result.job_path == "/org/freedesktop/systemd1/job/42"
    assert result.request_id == _REQUEST_ID
    assert result.endpoint_generation == _GENERATION
    assert result.guard_target == _request().target
    assert result.deadline_unix_ms == _NOW_MS + 10_000
    assert len(transport.calls) == 1
    call, timeout_seconds = transport.calls[0]
    assert timeout_seconds == 2.5
    assert call.destination == "org.freedesktop.systemd1"
    assert call.object_path == "/org/freedesktop/systemd1"
    assert call.interface == "org.freedesktop.systemd1.Manager"
    assert call.member == "StartTransientUnit"
    assert call.signature == "ssa(sv)a(sa(sv))"
    assert call.body[0:2] == (
        "rtsp-probe-447a1c4e4c794c508e5142c4dfa5fb19.service",
        "fail",
    )
    assert call.body[3] == ()
    assert call.unix_fds == (7, 8, descriptors.output_write_fd)

    wire_properties = {name: (signature, value) for name, signature, value in call.body[2]}
    unit_properties = _properties(build_probe_transient_unit(_request(), descriptors=descriptors))
    assert wire_properties["StandardInputFileDescriptor"] == ("h", 0)
    assert wire_properties["StandardErrorFileDescriptor"] == ("h", 1)
    assert wire_properties["StandardOutputFileDescriptor"] == ("h", 2)
    descriptor_properties = {
        "StandardInputFileDescriptor",
        "StandardErrorFileDescriptor",
        "StandardOutputFileDescriptor",
    }
    wire_non_descriptor = {
        name: value for name, value in wire_properties.items() if name not in descriptor_properties
    }
    unit_non_descriptor = {
        name: value for name, value in unit_properties.items() if name not in descriptor_properties
    }
    assert wire_non_descriptor == unit_non_descriptor


def test_systemd_manager_sanitizes_transport_failures() -> None:
    transport = _RecordingTransport(RuntimeError("secret-bearing remote error"))
    manager = SystemdProbeManager(transport=transport)
    output_read_fd, output_write_fd = os.pipe()
    descriptors = ProbeTransientDescriptors(
        run_gate_fd=7,
        sealed_input_fd=8,
        output_read_fd=output_read_fd,
        output_write_fd=output_write_fd,
    )

    try:
        with pytest.raises(ProbeSystemdError, match=r"^probe_transient_start_failed$") as raised:
            manager.start(_request(), descriptors=descriptors, timeout_seconds=2.5)
    finally:
        os.close(output_read_fd)
        os.close(output_write_fd)

    assert "secret" not in str(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert "secret-bearing" not in "".join(traceback.format_exception(raised.value))
    assert transport.recoveries == [
        ("rtsp-probe-447a1c4e4c794c508e5142c4dfa5fb19.service", 7.0)
    ]


def test_systemd_manager_constructs_policy_internally() -> None:
    transport = _RecordingTransport(
        ProbeSystemdReply(job_path="/org/freedesktop/systemd1/job/42")
    )
    manager = SystemdProbeManager(transport=transport)

    with pytest.raises(ProbeSystemdError, match="probe_transient_request_invalid"):
        manager.start(
            cast(ProbeBrokerRequest, object()),
            descriptors=ProbeTransientDescriptors(
                run_gate_fd=7,
                sealed_input_fd=8,
                output_read_fd=6,
                output_write_fd=9,
            ),
            timeout_seconds=2.5,
        )

    assert transport.calls == []


@pytest.mark.parametrize("timeout_seconds", [0.0, -1.0, 60.1, float("inf"), float("nan")])
def test_systemd_manager_rejects_an_invalid_timeout(timeout_seconds: float) -> None:
    transport = _RecordingTransport(
        ProbeSystemdReply(job_path="/org/freedesktop/systemd1/job/42")
    )
    manager = SystemdProbeManager(transport=transport)
    descriptors = ProbeTransientDescriptors(
        run_gate_fd=7,
        sealed_input_fd=8,
        output_read_fd=6,
        output_write_fd=9,
    )

    with pytest.raises(ProbeSystemdError, match="probe_transient_timeout_invalid"):
        manager.start(_request(), descriptors=descriptors, timeout_seconds=timeout_seconds)

    assert transport.calls == []


def _start_with_output_pipe() -> tuple[
    SystemdProbeManager,
    _RecordingTransport,
    ProbeTransientLease,
    int,
    int,
]:
    output_read_fd, output_write_fd = os.pipe()
    transport = _RecordingTransport(
        ProbeSystemdReply(job_path="/org/freedesktop/systemd1/job/42")
    )
    manager = SystemdProbeManager(transport=transport)
    lease = manager.start(
        _request(),
        descriptors=ProbeTransientDescriptors(
            run_gate_fd=100,
            sealed_input_fd=101,
            output_read_fd=output_read_fd,
            output_write_fd=output_write_fd,
        ),
        timeout_seconds=2.5,
    )
    return manager, transport, lease, output_read_fd, output_write_fd


def _assert_one_bounded_recovery(
    transport: _RecordingTransport,
    *,
    maximum_seconds: float,
) -> None:
    assert len(transport.recoveries) == 1
    unit_name, timeout_seconds = transport.recoveries[0]
    assert unit_name == "rtsp-probe-447a1c4e4c794c508e5142c4dfa5fb19.service"
    assert 0 < timeout_seconds <= maximum_seconds


def test_systemd_manager_reads_bounded_output_and_collects_the_unit() -> None:
    manager, transport, lease, output_read_fd, output_write_fd = _start_with_output_pipe()
    try:
        os.write(output_write_fd, b'{"status":"ok"}\n')
        os.close(output_write_fd)
        output_write_fd = -1

        assert manager.read_output(
            lease,
            output_fd=output_read_fd,
            timeout_seconds=1.0,
        ) == b'{"status":"ok"}\n'

        with pytest.raises(ProbeSystemdError, match="probe_transient_lease_invalid"):
            manager.read_output(
                lease,
                output_fd=output_read_fd,
                timeout_seconds=1.0,
            )
        _assert_one_bounded_recovery(transport, maximum_seconds=1.0)
    finally:
        os.close(output_read_fd)
        if output_write_fd >= 0:
            os.close(output_write_fd)


def test_systemd_manager_stops_the_unit_on_output_overflow() -> None:
    manager, transport, lease, output_read_fd, output_write_fd = _start_with_output_pipe()

    def write_overflow() -> None:
        try:
            remaining = memoryview(b"x" * 65_537)
            while remaining:
                remaining = remaining[os.write(output_write_fd, remaining) :]
        finally:
            os.close(output_write_fd)

    writer = Thread(target=write_overflow)
    writer.start()
    try:
        with pytest.raises(ProbeSystemdError, match="probe_transient_output_overflow"):
            manager.read_output(
                lease,
                output_fd=output_read_fd,
                timeout_seconds=1.0,
            )
        _assert_one_bounded_recovery(transport, maximum_seconds=1.0)
    finally:
        os.close(output_read_fd)
        writer.join(timeout=1)
    assert not writer.is_alive()


def test_systemd_manager_stops_the_unit_on_output_timeout() -> None:
    manager, transport, lease, output_read_fd, output_write_fd = _start_with_output_pipe()
    try:
        with pytest.raises(ProbeSystemdError, match="probe_transient_cleanup_pending"):
            manager.read_output(
                lease,
                output_fd=output_read_fd,
                timeout_seconds=0.01,
            )
        assert transport.recoveries == []
        assert manager.retry_pending_cleanup() == 0
        _assert_one_bounded_recovery(transport, maximum_seconds=7.0)
    finally:
        os.close(output_read_fd)
        os.close(output_write_fd)


def test_systemd_manager_rejects_empty_output_and_collects_the_unit() -> None:
    manager, transport, lease, output_read_fd, output_write_fd = _start_with_output_pipe()
    os.close(output_write_fd)
    output_write_fd = -1
    try:
        with pytest.raises(ProbeSystemdError, match="probe_transient_output_invalid"):
            manager.read_output(
                lease,
                output_fd=output_read_fd,
                timeout_seconds=1.0,
            )
        _assert_one_bounded_recovery(transport, maximum_seconds=1.0)
    finally:
        os.close(output_read_fd)
        if output_write_fd >= 0:
            os.close(output_write_fd)


def test_systemd_manager_rejects_a_non_reader_output_descriptor_and_stops() -> None:
    manager, transport, lease, output_read_fd, output_write_fd = _start_with_output_pipe()
    try:
        with pytest.raises(ProbeSystemdError, match="probe_transient_output_mismatch"):
            manager.read_output(
                lease,
                output_fd=output_write_fd,
                timeout_seconds=1.0,
            )
        _assert_one_bounded_recovery(transport, maximum_seconds=1.0)
    finally:
        os.close(output_read_fd)
        os.close(output_write_fd)


def test_systemd_manager_cancels_only_an_active_exact_unit() -> None:
    manager, transport, lease, output_read_fd, output_write_fd = _start_with_output_pipe()
    try:
        with pytest.raises(ProbeSystemdError, match="probe_transient_lease_invalid"):
            manager.cancel(replace(lease))
        manager.cancel(lease)
        with pytest.raises(ProbeSystemdError, match="probe_transient_lease_invalid"):
            manager.cancel(lease)
        _assert_one_bounded_recovery(transport, maximum_seconds=7.0)
    finally:
        os.close(output_read_fd)
        os.close(output_write_fd)


def test_systemd_manager_rejects_output_from_an_unrelated_pipe() -> None:
    manager, transport, lease, output_read_fd, output_write_fd = _start_with_output_pipe()
    forged_read_fd, forged_write_fd = os.pipe()
    try:
        os.write(forged_write_fd, b'{"forged":true}\n')
        os.close(forged_write_fd)
        forged_write_fd = -1

        with pytest.raises(ProbeSystemdError, match="probe_transient_output_mismatch"):
            manager.read_output(
                lease,
                output_fd=forged_read_fd,
                timeout_seconds=1.0,
            )

        _assert_one_bounded_recovery(transport, maximum_seconds=1.0)
    finally:
        os.close(output_read_fd)
        os.close(output_write_fd)
        os.close(forged_read_fd)
        if forged_write_fd >= 0:
            os.close(forged_write_fd)


def test_systemd_manager_retains_failed_cleanup_and_allows_a_bounded_retry() -> None:
    output_read_fd, output_write_fd = os.pipe()
    transport = _RecordingTransport(
        ProbeSystemdReply(job_path="/org/freedesktop/systemd1/job/42"),
        recovery=TimeoutError("injected cleanup timeout"),
    )
    manager = SystemdProbeManager(transport=transport)
    descriptors = ProbeTransientDescriptors(
        run_gate_fd=100,
        sealed_input_fd=101,
        output_read_fd=output_read_fd,
        output_write_fd=output_write_fd,
    )
    try:
        lease = manager.start(_request(), descriptors=descriptors, timeout_seconds=1.0)

        with pytest.raises(ProbeSystemdError, match="probe_transient_cleanup_pending"):
            manager.cancel(lease)
        with pytest.raises(ProbeSystemdError, match="probe_transient_already_active"):
            manager.start(_request(), descriptors=descriptors, timeout_seconds=1.0)

        transport.recovery = None
        assert manager.retry_pending_cleanup() == 0
        replacement = manager.start(
            _request(),
            descriptors=descriptors,
            timeout_seconds=1.0,
        )
        manager.cancel(replacement)
    finally:
        os.close(output_read_fd)
        os.close(output_write_fd)


def test_systemd_manager_retains_ambiguous_start_when_initial_cleanup_fails() -> None:
    output_read_fd, output_write_fd = os.pipe()
    transport = _RecordingTransport(
        TimeoutError("injected ambiguous start"),
        recovery=TimeoutError("injected cleanup timeout"),
    )
    manager = SystemdProbeManager(transport=transport)
    descriptors = ProbeTransientDescriptors(
        run_gate_fd=100,
        sealed_input_fd=101,
        output_read_fd=output_read_fd,
        output_write_fd=output_write_fd,
    )
    try:
        with pytest.raises(ProbeSystemdError, match="probe_transient_cleanup_pending"):
            manager.start(_request(), descriptors=descriptors, timeout_seconds=1.0)
        with pytest.raises(ProbeSystemdError, match="probe_transient_already_active"):
            manager.start(_request(), descriptors=descriptors, timeout_seconds=1.0)

        transport.recovery = None
        assert manager.retry_pending_cleanup() == 0
    finally:
        os.close(output_read_fd)
        os.close(output_write_fd)


def test_systemd_manager_does_not_cleanup_a_definitive_unit_exists_rejection() -> None:
    output_read_fd, output_write_fd = os.pipe()
    transport = _RecordingTransport(
        ProbeSystemdStartRejected("probe_transient_start_rejected")
    )
    manager = SystemdProbeManager(transport=transport)
    try:
        with pytest.raises(
            ProbeSystemdStartRejected,
            match="probe_transient_start_rejected",
        ):
            manager.start(
                _request(),
                descriptors=ProbeTransientDescriptors(
                    run_gate_fd=100,
                    sealed_input_fd=101,
                    output_read_fd=output_read_fd,
                    output_write_fd=output_write_fd,
                ),
                timeout_seconds=1.0,
            )
        assert transport.recoveries == []
    finally:
        os.close(output_read_fd)
        os.close(output_write_fd)


def test_systemd_manager_preserves_grouped_process_interruption_without_secrets() -> None:
    output_read_fd, output_write_fd = os.pipe()
    transport = _RecordingTransport(
        BaseExceptionGroup(
            "system bus operation and disconnect failed",
            [KeyboardInterrupt(), RuntimeError("secret-bearing disconnect failure")],
        )
    )
    manager = SystemdProbeManager(transport=transport)
    try:
        with pytest.raises(BaseExceptionGroup) as raised:
            manager.start(
                _request(),
                descriptors=ProbeTransientDescriptors(
                    run_gate_fd=100,
                    sealed_input_fd=101,
                    output_read_fd=output_read_fd,
                    output_write_fd=output_write_fd,
                ),
                timeout_seconds=1.0,
            )

        assert any(isinstance(item, KeyboardInterrupt) for item in raised.value.exceptions)
        assert "secret-bearing" not in "".join(traceback.format_exception(raised.value))
    finally:
        os.close(output_read_fd)
        os.close(output_write_fd)


def test_systemd_manager_recovers_when_interrupted_after_start_reply() -> None:
    output_read_fd, output_write_fd = os.pipe()
    transport = _RecordingTransport(
        ProbeSystemdReply(job_path=_InterruptingJobPath("not-observed"))
    )
    manager = SystemdProbeManager(transport=transport)
    descriptors = ProbeTransientDescriptors(
        run_gate_fd=100,
        sealed_input_fd=101,
        output_read_fd=output_read_fd,
        output_write_fd=output_write_fd,
    )
    try:
        with pytest.raises(KeyboardInterrupt):
            manager.start(_request(), descriptors=descriptors, timeout_seconds=1.0)

        _assert_one_bounded_recovery(transport, maximum_seconds=7.0)
        transport._reply = ProbeSystemdReply(
            job_path="/org/freedesktop/systemd1/job/43"
        )
        replacement = manager.start(
            _request(),
            descriptors=descriptors,
            timeout_seconds=1.0,
        )
        manager.cancel(replacement)
    finally:
        os.close(output_read_fd)
        os.close(output_write_fd)


@pytest.mark.parametrize(
    "job_path",
    [
        "not-a-systemd-job-path",
        _FailingJobPath("not-observed"),
    ],
)
def test_systemd_manager_recovers_after_an_invalid_start_reply(job_path: str) -> None:
    output_read_fd, output_write_fd = os.pipe()
    transport = _RecordingTransport(ProbeSystemdReply(job_path=job_path))
    manager = SystemdProbeManager(transport=transport)
    try:
        with pytest.raises(
            ProbeSystemdError,
            match=r"^probe_transient_response_invalid$",
        ):
            manager.start(
                _request(),
                descriptors=ProbeTransientDescriptors(
                    run_gate_fd=100,
                    sealed_input_fd=101,
                    output_read_fd=output_read_fd,
                    output_write_fd=output_write_fd,
                ),
                timeout_seconds=1.0,
            )

        _assert_one_bounded_recovery(transport, maximum_seconds=7.0)
    finally:
        os.close(output_read_fd)
        os.close(output_write_fd)


@pytest.mark.parametrize(
    ("interruption", "owns_lease", "recovery_count"),
    [
        ("before_publish", False, 1),
        ("after_publish", True, 0),
    ],
)
def test_systemd_manager_transfers_or_recovers_start_ownership_atomically(
    interruption: str,
    owns_lease: bool,
    recovery_count: int,
) -> None:
    output_read_fd, output_write_fd = os.pipe()
    transport = _RecordingTransport(
        ProbeSystemdReply(job_path="/org/freedesktop/systemd1/job/42")
    )
    manager = SystemdProbeManager(transport=transport)
    ledger = _LeaseLedger(interrupt=interruption)
    try:
        with pytest.raises(KeyboardInterrupt, match="publish interrupted"):
            manager.start_owned(
                _request(),
                descriptors=ProbeTransientDescriptors(
                    run_gate_fd=100,
                    sealed_input_fd=101,
                    output_read_fd=output_read_fd,
                    output_write_fd=output_write_fd,
                ),
                timeout_seconds=1.0,
                ownership=ledger,
            )

        assert (ledger.value is not None) is owns_lease
        assert len(transport.recoveries) == recovery_count
        if ledger.value is not None:
            manager.ensure_collected(
                ledger.value,
                timeout_seconds=1.0,
                ownership=ledger,
            )
            assert ledger.value is None
            assert len(transport.recoveries) == 1
    finally:
        os.close(output_read_fd)
        os.close(output_write_fd)


@pytest.mark.parametrize(
    ("release_interruption", "ledger_retains_lease"),
    [
        ("before_release", True),
        ("after_release", False),
    ],
)
def test_systemd_manager_makes_collected_handoff_retryable(
    release_interruption: str,
    ledger_retains_lease: bool,
) -> None:
    output_read_fd, output_write_fd = os.pipe()
    transport = _RecordingTransport(
        ProbeSystemdReply(job_path="/org/freedesktop/systemd1/job/42")
    )
    manager = SystemdProbeManager(transport=transport)
    ledger = _LeaseLedger(release_interrupt=release_interruption)
    try:
        manager.start_owned(
            _request(),
            descriptors=ProbeTransientDescriptors(
                run_gate_fd=100,
                sealed_input_fd=101,
                output_read_fd=output_read_fd,
                output_write_fd=output_write_fd,
            ),
            timeout_seconds=1.0,
            ownership=ledger,
        )
        lease = ledger.value
        assert lease is not None

        with pytest.raises(KeyboardInterrupt, match="release interrupted"):
            manager.ensure_collected(
                lease,
                timeout_seconds=1.0,
                ownership=ledger,
            )
        assert (ledger.value is lease) is ledger_retains_lease
        assert len(transport.recoveries) == 1

        if ledger.value is lease:
            ledger.release_interrupt = None
            manager.ensure_collected(
                lease,
                timeout_seconds=1.0,
                ownership=ledger,
            )
            assert ledger.value is None
            assert len(transport.recoveries) == 1

        replacement = manager.start(
            _request(),
            descriptors=ProbeTransientDescriptors(
                run_gate_fd=100,
                sealed_input_fd=101,
                output_read_fd=output_read_fd,
                output_write_fd=output_write_fd,
            ),
            timeout_seconds=1.0,
        )
        manager.cancel(replacement)
    finally:
        os.close(output_read_fd)
        os.close(output_write_fd)


def test_systemd_manager_releases_operation_when_ownership_check_is_interrupted(
) -> None:
    output_read_fd, output_write_fd = os.pipe()
    transport = _RecordingTransport(
        ProbeSystemdReply(job_path="/org/freedesktop/systemd1/job/42")
    )
    manager = SystemdProbeManager(transport=transport)
    ledger = _LeaseLedger(interrupt="after_publish", owns_interrupt=True)
    try:
        with pytest.raises(BaseExceptionGroup) as interrupted:
            manager.start_owned(
                _request(),
                descriptors=ProbeTransientDescriptors(
                    run_gate_fd=100,
                    sealed_input_fd=101,
                    output_read_fd=output_read_fd,
                    output_write_fd=output_write_fd,
                ),
                timeout_seconds=1.0,
                ownership=ledger,
            )
        assert any(
            isinstance(error, KeyboardInterrupt)
            for error in interrupted.value.exceptions
        )
        lease = ledger.value
        assert lease is not None

        manager.ensure_collected(
            lease,
            timeout_seconds=1.0,
            ownership=ledger,
        )
        assert ledger.value is None
    finally:
        os.close(output_read_fd)
        os.close(output_write_fd)


def test_systemd_manager_releases_operation_when_finalizer_is_interrupted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_read_fd, output_write_fd = os.pipe()
    transport = _RecordingTransport(
        ProbeSystemdReply(job_path="/org/freedesktop/systemd1/job/42")
    )
    manager = SystemdProbeManager(transport=transport)

    class _InterruptingSys:
        platform = sys.platform

        @staticmethod
        def exc_info() -> Never:
            raise KeyboardInterrupt("systemd finalizer interrupted")

    monkeypatch.setattr("rtsp_proxy.probe_systemd.sys", _InterruptingSys)
    try:
        with pytest.raises(KeyboardInterrupt, match="systemd finalizer interrupted"):
            manager.start(
                _request(),
                descriptors=ProbeTransientDescriptors(
                    run_gate_fd=100,
                    sealed_input_fd=101,
                    output_read_fd=output_read_fd,
                    output_write_fd=output_write_fd,
                ),
                timeout_seconds=1.0,
            )

        unit_name = f"rtsp-probe-{_REQUEST_ID.hex}.service"
        record = manager._units[unit_name]
        assert record.operation_lock.acquire(blocking=False)
        record.operation_lock.release()
        assert record.lease is not None
        manager.cancel(record.lease)
    finally:
        os.close(output_read_fd)
        os.close(output_write_fd)


def test_systemd_owned_cleanup_retries_only_through_the_exact_ledger() -> None:
    output_read_fd, output_write_fd = os.pipe()
    transport = _RecordingTransport(
        ProbeSystemdReply(job_path="/org/freedesktop/systemd1/job/42"),
        recovery=TimeoutError("first cleanup failed"),
    )
    manager = SystemdProbeManager(transport=transport)
    ledger = _LeaseLedger()
    try:
        manager.start_owned(
            _request(),
            descriptors=ProbeTransientDescriptors(
                run_gate_fd=100,
                sealed_input_fd=101,
                output_read_fd=output_read_fd,
                output_write_fd=output_write_fd,
            ),
            timeout_seconds=1.0,
            ownership=ledger,
        )
        lease = ledger.value
        assert lease is not None

        with pytest.raises(ProbeSystemdError, match="probe_transient_cleanup_pending"):
            manager.ensure_collected(
                lease,
                timeout_seconds=0.5,
                ownership=ledger,
            )
        assert ledger.value is lease
        assert manager.retry_pending_cleanup() == 1
        assert len(transport.recoveries) == 1

        transport.recovery = None
        manager.ensure_collected(
            lease,
            timeout_seconds=0.5,
            ownership=ledger,
        )
        assert ledger.value is None
        assert len(transport.recoveries) == 2
    finally:
        os.close(output_read_fd)
        os.close(output_write_fd)


def test_systemd_owned_cleanup_uses_the_callers_bounded_deadline() -> None:
    output_read_fd, output_write_fd = os.pipe()
    transport = _RecordingTransport(
        ProbeSystemdReply(job_path="/org/freedesktop/systemd1/job/42")
    )
    manager = SystemdProbeManager(transport=transport)
    ledger = _LeaseLedger()
    try:
        manager.start_owned(
            _request(),
            descriptors=ProbeTransientDescriptors(
                run_gate_fd=100,
                sealed_input_fd=101,
                output_read_fd=output_read_fd,
                output_write_fd=output_write_fd,
            ),
            timeout_seconds=1.0,
            ownership=ledger,
        )
        lease = ledger.value
        assert lease is not None

        manager.ensure_collected(
            lease,
            timeout_seconds=0.25,
            ownership=ledger,
        )
        assert 0 < transport.recoveries[-1][1] <= 0.25
        with pytest.raises(
            ProbeSystemdError,
            match="probe_transient_timeout_invalid",
        ):
            manager.ensure_collected(
                lease,
                timeout_seconds=True,
                ownership=ledger,
            )
    finally:
        os.close(output_read_fd)
        os.close(output_write_fd)


def test_systemd_sweep_finalizes_a_released_terminal_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_read_fd, output_write_fd = os.pipe()
    transport = _RecordingTransport(
        ProbeSystemdReply(job_path="/org/freedesktop/systemd1/job/42")
    )
    manager = SystemdProbeManager(transport=transport)
    ledger = _LeaseLedger()
    manager.start_owned(
        _request(),
        descriptors=ProbeTransientDescriptors(
            run_gate_fd=100,
            sealed_input_fd=101,
            output_read_fd=output_read_fd,
            output_write_fd=output_write_fd,
        ),
        timeout_seconds=1.0,
        ownership=ledger,
    )
    lease = ledger.value
    assert lease is not None
    original_remove = manager._remove_record

    def interrupt_remove(*args: object, **kwargs: object) -> Never:
        del args, kwargs
        raise KeyboardInterrupt("terminal removal interrupted")

    monkeypatch.setattr(manager, "_remove_record", interrupt_remove)
    try:
        with pytest.raises(KeyboardInterrupt, match="terminal removal interrupted"):
            manager.ensure_collected(
                lease,
                timeout_seconds=1.0,
                ownership=ledger,
            )
        assert ledger.value is None
        monkeypatch.setattr(manager, "_remove_record", original_remove)
        assert manager.retry_pending_cleanup() == 0

        replacement = manager.start(
            _request(),
            descriptors=ProbeTransientDescriptors(
                run_gate_fd=100,
                sealed_input_fd=101,
                output_read_fd=output_read_fd,
                output_write_fd=output_write_fd,
            ),
            timeout_seconds=1.0,
        )
        manager.cancel(replacement)
    finally:
        os.close(output_read_fd)
        os.close(output_write_fd)


@pytest.mark.parametrize("interruption", [False, True])
def test_systemd_manager_recovers_after_an_unexpected_output_reader_failure(
    monkeypatch: pytest.MonkeyPatch,
    interruption: bool,
) -> None:
    manager, transport, lease, output_read_fd, output_write_fd = _start_with_output_pipe()

    def fail_read(*args: object, **kwargs: object) -> Never:
        del args, kwargs
        if interruption:
            raise KeyboardInterrupt
        raise RuntimeError("injected output reader failure")

    monkeypatch.setattr("rtsp_proxy.probe_systemd._read_bounded_output", fail_read)
    try:
        expected = KeyboardInterrupt if interruption else ProbeSystemdError
        match = None if interruption else r"^probe_transient_output_failed$"
        with pytest.raises(expected, match=match):
            manager.read_output(
                lease,
                output_fd=output_read_fd,
                timeout_seconds=1.0,
            )

        _assert_one_bounded_recovery(transport, maximum_seconds=1.0)
    finally:
        os.close(output_read_fd)
        os.close(output_write_fd)


def test_systemd_manager_groups_an_interrupted_pending_cleanup_retry() -> None:
    output_read_fd, output_write_fd = os.pipe()
    transport = _RecordingTransport(
        ProbeSystemdReply(job_path="/org/freedesktop/systemd1/job/42"),
        recovery=TimeoutError("injected cleanup timeout"),
    )
    manager = SystemdProbeManager(transport=transport)
    try:
        lease = manager.start(
            _request(),
            descriptors=ProbeTransientDescriptors(
                run_gate_fd=100,
                sealed_input_fd=101,
                output_read_fd=output_read_fd,
                output_write_fd=output_write_fd,
            ),
            timeout_seconds=1.0,
        )
        with pytest.raises(ProbeSystemdError, match="probe_transient_cleanup_pending"):
            manager.cancel(lease)

        transport.recovery = KeyboardInterrupt()
        with pytest.raises(BaseExceptionGroup) as interrupted:
            manager.retry_pending_cleanup()
        assert any(
            isinstance(error, KeyboardInterrupt)
            for error in interrupted.value.exceptions
        )

        transport.recovery = None
        assert manager.retry_pending_cleanup() == 0
    finally:
        os.close(output_read_fd)
        os.close(output_write_fd)


def test_systemd_manager_rejects_a_non_lease_cleanup_request() -> None:
    manager = SystemdProbeManager(
        transport=_RecordingTransport(
            ProbeSystemdReply(job_path="/org/freedesktop/systemd1/job/42")
        )
    )

    with pytest.raises(ProbeSystemdError, match="probe_transient_lease_invalid"):
        manager.cancel(cast(ProbeTransientLease, object()))


def test_systemd_manager_retains_reservation_interrupted_before_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_read_fd, output_write_fd = os.pipe()
    transport = _RecordingTransport(
        ProbeSystemdReply(job_path="/org/freedesktop/systemd1/job/42")
    )
    manager = SystemdProbeManager(transport=transport)
    descriptors = ProbeTransientDescriptors(
        run_gate_fd=100,
        sealed_input_fd=101,
        output_read_fd=output_read_fd,
        output_write_fd=output_write_fd,
    )

    def interrupt_reserved_start(*args: object, **kwargs: object) -> Never:
        del args, kwargs
        raise KeyboardInterrupt

    monkeypatch.setattr(manager, "_start_reserved", interrupt_reserved_start)
    try:
        with pytest.raises(KeyboardInterrupt):
            manager.start(_request(), descriptors=descriptors, timeout_seconds=1.0)
        monkeypatch.undo()
        assert manager.retry_pending_cleanup() == 0
        assert transport.recoveries == []
        replacement = manager.start(
            _request(),
            descriptors=descriptors,
            timeout_seconds=1.0,
        )
        manager.cancel(replacement)
    finally:
        os.close(output_read_fd)
        os.close(output_write_fd)


def test_systemd_manager_retains_accepted_unit_interrupted_before_lease_return(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_read_fd, output_write_fd = os.pipe()
    transport = _RecordingTransport(
        ProbeSystemdReply(job_path="/org/freedesktop/systemd1/job/42")
    )
    manager = SystemdProbeManager(transport=transport)
    descriptors = ProbeTransientDescriptors(
        run_gate_fd=100,
        sealed_input_fd=101,
        output_read_fd=output_read_fd,
        output_write_fd=output_write_fd,
    )
    original_start = manager._start_reserved

    def interrupt_after_acceptance(*args: object, **kwargs: object) -> Never:
        original_start(*args, **kwargs)  # type: ignore[arg-type]
        raise KeyboardInterrupt

    monkeypatch.setattr(manager, "_start_reserved", interrupt_after_acceptance)
    try:
        with pytest.raises(KeyboardInterrupt):
            manager.start(_request(), descriptors=descriptors, timeout_seconds=1.0)
        monkeypatch.setattr(manager, "_start_reserved", original_start)
        assert manager.retry_pending_cleanup() == 0
        assert len(transport.recoveries) == 1
        assert transport.recoveries[0][0] == (
            "rtsp-probe-447a1c4e4c794c508e5142c4dfa5fb19.service"
        )
        assert 0 < transport.recoveries[0][1] <= 7.0
    finally:
        os.close(output_read_fd)
        os.close(output_write_fd)


def test_systemd_manager_retains_cleanup_interrupted_by_process_signal() -> None:
    output_read_fd, output_write_fd = os.pipe()
    transport = _RecordingTransport(
        ProbeSystemdReply(job_path="/org/freedesktop/systemd1/job/42"),
        recovery=KeyboardInterrupt(),
    )
    manager = SystemdProbeManager(transport=transport)
    try:
        lease = manager.start(
            _request(),
            descriptors=ProbeTransientDescriptors(
                run_gate_fd=100,
                sealed_input_fd=101,
                output_read_fd=output_read_fd,
                output_write_fd=output_write_fd,
            ),
            timeout_seconds=1.0,
        )

        with pytest.raises(BaseExceptionGroup) as interrupted:
            manager.cancel(lease)
        assert any(
            isinstance(error, KeyboardInterrupt)
            for error in interrupted.value.exceptions
        )
        with pytest.raises(ProbeSystemdError, match="probe_transient_cleanup_in_progress"):
            manager.cancel(lease)

        transport.recovery = None
        assert manager.retry_pending_cleanup() == 0
    finally:
        os.close(output_read_fd)
        os.close(output_write_fd)


def test_systemd_manager_retains_cleanup_when_recovery_entry_is_interrupted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, _, lease, output_read_fd, output_write_fd = _start_with_output_pipe()
    original_attempt = manager._attempt_recovery

    def interrupt_recovery(
        unit_name: str,
        *,
        timeout_seconds: float = 7.0,
    ) -> Never:
        del unit_name, timeout_seconds
        raise KeyboardInterrupt

    monkeypatch.setattr(manager, "_attempt_recovery", interrupt_recovery)
    try:
        with pytest.raises(BaseExceptionGroup) as interrupted:
            manager.cancel(lease)
        assert any(
            isinstance(error, KeyboardInterrupt)
            for error in interrupted.value.exceptions
        )
        with pytest.raises(ProbeSystemdError, match="probe_transient_cleanup_in_progress"):
            manager.cancel(lease)

        monkeypatch.setattr(manager, "_attempt_recovery", original_attempt)
        assert manager.retry_pending_cleanup() == 0
    finally:
        os.close(output_read_fd)
        os.close(output_write_fd)


def test_systemd_manager_retains_cleanup_interrupted_during_finalization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, _, lease, output_read_fd, output_write_fd = _start_with_output_pipe()
    original_finish = manager._finish_recovery

    def interrupt_finalization(*args: object, **kwargs: object) -> Never:
        del args, kwargs
        raise KeyboardInterrupt

    monkeypatch.setattr(manager, "_finish_recovery", interrupt_finalization)
    try:
        with pytest.raises(KeyboardInterrupt):
            manager.cancel(lease)
        with pytest.raises(ProbeSystemdError, match="probe_transient_cleanup_in_progress"):
            manager.cancel(lease)

        monkeypatch.setattr(manager, "_finish_recovery", original_finish)
        assert manager.retry_pending_cleanup() == 0
    finally:
        os.close(output_read_fd)
        os.close(output_write_fd)


def test_systemd_manager_caps_each_pending_cleanup_sweep() -> None:
    output_read_fd, output_write_fd = os.pipe()
    transport = _RecordingTransport(
        ProbeSystemdReply(job_path="/org/freedesktop/systemd1/job/42"),
        recovery=TimeoutError("injected cleanup timeout"),
    )
    manager = SystemdProbeManager(transport=transport)
    descriptors = ProbeTransientDescriptors(
        run_gate_fd=100,
        sealed_input_fd=101,
        output_read_fd=output_read_fd,
        output_write_fd=output_write_fd,
    )
    try:
        unit_names: list[str] = []
        for _ in range(10):
            lease = manager.start(
                replace(_request(), request_id=uuid4()),
                descriptors=descriptors,
                timeout_seconds=1.0,
            )
            unit_names.append(lease.unit_name)
            with pytest.raises(ProbeSystemdError, match="probe_transient_cleanup_pending"):
                manager.cancel(lease)

        recovery_count = len(transport.recoveries)
        assert manager.retry_pending_cleanup() == 10
        assert len(transport.recoveries) - recovery_count == 8

        stubborn_units = set(unit_names[:8])

        def recover_selectively(unit_name: str, *, timeout_seconds: float) -> None:
            transport.recoveries.append((unit_name, timeout_seconds))
            if unit_name in stubborn_units:
                raise TimeoutError("injected persistent cleanup timeout")

        transport.recover = recover_selectively  # type: ignore[method-assign]
        assert manager.retry_pending_cleanup() == 8
        assert set(unit_names[8:]).issubset(
            unit_name for unit_name, _ in transport.recoveries[recovery_count + 8 :]
        )

        stubborn_units.clear()
        assert manager.retry_pending_cleanup() == 0
    finally:
        os.close(output_read_fd)
        os.close(output_write_fd)


class _BlockingStartTransport(_RecordingTransport):
    def __init__(self) -> None:
        super().__init__(ProbeSystemdReply(job_path="/org/freedesktop/systemd1/job/42"))
        self.entered = Event()
        self.release = Event()

    def call(self, request: ProbeSystemdCall, *, timeout_seconds: float) -> ProbeSystemdReply:
        self.calls.append((request, timeout_seconds))
        self.entered.set()
        if not self.release.wait(timeout=1):
            raise TimeoutError("injected blocked start")
        return ProbeSystemdReply(job_path="/org/freedesktop/systemd1/job/42")


class _BlockingCleanupTransport(_RecordingTransport):
    def __init__(self) -> None:
        super().__init__(
            ProbeSystemdReply(job_path="/org/freedesktop/systemd1/job/42"),
            recovery=TimeoutError("injected initial cleanup timeout"),
        )
        self.block_cleanup = False
        self.cleanup_entered = Event()
        self.cleanup_release = Event()

    def recover(self, unit_name: str, *, timeout_seconds: float) -> None:
        self.recoveries.append((unit_name, timeout_seconds))
        if not self.block_cleanup:
            raise cast(BaseException, self.recovery)
        self.cleanup_entered.set()
        if not self.cleanup_release.wait(timeout=1):
            raise TimeoutError("injected blocked cleanup")


def test_systemd_manager_serializes_same_id_while_start_is_in_progress() -> None:
    output_read_fd, output_write_fd = os.pipe()
    transport = _BlockingStartTransport()
    manager = SystemdProbeManager(transport=transport)
    descriptors = ProbeTransientDescriptors(
        run_gate_fd=100,
        sealed_input_fd=101,
        output_read_fd=output_read_fd,
        output_write_fd=output_write_fd,
    )
    leases: list[ProbeTransientLease] = []

    def start() -> None:
        leases.append(
            manager.start(_request(), descriptors=descriptors, timeout_seconds=1.0)
        )

    thread = Thread(target=start)
    thread.start()
    try:
        assert transport.entered.wait(timeout=1)
        try:
            with pytest.raises(ProbeSystemdError, match="probe_transient_already_active"):
                manager.start(_request(), descriptors=descriptors, timeout_seconds=1.0)
        finally:
            transport.release.set()
            thread.join(timeout=1)
        assert not thread.is_alive()
        assert len(leases) == 1
        manager.cancel(leases[0])
    finally:
        transport.release.set()
        thread.join(timeout=1)
        os.close(output_read_fd)
        os.close(output_write_fd)


def test_systemd_manager_does_not_wait_behind_an_active_cleanup_sweep() -> None:
    output_read_fd, output_write_fd = os.pipe()
    transport = _BlockingCleanupTransport()
    manager = SystemdProbeManager(transport=transport)
    lease = manager.start(
        _request(),
        descriptors=ProbeTransientDescriptors(
            run_gate_fd=100,
            sealed_input_fd=101,
            output_read_fd=output_read_fd,
            output_write_fd=output_write_fd,
        ),
        timeout_seconds=1.0,
    )
    with pytest.raises(ProbeSystemdError, match="probe_transient_cleanup_pending"):
        manager.cancel(lease)
    transport.block_cleanup = True
    results: list[int] = []
    thread = Thread(target=lambda: results.append(manager.retry_pending_cleanup()))
    thread.start()
    try:
        assert transport.cleanup_entered.wait(timeout=1)
        assert manager.retry_pending_cleanup() == 1
    finally:
        transport.cleanup_release.set()
        thread.join(timeout=1)
        os.close(output_read_fd)
        os.close(output_write_fd)
    assert not thread.is_alive()
    assert results == [0]
