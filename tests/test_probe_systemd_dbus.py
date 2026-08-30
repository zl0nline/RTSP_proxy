from __future__ import annotations

import asyncio
import os
from collections.abc import Iterator
from ipaddress import ip_address
from uuid import UUID

import pytest
from dbus_next.constants import MessageType
from dbus_next.message import Message
from dbus_next.signature import Variant

from rtsp_proxy.probe_broker import ProbeBrokerRequest
from rtsp_proxy.probe_executor import ProbeConnectGuardTarget
from rtsp_proxy.probe_systemd import (
    ProbeSystemdError,
    ProbeSystemdStartRejected,
    ProbeTransientDescriptors,
    SystemdProbeManager,
)
from rtsp_proxy.probe_systemd_dbus import DbusNextSystemdTransport


class _FakeBus:
    def __init__(self, *, reply: Message | BaseException, block_connect: bool = False) -> None:
        self._reply = reply
        self._block_connect = block_connect
        self.connected = False
        self.disconnected = False
        self.disconnect_waited = False
        self.messages: list[Message] = []

    async def connect(self) -> _FakeBus:
        if self._block_connect:
            await asyncio.Event().wait()
        self.connected = True
        return self

    async def call(self, message: Message) -> Message | None:
        self.messages.append(message)
        if isinstance(self._reply, BaseException):
            raise self._reply
        return self._reply

    def disconnect(self) -> None:
        self.disconnected = True

    async def wait_for_disconnect(self) -> None:
        self.disconnect_waited = True


class _SequencedReplyBus(_FakeBus):
    def __init__(self, *replies: Message | BaseException) -> None:
        super().__init__(reply=replies[0])
        self._replies = list(replies)

    async def call(self, message: Message) -> Message | None:
        self.messages.append(message)
        reply = self._replies.pop(0)
        if isinstance(reply, BaseException):
            raise reply
        return reply


class _DisconnectFailureBus(_FakeBus):
    def disconnect(self) -> None:
        self.disconnected = True
        raise RuntimeError("injected disconnect failure")


class _DisconnectInterruptionBus(_FakeBus):
    async def wait_for_disconnect(self) -> None:
        self.disconnect_waited = True
        raise KeyboardInterrupt()


class _DisconnectAndWaitFailureBus(_DisconnectFailureBus):
    async def wait_for_disconnect(self) -> None:
        self.disconnect_waited = True
        raise RuntimeError("injected disconnect wait failure")


def _request() -> ProbeBrokerRequest:
    return ProbeBrokerRequest(
        request_id=UUID("447a1c4e-4c79-4c50-8e51-42c4dfa5fb19"),
        endpoint_generation=UUID("d7cbf9ca-5328-4ed2-a5eb-b9e1b0ca9914"),
        target=ProbeConnectGuardTarget(address=ip_address("192.0.2.10"), port=8554),
        deadline_unix_ms=1_800_000_010_000,
    )


@pytest.fixture
def descriptors() -> Iterator[ProbeTransientDescriptors]:
    output_read_fd, output_write_fd = os.pipe()
    try:
        yield ProbeTransientDescriptors(
            run_gate_fd=7,
            sealed_input_fd=8,
            output_read_fd=output_read_fd,
            output_write_fd=output_write_fd,
        )
    finally:
        os.close(output_read_fd)
        os.close(output_write_fd)


async def _factory(bus: _FakeBus, _deadline: float) -> _FakeBus:
    return bus


class _BusSequence:
    def __init__(self, *buses: _FakeBus) -> None:
        self._buses = list(buses)

    async def __call__(self, _deadline: float) -> _FakeBus:
        return self._buses.pop(0)


class _BlockingThenRecoveryFactory:
    def __init__(self, recovery_bus: _FakeBus) -> None:
        self._recovery_bus = recovery_bus
        self.calls = 0

    async def __call__(self, _deadline: float) -> _FakeBus:
        self.calls += 1
        if self.calls == 1:
            await asyncio.Event().wait()
        return self._recovery_bus


def _method_return() -> Message:
    return Message(
        message_type=MessageType.METHOD_RETURN,
        reply_serial=1,
        signature="o",
        body=["/org/freedesktop/systemd1/job/42"],
    )


def _no_such_unit() -> Message:
    return Message(
        message_type=MessageType.ERROR,
        reply_serial=1,
        error_name="org.freedesktop.systemd1.NoSuchUnit",
    )


def _unit_exists() -> Message:
    return Message(
        message_type=MessageType.ERROR,
        reply_serial=1,
        error_name="org.freedesktop.systemd1.UnitExists",
    )


def test_dbus_transport_sends_the_exact_message_and_unix_descriptors(
    descriptors: ProbeTransientDescriptors,
) -> None:
    bus = _FakeBus(reply=_method_return())
    transport = DbusNextSystemdTransport(bus_factory=lambda deadline: _factory(bus, deadline))
    manager = SystemdProbeManager(transport=transport)

    reply = manager.start(_request(), descriptors=descriptors, timeout_seconds=1.0)

    assert reply.job_path == "/org/freedesktop/systemd1/job/42"
    assert bus.connected
    assert bus.disconnected
    assert bus.disconnect_waited
    assert len(bus.messages) == 1
    message = bus.messages[0]
    assert message.destination == "org.freedesktop.systemd1"
    assert message.path == "/org/freedesktop/systemd1"
    assert message.interface == "org.freedesktop.systemd1.Manager"
    assert message.member == "StartTransientUnit"
    assert message.signature == "ssa(sv)a(sa(sv))"
    assert message.unix_fds == [7, 8, descriptors.output_write_fd]
    assert message.body[0:2] == [
        "rtsp-probe-447a1c4e4c794c508e5142c4dfa5fb19.service",
        "fail",
    ]
    assert message.body[3] == []

    properties = {name: value for name, value in message.body[2]}
    assert all(isinstance(value, Variant) for value in properties.values())
    assert properties["StandardInputFileDescriptor"].signature == "h"
    assert properties["StandardInputFileDescriptor"].value == 0
    assert properties["StandardErrorFileDescriptor"].signature == "h"
    assert properties["StandardErrorFileDescriptor"].value == 1
    assert properties["StandardOutputFileDescriptor"].signature == "h"
    assert properties["StandardOutputFileDescriptor"].value == 2
    assert properties["IPAddressAllow"].value == [[2, b"\xc0\x00\x02\x0a", 32]]
    assert "secret" not in repr(message.body)
    assert "8554" not in repr(message.body)


def test_dbus_transport_disconnects_and_sanitizes_a_remote_failure(
    descriptors: ProbeTransientDescriptors,
) -> None:
    bus = _FakeBus(reply=RuntimeError("secret-bearing systemd failure"))
    recovery_bus = _FakeBus(reply=_no_such_unit())
    manager = SystemdProbeManager(
        transport=DbusNextSystemdTransport(bus_factory=_BusSequence(bus, recovery_bus))
    )

    with pytest.raises(ProbeSystemdError, match=r"^probe_transient_start_failed$") as raised:
        manager.start(_request(), descriptors=descriptors, timeout_seconds=1.0)

    assert bus.disconnected
    assert bus.disconnect_waited
    assert recovery_bus.disconnected
    assert recovery_bus.disconnect_waited
    assert len(recovery_bus.messages) == 1
    assert recovery_bus.messages[0].member == "StopUnit"
    assert recovery_bus.messages[0].body == [
        "rtsp-probe-447a1c4e4c794c508e5142c4dfa5fb19.service",
        "replace",
    ]
    assert "secret" not in str(raised.value)


def test_dbus_transport_sanitizes_combined_operation_and_disconnect_failures(
    descriptors: ProbeTransientDescriptors,
) -> None:
    bus = _DisconnectAndWaitFailureBus(
        reply=RuntimeError("secret-bearing systemd failure")
    )
    recovery_bus = _FakeBus(reply=_no_such_unit())
    manager = SystemdProbeManager(
        transport=DbusNextSystemdTransport(
            bus_factory=_BusSequence(bus, recovery_bus)
        )
    )

    with pytest.raises(ProbeSystemdError, match=r"^probe_transient_start_failed$") as raised:
        manager.start(_request(), descriptors=descriptors, timeout_seconds=1.0)

    assert bus.disconnected
    assert bus.disconnect_waited
    assert recovery_bus.disconnected
    assert recovery_bus.disconnect_waited
    assert "secret" not in str(raised.value)


def test_dbus_transport_uses_one_deadline_for_connect_and_call(
    descriptors: ProbeTransientDescriptors,
) -> None:
    bus = _FakeBus(reply=_method_return(), block_connect=True)
    recovery_bus = _FakeBus(reply=_no_such_unit())
    manager = SystemdProbeManager(
        transport=DbusNextSystemdTransport(bus_factory=_BusSequence(bus, recovery_bus))
    )

    with pytest.raises(ProbeSystemdError, match=r"^probe_transient_start_failed$"):
        manager.start(_request(), descriptors=descriptors, timeout_seconds=0.01)

    assert bus.disconnected
    assert bus.disconnect_waited
    assert bus.messages == []
    assert recovery_bus.disconnected
    assert recovery_bus.disconnect_waited


def test_dbus_transport_bounds_bus_acquisition_before_authentication(
    descriptors: ProbeTransientDescriptors,
) -> None:
    recovery_bus = _FakeBus(reply=_no_such_unit())
    factory = _BlockingThenRecoveryFactory(recovery_bus)
    manager = SystemdProbeManager(transport=DbusNextSystemdTransport(bus_factory=factory))

    with pytest.raises(ProbeSystemdError, match=r"^probe_transient_start_failed$"):
        manager.start(_request(), descriptors=descriptors, timeout_seconds=0.01)

    assert factory.calls == 2
    assert recovery_bus.disconnected
    assert recovery_bus.disconnect_waited


def test_dbus_transport_stops_and_reads_back_the_exact_unit_during_recovery() -> None:
    bus = _SequencedReplyBus(_method_return(), _no_such_unit())
    transport = DbusNextSystemdTransport(
        bus_factory=lambda deadline: _factory(bus, deadline)
    )

    transport.recover(
        "rtsp-probe-447a1c4e4c794c508e5142c4dfa5fb19.service",
        timeout_seconds=1.0,
    )

    assert [message.member for message in bus.messages] == ["StopUnit", "GetUnit"]
    assert bus.messages[0].body == [
        "rtsp-probe-447a1c4e4c794c508e5142c4dfa5fb19.service",
        "replace",
    ]
    assert bus.messages[1].body == [
        "rtsp-probe-447a1c4e4c794c508e5142c4dfa5fb19.service"
    ]
    assert bus.disconnected
    assert bus.disconnect_waited


def test_dbus_transport_waits_until_the_recovered_unit_is_absent() -> None:
    bus = _SequencedReplyBus(_method_return(), _method_return(), _no_such_unit())
    transport = DbusNextSystemdTransport(
        bus_factory=lambda deadline: _factory(bus, deadline)
    )

    transport.recover(
        "rtsp-probe-447a1c4e4c794c508e5142c4dfa5fb19.service",
        timeout_seconds=1.0,
    )

    assert [message.member for message in bus.messages] == [
        "StopUnit",
        "GetUnit",
        "GetUnit",
    ]
    assert bus.disconnected
    assert bus.disconnect_waited


def test_dbus_transport_rejects_an_invalid_start_reply_and_recovers(
    descriptors: ProbeTransientDescriptors,
) -> None:
    invalid_reply = Message(
        message_type=MessageType.METHOD_RETURN,
        reply_serial=1,
        signature="s",
        body=["not-an-object-path"],
    )
    start_bus = _FakeBus(reply=invalid_reply)
    recovery_bus = _FakeBus(reply=_no_such_unit())
    manager = SystemdProbeManager(
        transport=DbusNextSystemdTransport(
            bus_factory=_BusSequence(start_bus, recovery_bus)
        )
    )

    with pytest.raises(ProbeSystemdError, match=r"^probe_transient_start_failed$"):
        manager.start(_request(), descriptors=descriptors, timeout_seconds=1.0)

    assert start_bus.disconnected
    assert start_bus.disconnect_waited
    assert [message.member for message in recovery_bus.messages] == ["StopUnit"]


def test_dbus_transport_rejects_recovery_outside_the_probe_namespace() -> None:
    bus = _FakeBus(reply=_no_such_unit())
    transport = DbusNextSystemdTransport(
        bus_factory=lambda deadline: _factory(bus, deadline)
    )

    with pytest.raises(RuntimeError, match="probe systemd unit name invalid"):
        transport.recover("postgresql.service", timeout_seconds=1.0)

    assert not bus.connected
    assert bus.messages == []


def test_dbus_transport_classifies_unit_exists_as_a_definitive_rejection(
    descriptors: ProbeTransientDescriptors,
) -> None:
    bus = _FakeBus(reply=_unit_exists())
    manager = SystemdProbeManager(
        transport=DbusNextSystemdTransport(
            bus_factory=lambda deadline: _factory(bus, deadline)
        )
    )

    with pytest.raises(ProbeSystemdStartRejected, match="probe_transient_start_rejected"):
        manager.start(_request(), descriptors=descriptors, timeout_seconds=1.0)

    assert len(bus.messages) == 1
    assert bus.messages[0].member == "StartTransientUnit"
    assert bus.disconnected
    assert bus.disconnect_waited


def test_unit_exists_remains_definitive_when_disconnect_also_fails(
    descriptors: ProbeTransientDescriptors,
) -> None:
    bus = _DisconnectFailureBus(reply=_unit_exists())
    manager = SystemdProbeManager(
        transport=DbusNextSystemdTransport(
            bus_factory=lambda deadline: _factory(bus, deadline)
        )
    )

    with pytest.raises(ProbeSystemdStartRejected, match="probe_transient_start_rejected"):
        manager.start(_request(), descriptors=descriptors, timeout_seconds=1.0)

    assert len(bus.messages) == 1
    assert bus.messages[0].member == "StartTransientUnit"
    assert bus.disconnected
    assert bus.disconnect_waited


def test_unit_exists_never_cleans_another_owner_when_disconnect_is_interrupted(
    descriptors: ProbeTransientDescriptors,
) -> None:
    bus = _DisconnectInterruptionBus(reply=_unit_exists())
    manager = SystemdProbeManager(
        transport=DbusNextSystemdTransport(
            bus_factory=lambda deadline: _factory(bus, deadline)
        )
    )

    with pytest.raises(KeyboardInterrupt):
        manager.start(_request(), descriptors=descriptors, timeout_seconds=1.0)

    assert len(bus.messages) == 1
    assert bus.messages[0].member == "StartTransientUnit"
    assert bus.disconnected
    assert bus.disconnect_waited
