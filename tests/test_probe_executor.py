from __future__ import annotations

import socket
import struct
from ipaddress import ip_address

import pytest

from rtsp_proxy.probe_executor import ProbeConnectGuardTarget


def test_connect_guard_target_encodes_one_exact_ipv4_tuple() -> None:
    target = ProbeConnectGuardTarget(address=ip_address("192.0.2.10"), port=8554)

    encoded = target.map_value()

    assert len(encoded) == 32
    version, family, port_network_order, address, reserved = struct.unpack(
        "=III16sI", encoded
    )
    assert version == 1
    assert family == socket.AF_INET
    assert port_network_order == socket.htons(8554)
    assert address == bytes.fromhex("c000020a") + bytes(12)
    assert reserved == 0


def test_connect_guard_target_encodes_one_exact_ipv6_tuple() -> None:
    target = ProbeConnectGuardTarget(address=ip_address("2001:db8::10"), port=554)

    version, family, port_network_order, address, reserved = struct.unpack(
        "=III16sI", target.map_value()
    )

    assert version == 1
    assert family == socket.AF_INET6
    assert port_network_order == socket.htons(554)
    assert address == bytes.fromhex("20010db8000000000000000000000010")
    assert reserved == 0


@pytest.mark.parametrize("port", [0, 65_536, True])
def test_connect_guard_target_rejects_invalid_ports(port: object) -> None:
    with pytest.raises(ValueError, match="probe_connect_guard_target_invalid"):
        ProbeConnectGuardTarget(address=ip_address("192.0.2.10"), port=port)  # type: ignore[arg-type]


def test_connect_guard_target_rejects_ipv4_mapped_ipv6() -> None:
    with pytest.raises(ValueError, match="probe_connect_guard_target_invalid"):
        ProbeConnectGuardTarget(address=ip_address("::ffff:192.0.2.10"), port=554)
