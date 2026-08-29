from __future__ import annotations

import fcntl
import os
import socket
import struct
import sys
from collections.abc import Callable
from ipaddress import ip_address
from typing import cast

import pytest

from rtsp_proxy.probe_executor import (
    PROBE_INPUT_REQUIRED_SEALS,
    ProbeConnectGuardTarget,
    create_sealed_probe_input,
    parse_probe_input_payload,
    validate_sealed_probe_input,
)

_FFCONCAT = (
    b"ffconcat version 1.0\n"
    b"file 'rtsp://camera:secret@192.0.2.10:8554/live'\n"
    b"option rtsp_transport tcp\n"
    b"option rw_timeout 5000000\n"
)
_F_GET_SEALS = 1034
_MFD_CLOEXEC = 0x0001
_MFD_ALLOW_SEALING = 0x0002


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


@pytest.mark.skipif(sys.platform != "linux", reason="Linux sealed-memfd contract")
def test_probe_input_is_cloexec_immutable_and_exactly_validated() -> None:
    descriptor = create_sealed_probe_input(_FFCONCAT)
    try:
        assert os.get_inheritable(descriptor) is False
        assert validate_sealed_probe_input(descriptor) == len(_FFCONCAT)
        assert os.lseek(descriptor, 0, os.SEEK_CUR) == 0
        assert os.read(descriptor, len(_FFCONCAT)) == _FFCONCAT
        assert os.read(descriptor, 1) == b""
        assert validate_sealed_probe_input(descriptor) == len(_FFCONCAT)
        assert os.lseek(descriptor, 0, os.SEEK_CUR) == 0
        seals = fcntl.fcntl(descriptor, _F_GET_SEALS)
        assert seals & PROBE_INPUT_REQUIRED_SEALS == PROBE_INPUT_REQUIRED_SEALS
        with pytest.raises(OSError):
            os.pwrite(descriptor, b"x", 0)
    finally:
        os.close(descriptor)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux sealed-memfd contract")
@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit])
def test_probe_input_closes_secret_descriptor_on_process_interruption(
    monkeypatch: pytest.MonkeyPatch,
    interruption: type[BaseException],
) -> None:
    descriptors: list[int] = []
    memfd_name = "memfd_create"
    native_memfd_create = cast(
        Callable[[str, int], int],
        getattr(os, memfd_name),
    )

    def create_and_capture(name: str, flags: int) -> int:
        descriptor = native_memfd_create(name, flags)
        descriptors.append(descriptor)
        return descriptor

    def interrupt(*_arguments: object) -> int:
        raise interruption()

    monkeypatch.setattr(os, memfd_name, create_and_capture)
    monkeypatch.setattr(fcntl, "fcntl", interrupt)

    with pytest.raises(interruption):
        create_sealed_probe_input(_FFCONCAT)

    assert len(descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(descriptors[0])


@pytest.mark.skipif(sys.platform != "linux", reason="Linux sealed-memfd contract")
def test_probe_input_preserves_primary_and_cleanup_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptors: list[int] = []
    memfd_name = "memfd_create"
    native_memfd_create = cast(
        Callable[[str, int], int],
        getattr(os, memfd_name),
    )
    native_close = os.close

    def create_and_capture(name: str, flags: int) -> int:
        descriptor = native_memfd_create(name, flags)
        descriptors.append(descriptor)
        return descriptor

    def interrupt(*_arguments: object) -> int:
        raise SystemExit()

    def fail_close(_descriptor: int) -> None:
        raise OSError("injected close failure")

    monkeypatch.setattr(os, memfd_name, create_and_capture)
    monkeypatch.setattr(fcntl, "fcntl", interrupt)
    monkeypatch.setattr(os, "close", fail_close)

    try:
        with pytest.raises(BaseExceptionGroup) as captured:
            create_sealed_probe_input(_FFCONCAT)
        assert len(captured.value.exceptions) == 2
        assert isinstance(captured.value.exceptions[0], SystemExit)
        assert isinstance(captured.value.exceptions[1], OSError)
        assert "secret" not in str(captured.value)
    finally:
        native_close(descriptors[0])


@pytest.mark.skipif(sys.platform != "linux", reason="Linux sealed-memfd contract")
def test_probe_input_rejects_an_unsealed_descriptor() -> None:
    descriptor = os.memfd_create(  # type: ignore[attr-defined]
        "rtsp-probe-test",
        _MFD_CLOEXEC | _MFD_ALLOW_SEALING,
    )
    try:
        os.write(descriptor, _FFCONCAT)
        with pytest.raises(ValueError, match="probe_input_seals_invalid"):
            validate_sealed_probe_input(descriptor)
    finally:
        os.close(descriptor)


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"rtsp://camera:secret@192.0.2.10/live\n",
        _FFCONCAT.replace(b"rtsp_transport tcp", b"rtsp_transport udp"),
        _FFCONCAT.replace(b"rw_timeout 5000000", b"rw_timeout 0"),
        _FFCONCAT.replace(b"rw_timeout 5000000", b"rw_timeout 05000000"),
        _FFCONCAT.replace(b"5000000", b"5" * 5_000),
        _FFCONCAT.replace(b"192.0.2.10", b"camera.internal"),
        _FFCONCAT.replace(b"192.0.2.10:8554", b""),
        _FFCONCAT.replace(b"/live", b"/live\\alternate"),
        _FFCONCAT.replace(b"/live", b"/live\tpart"),
        _FFCONCAT.replace(b"/live", b"/live#fragment"),
        _FFCONCAT.replace(b"/live", b"/\xff"),
        _FFCONCAT + b"option extra unsafe\n",
        _FFCONCAT.replace(b"\n", b"\r\n", 1),
        b"x" * 16_385,
    ],
)
def test_probe_input_rejects_noncanonical_or_oversized_payload(payload: bytes) -> None:
    with pytest.raises(ValueError, match="probe_input_payload_invalid"):
        create_sealed_probe_input(payload)


def test_probe_input_parser_returns_only_secret_free_guard_metadata() -> None:
    contract = parse_probe_input_payload(_FFCONCAT)

    assert contract.target == ProbeConnectGuardTarget(
        address=ip_address("192.0.2.10"),
        port=8554,
    )
    assert contract.io_timeout_microseconds == 5_000_000
    assert "secret" not in repr(contract)
