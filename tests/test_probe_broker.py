from __future__ import annotations

import array
import os
import socket
import struct
import sys
import threading
import time
from collections.abc import Callable
from ipaddress import ip_address
from uuid import UUID

import pytest

import rtsp_proxy.probe_broker as broker_module
from rtsp_proxy.probe_broker import (
    ProbeBrokerError,
    ProbeBrokerRequest,
    receive_probe_broker_request,
    send_probe_broker_request,
)
from rtsp_proxy.probe_executor import ProbeConnectGuardTarget, create_sealed_probe_input

_REQUEST_ID = UUID("447a1c4e-4c79-4c50-8e51-42c4dfa5fb19")
_GENERATION = UUID("d7cbf9ca-5328-4ed2-a5eb-b9e1b0ca9914")
_NOW_MS = 1_800_000_000_000
_FFCONCAT = (
    b"ffconcat version 1.0\n"
    b"file 'rtsp://camera:secret@192.0.2.10:8554/live'\n"
    b"option rtsp_transport tcp\n"
    b"option rw_timeout 5000000\n"
)


def _request(*, address: str = "192.0.2.10", port: int = 8554) -> ProbeBrokerRequest:
    return ProbeBrokerRequest(
        request_id=_REQUEST_ID,
        endpoint_generation=_GENERATION,
        target=ProbeConnectGuardTarget(address=ip_address(address), port=port),
        deadline_unix_ms=_NOW_MS + 10_000,
    )


def _fixed_wall_clock(value: int) -> Callable[[], int]:
    def read() -> int:
        return value

    return read


def test_broker_request_codec_is_deterministic_bounded_and_secret_free() -> None:
    request = _request()

    encoded = request.encode()

    assert len(encoded) < 1_024
    assert encoded == (
        b'{"address":"192.0.2.10","deadline_unix_ms":1800000010000,'
        b'"endpoint_generation":"d7cbf9ca-5328-4ed2-a5eb-b9e1b0ca9914",'
        b'"port":8554,"request_id":"447a1c4e-4c79-4c50-8e51-42c4dfa5fb19",'
        b'"schema_version":1}'
    )
    assert b"camera" not in encoded
    assert b"secret" not in encoded
    assert ProbeBrokerRequest.decode(encoded) == request


@pytest.mark.parametrize(
    "payload",
    [
        b"{}",
        _request().encode().replace(b'"schema_version":1', b'"schema_version":true'),
        _request().encode().replace(b'"port":8554', b'"port":false'),
        _request().encode().replace(b"192.0.2.10", b"camera.internal"),
        _request().encode().replace(b"192.0.2.10", b"192.0.2.010"),
        _request().encode().replace(b'"port":8554,', b'"port":8554,"extra":1,'),
        b"x" * 1_025,
    ],
)
def test_broker_request_decoder_rejects_noncanonical_or_unbounded_input(
    payload: bytes,
) -> None:
    with pytest.raises(ProbeBrokerError, match="probe_broker_request_invalid"):
        ProbeBrokerRequest.decode(payload)


def test_broker_sender_rejects_a_boolean_descriptor_without_closing_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

    def unexpected_close(_descriptor: int) -> None:
        raise AssertionError("invalid descriptor must not transfer ownership")

    monkeypatch.setattr(os, "close", unexpected_close)
    try:
        with pytest.raises(ProbeBrokerError, match="probe_broker_descriptor_invalid"):
            send_probe_broker_request(sender, _request(), True, timeout_seconds=1)
    finally:
        sender.close()
        receiver.close()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux SCM_RIGHTS contract")
def test_broker_transport_authenticates_peer_and_receives_one_bound_sealed_fd() -> None:
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    descriptor = create_sealed_probe_input(_FFCONCAT)
    try:
        send_probe_broker_request(sender, _request(), descriptor, timeout_seconds=1)
        with pytest.raises(OSError):
            os.fstat(descriptor)

        received = receive_probe_broker_request(
            receiver,
            expected_uid=os.getuid(),
            expected_gid=os.getgid(),
            request_timeout_seconds=1,
            wall_clock_ms=lambda: _NOW_MS,
        )
        with received:
            assert received.request == _request()
            received_descriptor = received.descriptor
            assert os.get_inheritable(received_descriptor) is False
            assert os.lseek(received_descriptor, 0, os.SEEK_CUR) == 0
            assert os.read(received_descriptor, len(_FFCONCAT)) == _FFCONCAT
            assert "secret" not in repr(received)
        with pytest.raises(ProbeBrokerError, match="probe_broker_descriptor_closed"):
            _ = received.descriptor
        with pytest.raises(OSError):
            os.fstat(received_descriptor)
    finally:
        sender.close()
        receiver.close()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux SCM_RIGHTS contract")
def test_broker_transport_rejects_wrong_peer_or_expired_request_before_acceptance() -> None:
    for expected_uid, now_unix_ms, reason in (
        (os.getuid() + 1, _NOW_MS, "probe_broker_peer_denied"),
        (os.getuid(), _NOW_MS + 10_000, "probe_broker_request_expired"),
    ):
        sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        descriptor = create_sealed_probe_input(_FFCONCAT)
        try:
            send_probe_broker_request(sender, _request(), descriptor, timeout_seconds=1)
            with pytest.raises(ProbeBrokerError, match=reason):
                receive_probe_broker_request(
                    receiver,
                    expected_uid=expected_uid,
                    expected_gid=os.getgid(),
                    request_timeout_seconds=1,
                    wall_clock_ms=_fixed_wall_clock(now_unix_ms),
                )
        finally:
            sender.close()
            receiver.close()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux SCM_RIGHTS contract")
def test_broker_sender_consumes_secret_fd_when_target_binding_fails() -> None:
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    descriptor = create_sealed_probe_input(_FFCONCAT)
    try:
        with pytest.raises(ProbeBrokerError, match="probe_broker_target_mismatch"):
            send_probe_broker_request(
                sender,
                _request(address="192.0.2.11"),
                descriptor,
                timeout_seconds=1,
            )
        with pytest.raises(OSError):
            os.fstat(descriptor)
    finally:
        sender.close()
        receiver.close()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux SCM_RIGHTS contract")
def test_broker_transport_closes_received_fd_when_tuple_or_fd_count_is_invalid() -> None:
    baseline = len(os.listdir("/proc/self/fd"))
    for mismatched_request, descriptor_count, reason in (
        (_request(address="192.0.2.11"), 1, "probe_broker_target_mismatch"),
        (_request(), 0, "probe_broker_descriptor_count_invalid"),
        (_request(), 2, "probe_broker_descriptor_count_invalid"),
        (_request(), 3, "probe_broker_ancillary_invalid"),
    ):
        sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        descriptors = [create_sealed_probe_input(_FFCONCAT) for _ in range(descriptor_count)]
        try:
            payload = mismatched_request.encode()
            frame = struct.pack("!I", len(payload)) + payload
            ancillary = []
            if descriptors:
                ancillary = [
                    (
                        socket.SOL_SOCKET,
                        socket.SCM_RIGHTS,
                        array.array("i", descriptors),
                    )
                ]
            sender.sendmsg([frame], ancillary)
            with pytest.raises(ProbeBrokerError, match=reason):
                receive_probe_broker_request(
                    receiver,
                    expected_uid=os.getuid(),
                    expected_gid=os.getgid(),
                    request_timeout_seconds=1,
                    wall_clock_ms=lambda: _NOW_MS,
                )
        finally:
            for descriptor in descriptors:
                os.close(descriptor)
            sender.close()
            receiver.close()
        assert len(os.listdir("/proc/self/fd")) == baseline


@pytest.mark.skipif(sys.platform != "linux", reason="Linux SCM_RIGHTS contract")
def test_broker_transport_times_out_a_stalled_frame() -> None:
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sender.sendall(b"\x00")
        with pytest.raises(ProbeBrokerError, match="probe_broker_unavailable"):
            receive_probe_broker_request(
                receiver,
                expected_uid=os.getuid(),
                expected_gid=os.getgid(),
                request_timeout_seconds=0.01,
                wall_clock_ms=lambda: _NOW_MS,
            )
    finally:
        sender.close()
        receiver.close()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux SCM_RIGHTS contract")
def test_broker_transport_uses_one_absolute_deadline_against_a_slow_drip() -> None:
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    stopping = threading.Event()
    frame = struct.pack("!I", len(_request().encode())) + _request().encode()

    def drip() -> None:
        try:
            for byte in frame:
                if stopping.is_set():
                    return
                sender.sendall(bytes([byte]))
                if stopping.wait(0.006):
                    return
        except OSError:
            return

    thread = threading.Thread(target=drip, daemon=True)
    thread.start()
    started = time.monotonic()
    try:
        with pytest.raises(ProbeBrokerError, match="probe_broker_unavailable"):
            receive_probe_broker_request(
                receiver,
                expected_uid=os.getuid(),
                expected_gid=os.getgid(),
                request_timeout_seconds=0.02,
                wall_clock_ms=lambda: _NOW_MS,
            )
        assert time.monotonic() - started < 0.1
    finally:
        stopping.set()
        thread.join(timeout=1)
        sender.close()
        receiver.close()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux SCM_RIGHTS contract")
def test_broker_sender_uses_one_absolute_deadline_across_partial_send() -> None:
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    descriptor = create_sealed_probe_input(_FFCONCAT)

    class PartialSendSocket(socket.socket):
        sendall_called = False

        def sendmsg(  # type: ignore[override]
            self,
            _buffers: object,
            _ancillary: object,
        ) -> int:
            return 1

        def sendall(
            self,
            _data: object,
            _flags: int = 0,
        ) -> None:
            self.sendall_called = True

    sender = PartialSendSocket(fileno=left.detach())
    observed_times = iter([10.0, 10.1, 11.1])
    try:
        with pytest.raises(ProbeBrokerError, match="probe_broker_unavailable"):
            send_probe_broker_request(
                sender,
                _request(),
                descriptor,
                timeout_seconds=1,
                monotonic=lambda: next(observed_times),
            )
        assert sender.sendall_called is False
        with pytest.raises(OSError):
            os.fstat(descriptor)
    finally:
        sender.close()
        right.close()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux SCM_RIGHTS contract")
def test_broker_transport_rechecks_request_expiry_after_frame_read() -> None:
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    descriptor = create_sealed_probe_input(_FFCONCAT)
    observed_times = iter([_NOW_MS, _NOW_MS + 10_000])
    try:
        payload = _request().encode()
        frame = struct.pack("!I", len(payload)) + payload
        sender.sendmsg(
            [frame],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [descriptor]))],
        )
        with pytest.raises(ProbeBrokerError, match="probe_broker_request_expired"):
            receive_probe_broker_request(
                receiver,
                expected_uid=os.getuid(),
                expected_gid=os.getgid(),
                request_timeout_seconds=1,
                wall_clock_ms=lambda: next(observed_times),
            )
    finally:
        os.close(descriptor)
        sender.close()
        receiver.close()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux SCM_RIGHTS contract")
def test_broker_transport_closes_installed_fd_on_process_interruption(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline = len(os.listdir("/proc/self/fd"))
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    descriptor = create_sealed_probe_input(_FFCONCAT)
    try:
        payload = _request().encode()
        frame = struct.pack("!I", len(payload)) + payload
        sender.sendmsg(
            [frame],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [descriptor]))],
        )

        def interrupt(_descriptor: int, _inheritable: bool) -> None:
            raise KeyboardInterrupt()

        monkeypatch.setattr(os, "set_inheritable", interrupt)
        with pytest.raises(KeyboardInterrupt):
            receive_probe_broker_request(
                receiver,
                expected_uid=os.getuid(),
                expected_gid=os.getgid(),
                request_timeout_seconds=1,
                wall_clock_ms=lambda: _NOW_MS,
            )
    finally:
        os.close(descriptor)
        sender.close()
        receiver.close()
    assert len(os.listdir("/proc/self/fd")) == baseline


@pytest.mark.skipif(sys.platform != "linux", reason="Linux SCM_RIGHTS contract")
def test_broker_transport_keeps_fd_owned_when_result_handoff_is_interrupted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline = len(os.listdir("/proc/self/fd"))
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    descriptor = create_sealed_probe_input(_FFCONCAT)
    try:
        payload = _request().encode()
        frame = struct.pack("!I", len(payload)) + payload
        sender.sendmsg(
            [frame],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [descriptor]))],
        )

        def interrupt_handoff(*_args: object, **_kwargs: object) -> None:
            raise KeyboardInterrupt()

        monkeypatch.setattr(broker_module, "ReceivedProbeInput", interrupt_handoff)
        with pytest.raises(KeyboardInterrupt):
            receive_probe_broker_request(
                receiver,
                expected_uid=os.getuid(),
                expected_gid=os.getgid(),
                request_timeout_seconds=1,
                wall_clock_ms=lambda: _NOW_MS,
            )
    finally:
        os.close(descriptor)
        sender.close()
        receiver.close()
    assert len(os.listdir("/proc/self/fd")) == baseline
