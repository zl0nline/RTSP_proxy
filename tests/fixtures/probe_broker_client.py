#!/usr/bin/env python3
from __future__ import annotations

import array
import fcntl
import json
import os
import socket
import struct
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from threading import Event, Thread
from uuid import UUID

from rtsp_proxy.probe_broker import ProbeBrokerRequest, require_probe_broker_peer
from rtsp_proxy.probe_client import UnixProbeBrokerClient
from rtsp_proxy.probe_executor import PROBE_INPUT_REQUIRED_SEALS, ProbeConnectGuardTarget
from rtsp_proxy.probe_security import AdmittedProbeEndpoint, ProbeEndpointAdmission

HOSTILE_INPUT_CASES = (
    "http", "https", "file", "pipe", "tcp", "udp", "rtsps", "concat",
    "transport_udp", "transport_http", "redirect_enabled", "hostname",
    "tuple_address", "tuple_port", "extra_file",
)


def _contract_endpoint(
    *, endpoint_generation: UUID, address: IPv4Address | IPv6Address, port: int
) -> AdmittedProbeEndpoint:
    admitted = ProbeEndpointAdmission(
        site_key="contract",
        allowed_networks=(ip_network("10.0.0.8/32"),),
        resolve=lambda _hostname: ("10.0.0.8",),
        new_generation=lambda: endpoint_generation,
    ).admit(
        f"rtsp://contract:probe-broker-secret-canary@camera.invalid:{port}/live"
    )
    # The installed broker contract intentionally uses local listeners. Camera
    # admission rejects loopback; this test-only replacement represents an
    # identity that has already crossed that separate policy boundary.
    return replace(
        admitted,
        identity=replace(admitted.identity, address=address),
    )


def _hostile_payload(endpoint: AdmittedProbeEndpoint, input_case: str) -> bytes:
    if endpoint.literal_host != "127.0.0.1" or endpoint.port != 8554:
        raise ValueError("hostile_fixture_target_invalid")
    payload = endpoint.ffconcat_payload()
    substitutions = {
        "http": (b"rtsp://", b"http://"),
        "https": (b"rtsp://", b"https://"),
        "file": (b"rtsp://", b"file://"),
        "pipe": (b"rtsp://", b"pipe://"),
        "tcp": (b"rtsp://", b"tcp://"),
        "udp": (b"rtsp://", b"udp://"),
        "rtsps": (b"rtsp://", b"rtsps://"),
        "concat": (b"rtsp://", b"concat:rtsp://"),
        "transport_udp": (b"rtsp_transport tcp", b"rtsp_transport udp"),
        "transport_http": (b"rtsp_transport tcp", b"rtsp_transport http"),
        "redirect_enabled": (b"rtsp_flags no_redirect", b"rtsp_flags prefer_tcp"),
        "hostname": (b"@127.0.0.1:", b"@camera.invalid:"),
        "tuple_address": (b"@127.0.0.1:", b"@127.0.0.2:"),
        "tuple_port": (b":8554/live", b":8555/live"),
    }
    if input_case == "extra_file":
        return payload + b"file 'file:///probe-broker-secret-canary'\n"
    old, new = substitutions[input_case]
    if payload.count(old) != 1:
        raise ValueError("hostile_fixture_payload_invalid")
    return payload.replace(old, new, 1)


def _send_hostile_input(
    request: ProbeBrokerRequest, payload: bytes, *,
    socket_path: str = "/run/rtsp-proxy-probe-broker/control.sock",
    expected_uid: int = 0, expected_gid: int = 0,
) -> None:
    # Test-only raw sender: bypass caller validation to exercise the installed
    # broker's trust boundary. Never add this path to the production client.
    descriptor = os.memfd_create("hostile-probe-input", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        if os.write(descriptor, payload) != len(payload):
            raise RuntimeError("hostile_fixture_write_failed")
        # F_ADD_SEALS is Linux ABI 1033; some supported Python builds do not
        # export its symbolic constant (the production sealer uses the same ABI).
        fcntl.fcntl(descriptor, 1033, PROBE_INPUT_REQUIRED_SEALS)
        os.lseek(descriptor, 0, os.SEEK_SET)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(3)
            connection.connect(socket_path)
            require_probe_broker_peer(
                connection, expected_uid=expected_uid, expected_gid=expected_gid,
            )
            encoded = request.encode()
            frame = struct.pack("!I", len(encoded)) + encoded
            sent = connection.sendmsg(
                [frame], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [descriptor]))],
            )
            if sent <= 0:
                raise RuntimeError("hostile_fixture_send_failed")
            if sent < len(frame):
                connection.sendall(frame[sent:])
            if connection.recv(1) != b"":
                raise RuntimeError("hostile_fixture_request_accepted")
    finally:
        os.close(descriptor)


def main() -> int:
    try:
        if len(sys.argv) not in (6, 7):
            raise ValueError
        request_id = UUID(sys.argv[1])
        endpoint_generation = UUID(sys.argv[2])
        address = ip_address(sys.argv[3])
        port = int(sys.argv[4])
        deadline_after_ms = int(sys.argv[5])
        if not 10 <= deadline_after_ms <= 60_000:
            raise ValueError
        endpoint = _contract_endpoint(
            endpoint_generation=endpoint_generation,
            address=address,
            port=port,
        )
        if len(sys.argv) == 7:
            request = ProbeBrokerRequest(
                request_id=request_id, endpoint_generation=endpoint_generation,
                target=ProbeConnectGuardTarget(address=address, port=port),
                deadline_unix_ms=int(datetime.now(UTC).timestamp() * 1000) + deadline_after_ms,
            )
            _send_hostile_input(request, _hostile_payload(endpoint, sys.argv[6]))
            print('{"rejected":true}')
            return 0
        cancelled = Event()

        def read_cancellation() -> None:
            # A daemon must not hold Python's buffered-stdin lock at interpreter exit.
            if os.read(sys.stdin.fileno(), 16) == b"cancel\n":
                cancelled.set()

        Thread(target=read_cancellation, daemon=True).start()
        result = UnixProbeBrokerClient().execute(
            request_id=request_id,
            endpoint=endpoint,
            deadline_at=datetime.now(UTC) + timedelta(milliseconds=deadline_after_ms),
            cancelled=cancelled.is_set,
        )
        print(
            json.dumps(
                {
                    "audio_codec": result.audio_codec,
                    "failure_class": (
                        None if result.failure_class is None else result.failure_class.value
                    ),
                    "outcome": result.outcome.value,
                    "video_codec": result.video_codec,
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 0
    except Exception:
        print("probe_broker_client_failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
