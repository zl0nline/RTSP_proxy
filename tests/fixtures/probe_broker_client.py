#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import socket
import sys
import time
from ipaddress import ip_address
from uuid import UUID

from rtsp_proxy.probe_broker import (
    ProbeBrokerRequest,
    receive_probe_broker_response,
    send_probe_broker_request,
)
from rtsp_proxy.probe_executor import (
    ProbeConnectGuardTarget,
    create_sealed_probe_input,
    serialize_probe_input,
)

_BROKER_SOCKET = "/run/rtsp-proxy-probe-broker/control.sock"


def main() -> int:
    descriptor = -1
    connection: socket.socket | None = None
    try:
        if len(sys.argv) != 5:
            raise ValueError
        request_id = UUID(sys.argv[1])
        endpoint_generation = UUID(sys.argv[2])
        address = ip_address(sys.argv[3])
        port = int(sys.argv[4])
        target = ProbeConnectGuardTarget(address=address, port=port)
        payload = serialize_probe_input(
            address=address,
            port=port,
            path_and_query="/live",
            username="contract",
            password="probe-broker-secret-canary",
            io_timeout_microseconds=5_000_000,
        )
        descriptor = create_sealed_probe_input(payload)
        request = ProbeBrokerRequest(
            request_id=request_id,
            endpoint_generation=endpoint_generation,
            target=target,
            deadline_unix_ms=int(time.time() * 1_000) + 20_000,
        )
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(2)
        connection.connect(_BROKER_SOCKET)
        send_probe_broker_request(
            connection,
            request,
            descriptor,
            timeout_seconds=2,
        )
        descriptor = -1
        result = receive_probe_broker_response(
            connection,
            expected_request=request,
            timeout_seconds=20,
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
    finally:
        if connection is not None:
            connection.close()
        if descriptor >= 0:
            os.close(descriptor)


if __name__ == "__main__":
    raise SystemExit(main())
