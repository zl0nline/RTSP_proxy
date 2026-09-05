#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from threading import Event, Thread
from uuid import UUID

from rtsp_proxy.probe_client import UnixProbeBrokerClient
from rtsp_proxy.probe_security import AdmittedProbeEndpoint, ProbeEndpointAdmission


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


def main() -> int:
    try:
        if len(sys.argv) != 6:
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
        cancelled = Event()

        def read_cancellation() -> None:
            if sys.stdin.buffer.readline(16) == b"cancel\n":
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
