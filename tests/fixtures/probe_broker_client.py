#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address, ip_network
from uuid import UUID

from rtsp_proxy.probe_client import UnixProbeBrokerClient
from rtsp_proxy.probe_security import ProbeEndpointAdmission


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
        prefix_length = 32 if address.version == 4 else 128
        authority = str(address) if address.version == 4 else f"[{address}]"
        endpoint = ProbeEndpointAdmission(
            site_key="contract",
            allowed_networks=(
                ip_network(f"{address}/{prefix_length}"),
            ),
            resolve=lambda _hostname: (),
            new_generation=lambda: endpoint_generation,
        ).admit(
            f"rtsp://contract:probe-broker-secret-canary@{authority}:{port}/live"
        )
        result = UnixProbeBrokerClient().execute(
            request_id=request_id,
            endpoint=endpoint,
            deadline_at=datetime.now(UTC) + timedelta(milliseconds=deadline_after_ms),
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
