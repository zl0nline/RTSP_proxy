#!/usr/bin/python3
from __future__ import annotations

import json
import os
import socket
import time
from ipaddress import ip_address
from urllib.parse import urlsplit


def _write_all(descriptor: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise RuntimeError("fixture write made no progress")
        remaining = remaining[written:]


def main() -> int:
    if any(name in os.environ for name in ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES")):
        return 20
    if os.read(0, 1) != b"R":
        return 21
    payload = os.read(2, 16_385)
    if not payload or len(payload) > 16_384:
        return 22
    if b"/probe-systemd-overflow" in payload:
        _write_all(1, b"x" * 65_537)
        return 0
    if b"/probe-systemd-cancel" in payload:
        time.sleep(60)
        return 0
    if b"/probe-connect-guard-systemd" in payload:
        try:
            file_line = next(
                line for line in payload.decode("utf-8").splitlines()
                if line.startswith("file '") and line.endswith("'")
            )
            target = urlsplit(file_line[6:-1])
            if target.hostname is None or target.port is None:
                return 23
            address = ip_address(target.hostname)
            family = socket.AF_INET if address.version == 4 else socket.AF_INET6
            alternate_family = (
                socket.AF_INET6 if family == socket.AF_INET else socket.AF_INET
            )
            alternate_host = "::1" if alternate_family == socket.AF_INET6 else "127.0.0.1"
            results: dict[str, bool] = {}
            for label, connect_family, host, port in (
                ("allowed", family, target.hostname, target.port),
                ("wrong_port", family, target.hostname, target.port + 1),
                (
                    "wrong_family",
                    alternate_family,
                    alternate_host,
                    target.port,
                ),
            ):
                with socket.socket(connect_family, socket.SOCK_STREAM) as connection:
                    connection.settimeout(1.0)
                    results[label] = connection.connect_ex((host, port)) == 0
        except (OSError, StopIteration, UnicodeError, ValueError):
            return 24
        _write_all(
            1,
            json.dumps(results, sort_keys=True, separators=(",", ":")).encode()
            + b"\n",
        )
        return 0
    _write_all(1, b'{"status":"fixture-ok"}\n')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
