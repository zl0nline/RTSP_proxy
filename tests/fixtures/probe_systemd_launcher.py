#!/usr/bin/python3
from __future__ import annotations

import os
import time


def _write_all(descriptor: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise RuntimeError("fixture write made no progress")
        remaining = remaining[written:]


def main() -> int:
    if (
        os.environ.get("LISTEN_PID") != str(os.getpid())
        or os.environ.get("LISTEN_FDS") != "1"
        or os.environ.get("LISTEN_FDNAMES") != "probe-input"
    ):
        return 20
    if os.read(0, 1) != b"R":
        return 21
    payload = os.read(3, 16_385)
    if not payload or len(payload) > 16_384:
        return 22
    if b"/probe-systemd-overflow" in payload:
        _write_all(1, b"x" * 65_537)
        return 0
    if b"/probe-systemd-cancel" in payload:
        time.sleep(60)
        return 0
    _write_all(1, b'{"status":"fixture-ok"}\n')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
