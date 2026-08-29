#!/usr/bin/python3
"""PROTOTYPE ONLY: listener fixture and gated connect canary."""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import threading
import time
from pathlib import Path


def _listener(family: socket.AddressFamily, host: str, port: int) -> socket.socket:
    listener = socket.socket(family, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family is socket.AF_INET6:
        listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    listener.bind((host, port))
    listener.listen(16)
    return listener


def serve(allowed_port: int, denied_port: int, ready: Path) -> int:
    listeners = tuple(
        _listener(family, host, port)
        for family, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1"))
        for port in (allowed_port, denied_port)
    )
    stopping = threading.Event()

    def accept(listener: socket.socket) -> None:
        listener.settimeout(0.2)
        while not stopping.is_set():
            try:
                connection, _address = listener.accept()
            except TimeoutError:
                continue
            with connection:
                connection.sendall(b"ok")

    threads = tuple(
        threading.Thread(target=accept, args=(listener,), daemon=True)
        for listener in listeners
    )
    for thread in threads:
        thread.start()
    ready.touch(mode=0o600, exist_ok=False)

    def stop(_signum: int, _frame: object) -> None:
        stopping.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while not stopping.wait(0.2):
        pass
    for listener in listeners:
        listener.close()
    return 0


def _wait_for(path: Path, timeout_seconds: float = 10.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    while not path.exists():
        if time.monotonic() >= deadline:
            raise RuntimeError("prototype_gate_timeout")
        time.sleep(0.02)


def _connect(family: socket.AddressFamily, host: str, port: int) -> bool:
    with socket.socket(family, socket.SOCK_STREAM) as connection:
        connection.settimeout(1.0)
        return connection.connect_ex((host, port)) == 0


def check(
    allowed_port: int,
    denied_port: int,
    gate: Path,
    exit_gate: Path,
    output: Path,
) -> int:
    _wait_for(gate)
    result = {
        "allowed_ipv4": _connect(socket.AF_INET, "127.0.0.1", allowed_port),
        "denied_ipv4": _connect(socket.AF_INET, "127.0.0.1", denied_port),
        "allowed_ipv6": _connect(socket.AF_INET6, "::1", allowed_port),
        "denied_ipv6": _connect(socket.AF_INET6, "::1", denied_port),
    }
    descriptor = os.open(
        output,
        os.O_CLOEXEC | os.O_CREAT | os.O_EXCL | os.O_WRONLY,
        0o600,
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(result, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    _wait_for(exit_gate)
    return 0


def validate(output: Path, guarded: bool) -> int:
    with output.open(encoding="utf-8") as stream:
        observed = json.load(stream)
    expected = {
        "allowed_ipv4": True,
        "denied_ipv4": not guarded,
        "allowed_ipv6": True,
        "denied_ipv6": not guarded,
    }
    print(json.dumps({"expected": expected, "observed": observed}, sort_keys=True))
    return 0 if observed == expected else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve_parser = subparsers.add_parser("serve")
    serve_parser.add_argument("--allowed-port", type=int, required=True)
    serve_parser.add_argument("--denied-port", type=int, required=True)
    serve_parser.add_argument("--ready", type=Path, required=True)

    check_parser = subparsers.add_parser("check")
    check_parser.add_argument("--allowed-port", type=int, required=True)
    check_parser.add_argument("--denied-port", type=int, required=True)
    check_parser.add_argument("--gate", type=Path, required=True)
    check_parser.add_argument("--exit-gate", type=Path, required=True)
    check_parser.add_argument("--output", type=Path, required=True)

    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("--output", type=Path, required=True)
    validate_parser.add_argument("--guarded", action="store_true")

    arguments = parser.parse_args()
    if arguments.command == "serve":
        return serve(arguments.allowed_port, arguments.denied_port, arguments.ready)
    if arguments.command == "check":
        return check(
            arguments.allowed_port,
            arguments.denied_port,
            arguments.gate,
            arguments.exit_gate,
            arguments.output,
        )
    return validate(arguments.output, arguments.guarded)


if __name__ == "__main__":
    raise SystemExit(main())
