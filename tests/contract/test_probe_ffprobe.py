from __future__ import annotations

import os
import socket
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path

import pytest

PROBE_FFPROBE_BINARY = os.environ.get("PROBE_FFPROBE_BINARY")
pytestmark = pytest.mark.skipif(
    PROBE_FFPROBE_BINARY is None,
    reason="controlled probe ffprobe binary is required",
)


@dataclass(frozen=True)
class _ProbeResult:
    returncode: int
    stderr: bytes
    redirect_target_connected: bool


def _run_redirect_probe(*, refuse_redirect: bool) -> _ProbeResult:
    assert PROBE_FFPROBE_BINARY is not None
    source = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    source.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    target.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    source.bind(("127.0.0.1", 0))
    target.bind(("127.0.0.1", 0))
    source.listen(1)
    target.listen(1)
    target.settimeout(3.0)
    source_port = source.getsockname()[1]
    target_port = target.getsockname()[1]

    def redirect_once() -> None:
        connection, _address = source.accept()
        with connection:
            request = b""
            while b"\r\n\r\n" not in request:
                part = connection.recv(4_096)
                if not part:
                    break
                request += part
            cseq = next(
                (
                    line.split(b":", 1)[1].strip()
                    for line in request.split(b"\r\n")
                    if line.lower().startswith(b"cseq:")
                ),
                b"1",
            )
            connection.sendall(
                b"RTSP/1.0 302 Found\r\n"
                b"CSeq: "
                + cseq
                + b"\r\nLocation: rtsp://127.0.0.1:"
                + str(target_port).encode("ascii")
                + b"/redirected\r\nContent-Length: 0\r\n\r\n"
            )

    server = threading.Thread(target=redirect_once, daemon=True)
    server.start()
    option = "option rtsp_flags no_redirect\n" if refuse_redirect else ""
    payload = (
        "ffconcat version 1.0\n"
        f"file 'rtsp://127.0.0.1:{source_port}/source'\n"
        "option rtsp_transport tcp\n"
        f"{option}"
        "option rw_timeout 1000000\n"
    ).encode("ascii")
    completed: list[subprocess.CompletedProcess[bytes]] = []

    def run_probe() -> None:
        completed.append(
            subprocess.run(
                [
                    str(Path(PROBE_FFPROBE_BINARY).resolve(strict=True)),
                    "-v",
                    "quiet",
                    "-f",
                    "concat",
                    "-safe",
                    "0",
                    "-protocol_whitelist",
                    "file,pipe,rtsp,rtp,tcp",
                    "-i",
                    "pipe:0",
                    "-show_entries",
                    "stream=index",
                    "-of",
                    "json",
                ],
                input=payload,
                check=False,
                capture_output=True,
                timeout=6.0,
            )
        )

    worker = threading.Thread(target=run_probe)
    worker.start()
    try:
        redirected, _address = target.accept()
    except TimeoutError:
        redirect_target_connected = False
    else:
        redirect_target_connected = True
        redirected.close()
    finally:
        worker.join(7.0)
        server.join(1.0)
        source.close()
        target.close()

    assert not worker.is_alive()
    assert not server.is_alive()
    assert len(completed) == 1
    return _ProbeResult(
        returncode=completed[0].returncode,
        stderr=completed[0].stderr,
        redirect_target_connected=redirect_target_connected,
    )


def test_controlled_probe_ffprobe_refuses_redirect_without_logging() -> None:
    result = _run_redirect_probe(refuse_redirect=True)

    assert result.returncode != 0
    assert result.stderr == b""
    assert result.redirect_target_connected is False


def test_controlled_probe_ffprobe_keeps_default_redirect_behavior_opt_in() -> None:
    result = _run_redirect_probe(refuse_redirect=False)

    assert result.returncode != 0
    assert result.stderr == b""
    assert result.redirect_target_connected is True
