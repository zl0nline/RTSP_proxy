from __future__ import annotations

import json
import os
import socket
import struct
import subprocess
import threading
import time
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
    stdout: bytes
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
                + b"/redirected?token=redirect-secret-canary"
                + b"\r\nContent-Length: 0\r\n\r\n"
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
        stdout=completed[0].stdout,
        stderr=completed[0].stderr,
        redirect_target_connected=redirect_target_connected,
    )


def test_controlled_probe_ffprobe_refuses_redirect_without_logging() -> None:
    result = _run_redirect_probe(refuse_redirect=True)

    assert result.returncode != 0
    assert result.stderr == b""
    assert b"redirect-secret-canary" not in result.stdout + result.stderr
    assert result.redirect_target_connected is False


def test_controlled_probe_ffprobe_keeps_default_redirect_behavior_opt_in() -> None:
    result = _run_redirect_probe(refuse_redirect=False)

    assert result.returncode != 0
    assert result.stderr == b""
    assert result.redirect_target_connected is True


def test_controlled_probe_ffprobe_completes_ordinary_h264_rtsp_tcp() -> None:
    assert PROBE_FFPROBE_BINARY is not None
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(3.0)
    port = listener.getsockname()[1]
    requests: list[str] = []

    def serve_h264() -> None:
        connection, _address = listener.accept()
        connection.settimeout(5.0)
        pending = b""
        with connection:
            while True:
                while b"\r\n\r\n" not in pending:
                    part = connection.recv(4_096)
                    if not part:
                        return
                    pending += part
                request, pending = pending.split(b"\r\n\r\n", 1)
                lines = request.split(b"\r\n")
                request_line = lines[0]
                requests.append(request_line.decode("ascii"))
                method = request_line.split(b" ", 1)[0]
                cseq = next(
                    line.split(b":", 1)[1].strip()
                    for line in lines
                    if line.lower().startswith(b"cseq:")
                )
                body = b""
                if method == b"OPTIONS":
                    headers = b"Public: OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN\r\n"
                elif method == b"DESCRIBE":
                    body = (
                        "v=0\r\n"
                        "o=- 0 0 IN IP4 127.0.0.1\r\n"
                        "s=probe\r\n"
                        "t=0 0\r\n"
                        "a=control:*\r\n"
                        "m=video 0 RTP/AVP 96\r\n"
                        "c=IN IP4 127.0.0.1\r\n"
                        "a=rtpmap:96 H264/90000\r\n"
                        "a=fmtp:96 packetization-mode=1;"
                        "sprop-parameter-sets=Z0IAH5WoFAFuQA==,aM4xUg==\r\n"
                        "a=control:trackID=0\r\n"
                    ).encode("ascii")
                    headers = (
                        b"Content-Type: application/sdp\r\n"
                        b"Content-Base: rtsp://127.0.0.1:"
                        + str(port).encode("ascii")
                        + b"/live/\r\n"
                    )
                elif method == b"SETUP":
                    headers = (
                        b"Transport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n"
                        b"Session: test-session;timeout=60\r\n"
                    )
                elif method == b"PLAY":
                    headers = b"Session: test-session\r\nRange: npt=0.000-\r\n"
                else:
                    headers = b"Session: test-session\r\n"
                connection.sendall(
                    b"RTSP/1.0 200 OK\r\nCSeq: "
                    + cseq
                    + b"\r\nServer: rtsp-proxy-test\r\n"
                    + headers
                    + b"Content-Length: "
                    + str(len(body)).encode("ascii")
                    + b"\r\n\r\n"
                    + body
                )
                if method == b"PLAY":
                    for sequence in range(1, 4):
                        rtp = struct.pack(
                            "!BBHII",
                            0x80,
                            0x80 | 96,
                            sequence,
                            sequence * 3_600,
                            0x12345678,
                        ) + b"\x65\x88\x84\x00\x0a\xf2\x62\x80"
                        connection.sendall(b"$\x00" + struct.pack("!H", len(rtp)) + rtp)
                        time.sleep(0.04)
                    time.sleep(0.2)
                    return

    server = threading.Thread(target=serve_h264, daemon=True)
    server.start()
    payload = (
        "ffconcat version 1.0\n"
        f"file 'rtsp://127.0.0.1:{port}/live'\n"
        "option rtsp_transport tcp\n"
        "option rtsp_flags no_redirect\n"
        "option rw_timeout 2000000\n"
    ).encode("ascii")
    completed = subprocess.run(
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
            "stream=codec_name,codec_type",
            "-of",
            "json",
        ],
        input=payload,
        check=False,
        capture_output=True,
        timeout=6.0,
    )
    server.join(1.0)
    listener.close()

    assert not server.is_alive()
    assert completed.returncode == 0
    assert completed.stderr == b""
    assert requests == [
        f"OPTIONS rtsp://127.0.0.1:{port}/live RTSP/1.0",
        f"DESCRIBE rtsp://127.0.0.1:{port}/live RTSP/1.0",
        f"SETUP rtsp://127.0.0.1:{port}/live/trackID=0 RTSP/1.0",
        f"PLAY rtsp://127.0.0.1:{port}/live/ RTSP/1.0",
    ]
    output = json.loads(completed.stdout)
    assert output == {
        "programs": [],
        "stream_groups": [],
        "streams": [{"codec_name": "h264", "codec_type": "video"}],
    }
