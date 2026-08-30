from __future__ import annotations

import json
import os
import socket
import struct
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest

from rtsp_proxy.probe_launcher import PROBE_FFPROBE_ARGV, ProbeFfprobeResultDecoder
from rtsp_proxy.probes import ProbeExecutionResult, ProbeOutcome

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


@dataclass(frozen=True)
class _MediaProbeResult:
    completed: subprocess.CompletedProcess[bytes]
    requests: tuple[str, ...]
    port: int


def _fixed_probe_argv() -> list[str]:
    assert PROBE_FFPROBE_BINARY is not None
    argv = [str(Path(PROBE_FFPROBE_BINARY).resolve(strict=True)), *PROBE_FFPROBE_ARGV[1:]]
    argv[argv.index("pipe:2")] = "pipe:0"
    return argv


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
                _fixed_probe_argv(),
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


def _run_h264_media_probe(rtp_payloads: tuple[bytes, ...]) -> _MediaProbeResult:
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
                        "sprop-parameter-sets=Z0LQC4xpyAeEQjU=,aM48gA==\r\n"
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
                    for sequence, rtp_payload in enumerate(rtp_payloads, start=1):
                        rtp = struct.pack(
                            "!BBHII",
                            0x80,
                            (0x80 if sequence == len(rtp_payloads) else 0) | 96,
                            sequence,
                            3_600,
                            0x12345678,
                        ) + rtp_payload
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
        _fixed_probe_argv(),
        input=payload,
        check=False,
        capture_output=True,
        timeout=6.0,
    )
    server.join(1.0)
    listener.close()

    assert not server.is_alive()
    return _MediaProbeResult(
        completed=completed,
        requests=tuple(requests),
        port=port,
    )


def _expected_h264_requests(port: int) -> tuple[str, ...]:
    return (
        f"OPTIONS rtsp://127.0.0.1:{port}/live RTSP/1.0",
        f"DESCRIBE rtsp://127.0.0.1:{port}/live RTSP/1.0",
        f"SETUP rtsp://127.0.0.1:{port}/live/trackID=0 RTSP/1.0",
        f"PLAY rtsp://127.0.0.1:{port}/live/ RTSP/1.0",
    )


def test_controlled_probe_ffprobe_requires_a_decodable_h264_frame() -> None:
    result = _run_h264_media_probe(
        (
            bytes.fromhex("6742d00b8c69c807844235"),
            bytes.fromhex("68ce3c80"),
            bytes.fromhex("65b8000409fffff87a28000827fc"),
        ),
    )

    assert result.completed.returncode == 0
    assert result.completed.stderr == b""
    assert result.requests == _expected_h264_requests(result.port)
    output = json.loads(result.completed.stdout)
    assert output["programs"] == []
    assert output["stream_groups"] == []
    assert output["streams"] == [{"codec_name": "h264", "codec_type": "video"}]
    assert output["frames"]
    assert all(frame == {"media_type": "video"} for frame in output["frames"])
    completed_at = datetime(2026, 8, 30, 18, 0, tzinfo=UTC)
    assert ProbeFfprobeResultDecoder(clock=lambda: completed_at).decode(
        result.completed.stdout
    ) == ProbeExecutionResult(
        outcome=ProbeOutcome.HEALTHY,
        completed_at=completed_at,
        video_codec="h264",
    )


@pytest.mark.parametrize(
    "rtp_payloads",
    [(), (b"\x00\x00\x00",) * 3],
    ids=["zero-rtp", "corrupt-h264"],
)
def test_controlled_probe_ffprobe_rejects_metadata_without_a_decodable_frame(
    rtp_payloads: tuple[bytes, ...],
) -> None:
    result = _run_h264_media_probe(rtp_payloads)

    assert result.completed.stderr == b""
    assert result.requests == _expected_h264_requests(result.port)
    with pytest.raises(ValueError, match=r"^probe_ffprobe_result_invalid$"):
        ProbeFfprobeResultDecoder(
            clock=lambda: datetime(2026, 8, 30, 18, 0, tzinfo=UTC)
        ).decode(result.completed.stdout)
