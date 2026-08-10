from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

RTSP_PULL_SERVER_BINARY = os.environ.get("RTSP_PULL_SERVER_BINARY")
FFMPEG_BINARY = os.environ.get("FFMPEG_BINARY")
FFPROBE_BINARY = os.environ.get("FFPROBE_BINARY")
pytestmark = [
    pytest.mark.contract,
    pytest.mark.skipif(
        not all((RTSP_PULL_SERVER_BINARY, FFMPEG_BINARY, FFPROBE_BINARY)),
        reason="GStreamer pull server, FFmpeg and ffprobe binaries are required",
    ),
]


def unused_tcp_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def wait_for_listener(process: subprocess.Popen[str], port: int) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output, _ = process.communicate()
            pytest.fail(f"pull server exited before listen: {output}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    pytest.fail("pull server did not listen within ten seconds")


def process_owned_udp_sockets(process: subprocess.Popen[str]) -> frozenset[str]:
    if not sys.platform.startswith("linux"):
        return frozenset()
    socket_inodes = {
        target.removeprefix("socket:[").removesuffix("]")
        for fd in (Path("/proc") / str(process.pid) / "fd").iterdir()
        if (target := os.readlink(fd)).startswith("socket:[")
    }
    owned: set[str] = set()
    for table_name in ("udp", "udp6"):
        table = Path("/proc") / str(process.pid) / "net" / table_name
        for line in table.read_text(encoding="utf-8").splitlines()[1:]:
            fields = line.split()
            if fields[9] in socket_inodes:
                owned.add(f"{table_name}:{fields[1]}:{fields[2]}")
    return frozenset(owned)


def create_fixture(binary: str, path: Path, codec: str) -> None:
    encoder = "libx264" if codec == "h264" else "libx265"
    container = "h264" if codec == "h264" else "hevc"
    codec_options = (
        ["-x264-params", "keyint=25:min-keyint=25:scenecut=0"]
        if codec == "h264"
        else ["-x265-params", "pools=1:keyint=25:min-keyint=25:scenecut=0"]
    )
    result = subprocess.run(
        [
            binary,
            "-hide_banner",
            "-nostdin",
            "-loglevel",
            "error",
            "-f",
            "lavfi",
            "-i",
            "testsrc=size=160x120:rate=25",
            "-t",
            "2",
            "-an",
            "-pix_fmt",
            "yuv420p",
            "-threads",
            "1",
            "-c:v",
            encoder,
            "-g",
            "25",
            *codec_options,
            "-f",
            container,
            str(path),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert path.stat().st_size > 0


def probe_source(
    binary: str, port: int, path: str, transport: str
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            binary,
            "-v",
            "error",
            "-rtsp_transport",
            transport,
            "-timeout",
            "5000000",
            "-show_entries",
            "stream=codec_type,codec_name,width,height",
            "-of",
            "json",
            f"rtsp://127.0.0.1:{port}/{path}",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )


@pytest.mark.parametrize("codec", ["h264", "h265"])
def test_prepared_fixture_is_served_by_independent_pull_endpoints_over_tcp(
    tmp_path: Path, codec: str
) -> None:
    assert RTSP_PULL_SERVER_BINARY is not None
    assert FFMPEG_BINARY is not None
    assert FFPROBE_BINARY is not None
    fixture = tmp_path / f"fixture.{codec}"
    create_fixture(FFMPEG_BINARY, fixture, codec)
    port = unused_tcp_port()
    server = subprocess.Popen(
        [
            RTSP_PULL_SERVER_BINARY,
            "--address",
            "127.0.0.1",
            "--port",
            str(port),
            "--mount-prefix",
            "/source-",
            "--source-count",
            "2",
            "--fixture",
            str(fixture),
            "--codec",
            codec,
            "--fps",
            "25",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        wait_for_listener(server, port)
        assert process_owned_udp_sockets(server) == frozenset()
        for source_index in range(2):
            result = probe_source(
                FFPROBE_BINARY,
                port,
                f"source-{source_index:05d}",
                "tcp",
            )
            assert result.returncode == 0, result.stderr
            assert json.loads(result.stdout)["streams"] == [
                {
                    "codec_name": codec,
                    "codec_type": "video",
                    "width": 160,
                    "height": 120,
                }
            ]
        assert process_owned_udp_sockets(server) == frozenset()
        rejected_udp = probe_source(FFPROBE_BINARY, port, "source-00000", "udp")
        assert rejected_udp.returncode != 0
    finally:
        if server.poll() is None:
            server.send_signal(signal.SIGINT)
        output, _ = server.communicate(timeout=10)
    assert server.returncode == 0, output
    assert "transport=tcp" in output


def test_pull_server_rejects_relative_fixture_paths(tmp_path: Path) -> None:
    assert RTSP_PULL_SERVER_BINARY is not None
    fixture = tmp_path / "fixture.h264"
    fixture.write_bytes(b"fixture")

    result = subprocess.run(
        [
            RTSP_PULL_SERVER_BINARY,
            "--fixture",
            fixture.name,
            "--codec",
            "h264",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert result.returncode == 2
    assert "fixture_must_be_an_absolute_regular_file" in result.stderr
