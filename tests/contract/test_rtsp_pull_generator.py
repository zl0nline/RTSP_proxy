from __future__ import annotations

import hashlib
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
RTSP_LOAD_READER_BINARY = os.environ.get("RTSP_LOAD_READER_BINARY")
FFMPEG_BINARY = os.environ.get("FFMPEG_BINARY")
FFPROBE_BINARY = os.environ.get("FFPROBE_BINARY")
pytestmark = [
    pytest.mark.contract,
    pytest.mark.skipif(
        not all(
            (
                RTSP_PULL_SERVER_BINARY,
                RTSP_LOAD_READER_BINARY,
                FFMPEG_BINARY,
                FFPROBE_BINARY,
            )
        ),
        reason="GStreamer load binaries, FFmpeg and ffprobe are required",
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


def reader_evidence_arguments(plan: Path) -> list[str]:
    return [
        "--generator-host",
        "generator-a",
        "--profile-sha256",
        "a" * 64,
        "--reader-plan-sha256",
        hashlib.sha256(plan.read_bytes()).hexdigest(),
    ]


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
    assert RTSP_LOAD_READER_BINARY is not None
    assert FFMPEG_BINARY is not None
    assert FFPROBE_BINARY is not None
    fixture = tmp_path / f"fixture.{codec}"
    create_fixture(FFMPEG_BINARY, fixture, codec)
    expected_codec_name = "h264" if codec == "h264" else "hevc"
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
                    "codec_name": expected_codec_name,
                    "codec_type": "video",
                    "width": 160,
                    "height": 120,
                }
            ]
        assert process_owned_udp_sockets(server) == frozenset()
        rejected_udp = probe_source(FFPROBE_BINARY, port, "source-00000", "udp")
        assert rejected_udp.returncode != 0

        reader_plan = tmp_path / "reader-plan.tsv"
        reader_plan.write_text("source-00000\t2\t0\nsource-00001\t2\t2\n", encoding="utf-8")
        events_file = tmp_path / "reader-events.jsonl"
        load_reader = subprocess.Popen(
            [
                RTSP_LOAD_READER_BINARY,
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--reader-plan",
                str(reader_plan),
                "--codec",
                codec,
                "--connect-rate",
                "10",
                "--hold-seconds",
                "2",
                "--events-file",
                str(events_file),
                "--lifecycle",
                "single",
                "--global-reader-count",
                "4",
                *reader_evidence_arguments(reader_plan),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        time.sleep(1)
        assert load_reader.poll() is None
        assert process_owned_udp_sockets(load_reader) == frozenset()
        reader_output, _ = load_reader.communicate(timeout=10)
        assert load_reader.returncode == 0, reader_output
        assert "SUMMARY started=4 decodable=4 failed=0 transport=tcp" in reader_output
        assert "completed=true interrupted=false" in reader_output
        reader_events = [
            json.loads(line) for line in events_file.read_text(encoding="utf-8").splitlines()
        ]
        assert len(reader_events) == 13
        assert {event["event"] for event in reader_events} == {
            "reader_started",
            "play_sent",
            "first_decodable_frame",
            "run_completed",
        }
        assert {
            event["reader_id"]
            for event in reader_events
            if event["event"] == "first_decodable_frame"
        } == {0, 1, 2, 3}
        starts = sorted(
            event["at_monotonic_ms"]
            for event in reader_events
            if event["event"] == "reader_started"
        )
        assert starts[-1] - starts[0] >= 250
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


def test_load_reader_interruption_never_reports_a_partial_run_as_success(
    tmp_path: Path,
) -> None:
    assert RTSP_LOAD_READER_BINARY is not None
    plan = tmp_path / "plan.tsv"
    plan.write_text("source-00000\t4\t0\n", encoding="utf-8")
    events = tmp_path / "events.jsonl"
    process = subprocess.Popen(
        [
            RTSP_LOAD_READER_BINARY,
            "--host",
            "127.0.0.1",
            "--port",
            "9",
            "--reader-plan",
            str(plan),
            "--codec",
            "h264",
            "--connect-rate",
            "1",
            "--hold-seconds",
            "60",
            "--events-file",
            str(events),
            "--lifecycle",
            "single",
            "--global-reader-count",
            "4",
            "--allow-failures",
            *reader_evidence_arguments(plan),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    time.sleep(0.5)
    process.send_signal(signal.SIGTERM)
    output, _ = process.communicate(timeout=10)

    assert process.returncode == 6, output
    assert "completed=false interrupted=true" in output
    completion = json.loads(events.read_text(encoding="utf-8").splitlines()[-1])
    assert completion["event"] == "run_completed"
    assert completion["exit_code"] == 6
    assert completion["interrupted"] is True


def test_load_reader_rejects_a_group_readable_credentials_file(tmp_path: Path) -> None:
    assert RTSP_LOAD_READER_BINARY is not None
    plan = tmp_path / "plan.tsv"
    plan.write_text("source-00000\t1\t0\n", encoding="utf-8")
    credentials = tmp_path / "credentials.txt"
    credentials.write_text("user\npassword\n", encoding="utf-8")
    credentials.chmod(0o640)

    result = subprocess.run(
        [
            RTSP_LOAD_READER_BINARY,
            "--host",
            "127.0.0.1",
            "--port",
            "9",
            "--reader-plan",
            str(plan),
            "--codec",
            "h264",
            "--connect-rate",
            "1",
            "--hold-seconds",
            "1",
            "--events-file",
            str(tmp_path / "events.jsonl"),
            "--credentials-file",
            str(credentials),
            "--lifecycle",
            "single",
            "--global-reader-count",
            "1",
            *reader_evidence_arguments(plan),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 2
    assert "credentials_file_security_policy_failed" in result.stderr
