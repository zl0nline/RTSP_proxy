from pathlib import Path

import pytest

from rtsp_proxy.probe import FfprobeRunner, ProbeFailed, RtspEndpoint


def write_executable(path: Path, script: str) -> Path:
    path.write_text(script, encoding="utf-8")
    path.chmod(0o750)
    return path


def test_ffprobe_runner_uses_pinned_tcp_and_microsecond_timeout_contract(tmp_path: Path) -> None:
    binary = write_executable(
        tmp_path / "ffprobe",
        """#!/bin/sh
case "$*" in
  *"-rtsp_transport tcp -timeout 5000000"*) ;;
  *) exit 2 ;;
esac
printf '{"streams":[{"codec_name":"h264","width":160,"height":120}]}\n'
""",
    )
    runner = FfprobeRunner(
        binary=binary,
        io_timeout_seconds=5,
        total_timeout_seconds=10,
    )

    observation = runner.inspect(
        RtspEndpoint(
            host="127.0.0.1",
            port=9999,
            path="a" * 25,
            username="external",
            password="lab-secret",
        )
    )

    assert observation.streams[0].codec_name == "h264"
    assert observation.streams[0].width == 160
    assert observation.streams[0].height == 120


def test_ffprobe_runner_never_exposes_url_credentials_from_failed_stderr(tmp_path: Path) -> None:
    binary = write_executable(
        tmp_path / "ffprobe",
        """#!/bin/sh
printf 'failed input: %s\n' "$*" >&2
exit 1
""",
    )
    runner = FfprobeRunner(
        binary=binary,
        io_timeout_seconds=1,
        total_timeout_seconds=2,
    )

    with pytest.raises(ProbeFailed, match="ffprobe_failed") as failure:
        runner.inspect(
            RtspEndpoint(
                host="camera.invalid",
                port=554,
                path="main",
                username="source-user",
                password="source-secret",
            )
        )

    assert "source-user" not in str(failure.value)
    assert "source-secret" not in str(failure.value)
