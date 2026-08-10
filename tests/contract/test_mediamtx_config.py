from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

MEDIA_MTX_BINARY = os.environ.get("MEDIAMTX_BINARY")
pytestmark = [
    pytest.mark.contract,
    pytest.mark.skipif(
        not MEDIA_MTX_BINARY,
        reason="MEDIAMTX_BINARY is required for the external contract suite",
    ),
]


def unused_tcp_ports(count: int) -> tuple[int, ...]:
    ports: set[int] = set()
    while len(ports) < count:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            ports.add(int(listener.getsockname()[1]))
    return tuple(ports)


def effective_config(api_port: int, process: subprocess.Popen[str]) -> dict[str, Any]:
    deadline = time.monotonic() + 10
    url = f"http://127.0.0.1:{api_port}/v3/config/global/get"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output, _ = process.communicate()
            pytest.fail(f"MediaMTX exited during startup:\n{output}")
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                return json.load(response)  # type: ignore[no-any-return]
        except (OSError, urllib.error.URLError):
            time.sleep(0.1)
    pytest.fail("MediaMTX API did not become ready within 10 seconds")


def test_phase_0_baseline_exposes_only_ordinary_tcp_rtsp_and_local_management(
    tmp_path: Path,
) -> None:
    assert MEDIA_MTX_BINARY is not None
    api_port, metrics_port, rtsp_port = unused_tcp_ports(3)

    template = Path("deploy/mediamtx.yml.example").read_text(encoding="utf-8")
    generated = (
        template.replace("127.0.0.1:9997", f"127.0.0.1:{api_port}")
        .replace("127.0.0.1:9998", f"127.0.0.1:{metrics_port}")
        .replace("rtspAddress: :9999", f"rtspAddress: 127.0.0.1:{rtsp_port}")
    )
    config = tmp_path / "mediamtx.yml"
    config.write_text(generated, encoding="utf-8")

    process = subprocess.Popen(
        [MEDIA_MTX_BINARY, str(config)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        actual = effective_config(api_port, process)
        expected = {
            "api": True,
            "apiAddress": f"127.0.0.1:{api_port}",
            "metrics": True,
            "metricsAddress": f"127.0.0.1:{metrics_port}",
            "pprof": False,
            "playback": False,
            "rtsp": True,
            "rtspTransports": ["tcp"],
            "rtspEncryption": "no",
            "rtspAddress": f"127.0.0.1:{rtsp_port}",
            "rtmp": False,
            "hls": False,
            "webrtc": False,
            "srt": False,
            "moq": False,
        }
        assert {key: actual[key] for key in expected} == expected
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
        try:
            process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)
            pytest.fail("MediaMTX did not stop within 10 seconds after SIGINT")
