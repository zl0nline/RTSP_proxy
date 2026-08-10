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

import pytest

from rtsp_proxy.media import MediaMtxClient, MediaPathConfig

MEDIA_MTX_BINARY = os.environ.get("MEDIAMTX_BINARY")
FFMPEG_BINARY = os.environ.get("FFMPEG_BINARY")
FFPROBE_BINARY = os.environ.get("FFPROBE_BINARY")
pytestmark = [
    pytest.mark.contract,
    pytest.mark.skipif(
        not all((MEDIA_MTX_BINARY, FFMPEG_BINARY, FFPROBE_BINARY)),
        reason="MediaMTX, FFmpeg and ffprobe binaries are required",
    ),
]


def unused_tcp_ports(count: int) -> tuple[int, ...]:
    ports: set[int] = set()
    while len(ports) < count:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            ports.add(int(listener.getsockname()[1]))
    return tuple(ports)


def start_process(command: list[str]) -> subprocess.Popen[str]:
    return subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def stop_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
    try:
        process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate(timeout=5)
        pytest.fail("external contract process did not stop within 10 seconds")


def wait_for_json(url: str, process: subprocess.Popen[str], *, ready_path: bool = False) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output, _ = process.communicate()
            pytest.fail(f"external contract process exited early:\n{output}")
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                payload = json.load(response)
            if not ready_path or payload.get("ready") is True:
                return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(0.1)
    pytest.fail("external contract endpoint did not become ready within 10 seconds")


def test_external_rtsp_tcp_is_transparent_and_unrelated_hot_update_isolated(
    tmp_path: Path,
) -> None:
    assert MEDIA_MTX_BINARY is not None
    assert FFMPEG_BINARY is not None
    assert FFPROBE_BINARY is not None
    origin_api_port, origin_rtsp_port, proxy_api_port, proxy_metrics_port, proxy_rtsp_port = (
        unused_tcp_ports(5)
    )
    public_id = "f" * 25
    other_public_id = "g" * 25

    origin_config = tmp_path / "origin.yml"
    origin_config.write_text(
        f"""
logLevel: warn
logDestinations: [stdout]
authMethod: internal
authInternalUsers:
  - user: any
    pass:
    ips: [\"127.0.0.1\", \"::1\"]
    permissions:
      - action: api
      - action: publish
      - action: read
api: true
apiAddress: 127.0.0.1:{origin_api_port}
metrics: false
pprof: false
playback: false
rtsp: true
rtspTransports: [tcp]
rtspEncryption: \"no\"
rtspAddress: 127.0.0.1:{origin_rtsp_port}
rtmp: false
hls: false
webrtc: false
srt: false
moq: false
paths:
  fixture:
    source: publisher
""".lstrip(),
        encoding="utf-8",
    )

    template = Path("deploy/mediamtx.yml.example").read_text(encoding="utf-8")
    proxy_config = tmp_path / "proxy.yml"
    proxy_config.write_text(
        template.replace("127.0.0.1:9997", f"127.0.0.1:{proxy_api_port}")
        .replace("127.0.0.1:9998", f"127.0.0.1:{proxy_metrics_port}")
        .replace("rtspAddress: :9999", f"rtspAddress: 127.0.0.1:{proxy_rtsp_port}")
        .replace(
            "      - action: metrics\n",
            "      - action: metrics\n"
            "  - user: external\n"
            "    pass: lab-secret\n"
            "    permissions:\n"
            "      - action: read\n"
            f"        path: ~^({public_id}|{other_public_id})$\n",
        ),
        encoding="utf-8",
    )

    origin = start_process([MEDIA_MTX_BINARY, str(origin_config)])
    publisher: subprocess.Popen[str] | None = None
    proxy: subprocess.Popen[str] | None = None
    reader: subprocess.Popen[str] | None = None
    try:
        wait_for_json(
            f"http://127.0.0.1:{origin_api_port}/v3/config/global/get",
            origin,
        )
        publisher = start_process(
            [
                FFMPEG_BINARY,
                "-hide_banner",
                "-loglevel",
                "error",
                "-re",
                "-f",
                "lavfi",
                "-i",
                "testsrc=size=160x120:rate=10",
                "-an",
                "-c:v",
                "libx264",
                "-preset",
                "ultrafast",
                "-tune",
                "zerolatency",
                "-g",
                "10",
                "-f",
                "rtsp",
                "-rtsp_transport",
                "tcp",
                f"rtsp://127.0.0.1:{origin_rtsp_port}/fixture",
            ]
        )
        wait_for_json(
            f"http://127.0.0.1:{origin_api_port}/v3/paths/get/fixture",
            publisher,
            ready_path=True,
        )

        proxy = start_process([MEDIA_MTX_BINARY, str(proxy_config)])
        wait_for_json(
            f"http://127.0.0.1:{proxy_api_port}/v3/config/global/get",
            proxy,
        )
        client = MediaMtxClient(
            api_url=f"http://127.0.0.1:{proxy_api_port}",
            timeout_seconds=2,
        )
        client.put_path(
            MediaPathConfig(
                name=public_id,
                source_url=f"rtsp://127.0.0.1:{origin_rtsp_port}/fixture",
                source_on_demand=True,
            )
        )
        client.put_path(
            MediaPathConfig(
                name=other_public_id,
                source_url=f"rtsp://127.0.0.1:{origin_rtsp_port}/fixture",
                source_on_demand=True,
            )
        )

        result = subprocess.run(
            [
                FFPROBE_BINARY,
                "-v",
                "error",
                "-rtsp_transport",
                "tcp",
                "-rw_timeout",
                "5000000",
                "-show_entries",
                "stream=codec_name,width,height",
                "-of",
                "json",
                f"rtsp://external:lab-secret@127.0.0.1:{proxy_rtsp_port}/{public_id}",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.returncode == 0, "ffprobe failed against the ordinary RTSP endpoint"
        assert json.loads(result.stdout)["streams"] == [
            {"codec_name": "h264", "width": 160, "height": 120}
        ]

        reader = start_process(
            [
                FFMPEG_BINARY,
                "-hide_banner",
                "-loglevel",
                "error",
                "-rtsp_transport",
                "tcp",
                "-i",
                f"rtsp://external:lab-secret@127.0.0.1:{proxy_rtsp_port}/{other_public_id}",
                "-t",
                "3",
                "-map",
                "0:v:0",
                "-f",
                "null",
                "-",
            ]
        )
        time.sleep(0.5)
        if reader.poll() is not None:
            reader_output, _ = reader.communicate()
            pytest.fail("reader failed before the isolated hot update: " + reader_output)

        client.put_path(
            MediaPathConfig(
                name=public_id,
                source_url=f"rtsp://127.0.0.1:{origin_rtsp_port}/different",
                source_on_demand=True,
            )
        )

        reader_output, _ = reader.communicate(timeout=10)
        assert reader.returncode == 0, (
            "reader of an unrelated path was interrupted: " + reader_output
        )
        reader = None
    finally:
        for process in (reader, proxy, publisher, origin):
            if process is not None:
                stop_process(process)
