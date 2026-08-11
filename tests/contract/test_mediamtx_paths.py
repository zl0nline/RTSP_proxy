from __future__ import annotations

import os
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from rtsp_proxy.identifiers import PublicId
from rtsp_proxy.media import MediaMtxClient, MediaPathConfig

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


def wait_until_ready(api_url: str, process: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output, _ = process.communicate()
            pytest.fail(f"MediaMTX exited during startup:\n{output}")
        try:
            with urllib.request.urlopen(f"{api_url}/v3/config/global/get", timeout=1):
                return
        except (OSError, urllib.error.URLError):
            time.sleep(0.1)
    pytest.fail("MediaMTX API did not become ready within 10 seconds")


def start_mediamtx(config: Path) -> subprocess.Popen[str]:
    assert MEDIA_MTX_BINARY is not None
    return subprocess.Popen(
        [MEDIA_MTX_BINARY, str(config)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def stop_mediamtx(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
    try:
        process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate(timeout=5)
        pytest.fail("MediaMTX did not stop within 10 seconds after SIGINT")


def test_path_hot_update_and_delete_are_idempotent_and_isolated(tmp_path: Path) -> None:
    assert MEDIA_MTX_BINARY is not None
    api_port, metrics_port, rtsp_port, source_port = unused_tcp_ports(4)
    api_url = f"http://127.0.0.1:{api_port}"
    template = Path("deploy/mediamtx.yml.example").read_text(encoding="utf-8")
    config = tmp_path / "mediamtx.yml"
    config.write_text(
        template.replace("127.0.0.1:9997", f"127.0.0.1:{api_port}")
        .replace("127.0.0.1:9998", f"127.0.0.1:{metrics_port}")
        .replace("rtspAddress: :9999", f"rtspAddress: 127.0.0.1:{rtsp_port}"),
        encoding="utf-8",
    )
    process = start_mediamtx(config)
    first_name = "a" * 26
    second_name = "b" * 25 + "a"
    first_id = PublicId.parse(first_name)
    second_id = PublicId.parse(second_name)
    client = MediaMtxClient(api_url=api_url, timeout_seconds=2)
    first_v1 = MediaPathConfig(
        name=first_id,
        source_url=f"rtsp://127.0.0.1:{source_port}/first-v1",
    )
    first_v2 = MediaPathConfig(
        name=first_id,
        source_url=f"rtsp://127.0.0.1:{source_port}/first-v2",
    )
    second = MediaPathConfig(
        name=second_id,
        source_url=f"rtsp://127.0.0.1:{source_port}/second",
    )

    try:
        wait_until_ready(api_url, process)
        client.put_path(first_v1)
        client.put_path(second)
        client.put_path(first_v2)

        assert set(client.inventory_paths().camera_ids) == {first_id, second_id}
        assert client.get_path(first_id) == first_v2
        assert client.get_path(second_id) == second

        client.delete_path(first_id)
        client.delete_path(first_id)

        assert client.get_path(first_id) is None
        assert client.get_path(second_id) == second
    finally:
        stop_mediamtx(process)


def test_runtime_paths_require_cold_restore_after_a_media_node_restart(tmp_path: Path) -> None:
    assert MEDIA_MTX_BINARY is not None
    api_port, metrics_port, rtsp_port, source_port = unused_tcp_ports(4)
    api_url = f"http://127.0.0.1:{api_port}"
    template = Path("deploy/mediamtx.yml.example").read_text(encoding="utf-8")
    config = tmp_path / "mediamtx.yml"
    config.write_text(
        template.replace("127.0.0.1:9997", f"127.0.0.1:{api_port}")
        .replace("127.0.0.1:9998", f"127.0.0.1:{metrics_port}")
        .replace("rtspAddress: :9999", f"rtspAddress: 127.0.0.1:{rtsp_port}"),
        encoding="utf-8",
    )
    path = MediaPathConfig(
        name=PublicId.parse("e" * 25 + "a"),
        source_url=f"rtsp://127.0.0.1:{source_port}/main",
    )
    client = MediaMtxClient(api_url=api_url, timeout_seconds=2)

    first_process = start_mediamtx(config)
    try:
        wait_until_ready(api_url, first_process)
        client.put_path(path)
        assert client.get_path(path.name) == path
    finally:
        stop_mediamtx(first_process)

    second_process = start_mediamtx(config)
    try:
        wait_until_ready(api_url, second_process)
        assert client.get_path(path.name) is None

        client.put_path(path)
        assert client.get_path(path.name) == path
    finally:
        stop_mediamtx(second_process)
