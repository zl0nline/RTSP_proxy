from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import subprocess
import time
import urllib.request
from base64 import b64encode
from contextlib import suppress
from pathlib import Path
from uuid import UUID

import pytest

from rtsp_proxy.node_runtime import (
    LinuxNodeSupervisor,
    MediaNodeSmokeProbe,
    NodeManagementCredentials,
    NodeRuntimeCommand,
    NodeRuntimeSpec,
    SecureNodeConfigStore,
    SystemdNodeProcessController,
)
from rtsp_proxy.nodes import NodeRuntimeAction

MEDIA_MTX_BINARY = os.environ.get("MEDIAMTX_BINARY")
RTSP_PULL_SERVER_BINARY = os.environ.get("RTSP_PULL_SERVER_BINARY")
RTSP_LOAD_READER_BINARY = os.environ.get("RTSP_LOAD_READER_BINARY")
FFMPEG_BINARY = os.environ.get("FFMPEG_BINARY")
pytestmark = [
    pytest.mark.contract,
    pytest.mark.skipif(
        not all(
            (
                MEDIA_MTX_BINARY,
                RTSP_PULL_SERVER_BINARY,
                RTSP_LOAD_READER_BINARY,
                FFMPEG_BINARY,
            )
        )
        or os.name != "posix"
        or os.geteuid() != 0
        or not Path("/proc").is_dir(),
        reason="root native Linux systemd and media/load binaries are required",
    ),
]


def unused_tcp_ports(count: int) -> tuple[int, ...]:
    ports: set[int] = set()
    while len(ports) < count:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            ports.add(int(listener.getsockname()[1]))
    return tuple(ports)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as artifact:
        for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def create_fixture(path: Path) -> None:
    assert FFMPEG_BINARY is not None
    result = subprocess.run(
        [
            FFMPEG_BINARY,
            "-hide_banner",
            "-nostdin",
            "-loglevel",
            "error",
            "-f",
            "lavfi",
            "-i",
            "testsrc=size=160x120:rate=10",
            "-t",
            "2",
            "-an",
            "-pix_fmt",
            "yuv420p",
            "-threads",
            "1",
            "-c:v",
            "libx264",
            "-preset",
            "ultrafast",
            "-tune",
            "zerolatency",
            "-g",
            "10",
            "-x264-params",
            "keyint=10:min-keyint=10:scenecut=0",
            "-f",
            "h264",
            str(path),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr


def wait_for_listener(process: subprocess.Popen[str], port: int) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        assert process.poll() is None
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    pytest.fail("source server did not listen")


def reader_event_count(path: Path, event: str) -> int:
    if not path.exists():
        return 0
    return sum(
        1
        for line in path.read_text(encoding="utf-8").splitlines()
        if json.loads(line).get("event") == event
    )


def outbound_rtp_packets(
    spec: NodeRuntimeSpec,
    credentials: NodeManagementCredentials,
) -> int:
    username = credentials.username
    password = credentials.password
    request = urllib.request.Request(
        f"http://127.0.0.1:{spec.metrics_port}/metrics",
        headers={
            "Authorization": "Basic "
            + b64encode(f"{username}:{password}".encode()).decode()
        },
    )
    with urllib.request.urlopen(request, timeout=2) as response:
        payload = response.read().decode("utf-8")
    return sum(
        int(float(line.rsplit(" ", 1)[1]))
        for line in payload.splitlines()
        if line.startswith("rtsp_sessions_outbound_rtp_packets{")
    )


def wait_for_rtp_progress(
    spec: NodeRuntimeSpec,
    credentials: NodeManagementCredentials,
    previous: int,
) -> int:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        current = outbound_rtp_packets(spec, credentials)
        if current > previous:
            return current
        time.sleep(0.1)
    pytest.fail("unaffected node did not keep forwarding RTP")


def stop_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        process.terminate()
    try:
        output, _ = process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        output, _ = process.communicate(timeout=5)
    assert process.returncode == 0, output


def test_two_real_nodes_keep_process_listener_and_session_isolation(
    tmp_path: Path,
) -> None:
    assert MEDIA_MTX_BINARY is not None
    assert RTSP_PULL_SERVER_BINARY is not None
    assert RTSP_LOAD_READER_BINARY is not None
    binary = Path(MEDIA_MTX_BINARY).resolve(strict=True)
    config_root = Path("/etc/rtsp-proxy/nodes")
    config_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    config_root.chmod(0o700)
    ports = unused_tcp_ports(6)
    binary_sha256 = sha256(binary)
    first = NodeRuntimeSpec(
        node_id=UUID("00000000-0000-0000-0000-000000000001"),
        external_port=ports[0],
        api_port=ports[1],
        metrics_port=ports[2],
        desired_revision=1,
        release_id="native-contract",
        mediamtx_binary_sha256=binary_sha256,
    )
    second = NodeRuntimeSpec(
        node_id=UUID("00000000-0000-0000-0000-000000000002"),
        external_port=ports[3],
        api_port=ports[4],
        metrics_port=ports[5],
        desired_revision=1,
        release_id="native-contract",
        mediamtx_binary_sha256=binary_sha256,
    )
    fixture = tmp_path / "fixture.h264"
    create_fixture(fixture)
    source_port = unused_tcp_ports(1)[0]
    source = subprocess.Popen(
        [
            RTSP_PULL_SERVER_BINARY,
            "--address",
            "127.0.0.1",
            "--port",
            str(source_port),
            "--mount-prefix",
            "/fixture-",
            "--source-count",
            "1",
            "--fixture",
            str(fixture),
            "--fixture-sha256",
            sha256(fixture),
            "--codec",
            "h264",
            "--fps",
            "10",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    wait_for_listener(source, source_port)
    reader: subprocess.Popen[str] | None = None
    process = SystemdNodeProcessController(
        systemctl=Path("/usr/bin/systemctl"),
    )
    supervisor = LinuxNodeSupervisor(
        config_store=SecureNodeConfigStore(
            root=config_root,
            owner_uid=0,
            binary_path=binary,
        ),
        process=process,
        smoke=MediaNodeSmokeProbe(timeout_seconds=1),
        port_is_bindable=lambda port: _port_is_bindable(port),
        smoke_attempts=40,
        retry_delay_seconds=0.1,
    )
    try:
        first_started = supervisor.execute(
            NodeRuntimeCommand.for_node(NodeRuntimeAction.PROVISION_START, first)
        )
        second_started = supervisor.execute(
            NodeRuntimeCommand.for_node(NodeRuntimeAction.PROVISION_START, second)
        )
        assert first_started.process_id != second_started.process_id
        assert first_started.process_start_ticks is not None
        assert second_started.process_start_ticks is not None
        credentials = SecureNodeConfigStore(root=config_root).credentials(second)
        reader_identity = SecureNodeConfigStore(root=config_root).reader_credentials(second)
        assert credentials is not None
        assert reader_identity is not None
        api_request = urllib.request.Request(
            f"http://127.0.0.1:{second.api_port}/v3/config/paths/replace/"
            "__rtsp_proxy_runtime_probe",
            data=json.dumps(
                {
                    "source": f"rtsp://127.0.0.1:{source_port}/fixture-00000",
                    "sourceOnDemand": True,
                    "sourceOnDemandCloseAfter": "10s",
                    "rtspTransport": "tcp",
                }
            ).encode(),
            headers={
                "Authorization": "Basic "
                + b64encode(f"{credentials.username}:{credentials.password}".encode()).decode(),
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(api_request, timeout=2):
            pass
        plan = tmp_path / "readers.tsv"
        plan.write_text("__rtsp_proxy_runtime_probe\t1\t0\t0\t0\n", encoding="utf-8")
        reader_credentials = tmp_path / "reader-credentials.txt"
        reader_credentials.write_text(
            f"{reader_identity.username}\n{reader_identity.password}\n",
            encoding="utf-8",
        )
        reader_credentials.chmod(0o600)
        events = tmp_path / "events.jsonl"
        reader = subprocess.Popen(
            [
                RTSP_LOAD_READER_BINARY,
                "--host",
                "127.0.0.1",
                "--port",
                str(second.external_port),
                "--reader-plan",
                str(plan),
                "--credentials-file",
                str(reader_credentials),
                "--codec",
                "h264",
                "--connect-rate",
                "10",
                "--hold-seconds",
                "20",
                "--evidence-grace-seconds",
                "1",
                "--events-file",
                str(events),
                "--lifecycle",
                "single",
                "--global-reader-count",
                "1",
                "--generator-host",
                "isolation",
                "--profile-sha256",
                "a" * 64,
                "--reader-plan-sha256",
                hashlib.sha256(plan.read_bytes()).hexdigest(),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        deadline = time.monotonic() + 5
        while (
            reader_event_count(events, "first_decodable_frame") < 1
            and time.monotonic() < deadline
        ):
            assert reader.poll() is None
            time.sleep(0.1)
        assert reader_event_count(events, "first_decodable_frame") >= 1
        before_restart = outbound_rtp_packets(second, credentials)

        first_restarted = supervisor.execute(
            NodeRuntimeCommand.for_node(NodeRuntimeAction.RESTART, first)
        )
        second_after_restart = supervisor.execute(
            NodeRuntimeCommand.for_node(NodeRuntimeAction.OBSERVE, second)
        )

        assert first_restarted.process_id != first_started.process_id
        assert second_after_restart.process_id == second_started.process_id
        assert second_after_restart.process_start_ticks == second_started.process_start_ticks
        assert reader.poll() is None
        after_restart = wait_for_rtp_progress(second, credentials, before_restart)

        supervisor.execute(NodeRuntimeCommand.for_node(NodeRuntimeAction.STOP, first))
        second_after_stop = supervisor.execute(
            NodeRuntimeCommand.for_node(NodeRuntimeAction.OBSERVE, second)
        )
        assert second_after_stop.process_id == second_started.process_id
        wait_for_rtp_progress(second, credentials, after_restart)
        assert reader.poll() is None
        reader_output, _ = reader.communicate(timeout=25)
        assert reader.returncode == 0, reader_output
        assert "SUMMARY started=1 decodable=1 failed=0 transport=tcp" in reader_output
    finally:
        if reader is not None and reader.poll() is None:
            reader.kill()
            reader.communicate(timeout=5)
        for spec in (first, second):
            with suppress(Exception):
                process.execute(NodeRuntimeAction.STOP, spec)
            shutil.rmtree(config_root / str(spec.node_id), ignore_errors=True)
        stop_process(source)


def _port_is_bindable(port: int) -> bool:
    try:
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", port))
    except OSError:
        return False
    return True
