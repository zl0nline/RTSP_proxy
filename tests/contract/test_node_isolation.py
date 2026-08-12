from __future__ import annotations

import hashlib
import os
import socket
from pathlib import Path
from uuid import UUID

import pytest

from rtsp_proxy.node_runtime import (
    DirectNodeProcessController,
    LinuxNodeSupervisor,
    MediaNodeSmokeProbe,
    NodeRuntimeCommand,
    NodeRuntimeSpec,
    SecureNodeConfigStore,
)
from rtsp_proxy.nodes import NodeRuntimeAction

MEDIA_MTX_BINARY = os.environ.get("MEDIAMTX_BINARY")
pytestmark = [
    pytest.mark.contract,
    pytest.mark.skipif(
        not MEDIA_MTX_BINARY or os.name != "posix" or not Path("/proc").is_dir(),
        reason="native Linux MEDIAMTX_BINARY is required",
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


def send_options(connection: socket.socket, port: int, cseq: int) -> bytes:
    request = (
        f"OPTIONS rtsp://127.0.0.1:{port}/ RTSP/1.0\r\n"
        f"CSeq: {cseq}\r\n"
        "User-Agent: rtsp-proxy-isolation-contract/1\r\n\r\n"
    ).encode("ascii")
    connection.sendall(request)
    response = bytearray()
    while b"\r\n\r\n" not in response:
        chunk = connection.recv(4096)
        assert chunk
        response.extend(chunk)
        assert len(response) <= 8192
    first_line = bytes(response).partition(b"\r\n")[0]
    assert first_line.startswith(b"RTSP/1.0 ")
    return bytes(response)


def test_two_real_nodes_keep_process_listener_and_session_isolation(
    tmp_path: Path,
) -> None:
    assert MEDIA_MTX_BINARY is not None
    binary = Path(MEDIA_MTX_BINARY).resolve(strict=True)
    config_root = tmp_path / "nodes"
    config_root.mkdir(mode=0o750)
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
    process = DirectNodeProcessController(
        mediamtx_binary=binary,
        config_root=config_root,
    )
    supervisor = LinuxNodeSupervisor(
        config_store=SecureNodeConfigStore(root=config_root, group_id=None),
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

        with socket.create_connection(("127.0.0.1", second.external_port), timeout=2) as session:
            session.settimeout(2)
            send_options(session, second.external_port, 1)

            first_restarted = supervisor.execute(
                NodeRuntimeCommand.for_node(NodeRuntimeAction.RESTART, first)
            )
            second_after_restart = supervisor.execute(
                NodeRuntimeCommand.for_node(NodeRuntimeAction.OBSERVE, second)
            )

            assert first_restarted.process_id != first_started.process_id
            assert second_after_restart.process_id == second_started.process_id
            assert (
                second_after_restart.process_start_ticks
                == second_started.process_start_ticks
            )
            send_options(session, second.external_port, 2)

        supervisor.execute(NodeRuntimeCommand.for_node(NodeRuntimeAction.STOP, first))
        second_after_stop = supervisor.execute(
            NodeRuntimeCommand.for_node(NodeRuntimeAction.OBSERVE, second)
        )
        assert second_after_stop.process_id == second_started.process_id
    finally:
        process.close()


def _port_is_bindable(port: int) -> bool:
    try:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", port))
    except OSError:
        return False
    return True
