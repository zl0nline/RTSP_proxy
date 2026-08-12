from __future__ import annotations

import json
import socket
from dataclasses import replace
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import ClassVar
from uuid import UUID, uuid4

import pytest

from rtsp_proxy.identifiers import PublicId
from rtsp_proxy.media import MediaNodeUnavailable, MediaPathConfig
from rtsp_proxy.node_runtime import (
    LinuxNodeSupervisor,
    MediaNodeConfigRenderer,
    NodeManagementCredentials,
    NodeProcessSnapshot,
    NodeRuntimePolicy,
    NodeRuntimeSpec,
    RootMediaNodeAdapter,
    SecureNodeConfigStore,
    UnixMediaNodeClientFactory,
    UnixNodeSupervisorServer,
)
from rtsp_proxy.nodes import MediaNode, NodeHealth, NodeRuntimeAction, NodeState

NODE_ID = UUID("00000000-0000-0000-0000-000000000001")
PUBLIC_ID = PublicId.parse("a" * 26)


def ready_node() -> MediaNode:
    now = datetime.now(UTC)
    return MediaNode(
        id=NODE_ID,
        name="media-a",
        external_port=12000,
        api_port=13000,
        metrics_port=14000,
        release_id="v1.20.0",
        mediamtx_binary_sha256="a" * 64,
        state=NodeState.RUNNING,
        runtime_state=NodeState.RUNNING,
        health=NodeHealth.HEALTHY,
        management_fresh=True,
        management_observed_at=now,
        runtime_observed_at=now,
        config_compatible=True,
        desired_revision=3,
        applied_revision=3,
        process_id=123,
        process_start_ticks=456,
        process_boot_id=UUID("10000000-0000-0000-0000-000000000001"),
        observed_config_sha256="b" * 64,
        observed_release_id="v1.20.0",
    )


def unix_answer(
    socket_path: Path,
    response: dict[str, object],
    captured: dict[str, object],
) -> Thread:
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    listener.listen(1)

    def answer() -> None:
        try:
            connection, _ = listener.accept()
            with connection:
                captured.update(json.loads(connection.makefile("rb").readline(65537)))
                connection.sendall((json.dumps(response) + "\n").encode())
        finally:
            listener.close()

    thread = Thread(target=answer)
    thread.start()
    return thread


def test_node_aware_media_client_uses_only_the_selected_node_identity(
) -> None:
    socket_path = Path("/tmp") / f"rtsp-media-{uuid4().hex}.sock"
    captured: dict[str, object] = {}
    server = unix_answer(
        socket_path,
        {
            "schema_version": 1,
            "ok": True,
            "path": {
                "name": str(PUBLIC_ID),
                "source_url": "rtsp://camera.invalid/main",
            },
            "inventory": None,
            "error": None,
        },
        captured,
    )

    actual = UnixMediaNodeClientFactory(
        socket_path=socket_path,
        timeout_seconds=1,
    ).for_node(ready_node()).get_path(PUBLIC_ID)

    server.join(timeout=2)
    socket_path.unlink(missing_ok=True)
    assert actual == MediaPathConfig(
        name=PUBLIC_ID,
        source_url="rtsp://camera.invalid/main",
    )
    assert captured == {
        "schema_version": 1,
        "request_type": "media_path",
        "operation": "get",
        "spec": {
            "node_id": str(NODE_ID),
            "external_port": 12000,
            "api_port": 13000,
            "metrics_port": 14000,
            "desired_revision": 3,
            "release_id": "v1.20.0",
            "mediamtx_binary_sha256": "a" * 64,
        },
        "path": {"name": str(PUBLIC_ID), "source_url": None},
    }


def test_node_aware_media_client_fails_before_io_for_an_unready_node(
    tmp_path: Path,
) -> None:
    node = replace(ready_node(), management_fresh=False)

    with pytest.raises(MediaNodeUnavailable, match="media_node_not_ready"):
        UnixMediaNodeClientFactory(
            socket_path=tmp_path / "missing.sock",
            timeout_seconds=1,
        ).for_node(node)


def test_node_aware_media_client_sanitizes_helper_failures(tmp_path: Path) -> None:
    socket_path = Path("/tmp") / f"rtsp-media-{uuid4().hex}.sock"
    server = unix_answer(
        socket_path,
        {
            "schema_version": 1,
            "ok": False,
            "path": None,
            "inventory": None,
            "error": "node_media_operation_failed",
        },
        {},
    )

    with pytest.raises(MediaNodeUnavailable) as raised:
        UnixMediaNodeClientFactory(
            socket_path=socket_path,
            timeout_seconds=1,
        ).for_node(ready_node()).put_path(
            MediaPathConfig(
                name=PUBLIC_ID,
                source_url="rtsp://camera.invalid/private",
            )
        )

    server.join(timeout=2)
    socket_path.unlink(missing_ok=True)
    assert "camera.invalid" not in str(raised.value)


class MediaApiHandler(BaseHTTPRequestHandler):
    paths: ClassVar[dict[str, dict[str, object]]] = {}
    runtime: ClassVar[dict[str, tuple[bool, int]]] = {}

    def do_POST(self) -> None:
        name = self.path.removeprefix("/v3/config/paths/replace/")
        payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.paths[name] = {
            "name": name,
            "source": payload["source"],
            "sourceOnDemand": payload["sourceOnDemand"],
            "sourceOnDemandCloseAfter": payload["sourceOnDemandCloseAfter"],
        }
        self._respond(200, {"status": "ok"})

    def do_GET(self) -> None:
        if self.path.startswith("/v3/paths/get/"):
            name = self.path.removeprefix("/v3/paths/get/")
            runtime = self.runtime.get(name)
            if runtime is None:
                self._respond(404, {"error": "not found"})
            else:
                self._respond(
                    200,
                    {
                        "name": name,
                        "ready": runtime[0],
                        "readers": [{} for _ in range(runtime[1])],
                    },
                )
            return
        name = self.path.removeprefix("/v3/config/paths/get/")
        payload = self.paths.get(name)
        if payload is None:
            self._respond(404, {"error": "not found"})
        else:
            self._respond(200, payload)

    def log_message(self, format: str, *args: object) -> None:
        return

    def _respond(self, status: int, payload: dict[str, object]) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class StableProcess:
    def __init__(self, snapshot: NodeProcessSnapshot) -> None:
        self.snapshot = snapshot

    def execute(
        self,
        action: NodeRuntimeAction,
        spec: NodeRuntimeSpec,
        deadline: object | None = None,
    ) -> NodeProcessSnapshot:
        assert action is NodeRuntimeAction.OBSERVE
        return self.snapshot


class UnusedSmoke:
    def check(self, *args: object, **kwargs: object) -> None:
        pytest.fail("lifecycle smoke must not run for a media path command")


def test_node_media_command_converges_through_the_privileged_helper(
    tmp_path: Path,
) -> None:
    MediaApiHandler.paths = {}
    MediaApiHandler.runtime = {str(PUBLIC_ID): (True, 1)}
    media_api = ThreadingHTTPServer(("127.0.0.1", 0), MediaApiHandler)
    api_thread = Thread(target=media_api.serve_forever)
    api_thread.start()
    node = replace(ready_node(), api_port=int(media_api.server_address[1]))
    spec = NodeRuntimeSpec(
        node_id=node.id,
        external_port=node.external_port,
        api_port=node.api_port,
        metrics_port=node.metrics_port,
        desired_revision=node.desired_revision,
        release_id=node.release_id,
        mediamtx_binary_sha256=node.mediamtx_binary_sha256,
    )
    config_root = tmp_path / "nodes"
    config_root.mkdir(mode=0o700)
    config_store = SecureNodeConfigStore(root=config_root)
    credentials = NodeManagementCredentials(
        username=f"node-{node.id}",
        password="management-password-00000000000000000001",
    )
    rendered = MediaNodeConfigRenderer().render(spec, credentials)
    config_store.install(spec, rendered, credentials=credentials)
    snapshot = NodeProcessSnapshot(
        active=True,
        pid=123,
        process_start_ticks=456,
        boot_id=node.process_boot_id,
        executable_sha256=node.mediamtx_binary_sha256,
    )
    process = StableProcess(snapshot)
    server = UnixNodeSupervisorServer(
        supervisor=LinuxNodeSupervisor(
            config_store=config_store,
            process=process,
            smoke=UnusedSmoke(),
            port_is_bindable=lambda port: False,
        ),
        policy=NodeRuntimePolicy(
            external_port_start=node.external_port,
            external_port_end=node.external_port,
            api_port_start=node.api_port,
            api_port_end=node.api_port,
            metrics_port_start=node.metrics_port,
            metrics_port_end=node.metrics_port,
            release_id=node.release_id,
            mediamtx_binary_sha256=node.mediamtx_binary_sha256,
        ),
        media=RootMediaNodeAdapter(
            config_store=config_store,
            process=process,
            timeout_seconds=1,
        ),
    )
    socket_path = Path("/tmp") / f"rtsp-media-{uuid4().hex}.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    listener.listen(3)

    def serve_two() -> None:
        try:
            for _ in range(3):
                connection, _ = listener.accept()
                with connection:
                    server.serve_connection(connection)
        finally:
            listener.close()

    helper_thread = Thread(target=serve_two)
    helper_thread.start()
    client = UnixMediaNodeClientFactory(
        socket_path=socket_path,
        timeout_seconds=1,
    ).for_node(node)
    path = MediaPathConfig(
        name=PUBLIC_ID,
        source_url="rtsp://camera.invalid/main",
    )
    try:
        client.put_path(path)
        assert client.get_path(PUBLIC_ID) == path
        assert client.path_runtime_status(PUBLIC_ID) == (True, 1)
    finally:
        helper_thread.join(timeout=2)
        socket_path.unlink(missing_ok=True)
        media_api.shutdown()
        media_api.server_close()
        api_thread.join(timeout=2)
