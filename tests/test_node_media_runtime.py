from __future__ import annotations

import json
import socket
import time
from dataclasses import replace
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import ClassVar
from uuid import UUID, uuid4

import pytest

from rtsp_proxy.identifiers import PublicId
from rtsp_proxy.media import (
    MediaNodeProtocolError,
    MediaNodeUnavailable,
    MediaPathConfig,
    MediaPathInventory,
)
from rtsp_proxy.node_runtime import (
    LinuxNodeSupervisor,
    MediaNodeConfigRenderer,
    MediaPathCommand,
    MediaPathOperation,
    NodeManagementCredentials,
    NodeOperationDeadline,
    NodeProcessSnapshot,
    NodeRuntimePolicy,
    NodeRuntimeSpec,
    RootMediaNodeAdapter,
    SecureNodeConfigStore,
    UnixMediaNodeClient,
    UnixMediaNodeClientFactory,
    UnixNodeDisruptionObserver,
    UnixNodeSupervisorServer,
)
from rtsp_proxy.nodes import MediaNode, NodeHealth, NodeRuntimeAction, NodeState
from rtsp_proxy.observability import NodeMetricObservation, NodeMetricSample, PathMetricCounters

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


def test_node_aware_media_client_uses_only_the_selected_node_identity() -> None:
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
                "max_readers": 1,
            },
            "inventory": None,
            "error": None,
        },
        captured,
    )

    actual = (
        UnixMediaNodeClientFactory(
            socket_path=socket_path,
            timeout_seconds=1,
        )
        .for_node(ready_node())
        .get_path(PUBLIC_ID)
    )

    server.join(timeout=2)
    socket_path.unlink(missing_ok=True)
    assert actual == MediaPathConfig(
        name=PUBLIC_ID,
        source_url="rtsp://camera.invalid/main",
    )
    deadline_unix_ms = captured.pop("deadline_unix_ms")
    assert isinstance(deadline_unix_ms, int)
    assert deadline_unix_ms > int(time.time() * 1000)
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
        "path": {"name": str(PUBLIC_ID), "source_url": None, "max_readers": None},
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


def test_node_metrics_round_trip_binds_generation_and_path_counters() -> None:
    socket_path = Path("/tmp") / f"rtsp-media-{uuid4().hex}.sock"
    server = unix_answer(
        socket_path,
        {
            "schema_version": 1,
            "ok": True,
            "path": None,
            "inventory": None,
            "runtime": None,
            "metrics": {
                "active_sources": 1,
                "occupied_streams": 1,
                "received_bytes_total": 100,
                "sent_bytes_total": 200,
                "path_counters": [
                    {
                        "public_id": str(PUBLIC_ID),
                        "received_bytes_total": 100,
                        "sent_bytes_total": 200,
                        "ready": True,
                    }
                ],
                "occupied_public_ids": [str(PUBLIC_ID)],
                "process_id": 123,
                "process_start_ticks": 456,
                "process_boot_id": str(ready_node().process_boot_id),
                "release_id": "v1.20.0",
            },
            "error": None,
        },
        {},
    )

    actual = (
        UnixMediaNodeClientFactory(
            socket_path=socket_path,
            timeout_seconds=1,
        )
        .for_node(ready_node())
        .node_metrics()
    )

    server.join(timeout=1)
    socket_path.unlink(missing_ok=True)
    assert actual == NodeMetricObservation(
        sample=NodeMetricSample(
            1,
            1,
            100,
            200,
            path_counters=(
                PathMetricCounters(str(PUBLIC_ID), 100, 200, ready=True),
            ),
            occupied_public_ids=(str(PUBLIC_ID),),
        ),
        process_id=123,
        process_start_ticks=456,
        process_boot_id=ready_node().process_boot_id,  # type: ignore[arg-type]
        release_id="v1.20.0",
    )


def test_node_disruption_observer_returns_exact_process_bound_reader_set() -> None:
    socket_path = Path("/tmp") / f"rtsp-media-{uuid4().hex}.sock"
    server = unix_answer(
        socket_path,
        {
            "schema_version": 1,
            "ok": True,
            "path": None,
            "inventory": None,
            "runtime": None,
            "metrics": {
                "active_sources": 1,
                "occupied_streams": 1,
                "received_bytes_total": 100,
                "sent_bytes_total": 200,
                "path_counters": [
                    {
                        "public_id": str(PUBLIC_ID),
                        "received_bytes_total": 100,
                        "sent_bytes_total": 200,
                    }
                ],
                "occupied_public_ids": [str(PUBLIC_ID)],
                "process_id": 123,
                "process_start_ticks": 456,
                "process_boot_id": str(ready_node().process_boot_id),
                "release_id": "v1.20.0",
            },
            "error": None,
        },
        {},
    )
    observed_at = datetime(2026, 8, 24, 12, 0, tzinfo=UTC)
    observer = UnixNodeDisruptionObserver(
        media_nodes=UnixMediaNodeClientFactory(
            socket_path=socket_path,
            timeout_seconds=1,
        ),
        clock=lambda: observed_at,
    )

    observation = observer.observe(ready_node())

    server.join(timeout=1)
    socket_path.unlink(missing_ok=True)
    assert observation.active_reader_public_ids == (PUBLIC_ID,)
    assert observation.observed_at == observed_at
    assert observation.process_id == 123
    assert observation.process_start_ticks == 456
    assert observation.process_boot_id == ready_node().process_boot_id
    assert observation.release_id == "v1.20.0"


def test_node_disruption_fence_closes_paths_before_snapshot_and_restores_on_abort() -> None:
    node = ready_node()

    class MemoryMediaClient:
        def __init__(self) -> None:
            self.path = MediaPathConfig(
                name=PUBLIC_ID,
                source_url="rtsp://camera.invalid/main",
            )
            self.reader_attempts: list[str] = []

        def get_path(self, name: PublicId) -> MediaPathConfig | None:
            return self.path if name == self.path.name else None

        def put_path(self, path: MediaPathConfig) -> None:
            self.path = path

        def node_metrics(self) -> NodeMetricObservation:
            self.reader_attempts.append("denied" if self.path.max_readers == -1 else "admitted")
            return NodeMetricObservation(
                sample=NodeMetricSample(
                    active_sources=1,
                    occupied_streams=1,
                    received_bytes_total=100,
                    sent_bytes_total=200,
                    path_counters=(PathMetricCounters(str(PUBLIC_ID), 100, 200),),
                    occupied_public_ids=(str(PUBLIC_ID),),
                ),
                process_id=123,
                process_start_ticks=456,
                process_boot_id=node.process_boot_id,  # type: ignore[arg-type]
                release_id=node.release_id,
            )

    class MemoryMediaFactory:
        def __init__(self, client: MemoryMediaClient) -> None:
            self.client = client
            self.deadlines: list[int] = []

        def for_node(self, selected: MediaNode) -> MemoryMediaClient:
            assert selected == node
            return self.client

        def for_node_until(
            self,
            selected: MediaNode,
            *,
            deadline_unix_ms: int,
        ) -> MemoryMediaClient:
            self.deadlines.append(deadline_unix_ms)
            return self.for_node(selected)

    client = MemoryMediaClient()
    factory = MemoryMediaFactory(client)
    observer = UnixNodeDisruptionObserver(
        media_nodes=factory,  # type: ignore[arg-type]
        wall_time=lambda: 1_000.0,
    )

    with (
        pytest.raises(RuntimeError, match="abort"),
        observer.fence(node, (PUBLIC_ID,)) as lease,
    ):
        assert lease.observation.active_reader_public_ids == (PUBLIC_ID,)
        assert lease.work_deadline_unix_ms == 1_050_000
        assert client.path.max_readers == -1
        raise RuntimeError("abort")

    assert client.reader_attempts == ["denied"]
    assert client.path.max_readers == 1
    assert factory.deadlines == [1_050_000, 1_060_000]


def test_node_disruption_fence_accepts_registered_camera_without_runtime_path() -> None:
    node = ready_node()

    class MissingPathClient:
        def get_path(self, _name: PublicId) -> None:
            return None

        def put_path(self, _path: MediaPathConfig) -> None:
            raise AssertionError("an absent disabled path must not be created")

        def node_metrics(self) -> NodeMetricObservation:
            return NodeMetricObservation(
                sample=NodeMetricSample(0, 0, 0, 0, occupied_public_ids=()),
                process_id=123,
                process_start_ticks=456,
                process_boot_id=node.process_boot_id,  # type: ignore[arg-type]
                release_id=node.release_id,
            )

    class MissingPathFactory:
        def __init__(self) -> None:
            self.client = MissingPathClient()

        def for_node_until(
            self,
            selected: MediaNode,
            *,
            deadline_unix_ms: int,
        ) -> MissingPathClient:
            assert selected == node
            assert deadline_unix_ms > int(time.time() * 1000)
            return self.client

    observer = UnixNodeDisruptionObserver(
        media_nodes=MissingPathFactory(),  # type: ignore[arg-type]
    )

    with observer.fence(node, (PUBLIC_ID,)) as lease:
        assert lease.observation.active_reader_public_ids == ()
        lease.complete()


def test_node_disruption_fence_restores_ambiguous_committed_put() -> None:
    node = ready_node()

    class AmbiguousPutClient:
        def __init__(self) -> None:
            self.path = MediaPathConfig(
                name=PUBLIC_ID,
                source_url="rtsp://camera.invalid/main",
            )
            self.fail_fence_once = True

        def get_path(self, _name: PublicId) -> MediaPathConfig:
            return self.path

        def put_path(self, path: MediaPathConfig) -> None:
            self.path = path
            if path.max_readers == -1 and self.fail_fence_once:
                self.fail_fence_once = False
                raise MediaNodeUnavailable("node_media_deadline_exceeded")

        def node_metrics(self) -> NodeMetricObservation:
            raise AssertionError("metrics must not run after an ambiguous fence PUT")

    class AmbiguousPutFactory:
        def __init__(self) -> None:
            self.client = AmbiguousPutClient()
            self.deadlines: list[int] = []

        def for_node_until(
            self,
            selected: MediaNode,
            *,
            deadline_unix_ms: int,
        ) -> AmbiguousPutClient:
            assert selected == node
            assert deadline_unix_ms > int(time.time() * 1000)
            self.deadlines.append(deadline_unix_ms)
            return self.client

    factory = AmbiguousPutFactory()
    observer = UnixNodeDisruptionObserver(
        media_nodes=factory,  # type: ignore[arg-type]
    )

    with (
        pytest.raises(MediaNodeUnavailable, match="node_media_deadline_exceeded"),
        observer.fence(node, (PUBLIC_ID,)),
    ):
        raise AssertionError("unreachable")

    assert factory.client.path.max_readers == 1
    assert len(factory.deadlines) == 2
    assert factory.deadlines[1] > factory.deadlines[0]


def test_node_media_shared_deadline_expires_before_any_new_helper_io(tmp_path: Path) -> None:
    client = UnixMediaNodeClient(
        socket_path=tmp_path / "must-not-be-opened.sock",
        timeout_seconds=10,
        node=ready_node(),
        deadline_unix_ms=int(time.time() * 1000) - 1,
    )

    with pytest.raises(MediaNodeUnavailable, match="node_media_deadline_exceeded"):
        client.get_path(PUBLIC_ID)


def test_node_media_shared_deadline_is_bound_to_the_helper_request() -> None:
    socket_path = Path("/tmp") / f"rtsp-media-{uuid4().hex}.sock"
    captured: dict[str, object] = {}
    server = unix_answer(
        socket_path,
        {
            "schema_version": 1,
            "ok": True,
            "path": None,
            "inventory": None,
            "runtime": None,
            "metrics": None,
            "error": None,
        },
        captured,
    )
    deadline_unix_ms = int((time.time() + 10) * 1000)
    client = UnixMediaNodeClient(
        socket_path=socket_path,
        timeout_seconds=10,
        node=ready_node(),
        deadline_unix_ms=deadline_unix_ms,
    )

    assert client.get_path(PUBLIC_ID) is None

    server.join(timeout=2)
    socket_path.unlink(missing_ok=True)
    assert captured["deadline_unix_ms"] == deadline_unix_ms


def test_hundred_path_fence_stops_at_one_shared_deadline() -> None:
    node = ready_node()
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    public_ids = tuple(
        sorted(
            (
                PublicId.parse("a" * 23 + alphabet[index // 32] + alphabet[index % 32] + "a")
                for index in range(100)
            ),
            key=str,
        )
    )

    class DeadlineClient:
        calls = 0

        def get_path(self, _name: PublicId) -> None:
            self.calls += 1
            if self.calls == 5:
                raise MediaNodeUnavailable("node_media_deadline_exceeded")
            return None

        def put_path(self, _path: MediaPathConfig) -> None:
            raise AssertionError("absent paths must not be mutated")

        def node_metrics(self) -> NodeMetricObservation:
            raise AssertionError("metrics must not run after deadline")

    class DeadlineFactory:
        def __init__(self) -> None:
            self.client = DeadlineClient()
            self.deadlines: list[int] = []

        def for_node_until(
            self,
            selected: MediaNode,
            *,
            deadline_unix_ms: int,
        ) -> DeadlineClient:
            assert selected == node
            self.deadlines.append(deadline_unix_ms)
            return self.client

    factory = DeadlineFactory()
    observer = UnixNodeDisruptionObserver(
        media_nodes=factory,  # type: ignore[arg-type]
        wall_time=lambda: 1_000.0,
        fence_timeout_seconds=1,
    )

    with (
        pytest.raises(MediaNodeUnavailable, match="node_media_deadline_exceeded"),
        observer.fence(node, public_ids),
    ):
        raise AssertionError("unreachable")

    assert len(factory.deadlines) == 1
    assert 1_000_000 < factory.deadlines[0] < 1_001_000
    assert factory.client.calls == 5


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


@pytest.mark.parametrize(
    ("response", "operation", "error"),
    (
        (
            {
                "schema_version": 1,
                "ok": True,
                "path": {
                    "name": str(PUBLIC_ID),
                    "source_url": "x",
                    "max_readers": 1,
                },
                "inventory": None,
                "runtime": None,
                "error": None,
            },
            "put",
            "node_media_response_invalid",
        ),
        (
            {
                "schema_version": 1,
                "ok": True,
                "path": None,
                "inventory": {"camera_ids": [str(PUBLIC_ID)], "no_oracle_matcher_present": True},
                "runtime": None,
                "error": None,
            },
            "get",
            "node_media_response_invalid",
        ),
        (
            {
                "schema_version": 1,
                "ok": True,
                "path": {
                    "name": str(PUBLIC_ID),
                    "source_url": None,
                    "max_readers": None,
                },
                "inventory": None,
                "runtime": None,
                "error": None,
            },
            "get",
            "node_media_response_invalid",
        ),
        (
            {
                "schema_version": 1,
                "ok": True,
                "path": None,
                "inventory": {
                    "camera_ids": [str(PUBLIC_ID), str(PUBLIC_ID)],
                    "no_oracle_matcher_present": True,
                },
                "runtime": None,
                "error": None,
            },
            "inventory",
            "node_media_response_invalid",
        ),
        (
            {
                "schema_version": 1,
                "ok": True,
                "path": None,
                "inventory": None,
                "runtime": {"ready": True, "reader_count": 1},
                "error": None,
            },
            "delete",
            "node_media_response_invalid",
        ),
        (
            {
                "schema_version": 1,
                "ok": True,
                "path": {
                    "name": str(PUBLIC_ID),
                    "source_url": "x",
                    "max_readers": 1,
                },
                "inventory": None,
                "runtime": None,
                "error": None,
            },
            "runtime",
            "node_media_response_invalid",
        ),
    ),
)
def test_node_media_client_rejects_cross_operation_payloads(
    tmp_path: Path,
    response: dict[str, object],
    operation: str,
    error: str,
) -> None:
    socket_path = Path("/tmp") / f"rtsp-media-{uuid4().hex}.sock"
    server = unix_answer(socket_path, response, {})
    client = UnixMediaNodeClientFactory(socket_path=socket_path, timeout_seconds=1).for_node(
        ready_node()
    )

    with pytest.raises(MediaNodeProtocolError, match=error):
        if operation == "put":
            client.put_path(MediaPathConfig(name=PUBLIC_ID, source_url="rtsp://x.invalid/main"))
        elif operation == "get":
            client.get_path(PUBLIC_ID)
        elif operation == "inventory":
            client.inventory_paths()
        elif operation == "delete":
            client.delete_path(PUBLIC_ID)
        else:
            client.path_runtime_status(PUBLIC_ID)
    server.join(timeout=1)
    socket_path.unlink(missing_ok=True)


def test_node_media_client_covers_inventory_delete_runtime_and_transport_failures(
    tmp_path: Path,
) -> None:
    responses: tuple[tuple[str, dict[str, object]], ...] = (
        (
            "inventory",
            {
                "schema_version": 1,
                "ok": True,
                "path": None,
                "inventory": {"camera_ids": [str(PUBLIC_ID)], "no_oracle_matcher_present": True},
                "runtime": None,
                "error": None,
            },
        ),
        (
            "delete",
            {
                "schema_version": 1,
                "ok": True,
                "path": None,
                "inventory": None,
                "runtime": None,
                "error": None,
            },
        ),
        (
            "runtime-missing",
            {
                "schema_version": 1,
                "ok": True,
                "path": None,
                "inventory": None,
                "runtime": None,
                "error": None,
            },
        ),
    )
    for operation, response in responses:
        socket_path = Path("/tmp") / f"rtsp-media-{uuid4().hex}.sock"
        server = unix_answer(socket_path, response, {})
        client = UnixMediaNodeClientFactory(
            socket_path=socket_path,
            timeout_seconds=1,
        ).for_node(ready_node())
        if operation == "inventory":
            assert client.inventory_paths().camera_ids == (PUBLIC_ID,)
        elif operation == "delete":
            client.delete_path(PUBLIC_ID)
        else:
            assert client.path_runtime_status(PUBLIC_ID) is None
        server.join(timeout=1)
        socket_path.unlink(missing_ok=True)

    with pytest.raises(MediaNodeUnavailable, match="node_media_unavailable"):
        UnixMediaNodeClientFactory(
            socket_path=tmp_path / "missing.sock",
            timeout_seconds=1,
        ).for_node(ready_node()).get_path(PUBLIC_ID)


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
            "maxReaders": payload["maxReaders"],
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


def test_root_media_adapter_validates_config_process_and_every_operation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "nodes"
    root.mkdir(mode=0o700)
    store = SecureNodeConfigStore(root=root)
    spec = NodeRuntimeSpec(
        node_id=NODE_ID,
        external_port=12000,
        api_port=13000,
        metrics_port=14000,
        desired_revision=3,
        release_id="v1.20.0",
        mediamtx_binary_sha256="a" * 64,
    )
    with pytest.raises(ValueError, match="node_media_timeout_invalid"):
        RootMediaNodeAdapter(
            config_store=store,
            process=StableProcess(
                NodeProcessSnapshot(
                    active=False,
                    pid=None,
                    process_start_ticks=None,
                    boot_id=None,
                    executable_sha256=None,
                )
            ),
            timeout_seconds=0,
        )
    adapter = RootMediaNodeAdapter(
        config_store=store,
        process=StableProcess(
            NodeProcessSnapshot(
                active=False,
                pid=None,
                process_start_ticks=None,
                boot_id=None,
                executable_sha256=None,
            )
        ),
        timeout_seconds=1,
    )
    with pytest.raises(Exception, match="node_config_not_applied"):
        adapter.execute(MediaPathCommand(operation=MediaPathOperation.INVENTORY, spec=spec))

    credentials = NodeManagementCredentials(
        username=f"node-{NODE_ID}",
        password="management-password-00000000000000000001",
    )
    store.install(
        spec,
        MediaNodeConfigRenderer().render(spec, credentials),
        credentials=credentials,
    )
    with pytest.raises(Exception, match="node_process_release_mismatch"):
        adapter.execute(MediaPathCommand(operation=MediaPathOperation.INVENTORY, spec=spec))

    snapshot = NodeProcessSnapshot(
        active=True,
        pid=123,
        process_start_ticks=456,
        boot_id=UUID("10000000-0000-0000-0000-000000000001"),
        executable_sha256="a" * 64,
    )
    stable = RootMediaNodeAdapter(
        config_store=store,
        process=StableProcess(snapshot),
        timeout_seconds=1,
    )

    class FakeClient:
        def inventory_paths(self) -> MediaPathInventory:
            return MediaPathInventory(
                camera_ids=(PUBLIC_ID,),
                no_oracle_matcher_present=True,
            )

        def put_path(self, path: MediaPathConfig) -> None:
            assert path.name == PUBLIC_ID

        def get_path(self, name: PublicId) -> MediaPathConfig:
            return MediaPathConfig(name=name, source_url="rtsp://x.invalid/main")

        def path_runtime_status(self, name: PublicId) -> tuple[bool, int]:
            return (True, 1)

        def delete_path(self, name: PublicId) -> None:
            assert name == PUBLIC_ID

    fake = FakeClient()
    assert stable._execute_operation(
        fake,  # type: ignore[arg-type]
        MediaPathCommand(operation=MediaPathOperation.INVENTORY, spec=spec),
    ) == MediaPathInventory(camera_ids=(PUBLIC_ID,), no_oracle_matcher_present=True)
    stable._execute_operation(
        fake,  # type: ignore[arg-type]
        MediaPathCommand(
            operation=MediaPathOperation.PUT,
            spec=spec,
            path=MediaPathConfig(name=PUBLIC_ID, source_url="rtsp://x.invalid/main"),
        ),
    )
    assert stable._execute_operation(
        fake,  # type: ignore[arg-type]
        MediaPathCommand(operation=MediaPathOperation.GET, spec=spec, path=PUBLIC_ID),
    ) == MediaPathConfig(name=PUBLIC_ID, source_url="rtsp://x.invalid/main")
    assert stable._execute_operation(
        fake,  # type: ignore[arg-type]
        MediaPathCommand(operation=MediaPathOperation.RUNTIME, spec=spec, path=PUBLIC_ID),
    ) == (True, 1)
    stable._execute_operation(
        fake,  # type: ignore[arg-type]
        MediaPathCommand(operation=MediaPathOperation.DELETE, spec=spec, path=PUBLIC_ID),
    )


def test_media_request_deadline_expires_while_waiting_for_node_lock(
    tmp_path: Path,
) -> None:
    node = ready_node()
    config_root = tmp_path / "nodes"
    config_root.mkdir(mode=0o700)
    store = SecureNodeConfigStore(root=config_root)
    snapshot = NodeProcessSnapshot(
        active=True,
        pid=123,
        process_start_ticks=456,
        boot_id=node.process_boot_id,
        executable_sha256=node.mediamtx_binary_sha256,
    )
    server = UnixNodeSupervisorServer(
        supervisor=LinuxNodeSupervisor(
            config_store=store,
            process=StableProcess(snapshot),
            smoke=UnusedSmoke(),
            port_is_bindable=lambda _port: False,
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
        media=object(),  # type: ignore[arg-type]
        operation_timeout_seconds=21,
        cleanup_reserve_seconds=20,
    )
    held = server._node_lock(
        node.id,
        NodeOperationDeadline(expires_monotonic=time.monotonic() + 1),
    )
    request = {
        "schema_version": 1,
        "request_type": "media_path",
        "operation": "get",
        "spec": {
            "node_id": str(node.id),
            "external_port": node.external_port,
            "api_port": node.api_port,
            "metrics_port": node.metrics_port,
            "desired_revision": node.desired_revision,
            "release_id": node.release_id,
            "mediamtx_binary_sha256": node.mediamtx_binary_sha256,
        },
        "path": {
            "name": str(PUBLIC_ID),
            "source_url": None,
            "max_readers": None,
        },
        "deadline_unix_ms": int(time.time() * 1000) + 20,
    }
    with held:
        result = server._serve_media_request(
            (json.dumps(request, separators=(",", ":")) + "\n").encode()
        )

    assert result == {
        "schema_version": 1,
        "ok": False,
        "path": None,
        "inventory": None,
        "runtime": None,
        "error": "node_runtime_operation_timeout",
    }


def test_read_only_helper_rejects_media_path_mutation_before_adapter_call(
    tmp_path: Path,
) -> None:
    node = ready_node()
    config_root = tmp_path / "nodes-read-only-media"
    config_root.mkdir(mode=0o700)
    server = UnixNodeSupervisorServer(
        supervisor=LinuxNodeSupervisor(
            config_store=SecureNodeConfigStore(root=config_root),
            process=StableProcess(
                NodeProcessSnapshot(
                    active=False,
                    pid=None,
                    process_start_ticks=None,
                    boot_id=None,
                    executable_sha256=None,
                )
            ),
            smoke=UnusedSmoke(),
            port_is_bindable=lambda _port: True,
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
        media=object(),  # type: ignore[arg-type]
        read_only=True,
    )
    request = {
        "schema_version": 1,
        "request_type": "media_path",
        "operation": "delete",
        "spec": {
            "node_id": str(node.id),
            "external_port": node.external_port,
            "api_port": node.api_port,
            "metrics_port": node.metrics_port,
            "desired_revision": node.desired_revision,
            "release_id": node.release_id,
            "mediamtx_binary_sha256": node.mediamtx_binary_sha256,
        },
        "path": {"name": str(PUBLIC_ID), "source_url": None, "max_readers": None},
        "deadline_unix_ms": int(time.time() * 1000) + 1000,
    }

    result = server._serve_media_request(
        (json.dumps(request, separators=(",", ":")) + "\n").encode()
    )

    assert result["error"] == "node_helper_read_only"
