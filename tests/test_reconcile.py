from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from rtsp_proxy.database import PostgresNodeStore
from rtsp_proxy.identifiers import PublicId
from rtsp_proxy.media import (
    MediaNodeProtocolError,
    MediaNodeUnavailable,
    MediaPathConfig,
    MediaPathInventory,
)
from rtsp_proxy.migrate import upgrade_database
from rtsp_proxy.nodes import (
    CameraControl,
    CameraLifecycleConflict,
    CameraMove,
    CameraMoveExpired,
    CameraMoveState,
    CameraMoveStore,
    CameraNotFound,
    CameraPlacement,
    CameraState,
    InMemoryNodeStore,
    MediaNode,
    NodeHealth,
    NodeLifecycleBusy,
    NodeLifecycleConflict,
    NodeRuntimeObservation,
    NodeState,
)
from rtsp_proxy.reconcile import (
    CameraDisruptionConfirmationRequired,
    CameraMoveControl,
    CameraMoveReconciler,
    CameraMutationControl,
    CameraMutationOperation,
    CameraOccupied,
    CameraReconciler,
    CameraRuntimeObserver,
    ConfirmationTokenService,
    MediaNodeClient,
    MediaNodeClientFactory,
    MoveConfirmationRequired,
    ReconcileCancelled,
    ReconcileCoordinator,
    ReconcileRetry,
)

NODE_A = UUID("00000000-0000-0000-0000-000000000001")
NODE_B = UUID("00000000-0000-0000-0000-000000000002")
CAMERA_A = UUID("10000000-0000-0000-0000-000000000001")
PUBLIC_A = PublicId.parse("a" * 26)


class RecordingMediaNode(MediaNodeClient):
    def __init__(self) -> None:
        self.paths: dict[PublicId, MediaPathConfig] = {}
        self.puts: list[MediaPathConfig] = []
        self.deletes: list[PublicId] = []
        self.fail_put_after_apply = False
        self.runtime: dict[PublicId, tuple[bool, int] | None] = {}
        self.no_oracle_matcher_present = True

    def put_path(self, path: MediaPathConfig) -> None:
        self.paths[path.name] = path
        self.puts.append(path)
        if self.fail_put_after_apply:
            self.fail_put_after_apply = False
            raise MediaNodeUnavailable("mediamtx_unavailable")

    def get_path(self, name: PublicId) -> MediaPathConfig | None:
        return self.paths.get(name)

    def inventory_paths(self) -> MediaPathInventory:
        return MediaPathInventory(
            camera_ids=tuple(sorted(self.paths, key=str)),
            no_oracle_matcher_present=self.no_oracle_matcher_present,
        )

    def delete_path(self, name: PublicId) -> None:
        self.paths.pop(name, None)
        self.deletes.append(name)

    def path_runtime_status(self, name: PublicId) -> tuple[bool, int] | None:
        return self.runtime.get(name)


class RecordingMediaNodeFactory(MediaNodeClientFactory):
    def __init__(self) -> None:
        self.clients = {
            NODE_A: RecordingMediaNode(),
            NODE_B: RecordingMediaNode(),
        }
        self.requested: list[UUID] = []

    def for_node(self, node: MediaNode) -> MediaNodeClient:
        self.requested.append(node.id)
        return self.clients[node.id]


def running_node(node_id: UUID, port: int) -> MediaNode:
    now = datetime.now(UTC)
    return MediaNode(
        id=node_id,
        name=f"node-{node_id.int}",
        external_port=port,
        api_port=port + 1000,
        metrics_port=port + 2000,
        state=NodeState.RUNNING,
        runtime_state=NodeState.RUNNING,
        health=NodeHealth.HEALTHY,
        management_fresh=True,
        management_observed_at=now,
        runtime_observed_at=now,
        config_compatible=True,
        desired_revision=1,
        applied_revision=1,
        process_id=100 + node_id.int,
        process_start_ticks=1000 + node_id.int,
        process_boot_id=UUID("20000000-0000-0000-0000-000000000001"),
        observed_config_sha256="0" * 64,
        observed_release_id="0.1.0",
    )


def camera_store(
    *,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> InMemoryNodeStore:
    store = InMemoryNodeStore(
        nodes=(running_node(NODE_A, 12000), running_node(NODE_B, 12001)),
        clock=clock,
    )
    CameraControl(
        store=store,
        new_camera_id=lambda: CAMERA_A,
        new_public_id=lambda: str(PUBLIC_A),
    ).create_camera(
        name="entrance",
        source_url="rtsp://camera.invalid/main",
        node_id=NODE_A,
    )
    return store


def test_camera_move_contract_rejects_ambiguous_persisted_safety_fields() -> None:
    now = datetime.now(UTC)
    fields: dict[str, object] = {
        "id": UUID("30000000-0000-0000-0000-000000000001"),
        "camera_id": CAMERA_A,
        "public_id": PUBLIC_A,
        "source_url": "rtsp://camera.invalid/main",
        "source_node_id": NODE_A,
        "target_node_id": NODE_B,
        "source_generation": 1,
        "target_generation": 2,
        "desired_revision": 2,
        "force": False,
        "confirmed_disconnect_readers": 0,
        "source_port": 12000,
        "target_port": 12001,
        "source_endpoint": f"rtsp://server:12000/{PUBLIC_A}",
        "target_endpoint": f"rtsp://server:12001/{PUBLIC_A}",
        "expires_at": now + timedelta(minutes=5),
    }

    for override, reason in (
        ({"confirmed_disconnect_readers": 2}, "camera_move_confirmed_readers_invalid"),
        ({"expires_at": datetime.now()}, "camera_move_expiry_timezone_required"),
        ({"source_port": 0}, "camera_move_port_invalid"),
        ({"source_endpoint": None}, "camera_move_endpoint_invalid"),
        (
            {
                "source_port": None,
                "target_port": None,
                "source_endpoint": None,
                "target_endpoint": None,
            },
            "camera_move_endpoint_invalid",
        ),
    ):
        with pytest.raises(ValueError, match=reason):
            CameraMove(**(fields | override))  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="media_path_reader_limit_invalid"):
        MediaPathConfig(name=PUBLIC_A, source_url="rtsp://camera.invalid/main", max_readers=0)


def test_reconcile_applies_only_the_selected_node_and_then_becomes_noop() -> None:
    store = camera_store()
    factory = RecordingMediaNodeFactory()
    reconciler = CameraReconciler(store=store, media_nodes=factory)

    first = reconciler.reconcile_node(NODE_A)
    second = reconciler.reconcile_node(NODE_A)

    assert first.applied == 1
    assert first.unchanged == 0
    assert second.applied == 0
    assert second.unchanged == 1
    assert factory.requested == [NODE_A, NODE_A]
    assert factory.clients[NODE_A].paths == {
        PUBLIC_A: MediaPathConfig(
            name=PUBLIC_A,
            source_url="rtsp://camera.invalid/main",
        )
    }
    assert factory.clients[NODE_B].paths == {}
    assert store.list_cameras()[0].applied_revision == 1


def test_reconcile_reads_back_an_unknown_write_result_before_retrying() -> None:
    store = camera_store()
    factory = RecordingMediaNodeFactory()
    factory.clients[NODE_A].fail_put_after_apply = True

    report = CameraReconciler(store=store, media_nodes=factory).reconcile_node(NODE_A)

    assert report.applied == 1
    assert store.list_cameras()[0].applied_revision == 1


def test_reconcile_fails_closed_when_read_back_does_not_match() -> None:
    store = camera_store()
    factory = RecordingMediaNodeFactory()
    client = factory.clients[NODE_A]

    def unavailable_without_apply(path: MediaPathConfig) -> None:
        raise MediaNodeUnavailable("mediamtx_unavailable")

    client.put_path = unavailable_without_apply  # type: ignore[method-assign]

    with pytest.raises(ReconcileRetry, match="camera_reconcile_unverified"):
        CameraReconciler(store=store, media_nodes=factory).reconcile_node(NODE_A)

    assert store.list_cameras()[0].applied_revision == 0


def test_stale_reconcile_cannot_mark_a_newer_desired_revision_applied() -> None:
    store = camera_store()
    current = store.list_cameras()[0]
    store.update_camera(
        CAMERA_A,
        name="entrance-renamed",
        source_url=current.source_url,
    )

    assert (
        store.mark_camera_applied(
            camera_id=CAMERA_A,
            node_id=NODE_A,
            placement_generation=1,
            desired_revision=1,
        )
        is False
    )
    assert store.list_cameras()[0].applied_revision == 0


def test_postgresql_reconcile_fences_and_persists_the_applied_revision(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresNodeStore(postgres_database_url)
    node = store.register_automatically(
        name="media-a",
        allowed_ports=(12000,),
        max_nodes=1,
        preferred_port=12000,
        choose_port=lambda available: available[0],
        new_node_id=lambda: NODE_A,
        api_ports=(13000,),
        metrics_ports=(14000,),
        mediamtx_binary_sha256="a" * 64,
    )
    node = store.request_desired_state(node.id, NodeState.RUNNING)
    store.apply_runtime_observation(
        node.id,
        NodeRuntimeObservation(
            state=NodeState.RUNNING,
            health=NodeHealth.HEALTHY,
            management_fresh=True,
            config_compatible=True,
            applied_revision=node.desired_revision,
            process_id=123,
            process_start_ticks=456,
            process_boot_id=UUID("20000000-0000-0000-0000-000000000001"),
            config_sha256="b" * 64,
            release_id="0.1.0",
        ),
    )
    CameraControl(
        store=store,
        new_camera_id=lambda: CAMERA_A,
        new_public_id=lambda: str(PUBLIC_A),
    ).create_camera(
        name="entrance",
        source_url="rtsp://camera.invalid/main",
        node_id=NODE_A,
    )

    report = CameraReconciler(
        store=store,
        media_nodes=RecordingMediaNodeFactory(),
    ).reconcile_node(NODE_A)

    assert report.applied == 1
    assert store.list_cameras()[0].applied_revision == 1
    store.close()


def test_postgresql_camera_lifecycle_is_revisioned_until_verified_delete(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresNodeStore(postgres_database_url)
    node = store.register_automatically(
        name="media-a",
        allowed_ports=(12000,),
        max_nodes=1,
        preferred_port=12000,
        choose_port=lambda available: available[0],
        new_node_id=lambda: NODE_A,
        api_ports=(13000,),
        metrics_ports=(14000,),
        mediamtx_binary_sha256="a" * 64,
    )
    node = store.request_desired_state(node.id, NodeState.RUNNING)
    store.apply_runtime_observation(
        node.id,
        NodeRuntimeObservation(
            state=NodeState.RUNNING,
            health=NodeHealth.HEALTHY,
            management_fresh=True,
            config_compatible=True,
            applied_revision=node.desired_revision,
            process_id=123,
            process_start_ticks=456,
            process_boot_id=UUID("20000000-0000-0000-0000-000000000001"),
            config_sha256="b" * 64,
            release_id="0.1.0",
        ),
    )
    CameraControl(
        store=store,
        new_camera_id=lambda: CAMERA_A,
        new_public_id=lambda: str(PUBLIC_A),
    ).create_camera(
        name="entrance",
        source_url="rtsp://camera.invalid/main",
        node_id=NODE_A,
    )
    factory = RecordingMediaNodeFactory()
    reconciler = CameraReconciler(store=store, media_nodes=factory)
    reconciler.reconcile_node(NODE_A)

    assert store.set_camera_enabled(CAMERA_A, enabled=False).desired_revision == 2
    reconciler.reconcile_node(NODE_A)
    assert store.set_camera_enabled(CAMERA_A, enabled=True).desired_revision == 3
    reconciler.reconcile_node(NODE_A)
    deleting = store.request_camera_delete(CAMERA_A)
    before = store.get_node(NODE_A)
    reconciler.reconcile_node(NODE_A)
    after = store.get_node(NODE_A)

    assert deleting.state is CameraState.DELETING
    assert before is not None and before.registered_cameras == 1
    assert after is not None and after.registered_cameras == 0
    assert store.list_cameras() == ()
    store.close()


def test_runtime_observation_is_scoped_to_the_current_camera_node() -> None:
    store = camera_store()
    factory = RecordingMediaNodeFactory()
    factory.clients[NODE_A].runtime[PUBLIC_A] = (True, 1)

    observation = CameraRuntimeObserver(
        store=store,
        media_nodes=factory,
    ).observe(CAMERA_A)

    assert observation.ready is True
    assert observation.reader_count == 1
    assert observation.occupied is True
    assert observation.reader_limit_violated is False
    assert factory.requested == [NODE_A]
    assert factory.clients[NODE_B].runtime == {}


def test_move_preview_fails_closed_when_reader_limit_is_already_violated() -> None:
    store = camera_store()
    factory = RecordingMediaNodeFactory()
    factory.clients[NODE_A].runtime[PUBLIC_A] = (True, 2)
    control, _ = move_services(store, factory)

    from rtsp_proxy.reconcile import CameraReaderInvariantViolation

    with pytest.raises(
        CameraReaderInvariantViolation,
        match="camera_reader_limit_violated",
    ):
        control.preview(CAMERA_A, target_node_id=NODE_B)


def test_node_port_confirmation_is_bound_to_blast_radius_and_expiry() -> None:
    wall_time = [1_700_000_000.0]
    confirmations = ConfirmationTokenService(
        secret=b"test-confirmation-secret-that-is-at-least-32-bytes",
        lifetime_seconds=30,
        wall_time=lambda: wall_time[0],
    )
    fingerprint = "a" * 64
    token = confirmations.issue_node_port_change(
        node_id=NODE_A,
        old_port=12000,
        new_port=12002,
        desired_revision=3,
        registered_cameras=1,
        blast_radius_sha256=fingerprint,
    )

    assert confirmations.verify_node_port_change(
        token,
        node_id=NODE_A,
        old_port=12000,
        new_port=12002,
        desired_revision=3,
        registered_cameras=1,
        blast_radius_sha256=fingerprint,
    )
    assert not confirmations.verify_node_port_change(
        token,
        node_id=NODE_A,
        old_port=12000,
        new_port=12002,
        desired_revision=3,
        registered_cameras=1,
        blast_radius_sha256="invalid",
    )
    assert not confirmations.verify_node_port_change(
        token,
        node_id=NODE_A,
        old_port=12000,
        new_port=12003,
        desired_revision=3,
        registered_cameras=1,
        blast_radius_sha256=fingerprint,
    )
    wall_time[0] += 31
    assert not confirmations.verify_node_port_change(
        token,
        node_id=NODE_A,
        old_port=12000,
        new_port=12002,
        desired_revision=3,
        registered_cameras=1,
        blast_radius_sha256=fingerprint,
    )


def test_node_reconfigure_confirmation_is_bound_to_exact_node_revision_and_placements() -> None:
    wall_time = [1_700_000_000.0]
    confirmations = ConfirmationTokenService(
        secret=b"test-confirmation-secret-that-is-at-least-32-bytes",
        lifetime_seconds=30,
        wall_time=lambda: wall_time[0],
    )
    fingerprint = "b" * 64
    token = confirmations.issue_node_reconfigure(
        node_id=NODE_A,
        external_port=12000,
        desired_revision=3,
        registered_cameras=1,
        blast_radius_sha256=fingerprint,
        target_release_id="0.2.0",
        target_mediamtx_binary_sha256="a" * 64,
    )

    assert confirmations.verify_node_reconfigure(
        token,
        node_id=NODE_A,
        external_port=12000,
        desired_revision=3,
        registered_cameras=1,
        blast_radius_sha256=fingerprint,
        target_release_id="0.2.0",
        target_mediamtx_binary_sha256="a" * 64,
    )
    assert not confirmations.verify_node_reconfigure(
        token,
        node_id=NODE_A,
        external_port=12001,
        desired_revision=3,
        registered_cameras=1,
        blast_radius_sha256=fingerprint,
        target_release_id="0.2.0",
        target_mediamtx_binary_sha256="a" * 64,
    )
    assert not confirmations.verify_node_reconfigure(
        token,
        node_id=NODE_A,
        external_port=12000,
        desired_revision=4,
        registered_cameras=1,
        blast_radius_sha256=fingerprint,
        target_release_id="0.2.0",
        target_mediamtx_binary_sha256="a" * 64,
    )
    assert not confirmations.verify_node_reconfigure(
        token,
        node_id=NODE_A,
        external_port=12000,
        desired_revision=3,
        registered_cameras=1,
        blast_radius_sha256=fingerprint,
        target_release_id="0.2.1",
        target_mediamtx_binary_sha256="c" * 64,
    )
    assert not confirmations.verify_node_reconfigure(
        token,
        node_id=NODE_A,
        external_port=12000,
        desired_revision=3,
        registered_cameras=1,
        blast_radius_sha256="invalid",
        target_release_id="0.2.0",
        target_mediamtx_binary_sha256="a" * 64,
    )
    wall_time[0] += 31
    assert not confirmations.verify_node_reconfigure(
        token,
        node_id=NODE_A,
        external_port=12000,
        desired_revision=3,
        registered_cameras=1,
        blast_radius_sha256=fingerprint,
        target_release_id="0.2.0",
        target_mediamtx_binary_sha256="a" * 64,
    )


def move_services(
    store: CameraMoveStore,
    factory: RecordingMediaNodeFactory,
) -> tuple[CameraMoveControl, CameraMoveReconciler]:
    confirmations = ConfirmationTokenService(
        secret=b"test-confirmation-secret-that-is-at-least-32-bytes",
        lifetime_seconds=30,
        wall_time=lambda: 1_700_000_000.0,
    )
    control = CameraMoveControl(
        store=store,
        runtime=CameraRuntimeObserver(store=store, media_nodes=factory),
        confirmations=confirmations,
        new_move_id=lambda: UUID("30000000-0000-0000-0000-000000000001"),
    )
    return control, CameraMoveReconciler(store=store, media_nodes=factory)


def test_unoccupied_move_switches_only_after_target_read_back() -> None:
    store = camera_store()
    factory = RecordingMediaNodeFactory()
    CameraReconciler(store=store, media_nodes=factory).reconcile_node(NODE_A)
    factory.clients[NODE_A].runtime[PUBLIC_A] = (True, 0)
    control, moves = move_services(store, factory)

    move = control.request_move(CAMERA_A, target_node_id=NODE_B)
    before = store.get_camera(CAMERA_A)
    completed = moves.resume(move.id)
    after = store.get_camera(CAMERA_A)

    assert before is not None and before.node_id == NODE_A
    assert completed.state.value == "complete"
    assert after is not None and after.node_id == NODE_B
    assert after.node_port == 12001
    assert after.placement_generation == 2
    assert factory.clients[NODE_A].paths == {}
    assert factory.clients[NODE_B].paths[PUBLIC_A].source_url == ("rtsp://camera.invalid/main")
    assert store.get_node(NODE_A).registered_cameras == 0  # type: ignore[union-attr]
    assert store.get_node(NODE_B).registered_cameras == 1  # type: ignore[union-attr]


def test_occupied_move_is_denied_before_target_prepare() -> None:
    store = camera_store()
    factory = RecordingMediaNodeFactory()
    factory.clients[NODE_A].runtime[PUBLIC_A] = (True, 1)
    control, _ = move_services(store, factory)

    with pytest.raises(CameraOccupied, match="camera_occupied"):
        control.request_move(CAMERA_A, target_node_id=NODE_B)

    assert factory.clients[NODE_B].paths == {}


def test_forced_move_requires_a_confirmation_bound_to_the_exact_target() -> None:
    store = camera_store()
    factory = RecordingMediaNodeFactory()
    factory.clients[NODE_A].runtime[PUBLIC_A] = (True, 1)
    control, moves = move_services(store, factory)
    preview = control.preview(CAMERA_A, target_node_id=NODE_B)

    with pytest.raises(MoveConfirmationRequired, match="move_confirmation_required"):
        control.request_move(
            CAMERA_A,
            target_node_id=NODE_B,
            force=True,
            confirmation_token=None,
        )

    move = control.request_move(
        CAMERA_A,
        target_node_id=NODE_B,
        force=True,
        confirmation_token=preview.confirmation_token,
    )

    assert preview.occupied is True
    assert preview.disconnect_readers == 1
    assert moves.resume(move.id).state.value == "complete"


def test_late_reader_is_fenced_and_aborts_ordinary_move_without_duplicate_path() -> None:
    store = camera_store()
    factory = RecordingMediaNodeFactory()
    CameraReconciler(store=store, media_nodes=factory).reconcile_node(NODE_A)
    factory.clients[NODE_A].runtime[PUBLIC_A] = (True, 0)
    control, moves = move_services(store, factory)
    move = control.request_move(CAMERA_A, target_node_id=NODE_B)
    factory.clients[NODE_A].runtime[PUBLIC_A] = (True, 1)

    result = moves.resume(move.id)

    assert result.state is CameraMoveState.ABORTED
    assert result.abort_reason == "camera_move_occupancy_changed"
    assert store.get_camera(CAMERA_A).node_id == NODE_A  # type: ignore[union-attr]
    assert factory.clients[NODE_B].paths == {}
    assert factory.clients[NODE_A].paths[PUBLIC_A].max_readers == 1


def test_move_expires_and_removes_prepared_target_before_it_can_be_read() -> None:
    current_time = [datetime(2026, 8, 12, tzinfo=UTC)]
    store = camera_store(clock=lambda: current_time[0])
    factory = RecordingMediaNodeFactory()
    CameraReconciler(store=store, media_nodes=factory).reconcile_node(NODE_A)
    factory.clients[NODE_A].runtime[PUBLIC_A] = (True, 0)
    confirmations = ConfirmationTokenService(
        secret=b"test-confirmation-secret-that-is-at-least-32-bytes",
        lifetime_seconds=30,
    )
    control = CameraMoveControl(
        store=store,
        runtime=CameraRuntimeObserver(store=store, media_nodes=factory),
        confirmations=confirmations,
        new_move_id=lambda: UUID("30000000-0000-0000-0000-000000000001"),
        move_timeout_seconds=1,
    )
    move = control.request_move(CAMERA_A, target_node_id=NODE_B)
    current_time[0] += timedelta(seconds=2)
    factory.clients[NODE_B].paths[PUBLIC_A] = MediaPathConfig(
        name=PUBLIC_A,
        source_url="rtsp://camera.invalid/main",
        max_readers=-1,
    )

    result = CameraMoveReconciler(store=store, media_nodes=factory).resume(move.id)

    assert result.state is CameraMoveState.ABORTED
    assert factory.clients[NODE_B].paths == {}


def test_postgresql_move_deadline_uses_database_clock_not_web_clock(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresNodeStore(postgres_database_url)
    for node_id, port in (
        (NODE_A, 12000),
        (NODE_B, 12001),
    ):
        def allocate_node_id(selected: UUID = node_id) -> UUID:
            return selected

        node = store.register_automatically(
            name=f"node-{node_id.int}",
            allowed_ports=(12000, 12001),
            max_nodes=2,
            preferred_port=port,
            choose_port=lambda available: available[0],
            new_node_id=allocate_node_id,
            api_ports=(13000, 13001),
            metrics_ports=(14000, 14001),
        )
        node = store.request_desired_state(node.id, NodeState.RUNNING)
        store.apply_runtime_observation(
            node.id,
            NodeRuntimeObservation(
                state=NodeState.RUNNING,
                health=NodeHealth.HEALTHY,
                management_fresh=True,
                config_compatible=True,
                applied_revision=node.desired_revision,
                process_id=100 + node.id.int,
                process_start_ticks=1000 + node.id.int,
                process_boot_id=UUID("20000000-0000-0000-0000-000000000001"),
                config_sha256="b" * 64,
                release_id="0.1.0",
            ),
        )
    CameraControl(
        store=store,
        new_camera_id=lambda: CAMERA_A,
        new_public_id=lambda: str(PUBLIC_A),
    ).create_camera(
        name="entrance",
        source_url="rtsp://camera.invalid/main",
        node_id=NODE_A,
    )
    factory = RecordingMediaNodeFactory()
    factory.clients[NODE_A].runtime[PUBLIC_A] = (True, 0)
    control = CameraMoveControl(
        store=store,
        runtime=CameraRuntimeObserver(store=store, media_nodes=factory),
        confirmations=ConfirmationTokenService(secret=b"x" * 32, lifetime_seconds=30),
        new_move_id=lambda: UUID("30000000-0000-0000-0000-000000000001"),
        move_timeout_seconds=300,
    )

    before = datetime.now(UTC)
    move = control.request_move(CAMERA_A, target_node_id=NODE_B)
    after = datetime.now(UTC)

    assert before + timedelta(seconds=299) < move.expires_at
    assert move.expires_at < after + timedelta(seconds=301)
    store.close()


def test_move_expiring_at_the_atomic_switch_is_aborted_and_restores_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = camera_store()
    factory = RecordingMediaNodeFactory()
    CameraReconciler(store=store, media_nodes=factory).reconcile_node(NODE_A)
    factory.clients[NODE_A].runtime[PUBLIC_A] = (True, 0)
    control, moves = move_services(store, factory)
    move = control.request_move(CAMERA_A, target_node_id=NODE_B)

    def expired_switch(
        _move_id: UUID,
        *,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> CameraMove:
        assert not cancelled()
        raise CameraMoveExpired("camera_move_expired")

    monkeypatch.setattr(store, "switch_camera_move", expired_switch)

    result = moves.resume(move.id)

    assert result.state is CameraMoveState.ABORTED
    assert result.abort_reason == "camera_move_expired"
    assert store.get_camera(CAMERA_A).node_id == NODE_A  # type: ignore[union-attr]
    assert factory.clients[NODE_B].paths == {}
    assert factory.clients[NODE_A].paths[PUBLIC_A].max_readers == 1


def test_disruptive_camera_mutation_rechecks_current_reader_under_node_guard() -> None:
    store = camera_store()
    factory = RecordingMediaNodeFactory()
    CameraReconciler(store=store, media_nodes=factory).reconcile_node(NODE_A)
    confirmations = ConfirmationTokenService(
        secret=b"test-confirmation-secret-that-is-at-least-32-bytes",
        lifetime_seconds=30,
    )
    control = CameraMutationControl(
        store=store,
        media_nodes=factory,
        confirmations=confirmations,
    )
    factory.clients[NODE_A].runtime[PUBLIC_A] = (True, 0)
    preview = control.preview(CAMERA_A, operation=CameraMutationOperation.DISABLE)
    factory.clients[NODE_A].runtime[PUBLIC_A] = (True, 1)

    with pytest.raises(
        CameraDisruptionConfirmationRequired,
        match="camera_disruption_confirmation_required",
    ):
        control.disable(CAMERA_A, confirmation_token=preview.confirmation_token)

    assert store.get_camera(CAMERA_A).state is CameraState.ENABLED  # type: ignore[union-attr]
    assert factory.clients[NODE_A].paths[PUBLIC_A].max_readers == 1


def test_disruptive_camera_mutation_accepts_exact_current_confirmation() -> None:
    store = camera_store()
    factory = RecordingMediaNodeFactory()
    CameraReconciler(store=store, media_nodes=factory).reconcile_node(NODE_A)
    factory.clients[NODE_A].runtime[PUBLIC_A] = (True, 1)
    confirmations = ConfirmationTokenService(
        secret=b"test-confirmation-secret-that-is-at-least-32-bytes",
        lifetime_seconds=30,
    )
    control = CameraMutationControl(
        store=store,
        media_nodes=factory,
        confirmations=confirmations,
    )
    preview = control.preview(CAMERA_A, operation=CameraMutationOperation.DISABLE)

    disabled = control.disable(
        CAMERA_A,
        confirmation_token=preview.confirmation_token,
    )

    assert disabled.state is CameraState.DISABLED
    assert factory.clients[NODE_A].paths[PUBLIC_A].max_readers == -1


def test_supplied_camera_confirmation_remains_mandatory_after_reader_disconnects() -> None:
    store = camera_store()
    factory = RecordingMediaNodeFactory()
    CameraReconciler(store=store, media_nodes=factory).reconcile_node(NODE_A)
    factory.clients[NODE_A].runtime[PUBLIC_A] = (True, 1)
    confirmations = ConfirmationTokenService(
        secret=b"test-confirmation-secret-that-is-at-least-32-bytes",
        lifetime_seconds=30,
    )
    control = CameraMutationControl(
        store=store,
        media_nodes=factory,
        confirmations=confirmations,
    )
    preview = control.preview(CAMERA_A, operation=CameraMutationOperation.DISABLE)
    factory.clients[NODE_A].runtime[PUBLIC_A] = (False, 0)

    with pytest.raises(
        CameraDisruptionConfirmationRequired,
        match="camera_disruption_confirmation_required",
    ):
        control.delete(
            CAMERA_A,
            expected_revision=preview.desired_revision,
            confirmation_token=preview.confirmation_token,
        )

    assert store.get_camera(CAMERA_A).state is CameraState.ENABLED  # type: ignore[union-attr]
    assert factory.clients[NODE_A].paths[PUBLIC_A].max_readers == 1


def test_name_only_update_cannot_ignore_a_supplied_confirmation() -> None:
    store = camera_store()
    factory = RecordingMediaNodeFactory()
    CameraReconciler(store=store, media_nodes=factory).reconcile_node(NODE_A)
    factory.clients[NODE_A].runtime[PUBLIC_A] = (True, 1)
    control = CameraMutationControl(
        store=store,
        media_nodes=factory,
        confirmations=ConfirmationTokenService(
            secret=b"test-confirmation-secret-that-is-at-least-32-bytes",
            lifetime_seconds=30,
        ),
    )
    preview = control.preview(
        CAMERA_A,
        operation=CameraMutationOperation.UPDATE_SOURCE,
        name="Previewed name",
        source_url="rtsp://camera.invalid/main",
    )
    factory.clients[NODE_A].runtime[PUBLIC_A] = (False, 0)

    with pytest.raises(
        CameraDisruptionConfirmationRequired,
        match="camera_disruption_confirmation_required",
    ):
        control.update(
            CAMERA_A,
            name="Altered name",
            source_url="rtsp://camera.invalid/main",
            expected_revision=preview.desired_revision,
            confirmation_token=preview.confirmation_token,
        )

    assert store.get_camera(CAMERA_A).name == "entrance"  # type: ignore[union-attr]
    assert factory.clients[NODE_A].paths[PUBLIC_A].max_readers == 1


def test_camera_mutation_rejects_stale_expected_revision_before_runtime_change() -> None:
    store = camera_store()
    factory = RecordingMediaNodeFactory()
    CameraReconciler(store=store, media_nodes=factory).reconcile_node(NODE_A)
    control = CameraMutationControl(
        store=store,
        media_nodes=factory,
        confirmations=ConfirmationTokenService(
            secret=b"test-confirmation-secret-that-is-at-least-32-bytes",
            lifetime_seconds=30,
        ),
    )

    with pytest.raises(CameraLifecycleConflict, match="camera_revision_conflict"):
        control.disable(
            CAMERA_A,
            expected_revision=999,
            confirmation_token=None,
        )

    assert factory.clients[NODE_A].paths[PUBLIC_A].max_readers == 1


def test_disruptive_camera_mutation_rejects_revision_changed_after_media_fence() -> None:
    store = camera_store()
    factory = RecordingMediaNodeFactory()
    CameraReconciler(store=store, media_nodes=factory).reconcile_node(NODE_A)
    original_status = factory.clients[NODE_A].path_runtime_status

    def rename_while_fenced(name: PublicId) -> tuple[bool, int] | None:
        store.update_camera(
            CAMERA_A,
            name="concurrent rename",
            source_url="rtsp://camera.invalid/main",
            expected_revision=1,
        )
        return original_status(name)

    factory.clients[NODE_A].path_runtime_status = rename_while_fenced  # type: ignore[method-assign]
    control = CameraMutationControl(
        store=store,
        media_nodes=factory,
        confirmations=ConfirmationTokenService(
            secret=b"test-confirmation-secret-that-is-at-least-32-bytes",
            lifetime_seconds=30,
        ),
    )

    with pytest.raises(CameraLifecycleConflict, match="camera_revision_conflict"):
        control.disable(CAMERA_A, confirmation_token=None)

    current = store.get_camera(CAMERA_A)
    assert current is not None
    assert current.name == "concurrent rename"
    assert current.state is CameraState.ENABLED
    assert factory.clients[NODE_A].paths[PUBLIC_A].max_readers == 1


def test_reconcile_cancellation_is_checked_between_each_delete_call() -> None:
    client = RecordingMediaNode()
    client.paths[PUBLIC_A] = MediaPathConfig(
        name=PUBLIC_A,
        source_url="rtsp://camera.invalid/main",
    )
    calls = 0

    def cancelled() -> bool:
        nonlocal calls
        calls += 1
        return calls >= 2

    with pytest.raises(ReconcileCancelled, match="camera_reconcile_cancelled"):
        CameraReconciler._remove_disabled_path(client, PUBLIC_A, cancelled)

    assert PUBLIC_A in client.paths


def test_move_prepare_cancellation_skips_error_readback() -> None:
    store = camera_store()
    factory = RecordingMediaNodeFactory()
    CameraReconciler(store=store, media_nodes=factory).reconcile_node(NODE_A)
    factory.clients[NODE_A].runtime[PUBLIC_A] = (True, 0)
    control, moves = move_services(store, factory)
    move = control.request_move(CAMERA_A, target_node_id=NODE_B)
    target = factory.clients[NODE_B]
    calls = 0
    cancelled = False

    def fail_initial_get(_name: PublicId) -> MediaPathConfig | None:
        nonlocal calls, cancelled
        calls += 1
        cancelled = True
        raise MediaNodeUnavailable("mediamtx_unavailable")

    target.get_path = fail_initial_get  # type: ignore[assignment]

    with pytest.raises(ReconcileCancelled, match="camera_reconcile_cancelled"):
        moves.resume(move.id, cancelled=lambda: cancelled)

    assert calls == 1


def test_camera_mutation_covers_noop_missing_node_and_failed_store_restore() -> None:
    store = camera_store()
    factory = RecordingMediaNodeFactory()
    CameraReconciler(store=store, media_nodes=factory).reconcile_node(NODE_A)
    confirmations = ConfirmationTokenService(
        secret=b"test-confirmation-secret-that-is-at-least-32-bytes",
        lifetime_seconds=30,
    )
    control = CameraMutationControl(
        store=store,
        media_nodes=factory,
        confirmations=confirmations,
    )
    current = store.get_camera(CAMERA_A)
    assert current is not None
    assert control.update(
        CAMERA_A,
        name="renamed",
        source_url=current.source_url,
        confirmation_token=None,
    ).name == "renamed"
    store.set_camera_enabled(CAMERA_A, enabled=False)
    assert control.disable(CAMERA_A, confirmation_token=None).state is CameraState.DISABLED

    with pytest.raises(CameraNotFound):
        control.preview(UUID(int=999), operation=CameraMutationOperation.DELETE)

    class MissingNodeStore(InMemoryNodeStore):
        def get_node(self, node_id: UUID) -> None:
            return None

    missing_store = MissingNodeStore(nodes=(running_node(NODE_A, 12000),))
    CameraControl(
        store=missing_store,
        new_camera_id=lambda: CAMERA_A,
        new_public_id=lambda: str(PUBLIC_A),
    ).create_camera(
        name="entrance",
        source_url="rtsp://camera.invalid/main",
        node_id=NODE_A,
    )
    with pytest.raises(ReconcileRetry, match="camera_runtime_node_missing"):
        CameraMutationControl(
            store=missing_store,
            media_nodes=factory,
            confirmations=confirmations,
        ).preview(CAMERA_A, operation=CameraMutationOperation.DELETE)

    class RejectUpdateStore(InMemoryNodeStore):
        def update_camera(
            self,
            camera_id: UUID,
            *,
            name: str,
            source_url: str,
            expected_revision: int | None = None,
        ) -> CameraPlacement:
            raise CameraLifecycleConflict("camera_revision_conflict")

    rejecting = RejectUpdateStore(nodes=(running_node(NODE_A, 12000),))
    CameraControl(
        store=rejecting,
        new_camera_id=lambda: CAMERA_A,
        new_public_id=lambda: str(PUBLIC_A),
    ).create_camera(
        name="entrance",
        source_url="rtsp://camera.invalid/main",
        node_id=NODE_A,
    )
    rejecting_control = CameraMutationControl(
        store=rejecting,
        media_nodes=factory,
        confirmations=confirmations,
    )
    with pytest.raises(CameraLifecycleConflict, match="camera_revision_conflict"):
        rejecting_control.update(
            CAMERA_A,
            name="renamed",
            source_url="rtsp://camera.invalid/sub",
            confirmation_token=None,
        )
    assert factory.clients[NODE_A].paths[PUBLIC_A].max_readers == 1


def test_move_resume_covers_activation_retry_and_terminal_idempotence() -> None:
    store = camera_store()
    factory = RecordingMediaNodeFactory()
    CameraReconciler(store=store, media_nodes=factory).reconcile_node(NODE_A)
    factory.clients[NODE_A].runtime[PUBLIC_A] = (True, 0)
    control, moves = move_services(store, factory)
    move = control.request_move(CAMERA_A, target_node_id=NODE_B)
    target = factory.clients[NODE_B]
    original_put = target.put_path
    activation_failed = False

    def fail_activation(path: MediaPathConfig) -> None:
        nonlocal activation_failed
        if path.max_readers == 1 and not activation_failed:
            activation_failed = True
            raise MediaNodeUnavailable("mediamtx_unavailable")
        original_put(path)

    target.put_path = fail_activation  # type: ignore[method-assign]
    with pytest.raises(MediaNodeUnavailable):
        moves.resume(move.id)
    assert store.get_camera_move(move.id).state is CameraMoveState.ACTIVATE_TARGET  # type: ignore[union-attr]
    completed = moves.resume(move.id)
    assert completed.state is CameraMoveState.COMPLETE
    assert moves.resume(move.id) == completed


def test_reconcile_cancellation_stops_before_any_external_mutation() -> None:
    store = camera_store()
    factory = RecordingMediaNodeFactory()
    from rtsp_proxy.reconcile import ReconcileCancelled

    with pytest.raises(ReconcileCancelled):
        CameraReconciler(store=store, media_nodes=factory).reconcile_node(
            NODE_A,
            cancelled=lambda: True,
        )
    assert factory.requested == []


def test_move_resumes_cleanup_after_current_placement_was_switched() -> None:
    store = camera_store()
    factory = RecordingMediaNodeFactory()
    CameraReconciler(store=store, media_nodes=factory).reconcile_node(NODE_A)
    factory.clients[NODE_A].runtime[PUBLIC_A] = (True, 0)
    control, moves = move_services(store, factory)
    move = control.request_move(CAMERA_A, target_node_id=NODE_B)
    source = factory.clients[NODE_A]
    original_delete = source.delete_path
    attempts = 0

    def fail_first_delete(name: PublicId) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise MediaNodeUnavailable("mediamtx_unavailable")
        original_delete(name)

    source.delete_path = fail_first_delete  # type: ignore[method-assign]

    with pytest.raises(ReconcileRetry):
        moves.resume(move.id)

    switched = store.get_camera(CAMERA_A)
    assert switched is not None and switched.node_id == NODE_B
    assert store.get_camera_move(move.id).state.value == "cleanup_source"  # type: ignore[union-attr]
    assert moves.resume(move.id).state.value == "complete"
    assert factory.clients[NODE_A].paths == {}


def test_active_move_fences_competing_camera_mutations() -> None:
    store = camera_store()
    factory = RecordingMediaNodeFactory()
    factory.clients[NODE_A].runtime[PUBLIC_A] = (True, 0)
    control, moves = move_services(store, factory)
    move = control.request_move(CAMERA_A, target_node_id=NODE_B)

    with pytest.raises(CameraLifecycleConflict, match="camera_move_in_progress"):
        store.update_camera(
            CAMERA_A,
            name="changed",
            source_url="rtsp://camera.invalid/main",
        )
    with pytest.raises(CameraLifecycleConflict, match="camera_move_in_progress"):
        store.set_camera_enabled(CAMERA_A, enabled=False)
    with pytest.raises(CameraLifecycleConflict, match="camera_move_in_progress"):
        store.request_camera_delete(CAMERA_A)

    assert moves.resume(move.id).state is CameraMoveState.COMPLETE


def test_empty_target_node_lifecycle_is_fenced_by_active_move() -> None:
    store = camera_store()
    factory = RecordingMediaNodeFactory()
    factory.clients[NODE_A].runtime[PUBLIC_A] = (True, 0)
    control, moves = move_services(store, factory)
    move = control.request_move(CAMERA_A, target_node_id=NODE_B)

    operations: tuple[Callable[[], object], ...] = (
        lambda: store.request_stop(NODE_B),
        lambda: store.request_restart(NODE_B),
    )
    for operation in operations:
        with pytest.raises(NodeLifecycleConflict, match="node_operation_in_progress"):
            operation()

    assert moves.resume(move.id).state is CameraMoveState.COMPLETE


def test_postgresql_move_resumes_with_one_current_placement(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresNodeStore(postgres_database_url)
    for node_id, external_port, api_port, metrics_port in (
        (NODE_A, 12000, 13000, 14000),
        (NODE_B, 12001, 13001, 14001),
    ):

        def current_node_id(node_id: UUID = node_id) -> UUID:
            return node_id

        node = store.register_automatically(
            name=f"media-{node_id.int}",
            allowed_ports=(external_port,),
            max_nodes=2,
            preferred_port=external_port,
            choose_port=lambda available: available[0],
            new_node_id=current_node_id,
            api_ports=(api_port,),
            metrics_ports=(metrics_port,),
            mediamtx_binary_sha256="a" * 64,
        )
        node = store.request_desired_state(node.id, NodeState.RUNNING)
        store.apply_runtime_observation(
            node.id,
            NodeRuntimeObservation(
                state=NodeState.RUNNING,
                health=NodeHealth.HEALTHY,
                management_fresh=True,
                config_compatible=True,
                applied_revision=node.desired_revision,
                process_id=100 + node_id.int,
                process_start_ticks=200 + node_id.int,
                process_boot_id=UUID("20000000-0000-0000-0000-000000000001"),
                config_sha256="b" * 64,
                release_id="0.1.0",
            ),
        )
    CameraControl(
        store=store,
        new_camera_id=lambda: CAMERA_A,
        new_public_id=lambda: str(PUBLIC_A),
    ).create_camera(
        name="entrance",
        source_url="rtsp://camera.invalid/main",
        node_id=NODE_A,
    )
    factory = RecordingMediaNodeFactory()
    CameraReconciler(store=store, media_nodes=factory).reconcile_node(NODE_A)
    factory.clients[NODE_A].runtime[PUBLIC_A] = (True, 0)
    control, moves = move_services(store, factory)
    move = control.request_move(CAMERA_A, target_node_id=NODE_B)
    source = factory.clients[NODE_A]
    original_delete = source.delete_path
    failed = False

    def fail_once(name: PublicId) -> None:
        nonlocal failed
        if not failed:
            failed = True
            raise MediaNodeUnavailable("mediamtx_unavailable")
        original_delete(name)

    source.delete_path = fail_once  # type: ignore[method-assign]

    with pytest.raises(ReconcileRetry):
        moves.resume(move.id)

    switched = store.get_camera(CAMERA_A)
    assert switched is not None and switched.node_id == NODE_B
    assert switched.placement_generation == 2
    assert store.get_camera_move(move.id).state is CameraMoveState.CLEANUP_SOURCE  # type: ignore[union-attr]
    assert moves.resume(move.id).state is CameraMoveState.COMPLETE
    assert store.get_node(NODE_A).registered_cameras == 0  # type: ignore[union-attr]
    assert store.get_node(NODE_B).registered_cameras == 1  # type: ignore[union-attr]
    store.close()


def test_postgresql_move_abort_is_durable_idempotent_and_restores_revision(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresNodeStore(postgres_database_url)
    for node_id, external_port, api_port, metrics_port in (
        (NODE_A, 12000, 13000, 14000),
        (NODE_B, 12001, 13001, 14001),
    ):
        def selected_node_id(selected: UUID = node_id) -> UUID:
            return selected

        node = store.register_automatically(
            name=f"media-{node_id.int}",
            allowed_ports=(external_port,),
            max_nodes=2,
            preferred_port=external_port,
            choose_port=lambda available: available[0],
            new_node_id=selected_node_id,
            api_ports=(api_port,),
            metrics_ports=(metrics_port,),
            mediamtx_binary_sha256="a" * 64,
        )
        node = store.request_desired_state(node.id, NodeState.RUNNING)
        store.apply_runtime_observation(
            node.id,
            NodeRuntimeObservation(
                state=NodeState.RUNNING,
                health=NodeHealth.HEALTHY,
                management_fresh=True,
                config_compatible=True,
                applied_revision=node.desired_revision,
                process_id=100 + node_id.int,
                process_start_ticks=200 + node_id.int,
                process_boot_id=UUID("20000000-0000-0000-0000-000000000001"),
                config_sha256="b" * 64,
                release_id="0.1.0",
            ),
        )
    CameraControl(
        store=store,
        new_camera_id=lambda: CAMERA_A,
        new_public_id=lambda: str(PUBLIC_A),
    ).create_camera(
        name="entrance",
        source_url="rtsp://camera.invalid/main",
        node_id=NODE_A,
    )
    move = store.create_camera_move(
        move_id=UUID("30000000-0000-0000-0000-000000000001"),
        camera_id=CAMERA_A,
        target_node_id=NODE_B,
        expected_revision=1,
        force=False,
    )

    cleanup = store.request_camera_move_abort(move.id, reason="camera_move_expired")
    assert cleanup.state is CameraMoveState.CLEANUP_TARGET
    assert store.request_camera_move_abort(
        move.id,
        reason="camera_move_expired",
    ) == cleanup
    aborted = store.abort_camera_move(move.id)
    assert aborted.state is CameraMoveState.ABORTED
    assert store.abort_camera_move(move.id) == aborted
    camera = store.get_camera(CAMERA_A)
    assert camera is not None
    assert camera.node_id == NODE_A
    assert camera.desired_revision == 3
    assert store.list_incomplete_camera_moves() == ()
    store.close()


def test_reconcile_cycle_isolates_one_unavailable_node_and_continues() -> None:
    store = camera_store()
    factory = RecordingMediaNodeFactory()

    class UnavailableMediaNode(RecordingMediaNode):
        def inventory_paths(self) -> MediaPathInventory:
            raise MediaNodeUnavailable("mediamtx_unavailable")

    factory.clients[NODE_A] = UnavailableMediaNode()
    coordinator = ReconcileCoordinator(
        store=store,
        cameras=CameraReconciler(store=store, media_nodes=factory),
        moves=CameraMoveReconciler(store=store, media_nodes=factory),
    )

    report = coordinator.run_once()

    assert report.retryable_failures == 1
    assert report.reconciled_nodes == 1
    assert factory.requested == [NODE_A, NODE_B]


def test_reconcile_fails_closed_when_reserved_no_oracle_matcher_is_missing() -> None:
    store = camera_store()
    factory = RecordingMediaNodeFactory()
    factory.clients[NODE_A].no_oracle_matcher_present = False

    with pytest.raises(ReconcileRetry, match="camera_reconcile_reserved_path_missing"):
        CameraReconciler(store=store, media_nodes=factory).reconcile_node(NODE_A)

    camera = store.get_camera(CAMERA_A)
    assert camera is not None
    assert camera.applied_revision == 0
    assert factory.clients[NODE_A].puts == []


def test_disabled_camera_remains_registered_but_its_path_is_removed() -> None:
    store = camera_store()
    factory = RecordingMediaNodeFactory()
    reconciler = CameraReconciler(store=store, media_nodes=factory)
    reconciler.reconcile_node(NODE_A)

    disabled = store.set_camera_enabled(CAMERA_A, enabled=False)
    report = reconciler.reconcile_node(NODE_A)

    assert disabled.state is CameraState.DISABLED
    assert disabled.desired_revision == 2
    assert report.applied == 1
    assert factory.clients[NODE_A].paths == {}
    assert store.list_cameras()[0].applied_revision == 2
    assert store.get_node(NODE_A).registered_cameras == 1  # type: ignore[union-attr]


def test_delete_releases_capacity_only_after_path_absence_is_verified() -> None:
    store = camera_store()
    factory = RecordingMediaNodeFactory()
    reconciler = CameraReconciler(store=store, media_nodes=factory)
    reconciler.reconcile_node(NODE_A)

    deleting = store.request_camera_delete(CAMERA_A)
    before = store.get_node(NODE_A)
    report = reconciler.reconcile_node(NODE_A)
    after = store.get_node(NODE_A)

    assert deleting.state is CameraState.DELETING
    assert deleting.desired_revision == 2
    assert before is not None and before.registered_cameras == 1
    assert report.applied == 1
    assert after is not None and after.registered_cameras == 0
    assert store.list_cameras() == ()
    assert reconciler.reconcile_node(NODE_A).applied == 0


def test_confirmation_decoder_rejects_malformed_tokens_and_invalid_expiry() -> None:
    confirmations = ConfirmationTokenService(
        secret=b"test-confirmation-secret-that-is-at-least-32-bytes",
        lifetime_seconds=30,
        wall_time=lambda: 1_700_000_000.0,
    )
    valid = confirmations.issue_node_port_change(
        node_id=NODE_A,
        old_port=12000,
        new_port=12001,
        desired_revision=1,
        registered_cameras=0,
        blast_radius_sha256="a" * 64,
    )

    for token in ("x" * 4097, "no-dot", "!bad!.signature", valid + ".extra"):
        assert not confirmations.verify_node_port_change(
            token,
            node_id=NODE_A,
            old_port=12000,
            new_port=12001,
            desired_revision=1,
            registered_cameras=0,
            blast_radius_sha256="a" * 64,
        )
    assert not confirmations.verify_node_port_change(
        valid,
        node_id=NODE_A,
        old_port=12000,
        new_port=12001,
        desired_revision=1,
        registered_cameras=0,
        blast_radius_sha256="invalid",
    )


def test_reconcile_failures_and_orphans_are_isolated_and_verified() -> None:
    store = camera_store()
    factory = RecordingMediaNodeFactory()
    reconciler = CameraReconciler(store=store, media_nodes=factory)
    client = factory.clients[NODE_A]
    orphan = PublicId.parse("b" * 25 + "e")
    client.paths[orphan] = MediaPathConfig(name=orphan, source_url="rtsp://old.invalid/main")

    report = reconciler.reconcile_node(NODE_A)

    assert report.applied == 1
    assert report.deleted_orphans == 1
    assert orphan not in client.paths
    with pytest.raises(ReconcileRetry, match="camera_reconcile_node_unavailable"):
        CameraReconciler(
            store=InMemoryNodeStore(nodes=(MediaNode(id=NODE_A, name="down", external_port=1),)),
            media_nodes=factory,
        ).reconcile_node(NODE_A)
    with pytest.raises(Exception, match="node_not_found"):
        reconciler.reconcile_node(UUID(int=99))

    class StubbornNode(RecordingMediaNode):
        def delete_path(self, name: PublicId) -> None:
            self.deletes.append(name)

    stubborn = StubbornNode()
    stubborn.paths[PUBLIC_A] = MediaPathConfig(
        name=PUBLIC_A,
        source_url="rtsp://camera.invalid/main",
    )
    with pytest.raises(ReconcileRetry, match="camera_reconcile_delete_unverified"):
        CameraReconciler._remove_disabled_path(stubborn, PUBLIC_A)

    class UnreadableNode(RecordingMediaNode):
        def get_path(self, name: PublicId) -> MediaPathConfig | None:
            raise MediaNodeProtocolError("bad")

    with pytest.raises(ReconcileRetry, match="camera_reconcile_unverified"):
        CameraReconciler._safe_read_back(
            UnreadableNode(),
            MediaPathConfig(name=PUBLIC_A, source_url="rtsp://camera.invalid/main"),
        )
    with pytest.raises(ReconcileRetry, match="camera_reconcile_orphan_unverified"):
        CameraReconciler._safe_get(UnreadableNode(), PUBLIC_A)


def test_reconcile_coordinator_counts_busy_moves_and_skips_stopped_nodes() -> None:
    store = camera_store()
    factory = RecordingMediaNodeFactory()

    class BusyMoves(CameraMoveReconciler):
        def resume(
            self,
            move_id: UUID,
            *,
            cancelled: Callable[[], bool] = lambda: False,
        ) -> CameraMove:
            raise NodeLifecycleBusy("busy")

    move, _ = move_services(store, factory)
    requested = move.request_move(CAMERA_A, target_node_id=NODE_B)
    stopped = store.get_node(NODE_B)
    assert stopped is not None
    store.apply_runtime_observation(
        NODE_B,
        NodeRuntimeObservation(state=NodeState.STOPPED, health=NodeHealth.UNKNOWN),
    )
    report = ReconcileCoordinator(
        store=store,
        cameras=CameraReconciler(store=store, media_nodes=factory),
        moves=BusyMoves(store=store, media_nodes=factory),
    ).run_once()

    assert requested.state is CameraMoveState.PREPARE_TARGET
    assert report.retryable_failures == 1
    assert report.reconciled_nodes == 1
