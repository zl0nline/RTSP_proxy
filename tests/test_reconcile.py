from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest

from rtsp_proxy.database import PostgresNodeStore
from rtsp_proxy.identifiers import PublicId
from rtsp_proxy.media import MediaNodeUnavailable, MediaPathConfig, MediaPathInventory
from rtsp_proxy.migrate import upgrade_database
from rtsp_proxy.nodes import (
    CameraControl,
    CameraLifecycleConflict,
    CameraMoveState,
    CameraMoveStore,
    CameraState,
    InMemoryNodeStore,
    MediaNode,
    NodeHealth,
    NodeRuntimeObservation,
    NodeState,
)
from rtsp_proxy.reconcile import (
    CameraMoveControl,
    CameraMoveReconciler,
    CameraOccupied,
    CameraReconciler,
    CameraRuntimeObserver,
    ConfirmationTokenService,
    MediaNodeClient,
    MediaNodeClientFactory,
    MoveConfirmationRequired,
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
            no_oracle_matcher_present=False,
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
        observed_release_id="v1.20.0",
    )


def camera_store() -> InMemoryNodeStore:
    store = InMemoryNodeStore(nodes=(running_node(NODE_A, 12000), running_node(NODE_B, 12001)))
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
            release_id="v1.20.0",
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
            release_id="v1.20.0",
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
                release_id="v1.20.0",
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
