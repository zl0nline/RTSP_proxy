from __future__ import annotations

import errno
import hashlib
import socket
import time
import unicodedata
from collections.abc import Callable, Collection, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import AbstractContextManager, contextmanager, suppress
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from threading import Lock, RLock
from typing import Protocol
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from rtsp_proxy.identifiers import PublicId


class NodeState(StrEnum):
    PROVISIONING = "provisioning"
    STOPPED = "stopped"
    STOPPING = "stopping"
    STARTING = "starting"
    RUNNING = "running"
    DRAINING = "draining"
    MAINTENANCE = "maintenance"
    FAILED = "failed"
    DELETING = "deleting"


class NodeHealth(StrEnum):
    UNKNOWN = "unknown"
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"


class NodeRuntimeAction(StrEnum):
    PROVISION_START = "provision_start"
    START = "start"
    STOP = "stop"
    RESTART = "restart"
    RECONFIGURE_RESTART = "reconfigure_restart"
    DELETE = "delete"
    OBSERVE = "observe"


class NodeCreationMode(StrEnum):
    OPERATOR = "operator"
    AUTOMATIC = "automatic"


@dataclass(frozen=True, slots=True)
class NodeRuntimeObservation:
    state: NodeState
    health: NodeHealth
    management_fresh: bool = False
    config_compatible: bool = False
    applied_revision: int = 0
    process_id: int | None = None
    process_start_ticks: int | None = None
    process_boot_id: UUID | None = None
    config_sha256: str | None = None
    release_id: str | None = None


class NodeRuntime(Protocol):
    def execute(
        self,
        action: NodeRuntimeAction,
        node: MediaNode,
    ) -> NodeRuntimeObservation: ...


@dataclass(frozen=True, slots=True)
class MediaNode:
    id: UUID
    name: str
    external_port: int
    api_port: int = 20000
    metrics_port: int = 20100
    release_id: str = "0.1.0"
    mediamtx_binary_sha256: str = "0" * 64
    creation_mode: NodeCreationMode = NodeCreationMode.OPERATOR
    state: NodeState = NodeState.PROVISIONING
    runtime_state: NodeState = NodeState.PROVISIONING
    health: NodeHealth = NodeHealth.UNKNOWN
    registered_cameras: int = 0
    camera_capacity: int = 100
    active_sources: int = 0
    maintenance: bool = False
    management_fresh: bool = False
    management_observed_at: datetime | None = None
    runtime_observed_at: datetime | None = None
    config_compatible: bool = False
    desired_revision: int = 1
    applied_revision: int = 0
    process_id: int | None = None
    process_start_ticks: int | None = None
    process_boot_id: UUID | None = None
    observed_config_sha256: str | None = None
    observed_release_id: str | None = None


class PlacementMode(StrEnum):
    AUTOMATIC = "automatic"
    MANUAL = "manual"


class CameraState(StrEnum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    DELETING = "deleting"
    DELETED = "deleted"


class CameraMoveState(StrEnum):
    PREPARE_TARGET = "prepare_target"
    ACTIVATE_TARGET = "activate_target"
    CLEANUP_SOURCE = "cleanup_source"
    CLEANUP_TARGET = "cleanup_target"
    COMPLETE = "complete"
    ABORTED = "aborted"


@dataclass(frozen=True, slots=True)
class CameraMove:
    id: UUID
    camera_id: UUID
    public_id: PublicId
    source_url: str
    source_node_id: UUID
    target_node_id: UUID
    source_generation: int
    target_generation: int
    desired_revision: int
    force: bool
    confirmed_disconnect_readers: int
    source_port: int | None
    target_port: int | None
    source_endpoint: str | None
    target_endpoint: str | None
    expires_at: datetime
    abort_reason: str | None = None
    state: CameraMoveState = CameraMoveState.PREPARE_TARGET

    def __post_init__(self) -> None:
        if self.confirmed_disconnect_readers not in {0, 1}:
            raise ValueError("camera_move_confirmed_readers_invalid")
        if self.expires_at.tzinfo is None:
            raise ValueError("camera_move_expiry_timezone_required")
        for port in (self.source_port, self.target_port):
            if port is not None and not 1 <= port <= 65535:
                raise ValueError("camera_move_port_invalid")
        if (self.source_endpoint is None) != (self.source_port is None) or (
            self.target_endpoint is None
        ) != (self.target_port is None):
            raise ValueError("camera_move_endpoint_invalid")
        if not camera_move_is_terminal(self.state) and any(
            value is None
            for value in (
                self.source_port,
                self.target_port,
                self.source_endpoint,
                self.target_endpoint,
            )
        ):
            raise ValueError("camera_move_endpoint_invalid")


def camera_move_is_terminal(state: CameraMoveState) -> bool:
    return state in {CameraMoveState.COMPLETE, CameraMoveState.ABORTED}


class NodePortChangeState(StrEnum):
    PREPARED = "prepared"
    COMPLETE = "complete"
    ABORTED = "aborted"


@dataclass(frozen=True, slots=True)
class NodePortChange:
    id: UUID
    node_id: UUID
    old_port: int
    new_port: int
    source_revision: int
    target_revision: int
    registered_cameras: int
    blast_radius_sha256: str
    state: NodePortChangeState = NodePortChangeState.PREPARED


@dataclass(frozen=True, slots=True)
class NodePortChangePreview:
    node_id: UUID
    old_port: int
    new_port: int
    desired_revision: int
    registered_cameras: int
    blast_radius_sha256: str
    confirmation_token: str


@dataclass(frozen=True, slots=True)
class NodeReconfigurePreview:
    node_id: UUID
    external_port: int
    desired_revision: int
    registered_cameras: int
    blast_radius_sha256: str
    target_release_id: str
    target_mediamtx_binary_sha256: str
    confirmation_token: str


@dataclass(frozen=True, slots=True)
class CameraPlacement:
    id: UUID
    name: str
    source_url: str
    public_id: PublicId
    node_id: UUID
    node_port: int
    placement_mode: PlacementMode
    placement_generation: int = 1
    state: CameraState = CameraState.ENABLED
    desired_revision: int = 1
    applied_revision: int = 0


@dataclass(frozen=True, slots=True)
class CameraCatalogItem:
    id: UUID
    name: str
    public_id: PublicId
    node_id: UUID
    node_name: str
    node_port: int
    placement_mode: PlacementMode
    state: CameraState
    desired_revision: int
    applied_revision: int

    def __post_init__(self) -> None:
        validate_camera_name(self.name)


@dataclass(frozen=True, slots=True)
class CameraCatalogQuery:
    after: UUID | None = None
    limit: int = 50
    search: str | None = None
    node_id: UUID | None = None
    state: CameraState | None = None

    def __post_init__(self) -> None:
        if not 1 <= self.limit <= 100:
            raise ValueError("camera_catalog_limit_invalid")
        if self.search is None:
            return
        normalized = self.search.strip()
        if (
            not normalized
            or len(normalized) < 3
            or len(normalized) > 128
            or any(ord(character) < 32 for character in normalized)
        ):
            raise ValueError("camera_catalog_search_invalid")
        object.__setattr__(self, "search", normalized)


@dataclass(frozen=True, slots=True)
class CameraCatalogPage:
    items: tuple[CameraCatalogItem, ...]
    next_after: UUID | None

    def __post_init__(self) -> None:
        if len(self.items) > 100 or tuple(sorted(item.id for item in self.items)) != tuple(
            item.id for item in self.items
        ):
            raise ValueError("camera_catalog_page_invalid")
        if self.next_after is not None and (
            not self.items or self.next_after != self.items[-1].id
        ):
            raise ValueError("camera_catalog_cursor_invalid")


class CameraCatalogUnavailable(RuntimeError):
    """The bounded, secret-free camera catalog cannot be read safely."""


PortChoice = Callable[[tuple[int, ...]], int]
NodeIdFactory = Callable[[], UUID]
PublicIdFactory = Callable[[], str]
PortBindable = Callable[[int], bool]


@dataclass(frozen=True, slots=True)
class NodeProvisioningPolicy:
    port_range_start: int
    port_range_end: int
    max_nodes: int
    reserved_ports: tuple[int, ...]
    api_ports: tuple[int, ...]
    metrics_ports: tuple[int, ...]
    release_id: str
    mediamtx_binary_sha256: str
    management_freshness_seconds: int = 30


class NodePortRangeExhausted(RuntimeError):
    """No external port remains available for a new media node."""


class NodeManagementPortRangeExhausted(RuntimeError):
    """No complete loopback API/metrics port pair remains available."""


class MaximumNodesReached(RuntimeError):
    """The configured server node limit has been reached."""


class NodePortOutOfRange(ValueError):
    """A requested external port is outside the configured range."""


class NodePortInUse(RuntimeError):
    """A requested external port is already assigned to another node."""


class NodeCameraCapacityReached(RuntimeError):
    """A media node already contains its maximum registered cameras."""


class NodeNotEmpty(RuntimeError):
    """A lifecycle operation requires a node without registered cameras."""


class NodeLifecycleConflict(RuntimeError):
    """The requested operation is not valid from the desired lifecycle state."""


class NodeLifecycleBusy(NodeLifecycleConflict):
    """Lifecycle serialization capacity is temporarily unavailable."""


class NodeReleaseConflict(RuntimeError):
    """A release transition requires an empty, stopped and converged node."""


class NodeNotFound(LookupError):
    """A requested node does not exist."""


class NodeRuntimeUnavailable(RuntimeError):
    """The Linux process adapter is not configured."""


class NodeRuntimeFailed(RuntimeError):
    """The exact node operation failed; no other node was targeted."""

    def __init__(self, code: str, *, node_id: UUID) -> None:
        super().__init__(code)
        self.code = code
        self.node_id = node_id


class InvalidNodeRuntimeObservation(ValueError):
    """Runtime evidence is incomplete or does not match desired node identity."""


class EligibleNodeMissing(RuntimeError):
    """No running healthy node has camera capacity."""


class InvalidCameraSource(ValueError):
    """A camera source endpoint is invalid or contains an unencrypted secret."""


class InvalidCameraName(ValueError):
    """A camera display name cannot be represented consistently by all adapters."""


class CameraNotFound(LookupError):
    """A requested camera does not exist."""


class CameraLifecycleConflict(RuntimeError):
    """The camera command conflicts with its desired lifecycle state."""


class CameraRevisionConflict(CameraLifecycleConflict):
    """The submitted camera revision is no longer authoritative."""

    def __init__(self, *, expected_revision: int, current_revision: int) -> None:
        super().__init__("camera_revision_conflict")
        self.expected_revision = expected_revision
        self.current_revision = current_revision


class CameraMoveExpired(CameraLifecycleConflict):
    """A prepared move reached its durable switch deadline."""


MAX_CAMERA_SOURCE_URL_BYTES = 8192
MAX_CAMERA_NAME_LENGTH = 128


class NodeDisruptionConfirmations(Protocol):
    def issue_node_port_change(
        self,
        *,
        node_id: UUID,
        old_port: int,
        new_port: int,
        desired_revision: int,
        registered_cameras: int,
        blast_radius_sha256: str,
    ) -> str: ...

    def verify_node_port_change(
        self,
        token: str,
        *,
        node_id: UUID,
        old_port: int,
        new_port: int,
        desired_revision: int,
        registered_cameras: int,
        blast_radius_sha256: str,
    ) -> bool: ...

    def issue_node_reconfigure(
        self,
        *,
        node_id: UUID,
        external_port: int,
        desired_revision: int,
        registered_cameras: int,
        blast_radius_sha256: str,
        target_release_id: str,
        target_mediamtx_binary_sha256: str,
    ) -> str: ...

    def verify_node_reconfigure(
        self,
        token: str,
        *,
        node_id: UUID,
        external_port: int,
        desired_revision: int,
        registered_cameras: int,
        blast_radius_sha256: str,
        target_release_id: str,
        target_mediamtx_binary_sha256: str,
    ) -> bool: ...


class NodeDisruptionConfirmationRequired(RuntimeError):
    """A disruptive node operation lacks an exact current confirmation."""


class InMemoryNodeStore:
    """Thread-safe development adapter for the future PostgreSQL node store."""

    def __init__(
        self,
        *,
        nodes: tuple[MediaNode, ...] = (),
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._nodes: list[MediaNode] = list(nodes)
        self._cameras: list[CameraPlacement] = []
        self._camera_moves: list[CameraMove] = []
        self._port_changes: list[NodePortChange] = []
        self._lock = RLock()
        self._lifecycle_locks = {node.id: Lock() for node in nodes}
        self._clock = clock

    @contextmanager
    def provisioning_guard(self) -> Iterator[None]:
        with self._lock:
            yield

    @contextmanager
    def lifecycle_guard(self, node_id: UUID) -> Iterator[None]:
        with self._lock:
            node_lock = self._lifecycle_locks.get(node_id)
            if node_lock is None:
                raise NodeNotFound("node_not_found")
        with node_lock:
            yield

    @contextmanager
    def reconcile_guard(
        self,
        node_id: UUID,
        *,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> Iterator[None]:
        with self._lock:
            node_lock = self._lifecycle_locks.get(node_id)
            if node_lock is None:
                raise NodeNotFound("node_not_found")
        while True:
            if cancelled():
                raise NodeLifecycleBusy("node_lifecycle_busy")
            if node_lock.acquire(timeout=0.05):
                break
        try:
            yield
        finally:
            node_lock.release()

    def register_automatically(
        self,
        *,
        name: str,
        allowed_ports: Collection[int],
        max_nodes: int,
        preferred_port: int | None,
        choose_port: PortChoice,
        new_node_id: NodeIdFactory,
        api_ports: Collection[int] = tuple(range(20000, 20100)),
        metrics_ports: Collection[int] = tuple(range(20100, 20200)),
        release_id: str = "0.1.0",
        mediamtx_binary_sha256: str = "0" * 64,
        creation_mode: NodeCreationMode = NodeCreationMode.OPERATOR,
        is_port_bindable: PortBindable | None = None,
    ) -> MediaNode:
        with self._lock:
            if preferred_port is not None and preferred_port not in allowed_ports:
                raise NodePortOutOfRange("node_port_out_of_range")
            if len(self._nodes) >= max_nodes:
                raise MaximumNodesReached("max_nodes_reached")
            occupied = {node.external_port for node in self._nodes}
            occupied.update(
                change.new_port
                for change in self._port_changes
                if change.state is NodePortChangeState.PREPARED
            )
            if preferred_port is not None and preferred_port in occupied:
                raise NodePortInUse("node_port_in_use")
            available = tuple(port for port in allowed_ports if port not in occupied)
            if not available:
                raise NodePortRangeExhausted("node_port_range_exhausted")
            probe = is_port_bindable or (lambda port: True)
            external_port = select_port_with_bounded_recheck(
                available,
                preferred_port=preferred_port,
                choose_port=choose_port,
                is_port_bindable=probe,
            )
            occupied_management = {
                port for node in self._nodes for port in (node.api_port, node.metrics_port)
            }
            available_api = tuple(port for port in api_ports if port not in occupied_management)
            available_metrics = tuple(
                port for port in metrics_ports if port not in occupied_management
            )
            if not available_api or not available_metrics:
                raise NodeManagementPortRangeExhausted("node_management_port_range_exhausted")
            try:
                api_port = select_port_with_bounded_recheck(
                    available_api,
                    preferred_port=None,
                    choose_port=lambda candidates: candidates[0],
                    is_port_bindable=probe,
                )
                metrics_port = select_port_with_bounded_recheck(
                    tuple(
                        port for port in available_metrics if port not in {external_port, api_port}
                    ),
                    preferred_port=None,
                    choose_port=lambda candidates: candidates[0],
                    is_port_bindable=probe,
                )
            except NodePortRangeExhausted:
                raise NodeManagementPortRangeExhausted(
                    "node_management_port_range_exhausted"
                ) from None
            node = MediaNode(
                id=new_node_id(),
                name=name,
                external_port=external_port,
                api_port=api_port,
                metrics_port=metrics_port,
                release_id=release_id,
                mediamtx_binary_sha256=mediamtx_binary_sha256,
                creation_mode=creation_mode,
            )
            self._nodes.append(node)
            self._lifecycle_locks[node.id] = Lock()
            return node

    def list_nodes(self) -> tuple[MediaNode, ...]:
        with self._lock:
            return tuple(self._nodes)

    def get_node(self, node_id: UUID) -> MediaNode | None:
        with self._lock:
            return next((node for node in self._nodes if node.id == node_id), None)

    def apply_runtime_observation(
        self,
        node_id: UUID,
        observation: NodeRuntimeObservation,
    ) -> MediaNode:
        with self._lock:
            node = next((candidate for candidate in self._nodes if candidate.id == node_id), None)
            if node is None:
                raise NodeNotFound("node_not_found")
            validate_runtime_observation(node, observation)
            observed_at = datetime.now(UTC)
            updated = replace(
                node,
                runtime_state=observation.state,
                health=observation.health,
            )
            updated = replace(
                updated,
                management_fresh=observation.management_fresh,
                management_observed_at=(observed_at if observation.management_fresh else None),
                runtime_observed_at=observed_at,
                config_compatible=observation.config_compatible,
                applied_revision=observation.applied_revision,
                process_id=observation.process_id,
                process_start_ticks=observation.process_start_ticks,
                process_boot_id=observation.process_boot_id,
                observed_config_sha256=observation.config_sha256,
                observed_release_id=observation.release_id,
            )
            self._nodes[self._nodes.index(node)] = updated
            return updated

    def request_desired_state(self, node_id: UUID, state: NodeState) -> MediaNode:
        with self._lock:
            node = next((candidate for candidate in self._nodes if candidate.id == node_id), None)
            if node is None:
                raise NodeNotFound("node_not_found")
            if node.state is state:
                return node
            updated = replace(
                node,
                state=state,
                desired_revision=node.desired_revision + 1,
            )
            self._nodes[self._nodes.index(node)] = updated
            return updated

    def request_administrative_state(
        self,
        node_id: UUID,
        state: NodeState,
    ) -> MediaNode:
        with self._lock:
            node = next((candidate for candidate in self._nodes if candidate.id == node_id), None)
            if node is None:
                raise NodeNotFound("node_not_found")
            allowed = {
                NodeState.DRAINING: {NodeState.RUNNING},
                NodeState.MAINTENANCE: {NodeState.DRAINING},
                NodeState.RUNNING: {NodeState.DRAINING, NodeState.MAINTENANCE},
            }
            if state not in allowed or node.state not in allowed[state]:
                if node.state is state:
                    return node
                raise NodeLifecycleConflict("node_administrative_transition_invalid")
            desired_revision = node.desired_revision + 1
            updated = replace(
                node,
                state=state,
                maintenance=state is NodeState.MAINTENANCE,
                desired_revision=desired_revision,
                applied_revision=desired_revision,
            )
            self._nodes[self._nodes.index(node)] = updated
            return updated

    def begin_port_change(
        self,
        *,
        change_id: UUID,
        node_id: UUID,
        new_port: int,
        allowed_ports: Collection[int],
        expected_revision: int,
        expected_registered_cameras: int,
        expected_blast_radius_sha256: str,
    ) -> NodePortChange:
        with self._lock:
            node = next((candidate for candidate in self._nodes if candidate.id == node_id), None)
            if node is None:
                raise NodeNotFound("node_not_found")
            if new_port not in allowed_ports:
                raise NodePortOutOfRange("node_port_out_of_range")
            if node.state is not NodeState.RUNNING or node.runtime_state is not NodeState.RUNNING:
                raise NodeLifecycleConflict("node_not_running")
            if node.desired_revision != expected_revision:
                raise NodeLifecycleConflict("node_revision_conflict")
            cameras = tuple(
                camera
                for camera in self._cameras
                if camera.node_id == node_id and camera.state is not CameraState.DELETED
            )
            blast_radius_sha256 = camera_placement_fingerprint(
                tuple((camera.id, camera.placement_generation) for camera in cameras)
            )
            if (
                node.registered_cameras != expected_registered_cameras
                or len(cameras) != expected_registered_cameras
                or blast_radius_sha256 != expected_blast_radius_sha256
            ):
                raise NodeLifecycleConflict("node_blast_radius_changed")
            if node.external_port == new_port:
                raise NodeLifecycleConflict("node_port_unchanged")
            if any(
                candidate.external_port == new_port and candidate.id != node_id
                for candidate in self._nodes
            ) or any(
                change.new_port == new_port and change.state is NodePortChangeState.PREPARED
                for change in self._port_changes
            ):
                raise NodePortInUse("node_port_in_use")
            if any(
                change.node_id == node_id and change.state is NodePortChangeState.PREPARED
                for change in self._port_changes
            ):
                raise NodeLifecycleConflict("node_port_change_in_progress")
            if self.list_node_active_moves(node_id):
                raise NodeLifecycleConflict("node_camera_move_in_progress")
            change = NodePortChange(
                id=change_id,
                node_id=node_id,
                old_port=node.external_port,
                new_port=new_port,
                source_revision=node.desired_revision,
                target_revision=node.desired_revision + 1,
                registered_cameras=expected_registered_cameras,
                blast_radius_sha256=expected_blast_radius_sha256,
            )
            self._port_changes.append(change)
            return change

    def list_incomplete_port_changes(self) -> tuple[NodePortChange, ...]:
        with self._lock:
            return tuple(
                change
                for change in self._port_changes
                if change.state is NodePortChangeState.PREPARED
            )

    def complete_port_change(
        self,
        change_id: UUID,
        observation: NodeRuntimeObservation,
    ) -> MediaNode:
        with self._lock:
            change = next(
                (candidate for candidate in self._port_changes if candidate.id == change_id),
                None,
            )
            if change is None:
                raise NodeNotFound("node_port_change_not_found")
            node = next(candidate for candidate in self._nodes if candidate.id == change.node_id)
            if change.state is NodePortChangeState.COMPLETE:
                return node
            if change.state is not NodePortChangeState.PREPARED:
                raise NodeLifecycleConflict("node_port_change_not_prepared")
            provisional = replace(
                node,
                external_port=change.new_port,
                desired_revision=change.target_revision,
            )
            validate_runtime_observation(provisional, observation)
            observed_at = datetime.now(UTC)
            updated = replace(
                provisional,
                runtime_state=observation.state,
                health=observation.health,
                management_fresh=observation.management_fresh,
                management_observed_at=(observed_at if observation.management_fresh else None),
                runtime_observed_at=observed_at,
                config_compatible=observation.config_compatible,
                applied_revision=observation.applied_revision,
                process_id=observation.process_id,
                process_start_ticks=observation.process_start_ticks,
                process_boot_id=observation.process_boot_id,
                observed_config_sha256=observation.config_sha256,
                observed_release_id=observation.release_id,
            )
            self._nodes[self._nodes.index(node)] = updated
            self._cameras = [
                replace(camera, node_port=change.new_port)
                if camera.node_id == node.id and camera.state is not CameraState.DELETED
                else camera
                for camera in self._cameras
            ]
            self._port_changes[self._port_changes.index(change)] = replace(
                change,
                state=NodePortChangeState.COMPLETE,
            )
            return updated

    def abort_port_change(
        self,
        change_id: UUID,
        observation: NodeRuntimeObservation,
    ) -> MediaNode:
        with self._lock:
            change = next(
                (candidate for candidate in self._port_changes if candidate.id == change_id),
                None,
            )
            if change is None:
                raise NodeNotFound("node_port_change_not_found")
            node = next(candidate for candidate in self._nodes if candidate.id == change.node_id)
            if change.state is NodePortChangeState.ABORTED:
                return node
            if change.state is not NodePortChangeState.PREPARED:
                raise NodeLifecycleConflict("node_port_change_not_prepared")
            restored = replace(
                node,
                external_port=change.old_port,
                desired_revision=change.source_revision,
            )
            validate_runtime_observation(restored, observation)
            observed_at = datetime.now(UTC)
            updated = replace(
                restored,
                runtime_state=observation.state,
                health=observation.health,
                management_fresh=observation.management_fresh,
                management_observed_at=(observed_at if observation.management_fresh else None),
                runtime_observed_at=observed_at,
                config_compatible=observation.config_compatible,
                applied_revision=observation.applied_revision,
                process_id=observation.process_id,
                process_start_ticks=observation.process_start_ticks,
                process_boot_id=observation.process_boot_id,
                observed_config_sha256=observation.config_sha256,
                observed_release_id=observation.release_id,
            )
            self._nodes[self._nodes.index(node)] = updated
            self._port_changes[self._port_changes.index(change)] = replace(
                change,
                state=NodePortChangeState.ABORTED,
            )
            return updated

    def request_node_delete(self, node_id: UUID) -> MediaNode:
        with self._lock:
            node = next((candidate for candidate in self._nodes if candidate.id == node_id), None)
            if node is None:
                raise NodeNotFound("node_not_found")
            if node.registered_cameras:
                raise NodeNotEmpty("node_not_empty")
            if node.state not in {NodeState.STOPPED, NodeState.FAILED, NodeState.DELETING}:
                raise NodeLifecycleConflict("node_delete_requires_stopped_or_failed")
            if self.list_node_active_moves(node_id) or any(
                change.node_id == node_id and change.state is NodePortChangeState.PREPARED
                for change in self._port_changes
            ):
                raise NodeLifecycleConflict("node_operation_in_progress")
            if node.state is NodeState.DELETING:
                return node
            updated = replace(
                node,
                state=NodeState.DELETING,
                desired_revision=node.desired_revision + 1,
                management_fresh=False,
                management_observed_at=None,
            )
            self._nodes[self._nodes.index(node)] = updated
            return updated

    def finalize_node_delete(self, node_id: UUID) -> None:
        with self._lock:
            node = next((candidate for candidate in self._nodes if candidate.id == node_id), None)
            if node is None:
                return
            if node.state is not NodeState.DELETING or node.registered_cameras:
                raise NodeLifecycleConflict("node_delete_not_ready")
            self._nodes.remove(node)
            self._lifecycle_locks.pop(node_id, None)

    def request_stop(self, node_id: UUID) -> MediaNode:
        with self._lock:
            node = next((candidate for candidate in self._nodes if candidate.id == node_id), None)
            if node is None:
                raise NodeNotFound("node_not_found")
            if self.list_node_active_moves(node_id):
                raise NodeLifecycleConflict("node_operation_in_progress")
            if node.registered_cameras:
                raise NodeNotEmpty("node_not_empty")
            if node.state is NodeState.STOPPED:
                return node
            updated = replace(
                node,
                state=NodeState.STOPPED,
                maintenance=False,
                desired_revision=node.desired_revision + 1,
            )
            self._nodes[self._nodes.index(node)] = updated
            return updated

    def request_restart(self, node_id: UUID) -> MediaNode:
        with self._lock:
            node = next((candidate for candidate in self._nodes if candidate.id == node_id), None)
            if node is None:
                raise NodeNotFound("node_not_found")
            if self.list_node_active_moves(node_id):
                raise NodeLifecycleConflict("node_operation_in_progress")
            if node.state is not NodeState.RUNNING:
                raise NodeLifecycleConflict("node_not_running")
            if node.registered_cameras:
                raise NodeNotEmpty("node_not_empty")
            updated = replace(node, desired_revision=node.desired_revision + 1)
            self._nodes[self._nodes.index(node)] = updated
            return updated

    def request_reconfigure(
        self,
        node_id: UUID,
        *,
        expected_revision: int,
        expected_registered_cameras: int,
        expected_blast_radius_sha256: str,
        release_id: str | None = None,
        mediamtx_binary_sha256: str | None = None,
    ) -> MediaNode:
        if (release_id is None) != (mediamtx_binary_sha256 is None):
            raise ValueError("node_release_identity_incomplete")
        if release_id is not None and mediamtx_binary_sha256 is not None:
            NodeRuntimeSpecLike.validate_release(release_id, mediamtx_binary_sha256)
        with self._lock:
            node = next((candidate for candidate in self._nodes if candidate.id == node_id), None)
            if node is None:
                raise NodeNotFound("node_not_found")
            if node.state is not NodeState.DRAINING:
                raise NodeLifecycleConflict("node_not_draining")
            if node.runtime_state not in {
                NodeState.RUNNING,
                NodeState.STOPPED,
                NodeState.FAILED,
            }:
                raise NodeLifecycleConflict("node_reconfigure_runtime_invalid")
            if node.desired_revision != expected_revision:
                raise NodeLifecycleConflict("node_revision_conflict")
            if self.list_node_active_moves(node_id) or any(
                change.node_id == node_id and change.state is NodePortChangeState.PREPARED
                for change in self._port_changes
            ):
                raise NodeLifecycleConflict("node_operation_in_progress")
            cameras = tuple(
                camera
                for camera in self._cameras
                if camera.node_id == node_id and camera.state is not CameraState.DELETED
            )
            blast_radius_sha256 = camera_placement_fingerprint(
                tuple((camera.id, camera.placement_generation) for camera in cameras)
            )
            if (
                node.registered_cameras != expected_registered_cameras
                or len(cameras) != expected_registered_cameras
                or blast_radius_sha256 != expected_blast_radius_sha256
            ):
                raise NodeLifecycleConflict("node_blast_radius_changed")
            release_changed = release_id is not None and (
                node.release_id != release_id
                or node.mediamtx_binary_sha256 != mediamtx_binary_sha256
            )
            updated = replace(
                node,
                release_id=node.release_id if release_id is None else release_id,
                mediamtx_binary_sha256=(
                    node.mediamtx_binary_sha256
                    if mediamtx_binary_sha256 is None
                    else mediamtx_binary_sha256
                ),
                desired_revision=node.desired_revision + 1,
                applied_revision=0 if release_changed else node.applied_revision,
                management_fresh=False,
                management_observed_at=None,
                config_compatible=False,
            )
            self._nodes[self._nodes.index(node)] = updated
            return updated

    def request_release(
        self,
        node_id: UUID,
        *,
        release_id: str,
        mediamtx_binary_sha256: str,
    ) -> MediaNode:
        NodeRuntimeSpecLike.validate_release(release_id, mediamtx_binary_sha256)
        with self._lock:
            node = next((candidate for candidate in self._nodes if candidate.id == node_id), None)
            if node is None:
                raise NodeNotFound("node_not_found")
            if self.list_node_active_moves(node_id):
                raise NodeLifecycleConflict("node_operation_in_progress")
            if (
                node.state is not NodeState.STOPPED
                or node.runtime_state is not NodeState.STOPPED
                or node.registered_cameras
                or node.applied_revision != node.desired_revision
            ):
                raise NodeReleaseConflict("node_release_transition_requires_stopped_empty")
            if (
                node.release_id == release_id
                and node.mediamtx_binary_sha256 == mediamtx_binary_sha256
            ):
                return node
            updated = replace(
                node,
                release_id=release_id,
                mediamtx_binary_sha256=mediamtx_binary_sha256,
                desired_revision=node.desired_revision + 1,
                applied_revision=0,
                config_compatible=False,
                management_fresh=False,
                management_observed_at=None,
            )
            self._nodes[self._nodes.index(node)] = updated
            return updated

    def place_camera_automatically(
        self,
        *,
        camera_id: UUID,
        name: str,
        source_url: str,
        public_id: PublicId,
        management_freshness_seconds: int = 30,
    ) -> CameraPlacement:
        name = validate_camera_name(name)
        source_url = validate_camera_source_url(source_url)
        with self._lock:
            eligible = [
                node
                for node in self._nodes
                if is_node_eligible(
                    node,
                    management_freshness_seconds=management_freshness_seconds,
                )
                and not self._node_has_prepared_port_change(node.id)
            ]
            if not eligible:
                raise EligibleNodeMissing("eligible_node_missing")
            else:
                selected = min(
                    eligible,
                    key=lambda node: (
                        node.registered_cameras,
                        node.active_sources,
                        node.id.int,
                    ),
                )
            placement = CameraPlacement(
                id=camera_id,
                name=name,
                source_url=source_url,
                public_id=public_id,
                node_id=selected.id,
                node_port=selected.external_port,
                placement_mode=PlacementMode.AUTOMATIC,
            )
            self._cameras.append(placement)
            selected_index = self._nodes.index(selected)
            self._nodes[selected_index] = replace(
                selected,
                registered_cameras=selected.registered_cameras + 1,
            )
            return placement

    def place_camera_manually(
        self,
        *,
        camera_id: UUID,
        name: str,
        source_url: str,
        public_id: PublicId,
        node_id: UUID,
        management_freshness_seconds: int = 30,
    ) -> CameraPlacement:
        name = validate_camera_name(name)
        source_url = validate_camera_source_url(source_url)
        with self._lock:
            selected = next((node for node in self._nodes if node.id == node_id), None)
            if selected is None:
                raise NodeNotFound("node_not_found")
            if selected.registered_cameras >= selected.camera_capacity:
                raise NodeCameraCapacityReached("node_camera_capacity_reached")
            if self._node_has_prepared_port_change(node_id):
                raise EligibleNodeMissing("manual_node_ineligible")
            if not is_node_eligible(
                selected,
                management_freshness_seconds=management_freshness_seconds,
            ):
                raise EligibleNodeMissing("manual_node_ineligible")
            placement = CameraPlacement(
                id=camera_id,
                name=name,
                source_url=source_url,
                public_id=public_id,
                node_id=selected.id,
                node_port=selected.external_port,
                placement_mode=PlacementMode.MANUAL,
            )
            self._cameras.append(placement)
            selected_index = self._nodes.index(selected)
            self._nodes[selected_index] = replace(
                selected,
                registered_cameras=selected.registered_cameras + 1,
            )
            return placement

    def list_cameras(self) -> tuple[CameraPlacement, ...]:
        with self._lock:
            return tuple(
                camera for camera in self._cameras if camera.state is not CameraState.DELETED
            )

    def camera_catalog(self, query: CameraCatalogQuery) -> CameraCatalogPage:
        with self._lock:
            node_names = {node.id: node.name for node in self._nodes}
            candidates = sorted(
                (
                    camera
                    for camera in self._cameras
                    if camera.state is not CameraState.DELETED
                    and (query.after is None or camera.id > query.after)
                    and (query.node_id is None or camera.node_id == query.node_id)
                    and (query.state is None or camera.state is query.state)
                    and (
                        query.search is None
                        or query.search in camera.name
                        or query.search in str(camera.public_id)
                    )
                ),
                key=lambda camera: camera.id.int,
            )
            selected = candidates[: query.limit + 1]
            has_more = len(selected) > query.limit
            items = tuple(
                _camera_catalog_item(camera, node_name=node_names[camera.node_id])
                for camera in selected[: query.limit]
            )
            return CameraCatalogPage(
                items=items,
                next_after=items[-1].id if has_more else None,
            )

    def camera_detail(self, camera_id: UUID) -> CameraCatalogItem | None:
        with self._lock:
            camera = next(
                (
                    candidate
                    for candidate in self._cameras
                    if candidate.id == camera_id
                    and candidate.state is not CameraState.DELETED
                ),
                None,
            )
            if camera is None:
                return None
            node = next(
                (candidate for candidate in self._nodes if candidate.id == camera.node_id),
                None,
            )
            if node is None:
                raise CameraCatalogUnavailable("camera_catalog_unavailable")
            return _camera_catalog_item(camera, node_name=node.name)

    def get_camera(self, camera_id: UUID) -> CameraPlacement | None:
        with self._lock:
            return next(
                (
                    camera
                    for camera in self._cameras
                    if camera.id == camera_id and camera.state is not CameraState.DELETED
                ),
                None,
            )

    def list_node_cameras(self, node_id: UUID) -> tuple[CameraPlacement, ...]:
        with self._lock:
            if not any(node.id == node_id for node in self._nodes):
                raise NodeNotFound("node_not_found")
            return tuple(
                camera
                for camera in self._cameras
                if camera.node_id == node_id and camera.state is not CameraState.DELETED
            )

    def list_node_active_moves(self, node_id: UUID) -> tuple[CameraMove, ...]:
        with self._lock:
            return tuple(
                move
                for move in self._camera_moves
                if node_id in {move.source_node_id, move.target_node_id}
                and not camera_move_is_terminal(move.state)
            )

    def update_camera(
        self,
        camera_id: UUID,
        *,
        name: str,
        source_url: str,
        expected_revision: int | None = None,
    ) -> CameraPlacement:
        name = validate_camera_name(name)
        source_url = validate_camera_source_url(source_url)
        with self._lock:
            camera = next(
                (candidate for candidate in self._cameras if candidate.id == camera_id),
                None,
            )
            if camera is None:
                raise CameraNotFound("camera_not_found")
            if camera.state is CameraState.DELETED:
                raise CameraNotFound("camera_not_found")
            if camera.state is CameraState.DELETING:
                raise CameraLifecycleConflict("camera_deleting")
            if expected_revision is not None and camera.desired_revision != expected_revision:
                raise CameraRevisionConflict(
                    expected_revision=expected_revision,
                    current_revision=camera.desired_revision,
                )
            self._require_no_active_camera_move(camera_id)
            if self._node_has_prepared_port_change(camera.node_id):
                raise CameraLifecycleConflict("node_port_change_in_progress")
            if camera.name == name and camera.source_url == source_url:
                return camera
            updated = replace(
                camera,
                name=name,
                source_url=source_url,
                desired_revision=camera.desired_revision + 1,
            )
            self._cameras[self._cameras.index(camera)] = updated
            return updated

    def set_camera_enabled(
        self,
        camera_id: UUID,
        *,
        enabled: bool,
        expected_revision: int | None = None,
    ) -> CameraPlacement:
        with self._lock:
            camera = next(
                (candidate for candidate in self._cameras if candidate.id == camera_id),
                None,
            )
            if camera is None or camera.state is CameraState.DELETED:
                raise CameraNotFound("camera_not_found")
            if camera.state is CameraState.DELETING:
                raise CameraLifecycleConflict("camera_deleting")
            if expected_revision is not None and camera.desired_revision != expected_revision:
                raise CameraRevisionConflict(
                    expected_revision=expected_revision,
                    current_revision=camera.desired_revision,
                )
            self._require_no_active_camera_move(camera_id)
            if self._node_has_prepared_port_change(camera.node_id):
                raise CameraLifecycleConflict("node_port_change_in_progress")
            target = CameraState.ENABLED if enabled else CameraState.DISABLED
            if camera.state is target:
                return camera
            updated = replace(
                camera,
                state=target,
                desired_revision=camera.desired_revision + 1,
            )
            self._cameras[self._cameras.index(camera)] = updated
            return updated

    def request_camera_delete(
        self,
        camera_id: UUID,
        *,
        expected_revision: int | None = None,
    ) -> CameraPlacement:
        with self._lock:
            camera = next(
                (candidate for candidate in self._cameras if candidate.id == camera_id),
                None,
            )
            if camera is None or camera.state is CameraState.DELETED:
                raise CameraNotFound("camera_not_found")
            if expected_revision is not None and camera.desired_revision != expected_revision:
                raise CameraRevisionConflict(
                    expected_revision=expected_revision,
                    current_revision=camera.desired_revision,
                )
            if camera.state is CameraState.DELETING:
                return camera
            self._require_no_active_camera_move(camera_id)
            if self._node_has_prepared_port_change(camera.node_id):
                raise CameraLifecycleConflict("node_port_change_in_progress")
            updated = replace(
                camera,
                state=CameraState.DELETING,
                desired_revision=camera.desired_revision + 1,
            )
            self._cameras[self._cameras.index(camera)] = updated
            return updated

    def create_camera_move(
        self,
        *,
        move_id: UUID,
        camera_id: UUID,
        target_node_id: UUID,
        expected_revision: int,
        force: bool,
        confirmed_disconnect_readers: int = 0,
        timeout_seconds: int = 300,
    ) -> CameraMove:
        if timeout_seconds < 1 or timeout_seconds > 3600:
            raise ValueError("camera_move_timeout_invalid")
        with self._lock:
            camera = next(
                (candidate for candidate in self._cameras if candidate.id == camera_id),
                None,
            )
            target = next(
                (candidate for candidate in self._nodes if candidate.id == target_node_id),
                None,
            )
            if camera is None or camera.state is CameraState.DELETED:
                raise CameraNotFound("camera_not_found")
            if camera.state is not CameraState.ENABLED:
                raise CameraLifecycleConflict("camera_not_enabled")
            if camera.desired_revision != expected_revision:
                raise CameraRevisionConflict(
                    expected_revision=expected_revision,
                    current_revision=camera.desired_revision,
                )
            if camera.node_id == target_node_id:
                raise CameraLifecycleConflict("camera_already_on_target")
            if target is None:
                raise NodeNotFound("node_not_found")
            if not is_node_eligible(target):
                raise EligibleNodeMissing("manual_node_ineligible")
            if self._node_has_prepared_port_change(camera.node_id) or (
                self._node_has_prepared_port_change(target_node_id)
            ):
                raise CameraLifecycleConflict("node_port_change_in_progress")
            if any(
                move.camera_id == camera_id and not camera_move_is_terminal(move.state)
                for move in self._camera_moves
            ):
                raise CameraLifecycleConflict("camera_move_in_progress")
            source = next(node for node in self._nodes if node.id == camera.node_id)
            desired_revision = camera.desired_revision + 1
            move = CameraMove(
                id=move_id,
                camera_id=camera.id,
                public_id=camera.public_id,
                source_url=camera.source_url,
                source_node_id=camera.node_id,
                target_node_id=target_node_id,
                source_generation=camera.placement_generation,
                target_generation=camera.placement_generation + 1,
                desired_revision=desired_revision,
                force=force,
                confirmed_disconnect_readers=confirmed_disconnect_readers,
                source_port=source.external_port,
                target_port=target.external_port,
                source_endpoint=(
                    f"rtsp://server:{source.external_port}/{camera.public_id}"
                ),
                target_endpoint=f"rtsp://server:{target.external_port}/{camera.public_id}",
                expires_at=self._clock() + timedelta(seconds=timeout_seconds),
            )
            self._camera_moves.append(move)
            self._cameras[self._cameras.index(camera)] = replace(
                camera,
                desired_revision=desired_revision,
            )
            return move

    def get_camera_move(self, move_id: UUID) -> CameraMove | None:
        with self._lock:
            return next((move for move in self._camera_moves if move.id == move_id), None)

    def list_incomplete_camera_moves(self) -> tuple[CameraMove, ...]:
        with self._lock:
            return tuple(
                move for move in self._camera_moves if not camera_move_is_terminal(move.state)
            )

    def switch_camera_move(
        self,
        move_id: UUID,
        *,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> CameraMove:
        with self._lock:
            if cancelled():
                raise NodeLifecycleBusy("node_lifecycle_busy")
            move = next(
                (candidate for candidate in self._camera_moves if candidate.id == move_id),
                None,
            )
            if move is None:
                raise CameraNotFound("camera_move_not_found")
            if move.state is not CameraMoveState.PREPARE_TARGET:
                return move
            if move.expires_at <= self._clock():
                raise CameraMoveExpired("camera_move_expired")
            camera = next(
                candidate for candidate in self._cameras if candidate.id == move.camera_id
            )
            source = next(
                candidate for candidate in self._nodes if candidate.id == move.source_node_id
            )
            target = next(
                candidate for candidate in self._nodes if candidate.id == move.target_node_id
            )
            if (
                camera.node_id != move.source_node_id
                or camera.placement_generation != move.source_generation
                or camera.desired_revision != move.desired_revision
            ):
                raise CameraLifecycleConflict("camera_move_fenced")
            if target.registered_cameras >= target.camera_capacity:
                raise NodeCameraCapacityReached("node_camera_capacity_reached")
            if not is_node_eligible(target):
                raise EligibleNodeMissing("manual_node_ineligible")
            if self._node_has_prepared_port_change(source.id) or (
                self._node_has_prepared_port_change(target.id)
            ):
                raise CameraLifecycleConflict("node_port_change_in_progress")
            self._nodes[self._nodes.index(source)] = replace(
                source,
                registered_cameras=source.registered_cameras - 1,
            )
            self._nodes[self._nodes.index(target)] = replace(
                target,
                registered_cameras=target.registered_cameras + 1,
            )
            self._cameras[self._cameras.index(camera)] = replace(
                camera,
                node_id=target.id,
                node_port=target.external_port,
                placement_mode=PlacementMode.MANUAL,
                placement_generation=move.target_generation,
            )
            updated = replace(move, state=CameraMoveState.CLEANUP_SOURCE)
            self._camera_moves[self._camera_moves.index(move)] = updated
            return updated

    def mark_camera_move_source_cleaned(self, move_id: UUID) -> CameraMove:
        with self._lock:
            move = next(
                (candidate for candidate in self._camera_moves if candidate.id == move_id),
                None,
            )
            if move is None:
                raise CameraNotFound("camera_move_not_found")
            if move.state is CameraMoveState.ACTIVATE_TARGET:
                return move
            if move.state is not CameraMoveState.CLEANUP_SOURCE:
                raise CameraLifecycleConflict("camera_move_not_switched")
            updated = replace(move, state=CameraMoveState.ACTIVATE_TARGET)
            self._camera_moves[self._camera_moves.index(move)] = updated
            return updated

    def request_camera_move_abort(
        self,
        move_id: UUID,
        *,
        reason: str,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> CameraMove:
        with self._lock:
            if cancelled():
                raise NodeLifecycleBusy("node_lifecycle_busy")
            move = next(
                (candidate for candidate in self._camera_moves if candidate.id == move_id),
                None,
            )
            if move is None:
                raise CameraNotFound("camera_move_not_found")
            if camera_move_is_terminal(move.state) or move.state is CameraMoveState.CLEANUP_TARGET:
                return move
            if move.state is not CameraMoveState.PREPARE_TARGET:
                raise CameraLifecycleConflict("camera_move_already_switched")
            camera = next(
                candidate for candidate in self._cameras if candidate.id == move.camera_id
            )
            if camera.desired_revision == move.desired_revision:
                self._cameras[self._cameras.index(camera)] = replace(
                    camera,
                    desired_revision=camera.desired_revision + 1,
                )
            updated = replace(
                move,
                state=CameraMoveState.CLEANUP_TARGET,
                abort_reason=reason,
            )
            self._camera_moves[self._camera_moves.index(move)] = updated
            return updated

    def abort_camera_move(self, move_id: UUID) -> CameraMove:
        with self._lock:
            move = next(
                (candidate for candidate in self._camera_moves if candidate.id == move_id),
                None,
            )
            if move is None:
                raise CameraNotFound("camera_move_not_found")
            if move.state is CameraMoveState.ABORTED:
                return move
            if move.state is not CameraMoveState.CLEANUP_TARGET:
                raise CameraLifecycleConflict("camera_move_abort_not_prepared")
            updated = replace(move, state=CameraMoveState.ABORTED)
            self._camera_moves[self._camera_moves.index(move)] = updated
            return updated

    def _require_no_active_camera_move(self, camera_id: UUID) -> None:
        if any(
            move.camera_id == camera_id and not camera_move_is_terminal(move.state)
            for move in self._camera_moves
        ):
            raise CameraLifecycleConflict("camera_move_in_progress")

    def _node_has_prepared_port_change(self, node_id: UUID) -> bool:
        return any(
            change.node_id == node_id and change.state is NodePortChangeState.PREPARED
            for change in self._port_changes
        )

    def complete_camera_move(self, move_id: UUID) -> CameraMove:
        with self._lock:
            move = next(
                (candidate for candidate in self._camera_moves if candidate.id == move_id),
                None,
            )
            if move is None:
                raise CameraNotFound("camera_move_not_found")
            if move.state is CameraMoveState.COMPLETE:
                return move
            if move.state is not CameraMoveState.ACTIVATE_TARGET:
                raise CameraLifecycleConflict("camera_move_not_switched")
            camera = next(
                candidate for candidate in self._cameras if candidate.id == move.camera_id
            )
            self._cameras[self._cameras.index(camera)] = replace(
                camera,
                applied_revision=move.desired_revision,
            )
            updated = replace(move, state=CameraMoveState.COMPLETE)
            self._camera_moves[self._camera_moves.index(move)] = updated
            return updated

    def mark_camera_applied(
        self,
        *,
        camera_id: UUID,
        node_id: UUID,
        placement_generation: int,
        desired_revision: int,
    ) -> bool:
        with self._lock:
            camera = next(
                (candidate for candidate in self._cameras if candidate.id == camera_id),
                None,
            )
            if (
                camera is None
                or camera.node_id != node_id
                or camera.placement_generation != placement_generation
                or camera.desired_revision != desired_revision
            ):
                return False
            if any(
                move.camera_id == camera_id and not camera_move_is_terminal(move.state)
                for move in self._camera_moves
            ):
                return False
            if camera.state is CameraState.DELETING:
                node = next(candidate for candidate in self._nodes if candidate.id == node_id)
                self._nodes[self._nodes.index(node)] = replace(
                    node,
                    registered_cameras=node.registered_cameras - 1,
                )
                updated = replace(
                    camera,
                    state=CameraState.DELETED,
                    applied_revision=desired_revision,
                )
            else:
                updated = replace(camera, applied_revision=desired_revision)
            self._cameras[self._cameras.index(camera)] = updated
            return True


class NodeControl:
    def __init__(
        self,
        *,
        store: NodeStore,
        choose_port: PortChoice,
        new_node_id: NodeIdFactory,
        is_port_bindable: PortBindable | None = None,
        node_runtime: NodeRuntime | None = None,
        provision_on_create: bool = False,
        recovery_workers: int = 4,
        confirmations: NodeDisruptionConfirmations | None = None,
        new_operation_id: NodeIdFactory = uuid4,
        sleep: Callable[[float], None] = time.sleep,
        reconfigure_release_id: str | None = None,
        reconfigure_mediamtx_binary_sha256: str | None = None,
    ) -> None:
        if recovery_workers < 1 or recovery_workers > 16:
            raise ValueError("node_recovery_workers_invalid")
        self._store = store
        self._choose_port = choose_port
        self._new_node_id = new_node_id
        self._is_port_bindable = is_port_bindable or (lambda port: True)
        self._node_runtime = node_runtime
        self._provision_on_create = provision_on_create
        self._recovery_workers = recovery_workers
        self._confirmations = confirmations
        self._new_operation_id = new_operation_id
        self._sleep = sleep
        if (reconfigure_release_id is None) != (
            reconfigure_mediamtx_binary_sha256 is None
        ):
            raise ValueError("node_release_identity_incomplete")
        if (
            reconfigure_release_id is not None
            and reconfigure_mediamtx_binary_sha256 is not None
        ):
            NodeRuntimeSpecLike.validate_release(
                reconfigure_release_id,
                reconfigure_mediamtx_binary_sha256,
            )
        self._reconfigure_release_id = reconfigure_release_id
        self._reconfigure_mediamtx_binary_sha256 = (
            reconfigure_mediamtx_binary_sha256
        )

    def register_node(
        self,
        *,
        name: str,
        port_range_start: int,
        port_range_end: int,
        max_nodes: int,
        external_port: int | None = None,
        reserved_ports: Collection[int] = (),
        api_ports: Collection[int] = tuple(range(20000, 20100)),
        metrics_ports: Collection[int] = tuple(range(20100, 20200)),
        release_id: str = "0.1.0",
        mediamtx_binary_sha256: str = "0" * 64,
        creation_mode: NodeCreationMode = NodeCreationMode.OPERATOR,
    ) -> MediaNode:
        configured_ports = tuple(
            port
            for port in range(port_range_start, port_range_end + 1)
            if port not in reserved_ports
        )
        if external_port is not None:
            if external_port in configured_ports and not self._is_port_bindable(external_port):
                raise NodePortInUse("node_port_in_use")
            candidate_ports: Collection[int] = configured_ports
        else:
            candidate_ports = tuple(
                port for port in configured_ports if self._is_port_bindable(port)
            )
        node = self._store.register_automatically(
            name=name,
            allowed_ports=candidate_ports,
            max_nodes=max_nodes,
            preferred_port=external_port,
            choose_port=self._choose_port,
            new_node_id=self._new_node_id,
            api_ports=api_ports,
            metrics_ports=metrics_ports,
            release_id=release_id,
            mediamtx_binary_sha256=mediamtx_binary_sha256,
            creation_mode=creation_mode,
            is_port_bindable=self._is_port_bindable,
        )
        if self._provision_on_create or creation_mode is NodeCreationMode.AUTOMATIC:
            try:
                return self._provision_reserved_node(node)
            except NodeLifecycleBusy:
                if creation_mode is NodeCreationMode.OPERATOR:
                    return node
                raise
        return node

    def list_nodes(self) -> tuple[MediaNode, ...]:
        return self._store.list_nodes()

    def ensure_automatic_capacity(self, policy: NodeProvisioningPolicy) -> MediaNode:
        if self._node_runtime is None:
            raise NodeRuntimeUnavailable("node_runtime_unavailable")
        with self._store.provisioning_guard():
            eligible = tuple(
                node
                for node in self._store.list_nodes()
                if is_node_eligible(
                    node,
                    management_freshness_seconds=policy.management_freshness_seconds,
                )
            )
            if eligible:
                return min(
                    eligible,
                    key=lambda node: (
                        node.registered_cameras,
                        node.active_sources,
                        node.id.int,
                    ),
                )
            retryable = tuple(
                node
                for node in self._store.list_nodes()
                if node.creation_mode is NodeCreationMode.AUTOMATIC
                and node.registered_cameras == 0
                and not node.maintenance
                and node.runtime_state
                in {
                    NodeState.PROVISIONING,
                    NodeState.STOPPED,
                    NodeState.FAILED,
                }
            )
            if retryable:
                return self.start_node(min(retryable, key=lambda node: node.id.int).id)
            return self.register_node(
                name="automatic-node",
                port_range_start=policy.port_range_start,
                port_range_end=policy.port_range_end,
                max_nodes=policy.max_nodes,
                reserved_ports=policy.reserved_ports,
                api_ports=policy.api_ports,
                metrics_ports=policy.metrics_ports,
                release_id=policy.release_id,
                mediamtx_binary_sha256=policy.mediamtx_binary_sha256,
                creation_mode=NodeCreationMode.AUTOMATIC,
            )

    def start_node(self, node_id: UUID) -> MediaNode:
        with self._store.lifecycle_guard(node_id):
            return self._start_node_locked(node_id)

    def stop_node(self, node_id: UUID) -> MediaNode:
        with self._store.lifecycle_guard(node_id):
            return self._stop_node_locked(node_id)

    def restart_node(self, node_id: UUID) -> MediaNode:
        with self._store.lifecycle_guard(node_id):
            self._require_node_and_runtime(node_id)
            desired = self._store.request_restart(node_id)
            return self._execute_runtime(desired, NodeRuntimeAction.RESTART)

    def preview_reconfigure(self, node_id: UUID) -> NodeReconfigurePreview:
        with self._store.lifecycle_guard(node_id):
            node = self._require_node_and_runtime(node_id)
            if node.state is not NodeState.DRAINING:
                raise NodeLifecycleConflict("node_not_draining")
            if node.runtime_state not in {
                NodeState.RUNNING,
                NodeState.STOPPED,
                NodeState.FAILED,
            }:
                raise NodeLifecycleConflict("node_reconfigure_runtime_invalid")
            if self._confirmations is None:
                raise NodeRuntimeUnavailable("node_confirmation_unavailable")
            blast_radius_sha256 = self._node_camera_fingerprint(node.id)
            target_release_id = self._reconfigure_release_id or node.release_id
            target_binary_sha256 = (
                self._reconfigure_mediamtx_binary_sha256
                or node.mediamtx_binary_sha256
            )
            token = self._confirmations.issue_node_reconfigure(
                node_id=node.id,
                external_port=node.external_port,
                desired_revision=node.desired_revision,
                registered_cameras=node.registered_cameras,
                blast_radius_sha256=blast_radius_sha256,
                target_release_id=target_release_id,
                target_mediamtx_binary_sha256=target_binary_sha256,
            )
            return NodeReconfigurePreview(
                node_id=node.id,
                external_port=node.external_port,
                desired_revision=node.desired_revision,
                registered_cameras=node.registered_cameras,
                blast_radius_sha256=blast_radius_sha256,
                target_release_id=target_release_id,
                target_mediamtx_binary_sha256=target_binary_sha256,
                confirmation_token=token,
            )

    def reconfigure_node(
        self,
        node_id: UUID,
        *,
        confirmation_token: str | None,
    ) -> MediaNode:
        with self._store.lifecycle_guard(node_id):
            current = self._require_node_and_runtime(node_id)
            blast_radius_sha256 = self._node_camera_fingerprint(current.id)
            target_release_id = self._reconfigure_release_id or current.release_id
            target_binary_sha256 = (
                self._reconfigure_mediamtx_binary_sha256
                or current.mediamtx_binary_sha256
            )
            if (
                self._confirmations is None
                or confirmation_token is None
                or not self._confirmations.verify_node_reconfigure(
                    confirmation_token,
                    node_id=current.id,
                    external_port=current.external_port,
                    desired_revision=current.desired_revision,
                    registered_cameras=current.registered_cameras,
                    blast_radius_sha256=blast_radius_sha256,
                    target_release_id=target_release_id,
                    target_mediamtx_binary_sha256=target_binary_sha256,
                )
            ):
                raise NodeDisruptionConfirmationRequired(
                    "node_disruption_confirmation_required"
                )
            if self._reconfigure_release_id is None:
                desired = self._store.request_reconfigure(
                    node_id,
                    expected_revision=current.desired_revision,
                    expected_registered_cameras=current.registered_cameras,
                    expected_blast_radius_sha256=blast_radius_sha256,
                )
            else:
                desired = self._store.request_reconfigure(
                    node_id,
                    expected_revision=current.desired_revision,
                    expected_registered_cameras=current.registered_cameras,
                    expected_blast_radius_sha256=blast_radius_sha256,
                    release_id=self._reconfigure_release_id,
                    mediamtx_binary_sha256=(
                        self._reconfigure_mediamtx_binary_sha256
                    ),
                )
            return self._execute_runtime(desired, NodeRuntimeAction.RECONFIGURE_RESTART)

    def set_administrative_state(
        self,
        node_id: UUID,
        state: NodeState,
    ) -> MediaNode:
        with self._store.lifecycle_guard(node_id):
            if state not in {
                NodeState.DRAINING,
                NodeState.MAINTENANCE,
                NodeState.RUNNING,
            }:
                raise NodeLifecycleConflict("node_administrative_transition_invalid")
            return self._store.request_administrative_state(node_id, state)

    def preview_port_change(
        self,
        node_id: UUID,
        *,
        new_port: int,
        allowed_ports: Collection[int],
    ) -> NodePortChangePreview:
        with self._store.lifecycle_guard(node_id):
            node = self._store.get_node(node_id)
            if node is None:
                raise NodeNotFound("node_not_found")
            if new_port not in allowed_ports:
                raise NodePortOutOfRange("node_port_out_of_range")
            if node.state is not NodeState.RUNNING or node.runtime_state is not NodeState.RUNNING:
                raise NodeLifecycleConflict("node_not_running")
            if node.external_port == new_port:
                raise NodeLifecycleConflict("node_port_unchanged")
            if self._confirmations is None:
                raise NodeRuntimeUnavailable("node_confirmation_unavailable")
            blast_radius_sha256 = self._node_camera_fingerprint(node.id)
            token = self._confirmations.issue_node_port_change(
                node_id=node.id,
                old_port=node.external_port,
                new_port=new_port,
                desired_revision=node.desired_revision,
                registered_cameras=node.registered_cameras,
                blast_radius_sha256=blast_radius_sha256,
            )
            return NodePortChangePreview(
                node_id=node.id,
                old_port=node.external_port,
                new_port=new_port,
                desired_revision=node.desired_revision,
                registered_cameras=node.registered_cameras,
                blast_radius_sha256=blast_radius_sha256,
                confirmation_token=token,
            )

    def change_port(
        self,
        node_id: UUID,
        *,
        new_port: int,
        allowed_ports: Collection[int],
        confirmation_token: str | None,
    ) -> MediaNode:
        with self._store.lifecycle_guard(node_id):
            current = self._require_node_and_runtime(node_id)
            blast_radius_sha256 = self._node_camera_fingerprint(current.id)
            if (
                self._confirmations is None
                or confirmation_token is None
                or not (
                    self._confirmations.verify_node_port_change(
                        confirmation_token,
                        node_id=current.id,
                        old_port=current.external_port,
                        new_port=new_port,
                        desired_revision=current.desired_revision,
                        registered_cameras=current.registered_cameras,
                        blast_radius_sha256=blast_radius_sha256,
                    )
                )
            ):
                raise NodeDisruptionConfirmationRequired("node_disruption_confirmation_required")
            if not self._is_port_bindable(new_port):
                raise NodePortInUse("node_port_in_use")
            change = self._store.begin_port_change(
                change_id=self._new_operation_id(),
                node_id=node_id,
                new_port=new_port,
                allowed_ports=allowed_ports,
                expected_revision=current.desired_revision,
                expected_registered_cameras=current.registered_cameras,
                expected_blast_radius_sha256=blast_radius_sha256,
            )
            target = replace(
                current,
                external_port=change.new_port,
                desired_revision=change.target_revision,
            )
            assert self._node_runtime is not None
            try:
                target_observation = self._node_runtime.execute(
                    NodeRuntimeAction.RECONFIGURE_RESTART,
                    target,
                )
            except Exception as change_error:
                self._rollback_port_change(current, change, change_error)
                raise AssertionError("unreachable") from change_error
            if not self._wait_for_port_release(change.old_port):
                self._rollback_port_change(
                    current,
                    change,
                    RuntimeError("node_old_port_still_listening"),
                )
                raise AssertionError("unreachable")
            try:
                return self._store.complete_port_change(change.id, target_observation)
            except Exception as commit_error:
                try:
                    committed = self._store.get_node(current.id)
                    incomplete_ids = {
                        candidate.id
                        for candidate in self._store.list_incomplete_port_changes()
                    }
                except Exception:
                    raise NodeRuntimeFailed(
                        "node_port_change_commit_unknown",
                        node_id=current.id,
                    ) from commit_error
                if (
                    committed is not None
                    and committed.external_port == change.new_port
                    and committed.desired_revision == change.target_revision
                    and committed.applied_revision == change.target_revision
                    and change.id not in incomplete_ids
                ):
                    return committed
                if (
                    committed is None
                    or committed.external_port != change.old_port
                    or committed.desired_revision != change.source_revision
                ):
                    raise NodeRuntimeFailed(
                        "node_port_change_commit_unknown",
                        node_id=current.id,
                    ) from commit_error
                self._rollback_port_change(current, change, commit_error)
                raise AssertionError("unreachable") from commit_error

    def _rollback_port_change(
        self,
        current: MediaNode,
        change: NodePortChange,
        change_error: Exception,
    ) -> None:
        assert self._node_runtime is not None
        try:
            rollback_observation = self._node_runtime.execute(
                NodeRuntimeAction.RECONFIGURE_RESTART,
                current,
            )
        except Exception as rollback_error:
            with suppress(Exception):
                self._store.apply_runtime_observation(
                    current.id,
                    NodeRuntimeObservation(
                        state=NodeState.FAILED,
                        health=NodeHealth.UNHEALTHY,
                        applied_revision=current.applied_revision,
                        config_compatible=False,
                    ),
                )
            raise NodeRuntimeFailed(
                "node_port_change_rollback_failed",
                node_id=current.id,
            ) from rollback_error
        try:
            self._store.abort_port_change(change.id, rollback_observation)
        except Exception as rollback_commit_error:
            try:
                committed = self._store.get_node(current.id)
                incomplete_ids = {
                    candidate.id
                    for candidate in self._store.list_incomplete_port_changes()
                }
            except Exception:
                raise NodeRuntimeFailed(
                    "node_port_change_rollback_commit_unknown",
                    node_id=current.id,
                ) from rollback_commit_error
            if not (
                committed is not None
                and committed.external_port == change.old_port
                and committed.desired_revision == change.source_revision
                and committed.applied_revision == change.source_revision
                and change.id not in incomplete_ids
            ):
                with suppress(Exception):
                    self._store.apply_runtime_observation(
                        current.id,
                        NodeRuntimeObservation(
                            state=NodeState.FAILED,
                            health=NodeHealth.UNHEALTHY,
                            applied_revision=min(
                                current.applied_revision,
                                committed.desired_revision
                                if committed is not None
                                else current.desired_revision,
                            ),
                            config_compatible=False,
                        ),
                    )
                raise NodeRuntimeFailed(
                    "node_port_change_rollback_failed",
                    node_id=current.id,
                ) from rollback_commit_error
        raise NodeRuntimeFailed(
            "node_port_change_rolled_back",
            node_id=current.id,
        ) from change_error

    def _wait_for_port_release(self, port: int) -> bool:
        for attempt in range(21):
            if self._is_port_bindable(port):
                return True
            if attempt < 20:
                self._sleep(0.05)
        return False

    def _node_camera_fingerprint(self, node_id: UUID) -> str:
        return camera_placement_fingerprint(
            tuple(
                (camera.id, camera.placement_generation)
                for camera in self._store.list_node_cameras(node_id)
            )
        )

    def delete_node(self, node_id: UUID) -> None:
        with self._store.lifecycle_guard(node_id):
            self._require_node_and_runtime(node_id)
            assert self._node_runtime is not None
            deleting = self._store.request_node_delete(node_id)
            try:
                observation = self._node_runtime.execute(
                    NodeRuntimeAction.DELETE,
                    deleting,
                )
                if observation.state is not NodeState.STOPPED:
                    raise RuntimeError("node_delete_not_stopped")
                self._store.finalize_node_delete(node_id)
            except Exception as error:
                with suppress(Exception):
                    self._store.apply_runtime_observation(
                        deleting.id,
                        NodeRuntimeObservation(
                            state=NodeState.FAILED,
                            health=NodeHealth.UNHEALTHY,
                            applied_revision=deleting.applied_revision,
                            config_compatible=False,
                        ),
                    )
                raise NodeRuntimeFailed(
                    "node_delete_failed",
                    node_id=node_id,
                ) from error

    def observe_node(self, node_id: UUID) -> MediaNode:
        with self._store.lifecycle_guard(node_id):
            return self._observe_node_locked(node_id)

    def update_node_release(
        self,
        node_id: UUID,
        *,
        release_id: str,
        mediamtx_binary_sha256: str,
    ) -> MediaNode:
        with self._store.lifecycle_guard(node_id):
            self._require_node_and_runtime(node_id)
            return self._store.request_release(
                node_id,
                release_id=release_id,
                mediamtx_binary_sha256=mediamtx_binary_sha256,
            )

    def recover_runtime_state(self) -> tuple[MediaNode, ...]:
        if self._node_runtime is None:
            raise NodeRuntimeUnavailable("node_runtime_unavailable")
        self._recover_port_changes()
        self._recover_node_deletions()
        candidates = tuple(
            node for node in self._store.list_nodes() if node.state is not NodeState.DELETING
        )
        if not candidates:
            return ()
        with ThreadPoolExecutor(
            max_workers=min(self._recovery_workers, len(candidates)),
            thread_name_prefix="node-recovery",
        ) as workers:
            return tuple(workers.map(self._recover_node, candidates))

    def _recover_port_changes(self) -> None:
        if self._node_runtime is None:
            return
        for change in self._store.list_incomplete_port_changes():
            node = self._store.get_node(change.node_id)
            if node is None:
                continue
            try:
                with self._store.lifecycle_guard(node.id):
                    rollback = replace(
                        node,
                        external_port=change.old_port,
                        desired_revision=change.source_revision,
                    )
                    observation = self._node_runtime.execute(
                        NodeRuntimeAction.RECONFIGURE_RESTART,
                        rollback,
                    )
                    self._store.abort_port_change(change.id, observation)
            except Exception:
                self._store.apply_runtime_observation(
                    node.id,
                    NodeRuntimeObservation(
                        state=NodeState.FAILED,
                        health=NodeHealth.UNHEALTHY,
                        applied_revision=node.applied_revision,
                        config_compatible=False,
                    ),
                )

    def _recover_node_deletions(self) -> None:
        if self._node_runtime is None:
            return
        for node in self._store.list_nodes():
            if node.state is not NodeState.DELETING:
                continue
            try:
                with self._store.lifecycle_guard(node.id):
                    observation = self._node_runtime.execute(
                        NodeRuntimeAction.DELETE,
                        node,
                    )
                    if observation.state is not NodeState.STOPPED:
                        raise RuntimeError("node_delete_not_stopped")
                    self._store.finalize_node_delete(node.id)
            except Exception:
                self._store.apply_runtime_observation(
                    node.id,
                    NodeRuntimeObservation(
                        state=NodeState.FAILED,
                        health=NodeHealth.UNHEALTHY,
                        applied_revision=node.applied_revision,
                        config_compatible=False,
                    ),
                )

    def _recover_node(self, node: MediaNode) -> MediaNode:
        try:
            with self._store.lifecycle_guard(node.id):
                current = self._require_node_and_runtime(node.id)
                observed = self._execute_runtime(current, NodeRuntimeAction.OBSERVE)
                if (
                    current.state is NodeState.RUNNING
                    and observed.runtime_state is not NodeState.RUNNING
                ):
                    return self._start_node_locked(node.id)
                if (
                    current.state is NodeState.STOPPED
                    and observed.runtime_state is NodeState.RUNNING
                ):
                    return self._stop_node_locked(node.id)
                return observed
        except (NodeRuntimeFailed, NodeNotEmpty, NodeLifecycleConflict, NodeNotFound):
            failed = self._store.get_node(node.id)
            if failed is None:
                raise NodeNotFound("node_not_found") from None
            return failed

    def _provision_reserved_node(self, node: MediaNode) -> MediaNode:
        return self.start_node(node.id)

    def _start_node_locked(self, node_id: UUID) -> MediaNode:
        self._require_node_and_runtime(node_id)
        desired = self._store.request_desired_state(node_id, NodeState.RUNNING)
        action = (
            NodeRuntimeAction.PROVISION_START
            if desired.applied_revision == 0
            else NodeRuntimeAction.START
        )
        return self._execute_runtime(desired, action)

    def _stop_node_locked(self, node_id: UUID) -> MediaNode:
        self._require_node_and_runtime(node_id)
        desired = self._store.request_stop(node_id)
        return self._execute_runtime(desired, NodeRuntimeAction.STOP)

    def _observe_node_locked(self, node_id: UUID) -> MediaNode:
        node = self._require_node_and_runtime(node_id)
        return self._execute_runtime(node, NodeRuntimeAction.OBSERVE)

    def _require_node_and_runtime(self, node_id: UUID) -> MediaNode:
        node = self._store.get_node(node_id)
        if node is None:
            raise NodeNotFound("node_not_found")
        if self._node_runtime is None:
            raise NodeRuntimeUnavailable("node_runtime_unavailable")
        return node

    def _execute_runtime(
        self,
        node: MediaNode,
        action: NodeRuntimeAction,
    ) -> MediaNode:
        assert self._node_runtime is not None
        try:
            observation = self._node_runtime.execute(action, node)
        except Exception as error:
            self._store.apply_runtime_observation(
                node.id,
                NodeRuntimeObservation(
                    state=NodeState.FAILED,
                    health=NodeHealth.UNHEALTHY,
                    applied_revision=node.applied_revision,
                    config_compatible=False,
                ),
            )
            raise NodeRuntimeFailed("node_runtime_operation_failed", node_id=node.id) from error
        try:
            return self._store.apply_runtime_observation(node.id, observation)
        except Exception as error:
            self._store.apply_runtime_observation(
                node.id,
                NodeRuntimeObservation(
                    state=NodeState.FAILED,
                    health=NodeHealth.UNHEALTHY,
                    applied_revision=node.applied_revision,
                    config_compatible=False,
                ),
            )
            raise NodeRuntimeFailed("node_runtime_operation_failed", node_id=node.id) from error


class CameraControl:
    def __init__(
        self,
        *,
        store: CameraStore,
        new_camera_id: NodeIdFactory,
        new_public_id: PublicIdFactory,
        management_freshness_seconds: int = 30,
        ensure_automatic_capacity: Callable[[], MediaNode] | None = None,
    ) -> None:
        self._store = store
        self._new_camera_id = new_camera_id
        self._new_public_id = new_public_id
        self._management_freshness_seconds = management_freshness_seconds
        self._ensure_automatic_capacity = ensure_automatic_capacity

    def create_camera(
        self,
        *,
        name: str,
        source_url: str,
        node_id: UUID | None = None,
    ) -> CameraPlacement:
        validated_name = validate_camera_name(name)
        validated_source_url = validate_camera_source_url(source_url)
        camera_id = self._new_camera_id()
        public_id = PublicId.parse(self._new_public_id())
        if node_id is not None:
            return self._store.place_camera_manually(
                camera_id=camera_id,
                name=validated_name,
                source_url=validated_source_url,
                public_id=public_id,
                node_id=node_id,
                management_freshness_seconds=self._management_freshness_seconds,
            )
        try:
            return self._store.place_camera_automatically(
                camera_id=camera_id,
                name=validated_name,
                source_url=validated_source_url,
                public_id=public_id,
                management_freshness_seconds=self._management_freshness_seconds,
            )
        except EligibleNodeMissing:
            if self._ensure_automatic_capacity is None:
                raise
        self._ensure_automatic_capacity()
        return self._store.place_camera_automatically(
            camera_id=camera_id,
            name=validated_name,
            source_url=validated_source_url,
            public_id=public_id,
            management_freshness_seconds=self._management_freshness_seconds,
        )

    def list_cameras(self) -> tuple[CameraPlacement, ...]:
        return self._store.list_cameras()

    def catalog(self, query: CameraCatalogQuery) -> CameraCatalogPage:
        try:
            return self._store.camera_catalog(query)
        except CameraCatalogUnavailable:
            raise
        except Exception:
            raise CameraCatalogUnavailable("camera_catalog_unavailable") from None

    def detail(self, camera_id: UUID) -> CameraCatalogItem | None:
        try:
            return self._store.camera_detail(camera_id)
        except CameraCatalogUnavailable:
            raise
        except Exception:
            raise CameraCatalogUnavailable("camera_catalog_unavailable") from None

    def update_camera(
        self,
        camera_id: UUID,
        *,
        name: str,
        source_url: str,
        expected_revision: int | None = None,
    ) -> CameraPlacement:
        return self._store.update_camera(
            camera_id,
            name=validate_camera_name(name),
            source_url=source_url,
            expected_revision=expected_revision,
        )

    def set_camera_enabled(
        self,
        camera_id: UUID,
        *,
        enabled: bool,
        expected_revision: int | None = None,
    ) -> CameraPlacement:
        return self._store.set_camera_enabled(
            camera_id,
            enabled=enabled,
            expected_revision=expected_revision,
        )

    def delete_camera(self, camera_id: UUID) -> CameraPlacement:
        return self._store.request_camera_delete(camera_id)


class NodeStore(Protocol):
    def provisioning_guard(self) -> AbstractContextManager[None]: ...

    def lifecycle_guard(self, node_id: UUID) -> AbstractContextManager[None]: ...

    def register_automatically(
        self,
        *,
        name: str,
        allowed_ports: Collection[int],
        max_nodes: int,
        preferred_port: int | None,
        choose_port: PortChoice,
        new_node_id: NodeIdFactory,
        api_ports: Collection[int] = tuple(range(20000, 20100)),
        metrics_ports: Collection[int] = tuple(range(20100, 20200)),
        release_id: str = "0.1.0",
        mediamtx_binary_sha256: str = "0" * 64,
        creation_mode: NodeCreationMode = NodeCreationMode.OPERATOR,
        is_port_bindable: PortBindable | None = None,
    ) -> MediaNode: ...

    def list_nodes(self) -> tuple[MediaNode, ...]: ...

    def get_node(self, node_id: UUID) -> MediaNode | None: ...

    def list_node_cameras(self, node_id: UUID) -> tuple[CameraPlacement, ...]: ...

    def request_desired_state(self, node_id: UUID, state: NodeState) -> MediaNode: ...

    def request_administrative_state(
        self,
        node_id: UUID,
        state: NodeState,
    ) -> MediaNode: ...

    def begin_port_change(
        self,
        *,
        change_id: UUID,
        node_id: UUID,
        new_port: int,
        allowed_ports: Collection[int],
        expected_revision: int,
        expected_registered_cameras: int,
        expected_blast_radius_sha256: str,
    ) -> NodePortChange: ...

    def list_incomplete_port_changes(self) -> tuple[NodePortChange, ...]: ...

    def complete_port_change(
        self,
        change_id: UUID,
        observation: NodeRuntimeObservation,
    ) -> MediaNode: ...

    def abort_port_change(
        self,
        change_id: UUID,
        observation: NodeRuntimeObservation,
    ) -> MediaNode: ...

    def request_node_delete(self, node_id: UUID) -> MediaNode: ...

    def finalize_node_delete(self, node_id: UUID) -> None: ...

    def request_stop(self, node_id: UUID) -> MediaNode: ...

    def request_restart(self, node_id: UUID) -> MediaNode: ...

    def request_reconfigure(
        self,
        node_id: UUID,
        *,
        expected_revision: int,
        expected_registered_cameras: int,
        expected_blast_radius_sha256: str,
        release_id: str | None = None,
        mediamtx_binary_sha256: str | None = None,
    ) -> MediaNode: ...

    def request_release(
        self,
        node_id: UUID,
        *,
        release_id: str,
        mediamtx_binary_sha256: str,
    ) -> MediaNode: ...

    def apply_runtime_observation(
        self,
        node_id: UUID,
        observation: NodeRuntimeObservation,
    ) -> MediaNode: ...


class CameraStore(Protocol):
    def place_camera_automatically(
        self,
        *,
        camera_id: UUID,
        name: str,
        source_url: str,
        public_id: PublicId,
        management_freshness_seconds: int = 30,
    ) -> CameraPlacement: ...

    def place_camera_manually(
        self,
        *,
        camera_id: UUID,
        name: str,
        source_url: str,
        public_id: PublicId,
        node_id: UUID,
        management_freshness_seconds: int = 30,
    ) -> CameraPlacement: ...

    def list_cameras(self) -> tuple[CameraPlacement, ...]: ...

    def camera_catalog(self, query: CameraCatalogQuery) -> CameraCatalogPage: ...

    def camera_detail(self, camera_id: UUID) -> CameraCatalogItem | None: ...

    def get_camera(self, camera_id: UUID) -> CameraPlacement | None: ...

    def update_camera(
        self,
        camera_id: UUID,
        *,
        name: str,
        source_url: str,
        expected_revision: int | None = None,
    ) -> CameraPlacement: ...

    def set_camera_enabled(
        self,
        camera_id: UUID,
        *,
        enabled: bool,
        expected_revision: int | None = None,
    ) -> CameraPlacement: ...

    def request_camera_delete(
        self,
        camera_id: UUID,
        *,
        expected_revision: int | None = None,
    ) -> CameraPlacement: ...


class ReconcileStore(Protocol):
    def reconcile_guard(
        self,
        node_id: UUID,
        *,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> AbstractContextManager[None]: ...

    def get_node(self, node_id: UUID) -> MediaNode | None: ...

    def list_nodes(self) -> tuple[MediaNode, ...]: ...

    def list_node_cameras(self, node_id: UUID) -> tuple[CameraPlacement, ...]: ...

    def list_node_active_moves(self, node_id: UUID) -> tuple[CameraMove, ...]: ...

    def get_camera(self, camera_id: UUID) -> CameraPlacement | None: ...

    def mark_camera_applied(
        self,
        *,
        camera_id: UUID,
        node_id: UUID,
        placement_generation: int,
        desired_revision: int,
    ) -> bool: ...


class CameraMoveStore(ReconcileStore, Protocol):
    def create_camera_move(
        self,
        *,
        move_id: UUID,
        camera_id: UUID,
        target_node_id: UUID,
        expected_revision: int,
        force: bool,
        confirmed_disconnect_readers: int = 0,
        timeout_seconds: int = 300,
    ) -> CameraMove: ...

    def get_camera_move(self, move_id: UUID) -> CameraMove | None: ...

    def list_incomplete_camera_moves(self) -> tuple[CameraMove, ...]: ...

    def switch_camera_move(
        self,
        move_id: UUID,
        *,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> CameraMove: ...

    def mark_camera_move_source_cleaned(self, move_id: UUID) -> CameraMove: ...

    def complete_camera_move(self, move_id: UUID) -> CameraMove: ...

    def request_camera_move_abort(
        self,
        move_id: UUID,
        *,
        reason: str,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> CameraMove: ...

    def abort_camera_move(self, move_id: UUID) -> CameraMove: ...


def tcp_port_is_bindable(port: int) -> bool:
    probes: tuple[tuple[socket.AddressFamily, str], ...] = (
        (socket.AF_INET, "0.0.0.0"),
        (socket.AF_INET6, "::"),
    )
    for family, address in probes:
        try:
            with socket.socket(family, socket.SOCK_STREAM) as listener:
                if family is socket.AF_INET6:
                    listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                listener.bind((address, port))
        except OSError as error:
            if family is socket.AF_INET6 and error.errno in {
                errno.EAFNOSUPPORT,
                errno.EPROTONOSUPPORT,
                errno.EADDRNOTAVAIL,
            }:
                continue
            return False
    return True


def validate_camera_source_url(value: str) -> str:
    if len(value.encode("utf-8")) > MAX_CAMERA_SOURCE_URL_BYTES:
        raise InvalidCameraSource("camera_source_url_too_long")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise InvalidCameraSource("camera_source_url_invalid") from error
    if (
        parsed.scheme.lower() != "rtsp"
        or parsed.hostname is None
        or parsed.fragment
        or not parsed.path.startswith("/")
        or port == 0
    ):
        raise InvalidCameraSource("camera_source_url_invalid")
    if parsed.username is not None or parsed.password is not None or parsed.query:
        raise InvalidCameraSource("camera_source_secret_reference_required")
    return value


def validate_camera_name(value: str) -> str:
    if (
        not value
        or len(value) > MAX_CAMERA_NAME_LENGTH
        or value.isspace()
        or any(unicodedata.category(character).startswith("C") for character in value)
    ):
        raise InvalidCameraName("camera_name_invalid")
    return value


class NodeRuntimeSpecLike:
    @staticmethod
    def validate_release(release_id: str, digest: str) -> None:
        if not release_id or len(release_id) > 128:
            raise ValueError("node_release_id_invalid")
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise ValueError("node_binary_sha256_invalid")


def camera_placement_fingerprint(
    placements: Collection[tuple[UUID, int]],
) -> str:
    payload = "\n".join(
        f"{camera_id}:{generation}"
        for camera_id, generation in sorted(
            placements,
            key=lambda item: item[0].int,
        )
    )
    return hashlib.sha256(payload.encode("ascii")).hexdigest()


def is_node_eligible(
    node: MediaNode,
    *,
    management_freshness_seconds: int = 30,
    now: datetime | None = None,
) -> bool:
    observed_at = node.management_observed_at
    current_time = datetime.now(UTC) if now is None else now
    return (
        node.state is NodeState.RUNNING
        and node.runtime_state is NodeState.RUNNING
        and node.health is NodeHealth.HEALTHY
        and node.management_fresh
        and observed_at is not None
        and observed_at >= current_time - timedelta(seconds=management_freshness_seconds)
        and node.config_compatible
        and node.applied_revision == node.desired_revision
        and not node.maintenance
        and node.registered_cameras < node.camera_capacity
    )


def validate_runtime_observation(
    node: MediaNode,
    observation: NodeRuntimeObservation,
) -> None:
    if observation.applied_revision < 0 or observation.applied_revision > node.desired_revision:
        raise InvalidNodeRuntimeObservation("runtime_applied_revision_invalid")
    if (
        observation.state in {NodeState.RUNNING, NodeState.STOPPED}
        and observation.config_compatible
        and observation.applied_revision != node.desired_revision
    ):
        raise InvalidNodeRuntimeObservation("runtime_observation_revision_stale")
    identity = (
        observation.process_id,
        observation.process_start_ticks,
        observation.process_boot_id,
    )
    running = observation.state is NodeState.RUNNING
    if running != all(value is not None for value in identity):
        raise InvalidNodeRuntimeObservation("runtime_process_identity_invalid")
    if running and (
        observation.process_id is None
        or observation.process_id < 1
        or observation.process_start_ticks is None
        or observation.process_start_ticks < 1
    ):
        raise InvalidNodeRuntimeObservation("runtime_process_identity_invalid")
    if observation.management_fresh and not running:
        raise InvalidNodeRuntimeObservation("runtime_management_freshness_invalid")
    if observation.config_compatible and (
        observation.config_sha256 is None
        or observation.release_id != node.release_id
        or observation.applied_revision != node.desired_revision
    ):
        raise InvalidNodeRuntimeObservation("runtime_config_identity_invalid")


def _camera_catalog_item(
    camera: CameraPlacement,
    *,
    node_name: str,
) -> CameraCatalogItem:
    return CameraCatalogItem(
        id=camera.id,
        name=validate_camera_name(camera.name),
        public_id=camera.public_id,
        node_id=camera.node_id,
        node_name=node_name,
        node_port=camera.node_port,
        placement_mode=camera.placement_mode,
        state=camera.state,
        desired_revision=camera.desired_revision,
        applied_revision=camera.applied_revision,
    )


def select_port_with_bounded_recheck(
    available: tuple[int, ...],
    *,
    preferred_port: int | None,
    choose_port: PortChoice,
    is_port_bindable: PortBindable,
) -> int:
    candidates = list(available)
    for _ in range(len(candidates)):
        selected = preferred_port if preferred_port is not None else choose_port(tuple(candidates))
        if selected not in candidates:
            raise RuntimeError("node_port_selector_invalid")
        if is_port_bindable(selected):
            return selected
        if preferred_port is not None:
            raise NodePortInUse("node_port_in_use")
        candidates.remove(selected)
    raise NodePortRangeExhausted("node_port_range_exhausted")
