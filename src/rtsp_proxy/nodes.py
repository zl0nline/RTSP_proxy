from __future__ import annotations

import errno
import socket
from collections.abc import Callable, Collection, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from threading import Lock, RLock
from typing import Protocol
from urllib.parse import urlsplit
from uuid import UUID

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
    release_id: str = "v1.20.0"
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


@dataclass(frozen=True, slots=True)
class CameraPlacement:
    id: UUID
    name: str
    source_url: str
    public_id: PublicId
    node_id: UUID
    node_port: int
    placement_mode: PlacementMode
    desired_revision: int = 1
    applied_revision: int = 0


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


class InMemoryNodeStore:
    """Thread-safe development adapter for the future PostgreSQL node store."""

    def __init__(self, *, nodes: tuple[MediaNode, ...] = ()) -> None:
        self._nodes: list[MediaNode] = list(nodes)
        self._cameras: list[CameraPlacement] = []
        self._lock = RLock()
        self._lifecycle_locks = {node.id: Lock() for node in nodes}

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
        release_id: str = "v1.20.0",
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
                port
                for node in self._nodes
                for port in (node.api_port, node.metrics_port)
            }
            available_api = tuple(port for port in api_ports if port not in occupied_management)
            available_metrics = tuple(
                port for port in metrics_ports if port not in occupied_management
            )
            if not available_api or not available_metrics:
                raise NodeManagementPortRangeExhausted(
                    "node_management_port_range_exhausted"
                )
            try:
                api_port = select_port_with_bounded_recheck(
                    available_api,
                    preferred_port=None,
                    choose_port=lambda candidates: candidates[0],
                    is_port_bindable=probe,
                )
                metrics_port = select_port_with_bounded_recheck(
                    tuple(
                        port
                        for port in available_metrics
                        if port not in {external_port, api_port}
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
                management_observed_at=(
                    observed_at if observation.management_fresh else None
                ),
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

    def request_stop(self, node_id: UUID) -> MediaNode:
        with self._lock:
            node = next((candidate for candidate in self._nodes if candidate.id == node_id), None)
            if node is None:
                raise NodeNotFound("node_not_found")
            if node.registered_cameras:
                raise NodeNotEmpty("node_not_empty")
            if node.state is NodeState.STOPPED:
                return node
            updated = replace(
                node,
                state=NodeState.STOPPED,
                desired_revision=node.desired_revision + 1,
            )
            self._nodes[self._nodes.index(node)] = updated
            return updated

    def request_restart(self, node_id: UUID) -> MediaNode:
        with self._lock:
            node = next((candidate for candidate in self._nodes if candidate.id == node_id), None)
            if node is None:
                raise NodeNotFound("node_not_found")
            if node.state is not NodeState.RUNNING:
                raise NodeLifecycleConflict("node_not_running")
            if node.registered_cameras:
                raise NodeNotEmpty("node_not_empty")
            updated = replace(node, desired_revision=node.desired_revision + 1)
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
        source_url = validate_camera_source_url(source_url)
        with self._lock:
            eligible = [
                node
                for node in self._nodes
                if is_node_eligible(
                    node,
                    management_freshness_seconds=management_freshness_seconds,
                )
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
        source_url = validate_camera_source_url(source_url)
        with self._lock:
            selected = next((node for node in self._nodes if node.id == node_id), None)
            if selected is None:
                raise NodeNotFound("node_not_found")
            if selected.registered_cameras >= selected.camera_capacity:
                raise NodeCameraCapacityReached("node_camera_capacity_reached")
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
            return tuple(self._cameras)


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
        release_id: str = "v1.20.0",
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
            return self._provision_reserved_node(node)
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
            node = self._store.get_node(node_id)
            if node is None:
                raise NodeNotFound("node_not_found")
            if self._node_runtime is None:
                raise NodeRuntimeUnavailable("node_runtime_unavailable")
            desired = self._store.request_desired_state(node_id, NodeState.RUNNING)
            action = (
                NodeRuntimeAction.PROVISION_START
                if desired.applied_revision == 0
                else NodeRuntimeAction.START
            )
            return self._execute_runtime(desired, action)

    def stop_node(self, node_id: UUID) -> MediaNode:
        with self._store.lifecycle_guard(node_id):
            self._require_node_and_runtime(node_id)
            desired = self._store.request_stop(node_id)
            return self._execute_runtime(desired, NodeRuntimeAction.STOP)

    def restart_node(self, node_id: UUID) -> MediaNode:
        with self._store.lifecycle_guard(node_id):
            self._require_node_and_runtime(node_id)
            desired = self._store.request_restart(node_id)
            return self._execute_runtime(desired, NodeRuntimeAction.RESTART)

    def observe_node(self, node_id: UUID) -> MediaNode:
        with self._store.lifecycle_guard(node_id):
            node = self._require_node_and_runtime(node_id)
            return self._execute_runtime(node, NodeRuntimeAction.OBSERVE)

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

    def _recover_node(self, node: MediaNode) -> MediaNode:
        try:
            observed = self.observe_node(node.id)
            if (
                node.state is NodeState.RUNNING
                and observed.runtime_state is not NodeState.RUNNING
            ):
                return self.start_node(node.id)
            if (
                node.state is NodeState.STOPPED
                and observed.runtime_state is NodeState.RUNNING
            ):
                return self.stop_node(node.id)
            return observed
        except (NodeRuntimeFailed, NodeNotEmpty, NodeLifecycleConflict, NodeNotFound):
            failed = self._store.get_node(node.id)
            if failed is None:
                raise NodeNotFound("node_not_found") from None
            return failed

    def _provision_reserved_node(self, node: MediaNode) -> MediaNode:
        return self.start_node(node.id)

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
        validated_source_url = validate_camera_source_url(source_url)
        camera_id = self._new_camera_id()
        public_id = PublicId.parse(self._new_public_id())
        if node_id is not None:
            return self._store.place_camera_manually(
                camera_id=camera_id,
                name=name,
                source_url=validated_source_url,
                public_id=public_id,
                node_id=node_id,
                management_freshness_seconds=self._management_freshness_seconds,
            )
        try:
            return self._store.place_camera_automatically(
                camera_id=camera_id,
                name=name,
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
            name=name,
            source_url=validated_source_url,
            public_id=public_id,
            management_freshness_seconds=self._management_freshness_seconds,
        )

    def list_cameras(self) -> tuple[CameraPlacement, ...]:
        return self._store.list_cameras()


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
        release_id: str = "v1.20.0",
        mediamtx_binary_sha256: str = "0" * 64,
        creation_mode: NodeCreationMode = NodeCreationMode.OPERATOR,
        is_port_bindable: PortBindable | None = None,
    ) -> MediaNode: ...

    def list_nodes(self) -> tuple[MediaNode, ...]: ...

    def get_node(self, node_id: UUID) -> MediaNode | None: ...

    def request_desired_state(self, node_id: UUID, state: NodeState) -> MediaNode: ...

    def request_stop(self, node_id: UUID) -> MediaNode: ...

    def request_restart(self, node_id: UUID) -> MediaNode: ...

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


class NodeRuntimeSpecLike:
    @staticmethod
    def validate_release(release_id: str, digest: str) -> None:
        if not release_id or len(release_id) > 128:
            raise ValueError("node_release_id_invalid")
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise ValueError("node_binary_sha256_invalid")


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
