from __future__ import annotations

import errno
import socket
from collections.abc import Callable, Collection
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from threading import RLock
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


@dataclass(frozen=True, slots=True)
class NodeRuntimeObservation:
    state: NodeState
    health: NodeHealth
    management_fresh: bool = False
    config_compatible: bool = False


class NodeRuntime(Protocol):
    def start(self, node: MediaNode) -> NodeRuntimeObservation: ...


@dataclass(frozen=True, slots=True)
class MediaNode:
    id: UUID
    name: str
    external_port: int
    state: NodeState = NodeState.PROVISIONING
    runtime_state: NodeState = NodeState.PROVISIONING
    health: NodeHealth = NodeHealth.UNKNOWN
    registered_cameras: int = 0
    camera_capacity: int = 100
    active_sources: int = 0
    maintenance: bool = False
    management_fresh: bool = False
    management_observed_at: datetime | None = None
    config_compatible: bool = False
    desired_revision: int = 1
    applied_revision: int = 0


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


class NodePortRangeExhausted(RuntimeError):
    """No external port remains available for a new media node."""


class MaximumNodesReached(RuntimeError):
    """The configured server node limit has been reached."""


class NodePortOutOfRange(ValueError):
    """A requested external port is outside the configured range."""


class NodePortInUse(RuntimeError):
    """A requested external port is already assigned to another node."""


class NodeCameraCapacityReached(RuntimeError):
    """A media node already contains its maximum registered cameras."""


class NodeNotFound(LookupError):
    """A requested node does not exist."""


class NodeRuntimeUnavailable(RuntimeError):
    """The Linux process adapter is not configured."""


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

    def register_automatically(
        self,
        *,
        name: str,
        allowed_ports: Collection[int],
        max_nodes: int,
        preferred_port: int | None,
        choose_port: PortChoice,
        new_node_id: NodeIdFactory,
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
            selected = _select_port_with_bounded_recheck(
                available,
                preferred_port=preferred_port,
                choose_port=choose_port,
                is_port_bindable=probe,
            )
            node = MediaNode(
                id=new_node_id(),
                name=name,
                external_port=selected,
            )
            self._nodes.append(node)
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
            updated = replace(
                node,
                runtime_state=observation.state,
                health=observation.health,
            )
            updated = replace(
                updated,
                management_fresh=observation.management_fresh,
                management_observed_at=(
                    datetime.now(UTC) if observation.management_fresh else None
                ),
                config_compatible=observation.config_compatible,
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
    ) -> None:
        self._store = store
        self._choose_port = choose_port
        self._new_node_id = new_node_id
        self._is_port_bindable = is_port_bindable or (lambda port: True)
        self._node_runtime = node_runtime

    def register_node(
        self,
        *,
        name: str,
        port_range_start: int,
        port_range_end: int,
        max_nodes: int,
        external_port: int | None = None,
        reserved_ports: Collection[int] = (),
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
        return self._store.register_automatically(
            name=name,
            allowed_ports=candidate_ports,
            max_nodes=max_nodes,
            preferred_port=external_port,
            choose_port=self._choose_port,
            new_node_id=self._new_node_id,
            is_port_bindable=self._is_port_bindable,
        )

    def list_nodes(self) -> tuple[MediaNode, ...]:
        return self._store.list_nodes()

    def start_node(self, node_id: UUID) -> MediaNode:
        node = self._store.get_node(node_id)
        if node is None:
            raise NodeNotFound("node_not_found")
        if self._node_runtime is None:
            raise NodeRuntimeUnavailable("node_runtime_unavailable")
        desired = self._store.request_desired_state(node_id, NodeState.RUNNING)
        observation = self._node_runtime.start(desired)
        return self._store.apply_runtime_observation(node_id, observation)


class CameraControl:
    def __init__(
        self,
        *,
        store: CameraStore,
        new_camera_id: NodeIdFactory,
        new_public_id: PublicIdFactory,
        management_freshness_seconds: int = 30,
    ) -> None:
        self._store = store
        self._new_camera_id = new_camera_id
        self._new_public_id = new_public_id
        self._management_freshness_seconds = management_freshness_seconds

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
    def register_automatically(
        self,
        *,
        name: str,
        allowed_ports: Collection[int],
        max_nodes: int,
        preferred_port: int | None,
        choose_port: PortChoice,
        new_node_id: NodeIdFactory,
        is_port_bindable: PortBindable | None = None,
    ) -> MediaNode: ...

    def list_nodes(self) -> tuple[MediaNode, ...]: ...

    def get_node(self, node_id: UUID) -> MediaNode | None: ...

    def request_desired_state(self, node_id: UUID, state: NodeState) -> MediaNode: ...

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
        and not node.maintenance
        and node.registered_cameras < node.camera_capacity
    )


def _select_port_with_bounded_recheck(
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
