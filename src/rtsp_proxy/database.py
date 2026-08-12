from __future__ import annotations

import time
from collections.abc import Collection, Iterator, Mapping
from contextlib import contextmanager
from datetime import timedelta
from uuid import UUID, uuid4

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    Uuid,
    create_engine,
    func,
    insert,
    select,
    text,
    update,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.exc import TimeoutError as SQLAlchemyTimeoutError
from sqlalchemy.sql.base import Executable

from rtsp_proxy.identifiers import PublicId
from rtsp_proxy.nodes import (
    CameraPlacement,
    EligibleNodeMissing,
    InvalidNodeRuntimeObservation,
    MaximumNodesReached,
    MediaNode,
    NodeCameraCapacityReached,
    NodeCreationMode,
    NodeHealth,
    NodeIdFactory,
    NodeLifecycleBusy,
    NodeLifecycleConflict,
    NodeManagementPortRangeExhausted,
    NodeNotEmpty,
    NodeNotFound,
    NodePortInUse,
    NodePortOutOfRange,
    NodePortRangeExhausted,
    NodeReleaseConflict,
    NodeRuntimeObservation,
    NodeState,
    PlacementMode,
    PortBindable,
    PortChoice,
    is_node_eligible,
    select_port_with_bounded_recheck,
    validate_camera_source_url,
    validate_runtime_observation,
)
from rtsp_proxy.release import APPLICATION_SCHEMA

metadata = MetaData()

media_nodes = Table(
    "media_nodes",
    metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    Column("name", String(128), nullable=False),
    Column("external_port", Integer, nullable=False, unique=True),
    Column("api_port", Integer, nullable=False, unique=True),
    Column("metrics_port", Integer, nullable=False, unique=True),
    Column("release_id", String(128), nullable=False),
    Column("mediamtx_binary_sha256", String(64), nullable=False),
    Column("creation_mode", String(16), nullable=False),
    Column("state", String(32), nullable=False),
    Column("runtime_state", String(32), nullable=False),
    Column("health", String(32), nullable=False),
    Column("registered_cameras", Integer, nullable=False),
    Column("camera_capacity", Integer, nullable=False),
    Column("active_sources", Integer, nullable=False),
    Column("maintenance", Boolean, nullable=False),
    Column("management_fresh", Boolean, nullable=False),
    Column("management_observed_at", DateTime(timezone=True), nullable=True),
    Column("runtime_observed_at", DateTime(timezone=True), nullable=True),
    Column("config_compatible", Boolean, nullable=False),
    Column("desired_revision", BigInteger, nullable=False),
    Column("applied_revision", BigInteger, nullable=False),
    Column("process_id", Integer, nullable=True),
    Column("process_start_ticks", BigInteger, nullable=True),
    Column("process_boot_id", Uuid(as_uuid=True), nullable=True),
    Column("observed_config_sha256", String(64), nullable=True),
    Column("observed_release_id", String(128), nullable=True),
    CheckConstraint("external_port BETWEEN 1 AND 65535"),
    CheckConstraint("api_port BETWEEN 1 AND 65535"),
    CheckConstraint("metrics_port BETWEEN 1 AND 65535"),
    CheckConstraint("external_port <> api_port"),
    CheckConstraint("external_port <> metrics_port"),
    CheckConstraint("api_port <> metrics_port"),
    CheckConstraint("mediamtx_binary_sha256 ~ '^[0-9a-f]{64}$'"),
    CheckConstraint("creation_mode IN ('operator', 'automatic')"),
    CheckConstraint("registered_cameras BETWEEN 0 AND 100"),
    CheckConstraint("camera_capacity = 100"),
    CheckConstraint("active_sources >= 0"),
    CheckConstraint(
        "state IN ('provisioning', 'stopped', 'stopping', 'starting', 'running', "
        "'draining', 'maintenance', 'failed', 'deleting')"
    ),
    CheckConstraint(
        "runtime_state IN ('provisioning', 'stopped', 'stopping', 'starting', 'running', "
        "'draining', 'maintenance', 'failed', 'deleting')"
    ),
    CheckConstraint("health IN ('unknown', 'healthy', 'unhealthy')"),
    CheckConstraint("desired_revision >= 1"),
    CheckConstraint("applied_revision BETWEEN 0 AND desired_revision"),
    CheckConstraint("process_id IS NULL OR process_id > 0"),
    CheckConstraint("process_start_ticks IS NULL OR process_start_ticks > 0"),
    CheckConstraint(
        "observed_config_sha256 IS NULL OR "
        "observed_config_sha256 ~ '^[0-9a-f]{64}$'"
    ),
)

cameras = Table(
    "cameras",
    metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    Column("name", String(128), nullable=False),
    Column("source_url", Text, nullable=False),
    Column("public_id", String(26), nullable=False, unique=True),
    Column("desired_revision", BigInteger, nullable=False),
    Column("applied_revision", BigInteger, nullable=False),
    CheckConstraint("public_id ~ '^[a-z2-7]{25}[aeimquy4]$'"),
    CheckConstraint("desired_revision >= 1"),
    CheckConstraint("applied_revision BETWEEN 0 AND desired_revision"),
)

camera_placements = Table(
    "camera_placements",
    metadata,
    Column(
        "camera_id",
        Uuid(as_uuid=True),
        ForeignKey("cameras.id", ondelete="RESTRICT"),
        primary_key=True,
    ),
    Column(
        "node_id",
        Uuid(as_uuid=True),
        ForeignKey("media_nodes.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    ),
    Column("placement_mode", String(16), nullable=False),
    Column("generation", BigInteger, nullable=False),
    CheckConstraint("generation >= 1"),
    CheckConstraint("placement_mode IN ('automatic', 'manual')"),
)

camera_placement_history = Table(
    "camera_placement_history",
    metadata,
    Column(
        "camera_id",
        Uuid(as_uuid=True),
        ForeignKey("cameras.id", ondelete="RESTRICT"),
        primary_key=True,
    ),
    Column("generation", BigInteger, primary_key=True),
    Column(
        "node_id",
        Uuid(as_uuid=True),
        ForeignKey("media_nodes.id", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column("placement_mode", String(16), nullable=False),
    Column(
        "placed_at",
        DateTime(timezone=True),
        nullable=False,
        server_default=text("clock_timestamp()"),
    ),
    CheckConstraint("generation >= 1"),
    CheckConstraint("placement_mode IN ('automatic', 'manual')"),
)

audit_events = Table(
    "audit_events",
    metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    Column("aggregate_type", String(32), nullable=False),
    Column("aggregate_id", Uuid(as_uuid=True), nullable=False),
    Column("event_type", String(64), nullable=False),
    Column("aggregate_revision", BigInteger, nullable=False),
    Column("payload", JSONB, nullable=False),
    Column(
        "occurred_at",
        DateTime(timezone=True),
        nullable=False,
        server_default=text("clock_timestamp()"),
    ),
    CheckConstraint("aggregate_revision >= 1"),
)

outbox_messages = Table(
    "outbox_messages",
    metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    Column("aggregate_type", String(32), nullable=False),
    Column("aggregate_id", Uuid(as_uuid=True), nullable=False),
    Column("event_type", String(64), nullable=False),
    Column("aggregate_revision", BigInteger, nullable=False),
    Column("payload", JSONB, nullable=False),
    Column("status", String(16), nullable=False, server_default="pending"),
    Column("attempts", Integer, nullable=False, server_default="0"),
    Column(
        "available_at",
        DateTime(timezone=True),
        nullable=False,
        server_default=text("clock_timestamp()"),
    ),
    Column(
        "occurred_at",
        DateTime(timezone=True),
        nullable=False,
        server_default=text("clock_timestamp()"),
    ),
    Column("published_at", DateTime(timezone=True), nullable=True),
    CheckConstraint("attempts >= 0"),
    CheckConstraint("aggregate_revision >= 1"),
    CheckConstraint("status IN ('pending', 'processing', 'published', 'failed')"),
)

_NODE_REGISTRY_LOCK_KEY = 0x52545350524F5859
_NODE_PROVISIONING_LOCK_KEY = 0x4E4F444550524F56
_CAMERA_PLACEMENT_LOCK_KEY = 0x43414D504C414345


class DatabaseSchemaMismatch(RuntimeError):
    """The live PostgreSQL revision is incompatible with this application."""


class PostgresNodeStore:
    def __init__(
        self,
        database_url: str,
        *,
        lifecycle_lock_pool_size: int = 4,
        lifecycle_lock_timeout_seconds: float = 5,
    ) -> None:
        if lifecycle_lock_pool_size < 2 or lifecycle_lock_pool_size > 16:
            raise ValueError("node_lifecycle_lock_pool_size_invalid")
        if lifecycle_lock_timeout_seconds <= 0 or lifecycle_lock_timeout_seconds > 30:
            raise ValueError("node_lifecycle_lock_timeout_invalid")
        self._engine = create_engine(
            database_url,
            pool_pre_ping=True,
            hide_parameters=True,
        )
        self._lock_engine = create_engine(
            database_url,
            pool_pre_ping=True,
            hide_parameters=True,
            pool_size=lifecycle_lock_pool_size,
            max_overflow=0,
            pool_timeout=lifecycle_lock_timeout_seconds,
        )
        self._provision_engine = create_engine(
            database_url,
            pool_pre_ping=True,
            hide_parameters=True,
            pool_size=1,
            max_overflow=0,
            pool_timeout=lifecycle_lock_timeout_seconds,
        )
        self._lifecycle_lock_timeout_seconds = lifecycle_lock_timeout_seconds

    def assert_schema_compatible(self) -> None:
        try:
            with self._engine.connect() as connection:
                revisions = tuple(
                    connection.scalars(text("SELECT version_num FROM alembic_version"))
                )
        except SQLAlchemyError:
            raise DatabaseSchemaMismatch("database_schema_mismatch") from None
        if revisions != (APPLICATION_SCHEMA,):
            raise DatabaseSchemaMismatch("database_schema_mismatch")

    @contextmanager
    def provisioning_guard(self) -> Iterator[None]:
        try:
            with self._provision_engine.connect() as connection:
                parameters: dict[str, object] = {"key": _NODE_PROVISIONING_LOCK_KEY}
                self._acquire_advisory_lock(
                    connection,
                    text("SELECT pg_try_advisory_lock(:key)"),
                    parameters,
                )
                try:
                    yield
                finally:
                    connection.execute(
                        text("SELECT pg_advisory_unlock(:key)"),
                        parameters,
                    )
        except SQLAlchemyTimeoutError:
            raise NodeLifecycleBusy("node_lifecycle_busy") from None

    @contextmanager
    def lifecycle_guard(self, node_id: UUID) -> Iterator[None]:
        """Serialize one node's external process mutation across web processes."""

        try:
            with self._lock_engine.connect() as connection:
                parameters = {"node_id": str(node_id), "seed": _NODE_REGISTRY_LOCK_KEY}
                self._acquire_advisory_lock(
                    connection,
                    text(
                        "SELECT pg_try_advisory_lock("
                        "hashtextextended(CAST(:node_id AS text), :seed))"
                    ),
                    parameters,
                )
                try:
                    if self.get_node(node_id) is None:
                        raise NodeNotFound("node_not_found")
                    yield
                finally:
                    connection.execute(
                        text(
                            "SELECT pg_advisory_unlock("
                            "hashtextextended(CAST(:node_id AS text), :seed))"
                        ),
                        parameters,
                    )
        except SQLAlchemyTimeoutError:
            raise NodeLifecycleBusy("node_lifecycle_busy") from None

    def _acquire_advisory_lock(
        self,
        connection: Connection,
        statement: Executable,
        parameters: Mapping[str, object],
    ) -> None:
        deadline = time.monotonic() + self._lifecycle_lock_timeout_seconds
        while True:
            if connection.scalar(statement, parameters):
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise NodeLifecycleBusy("node_lifecycle_busy")
            time.sleep(min(0.05, remaining))

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
        with self._engine.begin() as connection:
            _require_synchronous_commit(connection)
            connection.execute(
                text("SELECT pg_advisory_xact_lock(:key)"),
                {"key": _NODE_REGISTRY_LOCK_KEY},
            )
            if preferred_port is not None and preferred_port not in allowed_ports:
                raise NodePortOutOfRange("node_port_out_of_range")
            node_count = connection.scalar(select(func.count()).select_from(media_nodes))
            if node_count is None or node_count >= max_nodes:
                raise MaximumNodesReached("max_nodes_reached")
            occupied = set(connection.scalars(select(media_nodes.c.external_port)))
            if preferred_port is not None and preferred_port in occupied:
                raise NodePortInUse("node_port_in_use")
            available = tuple(port for port in allowed_ports if port not in occupied)
            if not available:
                raise NodePortRangeExhausted("node_port_range_exhausted")
            probe = is_port_bindable or (lambda port: True)
            occupied_management = set(connection.scalars(select(media_nodes.c.api_port)))
            occupied_management.update(
                connection.scalars(select(media_nodes.c.metrics_port))
            )
            available_api = tuple(
                port for port in api_ports if port not in occupied_management
            )
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
                    tuple(port for port in available_metrics if port != api_port),
                    preferred_port=None,
                    choose_port=lambda candidates: candidates[0],
                    is_port_bindable=probe,
                )
            except NodePortRangeExhausted:
                raise NodeManagementPortRangeExhausted(
                    "node_management_port_range_exhausted"
                ) from None
            candidates = list(available)
            node: MediaNode | None = None
            for _ in range(len(candidates)):
                selected = (
                    preferred_port
                    if preferred_port is not None
                    else choose_port(tuple(candidates))
                )
                if selected not in candidates:
                    raise RuntimeError("node_port_selector_invalid")
                if not probe(selected):
                    if preferred_port is not None:
                        raise NodePortInUse("node_port_in_use")
                    candidates.remove(selected)
                    continue
                candidate = MediaNode(
                    id=new_node_id(),
                    name=name,
                    external_port=selected,
                    api_port=api_port,
                    metrics_port=metrics_port,
                    release_id=release_id,
                    mediamtx_binary_sha256=mediamtx_binary_sha256,
                    creation_mode=creation_mode,
                )
                try:
                    with connection.begin_nested():
                        connection.execute(
                            insert(media_nodes).values(
                                id=candidate.id,
                                name=candidate.name,
                                external_port=candidate.external_port,
                                api_port=candidate.api_port,
                                metrics_port=candidate.metrics_port,
                                release_id=candidate.release_id,
                                mediamtx_binary_sha256=(
                                    candidate.mediamtx_binary_sha256
                                ),
                                creation_mode=candidate.creation_mode.value,
                                state=candidate.state.value,
                                runtime_state=candidate.runtime_state.value,
                                health=candidate.health.value,
                                registered_cameras=candidate.registered_cameras,
                                camera_capacity=candidate.camera_capacity,
                                active_sources=candidate.active_sources,
                                maintenance=candidate.maintenance,
                                management_fresh=candidate.management_fresh,
                                management_observed_at=candidate.management_observed_at,
                                runtime_observed_at=candidate.runtime_observed_at,
                                config_compatible=candidate.config_compatible,
                                desired_revision=candidate.desired_revision,
                                applied_revision=candidate.applied_revision,
                                process_id=candidate.process_id,
                                process_start_ticks=candidate.process_start_ticks,
                                process_boot_id=candidate.process_boot_id,
                                observed_config_sha256=(
                                    candidate.observed_config_sha256
                                ),
                                observed_release_id=candidate.observed_release_id,
                            )
                        )
                except IntegrityError as error:
                    if not _is_external_port_conflict(error):
                        raise
                    if preferred_port is not None:
                        raise NodePortInUse("node_port_in_use") from None
                    candidates.remove(selected)
                    continue
                node = candidate
                break
            if node is None:
                raise NodePortRangeExhausted("node_port_range_exhausted")
            _record_normative_event(
                connection,
                aggregate_type="media_node",
                aggregate_id=node.id,
                event_type="media_node.created",
                payload={
                    "name": node.name,
                    "external_port": node.external_port,
                    "api_port": node.api_port,
                    "metrics_port": node.metrics_port,
                    "release_id": node.release_id,
                    "creation_mode": node.creation_mode.value,
                    "camera_capacity": node.camera_capacity,
                    "desired_revision": node.desired_revision,
                },
                aggregate_revision=node.desired_revision,
            )
            return node

    def list_nodes(self) -> tuple[MediaNode, ...]:
        with self._engine.connect() as connection:
            rows = connection.execute(select(media_nodes).order_by(media_nodes.c.id)).mappings()
            return tuple(_media_node(row) for row in rows)

    def get_node(self, node_id: UUID) -> MediaNode | None:
        with self._engine.connect() as connection:
            row = connection.execute(
                select(media_nodes).where(media_nodes.c.id == node_id)
            ).mappings().one_or_none()
            return None if row is None else _media_node(row)

    def apply_runtime_observation(
        self,
        node_id: UUID,
        observation: NodeRuntimeObservation,
    ) -> MediaNode:
        with self._engine.begin() as connection:
            current = connection.execute(
                select(media_nodes)
                .where(media_nodes.c.id == node_id)
                .with_for_update()
            ).mappings().one_or_none()
            if current is None:
                raise NodeNotFound("node_not_found")
            node = _media_node(current)
            try:
                validate_runtime_observation(node, observation)
            except InvalidNodeRuntimeObservation:
                raise
            row = connection.execute(
                update(media_nodes)
                .where(media_nodes.c.id == node_id)
                .values(
                    runtime_state=observation.state.value,
                    health=observation.health.value,
                )
                .values(
                    management_fresh=observation.management_fresh,
                    management_observed_at=(
                        func.clock_timestamp() if observation.management_fresh else None
                    ),
                    runtime_observed_at=func.clock_timestamp(),
                    config_compatible=observation.config_compatible,
                    applied_revision=observation.applied_revision,
                    process_id=observation.process_id,
                    process_start_ticks=observation.process_start_ticks,
                    process_boot_id=observation.process_boot_id,
                    observed_config_sha256=observation.config_sha256,
                    observed_release_id=observation.release_id,
                )
                .returning(*media_nodes.c)
            ).mappings().one_or_none()
            if row is None:
                raise NodeNotFound("node_not_found")
            return _media_node(row)

    def request_desired_state(self, node_id: UUID, state: NodeState) -> MediaNode:
        with self._engine.begin() as connection:
            _require_synchronous_commit(connection)
            current = connection.execute(
                select(media_nodes)
                .where(media_nodes.c.id == node_id)
                .with_for_update()
            ).mappings().one_or_none()
            if current is None:
                raise NodeNotFound("node_not_found")
            node = _media_node(current)
            if node.state is state:
                return node
            desired_revision = node.desired_revision + 1
            row = connection.execute(
                update(media_nodes)
                .where(media_nodes.c.id == node_id)
                .values(state=state.value, desired_revision=desired_revision)
                .returning(*media_nodes.c)
            ).mappings().one()
            _record_normative_event(
                connection,
                aggregate_type="media_node",
                aggregate_id=node_id,
                event_type="media_node.desired_state_changed",
                payload={
                    "previous_state": node.state.value,
                    "state": state.value,
                    "desired_revision": desired_revision,
                },
                aggregate_revision=desired_revision,
            )
            return _media_node(row)

    def request_stop(self, node_id: UUID) -> MediaNode:
        with self._engine.begin() as connection:
            _require_synchronous_commit(connection)
            self._lock_placements(connection)
            current = connection.execute(
                select(media_nodes)
                .where(media_nodes.c.id == node_id)
                .with_for_update()
            ).mappings().one_or_none()
            if current is None:
                raise NodeNotFound("node_not_found")
            node = _media_node(current)
            if node.registered_cameras:
                raise NodeNotEmpty("node_not_empty")
            if node.state is NodeState.STOPPED:
                return node
            desired_revision = node.desired_revision + 1
            row = connection.execute(
                update(media_nodes)
                .where(media_nodes.c.id == node_id)
                .values(
                    state=NodeState.STOPPED.value,
                    desired_revision=desired_revision,
                )
                .returning(*media_nodes.c)
            ).mappings().one()
            _record_normative_event(
                connection,
                aggregate_type="media_node",
                aggregate_id=node_id,
                event_type="media_node.desired_state_changed",
                payload={
                    "previous_state": node.state.value,
                    "state": NodeState.STOPPED.value,
                    "desired_revision": desired_revision,
                },
                aggregate_revision=desired_revision,
            )
            return _media_node(row)

    def request_restart(self, node_id: UUID) -> MediaNode:
        with self._engine.begin() as connection:
            _require_synchronous_commit(connection)
            self._lock_placements(connection)
            current = connection.execute(
                select(media_nodes)
                .where(media_nodes.c.id == node_id)
                .with_for_update()
            ).mappings().one_or_none()
            if current is None:
                raise NodeNotFound("node_not_found")
            node = _media_node(current)
            if node.state is not NodeState.RUNNING:
                raise NodeLifecycleConflict("node_not_running")
            if node.registered_cameras:
                raise NodeNotEmpty("node_not_empty")
            desired_revision = node.desired_revision + 1
            row = connection.execute(
                update(media_nodes)
                .where(media_nodes.c.id == node_id)
                .values(desired_revision=desired_revision)
                .returning(*media_nodes.c)
            ).mappings().one()
            _record_normative_event(
                connection,
                aggregate_type="media_node",
                aggregate_id=node_id,
                event_type="media_node.restart_requested",
                payload={"desired_revision": desired_revision},
                aggregate_revision=desired_revision,
            )
            return _media_node(row)

    def request_release(
        self,
        node_id: UUID,
        *,
        release_id: str,
        mediamtx_binary_sha256: str,
    ) -> MediaNode:
        if not release_id or len(release_id) > 128:
            raise ValueError("node_release_id_invalid")
        if len(mediamtx_binary_sha256) != 64 or any(
            character not in "0123456789abcdef"
            for character in mediamtx_binary_sha256
        ):
            raise ValueError("node_binary_sha256_invalid")
        with self._engine.begin() as connection:
            _require_synchronous_commit(connection)
            self._lock_placements(connection)
            current = connection.execute(
                select(media_nodes)
                .where(media_nodes.c.id == node_id)
                .with_for_update()
            ).mappings().one_or_none()
            if current is None:
                raise NodeNotFound("node_not_found")
            node = _media_node(current)
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
            desired_revision = node.desired_revision + 1
            row = connection.execute(
                update(media_nodes)
                .where(media_nodes.c.id == node_id)
                .values(
                    release_id=release_id,
                    mediamtx_binary_sha256=mediamtx_binary_sha256,
                    desired_revision=desired_revision,
                    applied_revision=0,
                    management_fresh=False,
                    management_observed_at=None,
                    config_compatible=False,
                )
                .returning(*media_nodes.c)
            ).mappings().one()
            _record_normative_event(
                connection,
                aggregate_type="media_node",
                aggregate_id=node_id,
                event_type="media_node.release_changed",
                payload={
                    "previous_release_id": node.release_id,
                    "release_id": release_id,
                    "desired_revision": desired_revision,
                },
                aggregate_revision=desired_revision,
            )
            return _media_node(row)

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
        with self._engine.begin() as connection:
            _require_synchronous_commit(connection)
            self._lock_placements(connection)
            selected = connection.execute(
                select(media_nodes)
                .where(
                    media_nodes.c.state == NodeState.RUNNING.value,
                    media_nodes.c.runtime_state == NodeState.RUNNING.value,
                    media_nodes.c.health == NodeHealth.HEALTHY.value,
                    media_nodes.c.management_fresh.is_(True),
                    media_nodes.c.management_observed_at
                    >= func.clock_timestamp()
                    - timedelta(seconds=management_freshness_seconds),
                    media_nodes.c.config_compatible.is_(True),
                    media_nodes.c.applied_revision == media_nodes.c.desired_revision,
                    media_nodes.c.maintenance.is_(False),
                    media_nodes.c.registered_cameras < media_nodes.c.camera_capacity,
                )
                .order_by(
                    media_nodes.c.registered_cameras,
                    media_nodes.c.active_sources,
                    media_nodes.c.id,
                )
                .limit(1)
                .with_for_update()
            ).mappings().one_or_none()
            if selected is None:
                raise EligibleNodeMissing("eligible_node_missing")
            else:
                selected_node = _media_node(selected)
            return self._insert_camera(
                connection=connection,
                selected=selected_node,
                camera_id=camera_id,
                name=name,
                source_url=source_url,
                public_id=public_id,
                placement_mode=PlacementMode.AUTOMATIC,
            )

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
        with self._engine.begin() as connection:
            _require_synchronous_commit(connection)
            self._lock_placements(connection)
            selected = connection.execute(
                select(media_nodes)
                .where(media_nodes.c.id == node_id)
                .with_for_update()
            ).mappings().one_or_none()
            if selected is None:
                raise NodeNotFound("node_not_found")
            node = _media_node(selected)
            if node.registered_cameras >= node.camera_capacity:
                raise NodeCameraCapacityReached("node_camera_capacity_reached")
            database_now = connection.scalar(select(func.clock_timestamp()))
            if database_now is None or not is_node_eligible(
                node,
                management_freshness_seconds=management_freshness_seconds,
                now=database_now,
            ):
                raise EligibleNodeMissing("manual_node_ineligible")
            return self._insert_camera(
                connection=connection,
                selected=node,
                camera_id=camera_id,
                name=name,
                source_url=source_url,
                public_id=public_id,
                placement_mode=PlacementMode.MANUAL,
            )

    def list_cameras(self) -> tuple[CameraPlacement, ...]:
        statement = (
            select(
                cameras.c.id,
                cameras.c.name,
                cameras.c.source_url,
                cameras.c.public_id,
                cameras.c.desired_revision,
                cameras.c.applied_revision,
                camera_placements.c.node_id,
                camera_placements.c.placement_mode,
                media_nodes.c.external_port.label("node_port"),
            )
            .join(camera_placements, camera_placements.c.camera_id == cameras.c.id)
            .join(media_nodes, media_nodes.c.id == camera_placements.c.node_id)
            .order_by(cameras.c.id)
        )
        with self._engine.connect() as connection:
            return tuple(_camera_placement(row) for row in connection.execute(statement).mappings())

    def _lock_placements(self, connection: Connection) -> None:
        connection.execute(
            text("SELECT pg_advisory_xact_lock(:key)"),
            {"key": _CAMERA_PLACEMENT_LOCK_KEY},
        )

    def _insert_camera(
        self,
        *,
        connection: Connection,
        selected: MediaNode,
        camera_id: UUID,
        name: str,
        source_url: str,
        public_id: PublicId,
        placement_mode: PlacementMode,
    ) -> CameraPlacement:
        connection.execute(
            insert(cameras).values(
                id=camera_id,
                name=name,
                source_url=source_url,
                public_id=str(public_id),
                desired_revision=1,
                applied_revision=0,
            )
        )
        connection.execute(
            insert(camera_placements).values(
                camera_id=camera_id,
                node_id=selected.id,
                placement_mode=placement_mode.value,
                generation=1,
            )
        )
        connection.execute(
            insert(camera_placement_history).values(
                camera_id=camera_id,
                node_id=selected.id,
                placement_mode=placement_mode.value,
                generation=1,
            )
        )
        connection.execute(
            update(media_nodes)
            .where(media_nodes.c.id == selected.id)
            .values(registered_cameras=selected.registered_cameras + 1)
        )
        _record_normative_event(
            connection,
            aggregate_type="camera",
            aggregate_id=camera_id,
            event_type="camera.created",
            payload={
                "name": name,
                "public_id": str(public_id),
                "node_id": str(selected.id),
                "placement_mode": placement_mode.value,
                "placement_generation": 1,
                "desired_revision": 1,
            },
            aggregate_revision=1,
        )
        return CameraPlacement(
            id=camera_id,
            name=name,
            source_url=source_url,
            public_id=public_id,
            node_id=selected.id,
            node_port=selected.external_port,
            placement_mode=placement_mode,
            desired_revision=1,
            applied_revision=0,
        )

    def close(self) -> None:
        self._engine.dispose()
        self._lock_engine.dispose()
        self._provision_engine.dispose()


def _media_node(row: RowMapping) -> MediaNode:
    return MediaNode(
        id=_uuid(row["id"]),
        name=str(row["name"]),
        external_port=int(row["external_port"]),
        api_port=int(row["api_port"]),
        metrics_port=int(row["metrics_port"]),
        release_id=str(row["release_id"]),
        mediamtx_binary_sha256=str(row["mediamtx_binary_sha256"]),
        creation_mode=NodeCreationMode(str(row["creation_mode"])),
        state=NodeState(str(row["state"])),
        runtime_state=NodeState(str(row["runtime_state"])),
        health=NodeHealth(str(row["health"])),
        registered_cameras=int(row["registered_cameras"]),
        camera_capacity=int(row["camera_capacity"]),
        active_sources=int(row["active_sources"]),
        maintenance=bool(row["maintenance"]),
        management_fresh=bool(row["management_fresh"]),
        management_observed_at=row["management_observed_at"],
        runtime_observed_at=row["runtime_observed_at"],
        config_compatible=bool(row["config_compatible"]),
        desired_revision=int(row["desired_revision"]),
        applied_revision=int(row["applied_revision"]),
        process_id=(None if row["process_id"] is None else int(row["process_id"])),
        process_start_ticks=(
            None
            if row["process_start_ticks"] is None
            else int(row["process_start_ticks"])
        ),
        process_boot_id=(
            None if row["process_boot_id"] is None else _uuid(row["process_boot_id"])
        ),
        observed_config_sha256=(
            None
            if row["observed_config_sha256"] is None
            else str(row["observed_config_sha256"])
        ),
        observed_release_id=(
            None
            if row["observed_release_id"] is None
            else str(row["observed_release_id"])
        ),
    )


def _uuid(value: object) -> UUID:
    if isinstance(value, UUID):
        return value
    return UUID(str(value))


def _camera_placement(row: RowMapping) -> CameraPlacement:
    return CameraPlacement(
        id=_uuid(row["id"]),
        name=str(row["name"]),
        source_url=str(row["source_url"]),
        public_id=PublicId.parse(str(row["public_id"])),
        node_id=_uuid(row["node_id"]),
        node_port=int(row["node_port"]),
        placement_mode=PlacementMode(str(row["placement_mode"])),
        desired_revision=int(row["desired_revision"]),
        applied_revision=int(row["applied_revision"]),
    )


def _record_normative_event(
    connection: Connection,
    *,
    aggregate_type: str,
    aggregate_id: UUID,
    event_type: str,
    payload: dict[str, object],
    aggregate_revision: int,
) -> None:
    event_id = uuid4()
    values = {
        "id": event_id,
        "aggregate_type": aggregate_type,
        "aggregate_id": aggregate_id,
        "event_type": event_type,
        "aggregate_revision": aggregate_revision,
        "payload": payload,
    }
    connection.execute(insert(audit_events).values(**values))
    connection.execute(insert(outbox_messages).values(**values))


def _require_synchronous_commit(connection: Connection) -> None:
    connection.execute(text("SET LOCAL synchronous_commit = on"))


def _is_external_port_conflict(error: IntegrityError) -> bool:
    diagnostic = getattr(error.orig, "diag", None)
    return getattr(diagnostic, "constraint_name", None) == "media_nodes_external_port_key"
