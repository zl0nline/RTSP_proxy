from __future__ import annotations

import hashlib
import math
import time
from collections.abc import Callable, Collection, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta
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
    delete,
    func,
    insert,
    or_,
    select,
    text,
    update,
)
from sqlalchemy.dialects.postgresql import ARRAY, CIDR, JSONB
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.exc import TimeoutError as SQLAlchemyTimeoutError
from sqlalchemy.sql.base import Executable
from sqlalchemy.sql.selectable import Select

from rtsp_proxy.access import AccessGrant, AccessPolicy, AccessTarget
from rtsp_proxy.identifiers import PublicId
from rtsp_proxy.nodes import (
    CameraCatalogItem,
    CameraCatalogPage,
    CameraCatalogQuery,
    CameraCatalogUnavailable,
    CameraLifecycleConflict,
    CameraMove,
    CameraMoveExpired,
    CameraMoveState,
    CameraNotFound,
    CameraPlacement,
    CameraRevisionConflict,
    CameraState,
    EligibleNodeMissing,
    InvalidNodeRuntimeObservation,
    MaximumNodesReached,
    MediaNode,
    NodeCameraCapacityReached,
    NodeCommandFence,
    NodeCreationMode,
    NodeHealth,
    NodeIdFactory,
    NodeLifecycleBusy,
    NodeLifecycleConflict,
    NodeManagementPortRangeExhausted,
    NodeMutationContext,
    NodeNotEmpty,
    NodeNotFound,
    NodePortChange,
    NodePortChangeState,
    NodePortInUse,
    NodePortOutOfRange,
    NodePortRangeExhausted,
    NodeRegistrationIdempotency,
    NodeRegistrationResult,
    NodeReleaseConflict,
    NodeRuntimeObservation,
    NodeRuntimeUnavailable,
    NodeState,
    PlacementMode,
    PortBindable,
    PortChoice,
    camera_move_is_terminal,
    camera_placement_fingerprint,
    is_node_eligible,
    select_port_with_bounded_recheck,
    validate_camera_name,
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
    CheckConstraint("observed_config_sha256 IS NULL OR observed_config_sha256 ~ '^[0-9a-f]{64}$'"),
)

node_registration_requests = Table(
    "node_registration_requests",
    metadata,
    Column("actor_session_id", Uuid(as_uuid=True), primary_key=True),
    Column("idempotency_key", Uuid(as_uuid=True), primary_key=True),
    Column("actor_account_id", Uuid(as_uuid=True), nullable=False),
    Column("request_sha256", String(64), nullable=False),
    Column("node_id", Uuid(as_uuid=True), nullable=False),
    Column(
        "created_at",
        DateTime(timezone=True),
        nullable=False,
        server_default=func.clock_timestamp(),
    ),
    CheckConstraint(
        "request_sha256 ~ '^[0-9a-f]{64}$'",
        name="node_registration_requests_sha256_valid",
    ),
)

cameras = Table(
    "cameras",
    metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    Column("name", String(128), nullable=False),
    Column("source_url", Text, nullable=False),
    Column("public_id", String(26), nullable=False, unique=True),
    Column("state", String(16), nullable=False),
    Column("desired_revision", BigInteger, nullable=False),
    Column("applied_revision", BigInteger, nullable=False),
    CheckConstraint(
        "state = 'deleted' OR ("
        "length(name) BETWEEN 1 AND 128 "
        "AND btrim(name) <> '' "
        "AND name !~ '[[:cntrl:]]')",
        name="ck_cameras_name",
    ),
    CheckConstraint("public_id ~ '^[a-z2-7]{25}[aeimquy4]$'"),
    CheckConstraint(
        "octet_length(source_url) BETWEEN 1 AND 8192 "
        "AND lower(source_url) LIKE 'rtsp://%/%' "
        "AND length(split_part(source_url, '/', 3)) > 0 "
        "AND position('@' IN split_part(source_url, '/', 3)) = 0 "
        "AND position('?' IN source_url) = 0 "
        "AND position('#' IN source_url) = 0",
        name="ck_cameras_source_url",
    ),
    CheckConstraint("state IN ('enabled', 'disabled', 'deleting', 'deleted')"),
    CheckConstraint("desired_revision >= 1"),
    CheckConstraint("applied_revision BETWEEN 0 AND desired_revision"),
)

public_id_tombstones = Table(
    "public_id_tombstones",
    metadata,
    Column("public_id", String(26), primary_key=True),
    Column(
        "created_at",
        DateTime(timezone=True),
        nullable=False,
        server_default=text("clock_timestamp()"),
    ),
    CheckConstraint("public_id ~ '^[a-z2-7]{25}[aeimquy4]$'"),
)

camera_access_policies = Table(
    "camera_access_policies",
    metadata,
    Column(
        "camera_id",
        Uuid(as_uuid=True),
        ForeignKey("cameras.id", ondelete="RESTRICT"),
        primary_key=True,
    ),
    Column("internet_cidrs", ARRAY(CIDR()), nullable=False),
    Column("local_cidrs", ARRAY(CIDR()), nullable=False),
    Column("revision", BigInteger, nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    CheckConstraint("revision >= 1"),
    CheckConstraint("cardinality(internet_cidrs) <= 128"),
    CheckConstraint("cardinality(local_cidrs) <= 128"),
)

camera_access_grants = Table(
    "camera_access_grants",
    metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    Column(
        "camera_id",
        Uuid(as_uuid=True),
        ForeignKey("cameras.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    ),
    Column("username", String(64), nullable=False, unique=True),
    Column("token_verifier", String(64), nullable=False),
    Column("pepper_key_id", String(64), nullable=False),
    Column("not_before", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("revoked_at", DateTime(timezone=True), nullable=True),
    Column("kind", String(16), nullable=False),
    Column("created_by", String(128), nullable=False),
    Column("last_used_at", DateTime(timezone=True), nullable=True),
    Column("revision", BigInteger, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    CheckConstraint("username ~ '^grant-[0-9a-f]{32}$'"),
    CheckConstraint("token_verifier ~ '^[0-9a-f]{64}$'"),
    CheckConstraint("not_before < expires_at"),
    CheckConstraint("revision >= 1"),
    CheckConstraint("kind IN ('temporary', 'service')"),
    CheckConstraint("length(created_by) BETWEEN 1 AND 128"),
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

camera_move_sagas = Table(
    "camera_move_sagas",
    metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    Column(
        "camera_id",
        Uuid(as_uuid=True),
        ForeignKey("cameras.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    ),
    Column(
        "source_node_id",
        Uuid(as_uuid=True),
        nullable=False,
    ),
    Column(
        "target_node_id",
        Uuid(as_uuid=True),
        nullable=False,
    ),
    Column("source_generation", BigInteger, nullable=False),
    Column("target_generation", BigInteger, nullable=False),
    Column("desired_revision", BigInteger, nullable=False),
    Column("force", Boolean, nullable=False),
    Column("confirmed_disconnect_readers", Integer, nullable=False),
    Column("source_port", Integer, nullable=True),
    Column("target_port", Integer, nullable=True),
    Column("source_endpoint", String(512), nullable=True),
    Column("target_endpoint", String(512), nullable=True),
    Column("abort_reason", String(64), nullable=True),
    Column("state", String(32), nullable=False),
    Column(
        "created_at",
        DateTime(timezone=True),
        nullable=False,
        server_default=text("clock_timestamp()"),
    ),
    Column(
        "completed_at",
        DateTime(timezone=True),
        nullable=True,
    ),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    CheckConstraint("source_node_id <> target_node_id"),
    CheckConstraint("source_generation >= 1"),
    CheckConstraint("target_generation = source_generation + 1"),
    CheckConstraint("desired_revision >= 2"),
    CheckConstraint("confirmed_disconnect_readers BETWEEN 0 AND 1"),
    CheckConstraint("source_port IS NULL OR source_port BETWEEN 1 AND 65535"),
    CheckConstraint("target_port IS NULL OR target_port BETWEEN 1 AND 65535"),
    CheckConstraint(
        "state IN ('complete', 'aborted') OR "
        "(source_port IS NOT NULL AND target_port IS NOT NULL "
        "AND source_endpoint IS NOT NULL AND target_endpoint IS NOT NULL)"
    ),
    CheckConstraint(
        "state IN ('prepare_target', 'activate_target', 'cleanup_source', "
        "'cleanup_target', 'complete', 'aborted')"
    ),
)

node_port_change_sagas = Table(
    "node_port_change_sagas",
    metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    Column(
        "node_id",
        Uuid(as_uuid=True),
        nullable=False,
        index=True,
    ),
    Column("old_port", Integer, nullable=False),
    Column("new_port", Integer, nullable=False),
    Column("source_revision", BigInteger, nullable=False),
    Column("target_revision", BigInteger, nullable=False),
    Column("registered_cameras", Integer, nullable=False),
    Column("blast_radius_sha256", String(64), nullable=False),
    Column("state", String(16), nullable=False),
    Column(
        "created_at",
        DateTime(timezone=True),
        nullable=False,
        server_default=text("clock_timestamp()"),
    ),
    Column("completed_at", DateTime(timezone=True), nullable=True),
    CheckConstraint("old_port BETWEEN 1 AND 65535"),
    CheckConstraint("new_port BETWEEN 1 AND 65535"),
    CheckConstraint("old_port <> new_port"),
    CheckConstraint("source_revision >= 1"),
    CheckConstraint("target_revision = source_revision + 1"),
    CheckConstraint("registered_cameras BETWEEN 0 AND 100"),
    CheckConstraint("blast_radius_sha256 ~ '^[0-9a-f]{64}$'"),
    CheckConstraint("state IN ('prepared', 'complete', 'aborted')"),
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
_CAMERA_CATALOG_INDEX_DEFINITIONS = {
    "ix_camera_placements_catalog_node_camera": (
        "CREATE INDEX ix_camera_placements_catalog_node_camera "
        "ON public.camera_placements USING btree (node_id, camera_id)"
    ),
    "ix_cameras_catalog_name_trgm": (
        "CREATE INDEX ix_cameras_catalog_name_trgm "
        "ON public.cameras USING gin (name gin_trgm_ops)"
    ),
    "ix_cameras_catalog_public_id_trgm": (
        "CREATE INDEX ix_cameras_catalog_public_id_trgm "
        "ON public.cameras USING gin (public_id gin_trgm_ops)"
    ),
    "ix_cameras_catalog_state_id": (
        "CREATE INDEX ix_cameras_catalog_state_id "
        "ON public.cameras USING btree (state, id) "
        "WHERE ((state)::text <> 'deleted'::text)"
    ),
}


class DatabaseSchemaMismatch(RuntimeError):
    """The live PostgreSQL revision is incompatible with this application."""


class PostgresNodeStore:
    def __init__(
        self,
        database_url: str,
        *,
        lifecycle_lock_pool_size: int = 4,
        lifecycle_lock_timeout_seconds: float = 5,
        statement_timeout_ms: int | None = None,
    ) -> None:
        if lifecycle_lock_pool_size < 2 or lifecycle_lock_pool_size > 16:
            raise ValueError("node_lifecycle_lock_pool_size_invalid")
        if lifecycle_lock_timeout_seconds <= 0 or lifecycle_lock_timeout_seconds > 30:
            raise ValueError("node_lifecycle_lock_timeout_invalid")
        if statement_timeout_ms is not None and not 100 <= statement_timeout_ms <= 5000:
            raise ValueError("database_statement_timeout_invalid")
        connect_args = (
            {}
            if statement_timeout_ms is None
            else {
                "connect_timeout": max(1, math.ceil(statement_timeout_ms / 1000)),
                "options": f"-c statement_timeout={statement_timeout_ms}",
            }
        )
        self._engine = create_engine(
            database_url,
            pool_pre_ping=True,
            hide_parameters=True,
            pool_timeout=min(1.0, lifecycle_lock_timeout_seconds),
            connect_args=connect_args,
        )
        self._lock_engine = create_engine(
            database_url,
            pool_pre_ping=True,
            hide_parameters=True,
            pool_size=lifecycle_lock_pool_size,
            max_overflow=0,
            pool_timeout=min(0.05, lifecycle_lock_timeout_seconds),
            connect_args=connect_args,
        )
        self._provision_engine = create_engine(
            database_url,
            pool_pre_ping=True,
            hide_parameters=True,
            pool_size=1,
            max_overflow=0,
            pool_timeout=lifecycle_lock_timeout_seconds,
            connect_args=connect_args,
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
        if revisions not in (
            ("0012_operator_sessions",),
            ("0013_operator_login",),
            ("0014_camera_catalog_projection",),
            ("0015_camera_name_contract",),
            (APPLICATION_SCHEMA,),
        ):
            raise DatabaseSchemaMismatch("database_schema_mismatch")

    def assert_schema_current(self) -> None:
        try:
            with self._engine.connect() as connection:
                revisions = tuple(
                    connection.scalars(text("SELECT version_num FROM alembic_version"))
                )
        except SQLAlchemyError:
            raise DatabaseSchemaMismatch("database_schema_mismatch") from None
        if revisions != (APPLICATION_SCHEMA,):
            raise DatabaseSchemaMismatch("database_schema_mismatch")

    def schema_is_current(self) -> bool:
        try:
            self.assert_schema_current()
        except DatabaseSchemaMismatch:
            return False
        return True

    def schema_supports_operator_login(self) -> bool:
        try:
            with self._engine.connect() as connection:
                revisions = tuple(
                    connection.scalars(text("SELECT version_num FROM alembic_version"))
                )
        except SQLAlchemyError:
            raise DatabaseSchemaMismatch("database_schema_mismatch") from None
        return revisions in (
            ("0013_operator_login",),
            ("0014_camera_catalog_projection",),
            ("0015_camera_name_contract",),
            (APPLICATION_SCHEMA,),
        )

    def assert_camera_catalog_ready(self) -> None:
        try:
            with self._engine.connect() as connection:
                self._require_camera_catalog_projection(connection)
        except CameraCatalogUnavailable:
            raise
        except SQLAlchemyError:
            raise CameraCatalogUnavailable("camera_catalog_unavailable") from None

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
            with self._lock_connection() as connection:
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
        *,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> None:
        deadline = time.monotonic() + self._lifecycle_lock_timeout_seconds
        while True:
            if cancelled():
                raise NodeLifecycleBusy("node_lifecycle_busy")
            if connection.scalar(statement, parameters):
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise NodeLifecycleBusy("node_lifecycle_busy")
            time.sleep(min(0.05, remaining))

    @contextmanager
    def _lock_connection(
        self,
        *,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> Iterator[Connection]:
        deadline = time.monotonic() + self._lifecycle_lock_timeout_seconds
        while True:
            if cancelled():
                raise NodeLifecycleBusy("node_lifecycle_busy")
            try:
                connection = self._lock_engine.connect()
            except SQLAlchemyTimeoutError:
                if time.monotonic() >= deadline:
                    raise NodeLifecycleBusy("node_lifecycle_busy") from None
                continue
            try:
                yield connection
            finally:
                connection.close()
            return

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
        mutation_context: NodeMutationContext | None = None,
        registration_idempotency: NodeRegistrationIdempotency | None = None,
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
            occupied.update(
                connection.scalars(
                    select(node_port_change_sagas.c.new_port).where(
                        node_port_change_sagas.c.state == NodePortChangeState.PREPARED.value
                    )
                )
            )
            if preferred_port is not None and preferred_port in occupied:
                raise NodePortInUse("node_port_in_use")
            available = tuple(port for port in allowed_ports if port not in occupied)
            if not available:
                raise NodePortRangeExhausted("node_port_range_exhausted")
            probe = is_port_bindable or (lambda port: True)
            occupied_management = set(connection.scalars(select(media_nodes.c.api_port)))
            occupied_management.update(connection.scalars(select(media_nodes.c.metrics_port)))
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
                    preferred_port if preferred_port is not None else choose_port(tuple(candidates))
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
                                mediamtx_binary_sha256=(candidate.mediamtx_binary_sha256),
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
                                observed_config_sha256=(candidate.observed_config_sha256),
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
                mutation_context=mutation_context,
            )
            if registration_idempotency is not None:
                connection.execute(
                    insert(node_registration_requests).values(
                        actor_session_id=registration_idempotency.actor_session_id,
                        idempotency_key=registration_idempotency.key,
                        actor_account_id=registration_idempotency.actor_account_id,
                        request_sha256=registration_idempotency.request_sha256,
                        node_id=node.id,
                    )
                )
            return node

    def register_idempotently(
        self,
        *,
        name: str,
        allowed_ports: Collection[int],
        max_nodes: int,
        preferred_port: int | None,
        choose_port: PortChoice,
        new_node_id: NodeIdFactory,
        idempotency: NodeRegistrationIdempotency,
        api_ports: Collection[int] = tuple(range(20000, 20100)),
        metrics_ports: Collection[int] = tuple(range(20100, 20200)),
        release_id: str = "0.1.0",
        mediamtx_binary_sha256: str = "0" * 64,
        creation_mode: NodeCreationMode = NodeCreationMode.OPERATOR,
        is_port_bindable: PortBindable | None = None,
        mutation_context: NodeMutationContext | None = None,
    ) -> NodeRegistrationResult:
        try:
            self.assert_schema_current()
        except DatabaseSchemaMismatch:
            raise NodeRuntimeUnavailable(
                "node_registration_schema_unavailable"
            ) from None
        advisory_key = _registration_advisory_key(idempotency)
        with self._lock_engine.begin() as guard:
            guard.execute(
                text("SELECT pg_advisory_xact_lock(:key)"),
                {"key": advisory_key},
            )
            previous = (
                guard.execute(
                    select(node_registration_requests).where(
                        node_registration_requests.c.actor_session_id
                        == idempotency.actor_session_id,
                        node_registration_requests.c.idempotency_key == idempotency.key,
                    )
                )
                .mappings()
                .one_or_none()
            )
            if previous is not None:
                if (
                    _uuid(previous["actor_account_id"])
                    != idempotency.actor_account_id
                    or str(previous["request_sha256"])
                    != idempotency.request_sha256
                ):
                    raise NodeLifecycleConflict("node_idempotency_conflict")
                node_row = (
                    guard.execute(
                        select(media_nodes).where(
                            media_nodes.c.id == _uuid(previous["node_id"])
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if node_row is None:
                    raise NodeLifecycleConflict("node_idempotency_target_missing")
                return NodeRegistrationResult(
                    node=_media_node(node_row),
                    replayed=True,
                )
            node = self.register_automatically(
                name=name,
                allowed_ports=allowed_ports,
                max_nodes=max_nodes,
                preferred_port=preferred_port,
                choose_port=choose_port,
                new_node_id=new_node_id,
                api_ports=api_ports,
                metrics_ports=metrics_ports,
                release_id=release_id,
                mediamtx_binary_sha256=mediamtx_binary_sha256,
                creation_mode=creation_mode,
                is_port_bindable=is_port_bindable,
                mutation_context=mutation_context,
                registration_idempotency=idempotency,
            )
            return NodeRegistrationResult(node=node, replayed=False)

    def lookup_registration(
        self,
        idempotency: NodeRegistrationIdempotency,
    ) -> NodeRegistrationResult | None:
        try:
            self.assert_schema_current()
        except DatabaseSchemaMismatch:
            raise NodeRuntimeUnavailable(
                "node_registration_schema_unavailable"
            ) from None
        with self._engine.connect() as connection:
            previous = (
                connection.execute(
                    select(node_registration_requests).where(
                        node_registration_requests.c.actor_session_id
                        == idempotency.actor_session_id,
                        node_registration_requests.c.idempotency_key == idempotency.key,
                    )
                )
                .mappings()
                .one_or_none()
            )
            if previous is None:
                return None
            if (
                _uuid(previous["actor_account_id"]) != idempotency.actor_account_id
                or str(previous["request_sha256"]) != idempotency.request_sha256
            ):
                raise NodeLifecycleConflict("node_idempotency_conflict")
            node_row = (
                connection.execute(
                    select(media_nodes).where(
                        media_nodes.c.id == _uuid(previous["node_id"])
                    )
                )
                .mappings()
                .one_or_none()
            )
            if node_row is None:
                raise NodeLifecycleConflict("node_idempotency_target_missing")
            return NodeRegistrationResult(
                node=_media_node(node_row),
                replayed=True,
            )

    def list_nodes(self) -> tuple[MediaNode, ...]:
        with self._engine.connect() as connection:
            rows = connection.execute(select(media_nodes).order_by(media_nodes.c.id)).mappings()
            return tuple(_media_node(row) for row in rows)

    def get_node(self, node_id: UUID) -> MediaNode | None:
        with self._engine.connect() as connection:
            row = (
                connection.execute(select(media_nodes).where(media_nodes.c.id == node_id))
                .mappings()
                .one_or_none()
            )
            return None if row is None else _media_node(row)

    def list_camera_move_targets(
        self,
        camera_id: UUID,
        *,
        management_freshness_seconds: int = 30,
    ) -> tuple[MediaNode, ...]:
        with self._engine.connect() as connection:
            placement = (
                connection.execute(
                    select(
                        cameras.c.state,
                        camera_placements.c.node_id,
                    )
                    .join(
                        camera_placements,
                        camera_placements.c.camera_id == cameras.c.id,
                    )
                    .where(cameras.c.id == camera_id)
                )
                .mappings()
                .one_or_none()
            )
            if placement is None or placement["state"] == CameraState.DELETED.value:
                raise CameraNotFound("camera_not_found")
            if placement["state"] != CameraState.ENABLED.value:
                raise CameraLifecycleConflict("camera_not_enabled")
            prepared_nodes = frozenset(
                connection.scalars(
                    select(node_port_change_sagas.c.node_id).where(
                        node_port_change_sagas.c.state
                        == NodePortChangeState.PREPARED.value
                    )
                )
            )
            source_node_id = UUID(str(placement["node_id"]))
            if source_node_id in prepared_nodes:
                return ()
            database_now = connection.scalar(select(func.clock_timestamp()))
            if database_now is None:
                return ()
            rows = connection.execute(
                select(media_nodes)
                .where(media_nodes.c.id != source_node_id)
                .order_by(media_nodes.c.id)
            ).mappings()
            return tuple(
                node
                for row in rows
                if (node := _media_node(row)).id not in prepared_nodes
                and is_node_eligible(
                    node,
                    management_freshness_seconds=management_freshness_seconds,
                    now=database_now,
                )
            )

    def apply_runtime_observation(
        self,
        node_id: UUID,
        observation: NodeRuntimeObservation,
    ) -> MediaNode:
        with self._engine.begin() as connection:
            current = (
                connection.execute(
                    select(media_nodes).where(media_nodes.c.id == node_id).with_for_update()
                )
                .mappings()
                .one_or_none()
            )
            if current is None:
                raise NodeNotFound("node_not_found")
            node = _media_node(current)
            try:
                validate_runtime_observation(node, observation)
            except InvalidNodeRuntimeObservation:
                raise
            row = (
                connection.execute(
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
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise NodeNotFound("node_not_found")
            return _media_node(row)

    def request_desired_state(
        self,
        node_id: UUID,
        state: NodeState,
        *,
        fence: NodeCommandFence | None = None,
        mutation_context: NodeMutationContext | None = None,
    ) -> MediaNode:
        with self._engine.begin() as connection:
            _require_synchronous_commit(connection)
            current = (
                connection.execute(
                    select(media_nodes).where(media_nodes.c.id == node_id).with_for_update()
                )
                .mappings()
                .one_or_none()
            )
            if current is None:
                raise NodeNotFound("node_not_found")
            node = _media_node(current)
            _require_node_command_fence(node, fence)
            if state is NodeState.RUNNING and node.state not in {
                NodeState.PROVISIONING,
                NodeState.STOPPED,
                NodeState.FAILED,
                NodeState.RUNNING,
            }:
                raise NodeLifecycleConflict("node_start_source_state_invalid")
            if node.state is state:
                return node
            desired_revision = node.desired_revision + 1
            row = (
                connection.execute(
                    update(media_nodes)
                    .where(media_nodes.c.id == node_id)
                    .values(state=state.value, desired_revision=desired_revision)
                    .returning(*media_nodes.c)
                )
                .mappings()
                .one()
            )
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
                mutation_context=mutation_context,
            )
            return _media_node(row)

    def request_administrative_state(
        self,
        node_id: UUID,
        state: NodeState,
        *,
        fence: NodeCommandFence | None = None,
        mutation_context: NodeMutationContext | None = None,
    ) -> MediaNode:
        with self._engine.begin() as connection:
            _require_synchronous_commit(connection)
            self._lock_placements(connection)
            current = (
                connection.execute(
                    select(media_nodes).where(media_nodes.c.id == node_id).with_for_update()
                )
                .mappings()
                .one_or_none()
            )
            if current is None:
                raise NodeNotFound("node_not_found")
            node = _media_node(current)
            _require_node_command_fence(node, fence)
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
            row = (
                connection.execute(
                    update(media_nodes)
                    .where(media_nodes.c.id == node_id)
                    .values(
                        state=state.value,
                        maintenance=state is NodeState.MAINTENANCE,
                        desired_revision=desired_revision,
                        applied_revision=desired_revision,
                    )
                    .returning(*media_nodes.c)
                )
                .mappings()
                .one()
            )
            _record_normative_event(
                connection,
                aggregate_type="media_node",
                aggregate_id=node_id,
                event_type="media_node.administrative_state_changed",
                payload={
                    "previous_state": node.state.value,
                    "state": state.value,
                    "desired_revision": desired_revision,
                },
                aggregate_revision=desired_revision,
                mutation_context=mutation_context,
            )
            return _media_node(row)

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
        mutation_context: NodeMutationContext | None = None,
    ) -> NodePortChange:
        with self._engine.begin() as connection:
            _require_synchronous_commit(connection)
            connection.execute(
                text("SELECT pg_advisory_xact_lock(:key)"),
                {"key": _NODE_REGISTRY_LOCK_KEY},
            )
            self._lock_placements(connection)
            current = (
                connection.execute(
                    select(media_nodes).where(media_nodes.c.id == node_id).with_for_update()
                )
                .mappings()
                .one_or_none()
            )
            if current is None:
                raise NodeNotFound("node_not_found")
            node = _media_node(current)
            if new_port not in allowed_ports:
                raise NodePortOutOfRange("node_port_out_of_range")
            if node.state is not NodeState.RUNNING or node.runtime_state is not NodeState.RUNNING:
                raise NodeLifecycleConflict("node_not_running")
            if node.desired_revision != expected_revision:
                raise NodeLifecycleConflict("node_revision_conflict")
            placements = tuple(
                (
                    _uuid(row["camera_id"]),
                    int(row["generation"]),
                )
                for row in connection.execute(
                    select(
                        camera_placements.c.camera_id,
                        camera_placements.c.generation,
                    ).where(camera_placements.c.node_id == node_id)
                ).mappings()
            )
            blast_radius_sha256 = camera_placement_fingerprint(placements)
            if (
                node.registered_cameras != expected_registered_cameras
                or len(placements) != expected_registered_cameras
                or blast_radius_sha256 != expected_blast_radius_sha256
            ):
                raise NodeLifecycleConflict("node_blast_radius_changed")
            if node.external_port == new_port:
                raise NodeLifecycleConflict("node_port_unchanged")
            reserved = connection.scalar(
                select(func.count())
                .select_from(media_nodes)
                .where(
                    media_nodes.c.external_port == new_port,
                    media_nodes.c.id != node_id,
                )
            ) or connection.scalar(
                select(func.count())
                .select_from(node_port_change_sagas)
                .where(
                    node_port_change_sagas.c.new_port == new_port,
                    node_port_change_sagas.c.state == NodePortChangeState.PREPARED.value,
                )
            )
            if reserved:
                raise NodePortInUse("node_port_in_use")
            active = connection.scalar(
                select(func.count())
                .select_from(node_port_change_sagas)
                .where(
                    node_port_change_sagas.c.node_id == node_id,
                    node_port_change_sagas.c.state == NodePortChangeState.PREPARED.value,
                )
            )
            active_moves = connection.scalar(
                select(func.count())
                .select_from(camera_move_sagas)
                .where(
                    (
                        (camera_move_sagas.c.source_node_id == node_id)
                        | (camera_move_sagas.c.target_node_id == node_id)
                    ),
                    camera_move_sagas.c.state.not_in(
                        (CameraMoveState.COMPLETE.value, CameraMoveState.ABORTED.value)
                    ),
                )
            )
            if active or active_moves:
                raise NodeLifecycleConflict("node_operation_in_progress")
            row = (
                connection.execute(
                    insert(node_port_change_sagas)
                    .values(
                        id=change_id,
                        node_id=node_id,
                        old_port=node.external_port,
                        new_port=new_port,
                        source_revision=node.desired_revision,
                        target_revision=node.desired_revision + 1,
                        registered_cameras=expected_registered_cameras,
                        blast_radius_sha256=expected_blast_radius_sha256,
                        state=NodePortChangeState.PREPARED.value,
                    )
                    .returning(*node_port_change_sagas.c)
                )
                .mappings()
                .one()
            )
            _record_normative_event(
                connection,
                aggregate_type="media_node",
                aggregate_id=node_id,
                event_type="media_node.port_change_prepared",
                payload={
                    "change_id": str(change_id),
                    "blast_radius_sha256": expected_blast_radius_sha256,
                    "old_port": node.external_port,
                    "new_port": new_port,
                    "registered_cameras": expected_registered_cameras,
                    "target_revision": node.desired_revision + 1,
                },
                aggregate_revision=node.desired_revision + 1,
                mutation_context=mutation_context,
            )
            return _node_port_change(row)

    def list_incomplete_port_changes(self) -> tuple[NodePortChange, ...]:
        with self._engine.connect() as connection:
            return tuple(
                _node_port_change(row)
                for row in connection.execute(
                    select(node_port_change_sagas)
                    .where(node_port_change_sagas.c.state == NodePortChangeState.PREPARED.value)
                    .order_by(node_port_change_sagas.c.created_at)
                ).mappings()
            )

    def complete_port_change(
        self,
        change_id: UUID,
        observation: NodeRuntimeObservation,
    ) -> MediaNode:
        return self._finish_port_change(change_id, observation, complete=True)

    def abort_port_change(
        self,
        change_id: UUID,
        observation: NodeRuntimeObservation,
    ) -> MediaNode:
        return self._finish_port_change(change_id, observation, complete=False)

    def _finish_port_change(
        self,
        change_id: UUID,
        observation: NodeRuntimeObservation,
        *,
        complete: bool,
    ) -> MediaNode:
        with self._engine.begin() as connection:
            _require_synchronous_commit(connection)
            connection.execute(
                text("SELECT pg_advisory_xact_lock(:key)"),
                {"key": _NODE_REGISTRY_LOCK_KEY},
            )
            change_row = (
                connection.execute(
                    select(node_port_change_sagas)
                    .where(node_port_change_sagas.c.id == change_id)
                    .with_for_update()
                )
                .mappings()
                .one_or_none()
            )
            if change_row is None:
                raise NodeNotFound("node_port_change_not_found")
            change = _node_port_change(change_row)
            node_row = (
                connection.execute(
                    select(media_nodes).where(media_nodes.c.id == change.node_id).with_for_update()
                )
                .mappings()
                .one()
            )
            node = _media_node(node_row)
            expected_state = (
                NodePortChangeState.COMPLETE if complete else NodePortChangeState.ABORTED
            )
            if change.state is expected_state:
                return node
            if change.state is not NodePortChangeState.PREPARED:
                raise NodeLifecycleConflict("node_port_change_not_prepared")
            provisional = replace(
                node,
                external_port=change.new_port if complete else change.old_port,
                desired_revision=(change.target_revision if complete else change.source_revision),
            )
            validate_runtime_observation(provisional, observation)
            values = {
                "state": provisional.state.value,
                "external_port": provisional.external_port,
                "desired_revision": provisional.desired_revision,
                "runtime_state": observation.state.value,
                "health": observation.health.value,
                "management_fresh": observation.management_fresh,
                "management_observed_at": (
                    func.clock_timestamp() if observation.management_fresh else None
                ),
                "runtime_observed_at": func.clock_timestamp(),
                "config_compatible": observation.config_compatible,
                "applied_revision": observation.applied_revision,
                "process_id": observation.process_id,
                "process_start_ticks": observation.process_start_ticks,
                "process_boot_id": observation.process_boot_id,
                "observed_config_sha256": observation.config_sha256,
                "observed_release_id": observation.release_id,
            }
            node_result = (
                connection.execute(
                    update(media_nodes)
                    .where(media_nodes.c.id == node.id)
                    .values(**values)
                    .returning(*media_nodes.c)
                )
                .mappings()
                .one()
            )
            connection.execute(
                update(node_port_change_sagas)
                .where(node_port_change_sagas.c.id == change_id)
                .values(
                    state=expected_state.value,
                    completed_at=func.clock_timestamp(),
                )
            )
            _record_normative_event(
                connection,
                aggregate_type="media_node",
                aggregate_id=node.id,
                event_type=(
                    "media_node.port_changed" if complete else "media_node.port_change_aborted"
                ),
                payload={
                    "change_id": str(change.id),
                    "old_port": change.old_port,
                    "new_port": change.new_port,
                },
                aggregate_revision=(change.target_revision if complete else change.source_revision),
            )
            return _media_node(node_result)

    def request_node_delete(
        self,
        node_id: UUID,
        *,
        fence: NodeCommandFence | None = None,
        mutation_context: NodeMutationContext | None = None,
    ) -> MediaNode:
        with self._engine.begin() as connection:
            _require_synchronous_commit(connection)
            self._lock_placements(connection)
            current = (
                connection.execute(
                    select(media_nodes).where(media_nodes.c.id == node_id).with_for_update()
                )
                .mappings()
                .one_or_none()
            )
            if current is None:
                raise NodeNotFound("node_not_found")
            node = _media_node(current)
            _require_node_command_fence(node, fence)
            if node.registered_cameras:
                raise NodeNotEmpty("node_not_empty")
            if node.state not in {NodeState.STOPPED, NodeState.FAILED, NodeState.DELETING}:
                raise NodeLifecycleConflict("node_delete_requires_stopped_or_failed")
            active_move = connection.scalar(
                select(func.count())
                .select_from(camera_move_sagas)
                .where(
                    (
                        (camera_move_sagas.c.source_node_id == node_id)
                        | (camera_move_sagas.c.target_node_id == node_id)
                    ),
                    camera_move_sagas.c.state.not_in(
                        (CameraMoveState.COMPLETE.value, CameraMoveState.ABORTED.value)
                    ),
                )
            )
            active_port = connection.scalar(
                select(func.count())
                .select_from(node_port_change_sagas)
                .where(
                    node_port_change_sagas.c.node_id == node_id,
                    node_port_change_sagas.c.state == NodePortChangeState.PREPARED.value,
                )
            )
            if active_move or active_port:
                raise NodeLifecycleConflict("node_operation_in_progress")
            if node.state is NodeState.DELETING:
                return node
            desired_revision = node.desired_revision + 1
            row = (
                connection.execute(
                    update(media_nodes)
                    .where(media_nodes.c.id == node_id)
                    .values(
                        state=NodeState.DELETING.value,
                        desired_revision=desired_revision,
                        management_fresh=False,
                        management_observed_at=None,
                    )
                    .returning(*media_nodes.c)
                )
                .mappings()
                .one()
            )
            _record_normative_event(
                connection,
                aggregate_type="media_node",
                aggregate_id=node_id,
                event_type="media_node.delete_requested",
                payload={"desired_revision": desired_revision},
                aggregate_revision=desired_revision,
                mutation_context=mutation_context,
            )
            return _media_node(row)

    def finalize_node_delete(self, node_id: UUID) -> None:
        with self._engine.begin() as connection:
            _require_synchronous_commit(connection)
            self._lock_placements(connection)
            current = (
                connection.execute(
                    select(media_nodes).where(media_nodes.c.id == node_id).with_for_update()
                )
                .mappings()
                .one_or_none()
            )
            if current is None:
                return
            node = _media_node(current)
            if node.state is not NodeState.DELETING or node.registered_cameras:
                raise NodeLifecycleConflict("node_delete_not_ready")
            current_placements = connection.scalar(
                select(func.count())
                .select_from(camera_placements)
                .where(camera_placements.c.node_id == node_id)
            )
            if current_placements:
                raise NodeNotEmpty("node_not_empty")
            connection.execute(delete(media_nodes).where(media_nodes.c.id == node_id))

    def request_stop(
        self,
        node_id: UUID,
        *,
        fence: NodeCommandFence | None = None,
        mutation_context: NodeMutationContext | None = None,
    ) -> MediaNode:
        with self._engine.begin() as connection:
            _require_synchronous_commit(connection)
            self._lock_placements(connection)
            current = (
                connection.execute(
                    select(media_nodes).where(media_nodes.c.id == node_id).with_for_update()
                )
                .mappings()
                .one_or_none()
            )
            if current is None:
                raise NodeNotFound("node_not_found")
            node = _media_node(current)
            _require_node_command_fence(node, fence)
            self._require_no_active_node_move(connection, node_id)
            if node.registered_cameras:
                raise NodeNotEmpty("node_not_empty")
            if node.state is NodeState.STOPPED:
                return node
            if node.state not in {
                NodeState.PROVISIONING,
                NodeState.RUNNING,
                NodeState.DRAINING,
                NodeState.MAINTENANCE,
            }:
                raise NodeLifecycleConflict("node_stop_source_state_invalid")
            desired_revision = node.desired_revision + 1
            row = (
                connection.execute(
                    update(media_nodes)
                    .where(media_nodes.c.id == node_id)
                    .values(
                        state=NodeState.STOPPED.value,
                        maintenance=False,
                        desired_revision=desired_revision,
                    )
                    .returning(*media_nodes.c)
                )
                .mappings()
                .one()
            )
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
                mutation_context=mutation_context,
            )
            return _media_node(row)

    def request_restart(
        self,
        node_id: UUID,
        *,
        fence: NodeCommandFence | None = None,
        mutation_context: NodeMutationContext | None = None,
    ) -> MediaNode:
        with self._engine.begin() as connection:
            _require_synchronous_commit(connection)
            self._lock_placements(connection)
            current = (
                connection.execute(
                    select(media_nodes).where(media_nodes.c.id == node_id).with_for_update()
                )
                .mappings()
                .one_or_none()
            )
            if current is None:
                raise NodeNotFound("node_not_found")
            node = _media_node(current)
            _require_node_command_fence(node, fence)
            self._require_no_active_node_move(connection, node_id)
            if node.state is not NodeState.RUNNING:
                raise NodeLifecycleConflict("node_not_running")
            if node.registered_cameras:
                raise NodeNotEmpty("node_not_empty")
            desired_revision = node.desired_revision + 1
            row = (
                connection.execute(
                    update(media_nodes)
                    .where(media_nodes.c.id == node_id)
                    .values(desired_revision=desired_revision)
                    .returning(*media_nodes.c)
                )
                .mappings()
                .one()
            )
            _record_normative_event(
                connection,
                aggregate_type="media_node",
                aggregate_id=node_id,
                event_type="media_node.restart_requested",
                payload={"desired_revision": desired_revision},
                aggregate_revision=desired_revision,
                mutation_context=mutation_context,
            )
            return _media_node(row)

    def request_reconfigure(
        self,
        node_id: UUID,
        *,
        expected_revision: int,
        expected_registered_cameras: int,
        expected_blast_radius_sha256: str,
        release_id: str | None = None,
        mediamtx_binary_sha256: str | None = None,
        mutation_context: NodeMutationContext | None = None,
    ) -> MediaNode:
        if (release_id is None) != (mediamtx_binary_sha256 is None):
            raise ValueError("node_release_identity_incomplete")
        if release_id is not None and mediamtx_binary_sha256 is not None:
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
            current = (
                connection.execute(
                    select(media_nodes).where(media_nodes.c.id == node_id).with_for_update()
                )
                .mappings()
                .one_or_none()
            )
            if current is None:
                raise NodeNotFound("node_not_found")
            node = _media_node(current)
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
            self._require_no_active_node_move(connection, node_id)
            if connection.scalar(
                select(func.count())
                .select_from(node_port_change_sagas)
                .where(
                    node_port_change_sagas.c.node_id == node_id,
                    node_port_change_sagas.c.state == NodePortChangeState.PREPARED.value,
                )
            ):
                raise NodeLifecycleConflict("node_operation_in_progress")
            placements = tuple(
                (_uuid(row["camera_id"]), int(row["generation"]))
                for row in connection.execute(
                    select(
                        camera_placements.c.camera_id,
                        camera_placements.c.generation,
                    ).where(camera_placements.c.node_id == node_id)
                ).mappings()
            )
            if (
                node.registered_cameras != expected_registered_cameras
                or len(placements) != expected_registered_cameras
                or camera_placement_fingerprint(placements) != expected_blast_radius_sha256
            ):
                raise NodeLifecycleConflict("node_blast_radius_changed")
            desired_revision = node.desired_revision + 1
            release_changed = release_id is not None and (
                node.release_id != release_id
                or node.mediamtx_binary_sha256 != mediamtx_binary_sha256
            )
            row = (
                connection.execute(
                    update(media_nodes)
                    .where(media_nodes.c.id == node_id)
                    .values(
                        release_id=node.release_id if release_id is None else release_id,
                        mediamtx_binary_sha256=(
                            node.mediamtx_binary_sha256
                            if mediamtx_binary_sha256 is None
                            else mediamtx_binary_sha256
                        ),
                        desired_revision=desired_revision,
                        applied_revision=0 if release_changed else node.applied_revision,
                        management_fresh=False,
                        management_observed_at=None,
                        config_compatible=False,
                    )
                    .returning(*media_nodes.c)
                )
                .mappings()
                .one()
            )
            _record_normative_event(
                connection,
                aggregate_type="media_node",
                aggregate_id=node_id,
                event_type="media_node.reconfigure_requested",
                payload={
                    "blast_radius_sha256": expected_blast_radius_sha256,
                    "external_port": node.external_port,
                    "registered_cameras": expected_registered_cameras,
                    "desired_revision": desired_revision,
                    "previous_release_id": node.release_id,
                    "release_id": node.release_id if release_id is None else release_id,
                    "release_changed": release_changed,
                },
                aggregate_revision=desired_revision,
                mutation_context=mutation_context,
            )
            return _media_node(row)

    def request_release(
        self,
        node_id: UUID,
        *,
        release_id: str,
        mediamtx_binary_sha256: str,
        fence: NodeCommandFence | None = None,
        mutation_context: NodeMutationContext | None = None,
    ) -> MediaNode:
        if not release_id or len(release_id) > 128:
            raise ValueError("node_release_id_invalid")
        if len(mediamtx_binary_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in mediamtx_binary_sha256
        ):
            raise ValueError("node_binary_sha256_invalid")
        with self._engine.begin() as connection:
            _require_synchronous_commit(connection)
            self._lock_placements(connection)
            current = (
                connection.execute(
                    select(media_nodes).where(media_nodes.c.id == node_id).with_for_update()
                )
                .mappings()
                .one_or_none()
            )
            if current is None:
                raise NodeNotFound("node_not_found")
            node = _media_node(current)
            _require_node_command_fence(node, fence)
            self._require_no_active_node_move(connection, node_id)
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
            row = (
                connection.execute(
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
                )
                .mappings()
                .one()
            )
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
                mutation_context=mutation_context,
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
        name = validate_camera_name(name)
        source_url = validate_camera_source_url(source_url)
        with self._engine.begin() as connection:
            _require_synchronous_commit(connection)
            self._lock_placements(connection)
            selected = (
                connection.execute(
                    select(media_nodes)
                    .where(
                        media_nodes.c.state == NodeState.RUNNING.value,
                        media_nodes.c.runtime_state == NodeState.RUNNING.value,
                        media_nodes.c.health == NodeHealth.HEALTHY.value,
                        media_nodes.c.management_fresh.is_(True),
                        media_nodes.c.management_observed_at
                        >= func.clock_timestamp() - timedelta(seconds=management_freshness_seconds),
                        media_nodes.c.config_compatible.is_(True),
                        media_nodes.c.applied_revision == media_nodes.c.desired_revision,
                        media_nodes.c.maintenance.is_(False),
                        media_nodes.c.registered_cameras < media_nodes.c.camera_capacity,
                        media_nodes.c.id.not_in(
                            select(node_port_change_sagas.c.node_id).where(
                                node_port_change_sagas.c.state
                                == NodePortChangeState.PREPARED.value
                            )
                        ),
                    )
                    .order_by(
                        media_nodes.c.registered_cameras,
                        media_nodes.c.active_sources,
                        media_nodes.c.id,
                    )
                    .limit(1)
                    .with_for_update()
                )
                .mappings()
                .one_or_none()
            )
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
        name = validate_camera_name(name)
        source_url = validate_camera_source_url(source_url)
        with self._engine.begin() as connection:
            _require_synchronous_commit(connection)
            self._lock_placements(connection)
            selected = (
                connection.execute(
                    select(media_nodes).where(media_nodes.c.id == node_id).with_for_update()
                )
                .mappings()
                .one_or_none()
            )
            if selected is None:
                raise NodeNotFound("node_not_found")
            node = _media_node(selected)
            if node.registered_cameras >= node.camera_capacity:
                raise NodeCameraCapacityReached("node_camera_capacity_reached")
            if self._has_active_port_change(connection, node_id):
                raise EligibleNodeMissing("manual_node_ineligible")
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
        with self._engine.connect() as connection:
            return tuple(
                _camera_placement(row)
                for row in connection.execute(
                    self._camera_query().where(cameras.c.state != CameraState.DELETED.value)
                ).mappings()
            )

    def camera_catalog(self, query: CameraCatalogQuery) -> CameraCatalogPage:
        statement = self._camera_catalog_query()
        if query.after is not None:
            statement = statement.where(cameras.c.id > query.after)
        if query.node_id is not None:
            statement = statement.where(camera_placements.c.node_id == query.node_id)
        if query.state is not None:
            statement = statement.where(cameras.c.state == query.state.value)
        if query.search is not None:
            escaped = (
                query.search.replace("\\", "\\\\")
                .replace("%", "\\%")
                .replace("_", "\\_")
            )
            pattern = f"%{escaped}%"
            statement = statement.where(
                or_(
                    cameras.c.name.like(pattern, escape="\\"),
                    cameras.c.public_id.like(pattern, escape="\\"),
                )
            )
        try:
            with self._engine.connect() as connection:
                self._require_camera_catalog_projection(connection)
                rows = tuple(
                    connection.execute(statement.limit(query.limit + 1)).mappings()
                )
        except CameraCatalogUnavailable:
            raise
        except SQLAlchemyError:
            raise CameraCatalogUnavailable("camera_catalog_unavailable") from None
        has_more = len(rows) > query.limit
        items = tuple(_camera_catalog_item(row) for row in rows[: query.limit])
        return CameraCatalogPage(
            items=items,
            next_after=items[-1].id if has_more else None,
        )

    def camera_detail(self, camera_id: UUID) -> CameraCatalogItem | None:
        try:
            with self._engine.connect() as connection:
                self._require_camera_catalog_projection(connection)
                row = (
                    connection.execute(
                        self._camera_catalog_query().where(cameras.c.id == camera_id)
                    )
                    .mappings()
                    .one_or_none()
                )
        except CameraCatalogUnavailable:
            raise
        except SQLAlchemyError:
            raise CameraCatalogUnavailable("camera_catalog_unavailable") from None
        return None if row is None else _camera_catalog_item(row)

    def get_camera(self, camera_id: UUID) -> CameraPlacement | None:
        with self._engine.connect() as connection:
            row = (
                connection.execute(
                    self._camera_query().where(
                        cameras.c.id == camera_id,
                        cameras.c.state != CameraState.DELETED.value,
                    )
                )
                .mappings()
                .one_or_none()
            )
            return None if row is None else _camera_placement(row)

    def list_node_cameras(self, node_id: UUID) -> tuple[CameraPlacement, ...]:
        with self._engine.connect() as connection:
            if (
                connection.scalar(
                    select(func.count()).select_from(media_nodes).where(media_nodes.c.id == node_id)
                )
                == 0
            ):
                raise NodeNotFound("node_not_found")
            return tuple(
                _camera_placement(row)
                for row in connection.execute(
                    self._camera_query().where(camera_placements.c.node_id == node_id)
                ).mappings()
            )

    def list_node_active_moves(self, node_id: UUID) -> tuple[CameraMove, ...]:
        statement = (
            select(
                camera_move_sagas,
                cameras.c.public_id,
                cameras.c.source_url,
            )
            .join(cameras, cameras.c.id == camera_move_sagas.c.camera_id)
            .where(
                (
                    (camera_move_sagas.c.source_node_id == node_id)
                    | (camera_move_sagas.c.target_node_id == node_id)
                ),
                camera_move_sagas.c.state.not_in(
                    (CameraMoveState.COMPLETE.value, CameraMoveState.ABORTED.value)
                ),
            )
            .order_by(camera_move_sagas.c.id)
        )
        with self._engine.connect() as connection:
            return tuple(_camera_move(row) for row in connection.execute(statement).mappings())

    @staticmethod
    def _camera_query() -> Select[tuple[object, ...]]:
        return (
            select(
                cameras.c.id,
                cameras.c.name,
                cameras.c.source_url,
                cameras.c.public_id,
                cameras.c.state,
                cameras.c.desired_revision,
                cameras.c.applied_revision,
                camera_placements.c.node_id,
                camera_placements.c.placement_mode,
                camera_placements.c.generation.label("placement_generation"),
                media_nodes.c.external_port.label("node_port"),
            )
            .join(camera_placements, camera_placements.c.camera_id == cameras.c.id)
            .join(media_nodes, media_nodes.c.id == camera_placements.c.node_id)
            .order_by(cameras.c.id)
        )

    @staticmethod
    def _camera_catalog_query() -> Select[tuple[object, ...]]:
        return (
            select(
                cameras.c.id,
                cameras.c.name,
                cameras.c.public_id,
                cameras.c.state,
                cameras.c.desired_revision,
                cameras.c.applied_revision,
                camera_placements.c.node_id,
                camera_placements.c.placement_mode,
                media_nodes.c.name.label("node_name"),
                media_nodes.c.external_port.label("node_port"),
            )
            .join(camera_placements, camera_placements.c.camera_id == cameras.c.id)
            .join(media_nodes, media_nodes.c.id == camera_placements.c.node_id)
            .where(cameras.c.state != CameraState.DELETED.value)
            .order_by(cameras.c.id)
        )

    @staticmethod
    def _require_camera_catalog_projection(connection: Connection) -> None:
        revisions = tuple(
            connection.scalars(text("SELECT version_num FROM alembic_version"))
        )
        if revisions not in (
            ("0015_camera_name_contract",),
            (APPLICATION_SCHEMA,),
        ):
            raise CameraCatalogUnavailable("camera_catalog_unavailable")
        if connection.scalar(
            text("SELECT count(*) FROM pg_extension WHERE extname = 'pg_trgm'")
        ) != 1:
            raise CameraCatalogUnavailable("camera_catalog_unavailable")
        observed = {
            name: (definition, valid, ready, live)
            for name, definition, valid, ready, live in connection.execute(
                text(
                    "SELECT index_class.relname, pg_get_indexdef(index_row.indexrelid), "
                    "index_row.indisvalid, index_row.indisready, index_row.indislive "
                    "FROM pg_index AS index_row "
                    "JOIN pg_class AS index_class "
                    "ON index_class.oid = index_row.indexrelid "
                    "JOIN pg_namespace AS index_namespace "
                    "ON index_namespace.oid = index_class.relnamespace "
                    "WHERE index_namespace.nspname = 'public' "
                    "AND index_class.relname IN ("
                    "'ix_camera_placements_catalog_node_camera', "
                    "'ix_cameras_catalog_name_trgm', "
                    "'ix_cameras_catalog_public_id_trgm', "
                    "'ix_cameras_catalog_state_id')"
                )
            ).tuples()
        }
        expected = {
            name: (definition, True, True, True)
            for name, definition in _CAMERA_CATALOG_INDEX_DEFINITIONS.items()
        }
        if observed != expected:
            raise CameraCatalogUnavailable("camera_catalog_unavailable")

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
        with self._engine.begin() as connection:
            _require_synchronous_commit(connection)
            self._lock_placements(connection)
            current = (
                connection.execute(
                    self._camera_query()
                    .where(cameras.c.id == camera_id)
                    .with_for_update(of=cameras)
                )
                .mappings()
                .one_or_none()
            )
            if current is None:
                raise CameraNotFound("camera_not_found")
            camera = _camera_placement(current)
            if camera.state is CameraState.DELETED:
                raise CameraNotFound("camera_not_found")
            if camera.state is CameraState.DELETING:
                raise CameraLifecycleConflict("camera_deleting")
            if expected_revision is not None and camera.desired_revision != expected_revision:
                raise CameraRevisionConflict(
                    expected_revision=expected_revision,
                    current_revision=camera.desired_revision,
                )
            self._require_no_active_camera_move(connection, camera_id)
            self._require_no_active_port_change(connection, camera.node_id)
            if camera.name == name and camera.source_url == source_url:
                return camera
            desired_revision = camera.desired_revision + 1
            connection.execute(
                update(cameras)
                .where(cameras.c.id == camera_id)
                .values(
                    name=name,
                    source_url=source_url,
                    desired_revision=desired_revision,
                )
            )
            _record_normative_event(
                connection,
                aggregate_type="camera",
                aggregate_id=camera_id,
                event_type="camera.updated",
                payload={
                    "name": name,
                    "node_id": str(camera.node_id),
                    "placement_generation": camera.placement_generation,
                    "desired_revision": desired_revision,
                },
                aggregate_revision=desired_revision,
            )
            return CameraPlacement(
                id=camera.id,
                name=name,
                source_url=source_url,
                public_id=camera.public_id,
                node_id=camera.node_id,
                node_port=camera.node_port,
                placement_mode=camera.placement_mode,
                placement_generation=camera.placement_generation,
                state=camera.state,
                desired_revision=desired_revision,
                applied_revision=camera.applied_revision,
            )

    def set_camera_enabled(
        self,
        camera_id: UUID,
        *,
        enabled: bool,
        expected_revision: int | None = None,
    ) -> CameraPlacement:
        with self._engine.begin() as connection:
            _require_synchronous_commit(connection)
            self._lock_placements(connection)
            current = (
                connection.execute(
                    self._camera_query()
                    .where(cameras.c.id == camera_id)
                    .with_for_update(of=cameras)
                )
                .mappings()
                .one_or_none()
            )
            if current is None:
                raise CameraNotFound("camera_not_found")
            camera = _camera_placement(current)
            if camera.state is CameraState.DELETED:
                raise CameraNotFound("camera_not_found")
            if camera.state is CameraState.DELETING:
                raise CameraLifecycleConflict("camera_deleting")
            if expected_revision is not None and camera.desired_revision != expected_revision:
                raise CameraRevisionConflict(
                    expected_revision=expected_revision,
                    current_revision=camera.desired_revision,
                )
            self._require_no_active_camera_move(connection, camera_id)
            self._require_no_active_port_change(connection, camera.node_id)
            target = CameraState.ENABLED if enabled else CameraState.DISABLED
            if camera.state is target:
                return camera
            desired_revision = camera.desired_revision + 1
            connection.execute(
                update(cameras)
                .where(cameras.c.id == camera_id)
                .values(
                    state=target.value,
                    desired_revision=desired_revision,
                )
            )
            _record_normative_event(
                connection,
                aggregate_type="camera",
                aggregate_id=camera_id,
                event_type=(
                    "camera.enabled" if target is CameraState.ENABLED else "camera.disabled"
                ),
                payload={
                    "node_id": str(camera.node_id),
                    "placement_generation": camera.placement_generation,
                    "desired_revision": desired_revision,
                },
                aggregate_revision=desired_revision,
            )
            return replace(
                camera,
                state=target,
                desired_revision=desired_revision,
            )

    def request_camera_delete(
        self,
        camera_id: UUID,
        *,
        expected_revision: int | None = None,
    ) -> CameraPlacement:
        with self._engine.begin() as connection:
            _require_synchronous_commit(connection)
            self._lock_placements(connection)
            current = (
                connection.execute(
                    self._camera_query()
                    .where(cameras.c.id == camera_id)
                    .with_for_update(of=cameras)
                )
                .mappings()
                .one_or_none()
            )
            if current is None:
                raise CameraNotFound("camera_not_found")
            camera = _camera_placement(current)
            if camera.state is CameraState.DELETED:
                raise CameraNotFound("camera_not_found")
            if expected_revision is not None and camera.desired_revision != expected_revision:
                raise CameraRevisionConflict(
                    expected_revision=expected_revision,
                    current_revision=camera.desired_revision,
                )
            if camera.state is CameraState.DELETING:
                return camera
            self._require_no_active_camera_move(connection, camera_id)
            self._require_no_active_port_change(connection, camera.node_id)
            desired_revision = camera.desired_revision + 1
            connection.execute(
                update(cameras)
                .where(cameras.c.id == camera_id)
                .values(
                    state=CameraState.DELETING.value,
                    desired_revision=desired_revision,
                )
            )
            _record_normative_event(
                connection,
                aggregate_type="camera",
                aggregate_id=camera_id,
                event_type="camera.delete_requested",
                payload={
                    "node_id": str(camera.node_id),
                    "placement_generation": camera.placement_generation,
                    "mode": "immediate",
                    "desired_revision": desired_revision,
                },
                aggregate_revision=desired_revision,
            )
            return replace(
                camera,
                state=CameraState.DELETING,
                desired_revision=desired_revision,
            )

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
        management_freshness_seconds: int = 30,
    ) -> CameraMove:
        if timeout_seconds < 1 or timeout_seconds > 3600:
            raise ValueError("camera_move_timeout_invalid")
        with self._engine.begin() as connection:
            _require_synchronous_commit(connection)
            self._lock_placements(connection)
            current = (
                connection.execute(
                    self._camera_query()
                    .where(cameras.c.id == camera_id)
                    .with_for_update(of=(cameras, camera_placements))
                )
                .mappings()
                .one_or_none()
            )
            if current is None:
                raise CameraNotFound("camera_not_found")
            camera = _camera_placement(current)
            if camera.state is not CameraState.ENABLED:
                raise CameraLifecycleConflict("camera_not_enabled")
            if camera.desired_revision != expected_revision:
                raise CameraRevisionConflict(
                    expected_revision=expected_revision,
                    current_revision=camera.desired_revision,
                )
            if camera.node_id == target_node_id:
                raise CameraLifecycleConflict("camera_already_on_target")
            target_row = (
                connection.execute(
                    select(media_nodes).where(media_nodes.c.id == target_node_id).with_for_update()
                )
                .mappings()
                .one_or_none()
            )
            if target_row is None:
                raise NodeNotFound("node_not_found")
            target = _media_node(target_row)
            self._require_no_active_port_change(connection, camera.node_id)
            self._require_no_active_port_change(connection, target.id)
            database_now = connection.scalar(select(func.clock_timestamp()))
            if database_now is None or not is_node_eligible(
                target,
                management_freshness_seconds=management_freshness_seconds,
                now=database_now,
            ):
                raise EligibleNodeMissing("manual_node_ineligible")
            move_expires_at = database_now + timedelta(seconds=timeout_seconds)
            desired_revision = camera.desired_revision + 1
            connection.execute(
                update(cameras)
                .where(cameras.c.id == camera_id)
                .values(desired_revision=desired_revision)
            )
            row = (
                connection.execute(
                    insert(camera_move_sagas)
                    .values(
                        id=move_id,
                        camera_id=camera.id,
                        source_node_id=camera.node_id,
                        target_node_id=target.id,
                        source_generation=camera.placement_generation,
                        target_generation=camera.placement_generation + 1,
                        desired_revision=desired_revision,
                        force=force,
                        confirmed_disconnect_readers=confirmed_disconnect_readers,
                        source_port=camera.node_port,
                        target_port=target.external_port,
                        source_endpoint=(
                            f"rtsp://server:{camera.node_port}/{camera.public_id}"
                        ),
                        target_endpoint=(
                            f"rtsp://server:{target.external_port}/{camera.public_id}"
                        ),
                        expires_at=move_expires_at,
                        state=CameraMoveState.PREPARE_TARGET.value,
                    )
                    .returning(*camera_move_sagas.c)
                )
                .mappings()
                .one()
            )
            _record_normative_event(
                connection,
                aggregate_type="camera",
                aggregate_id=camera.id,
                event_type="camera.move_requested",
                payload={
                    "move_id": str(move_id),
                    "source_node_id": str(camera.node_id),
                    "target_node_id": str(target.id),
                    "source_generation": camera.placement_generation,
                    "target_generation": camera.placement_generation + 1,
                    "force": force,
                    "desired_revision": desired_revision,
                },
                aggregate_revision=desired_revision,
            )
            return _camera_move_with_camera(row, camera)

    def get_camera_move(self, move_id: UUID) -> CameraMove | None:
        statement = (
            select(
                camera_move_sagas,
                cameras.c.public_id,
                cameras.c.source_url,
            )
            .join(cameras, cameras.c.id == camera_move_sagas.c.camera_id)
            .where(camera_move_sagas.c.id == move_id)
        )
        with self._engine.connect() as connection:
            row = connection.execute(statement).mappings().one_or_none()
            return None if row is None else _camera_move(row)

    def list_incomplete_camera_moves(self) -> tuple[CameraMove, ...]:
        statement = (
            select(
                camera_move_sagas,
                cameras.c.public_id,
                cameras.c.source_url,
            )
            .join(cameras, cameras.c.id == camera_move_sagas.c.camera_id)
            .where(
                camera_move_sagas.c.state.not_in(
                    (CameraMoveState.COMPLETE.value, CameraMoveState.ABORTED.value)
                )
            )
            .order_by(camera_move_sagas.c.created_at, camera_move_sagas.c.id)
        )
        with self._engine.connect() as connection:
            return tuple(_camera_move(row) for row in connection.execute(statement).mappings())

    def switch_camera_move(
        self,
        move_id: UUID,
        *,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> CameraMove:
        with self._engine.begin() as connection:
            _require_synchronous_commit(connection)
            self._lock_placements(connection, cancelled=cancelled)
            move_row = (
                connection.execute(
                    select(camera_move_sagas)
                    .where(camera_move_sagas.c.id == move_id)
                    .with_for_update()
                )
                .mappings()
                .one_or_none()
            )
            if move_row is None:
                raise CameraNotFound("camera_move_not_found")
            camera_row = (
                connection.execute(
                    self._camera_query()
                    .where(cameras.c.id == move_row["camera_id"])
                    .with_for_update(of=(cameras, camera_placements))
                )
                .mappings()
                .one_or_none()
            )
            if camera_row is None:
                raise CameraLifecycleConflict("camera_move_fenced")
            camera = _camera_placement(camera_row)
            move = _camera_move_with_camera(move_row, camera)
            if move.state is not CameraMoveState.PREPARE_TARGET:
                return move
            nodes = {
                _uuid(row["id"]): _media_node(row)
                for row in connection.execute(
                    select(media_nodes)
                    .where(media_nodes.c.id.in_((move.source_node_id, move.target_node_id)))
                    .order_by(media_nodes.c.id)
                    .with_for_update()
                ).mappings()
            }
            source = nodes.get(move.source_node_id)
            target = nodes.get(move.target_node_id)
            database_now = connection.scalar(select(func.clock_timestamp()))
            if source is None or target is None:
                raise CameraLifecycleConflict("camera_move_node_missing")
            if database_now is None or move.expires_at <= database_now:
                raise CameraMoveExpired("camera_move_expired")
            self._require_no_active_port_change(connection, source.id)
            self._require_no_active_port_change(connection, target.id)
            if (
                camera.node_id != move.source_node_id
                or camera.placement_generation != move.source_generation
                or camera.desired_revision != move.desired_revision
            ):
                raise CameraLifecycleConflict("camera_move_fenced")
            if not is_node_eligible(target, now=database_now):
                raise EligibleNodeMissing("manual_node_ineligible")
            connection.execute(
                update(camera_placements)
                .where(
                    camera_placements.c.camera_id == camera.id,
                    camera_placements.c.node_id == move.source_node_id,
                    camera_placements.c.generation == move.source_generation,
                )
                .values(
                    node_id=move.target_node_id,
                    placement_mode=PlacementMode.MANUAL.value,
                    generation=move.target_generation,
                )
            )
            connection.execute(
                insert(camera_placement_history).values(
                    camera_id=camera.id,
                    node_id=move.target_node_id,
                    placement_mode=PlacementMode.MANUAL.value,
                    generation=move.target_generation,
                )
            )
            connection.execute(
                update(media_nodes)
                .where(media_nodes.c.id == source.id)
                .values(registered_cameras=source.registered_cameras - 1)
            )
            connection.execute(
                update(media_nodes)
                .where(media_nodes.c.id == target.id)
                .values(registered_cameras=target.registered_cameras + 1)
            )
            row = (
                connection.execute(
                    update(camera_move_sagas)
                    .where(
                        camera_move_sagas.c.id == move.id,
                        camera_move_sagas.c.state == CameraMoveState.PREPARE_TARGET.value,
                    )
                    .values(state=CameraMoveState.CLEANUP_SOURCE.value)
                    .returning(*camera_move_sagas.c)
                )
                .mappings()
                .one()
            )
            return _camera_move_with_camera(row, camera)

    def mark_camera_move_source_cleaned(self, move_id: UUID) -> CameraMove:
        with self._engine.begin() as connection:
            _require_synchronous_commit(connection)
            row = (
                connection.execute(
                    select(
                        camera_move_sagas,
                        cameras.c.public_id,
                        cameras.c.source_url,
                    )
                    .join(cameras, cameras.c.id == camera_move_sagas.c.camera_id)
                    .where(camera_move_sagas.c.id == move_id)
                    .with_for_update(of=(camera_move_sagas, cameras))
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise CameraNotFound("camera_move_not_found")
            current = _camera_move(row)
            if current.state is CameraMoveState.ACTIVATE_TARGET:
                return current
            if current.state is not CameraMoveState.CLEANUP_SOURCE:
                raise CameraLifecycleConflict("camera_move_not_switched")
            connection.execute(
                update(camera_move_sagas)
                .where(
                    camera_move_sagas.c.id == move_id,
                    camera_move_sagas.c.state == CameraMoveState.CLEANUP_SOURCE.value,
                )
                .values(state=CameraMoveState.ACTIVATE_TARGET.value)
            )
            return replace(current, state=CameraMoveState.ACTIVATE_TARGET)

    def complete_camera_move(self, move_id: UUID) -> CameraMove:
        with self._engine.begin() as connection:
            _require_synchronous_commit(connection)
            row = (
                connection.execute(
                    select(
                        camera_move_sagas,
                        cameras.c.public_id,
                        cameras.c.source_url,
                    )
                    .join(cameras, cameras.c.id == camera_move_sagas.c.camera_id)
                    .where(camera_move_sagas.c.id == move_id)
                    .with_for_update(of=camera_move_sagas)
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise CameraNotFound("camera_move_not_found")
            current = _camera_move(row)
            if current.state is CameraMoveState.COMPLETE:
                return current
            if current.state is not CameraMoveState.ACTIVATE_TARGET:
                raise CameraLifecycleConflict("camera_move_not_switched")
            connection.execute(
                update(cameras)
                .where(cameras.c.id == current.camera_id)
                .values(applied_revision=current.desired_revision)
            )
            connection.execute(
                update(camera_move_sagas)
                .where(
                    camera_move_sagas.c.id == move_id,
                    camera_move_sagas.c.state == CameraMoveState.ACTIVATE_TARGET.value,
                )
                .values(
                    state=CameraMoveState.COMPLETE.value,
                    completed_at=func.clock_timestamp(),
                )
            )
            return replace(current, state=CameraMoveState.COMPLETE)

    def request_camera_move_abort(
        self,
        move_id: UUID,
        *,
        reason: str,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> CameraMove:
        if not reason or len(reason) > 64:
            raise ValueError("camera_move_abort_reason_invalid")
        with self._engine.begin() as connection:
            _require_synchronous_commit(connection)
            self._lock_placements(connection, cancelled=cancelled)
            row = (
                connection.execute(
                    select(
                        camera_move_sagas,
                        cameras.c.public_id,
                        cameras.c.source_url,
                        cameras.c.desired_revision.label("camera_desired_revision"),
                    )
                    .join(cameras, cameras.c.id == camera_move_sagas.c.camera_id)
                    .where(camera_move_sagas.c.id == move_id)
                    .with_for_update(of=(camera_move_sagas, cameras))
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise CameraNotFound("camera_move_not_found")
            current = _camera_move(row)
            if (
                camera_move_is_terminal(current.state)
                or current.state is CameraMoveState.CLEANUP_TARGET
            ):
                return current
            if current.state is not CameraMoveState.PREPARE_TARGET:
                raise CameraLifecycleConflict("camera_move_already_switched")
            camera_revision = int(row["camera_desired_revision"])
            abort_revision = camera_revision
            if camera_revision == current.desired_revision:
                abort_revision += 1
                connection.execute(
                    update(cameras)
                    .where(cameras.c.id == current.camera_id)
                    .values(desired_revision=abort_revision)
                )
            connection.execute(
                update(camera_move_sagas)
                .where(
                    camera_move_sagas.c.id == move_id,
                    camera_move_sagas.c.state == CameraMoveState.PREPARE_TARGET.value,
                )
                .values(
                    state=CameraMoveState.CLEANUP_TARGET.value,
                    abort_reason=reason,
                )
            )
            _record_normative_event(
                connection,
                aggregate_type="camera",
                aggregate_id=current.camera_id,
                event_type="camera.move_abort_requested",
                payload={
                    "move_id": str(current.id),
                    "reason": reason,
                    "source_node_id": str(current.source_node_id),
                    "target_node_id": str(current.target_node_id),
                    "desired_revision": abort_revision,
                },
                aggregate_revision=abort_revision,
            )
            return replace(
                current,
                state=CameraMoveState.CLEANUP_TARGET,
                abort_reason=reason,
            )

    def abort_camera_move(self, move_id: UUID) -> CameraMove:
        with self._engine.begin() as connection:
            _require_synchronous_commit(connection)
            row = (
                connection.execute(
                    select(
                        camera_move_sagas,
                        cameras.c.public_id,
                        cameras.c.source_url,
                    )
                    .join(cameras, cameras.c.id == camera_move_sagas.c.camera_id)
                    .where(camera_move_sagas.c.id == move_id)
                    .with_for_update(of=camera_move_sagas)
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise CameraNotFound("camera_move_not_found")
            current = _camera_move(row)
            if current.state is CameraMoveState.ABORTED:
                return current
            if current.state is not CameraMoveState.CLEANUP_TARGET:
                raise CameraLifecycleConflict("camera_move_abort_not_prepared")
            connection.execute(
                update(camera_move_sagas)
                .where(
                    camera_move_sagas.c.id == move_id,
                    camera_move_sagas.c.state == CameraMoveState.CLEANUP_TARGET.value,
                )
                .values(
                    state=CameraMoveState.ABORTED.value,
                    completed_at=func.clock_timestamp(),
                )
            )
            return replace(current, state=CameraMoveState.ABORTED)

    @staticmethod
    def _require_no_active_camera_move(
        connection: Connection,
        camera_id: UUID,
    ) -> None:
        active_move = connection.scalar(
            select(func.count())
            .select_from(camera_move_sagas)
            .where(
                camera_move_sagas.c.camera_id == camera_id,
                camera_move_sagas.c.state.not_in(
                    (CameraMoveState.COMPLETE.value, CameraMoveState.ABORTED.value)
                ),
            )
        )
        if active_move:
            raise CameraLifecycleConflict("camera_move_in_progress")

    @staticmethod
    def _require_no_active_node_move(connection: Connection, node_id: UUID) -> None:
        active_move = connection.scalar(
            select(func.count())
            .select_from(camera_move_sagas)
            .where(
                (
                    (camera_move_sagas.c.source_node_id == node_id)
                    | (camera_move_sagas.c.target_node_id == node_id)
                ),
                camera_move_sagas.c.state.not_in(
                    (CameraMoveState.COMPLETE.value, CameraMoveState.ABORTED.value)
                ),
            )
        )
        if active_move:
            raise NodeLifecycleConflict("node_operation_in_progress")

    @staticmethod
    def _require_no_active_port_change(
        connection: Connection,
        node_id: UUID,
    ) -> None:
        if PostgresNodeStore._has_active_port_change(connection, node_id):
            raise CameraLifecycleConflict("node_port_change_in_progress")

    @staticmethod
    def _has_active_port_change(
        connection: Connection,
        node_id: UUID,
    ) -> bool:
        active_change = connection.scalar(
            select(func.count())
            .select_from(node_port_change_sagas)
            .where(
                node_port_change_sagas.c.node_id == node_id,
                node_port_change_sagas.c.state == NodePortChangeState.PREPARED.value,
            )
        )
        return bool(active_change)

    def mark_camera_applied(
        self,
        *,
        camera_id: UUID,
        node_id: UUID,
        placement_generation: int,
        desired_revision: int,
    ) -> bool:
        with self._engine.begin() as connection:
            current = (
                connection.execute(
                    self._camera_query()
                    .where(
                        cameras.c.id == camera_id,
                        cameras.c.desired_revision == desired_revision,
                        camera_placements.c.node_id == node_id,
                        camera_placements.c.generation == placement_generation,
                    )
                    .with_for_update(of=(cameras, camera_placements))
                )
                .mappings()
                .one_or_none()
            )
            if current is None:
                return False
            camera = _camera_placement(current)
            active_move = connection.scalar(
                select(func.count())
                .select_from(camera_move_sagas)
                .where(
                    camera_move_sagas.c.camera_id == camera_id,
                    camera_move_sagas.c.state.not_in(
                        (CameraMoveState.COMPLETE.value, CameraMoveState.ABORTED.value)
                    ),
                )
            )
            if active_move:
                return False
            if camera.state is CameraState.DELETING:
                connection.execute(
                    delete(camera_placements).where(
                        camera_placements.c.camera_id == camera_id,
                        camera_placements.c.node_id == node_id,
                        camera_placements.c.generation == placement_generation,
                    )
                )
                connection.execute(
                    update(media_nodes)
                    .where(
                        media_nodes.c.id == node_id,
                        media_nodes.c.registered_cameras > 0,
                    )
                    .values(registered_cameras=media_nodes.c.registered_cameras - 1)
                )
                result = connection.execute(
                    update(cameras)
                    .where(
                        cameras.c.id == camera_id,
                        cameras.c.desired_revision == desired_revision,
                    )
                    .values(
                        state=CameraState.DELETED.value,
                        applied_revision=desired_revision,
                    )
                )
                return result.rowcount == 1
            result = connection.execute(
                update(cameras)
                .where(
                    cameras.c.id == camera_id,
                    cameras.c.desired_revision == desired_revision,
                )
                .values(applied_revision=desired_revision)
            )
            return result.rowcount == 1

    @contextmanager
    def reconcile_guard(
        self,
        node_id: UUID,
        *,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> Iterator[None]:
        try:
            with self._lock_connection(cancelled=cancelled) as connection:
                parameters = {"node_id": str(node_id), "seed": _NODE_REGISTRY_LOCK_KEY}
                self._acquire_advisory_lock(
                    connection,
                    text(
                        "SELECT pg_try_advisory_lock("
                        "hashtextextended(CAST(:node_id AS text), :seed))"
                    ),
                    parameters,
                    cancelled=cancelled,
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

    def _lock_placements(
        self,
        connection: Connection,
        *,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> None:
        self._acquire_advisory_lock(
            connection,
            text("SELECT pg_try_advisory_xact_lock(:key)"),
            {"key": _CAMERA_PLACEMENT_LOCK_KEY},
            cancelled=cancelled,
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
        connection.execute(insert(public_id_tombstones).values(public_id=str(public_id)))
        connection.execute(
            insert(cameras).values(
                id=camera_id,
                name=name,
                source_url=source_url,
                public_id=str(public_id),
                state=CameraState.ENABLED.value,
                desired_revision=1,
                applied_revision=0,
            )
        )
        connection.execute(
            insert(camera_access_policies).values(
                camera_id=camera_id,
                internet_cidrs=[],
                local_cidrs=[],
                revision=1,
                updated_at=func.clock_timestamp(),
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
        _record_normative_event(
            connection,
            aggregate_type="camera_access_policy",
            aggregate_id=camera_id,
            event_type="camera.access_policy_created",
            payload={
                "camera_id": str(camera_id),
                "internet_cidrs": [],
                "local_cidrs": [],
                "revision": 1,
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
            state=CameraState.ENABLED,
            desired_revision=1,
            applied_revision=0,
        )

    def get_access_policy(self, camera_id: UUID) -> AccessPolicy | None:
        with self._engine.connect() as connection:
            row = (
                connection.execute(
                    select(camera_access_policies).where(
                        camera_access_policies.c.camera_id == camera_id
                    )
                )
                .mappings()
                .one_or_none()
            )
            return None if row is None else _access_policy(row)

    def set_access_policy(
        self,
        policy: AccessPolicy,
        *,
        expected_revision: int,
    ) -> AccessPolicy:
        if policy.revision != expected_revision + 1:
            raise ValueError("access_policy_revision_invalid")
        with self._engine.begin() as connection:
            _require_synchronous_commit(connection)
            current = (
                connection.execute(
                    select(camera_access_policies)
                    .where(camera_access_policies.c.camera_id == policy.camera_id)
                    .with_for_update()
                )
                .mappings()
                .one_or_none()
            )
            if current is None:
                raise CameraNotFound("camera_not_found")
            if int(current["revision"]) != expected_revision:
                raise CameraLifecycleConflict("access_policy_revision_conflict")
            row = (
                connection.execute(
                    update(camera_access_policies)
                    .where(camera_access_policies.c.camera_id == policy.camera_id)
                    .values(
                        internet_cidrs=list(policy.internet_cidrs),
                        local_cidrs=list(policy.local_cidrs),
                        revision=policy.revision,
                        updated_at=func.clock_timestamp(),
                    )
                    .returning(*camera_access_policies.c)
                )
                .mappings()
                .one()
            )
            _record_normative_event(
                connection,
                aggregate_type="camera_access_policy",
                aggregate_id=policy.camera_id,
                event_type="camera.access_policy_changed",
                payload={
                    "camera_id": str(policy.camera_id),
                    "internet_cidrs": list(policy.internet_cidrs),
                    "local_cidrs": list(policy.local_cidrs),
                    "revision": policy.revision,
                },
                aggregate_revision=policy.revision,
            )
            return _access_policy(row)

    def get_access_target(
        self,
        *,
        node_id: UUID,
        public_id: PublicId,
    ) -> AccessTarget | None:
        with self._engine.connect() as connection:
            row = (
                connection.execute(
                    select(
                        cameras.c.id.label("camera_id"),
                        cameras.c.state.label("camera_state"),
                        camera_placements.c.node_id,
                        media_nodes.c.state.label("node_state"),
                        media_nodes.c.maintenance,
                        cameras.c.public_id,
                        camera_access_policies.c.internet_cidrs,
                        camera_access_policies.c.local_cidrs,
                        camera_access_policies.c.revision,
                    )
                    .select_from(
                        cameras.join(
                            camera_placements,
                            camera_placements.c.camera_id == cameras.c.id,
                        ).join(
                            camera_access_policies,
                            camera_access_policies.c.camera_id == cameras.c.id,
                        ).join(
                            media_nodes,
                            media_nodes.c.id == camera_placements.c.node_id,
                        )
                    )
                    .where(
                        cameras.c.public_id == str(public_id),
                        camera_placements.c.node_id == node_id,
                        cameras.c.state != CameraState.DELETED.value,
                    )
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                return None
            camera_id = _uuid(row["camera_id"])
            return AccessTarget(
                camera_id=camera_id,
                node_id=_uuid(row["node_id"]),
                public_id=PublicId.parse(str(row["public_id"])),
                enabled=(
                    str(row["camera_state"]) == CameraState.ENABLED.value
                    and str(row["node_state"]) == NodeState.RUNNING.value
                    and not bool(row["maintenance"])
                ),
                policy=AccessPolicy(
                    camera_id=camera_id,
                    revision=int(row["revision"]),
                    internet_cidrs=tuple(str(value) for value in row["internet_cidrs"]),
                    local_cidrs=tuple(str(value) for value in row["local_cidrs"]),
                ),
            )

    def get_access_grant(
        self,
        *,
        camera_id: UUID,
        username: str,
    ) -> AccessGrant | None:
        with self._engine.connect() as connection:
            row = (
                connection.execute(
                    select(camera_access_grants).where(
                        camera_access_grants.c.camera_id == camera_id,
                        camera_access_grants.c.username == username,
                    )
                )
                .mappings()
                .one_or_none()
            )
            return None if row is None else _access_grant(row)

    def get_access_grant_by_id(self, grant_id: UUID) -> AccessGrant | None:
        with self._engine.connect() as connection:
            row = (
                connection.execute(
                    select(camera_access_grants).where(camera_access_grants.c.id == grant_id)
                )
                .mappings()
                .one_or_none()
            )
            return None if row is None else _access_grant(row)

    def rehash_access_grant(
        self,
        grant_id: UUID,
        *,
        token_verifier: str,
        pepper_key_id: str,
        expected_revision: int,
    ) -> bool:
        if (
            len(token_verifier) != 64
            or any(character not in "0123456789abcdef" for character in token_verifier)
            or not pepper_key_id
            or len(pepper_key_id) > 64
        ):
            raise ValueError("access_grant_rehash_invalid")
        with self._engine.begin() as connection:
            return bool(
                connection.scalar(
                    select(
                        func.rtsp_proxy_auth_rehash_grant(
                            grant_id,
                            token_verifier,
                            pepper_key_id,
                            expected_revision,
                        )
                    )
                )
            )

    def mark_access_grant_used(self, grant_id: UUID) -> bool:
        with self._engine.begin() as connection:
            return bool(
                connection.scalar(
                    select(func.rtsp_proxy_auth_mark_grant_used(grant_id))
                )
            )

    def create_access_grant(self, grant: AccessGrant) -> AccessGrant:
        with self._engine.begin() as connection:
            _require_synchronous_commit(connection)
            if connection.scalar(
                select(cameras.c.id).where(
                    cameras.c.id == grant.camera_id,
                    cameras.c.state != CameraState.DELETED.value,
                )
            ) is None:
                raise CameraNotFound("camera_not_found")
            row = (
                connection.execute(
                    insert(camera_access_grants)
                    .values(
                        id=grant.id,
                        camera_id=grant.camera_id,
                        username=grant.username,
                        token_verifier=grant.token_verifier,
                        pepper_key_id=grant.pepper_key_id,
                        not_before=grant.not_before,
                        expires_at=grant.expires_at,
                        revoked_at=grant.revoked_at,
                        kind=grant.kind,
                        created_by=grant.created_by,
                        last_used_at=grant.last_used_at,
                        revision=grant.revision,
                        created_at=func.clock_timestamp(),
                    )
                    .returning(*camera_access_grants.c)
                )
                .mappings()
                .one()
            )
            _record_normative_event(
                connection,
                aggregate_type="camera_access_grant",
                aggregate_id=grant.id,
                event_type="camera.access_grant_created",
                payload=_access_grant_event_payload(grant),
                aggregate_revision=grant.revision,
            )
            return _access_grant(row)

    def revoke_access_grant(
        self,
        grant_id: UUID,
        *,
        revoked_at: datetime,
        expected_revision: int,
    ) -> AccessGrant:
        with self._engine.begin() as connection:
            _require_synchronous_commit(connection)
            current = self._lock_access_grant(connection, grant_id)
            if current.revision != expected_revision:
                raise CameraLifecycleConflict("access_grant_revision_conflict")
            if current.revoked_at is not None:
                return current
            updated = replace(
                current,
                revoked_at=revoked_at,
                revision=expected_revision + 1,
            )
            row = (
                connection.execute(
                    update(camera_access_grants)
                    .where(camera_access_grants.c.id == grant_id)
                    .values(revoked_at=revoked_at, revision=updated.revision)
                    .returning(*camera_access_grants.c)
                )
                .mappings()
                .one()
            )
            _record_normative_event(
                connection,
                aggregate_type="camera_access_grant",
                aggregate_id=grant_id,
                event_type="camera.access_grant_revoked",
                payload=_access_grant_event_payload(updated),
                aggregate_revision=updated.revision,
            )
            return _access_grant(row)

    def rotate_access_grant(
        self,
        grant_id: UUID,
        *,
        replacement: AccessGrant,
        old_expires_at: datetime,
        expected_revision: int,
    ) -> tuple[AccessGrant, AccessGrant]:
        with self._engine.begin() as connection:
            _require_synchronous_commit(connection)
            current = self._lock_access_grant(connection, grant_id)
            if current.revision != expected_revision or current.revoked_at is not None:
                raise CameraLifecycleConflict("access_grant_revision_conflict")
            if replacement.camera_id != current.camera_id or old_expires_at > current.expires_at:
                raise ValueError("access_grant_rotation_invalid")
            previous = replace(
                current,
                expires_at=old_expires_at,
                revision=expected_revision + 1,
            )
            connection.execute(
                update(camera_access_grants)
                .where(camera_access_grants.c.id == grant_id)
                .values(expires_at=old_expires_at, revision=previous.revision)
            )
            persisted = self._insert_access_grant(connection, replacement)
            _record_normative_event(
                connection,
                aggregate_type="camera_access_grant",
                aggregate_id=grant_id,
                event_type="camera.access_grant_rotation_started",
                payload=_access_grant_event_payload(previous),
                aggregate_revision=previous.revision,
            )
            _record_normative_event(
                connection,
                aggregate_type="camera_access_grant",
                aggregate_id=persisted.id,
                event_type="camera.access_grant_created",
                payload={
                    **_access_grant_event_payload(persisted),
                    "rotates_grant_id": str(grant_id),
                },
                aggregate_revision=persisted.revision,
            )
            return previous, persisted

    def _insert_access_grant(
        self,
        connection: Connection,
        grant: AccessGrant,
    ) -> AccessGrant:
        row = (
            connection.execute(
                insert(camera_access_grants)
                .values(
                    id=grant.id,
                    camera_id=grant.camera_id,
                    username=grant.username,
                    token_verifier=grant.token_verifier,
                    pepper_key_id=grant.pepper_key_id,
                    not_before=grant.not_before,
                    expires_at=grant.expires_at,
                    revoked_at=grant.revoked_at,
                    kind=grant.kind,
                    created_by=grant.created_by,
                    last_used_at=grant.last_used_at,
                    revision=grant.revision,
                    created_at=func.clock_timestamp(),
                )
                .returning(*camera_access_grants.c)
            )
            .mappings()
            .one()
        )
        return _access_grant(row)

    @staticmethod
    def _lock_access_grant(connection: Connection, grant_id: UUID) -> AccessGrant:
        row = (
            connection.execute(
                select(camera_access_grants)
                .where(camera_access_grants.c.id == grant_id)
                .with_for_update()
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise LookupError("access_grant_not_found")
        return _access_grant(row)

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
            None if row["process_start_ticks"] is None else int(row["process_start_ticks"])
        ),
        process_boot_id=(None if row["process_boot_id"] is None else _uuid(row["process_boot_id"])),
        observed_config_sha256=(
            None if row["observed_config_sha256"] is None else str(row["observed_config_sha256"])
        ),
        observed_release_id=(
            None if row["observed_release_id"] is None else str(row["observed_release_id"])
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
        placement_generation=int(row["placement_generation"]),
        state=CameraState(str(row["state"])),
        desired_revision=int(row["desired_revision"]),
        applied_revision=int(row["applied_revision"]),
    )


def _camera_catalog_item(row: RowMapping) -> CameraCatalogItem:
    return CameraCatalogItem(
        id=_uuid(row["id"]),
        name=validate_camera_name(str(row["name"])),
        public_id=PublicId.parse(str(row["public_id"])),
        node_id=_uuid(row["node_id"]),
        node_name=str(row["node_name"]),
        node_port=int(row["node_port"]),
        placement_mode=PlacementMode(str(row["placement_mode"])),
        state=CameraState(str(row["state"])),
        desired_revision=int(row["desired_revision"]),
        applied_revision=int(row["applied_revision"]),
    )


def _access_policy(row: RowMapping) -> AccessPolicy:
    return AccessPolicy(
        camera_id=_uuid(row["camera_id"]),
        revision=int(row["revision"]),
        internet_cidrs=tuple(str(value) for value in row["internet_cidrs"]),
        local_cidrs=tuple(str(value) for value in row["local_cidrs"]),
    )


def _access_grant(row: RowMapping) -> AccessGrant:
    return AccessGrant(
        id=_uuid(row["id"]),
        camera_id=_uuid(row["camera_id"]),
        username=str(row["username"]),
        token_verifier=str(row["token_verifier"]),
        pepper_key_id=str(row["pepper_key_id"]),
        not_before=row["not_before"],
        expires_at=row["expires_at"],
        revoked_at=row["revoked_at"],
        revision=int(row["revision"]),
        kind=str(row["kind"]),
        created_by=str(row["created_by"]),
        last_used_at=row["last_used_at"],
    )


def _access_grant_event_payload(grant: AccessGrant) -> dict[str, object]:
    return {
        "camera_id": str(grant.camera_id),
        "username": grant.username,
        "pepper_key_id": grant.pepper_key_id,
        "not_before": grant.not_before.isoformat(),
        "expires_at": grant.expires_at.isoformat(),
        "revoked_at": None if grant.revoked_at is None else grant.revoked_at.isoformat(),
        "revision": grant.revision,
        "kind": grant.kind,
        "created_by": grant.created_by,
        "last_used_at": (
            None if grant.last_used_at is None else grant.last_used_at.isoformat()
        ),
    }


def _camera_move(row: RowMapping) -> CameraMove:
    return CameraMove(
        id=_uuid(row["id"]),
        camera_id=_uuid(row["camera_id"]),
        public_id=PublicId.parse(str(row["public_id"])),
        source_url=str(row["source_url"]),
        source_node_id=_uuid(row["source_node_id"]),
        target_node_id=_uuid(row["target_node_id"]),
        source_generation=int(row["source_generation"]),
        target_generation=int(row["target_generation"]),
        desired_revision=int(row["desired_revision"]),
        force=bool(row["force"]),
        confirmed_disconnect_readers=int(row["confirmed_disconnect_readers"]),
        source_port=(None if row["source_port"] is None else int(row["source_port"])),
        target_port=(None if row["target_port"] is None else int(row["target_port"])),
        source_endpoint=(
            None if row["source_endpoint"] is None else str(row["source_endpoint"])
        ),
        target_endpoint=(
            None if row["target_endpoint"] is None else str(row["target_endpoint"])
        ),
        expires_at=row["expires_at"],
        abort_reason=(None if row["abort_reason"] is None else str(row["abort_reason"])),
        state=CameraMoveState(str(row["state"])),
    )


def _camera_move_with_camera(row: RowMapping, camera: CameraPlacement) -> CameraMove:
    return CameraMove(
        id=_uuid(row["id"]),
        camera_id=_uuid(row["camera_id"]),
        public_id=camera.public_id,
        source_url=camera.source_url,
        source_node_id=_uuid(row["source_node_id"]),
        target_node_id=_uuid(row["target_node_id"]),
        source_generation=int(row["source_generation"]),
        target_generation=int(row["target_generation"]),
        desired_revision=int(row["desired_revision"]),
        force=bool(row["force"]),
        confirmed_disconnect_readers=int(row["confirmed_disconnect_readers"]),
        source_port=(None if row["source_port"] is None else int(row["source_port"])),
        target_port=(None if row["target_port"] is None else int(row["target_port"])),
        source_endpoint=(
            None if row["source_endpoint"] is None else str(row["source_endpoint"])
        ),
        target_endpoint=(
            None if row["target_endpoint"] is None else str(row["target_endpoint"])
        ),
        expires_at=row["expires_at"],
        abort_reason=(None if row["abort_reason"] is None else str(row["abort_reason"])),
        state=CameraMoveState(str(row["state"])),
    )


def _node_port_change(row: RowMapping) -> NodePortChange:
    return NodePortChange(
        id=_uuid(row["id"]),
        node_id=_uuid(row["node_id"]),
        old_port=int(row["old_port"]),
        new_port=int(row["new_port"]),
        source_revision=int(row["source_revision"]),
        target_revision=int(row["target_revision"]),
        registered_cameras=int(row["registered_cameras"]),
        blast_radius_sha256=str(row["blast_radius_sha256"]),
        state=NodePortChangeState(str(row["state"])),
    )


def _record_normative_event(
    connection: Connection,
    *,
    aggregate_type: str,
    aggregate_id: UUID,
    event_type: str,
    payload: dict[str, object],
    aggregate_revision: int,
    mutation_context: NodeMutationContext | None = None,
) -> None:
    event_payload = dict(payload)
    if mutation_context is not None:
        if "operator" in event_payload:
            raise ValueError("node_event_operator_payload_reserved")
        event_payload["operator"] = mutation_context.event_payload()
    event_id = uuid4()
    values = {
        "id": event_id,
        "aggregate_type": aggregate_type,
        "aggregate_id": aggregate_id,
        "event_type": event_type,
        "aggregate_revision": aggregate_revision,
        "payload": event_payload,
    }
    connection.execute(insert(audit_events).values(**values))
    connection.execute(insert(outbox_messages).values(**values))


def _require_node_command_fence(
    node: MediaNode,
    fence: NodeCommandFence | None,
) -> None:
    if fence is None:
        return
    if (
        node.desired_revision != fence.expected_revision
        or node.state is not fence.expected_state
    ):
        raise NodeLifecycleConflict("node_command_fence_conflict")


def _registration_advisory_key(
    idempotency: NodeRegistrationIdempotency,
) -> int:
    digest = hashlib.sha256(
        idempotency.actor_session_id.bytes + idempotency.key.bytes
    ).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


def _require_synchronous_commit(connection: Connection) -> None:
    connection.execute(text("SET LOCAL synchronous_commit = on"))


def _is_external_port_conflict(error: IntegrityError) -> bool:
    diagnostic = getattr(error.orig, "diag", None)
    return getattr(diagnostic, "constraint_name", None) == "media_nodes_external_port_key"
