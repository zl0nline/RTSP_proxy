"""Bounded active-camera monitoring behind one fail-closed worker interface."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import Lock
from typing import Protocol
from uuid import UUID

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection, Engine, RowMapping
from sqlalchemy.exc import SQLAlchemyError

from rtsp_proxy.media import MediaNodeError
from rtsp_proxy.nodes import CameraNotFound, CameraPlacement, CameraState, MediaNode, NodeState
from rtsp_proxy.probe_routine import (
    CameraProbeProfile,
    RoutineProbeCandidate,
    RoutineProbeProducer,
)
from rtsp_proxy.probe_security import AdmittedProbeEndpoint, ProbeEndpointAdmission
from rtsp_proxy.probes import (
    BoundedProbeScheduler,
    ProbeExecutionResult,
    ProbeFailureClass,
    ProbeHealthRecord,
    ProbeLease,
    ProbeMethod,
    ProbeObservation,
    ProbeOutcome,
    ProbeTarget,
)
from rtsp_proxy.reconcile import CameraRuntimeObservation, ReconcileRetry

_LOCK_NAMESPACE = 1_384_126_418
_LOCK_KEY = 1


class ProbeWorkerUnavailable(RuntimeError):
    """The worker cannot prove singleton ownership or authoritative state."""


@dataclass(frozen=True, slots=True)
class ProbeWorkerCycle:
    candidates: int
    submitted: int
    executed: int
    persisted: int


@dataclass(frozen=True, slots=True)
class _ProfileRow:
    camera_id: UUID
    revision: int
    profile: CameraProbeProfile
    updated_at: datetime
    last_attempt_at: datetime | None


class ProbeWorkSource(Protocol):
    def acquire(self) -> None: ...
    def assert_owned(self) -> None: ...
    def active_profiles(self, *, limit: int) -> tuple[_ProfileRow, ...]: ...
    def execution_permit(
        self, target: ProbeTarget, *, profile_revision: int,
    ) -> AbstractContextManager[bool]: ...
    def mark_attempt(self, camera_id: UUID, *, revision: int) -> None: ...
    def close(self) -> None: ...


class ProbeCameraSource(Protocol):
    def get_cameras(self, camera_ids: tuple[UUID, ...]) -> tuple[CameraPlacement, ...]: ...
    def get_node(self, node_id: UUID) -> MediaNode | None: ...


class ProbeObservationProjection(Protocol):
    def assert_ready(self) -> None: ...
    def assert_health_ready(self) -> None: ...
    def health_for(self, target: ProbeTarget, *, method: ProbeMethod) -> ProbeHealthRecord: ...
    def record_if_current(
        self,
        observation: ProbeObservation,
        *,
        confirmation_spacing: timedelta | None = None,
    ) -> bool: ...


class ProbeRuntimeSource(Protocol):
    def observe(self, camera_id: UUID) -> CameraRuntimeObservation: ...


class ProbeExecutionClient(Protocol):
    def execute(
        self,
        *,
        request_id: UUID,
        endpoint: AdmittedProbeEndpoint,
        deadline_at: datetime,
        cancelled: Callable[[], bool] | None = None,
    ) -> ProbeExecutionResult: ...


@dataclass(frozen=True, slots=True)
class _ExecutableCandidate:
    routine: RoutineProbeCandidate
    profile_revision: int
    endpoint: AdmittedProbeEndpoint


class PostgresProbeWorkStore:
    """Hold singleton ownership and page explicit active profiles from PostgreSQL."""

    def __init__(
        self,
        database_url: str,
        *,
        statement_timeout_ms: int = 1000,
        execution_slots: int = 4,
    ) -> None:
        if (
            not database_url
            or not 100 <= statement_timeout_ms <= 5000
            or not 1 <= execution_slots <= 16
        ):
            raise ValueError("probe_worker_store_policy_invalid")
        self._engine: Engine = create_engine(
            database_url,
            pool_pre_ping=True,
            hide_parameters=True,
            pool_size=execution_slots + 2,
            max_overflow=0, pool_timeout=statement_timeout_ms / 1000,
            connect_args={
                "connect_timeout": max(1, statement_timeout_ms // 1000),
                "options": f"-c statement_timeout={statement_timeout_ms}",
            },
        )
        self._owner: Connection | None = None
        self._lock = Lock()
        self._cursor: tuple[datetime, UUID] | None = None

    def acquire(self) -> None:
        with self._lock:
            if self._owner is not None:
                self._assert_owned_locked()
                return
            owner = self._engine.connect()
            try:
                acquired = owner.scalar(
                    text("SELECT pg_try_advisory_lock(:namespace, :key)"),
                    {"namespace": _LOCK_NAMESPACE, "key": _LOCK_KEY},
                )
            except SQLAlchemyError:
                owner.close()
                raise ProbeWorkerUnavailable("probe_worker_store_unavailable") from None
            if acquired is not True:
                owner.close()
                raise ProbeWorkerUnavailable("probe_worker_already_running")
            try:
                columns = _schema_rows(owner, _PROFILE_COLUMNS)
                constraints = _schema_rows(owner, _PROFILE_CONSTRAINTS)
                privileges = owner.scalar(text(
                    "SELECT has_table_privilege(current_user, "
                    "'public.camera_probe_profiles', 'SELECT') "
                    "AND has_table_privilege(current_user, "
                    "'public.camera_probe_profiles', 'UPDATE')"
                ))
                if (
                    columns != _EXPECTED_PROFILE_COLUMNS
                    or constraints != _EXPECTED_PROFILE_CONSTRAINTS
                    or privileges is not True
                ):
                    raise ProbeWorkerUnavailable("probe_worker_schema_incompatible")
                owner.commit()
                self._owner = owner
            except SQLAlchemyError:
                owner.close()
                raise ProbeWorkerUnavailable("probe_worker_store_unavailable") from None
            except BaseException:
                owner.close()
                raise

    def assert_owned(self) -> None:
        with self._lock:
            self._assert_owned_locked()

    def _assert_owned_locked(self) -> None:
        owner = self._owner
        if owner is None:
            raise ProbeWorkerUnavailable("probe_worker_not_started")
        try:
            owned = owner.scalar(text(
                "SELECT EXISTS (SELECT 1 FROM pg_locks "
                "WHERE locktype='advisory' AND pid=pg_backend_pid() AND granted "
                "AND classid=:namespace AND objid=:key)"
            ), {"namespace": _LOCK_NAMESPACE, "key": _LOCK_KEY})
        except SQLAlchemyError:
            raise ProbeWorkerUnavailable("probe_worker_ownership_lost") from None
        finally:
            if not owner.closed:
                owner.rollback()
        if owned is not True:
            raise ProbeWorkerUnavailable("probe_worker_ownership_lost")

    def active_profiles(self, *, limit: int) -> tuple[_ProfileRow, ...]:
        if not 1 <= limit <= 256:
            raise ValueError("probe_worker_batch_invalid")
        self.assert_owned()
        try:
            with self._engine.connect() as connection:
                rows = self._profile_page(connection, limit=limit, cursor=self._cursor)
                if not rows and self._cursor is not None:
                    self._cursor = None
                    rows = self._profile_page(connection, limit=limit, cursor=None)
                if rows:
                    last = rows[-1]
                    scan_time = last["scan_time"]
                    camera_id = last["camera_id"]
                    if not isinstance(scan_time, datetime) or not isinstance(camera_id, UUID):
                        raise ProbeWorkerUnavailable("probe_worker_profile_invalid")
                    self._cursor = (scan_time, camera_id)
                return tuple(_profile_row(row) for row in rows)
        except SQLAlchemyError:
            raise ProbeWorkerUnavailable("probe_worker_store_unavailable") from None

    @staticmethod
    def _profile_page(
        connection: Connection,
        *,
        limit: int,
        cursor: tuple[datetime, UUID] | None,
    ) -> list[RowMapping]:
        cursor_time, cursor_id = (None, None) if cursor is None else cursor
        return list(connection.execute(text(
            "SELECT profile.*, "
            "COALESCE(profile.last_attempt_at, profile.updated_at) AS scan_time "
            "FROM camera_probe_profiles AS profile "
            "JOIN cameras AS camera ON camera.id=profile.camera_id "
            "JOIN camera_placements AS placement ON placement.camera_id=camera.id "
            "JOIN media_nodes AS node ON node.id=placement.node_id "
            "WHERE profile.enabled=true AND profile.max_source_sessions > 1 "
            "AND camera.state='enabled' AND node.state='running' "
            "AND node.maintenance=false AND (CAST(:cursor_time AS timestamptz) IS NULL "
            "OR COALESCE(profile.last_attempt_at, profile.updated_at) > :cursor_time "
            "OR (COALESCE(profile.last_attempt_at, profile.updated_at) = :cursor_time "
            "AND profile.camera_id > CAST(:cursor_id AS uuid))) "
            "ORDER BY scan_time, profile.camera_id LIMIT :limit"
        ), {
            "cursor_time": cursor_time,
            "cursor_id": cursor_id,
            "limit": limit,
        }).mappings())

    def mark_attempt(self, camera_id: UUID, *, revision: int) -> None:
        self.assert_owned()
        try:
            with self._engine.begin() as connection:
                connection.execute(text("SET LOCAL synchronous_commit = on"))
                connection.execute(text(
                    "UPDATE camera_probe_profiles SET last_attempt_at=clock_timestamp() "
                    "WHERE camera_id=:camera_id AND revision=:revision"
                ), {"camera_id": camera_id, "revision": revision})
        except SQLAlchemyError:
            raise ProbeWorkerUnavailable("probe_worker_store_unavailable") from None

    @contextmanager
    def execution_permit(
        self,
        target: ProbeTarget,
        *,
        profile_revision: int,
    ) -> Iterator[bool]:
        """Lock camera/profile admission through one broker execution.

        Profile and camera mutations take the camera row first too, so a
        capacity downgrade cannot commit while the corresponding source probe
        is alive. A shared node-row lock lets probes for the same node coexist
        while preventing a maintenance/state transition during execution.
        """
        if (
            not isinstance(target, ProbeTarget)
            or type(profile_revision) is not int
            or profile_revision < 1
            or target.source_endpoint_generation is None
        ):
            raise ValueError("probe_worker_execution_identity_invalid")
        self.assert_owned()
        try:
            with self._engine.connect() as connection, connection.begin():
                row = connection.execute(text(
                    "SELECT profile.revision, profile.enabled, camera.public_id, "
                    "profile.max_source_sessions, camera.state AS camera_state, "
                    "camera.desired_revision, placement.node_id, "
                    "placement.generation AS placement_generation, "
                    "node.state AS node_state, node.maintenance, "
                    "endpoint.site_key, endpoint.endpoint_generation "
                    "FROM cameras AS camera "
                    "JOIN camera_probe_profiles AS profile "
                    "ON profile.camera_id=camera.id "
                    "JOIN camera_placements AS placement "
                    "ON placement.camera_id=camera.id "
                    "JOIN media_nodes AS node ON node.id=placement.node_id "
                    "JOIN camera_probe_endpoints AS endpoint "
                    "ON endpoint.camera_id=camera.id "
                    "WHERE camera.id=:camera_id "
                    "FOR UPDATE OF camera, profile, placement, endpoint SKIP LOCKED "
                    "FOR SHARE OF node SKIP LOCKED"
                ), {"camera_id": target.camera_id}).mappings().one_or_none()
                permitted = bool(
                    row is not None
                    and row["revision"] == profile_revision
                    and row["enabled"] is True
                    and type(row["max_source_sessions"]) is int
                    and row["max_source_sessions"] > 1
                    and row["camera_state"] == CameraState.ENABLED.value
                    and row["public_id"] == str(target.public_id)
                    and row["desired_revision"] == target.desired_revision
                    and row["node_id"] == target.node_id
                    and row["placement_generation"] == target.placement_generation
                    and row["node_state"] == NodeState.RUNNING.value
                    and row["maintenance"] is False
                    and row["site_key"] == target.site_key
                    and row["endpoint_generation"] == target.source_endpoint_generation
                )
                yield permitted
        except SQLAlchemyError:
            raise ProbeWorkerUnavailable("probe_worker_store_unavailable") from None

    def close(self) -> None:
        with self._lock:
            owner, self._owner = self._owner, None
            try:
                if owner is not None:
                    owner.close()
            finally:
                self._engine.dispose()


class ProbeMonitoringWorker:
    """Load, schedule, execute and durably project one bounded monitoring cycle."""

    def __init__(
        self, *, work: ProbeWorkSource, cameras: ProbeCameraSource,
        observations: ProbeObservationProjection, runtime: ProbeRuntimeSource,
        admission: ProbeEndpointAdmission, client: ProbeExecutionClient,
        scheduler: BoundedProbeScheduler, batch_limit: int = 256,
        execution_workers: int = 4,
    ) -> None:
        if not 1 <= batch_limit <= 256 or not 1 <= execution_workers <= 16:
            raise ValueError("probe_worker_policy_invalid")
        self._work = work
        self._cameras = cameras
        self._observations = observations
        self._runtime = runtime
        self._admission = admission
        self._client = client
        self._scheduler = scheduler
        self._producer = RoutineProbeProducer(scheduler, batch_limit=batch_limit)
        self._batch_limit = batch_limit
        self._execution_workers = execution_workers

    def start(self) -> None:
        self._work.acquire()
        try:
            self._observations.assert_ready()
            self._observations.assert_health_ready()
        except BaseException:
            self._work.close()
            raise

    def run_once(
        self, *, now: datetime | None = None, cancelled: Callable[[], bool] = lambda: False,
    ) -> ProbeWorkerCycle:
        self._work.assert_owned()
        cycle_time = datetime.now(UTC) if now is None else now
        if cycle_time.tzinfo is None:
            raise ValueError("probe_worker_time_invalid")
        executable = self._load_candidates(cycle_time, cancelled)
        mapping = {item.routine.target.camera_id: item.routine for item in executable}
        submitted = self._producer.enqueue(mapping, now=cycle_time)
        by_camera = {item.routine.target.camera_id: item for item in executable}
        targets = {camera_id: item.routine.target for camera_id, item in by_camera.items()}
        leases = self._scheduler.claim_available(cycle_time, targets)
        persisted = 0
        executed = 0
        with ThreadPoolExecutor(
            max_workers=self._execution_workers, thread_name_prefix="rtsp-probe-worker",
        ) as pool:
            futures = {
                pool.submit(
                    self._execute_lease,
                    lease,
                    by_camera[lease.target.camera_id],
                    cancelled,
                ): lease
                for lease in leases
            }
            for future in as_completed(futures):
                lease = futures[future]
                item = by_camera[lease.target.camera_id]
                try:
                    result = future.result()
                except ProbeWorkerUnavailable:
                    self._scheduler.cancel(lease)
                    raise
                except Exception:
                    result = ProbeExecutionResult(
                        outcome=ProbeOutcome.INCONCLUSIVE,
                        completed_at=max(
                            lease.started_at,
                            min(datetime.now(UTC), lease.lease_expires_at),
                        ),
                        failure_class=ProbeFailureClass.EXECUTOR,
                    )
                if result is None:
                    self._scheduler.cancel(lease)
                    continue
                executed += 1
                result = item.routine.profile.classify(result)
                try:
                    observation = self._scheduler.complete(lease, result)
                except ValueError:
                    self._work.mark_attempt(
                        lease.target.camera_id, revision=item.profile_revision,
                    )
                    continue
                if self._observations.record_if_current(
                    observation,
                    confirmation_spacing=item.routine.profile.confirmation_interval,
                ):
                    persisted += 1
                self._work.mark_attempt(lease.target.camera_id, revision=item.profile_revision)
        return ProbeWorkerCycle(len(executable), len(submitted), executed, persisted)

    def close(self) -> None:
        self._work.close()

    def _execute_lease(
        self,
        lease: ProbeLease,
        item: _ExecutableCandidate,
        cancelled: Callable[[], bool],
    ) -> ProbeExecutionResult | None:
        if item.routine.target.source_endpoint_generation is None:
            return None
        with self._work.execution_permit(
            lease.target, profile_revision=item.profile_revision,
        ) as permitted:
            if not permitted:
                return None
            return self._client.execute(
                request_id=lease.request_id,
                endpoint=item.endpoint,
                deadline_at=lease.lease_expires_at,
                cancelled=cancelled,
            )

    def _load_candidates(
        self, now: datetime, cancelled: Callable[[], bool],
    ) -> tuple[_ExecutableCandidate, ...]:
        rows = self._work.active_profiles(limit=self._batch_limit)
        cameras = {
            camera.id: camera
            for camera in self._cameras.get_cameras(tuple(row.camera_id for row in rows))
        }
        candidates: list[_ExecutableCandidate] = []
        for row in rows:
            if cancelled():
                break
            camera = cameras.get(row.camera_id)
            if camera is None or camera.state is not CameraState.ENABLED:
                continue
            node = self._cameras.get_node(camera.node_id)
            if node is None or camera.probe_endpoint is None:
                continue
            try:
                observed = self._runtime.observe(camera.id)
                endpoint = self._admission.restore(camera.source_url, camera.probe_endpoint)
                target = ProbeTarget(
                    camera_id=camera.id, public_id=camera.public_id, node_id=camera.node_id,
                    site_key=camera.probe_endpoint.site_key,
                    desired_revision=camera.desired_revision,
                    placement_generation=camera.placement_generation, node_state=node.state,
                    enabled=True, maintenance=node.maintenance, occupied=observed.occupied,
                    source_pull_active=observed.ready,
                    max_source_sessions=row.profile.max_source_sessions,
                    source_endpoint_generation=camera.probe_endpoint.generation,
                )
                health = self._observations.health_for(target, method=ProbeMethod.SOURCE)
            except (CameraNotFound, MediaNodeError, ReconcileRetry, ValueError):
                continue
            candidates.append(_ExecutableCandidate(
                routine=RoutineProbeCandidate(
                    target=target, profile=row.profile, health=health,
                    last_attempt_at=row.last_attempt_at, registered_at=row.updated_at,
                ),
                profile_revision=row.revision, endpoint=endpoint,
            ))
        return tuple(candidates)


def _profile_row(row: RowMapping) -> _ProfileRow:
    return _ProfileRow(
        camera_id=row["camera_id"], revision=row["revision"],
        profile=CameraProbeProfile(
            enabled=row["enabled"], max_source_sessions=row["max_source_sessions"],
            require_video=row["require_video"], require_audio=row["require_audio"],
            routine_interval=_seconds(row["routine_seconds"]),
            confirmation_interval=_seconds(row["confirmation_seconds"]),
            execution_timeout=_seconds(row["timeout_seconds"]),
        ),
        updated_at=row["updated_at"], last_attempt_at=row["last_attempt_at"],
    )


def _seconds(value: object) -> timedelta:
    if type(value) is not int:
        raise ProbeWorkerUnavailable("probe_worker_profile_invalid")
    return timedelta(seconds=value)


def _schema_rows(connection: Connection, query: str) -> dict[str, tuple[object, ...]]:
    return {
        str(row[0]): tuple(row[1:])
        for row in connection.execute(text(query)).tuples()
    }


_EXPECTED_PROFILE_COLUMNS = {
    "camera_id": ("uuid", True, ""),
    "revision": ("bigint", True, ""),
    "enabled": ("boolean", True, ""),
    "max_source_sessions": ("integer", True, ""),
    "require_video": ("boolean", True, ""),
    "require_audio": ("boolean", True, ""),
    "routine_seconds": ("integer", True, ""),
    "confirmation_seconds": ("integer", True, ""),
    "timeout_seconds": ("integer", True, ""),
    "updated_at": ("timestamp with time zone", True, "clock_timestamp()"),
    "last_attempt_at": ("timestamp with time zone", False, ""),
}
_EXPECTED_PROFILE_CONSTRAINTS = {
    "camera_probe_profiles_pkey": ("p", True, "PRIMARY KEY (camera_id)"),
    "camera_probe_profiles_camera_id_fkey": (
        "f", True, "FOREIGN KEY (camera_id) REFERENCES cameras(id) ON DELETE CASCADE",
    ),
    "ck_camera_probe_profile_revision": ("c", True, "CHECK (revision >= 1)"),
    "ck_camera_probe_profile_capacity": (
        "c", True, "CHECK (max_source_sessions >= 1 AND max_source_sessions <= 16)",
    ),
    "ck_camera_probe_profile_media": ("c", True, "CHECK (require_video OR require_audio)"),
    "ck_camera_probe_profile_intervals": (
        "c", True,
        "CHECK (routine_seconds >= 30 AND routine_seconds <= 86400 "
        "AND confirmation_seconds >= 1 AND confirmation_seconds <= 3600 "
        "AND confirmation_seconds <= routine_seconds "
        "AND timeout_seconds >= 1 AND timeout_seconds <= 30)",
    ),
    "ck_camera_probe_profile_attempt_time": (
        "c", True, "CHECK (last_attempt_at IS NULL OR last_attempt_at >= updated_at)",
    ),
}
_PROFILE_COLUMNS = """
SELECT attribute.attname, format_type(attribute.atttypid, attribute.atttypmod),
       attribute.attnotnull, COALESCE(pg_get_expr(default_entry.adbin, default_entry.adrelid), '')
FROM pg_attribute AS attribute
JOIN pg_class AS table_entry ON table_entry.oid = attribute.attrelid
JOIN pg_namespace AS namespace_entry ON namespace_entry.oid = table_entry.relnamespace
LEFT JOIN pg_attrdef AS default_entry
  ON default_entry.adrelid = attribute.attrelid
 AND default_entry.adnum = attribute.attnum
WHERE namespace_entry.nspname = 'public'
  AND table_entry.relname = 'camera_probe_profiles'
  AND attribute.attnum > 0
  AND NOT attribute.attisdropped
"""
_PROFILE_CONSTRAINTS = """
SELECT constraint_entry.conname, constraint_entry.contype,
       constraint_entry.convalidated,
       pg_get_constraintdef(constraint_entry.oid, true)
FROM pg_constraint AS constraint_entry
JOIN pg_class AS table_entry ON table_entry.oid = constraint_entry.conrelid
JOIN pg_namespace AS namespace_entry ON namespace_entry.oid = table_entry.relnamespace
WHERE namespace_entry.nspname = 'public'
  AND table_entry.relname = 'camera_probe_profiles'
  AND constraint_entry.contype <> 'n'
"""
