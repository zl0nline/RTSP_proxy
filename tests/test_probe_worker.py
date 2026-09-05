from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from ipaddress import ip_network
from typing import cast
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

from rtsp_proxy.identifiers import PublicId, generate_public_id
from rtsp_proxy.media import MediaNodeUnavailable
from rtsp_proxy.nodes import (
    CameraPlacement,
    CameraState,
    MediaNode,
    NodeHealth,
    NodeState,
    PlacementMode,
)
from rtsp_proxy.probe_routine import CameraProbeProfile
from rtsp_proxy.probe_security import AdmittedProbeEndpoint, ProbeEndpointAdmission
from rtsp_proxy.probe_worker import (
    PostgresProbeWorkStore,
    ProbeMonitoringWorker,
    ProbeWorkerUnavailable,
    _ProfileRow,
)
from rtsp_proxy.probes import (
    BoundedProbeScheduler,
    ProbeExecutionResult,
    ProbeFailureClass,
    ProbeHealthRecord,
    ProbeMethod,
    ProbeObservation,
    ProbeOutcome,
    ProbeTarget,
)
from rtsp_proxy.reconcile import CameraRuntimeObservation

NOW = datetime(2026, 9, 6, 12, tzinfo=UTC)


def test_postgres_probe_worker_rejects_invalid_policy_and_unowned_access(
    postgres_database_url: str,
) -> None:
    from rtsp_proxy.migrate import upgrade_database

    with pytest.raises(ValueError, match="store_policy_invalid"):
        PostgresProbeWorkStore("")

    upgrade_database(postgres_database_url)
    store = PostgresProbeWorkStore(postgres_database_url)
    try:
        with pytest.raises(ProbeWorkerUnavailable, match="not_started"):
            store.assert_owned()
        store.acquire()
        with pytest.raises(ValueError, match="batch_invalid"):
            store.active_profiles(limit=0)
        with pytest.raises(
            ValueError, match="execution_identity_invalid",
        ), store.execution_permit(
            cast(ProbeTarget, object()),
            profile_revision=1,
        ):
            pass
    finally:
        store.close()


def test_postgres_probe_worker_lock_is_singleton_and_recoverable(
    postgres_database_url: str,
) -> None:
    from rtsp_proxy.migrate import upgrade_database

    upgrade_database(postgres_database_url)
    first = PostgresProbeWorkStore(postgres_database_url)
    second = PostgresProbeWorkStore(postgres_database_url)
    try:
        first.acquire()
        first.assert_owned()
        with pytest.raises(ProbeWorkerUnavailable, match="already_running"):
            second.acquire()
        first.close()
        second.acquire()
        second.assert_owned()
    finally:
        first.close()
        second.close()


def test_postgres_probe_worker_rejects_a_weakened_profile_schema(
    postgres_database_url: str,
) -> None:
    from rtsp_proxy.migrate import upgrade_database

    upgrade_database(postgres_database_url)
    engine = create_engine(postgres_database_url)
    with engine.begin() as connection:
        connection.execute(text(
            "ALTER TABLE camera_probe_profiles "
            "DROP CONSTRAINT ck_camera_probe_profile_capacity"
        ))
    engine.dispose()

    store = PostgresProbeWorkStore(postgres_database_url)
    try:
        with pytest.raises(ProbeWorkerUnavailable, match="schema_incompatible"):
            store.acquire()
    finally:
        store.close()


def test_postgres_probe_worker_pages_past_the_first_bounded_batch(
    postgres_database_url: str,
) -> None:
    from rtsp_proxy.migrate import upgrade_database

    upgrade_database(postgres_database_url)
    camera_ids = _seed_profile_rows(postgres_database_url, count=3)
    store = PostgresProbeWorkStore(postgres_database_url)
    try:
        store.acquire()
        first = store.active_profiles(limit=2)
        second = store.active_profiles(limit=2)
        wrapped = store.active_profiles(limit=2)
        target = _stored_probe_target(postgres_database_url, first[0].camera_id)
        with store.execution_permit(
            target,
            profile_revision=first[0].revision,
        ) as permitted:
            assert permitted is True
            competing = create_engine(postgres_database_url)
            try:
                with pytest.raises(SQLAlchemyError), competing.begin() as connection:
                    connection.execute(text("SET LOCAL lock_timeout = '100ms'"))
                    connection.execute(text(
                        "UPDATE camera_probe_profiles SET max_source_sessions=1 "
                        "WHERE camera_id=:camera_id"
                    ), {"camera_id": first[0].camera_id})
            finally:
                competing.dispose()
            competing = create_engine(postgres_database_url)
            try:
                with pytest.raises(SQLAlchemyError), competing.begin() as connection:
                    connection.execute(text("SET LOCAL lock_timeout = '100ms'"))
                    connection.execute(text(
                        "UPDATE camera_placements SET generation=generation + 1 "
                        "WHERE camera_id=:camera_id"
                    ), {"camera_id": first[0].camera_id})
            finally:
                competing.dispose()

        # A move can preserve the admitted endpoint generation. The final
        # permit must still reject the target claimed before that move.
        engine = create_engine(postgres_database_url)
        with engine.begin() as connection:
            connection.execute(text(
                "UPDATE camera_placements SET generation=generation + 1 "
                "WHERE camera_id=:camera_id"
            ), {"camera_id": first[0].camera_id})
        engine.dispose()
        with store.execution_permit(
            target,
            profile_revision=first[0].revision,
        ) as permitted:
            assert permitted is False
        store.mark_attempt(first[0].camera_id, revision=first[0].revision)
        engine = create_engine(postgres_database_url)
        with engine.connect() as connection:
            attempted_at = connection.scalar(text(
                "SELECT last_attempt_at FROM camera_probe_profiles "
                "WHERE camera_id=:camera_id"
            ), {"camera_id": first[0].camera_id})
        engine.dispose()
        assert isinstance(attempted_at, datetime)
    finally:
        store.close()

    assert len(first) == 2
    assert len(second) == 1
    assert {row.camera_id for row in first}.isdisjoint(
        {row.camera_id for row in second}
    )
    assert {row.camera_id for row in (*first, *second)} == set(camera_ids)
    assert tuple(row.camera_id for row in wrapped) == tuple(row.camera_id for row in first)


def test_monitoring_worker_runs_one_authoritative_bounded_cycle() -> None:
    source_url = "rtsp://camera.example.invalid/live"
    # Admission resolves only while the operator creates/updates the camera.
    admission = ProbeEndpointAdmission(
        site_key="local", allowed_networks=(ip_network("192.0.2.0/24"),),
        resolve=lambda _host: ("192.0.2.10",),
    )
    endpoint = admission.admit(source_url)
    camera_id = uuid4()
    node_id = uuid4()
    camera = CameraPlacement(
        id=camera_id, name="Camera", source_url=source_url,
        public_id=PublicId("a" * 26), node_id=node_id, node_port=10554,
        placement_mode=PlacementMode.AUTOMATIC, state=CameraState.ENABLED,
        desired_revision=1, applied_revision=1, probe_endpoint=endpoint.identity,
    )
    node = MediaNode(
        id=node_id, name="node", external_port=10554, state=NodeState.RUNNING,
        runtime_state=NodeState.RUNNING, health=NodeHealth.HEALTHY,
        maintenance=False, management_fresh=True, config_compatible=True,
        desired_revision=1, applied_revision=1,
    )
    profile = CameraProbeProfile(enabled=True, max_source_sessions=2)

    class Work:
        def __init__(self) -> None:
            self.marked: list[tuple[UUID, int]] = []
            self.permitted = True

        def acquire(self) -> None: pass
        def assert_owned(self) -> None: pass
        def active_profiles(self, *, limit: int) -> tuple[_ProfileRow, ...]:
            assert limit == 8
            return (_ProfileRow(camera_id, 3, profile, NOW - timedelta(hours=1), None),)
        @contextmanager
        def execution_permit(
            self, target: ProbeTarget, *, profile_revision: int,
        ) -> Iterator[bool]:
            assert target.camera_id == camera_id
            assert target.node_id == node_id
            assert target.desired_revision == camera.desired_revision
            assert target.placement_generation == camera.placement_generation
            assert profile_revision == 3
            assert target.source_endpoint_generation == endpoint.identity.generation
            yield self.permitted
        def mark_attempt(self, camera_id: UUID, *, revision: int) -> None:
            self.marked.append((camera_id, revision))
        def close(self) -> None: pass

    class Cameras:
        def get_cameras(self, camera_ids: tuple[UUID, ...]) -> tuple[CameraPlacement, ...]:
            assert camera_ids == (camera_id,)
            return (camera,)
        def get_node(self, requested: UUID) -> MediaNode | None:
            assert requested == node_id
            return node

    class Runtime:
        def observe(self, requested: UUID) -> CameraRuntimeObservation:
            return CameraRuntimeObservation(requested, node_id, False, 0, False, False)

    class Observations:
        def __init__(self) -> None:
            self.saved: list[tuple[ProbeObservation, timedelta | None]] = []
        def assert_ready(self) -> None: pass
        def assert_health_ready(self) -> None: pass
        def health_for(self, target: ProbeTarget, *, method: ProbeMethod) -> ProbeHealthRecord:
            return ProbeHealthRecord.for_target(target, method=method)
        def record_if_current(
            self,
            observation: ProbeObservation,
            *,
            confirmation_spacing: timedelta | None = None,
        ) -> bool:
            self.saved.append((observation, confirmation_spacing))
            return True

    class Client:
        def __init__(self) -> None:
            self.calls = 0
            self.fail = False

        def execute(
            self,
            *,
            request_id: UUID,
            endpoint: AdmittedProbeEndpoint,
            deadline_at: datetime,
            cancelled: Callable[[], bool] | None = None,
        ) -> ProbeExecutionResult:
            self.calls += 1
            if self.fail:
                raise RuntimeError("broker execution failed")
            assert endpoint.identity == camera.probe_endpoint
            return ProbeExecutionResult(
                outcome=ProbeOutcome.HEALTHY,
                completed_at=NOW + timedelta(seconds=1), video_codec="h264",
            )

    work = Work()
    observations = Observations()
    client = Client()
    scheduler = BoundedProbeScheduler(
        global_limit=2, per_node_limit=1, per_site_limit=2, source_limit=2,
        path_limit=1, queue_limit=8, lease_seconds=15, retry_delay_seconds=1,
        max_attempts=1,
    )
    worker = ProbeMonitoringWorker(
        work=work, cameras=Cameras(), observations=observations,
        runtime=Runtime(), admission=admission, client=client, scheduler=scheduler,
        batch_limit=8, execution_workers=2,
    )

    worker.start()
    with pytest.raises(ValueError, match="time_invalid"):
        worker.run_once(now=NOW.replace(tzinfo=None))
    cycle = worker.run_once(now=NOW)

    assert cycle.candidates == cycle.submitted == cycle.executed == cycle.persisted == 1
    assert work.marked == [(camera_id, 3)]
    assert len(observations.saved) == 1
    assert observations.saved[0][0].video_codec == "h264"
    assert client.calls == 1

    # Simulate an authoritative capacity downgrade after batch loading/claim
    # but immediately before the broker launch. The execution permit is the
    # final database-backed admission boundary.
    work.permitted = False
    work.marked.clear()
    rejected_observations = Observations()
    rejected_client = Client()
    rejected_scheduler = BoundedProbeScheduler(
        global_limit=2, per_node_limit=1, per_site_limit=2, source_limit=2,
        path_limit=1, queue_limit=8, lease_seconds=15, retry_delay_seconds=1,
        max_attempts=1,
    )
    rejected_worker = ProbeMonitoringWorker(
        work=work, cameras=Cameras(), observations=rejected_observations,
        runtime=Runtime(), admission=admission, client=rejected_client,
        scheduler=rejected_scheduler, batch_limit=8, execution_workers=2,
    )
    rejected_worker.start()
    rejected = rejected_worker.run_once(now=NOW)

    assert rejected.candidates == rejected.submitted == 1
    assert rejected.executed == rejected.persisted == 0
    assert rejected_client.calls == 0
    assert rejected_observations.saved == []
    assert work.marked == []
    assert rejected_scheduler.diagnostics().active == 0
    assert rejected_scheduler.diagnostics().queued == 0
    rejected_worker.close()

    # Unexpected client failures are isolated and projected as infrastructure
    # inconclusive rather than killing the authoritative cycle.
    work.permitted = True
    work.marked.clear()
    failing_observations = Observations()
    failing_client = Client()
    failing_client.fail = True
    failing_worker = ProbeMonitoringWorker(
        work=work, cameras=Cameras(), observations=failing_observations,
        runtime=Runtime(), admission=admission, client=failing_client,
        scheduler=BoundedProbeScheduler(
            global_limit=2, per_node_limit=1, per_site_limit=2, source_limit=2,
            path_limit=1, queue_limit=8, lease_seconds=15, retry_delay_seconds=1,
            max_attempts=1,
        ),
        batch_limit=8, execution_workers=2,
    )
    failing_worker.start()
    failed = failing_worker.run_once(now=NOW)

    assert failed.candidates == failed.submitted == failed.executed == failed.persisted == 1
    assert failing_client.calls == 1
    assert failing_observations.saved[0][0].outcome is ProbeOutcome.INCONCLUSIVE
    assert failing_observations.saved[0][0].failure_class is ProbeFailureClass.EXECUTOR
    assert work.marked == [(camera_id, 3)]
    failing_worker.close()


def test_runtime_failure_is_isolated_to_one_camera() -> None:
    source_url = "rtsp://camera.example.invalid/live"
    admission = ProbeEndpointAdmission(
        site_key="local", allowed_networks=(ip_network("192.0.2.0/24"),),
        resolve=lambda _host: ("192.0.2.10",),
    )
    node_id = uuid4()
    cameras = tuple(
        CameraPlacement(
            id=uuid4(), name=f"Camera {number}", source_url=source_url,
            public_id=PublicId(generate_public_id()), node_id=node_id, node_port=10554,
            placement_mode=PlacementMode.AUTOMATIC, state=CameraState.ENABLED,
            desired_revision=1, applied_revision=1,
            probe_endpoint=admission.admit(source_url).identity,
        )
        for number in range(2)
    )
    node = MediaNode(
        id=node_id, name="node", external_port=10554, state=NodeState.RUNNING,
        runtime_state=NodeState.RUNNING, health=NodeHealth.HEALTHY,
        maintenance=False, management_fresh=True, config_compatible=True,
        desired_revision=1, applied_revision=1,
    )
    profile = CameraProbeProfile(enabled=True, max_source_sessions=2)

    class Work:
        def acquire(self) -> None: pass
        def assert_owned(self) -> None: pass
        def active_profiles(self, *, limit: int) -> tuple[_ProfileRow, ...]:
            return tuple(
                _ProfileRow(camera.id, 1, profile, NOW - timedelta(hours=1), None)
                for camera in cameras
            )
        @contextmanager
        def execution_permit(
            self, target: ProbeTarget, *, profile_revision: int,
        ) -> Iterator[bool]:
            yield True
        def mark_attempt(self, camera_id: UUID, *, revision: int) -> None: pass
        def close(self) -> None: pass

    class Catalog:
        def get_cameras(self, camera_ids: tuple[UUID, ...]) -> tuple[CameraPlacement, ...]:
            return cameras
        def get_node(self, requested: UUID) -> MediaNode | None:
            return node

    class Runtime:
        def observe(self, requested: UUID) -> CameraRuntimeObservation:
            if requested == cameras[0].id:
                raise MediaNodeUnavailable("node unavailable")
            return CameraRuntimeObservation(requested, node_id, False, 0, False, False)

    class Observations:
        def __init__(self) -> None:
            self.saved: list[ProbeObservation] = []
        def assert_ready(self) -> None: pass
        def assert_health_ready(self) -> None: pass
        def health_for(self, target: ProbeTarget, *, method: ProbeMethod) -> ProbeHealthRecord:
            return ProbeHealthRecord.for_target(target, method=method)
        def record_if_current(
            self, observation: ProbeObservation, *,
            confirmation_spacing: timedelta | None = None,
        ) -> bool:
            self.saved.append(observation)
            return True

    class Client:
        def execute(
            self, *, request_id: UUID, endpoint: AdmittedProbeEndpoint,
            deadline_at: datetime, cancelled: Callable[[], bool] | None = None,
        ) -> ProbeExecutionResult:
            return ProbeExecutionResult(
                ProbeOutcome.HEALTHY, NOW + timedelta(seconds=1), video_codec="h264",
            )

    observations = Observations()
    worker = ProbeMonitoringWorker(
        work=Work(), cameras=Catalog(), observations=observations, runtime=Runtime(),
        admission=admission, client=Client(),
        scheduler=BoundedProbeScheduler(
            global_limit=2, per_node_limit=2, per_site_limit=2, source_limit=2,
            path_limit=1, queue_limit=8, lease_seconds=15, retry_delay_seconds=1,
            max_attempts=1,
        ),
        batch_limit=8, execution_workers=2,
    )
    worker.start()

    cycle = worker.run_once(now=NOW)

    assert cycle.candidates == cycle.submitted == cycle.executed == cycle.persisted == 1
    assert observations.saved[0].target.camera_id == cameras[1].id


def _seed_profile_rows(database_url: str, *, count: int) -> tuple[UUID, ...]:
    node_id = uuid4()
    camera_ids = tuple(uuid4() for _ in range(count))
    updated_at = datetime.now(UTC) - timedelta(hours=1)
    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(text(
            "INSERT INTO media_nodes "
            "(id, name, external_port, api_port, metrics_port, state, runtime_state, "
            "health, camera_capacity, registered_cameras, active_sources, maintenance, "
            "management_fresh, config_compatible, release_id, mediamtx_binary_sha256, "
            "desired_revision, applied_revision) "
            "VALUES (:id, 'probe-node', 12000, 13000, 14000, 'running', 'running', "
            "'healthy', 100, :count, 0, false, true, true, '0.2.1', :digest, 1, 1)"
        ), {"id": node_id, "count": count, "digest": "a" * 64})
        for number, camera_id in enumerate(camera_ids):
            public_id = generate_public_id()
            connection.execute(text(
                "INSERT INTO cameras "
                "(id, name, source_url, public_id, state, desired_revision, applied_revision) "
                "VALUES (:id, :name, 'rtsp://192.0.2.10/live', :public_id, "
                "'enabled', 1, 1)"
            ), {"id": camera_id, "name": f"camera-{number}", "public_id": public_id})
            connection.execute(
                text("INSERT INTO public_id_tombstones (public_id) VALUES (:public_id)"),
                {"public_id": public_id},
            )
            connection.execute(text(
                "INSERT INTO camera_placements "
                "(camera_id, node_id, placement_mode, generation) "
                "VALUES (:camera_id, :node_id, 'automatic', 1)"
            ), {"camera_id": camera_id, "node_id": node_id})
            connection.execute(text(
                "INSERT INTO camera_probe_endpoints "
                "(camera_id, admitted_revision, endpoint_generation, endpoint_address, "
                "endpoint_port, site_key, policy_sha256, source_sha256) "
                "VALUES (:camera_id, 1, :generation, '192.0.2.10', 554, 'local', "
                ":policy, :source)"
            ), {
                "camera_id": camera_id,
                "generation": uuid4(),
                "policy": "b" * 64,
                "source": "a" * 64,
            })
            connection.execute(text(
                "INSERT INTO camera_probe_profiles "
                "(camera_id, revision, enabled, max_source_sessions, require_video, "
                "require_audio, routine_seconds, confirmation_seconds, timeout_seconds, "
                "updated_at) VALUES (:camera_id, 1, true, 2, true, false, 300, 30, 15, "
                ":updated_at)"
            ), {"camera_id": camera_id, "updated_at": updated_at})
    engine.dispose()
    return camera_ids


def _stored_probe_target(database_url: str, camera_id: UUID) -> ProbeTarget:
    engine = create_engine(database_url)
    try:
        with engine.connect() as connection:
            row = connection.execute(text(
                "SELECT camera.public_id, camera.desired_revision, "
                "placement.node_id, placement.generation AS placement_generation, "
                "node.state AS node_state, node.maintenance, endpoint.site_key, "
                "endpoint.endpoint_generation, profile.max_source_sessions "
                "FROM cameras AS camera "
                "JOIN camera_placements AS placement ON placement.camera_id=camera.id "
                "JOIN media_nodes AS node ON node.id=placement.node_id "
                "JOIN camera_probe_endpoints AS endpoint ON endpoint.camera_id=camera.id "
                "JOIN camera_probe_profiles AS profile ON profile.camera_id=camera.id "
                "WHERE camera.id=:camera_id"
            ), {"camera_id": camera_id}).mappings().one()
    finally:
        engine.dispose()
    return ProbeTarget(
        camera_id=camera_id,
        public_id=PublicId.parse(row["public_id"]),
        node_id=row["node_id"],
        site_key=row["site_key"],
        desired_revision=row["desired_revision"],
        placement_generation=row["placement_generation"],
        node_state=NodeState(row["node_state"]),
        enabled=True,
        maintenance=row["maintenance"],
        occupied=False,
        source_pull_active=False,
        max_source_sessions=row["max_source_sessions"],
        source_endpoint_generation=row["endpoint_generation"],
    )
