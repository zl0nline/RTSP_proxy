from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from ipaddress import ip_network
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, text

from rtsp_proxy.identifiers import PublicId
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
    ProbeHealthRecord,
    ProbeMethod,
    ProbeObservation,
    ProbeOutcome,
    ProbeTarget,
)
from rtsp_proxy.reconcile import CameraRuntimeObservation

NOW = datetime(2026, 9, 6, 12, tzinfo=UTC)


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

        def acquire(self) -> None: pass
        def assert_owned(self) -> None: pass
        def active_profiles(self, *, limit: int) -> tuple[_ProfileRow, ...]:
            assert limit == 8
            return (_ProfileRow(camera_id, 3, profile, NOW - timedelta(hours=1), None),)
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
        def execute(
            self,
            *,
            request_id: UUID,
            endpoint: AdmittedProbeEndpoint,
            deadline_at: datetime,
            cancelled: Callable[[], bool] | None = None,
        ) -> ProbeExecutionResult:
            assert endpoint.identity == camera.probe_endpoint
            return ProbeExecutionResult(
                outcome=ProbeOutcome.HEALTHY,
                completed_at=NOW + timedelta(seconds=1), video_codec="h264",
            )

    work = Work()
    observations = Observations()
    scheduler = BoundedProbeScheduler(
        global_limit=2, per_node_limit=1, per_site_limit=2, source_limit=2,
        path_limit=1, queue_limit=8, lease_seconds=15, retry_delay_seconds=1,
        max_attempts=1,
    )
    worker = ProbeMonitoringWorker(
        work=work, cameras=Cameras(), observations=observations,
        runtime=Runtime(), admission=admission, client=Client(), scheduler=scheduler,
        batch_limit=8, execution_workers=2,
    )

    worker.start()
    cycle = worker.run_once(now=NOW)

    assert cycle.candidates == cycle.submitted == cycle.executed == cycle.persisted == 1
    assert work.marked == [(camera_id, 3)]
    assert len(observations.saved) == 1
    assert observations.saved[0][0].video_codec == "h264"
