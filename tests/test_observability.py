from __future__ import annotations

import os
import smtplib
import ssl
import subprocess
import time
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError, ProgrammingError

from rtsp_proxy.app import create_app
from rtsp_proxy.config import RuntimeRole, Settings
from rtsp_proxy.database import PostgresNodeStore
from rtsp_proxy.migrate import upgrade_database
from rtsp_proxy.nodes import (
    InMemoryNodeStore,
    MediaNode,
    NodeHealth,
    NodeRuntimeObservation,
    NodeState,
)
from rtsp_proxy.observability import (
    FleetCollector,
    FleetSnapshot,
    IncidentControl,
    IncidentState,
    InMemoryObservabilityStore,
    NodeMetricObservation,
    NodeMetricSample,
    NodeScrapeStatus,
    NotificationDispatcher,
    NotificationKind,
    NotificationMessage,
    NotificationStatus,
    PathMetricCounters,
    PostgresObservabilityStore,
    SmtpNotificationTransport,
    parse_mediamtx_path_metrics,
)

FIRST_NODE_ID = UUID("10000000-0000-0000-0000-000000000001")
SECOND_NODE_ID = UUID("20000000-0000-0000-0000-000000000002")
NOW = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)


def _node(
    node_id: UUID,
    *,
    port: int,
    runtime_state: NodeState = NodeState.RUNNING,
    health: NodeHealth = NodeHealth.HEALTHY,
    registered_cameras: int = 0,
) -> MediaNode:
    return MediaNode(
        id=node_id,
        name=f"node-{port}",
        external_port=port,
        api_port=port + 10_000,
        metrics_port=port + 11_000,
        state=NodeState.RUNNING,
        runtime_state=runtime_state,
        health=health,
        registered_cameras=registered_cameras,
        applied_revision=1,
        config_compatible=True,
        management_fresh=True,
        management_observed_at=NOW,
        runtime_observed_at=NOW,
    )


class RecordingMetricSource:
    def __init__(self) -> None:
        self.calls: list[UUID] = []

    def scrape(self, node: MediaNode) -> NodeMetricSample:
        self.calls.append(node.id)
        if node.id == FIRST_NODE_ID:
            raise OSError("must-not-leak-host-details")
        return NodeMetricSample(
            active_sources=4,
            occupied_streams=1,
            received_bytes_total=12_000,
            sent_bytes_total=8_000,
        )


class SequencedMetricSource:
    def __init__(self, samples: list[NodeMetricSample | Exception]) -> None:
        self._samples = samples

    def scrape(self, node: MediaNode) -> NodeMetricSample:
        del node
        value = self._samples.pop(0)
        if isinstance(value, Exception):
            raise value
        return value


class FailingRuntimeObserver:
    def __init__(self, node: MediaNode) -> None:
        self._node = node

    def observe_node(self, node_id: UUID) -> MediaNode:
        assert node_id == self._node.id
        return replace(
            self._node,
            runtime_state=NodeState.FAILED,
            health=NodeHealth.UNHEALTHY,
        )


class SequencedRuntimeObserver:
    def __init__(self, nodes: list[MediaNode]) -> None:
        self._nodes = nodes

    def observe_node(self, node_id: UUID) -> MediaNode:
        node = self._nodes.pop(0)
        assert node.id == node_id
        return node


def test_incident_control_emits_one_failure_and_one_recovery_without_reminders() -> None:
    store = InMemoryObservabilityStore()
    control = IncidentControl(store=store, clock=lambda: NOW)
    failed = _node(
        FIRST_NODE_ID,
        port=10000,
        runtime_state=NodeState.FAILED,
        health=NodeHealth.UNHEALTHY,
    )

    opened = control.observe(failed)
    repeated = control.observe(failed)

    assert opened is not None
    assert opened.state is IncidentState.OPEN
    assert repeated == opened
    assert [message.kind for message in store.list_notifications()] == [
        NotificationKind.FAILURE
    ]

    recovered = control.observe(
        _node(FIRST_NODE_ID, port=10000),
        observed_at=NOW + timedelta(minutes=3),
    )
    repeated_recovery = control.observe(
        _node(FIRST_NODE_ID, port=10000),
        observed_at=NOW + timedelta(minutes=4),
    )

    assert recovered is not None
    assert recovered.state is IncidentState.RECOVERED
    assert repeated_recovery == recovered
    messages = store.list_notifications()
    assert [message.kind for message in messages] == [
        NotificationKind.FAILURE,
        NotificationKind.RECOVERY,
    ]
    assert len({message.dedupe_key for message in messages}) == 2
    assert all(message.status is NotificationStatus.PENDING for message in messages)


def test_collector_preserves_each_node_when_one_metrics_scrape_fails() -> None:
    nodes = InMemoryNodeStore(
        nodes=(
            _node(FIRST_NODE_ID, port=10000, registered_cameras=50),
            _node(SECOND_NODE_ID, port=10001, registered_cameras=10),
        )
    )
    observations = InMemoryObservabilityStore()
    metrics = RecordingMetricSource()
    collector = FleetCollector(
        nodes=nodes,
        metrics=metrics,
        observations=observations,
        incidents=IncidentControl(store=observations, clock=lambda: NOW),
        max_nodes=50,
        external_port_capacity=1000,
        clock=lambda: NOW,
    )

    snapshot = collector.run_once()

    assert metrics.calls == [FIRST_NODE_ID, SECOND_NODE_ID]
    assert snapshot.generated_at == NOW
    assert snapshot.configured_nodes == 2
    assert snapshot.max_nodes == 50
    assert snapshot.registered_cameras == 60
    assert snapshot.external_ports_used == 2
    assert snapshot.external_ports_free == 998
    assert [node.node_id for node in snapshot.nodes] == [FIRST_NODE_ID, SECOND_NODE_ID]
    assert snapshot.nodes[0].scrape_status is NodeScrapeStatus.UNAVAILABLE
    assert snapshot.nodes[0].scrape_reason == "node_metrics_unavailable"
    assert snapshot.nodes[0].metrics is None
    assert snapshot.nodes[1].scrape_status is NodeScrapeStatus.FRESH
    assert snapshot.nodes[1].metrics == NodeMetricSample(
        active_sources=4,
        occupied_streams=1,
        received_bytes_total=12_000,
        sent_bytes_total=8_000,
    )
    assert observations.current_snapshot() == snapshot


def test_collector_observes_runtime_before_incident_and_snapshot() -> None:
    node = _node(FIRST_NODE_ID, port=10000)
    nodes = InMemoryNodeStore(nodes=(node,))
    observations = InMemoryObservabilityStore()
    snapshot = FleetCollector(
        nodes=nodes,
        runtime=FailingRuntimeObserver(node),
        metrics=RecordingMetricSource(),
        observations=observations,
        incidents=IncidentControl(store=observations, clock=lambda: NOW),
        max_nodes=50,
        external_port_capacity=1000,
        clock=lambda: NOW,
    ).run_once()

    assert snapshot.nodes[0].runtime_state is NodeState.FAILED
    notifications = observations.list_notifications()
    assert len(notifications) == 1
    assert notifications[0].kind is NotificationKind.FAILURE


def test_runtime_observation_failure_cannot_emit_a_false_recovery() -> None:
    class UnavailableRuntime:
        def observe_node(self, _node_id: UUID) -> MediaNode:
            raise OSError("runtime unavailable")

    node = _node(FIRST_NODE_ID, port=10000)
    observations = InMemoryObservabilityStore()
    IncidentControl(store=observations, clock=lambda: NOW).observe(
        replace(
            node,
            runtime_state=NodeState.FAILED,
            health=NodeHealth.UNHEALTHY,
        )
    )
    snapshot = FleetCollector(
        nodes=InMemoryNodeStore(nodes=(node,)),
        runtime=UnavailableRuntime(),
        metrics=RecordingMetricSource(),
        observations=observations,
        incidents=IncidentControl(store=observations, clock=lambda: NOW),
        max_nodes=50,
        external_port_capacity=1000,
        clock=lambda: NOW + timedelta(minutes=1),
    ).run_once().nodes[0]

    assert snapshot.scrape_status is NodeScrapeStatus.UNAVAILABLE
    assert snapshot.scrape_reason == "node_runtime_unavailable"
    assert [message.kind for message in observations.list_notifications()] == [
        NotificationKind.FAILURE
    ]


def test_collector_publishes_bitrate_reset_idle_and_stale_semantics() -> None:
    node = _node(FIRST_NODE_ID, port=10000)
    observations = InMemoryObservabilityStore()
    metrics = SequencedMetricSource(
        [
            NodeMetricSample(1, 1, 100, 200),
            NodeMetricSample(1, 1, 1_100, 2_200),
            NodeMetricSample(0, 0, 10, 20),
            OSError("must-not-leak"),
        ]
    )
    current_time = NOW
    monotonic_time = 100.0
    collector = FleetCollector(
        nodes=InMemoryNodeStore(nodes=(node,)),
        metrics=metrics,
        observations=observations,
        incidents=IncidentControl(store=observations, clock=lambda: current_time),
        max_nodes=50,
        external_port_capacity=1000,
        clock=lambda: current_time,
        monotonic_clock=lambda: monotonic_time,
        collection_interval_seconds=5,
    )

    assert collector.run_once().nodes[0].received_bitrate_bps is None
    current_time += timedelta(seconds=5)
    monotonic_time += 5
    flowing = collector.run_once().nodes[0]
    assert flowing.received_bitrate_bps == 1600
    assert flowing.sent_bitrate_bps == 3200
    current_time += timedelta(seconds=5)
    monotonic_time += 5
    reset = collector.run_once().nodes[0]
    assert reset.scrape_status is NodeScrapeStatus.IDLE
    assert reset.counters_reset
    assert reset.received_bitrate_bps is None
    current_time += timedelta(seconds=5)
    monotonic_time += 5
    stale = collector.run_once().nodes[0]
    assert stale.scrape_status is NodeScrapeStatus.STALE
    assert stale.metric_observed_at == NOW + timedelta(seconds=10)
    assert stale.metrics == reset.metrics


def test_collector_detects_one_path_reset_hidden_by_another_path_growth() -> None:
    node = _node(FIRST_NODE_ID, port=10000)
    observations = InMemoryObservabilityStore()
    metrics = SequencedMetricSource(
        [
            NodeMetricSample(
                2,
                0,
                200,
                200,
                path_counters=(
                    PathMetricCounters("aaaaaaaaaaaaaaaaaaaaaaaaaa", 100, 100),
                    PathMetricCounters("bbbbbbbbbbbbbbbbbbbbbbbbbi", 100, 100),
                ),
            ),
            NodeMetricSample(
                2,
                0,
                350,
                350,
                path_counters=(
                    PathMetricCounters("aaaaaaaaaaaaaaaaaaaaaaaaaa", 50, 50),
                    PathMetricCounters("bbbbbbbbbbbbbbbbbbbbbbbbbi", 300, 300),
                ),
            ),
        ]
    )
    current_time = NOW
    monotonic_time = 100.0
    collector = FleetCollector(
        nodes=InMemoryNodeStore(nodes=(node,)),
        metrics=metrics,
        observations=observations,
        incidents=IncidentControl(store=observations, clock=lambda: current_time),
        max_nodes=50,
        external_port_capacity=1000,
        clock=lambda: current_time,
        monotonic_clock=lambda: monotonic_time,
        collection_interval_seconds=5,
    )

    collector.run_once()
    current_time += timedelta(seconds=5)
    monotonic_time += 5
    snapshot = collector.run_once().nodes[0]

    assert snapshot.counters_reset
    assert snapshot.received_bitrate_bps is None
    assert snapshot.sent_bitrate_bps is None


def test_collector_resets_rates_when_the_media_process_generation_changes() -> None:
    node = _node(FIRST_NODE_ID, port=10000)
    first_generation = replace(
        node,
        process_id=100,
        process_start_ticks=1_000,
        process_boot_id=UUID("50000000-0000-0000-0000-000000000005"),
        observed_release_id="0.2.0",
    )
    second_generation = replace(
        node,
        process_id=101,
        process_start_ticks=2_000,
        process_boot_id=first_generation.process_boot_id,
        observed_release_id="0.2.0",
    )
    current_time = NOW
    monotonic_time = 100.0
    collector = FleetCollector(
        nodes=InMemoryNodeStore(nodes=(node,)),
        runtime=SequencedRuntimeObserver([first_generation, second_generation]),
        metrics=SequencedMetricSource(
            [NodeMetricSample(1, 1, 100, 100), NodeMetricSample(1, 1, 10_000, 10_000)]
        ),
        observations=InMemoryObservabilityStore(),
        incidents=IncidentControl(store=InMemoryObservabilityStore()),
        max_nodes=50,
        external_port_capacity=1000,
        clock=lambda: current_time,
        monotonic_clock=lambda: monotonic_time,
        collection_interval_seconds=5,
    )

    collector.run_once()
    current_time += timedelta(seconds=5)
    monotonic_time += 5
    restarted = collector.run_once().nodes[0]

    assert restarted.counters_reset
    assert restarted.received_bitrate_bps is None
    assert restarted.sent_bitrate_bps is None


def test_collector_rejects_metrics_from_a_different_process_generation() -> None:
    node = replace(
        _node(FIRST_NODE_ID, port=10000),
        process_id=100,
        process_start_ticks=1_000,
        process_boot_id=UUID("50000000-0000-0000-0000-000000000005"),
        observed_release_id="0.2.0",
    )

    class MismatchedMetrics:
        def scrape(self, _node: MediaNode) -> NodeMetricObservation:
            return NodeMetricObservation(
                sample=NodeMetricSample(1, 1, 100, 100),
                process_id=101,
                process_start_ticks=2_000,
                process_boot_id=node.process_boot_id,  # type: ignore[arg-type]
                release_id="0.2.0",
            )

    snapshot = FleetCollector(
        nodes=InMemoryNodeStore(nodes=(node,)),
        runtime=SequencedRuntimeObserver([node]),
        metrics=MismatchedMetrics(),
        observations=InMemoryObservabilityStore(),
        incidents=IncidentControl(store=InMemoryObservabilityStore()),
        max_nodes=50,
        external_port_capacity=1000,
    ).run_once().nodes[0]

    assert snapshot.scrape_status is NodeScrapeStatus.UNAVAILABLE
    assert snapshot.scrape_reason == "node_metric_generation_mismatch"


def test_collector_marks_successful_sample_stale_after_two_interval_gap() -> None:
    node = _node(FIRST_NODE_ID, port=10000)
    observations = InMemoryObservabilityStore()
    metrics = SequencedMetricSource(
        [NodeMetricSample(1, 0, 100, 100), NodeMetricSample(1, 0, 200, 200)]
    )
    current_time = NOW
    monotonic_time = 100.0
    collector = FleetCollector(
        nodes=InMemoryNodeStore(nodes=(node,)),
        metrics=metrics,
        observations=observations,
        incidents=IncidentControl(store=observations, clock=lambda: current_time),
        max_nodes=50,
        external_port_capacity=1000,
        clock=lambda: current_time,
        monotonic_clock=lambda: monotonic_time,
        collection_interval_seconds=5,
    )

    collector.run_once()
    current_time += timedelta(seconds=11)
    monotonic_time += 11
    snapshot = collector.run_once().nodes[0]

    assert snapshot.scrape_status is NodeScrapeStatus.STALE
    assert snapshot.scrape_reason == "node_metrics_gap"
    assert snapshot.received_bitrate_bps is None


def test_collector_publishes_without_waiting_for_an_overdue_node() -> None:
    class SlowMetrics:
        def __init__(self) -> None:
            self.calls = 0

        def scrape(self, node: MediaNode) -> NodeMetricSample:
            del node
            self.calls += 1
            time.sleep(0.2)
            return NodeMetricSample(0, 0, 0, 0)

    node = _node(FIRST_NODE_ID, port=10000)
    observations = InMemoryObservabilityStore()
    metrics = SlowMetrics()
    started = time.monotonic()
    collector = FleetCollector(
        nodes=InMemoryNodeStore(nodes=(node,)),
        metrics=metrics,
        observations=observations,
        incidents=IncidentControl(store=observations),
        max_nodes=50,
        external_port_capacity=1000,
        cycle_timeout_seconds=0.02,
    )

    snapshot = collector.run_once()

    assert time.monotonic() - started < 0.1
    assert snapshot.nodes[0].scrape_status is NodeScrapeStatus.UNAVAILABLE
    assert snapshot.nodes[0].scrape_reason == "node_collection_deadline"

    for _ in range(3):
        collector.run_once()
    assert metrics.calls == 1
    collector.close()


def test_postgres_incident_dedupe_survives_store_restart(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    node_store = PostgresNodeStore(postgres_database_url)
    try:
        with node_store.provisioning_guard():
            node = node_store.register_automatically(
                name="node-10000",
                allowed_ports=(10000,),
                api_ports=(20000,),
                metrics_ports=(20100,),
                max_nodes=50,
                preferred_port=10000,
                choose_port=lambda ports: ports[0],
                new_node_id=lambda: FIRST_NODE_ID,
            )
    finally:
        node_store.close()

    first_store = PostgresObservabilityStore(postgres_database_url)
    try:
        control = IncidentControl(store=first_store, clock=lambda: NOW)
        control.observe(
            _node(
                node.id,
                port=10000,
                runtime_state=NodeState.FAILED,
                health=NodeHealth.UNHEALTHY,
            )
        )
    finally:
        first_store.close()

    reopened = PostgresObservabilityStore(postgres_database_url)
    try:
        control = IncidentControl(store=reopened, clock=lambda: NOW + timedelta(minutes=1))
        incident = control.observe(
            _node(
                node.id,
                port=10000,
                runtime_state=NodeState.FAILED,
                health=NodeHealth.UNHEALTHY,
            )
        )
        notifications = reopened.list_notifications()
    finally:
        reopened.close()

    assert incident is not None
    assert incident.state is IncidentState.OPEN
    assert len(notifications) == 1
    assert notifications[0].kind is NotificationKind.FAILURE
    assert notifications[0].dedupe_key == f"node-incident:{incident.id}:failure"


@pytest.mark.parametrize(
    ("role", "script"),
    [
        ("rtsp_proxy_collector", "rtsp_proxy_collector.sql"),
        ("rtsp_proxy_notifier", "rtsp_proxy_notifier.sql"),
    ],
)
def test_observability_database_roles_cannot_read_secrets_or_mutate_control_plane(
    postgres_database_url: str,
    role: str,
    script: str,
) -> None:
    upgrade_database(postgres_database_url)
    parsed = make_url(postgres_database_url)
    assert parsed.database is not None and parsed.host is not None and parsed.port is not None
    administrator = create_engine(postgres_database_url)
    with administrator.begin() as connection:
        connection.execute(
            text(
                "DO $$ BEGIN "
                "IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = "
                "'rtsp_proxy_observability_hostile') THEN "
                "CREATE ROLE rtsp_proxy_observability_hostile NOLOGIN; END IF; END $$"
            )
        )
        connection.execute(
            text(
                f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = "
                f"'{role}') THEN CREATE ROLE {role} LOGIN; END IF; END $$"
            )
        )
        connection.execute(
            text(f"GRANT rtsp_proxy_observability_hostile TO {role}")
        )
    for _ in range(2):
        subprocess.run(
            (
                "psql",
                "--host",
                parsed.host,
                "--port",
                str(parsed.port),
                "--username",
                parsed.username or "postgres",
                "--dbname",
                parsed.database,
                "--set",
                f"DBNAME={parsed.database}",
                "--file",
                str(Path("deploy/postgresql", script).resolve()),
            ),
            check=True,
            capture_output=True,
            text=True,
        )
    restricted_url = str(parsed.set(username=role, password=None))
    restricted = create_engine(restricted_url)
    with restricted.connect() as connection:
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == (
            "0015_camera_name_contract"
        )
        assert not connection.scalar(
            text(
                "SELECT pg_has_role(current_user, "
                "'rtsp_proxy_observability_hostile', 'MEMBER')"
            )
        )
    with pytest.raises(ProgrammingError), restricted.begin() as connection:
        connection.execute(text("SELECT source_url FROM cameras"))
    with pytest.raises(ProgrammingError), restricted.begin() as connection:
        connection.execute(text("UPDATE media_nodes SET state='failed'"))
    with pytest.raises(ProgrammingError), restricted.begin() as connection:
        connection.execute(text("UPDATE notification_incidents SET state='closed'"))
    if role == "rtsp_proxy_notifier":
        with pytest.raises(ProgrammingError), restricted.begin() as connection:
            connection.execute(
                text("UPDATE notification_messages SET status='sent'")
            )
        store = PostgresObservabilityStore(restricted_url)
        try:
            store.assert_notification_ready()
            with administrator.begin() as connection:
                connection.execute(
                    text(
                        "REVOKE EXECUTE ON FUNCTION "
                        "rtsp_proxy_notifier_claim(timestamptz, timestamptz, uuid) "
                        "FROM rtsp_proxy_notifier"
                    )
                )
            with pytest.raises(RuntimeError, match="notification_capability_unavailable"):
                store.assert_notification_ready()
        finally:
            store.close()
    else:
        store = PostgresObservabilityStore(restricted_url)
        try:
            store.assert_collector_ready()
            with administrator.begin() as connection:
                connection.execute(
                    text("REVOKE SELECT ON media_nodes FROM rtsp_proxy_collector")
                )
            with pytest.raises(RuntimeError, match="collector_capability_unavailable"):
                store.assert_collector_ready()
        finally:
            store.close()


def test_postgres_incident_history_does_not_block_empty_node_delete(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    node_store = PostgresNodeStore(postgres_database_url)
    try:
        with node_store.provisioning_guard():
            node = node_store.register_automatically(
                name="node-incident-delete",
                allowed_ports=(10000,),
                api_ports=(20000,),
                metrics_ports=(20100,),
                max_nodes=50,
                preferred_port=10000,
                choose_port=lambda ports: ports[0],
                new_node_id=lambda: FIRST_NODE_ID,
            )
        incidents = PostgresObservabilityStore(postgres_database_url)
        try:
            IncidentControl(store=incidents, clock=lambda: NOW).observe(
                _node(
                    node.id,
                    port=10000,
                    runtime_state=NodeState.FAILED,
                    health=NodeHealth.UNHEALTHY,
                )
            )
        finally:
            incidents.close()
        stopped = node_store.request_stop(node.id)
        node_store.apply_runtime_observation(
            node.id,
            NodeRuntimeObservation(
                state=NodeState.STOPPED,
                health=NodeHealth.UNKNOWN,
                config_compatible=True,
                applied_revision=stopped.desired_revision,
                config_sha256="b" * 64,
                release_id=stopped.release_id,
            ),
        )
        node_store.request_node_delete(node.id)
        node_store.finalize_node_delete(node.id)
        assert node_store.get_node(node.id) is None
    finally:
        node_store.close()


def test_postgres_notification_claim_retry_and_recovery_are_durable(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    node_store = PostgresNodeStore(postgres_database_url)
    try:
        with node_store.provisioning_guard():
            node = node_store.register_automatically(
                name="node-notification-delivery",
                allowed_ports=(10000,),
                api_ports=(20000,),
                metrics_ports=(20100,),
                max_nodes=50,
                preferred_port=10000,
                choose_port=lambda ports: ports[0],
                new_node_id=lambda: FIRST_NODE_ID,
            )
        store = PostgresObservabilityStore(postgres_database_url)
        try:
            incidents = IncidentControl(store=store, clock=lambda: NOW)
            incidents.observe(
                _node(
                    node.id,
                    port=10000,
                    runtime_state=NodeState.FAILED,
                    health=NodeHealth.UNHEALTHY,
                )
            )
            incidents.observe(
                _node(node.id, port=10000),
                observed_at=NOW + timedelta(minutes=1),
            )
            transport = RecordingNotificationTransport(fail_attempts=1)
            dispatcher = NotificationDispatcher(
                store=store,
                transport=transport,
                max_attempts=2,
                retry_delay=timedelta(seconds=5),
                clock=lambda: NOW,
            )

            failed_attempt = dispatcher.run_once()
            assert failed_attempt is not None
            assert failed_attempt.status is NotificationStatus.PENDING
            assert dispatcher.run_once(now=NOW + timedelta(seconds=4)) is None
            failure = dispatcher.run_once(now=NOW + timedelta(seconds=5))
            recovery = dispatcher.run_once(now=NOW + timedelta(minutes=1))
            persisted = store.list_notifications()
        finally:
            store.close()
    finally:
        node_store.close()

    assert failure is not None and failure.status is NotificationStatus.SENT
    assert recovery is not None and recovery.status is NotificationStatus.SENT
    assert [message.attempts for message in persisted] == [2, 1]
    assert [message.kind for message in persisted] == [
        NotificationKind.FAILURE,
        NotificationKind.RECOVERY,
    ]


def test_postgres_fleet_snapshot_round_trip_preserves_typed_metric_state(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresObservabilityStore(postgres_database_url)
    expected = FleetCollector(
        nodes=InMemoryNodeStore(nodes=(_node(FIRST_NODE_ID, port=10000),)),
        metrics=SequencedMetricSource([NodeMetricSample(0, 0, 100, 200)]),
        observations=store,
        incidents=IncidentControl(store=InMemoryObservabilityStore(), clock=lambda: NOW),
        max_nodes=50,
        external_port_capacity=1000,
        clock=lambda: NOW,
    ).run_once()
    try:
        actual = store.current_snapshot()
    finally:
        store.close()

    assert actual == expected
    assert actual is not None
    assert actual.nodes[0].scrape_status is NodeScrapeStatus.IDLE


def test_notifier_database_operations_are_bounded_by_statement_timeout(
    postgres_database_url: str,
) -> None:
    upgrade_database(postgres_database_url)
    store = PostgresObservabilityStore(
        postgres_database_url,
        statement_timeout_ms=100,
    )
    blocker = create_engine(postgres_database_url, hide_parameters=True).connect()
    transaction = blocker.begin()
    try:
        blocker.execute(text("LOCK TABLE notification_messages IN ACCESS EXCLUSIVE MODE"))
        started_at = time.monotonic()
        with pytest.raises(DBAPIError):
            store.list_notifications()
        assert time.monotonic() - started_at < 1
    finally:
        transaction.rollback()
        blocker.close()
        store.close()

def test_metric_sample_rejects_impossible_single_reader_counts() -> None:
    with pytest.raises(ValueError, match="occupied_streams_invalid"):
        NodeMetricSample(
            active_sources=1,
            occupied_streams=101,
            received_bytes_total=0,
            sent_bytes_total=0,
        )


def test_metric_and_snapshot_models_reject_inconsistent_evidence() -> None:
    with pytest.raises(ValueError, match="path_metric_public_id_invalid"):
        PathMetricCounters("not-a-public-id", 0, 0)
    with pytest.raises(ValueError, match="path_metric_counter_invalid"):
        PathMetricCounters("aaaaaaaaaaaaaaaaaaaaaaaaaa", -1, 0)
    with pytest.raises(ValueError, match="active_sources_invalid"):
        NodeMetricSample(101, 0, 0, 0)
    with pytest.raises(ValueError, match="byte_counter_invalid"):
        NodeMetricSample(0, 0, -1, 0)
    with pytest.raises(ValueError, match="path_metric_counters_invalid"):
        NodeMetricSample(
            1,
            0,
            1,
            1,
            path_counters=(
                PathMetricCounters("bbbbbbbbbbbbbbbbbbbbbbbbbi", 0, 0),
                PathMetricCounters("aaaaaaaaaaaaaaaaaaaaaaaaaa", 1, 1),
            ),
        )
    duplicate_counter = PathMetricCounters("aaaaaaaaaaaaaaaaaaaaaaaaaa", 1, 1)
    with pytest.raises(ValueError, match="path_metric_counters_invalid"):
        NodeMetricSample(
            1,
            0,
            2,
            2,
            path_counters=(duplicate_counter, duplicate_counter),
        )
    with pytest.raises(ValueError, match="path_metric_aggregate_invalid"):
        NodeMetricSample(
            1,
            0,
            2,
            1,
            path_counters=(
                PathMetricCounters("aaaaaaaaaaaaaaaaaaaaaaaaaa", 1, 1),
            ),
        )
    with pytest.raises(ValueError, match="node_metric_process_identity_invalid"):
        NodeMetricObservation(
            NodeMetricSample(0, 0, 0, 0),
            process_id=0,
            process_start_ticks=1,
            process_boot_id=uuid4(),
            release_id="0.2.0",
        )

    valid = FleetSnapshot(
        generated_at=NOW,
        configured_nodes=0,
        max_nodes=50,
        registered_cameras=0,
        external_ports_used=0,
        external_ports_free=1000,
        nodes=(),
    )
    for changes, reason in (
        ({"generated_at": NOW.replace(tzinfo=None)}, "snapshot_timezone_required"),
        ({"configured_nodes": 1}, "snapshot_node_count_invalid"),
        ({"max_nodes": 101}, "snapshot_node_capacity_invalid"),
        ({"external_ports_used": 1}, "snapshot_port_count_invalid"),
        ({"external_ports_free": -1}, "snapshot_port_capacity_invalid"),
    ):
        with pytest.raises(ValueError, match=reason):
            replace(valid, **changes)


def test_observability_controls_reject_unbounded_or_naive_configuration() -> None:
    with pytest.raises(ValueError, match="incident_observation_timezone_required"):
        IncidentControl(store=InMemoryObservabilityStore()).observe(
            _node(FIRST_NODE_ID, port=10000),
            observed_at=NOW.replace(tzinfo=None),
        )
    with pytest.raises(ValueError, match="notification_max_attempts_invalid"):
        NotificationDispatcher(
            store=InMemoryObservabilityStore(),
            transport=RecordingNotificationTransport(),
            max_attempts=0,
        )
    with pytest.raises(ValueError, match="notification_timing_invalid"):
        NotificationDispatcher(
            store=InMemoryObservabilityStore(),
            transport=RecordingNotificationTransport(),
            retry_delay=timedelta(0),
        )
    def collector(
        *,
        max_nodes: int = 50,
        external_port_capacity: int = 1000,
        workers: int = 8,
        collection_interval_seconds: float = 5,
        cycle_timeout_seconds: float | None = None,
    ) -> FleetCollector:
        return FleetCollector(
            nodes=InMemoryNodeStore(nodes=()),
            metrics=RecordingMetricSource(),
            observations=InMemoryObservabilityStore(),
            incidents=IncidentControl(store=InMemoryObservabilityStore()),
            max_nodes=max_nodes,
            external_port_capacity=external_port_capacity,
            workers=workers,
            collection_interval_seconds=collection_interval_seconds,
            cycle_timeout_seconds=cycle_timeout_seconds,
        )

    invalid_factories: tuple[tuple[Callable[[], FleetCollector], str], ...] = (
        (lambda: collector(max_nodes=0), "max_nodes_invalid"),
        (
            lambda: collector(external_port_capacity=49),
            "external_port_capacity_invalid",
        ),
        (lambda: collector(workers=0), "collector_workers_invalid"),
        (
            lambda: collector(collection_interval_seconds=0),
            "collector_interval_invalid",
        ),
        (
            lambda: collector(cycle_timeout_seconds=0),
            "collector_cycle_timeout_invalid",
        ),
    )
    for factory, reason in invalid_factories:
        with pytest.raises(ValueError, match=reason):
            factory()


def test_mediamtx_path_metrics_are_reduced_to_bounded_node_aggregates() -> None:
    payload = b"""# Paths
paths{name="aaaaaaaaaaaaaaaaaaaaaaaaaa",state="ready"} 1
paths_readers{name="aaaaaaaaaaaaaaaaaaaaaaaaaa",state="ready",readerType="rtspSession"} 1
paths_inbound_bytes{name="aaaaaaaaaaaaaaaaaaaaaaaaaa",state="ready"} 12000
paths_outbound_bytes{name="aaaaaaaaaaaaaaaaaaaaaaaaaa",state="ready"} 8000
paths{name="bbbbbbbbbbbbbbbbbbbbbbbbbi",state="notReady"} 1
paths_readers{name="bbbbbbbbbbbbbbbbbbbbbbbbbi",state="notReady",readerType=""} 0
paths_inbound_bytes{name="bbbbbbbbbbbbbbbbbbbbbbbbbi",state="notReady"} 0
paths_outbound_bytes{name="bbbbbbbbbbbbbbbbbbbbbbbbbi",state="notReady"} 0
"""

    assert parse_mediamtx_path_metrics(payload) == NodeMetricSample(
        active_sources=1,
        occupied_streams=1,
        received_bytes_total=12_000,
        sent_bytes_total=8_000,
        path_counters=(
            PathMetricCounters("aaaaaaaaaaaaaaaaaaaaaaaaaa", 12_000, 8_000),
            PathMetricCounters("bbbbbbbbbbbbbbbbbbbbbbbbbi", 0, 0),
        ),
    )


@pytest.mark.parametrize(
    "payload",
    [
        b'paths{name="not-public",state="ready"} 1\n',
        (
            b'paths_readers{name="aaaaaaaaaaaaaaaaaaaaaaaaaa",state="ready",'
            b'readerType="rtspSession"} 2\n'
        ),
        b'paths_inbound_bytes{name="aaaaaaaaaaaaaaaaaaaaaaaaaa",state="ready"} -1\n',
    ],
)
def test_mediamtx_path_metrics_fail_closed_on_invalid_contract(payload: bytes) -> None:
    with pytest.raises(ValueError, match="node_metrics_invalid"):
        parse_mediamtx_path_metrics(payload)


@pytest.mark.parametrize(
    "payload",
    [
        b"x" * 1_048_577,
        b"paths 1\x00\n",
        b"paths 1\n",
        b'paths{name="aaaaaaaaaaaaaaaaaaaaaaaaaa",state="unknown"} 1\n',
        b'paths{name="aaaaaaaaaaaaaaaaaaaaaaaaaa",state="ready",state="ready"} 1\n',
        (
            b'paths{name="aaaaaaaaaaaaaaaaaaaaaaaaaa",state="ready"} 1\n'
            b'paths_readers{name="aaaaaaaaaaaaaaaaaaaaaaaaaa",state="ready",'
            b'readerType="rtspSession"} 1\n'
        ),
    ],
)
def test_mediamtx_path_metrics_reject_additional_bounded_parser_edges(
    payload: bytes,
) -> None:
    with pytest.raises(ValueError, match="node_metrics_invalid"):
        parse_mediamtx_path_metrics(payload)


def test_dashboard_snapshot_api_reads_only_the_persisted_collector_snapshot() -> None:
    observations = InMemoryObservabilityStore()
    FleetCollector(
        nodes=InMemoryNodeStore(nodes=(_node(SECOND_NODE_ID, port=10001),)),
        metrics=RecordingMetricSource(),
        observations=observations,
        incidents=IncidentControl(store=observations, clock=lambda: NOW),
        max_nodes=50,
        external_port_capacity=1000,
        clock=lambda: NOW,
    ).run_once()
    client = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            fleet_snapshots=observations,
            clock=lambda: NOW,
        )
    )

    response = client.get("/api/v1/dashboard/snapshot")

    assert response.status_code == 200
    assert response.json() == {
        "generated_at": "2026-08-13T12:00:00Z",
        "configured_nodes": 1,
        "max_nodes": 50,
        "registered_cameras": 0,
        "external_ports_used": 1,
        "external_ports_free": 999,
        "nodes": [
            {
                "node_id": str(SECOND_NODE_ID),
                "name": "node-10001",
                "external_port": 10001,
                "desired_state": "running",
                "runtime_state": "running",
                "health": "healthy",
                "registered_cameras": 0,
                "camera_capacity": 100,
                "desired_revision": 1,
                "applied_revision": 1,
                "scrape_status": "fresh",
                "scrape_reason": None,
                "metrics": {
                    "active_sources": 4,
                    "occupied_streams": 1,
                    "received_bytes_total": 12000,
                    "sent_bytes_total": 8000,
                },
                "metric_observed_at": "2026-08-13T12:00:00Z",
                "received_bitrate_bps": None,
                "sent_bitrate_bps": None,
                "counters_reset": False,
            }
        ],
    }


def test_dashboard_snapshot_api_fails_closed_for_missing_pending_or_stale_data() -> None:
    unavailable = TestClient(create_app(Settings(role=RuntimeRole.WEB)))
    assert unavailable.get("/api/v1/dashboard/snapshot").json()["detail"]["code"] == (
        "fleet_snapshot_unavailable"
    )

    observations = InMemoryObservabilityStore()
    pending = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            fleet_snapshots=observations,
            clock=lambda: NOW,
        )
    )
    assert pending.get("/api/v1/dashboard/snapshot").json()["detail"]["code"] == (
        "fleet_snapshot_pending"
    )
    FleetCollector(
        nodes=InMemoryNodeStore(nodes=()),
        metrics=SequencedMetricSource([]),
        observations=observations,
        incidents=IncidentControl(store=observations, clock=lambda: NOW),
        max_nodes=50,
        external_port_capacity=1000,
        clock=lambda: NOW,
    ).run_once()
    stale = TestClient(
        create_app(
            Settings(role=RuntimeRole.WEB),
            fleet_snapshots=observations,
            fleet_snapshot_max_age_seconds=5,
            clock=lambda: NOW + timedelta(seconds=6),
        )
    )
    response = stale.get("/api/v1/dashboard/snapshot")
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "fleet_snapshot_stale"


class RecordingNotificationTransport:
    def __init__(self, *, fail_attempts: int = 0) -> None:
        self.fail_attempts = fail_attempts
        self.sent: list[tuple[str, NotificationKind]] = []

    def send(self, message: NotificationMessage) -> None:
        if self.fail_attempts > 0:
            self.fail_attempts -= 1
            raise OSError("must-not-be-persisted")
        self.sent.append((message.dedupe_key, message.kind))


def test_notification_dispatcher_retries_boundedly_and_preserves_incident_order() -> None:
    store = InMemoryObservabilityStore()
    control = IncidentControl(store=store, clock=lambda: NOW)
    control.observe(
        _node(
            FIRST_NODE_ID,
            port=10000,
            runtime_state=NodeState.FAILED,
            health=NodeHealth.UNHEALTHY,
        )
    )
    control.observe(
        _node(FIRST_NODE_ID, port=10000),
        observed_at=NOW + timedelta(minutes=1),
    )
    transport = RecordingNotificationTransport(fail_attempts=1)
    dispatcher = NotificationDispatcher(
        store=store,
        transport=transport,
        max_attempts=3,
        retry_delay=timedelta(seconds=10),
        clock=lambda: NOW,
    )

    first = dispatcher.run_once()
    blocked_recovery = dispatcher.run_once()

    assert first is not None
    assert first.kind is NotificationKind.FAILURE
    assert first.status is NotificationStatus.PENDING
    assert first.attempts == 1
    assert blocked_recovery is None
    assert transport.sent == []

    sent_failure = dispatcher.run_once(now=NOW + timedelta(seconds=10))
    sent_recovery = dispatcher.run_once(now=NOW + timedelta(minutes=1))

    assert sent_failure is not None
    assert sent_failure.status is NotificationStatus.SENT
    assert sent_recovery is not None
    assert sent_recovery.kind is NotificationKind.RECOVERY
    assert sent_recovery.status is NotificationStatus.SENT
    assert [kind for _key, kind in transport.sent] == [
        NotificationKind.FAILURE,
        NotificationKind.RECOVERY,
    ]


def test_notification_dispatcher_marks_final_failure_without_storing_exception_text() -> None:
    store = InMemoryObservabilityStore()
    IncidentControl(store=store, clock=lambda: NOW).observe(
        _node(
            FIRST_NODE_ID,
            port=10000,
            runtime_state=NodeState.FAILED,
            health=NodeHealth.UNHEALTHY,
        )
    )
    dispatcher = NotificationDispatcher(
        store=store,
        transport=RecordingNotificationTransport(fail_attempts=10),
        max_attempts=2,
        retry_delay=timedelta(seconds=1),
        clock=lambda: NOW,
    )

    dispatcher.run_once()
    final = dispatcher.run_once(now=NOW + timedelta(seconds=1))

    assert final is not None
    assert final.status is NotificationStatus.FAILED_FINAL
    assert final.attempts == 2
    assert final.last_error_code == "notification_transport_failed"


def test_stale_notification_claim_becomes_terminal_and_cannot_complete() -> None:
    store = InMemoryObservabilityStore()
    IncidentControl(store=store, clock=lambda: NOW).observe(
        _node(
            FIRST_NODE_ID,
            port=10000,
            runtime_state=NodeState.FAILED,
            health=NodeHealth.UNHEALTHY,
        )
    )
    claimed = store.claim_notification(
        now=NOW,
        lease_timeout=timedelta(seconds=30),
    )
    assert claimed is not None and claimed.claim_token is not None

    assert (
        store.claim_notification(
            now=NOW + timedelta(seconds=31),
            lease_timeout=timedelta(seconds=30),
        )
        is None
    )
    with pytest.raises(ValueError, match="notification_not_claimed"):
        store.complete_notification(
            claimed.id,
            claim_token=claimed.claim_token,
            succeeded=True,
            completed_at=NOW + timedelta(seconds=32),
            max_attempts=3,
            retry_delay=timedelta(seconds=1),
        )
    final = store.list_notifications()[0]
    assert final.status is NotificationStatus.FAILED_FINAL
    assert final.attempts == 1
    assert final.last_error_code == "notification_delivery_ambiguous"


class RecordingSmtpClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []
        self.final_reply: tuple[int, bytes] = (250, b"queued")

    @property
    def sock(self) -> RecordingSmtpClient:
        return self

    def settimeout(self, value: float | None) -> None:
        self.calls.append(("timeout", value))

    def ehlo(self) -> None:
        self.calls.append(("ehlo", None))

    def starttls(self, *, context: ssl.SSLContext) -> None:
        assert context.verify_mode is ssl.CERT_REQUIRED
        assert context.check_hostname
        self.calls.append(("starttls", context))

    def login(self, username: str, password: str) -> None:
        self.calls.append(("login", (username, password)))

    def mail(self, sender: str) -> tuple[int, bytes]:
        self.calls.append(("mail", sender))
        return 250, b"ok"

    def rcpt(self, recipient: str) -> tuple[int, bytes]:
        self.calls.append(("rcpt", recipient))
        return 250, b"ok"

    def docmd(self, command: str, args: str = "") -> tuple[int, bytes]:
        self.calls.append(("docmd", (command, args)))
        return 354, b"continue"

    def send(self, payload: str | bytes) -> None:
        self.calls.append(("send", payload))

    def getreply(self) -> tuple[int, bytes]:
        self.calls.append(("reply", None))
        return self.final_reply

    def __enter__(self) -> RecordingSmtpClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None


class TeardownFailureSmtpClient(RecordingSmtpClient):
    def __enter__(self) -> TeardownFailureSmtpClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        raise smtplib.SMTPResponseException(500, b"quit failed")


def test_smtp_transport_uses_stable_message_id_and_safe_incident_content(
    tmp_path: Path,
) -> None:
    password_file = tmp_path / "smtp-password"
    password_file.write_text("smtp-secret\n", encoding="utf-8")
    password_file.chmod(0o600)
    client = RecordingSmtpClient()
    transport = SmtpNotificationTransport(
        host="smtp.example.test",
        port=587,
        username="mailer",
        password_file=password_file,
        from_address="rtsp-proxy@example.test",
        to_address="operator@example.test",
        starttls=True,
        trusted_password_owner_uid=os.getuid(),
        client_factory=lambda _host, _port, _timeout: client,
    )
    message = NotificationMessage(
        id=UUID("40000000-0000-0000-0000-000000000004"),
        incident_id=UUID("30000000-0000-0000-0000-000000000003"),
        node_id=FIRST_NODE_ID,
        kind=NotificationKind.FAILURE,
        dedupe_key=(
            "node-incident:30000000-0000-0000-0000-000000000003:failure"
        ),
        status=NotificationStatus.PROCESSING,
        attempts=0,
        available_at=NOW,
    )

    transport.send(message)

    assert [name for name, _value in client.calls if name != "timeout"] == [
        "ehlo",
        "starttls",
        "ehlo",
        "login",
        "mail",
        "rcpt",
        "docmd",
        "send",
        "reply",
    ]
    email = next(value for name, value in client.calls if name == "send")
    assert isinstance(email, str)
    assert "From: rtsp-proxy@example.test" in email
    assert "To: operator@example.test" in email
    assert "Message-ID:" in email
    assert (
        "<node-incident.30000000-0000-0000-0000-000000000003.failure@rtsp-proxy>"
    ) in email
    assert str(FIRST_NODE_ID) in email
    assert "failure" in email
    assert "smtp-secret" not in email
    assert "rtsp://" not in email


def test_smtp_data_disconnect_is_terminal_and_never_retried(tmp_path: Path) -> None:
    class AmbiguousSmtpClient(RecordingSmtpClient):
        def __enter__(self) -> AmbiguousSmtpClient:
            return self

        def getreply(self) -> tuple[int, bytes]:
            self.calls.append(("reply", None))
            raise OSError("relay-may-have-accepted-data")

    password_file = tmp_path / "smtp-password-ambiguous"
    password_file.write_text("secret\n", encoding="utf-8")
    password_file.chmod(0o600)
    store = InMemoryObservabilityStore()
    IncidentControl(store=store, clock=lambda: NOW).observe(
        _node(
            FIRST_NODE_ID,
            port=10000,
            runtime_state=NodeState.FAILED,
            health=NodeHealth.UNHEALTHY,
        )
    )
    transport = SmtpNotificationTransport(
        host="smtp.example.test",
        port=587,
        username="mailer",
        password_file=password_file,
        from_address="rtsp-proxy@example.test",
        to_address="operator@example.test",
        starttls=True,
        trusted_password_owner_uid=os.getuid(),
        client_factory=lambda _host, _port, _timeout: AmbiguousSmtpClient(),
    )
    dispatcher = NotificationDispatcher(
        store=store,
        transport=transport,
        retry_delay=timedelta(seconds=1),
        clock=lambda: NOW,
    )

    completed = dispatcher.run_once()

    assert completed is not None
    assert completed.status is NotificationStatus.FAILED_FINAL
    assert completed.last_error_code == "notification_delivery_ambiguous"
    assert dispatcher.run_once(now=NOW + timedelta(minutes=1)) is None


def test_dispatcher_rejects_a_store_claim_without_lease_token() -> None:
    class InvalidClaimStore(InMemoryObservabilityStore):
        def claim_notification(
            self,
            *,
            now: datetime,
            lease_timeout: timedelta,
        ) -> NotificationMessage | None:
            del lease_timeout
            return NotificationMessage(
                id=uuid4(),
                incident_id=uuid4(),
                node_id=FIRST_NODE_ID,
                kind=NotificationKind.FAILURE,
                dedupe_key=f"node-incident:{uuid4()}:failure",
                status=NotificationStatus.PROCESSING,
                attempts=1,
                available_at=now,
            )

    with pytest.raises(ValueError, match="notification_claim_invalid"):
        NotificationDispatcher(
            store=InvalidClaimStore(),
            transport=RecordingNotificationTransport(),
        ).run_once(now=NOW)


def test_explicit_smtp_data_rejection_uses_bounded_retry(tmp_path: Path) -> None:
    class RejectedSmtpClient(RecordingSmtpClient):
        def __enter__(self) -> RejectedSmtpClient:
            return self

        def docmd(self, command: str, args: str = "") -> tuple[int, bytes]:
            self.calls.append(("docmd", (command, args)))
            return 451, b"try later"


    password_file = tmp_path / "smtp-password-rejected"
    password_file.write_text("secret\n", encoding="utf-8")
    password_file.chmod(0o600)
    store = InMemoryObservabilityStore()
    IncidentControl(store=store, clock=lambda: NOW).observe(
        _node(
            FIRST_NODE_ID,
            port=10000,
            runtime_state=NodeState.FAILED,
            health=NodeHealth.UNHEALTHY,
        )
    )
    dispatcher = NotificationDispatcher(
        store=store,
        transport=SmtpNotificationTransport(
            host="smtp.example.test",
            port=587,
            username="mailer",
            password_file=password_file,
            from_address="rtsp-proxy@example.test",
            to_address="operator@example.test",
            starttls=True,
            trusted_password_owner_uid=os.getuid(),
            client_factory=lambda _host, _port, _timeout: RejectedSmtpClient(),
        ),
        max_attempts=2,
        retry_delay=timedelta(seconds=1),
        clock=lambda: NOW,
    )

    first = dispatcher.run_once()
    final = dispatcher.run_once(now=NOW + timedelta(seconds=1))

    assert first is not None and first.status is NotificationStatus.PENDING
    assert first.last_error_code == "notification_transport_failed"
    assert final is not None and final.status is NotificationStatus.FAILED_FINAL
    assert final.last_error_code == "notification_transport_failed"


def test_final_smtp_data_rejection_is_retryable(tmp_path: Path) -> None:
    client = RecordingSmtpClient()
    client.final_reply = (451, b"not accepted")
    password_file = tmp_path / "smtp-password-final-rejection"
    password_file.write_text("secret\n", encoding="utf-8")
    password_file.chmod(0o600)
    transport = SmtpNotificationTransport(
        host="smtp.example.test",
        port=587,
        username="mailer",
        password_file=password_file,
        from_address="rtsp-proxy@example.test",
        to_address="operator@example.test",
        starttls=True,
        trusted_password_owner_uid=os.getuid(),
        client_factory=lambda _host, _port, _timeout: client,
    )

    with pytest.raises(smtplib.SMTPDataError):
        transport.send(
            NotificationMessage(
                id=uuid4(),
                incident_id=uuid4(),
                node_id=FIRST_NODE_ID,
                kind=NotificationKind.FAILURE,
                dedupe_key=f"node-incident:{uuid4()}:failure",
                status=NotificationStatus.PROCESSING,
                attempts=1,
                available_at=NOW,
            )
        )


def test_smtp_success_ignores_quit_failure_after_relay_acceptance(tmp_path: Path) -> None:
    password_file = tmp_path / "smtp-password-teardown"
    password_file.write_text("secret\n", encoding="utf-8")
    password_file.chmod(0o600)
    transport = SmtpNotificationTransport(
        host="smtp.example.test",
        port=587,
        username="mailer",
        password_file=password_file,
        from_address="rtsp-proxy@example.test",
        to_address="operator@example.test",
        starttls=True,
        trusted_password_owner_uid=os.getuid(),
        client_factory=lambda _host, _port, _timeout: TeardownFailureSmtpClient(),
    )

    transport.send(
        NotificationMessage(
            id=uuid4(),
            incident_id=uuid4(),
            node_id=FIRST_NODE_ID,
            kind=NotificationKind.FAILURE,
            dedupe_key=f"node-incident:{uuid4()}:failure",
            status=NotificationStatus.PROCESSING,
            attempts=1,
            available_at=NOW,
        )
    )


def test_notification_retry_deadline_starts_after_transport_completion() -> None:
    store = InMemoryObservabilityStore()
    IncidentControl(store=store, clock=lambda: NOW).observe(
        _node(
            FIRST_NODE_ID,
            port=10000,
            runtime_state=NodeState.FAILED,
            health=NodeHealth.UNHEALTHY,
        )
    )
    times = iter((NOW, NOW + timedelta(seconds=30)))
    completed = NotificationDispatcher(
        store=store,
        transport=RecordingNotificationTransport(fail_attempts=1),
        retry_delay=timedelta(seconds=10),
        clock=lambda: next(times),
    ).run_once()

    assert completed is not None
    assert completed.available_at == NOW + timedelta(seconds=40)


def test_smtp_transport_requires_verified_tls_and_safe_password_file(tmp_path: Path) -> None:
    password_file = tmp_path / "smtp-password"
    password_file.write_text("secret\n", encoding="utf-8")
    password_file.chmod(0o644)

    with pytest.raises(ValueError, match="smtp_endpoint_invalid"):
        SmtpNotificationTransport(
            host="",
            port=587,
            username="mailer",
            password_file=password_file,
            from_address="rtsp-proxy@example.test",
            to_address="operator@example.test",
            starttls=True,
        )
    with pytest.raises(ValueError, match="smtp_identity_invalid"):
        SmtpNotificationTransport(
            host="smtp.example.test",
            port=587,
            username="",
            password_file=password_file,
            from_address="rtsp-proxy@example.test",
            to_address="operator@example.test",
            starttls=True,
        )
    with pytest.raises(ValueError, match="smtp_configuration_invalid"):
        SmtpNotificationTransport(
            host="smtp.example.test",
            port=587,
            username="mailer",
            password_file=password_file,
            from_address="rtsp-proxy@example.test",
            to_address="operator@example.test",
            starttls=False,
        )

    transport = SmtpNotificationTransport(
        host="smtp.example.test",
        port=587,
        username="mailer",
        password_file=password_file,
        from_address="rtsp-proxy@example.test",
        to_address="operator@example.test",
        starttls=True,
        trusted_password_owner_uid=os.getuid(),
        client_factory=lambda _host, _port, _timeout: RecordingSmtpClient(),
    )
    with pytest.raises(ValueError, match="smtp_password_file_unsafe"):
        transport.send(
            NotificationMessage(
                id=uuid4(),
                incident_id=uuid4(),
                node_id=FIRST_NODE_ID,
                kind=NotificationKind.FAILURE,
                dedupe_key=f"node-incident:{uuid4()}:failure",
                status=NotificationStatus.PROCESSING,
                attempts=1,
                available_at=NOW,
            )
        )


def test_smtp_transport_enforces_one_overall_deadline(tmp_path: Path) -> None:
    password_file = tmp_path / "smtp-password-deadline"
    password_file.write_text("secret\n", encoding="utf-8")
    password_file.chmod(0o600)
    ticks = iter((0.0, 0.1, 0.2, 0.3, 2.0))
    transport = SmtpNotificationTransport(
        host="smtp.example.test",
        port=587,
        username="mailer",
        password_file=password_file,
        from_address="rtsp-proxy@example.test",
        to_address="operator@example.test",
        starttls=True,
        timeout_seconds=1,
        trusted_password_owner_uid=os.getuid(),
        client_factory=lambda _host, _port, _timeout: RecordingSmtpClient(),
        monotonic_clock=lambda: next(ticks),
    )

    with pytest.raises(TimeoutError, match="smtp_delivery_timeout"):
        transport.send(
            NotificationMessage(
                id=uuid4(),
                incident_id=uuid4(),
                node_id=FIRST_NODE_ID,
                kind=NotificationKind.FAILURE,
                dedupe_key=f"node-incident:{uuid4()}:failure",
                status=NotificationStatus.PROCESSING,
                attempts=1,
                available_at=NOW,
            )
        )
