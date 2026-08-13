from __future__ import annotations

import math
import os
import re
import smtplib
import socket
import ssl
import stat
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor, wait
from contextlib import suppress
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from enum import StrEnum
from pathlib import Path
from threading import RLock
from time import monotonic
from typing import Protocol, Self, cast
from uuid import UUID, uuid4

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection, RowMapping

from rtsp_proxy.identifiers import InvalidPublicId, PublicId
from rtsp_proxy.nodes import MediaNode, NodeHealth, NodeState

_METRIC_LINE = re.compile(
    rb"^(?P<name>[a-z_]+)(?:\{(?P<labels>[^{}]{1,1024})\})? "
    rb"(?P<value>0|[1-9][0-9]*)$"
)
_METRIC_LABEL = re.compile(rb'(?:^|,)([A-Za-z][A-Za-z0-9]*)="([^"\\]*)"')
_PATH_METRICS = frozenset(
    {
        "paths",
        "paths_readers",
        "paths_inbound_bytes",
        "paths_outbound_bytes",
    }
)
_MAX_METRICS_BYTES = 1_048_576


class IncidentState(StrEnum):
    OPEN = "open"
    RECOVERED = "recovered"
    CLOSED = "closed"


class NotificationKind(StrEnum):
    FAILURE = "failure"
    RECOVERY = "recovery"


class NotificationStatus(StrEnum):
    PENDING = "pending"
    PROCESSING = "processing"
    SENT = "sent"
    FAILED_FINAL = "failed_final"


class NodeScrapeStatus(StrEnum):
    FRESH = "fresh"
    IDLE = "idle"
    STALE = "stale"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True, order=True)
class PathMetricCounters:
    public_id: str
    received_bytes_total: int
    sent_bytes_total: int

    def __post_init__(self) -> None:
        try:
            PublicId.parse(self.public_id)
        except InvalidPublicId:
            raise ValueError("path_metric_public_id_invalid") from None
        if self.received_bytes_total < 0 or self.sent_bytes_total < 0:
            raise ValueError("path_metric_counter_invalid")


@dataclass(frozen=True, slots=True)
class NodeMetricSample:
    active_sources: int
    occupied_streams: int
    received_bytes_total: int
    sent_bytes_total: int
    path_counters: tuple[PathMetricCounters, ...] = ()

    def __post_init__(self) -> None:
        if not 0 <= self.active_sources <= 100:
            raise ValueError("active_sources_invalid")
        if not 0 <= self.occupied_streams <= 100:
            raise ValueError("occupied_streams_invalid")
        if self.received_bytes_total < 0 or self.sent_bytes_total < 0:
            raise ValueError("byte_counter_invalid")
        if len(self.path_counters) > 100 or tuple(sorted(self.path_counters)) != (
            self.path_counters
        ):
            raise ValueError("path_metric_counters_invalid")
        if len({counter.public_id for counter in self.path_counters}) != len(
            self.path_counters
        ):
            raise ValueError("path_metric_counters_invalid")
        if self.path_counters and (
            sum(counter.received_bytes_total for counter in self.path_counters)
            != self.received_bytes_total
            or sum(counter.sent_bytes_total for counter in self.path_counters)
            != self.sent_bytes_total
        ):
            raise ValueError("path_metric_aggregate_invalid")


@dataclass(frozen=True, slots=True)
class NodeMetricObservation:
    sample: NodeMetricSample
    process_id: int
    process_start_ticks: int
    process_boot_id: UUID
    release_id: str

    def __post_init__(self) -> None:
        if self.process_id < 1 or self.process_start_ticks < 1 or not self.release_id:
            raise ValueError("node_metric_process_identity_invalid")


@dataclass(frozen=True, slots=True)
class NodeSnapshot:
    node_id: UUID
    name: str
    external_port: int
    desired_state: NodeState
    runtime_state: NodeState
    health: NodeHealth
    registered_cameras: int
    camera_capacity: int
    desired_revision: int
    applied_revision: int
    scrape_status: NodeScrapeStatus
    scrape_reason: str | None
    metrics: NodeMetricSample | None
    metric_observed_at: datetime | None = None
    received_bitrate_bps: float | None = None
    sent_bitrate_bps: float | None = None
    counters_reset: bool = False


@dataclass(frozen=True, slots=True)
class FleetSnapshot:
    generated_at: datetime
    configured_nodes: int
    max_nodes: int
    registered_cameras: int
    external_ports_used: int
    external_ports_free: int
    nodes: tuple[NodeSnapshot, ...]

    def __post_init__(self) -> None:
        if self.generated_at.tzinfo is None:
            raise ValueError("snapshot_timezone_required")
        if self.configured_nodes != len(self.nodes):
            raise ValueError("snapshot_node_count_invalid")
        if not 0 <= self.configured_nodes <= self.max_nodes <= 100:
            raise ValueError("snapshot_node_capacity_invalid")
        if self.external_ports_used != self.configured_nodes:
            raise ValueError("snapshot_port_count_invalid")
        if self.external_ports_free < 0:
            raise ValueError("snapshot_port_capacity_invalid")


@dataclass(frozen=True, slots=True)
class NotificationIncident:
    id: UUID
    node_id: UUID
    state: IncidentState
    opened_at: datetime
    recovered_at: datetime | None = None
    closed_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class NotificationMessage:
    id: UUID
    incident_id: UUID
    node_id: UUID
    kind: NotificationKind
    dedupe_key: str
    status: NotificationStatus
    attempts: int
    available_at: datetime
    last_error_code: str | None = None
    claim_token: UUID | None = None
    claimed_at: datetime | None = None
    failure_delivery_outcome: NotificationStatus | None = None


class NotificationTransport(Protocol):
    def send(self, message: NotificationMessage) -> None: ...


class NotificationDeliveryAmbiguous(RuntimeError):
    """The SMTP DATA command may have been accepted by the relay."""


class SmtpSocket(Protocol):
    def settimeout(self, value: float | None) -> None: ...


class SmtpClient(Protocol):
    @property
    def sock(self) -> SmtpSocket | socket.socket | None: ...

    def __enter__(self) -> Self: ...

    def __exit__(self, *exc_info: object) -> None: ...

    def ehlo(self) -> object: ...

    def starttls(self, *, context: ssl.SSLContext) -> object: ...

    def login(self, username: str, password: str) -> object: ...

    def mail(self, sender: str) -> tuple[int, bytes]: ...

    def rcpt(self, recipient: str) -> tuple[int, bytes]: ...

    def docmd(self, command: str, args: str = ...) -> tuple[int, bytes]: ...

    def send(self, payload: str | bytes) -> None: ...

    def getreply(self) -> tuple[int, bytes]: ...


class SmtpNotificationTransport:
    def __init__(
        self,
        *,
        host: str,
        port: int,
        username: str,
        password_file: Path,
        from_address: str,
        to_address: str,
        starttls: bool,
        ca_file: Path | None = None,
        timeout_seconds: float = 10,
        trusted_password_owner_uid: int = 0,
        client_factory: Callable[[str, int, float], SmtpClient] | None = None,
        monotonic_clock: Callable[[], float] = monotonic,
    ) -> None:
        if not host or not 1 <= port <= 65535:
            raise ValueError("smtp_endpoint_invalid")
        if not username or "@" not in from_address or "@" not in to_address:
            raise ValueError("smtp_identity_invalid")
        if (
            not starttls
            or not password_file.is_absolute()
            or not 0 < timeout_seconds <= 30
            or trusted_password_owner_uid < 0
        ):
            raise ValueError("smtp_configuration_invalid")
        self._host = host
        self._port = port
        self._username = username
        self._password_file = password_file
        self._from_address = from_address
        self._to_address = to_address
        self._starttls = starttls
        self._ca_file = ca_file
        self._timeout_seconds = timeout_seconds
        self._trusted_password_owner_uid = trusted_password_owner_uid
        self._client_factory = (
            cast(Callable[[str, int, float], SmtpClient], smtplib.SMTP)
            if client_factory is None
            else client_factory
        )
        self._monotonic = monotonic_clock

    def send(self, message: NotificationMessage) -> None:
        password = _read_smtp_password(
            self._password_file,
            trusted_owner_uid=self._trusted_password_owner_uid,
        )
        email = EmailMessage()
        email["From"] = self._from_address
        email["To"] = self._to_address
        email["Subject"] = (
            "RTSP Proxy: node failure"
            if message.kind is NotificationKind.FAILURE
            else "RTSP Proxy: node recovered"
        )
        email["Message-ID"] = (
            f"<node-incident.{message.incident_id}.{message.kind.value}@rtsp-proxy>"
        )
        email["X-RTSP-Proxy-Dedupe-Key"] = message.dedupe_key
        failure_outcome = (
            "unknown"
            if message.failure_delivery_outcome is None
            else message.failure_delivery_outcome.value
        )
        email.set_content(
            "RTSP Proxy node incident\n"
            f"node_id: {message.node_id}\n"
            f"event: {message.kind.value}\n"
            f"incident_id: {message.incident_id}\n"
            + (
                ""
                if message.kind is NotificationKind.FAILURE
                else f"failure_delivery: {failure_outcome}\n"
            )
        )
        tls_context = ssl.create_default_context(
            cafile=(None if self._ca_file is None else str(self._ca_file))
        )
        deadline = self._monotonic() + self._timeout_seconds
        accepted = False
        try:
            with self._client_factory(
                self._host,
                self._port,
                self._remaining_timeout(deadline),
            ) as client:
                self._apply_timeout(client, deadline)
                client.ehlo()
                self._apply_timeout(client, deadline)
                client.starttls(context=tls_context)
                self._apply_timeout(client, deadline)
                client.ehlo()
                self._apply_timeout(client, deadline)
                client.login(self._username, password)
                self._apply_timeout(client, deadline)
                mail_code, mail_response = client.mail(self._from_address)
                if not 200 <= mail_code < 300:
                    raise smtplib.SMTPResponseException(mail_code, mail_response)
                self._apply_timeout(client, deadline)
                recipient_code, recipient_response = client.rcpt(self._to_address)
                if not 200 <= recipient_code < 300:
                    raise smtplib.SMTPResponseException(
                        recipient_code, recipient_response
                    )
                self._apply_timeout(client, deadline)
                data_ready_code, data_ready_response = client.docmd("DATA")
                if data_ready_code != 354:
                    raise smtplib.SMTPDataError(data_ready_code, data_ready_response)
                wire_message = smtplib.quotedata(email.as_string())
                if not wire_message.endswith("\r\n"):
                    wire_message += "\r\n"
                try:
                    self._apply_timeout(client, deadline)
                    client.send(wire_message + ".\r\n")
                    self._apply_timeout(client, deadline)
                    data_code, data_response = client.getreply()
                except Exception as error:
                    raise NotificationDeliveryAmbiguous(
                        "notification_delivery_ambiguous"
                    ) from error
                if not 200 <= data_code < 300:
                    raise smtplib.SMTPDataError(data_code, data_response)
                accepted = True
        except Exception:
            if accepted:
                return
            raise

    def _remaining_timeout(self, deadline: float) -> float:
        remaining = deadline - self._monotonic()
        if remaining <= 0:
            raise TimeoutError("smtp_delivery_timeout")
        return remaining

    def _apply_timeout(self, client: SmtpClient, deadline: float) -> None:
        remaining = self._remaining_timeout(deadline)
        if client.sock is None:
            raise OSError("smtp_socket_unavailable")
        client.sock.settimeout(remaining)


def _read_smtp_password(path: Path, *, trusted_owner_uid: int) -> str:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
        file_stat = os.fstat(descriptor)
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or file_stat.st_uid != trusted_owner_uid
            or file_stat.st_nlink != 1
            or stat.S_IMODE(file_stat.st_mode) not in {0o400, 0o600}
        ):
            raise ValueError
        payload = os.read(descriptor, 4097)
        if len(payload) > 4096:
            raise ValueError
        password = payload.decode("utf-8").rstrip("\n")
        if not password or "\n" in password or len(password) > 4096:
            raise ValueError
        return password
    except (OSError, UnicodeError, ValueError):
        raise ValueError("smtp_password_file_unsafe") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


class IncidentStore(Protocol):
    def observe_incident(
        self,
        node: MediaNode,
        *,
        observed_at: datetime,
    ) -> NotificationIncident | None: ...

    def claim_notification(
        self,
        *,
        now: datetime,
        lease_timeout: timedelta,
    ) -> NotificationMessage | None: ...

    def complete_notification(
        self,
        notification_id: UUID,
        *,
        claim_token: UUID,
        succeeded: bool,
        completed_at: datetime,
        max_attempts: int,
        retry_delay: timedelta,
        delivery_ambiguous: bool = False,
    ) -> NotificationMessage: ...


class SnapshotStore(Protocol):
    def save_snapshot(self, snapshot: FleetSnapshot) -> None: ...


class SnapshotReader(Protocol):
    def current_snapshot(self) -> FleetSnapshot | None: ...


class NodeCatalog(Protocol):
    def list_nodes(self) -> tuple[MediaNode, ...]: ...


class NodeRuntimeObserver(Protocol):
    def observe_node(self, node_id: UUID) -> MediaNode: ...


class NodeMetricSource(Protocol):
    def scrape(self, node: MediaNode) -> NodeMetricSample | NodeMetricObservation: ...


class IncidentControl:
    def __init__(
        self,
        *,
        store: IncidentStore,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._store = store
        self._clock = clock

    def observe(
        self,
        node: MediaNode,
        *,
        observed_at: datetime | None = None,
    ) -> NotificationIncident | None:
        timestamp = self._clock() if observed_at is None else observed_at
        if timestamp.tzinfo is None:
            raise ValueError("incident_observation_timezone_required")
        return self._store.observe_incident(node, observed_at=timestamp)


class NotificationDispatcher:
    def __init__(
        self,
        *,
        store: IncidentStore,
        transport: NotificationTransport,
        max_attempts: int = 3,
        retry_delay: timedelta = timedelta(minutes=1),
        lease_timeout: timedelta = timedelta(minutes=2),
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if not 1 <= max_attempts <= 10:
            raise ValueError("notification_max_attempts_invalid")
        if retry_delay <= timedelta(0) or lease_timeout <= timedelta(0):
            raise ValueError("notification_timing_invalid")
        self._store = store
        self._transport = transport
        self._max_attempts = max_attempts
        self._retry_delay = retry_delay
        self._lease_timeout = lease_timeout
        self._clock = clock

    def run_once(self, *, now: datetime | None = None) -> NotificationMessage | None:
        claim_time = self._clock() if now is None else now
        notification = self._store.claim_notification(
            now=claim_time,
            lease_timeout=self._lease_timeout,
        )
        if notification is None:
            return None
        if notification.claim_token is None:
            raise ValueError("notification_claim_invalid")
        delivery_ambiguous = False
        try:
            self._transport.send(notification)
        except NotificationDeliveryAmbiguous:
            delivery_ambiguous = True
            succeeded = False
        except Exception:
            succeeded = False
        else:
            succeeded = True
        completed_at = self._clock() if now is None else now
        return self._store.complete_notification(
            notification.id,
            claim_token=notification.claim_token,
            succeeded=succeeded,
            completed_at=completed_at,
            max_attempts=self._max_attempts,
            retry_delay=self._retry_delay,
            delivery_ambiguous=delivery_ambiguous,
        )


class FleetCollector:
    def __init__(
        self,
        *,
        nodes: NodeCatalog,
        runtime: NodeRuntimeObserver | None = None,
        metrics: NodeMetricSource,
        observations: SnapshotStore,
        incidents: IncidentControl,
        max_nodes: int,
        external_port_capacity: int,
        workers: int = 8,
        cancelled: Callable[[], bool] = lambda: False,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        monotonic_clock: Callable[[], float] = monotonic,
        collection_interval_seconds: float = 5,
        cycle_timeout_seconds: float | None = None,
    ) -> None:
        if not 1 <= max_nodes <= 100:
            raise ValueError("max_nodes_invalid")
        if external_port_capacity < max_nodes:
            raise ValueError("external_port_capacity_invalid")
        if not 1 <= workers <= 16:
            raise ValueError("collector_workers_invalid")
        if collection_interval_seconds <= 0:
            raise ValueError("collector_interval_invalid")
        if cycle_timeout_seconds is not None and cycle_timeout_seconds <= 0:
            raise ValueError("collector_cycle_timeout_invalid")
        self._nodes = nodes
        self._runtime = runtime
        self._metrics = metrics
        self._observations = observations
        self._incidents = incidents
        self._max_nodes = max_nodes
        self._external_port_capacity = external_port_capacity
        self._workers = workers
        self._cancelled = cancelled
        self._clock = clock
        self._monotonic_clock = monotonic_clock
        self._collection_interval_seconds = collection_interval_seconds
        self._cycle_timeout_seconds = (
            collection_interval_seconds
            if cycle_timeout_seconds is None
            else cycle_timeout_seconds
        )
        self._metric_history: dict[
            UUID,
            tuple[tuple[object, ...], float, datetime, NodeMetricSample],
        ] = {}
        self._history_lock = RLock()
        self._catalog_cursor = 0
        self._executor = ThreadPoolExecutor(
            max_workers=self._workers,
            thread_name_prefix="fleet-node",
        )
        self._inflight: dict[UUID, Future[NodeSnapshot]] = {}

    def close(self) -> None:
        self._executor.shutdown(wait=True, cancel_futures=True)

    def run_once(self) -> FleetSnapshot:
        cycle_started_at = self._clock()
        if cycle_started_at.tzinfo is None:
            raise ValueError("snapshot_timezone_required")
        deadline = self._monotonic_clock() + self._cycle_timeout_seconds
        catalog = tuple(sorted(self._nodes.list_nodes(), key=lambda node: node.id.int))
        node_snapshots: list[NodeSnapshot] = []
        if self._cancelled():
            return self._empty_cancelled_snapshot(cycle_started_at)
        if catalog:
            cursor = self._catalog_cursor % len(catalog)
            catalog = catalog[cursor:] + catalog[:cursor]
            self._catalog_cursor = (cursor + self._workers) % len(catalog)
        futures: dict[Future[NodeSnapshot], MediaNode] = {}
        for node in catalog:
            prior = self._inflight.get(node.id)
            if prior is not None and prior.done():
                with suppress(Exception):
                    prior.result()
                self._inflight.pop(node.id, None)
                prior = None
            if prior is not None:
                node_snapshots.append(
                    self._unavailable_snapshot(
                        node,
                        reason="node_collection_deadline",
                    )
                )
                continue
            future = self._executor.submit(self._collect_node, node, deadline)
            self._inflight[node.id] = future
            futures[future] = node
        remaining = max(0.0, deadline - self._monotonic_clock())
        completed, overdue = wait(tuple(futures), timeout=remaining)
        for future in completed:
            node = futures[future]
            self._inflight.pop(node.id, None)
            try:
                node_snapshots.append(future.result())
            except Exception:
                node_snapshots.append(
                    self._unavailable_snapshot(node, reason="node_collection_failed")
                )
        for future in overdue:
            node = futures[future]
            if future.cancel():
                self._inflight.pop(node.id, None)
            node_snapshots.append(
                self._unavailable_snapshot(
                    node,
                    reason=(
                        "node_collection_cancelled"
                        if self._cancelled()
                        else "node_collection_deadline"
                    ),
                )
            )
        observed_ids = {node.node_id for node in node_snapshots}
        node_snapshots.extend(
            self._unavailable_snapshot(node, reason="node_collection_cancelled")
            for node in catalog
            if node.id not in observed_ids
        )
        node_snapshots.sort(key=lambda node: node.node_id.int)
        generated_at = self._clock()
        if generated_at.tzinfo is None:
            raise ValueError("snapshot_timezone_required")
        snapshot = FleetSnapshot(
            generated_at=generated_at,
            configured_nodes=len(node_snapshots),
            max_nodes=self._max_nodes,
            registered_cameras=sum(node.registered_cameras for node in node_snapshots),
            external_ports_used=len(node_snapshots),
            external_ports_free=self._external_port_capacity - len(node_snapshots),
            nodes=tuple(node_snapshots),
        )
        self._observations.save_snapshot(snapshot)
        return snapshot

    def _collect_node(self, catalog_node: MediaNode, deadline: float) -> NodeSnapshot:
        node = catalog_node
        if self._cancelled() or self._monotonic_clock() >= deadline:
            return self._unavailable_snapshot(node, reason="node_collection_cancelled")
        if self._runtime is not None:
            try:
                node = self._runtime.observe_node(catalog_node.id)
            except Exception:
                return self._unavailable_snapshot(
                    catalog_node,
                    reason="node_runtime_unavailable",
                )
        if self._cancelled() or self._monotonic_clock() >= deadline:
            return self._unavailable_snapshot(node, reason="node_collection_cancelled")
        self._incidents.observe(node, observed_at=self._clock())
        try:
            metric_result = self._metrics.scrape(node)
            if isinstance(metric_result, NodeMetricObservation):
                if _node_process_generation(node) != (
                    metric_result.process_id,
                    metric_result.process_start_ticks,
                    metric_result.process_boot_id,
                    metric_result.release_id,
                ):
                    return self._unavailable_snapshot(
                        node,
                        reason="node_metric_generation_mismatch",
                    )
                metric_sample = metric_result.sample
            else:
                metric_sample = metric_result
        except Exception:
            with self._history_lock:
                previous = self._metric_history.get(node.id)
            if previous is None:
                return self._unavailable_snapshot(node, reason="node_metrics_unavailable")
            return self._node_snapshot(
                node,
                status=NodeScrapeStatus.STALE,
                reason="node_metrics_stale",
                metrics=previous[3],
                metric_observed_at=previous[2],
            )
        if self._cancelled() or self._monotonic_clock() >= deadline:
            return self._unavailable_snapshot(node, reason="node_collection_deadline")
        observed_at = self._clock()
        observed_monotonic = self._monotonic_clock()
        received_bitrate: float | None = None
        sent_bitrate: float | None = None
        counters_reset = False
        with self._history_lock:
            previous = self._metric_history.get(node.id)
            self._metric_history[node.id] = (
                _node_process_generation(node),
                observed_monotonic,
                observed_at,
                metric_sample,
            )
        if previous is not None:
            elapsed = observed_monotonic - previous[1]
            received_delta = metric_sample.received_bytes_total - previous[3].received_bytes_total
            sent_delta = metric_sample.sent_bytes_total - previous[3].sent_bytes_total
            counters_reset = (
                previous[0] != _node_process_generation(node)
                or _path_counters_reset(previous[3], metric_sample)
            )
            if elapsed > self._collection_interval_seconds * 2:
                return self._node_snapshot(
                    node,
                    status=NodeScrapeStatus.STALE,
                    reason="node_metrics_gap",
                    metrics=metric_sample,
                    metric_observed_at=observed_at,
                    counters_reset=counters_reset,
                )
            if elapsed > 0 and not counters_reset:
                received_bitrate = received_delta * 8 / elapsed
                sent_bitrate = sent_delta * 8 / elapsed
        scrape_status = (
            NodeScrapeStatus.IDLE
            if metric_sample.active_sources == 0 and metric_sample.occupied_streams == 0
            else NodeScrapeStatus.FRESH
        )
        return self._node_snapshot(
            node,
            status=scrape_status,
            reason=None,
            metrics=metric_sample,
            metric_observed_at=observed_at,
            received_bitrate_bps=received_bitrate,
            sent_bitrate_bps=sent_bitrate,
            counters_reset=counters_reset,
        )

    @staticmethod
    def _node_snapshot(
        node: MediaNode,
        *,
        status: NodeScrapeStatus,
        reason: str | None,
        metrics: NodeMetricSample | None,
        metric_observed_at: datetime | None = None,
        received_bitrate_bps: float | None = None,
        sent_bitrate_bps: float | None = None,
        counters_reset: bool = False,
    ) -> NodeSnapshot:
        return NodeSnapshot(
            node_id=node.id,
            name=node.name,
            external_port=node.external_port,
            desired_state=node.state,
            runtime_state=node.runtime_state,
            health=node.health,
            registered_cameras=node.registered_cameras,
            camera_capacity=node.camera_capacity,
            desired_revision=node.desired_revision,
            applied_revision=node.applied_revision,
            scrape_status=status,
            scrape_reason=reason,
            metrics=metrics,
            metric_observed_at=metric_observed_at,
            received_bitrate_bps=received_bitrate_bps,
            sent_bitrate_bps=sent_bitrate_bps,
            counters_reset=counters_reset,
        )

    def _unavailable_snapshot(self, node: MediaNode, *, reason: str) -> NodeSnapshot:
        return self._node_snapshot(
            node,
            status=NodeScrapeStatus.UNAVAILABLE,
            reason=reason,
            metrics=None,
        )

    def _empty_cancelled_snapshot(self, generated_at: datetime) -> FleetSnapshot:
        return FleetSnapshot(
            generated_at=generated_at,
            configured_nodes=0,
            max_nodes=self._max_nodes,
            registered_cameras=0,
            external_ports_used=0,
            external_ports_free=self._external_port_capacity,
            nodes=(),
        )


class InMemoryObservabilityStore:
    def __init__(self) -> None:
        self._incidents: list[NotificationIncident] = []
        self._notifications: list[NotificationMessage] = []
        self._snapshot: FleetSnapshot | None = None
        self._lock = RLock()

    def observe_incident(
        self,
        node: MediaNode,
        *,
        observed_at: datetime,
    ) -> NotificationIncident | None:
        with self._lock:
            latest = next(
                (
                    incident
                    for incident in reversed(self._incidents)
                    if incident.node_id == node.id
                ),
                None,
            )
            failed = node.runtime_state is NodeState.FAILED
            recovered = (
                node.runtime_state is NodeState.RUNNING
                and node.health is NodeHealth.HEALTHY
            )
            if failed:
                if latest is not None and latest.state is IncidentState.OPEN:
                    return latest
                incident = NotificationIncident(
                    id=uuid4(),
                    node_id=node.id,
                    state=IncidentState.OPEN,
                    opened_at=observed_at,
                )
                self._incidents.append(incident)
                self._notifications.append(_notification(incident, NotificationKind.FAILURE))
                return incident
            if recovered and latest is not None and latest.state is IncidentState.OPEN:
                incident = NotificationIncident(
                    id=latest.id,
                    node_id=latest.node_id,
                    state=IncidentState.RECOVERED,
                    opened_at=latest.opened_at,
                    recovered_at=observed_at,
                )
                self._incidents[-1] = incident
                self._notifications.append(_notification(incident, NotificationKind.RECOVERY))
                return incident
            return latest

    def list_notifications(self) -> tuple[NotificationMessage, ...]:
        with self._lock:
            return tuple(self._notifications)

    def claim_notification(
        self,
        *,
        now: datetime,
        lease_timeout: timedelta,
    ) -> NotificationMessage | None:
        with self._lock:
            expired_incidents: set[UUID] = set()
            for index, message in enumerate(self._notifications):
                if (
                    message.status is NotificationStatus.PROCESSING
                    and message.claimed_at is not None
                    and message.claimed_at <= now - lease_timeout
                ):
                    self._notifications[index] = NotificationMessage(
                        id=message.id,
                        incident_id=message.incident_id,
                        node_id=message.node_id,
                        kind=message.kind,
                        dedupe_key=message.dedupe_key,
                        status=NotificationStatus.FAILED_FINAL,
                        attempts=message.attempts,
                        available_at=now,
                        last_error_code="notification_delivery_ambiguous",
                    )
                    expired_incidents.add(message.incident_id)
            for incident_id in expired_incidents:
                self._close_incident_if_complete(incident_id, now)
            failure_terminal = {
                message.incident_id
                for message in self._notifications
                if message.kind is NotificationKind.FAILURE
                and message.status
                in {NotificationStatus.SENT, NotificationStatus.FAILED_FINAL}
            }
            for index, message in enumerate(self._notifications):
                due = message.status is NotificationStatus.PENDING and message.available_at <= now
                ordered = (
                    message.kind is NotificationKind.FAILURE
                    or message.incident_id in failure_terminal
                )
                if due and ordered:
                    claim_token = uuid4()
                    claimed = NotificationMessage(
                        id=message.id,
                        incident_id=message.incident_id,
                        node_id=message.node_id,
                        kind=message.kind,
                        dedupe_key=message.dedupe_key,
                        status=NotificationStatus.PROCESSING,
                        attempts=message.attempts + 1,
                        available_at=message.available_at,
                        last_error_code=message.last_error_code,
                        claim_token=claim_token,
                        claimed_at=now,
                        failure_delivery_outcome=(
                            None
                            if message.kind is NotificationKind.FAILURE
                            else next(
                                candidate.status
                                for candidate in self._notifications
                                if candidate.incident_id == message.incident_id
                                and candidate.kind is NotificationKind.FAILURE
                            )
                        ),
                    )
                    self._notifications[index] = claimed
                    return claimed
            return None

    def complete_notification(
        self,
        notification_id: UUID,
        *,
        claim_token: UUID,
        succeeded: bool,
        completed_at: datetime,
        max_attempts: int,
        retry_delay: timedelta,
        delivery_ambiguous: bool = False,
    ) -> NotificationMessage:
        with self._lock:
            index = next(
                (
                    position
                    for position, message in enumerate(self._notifications)
                    if message.id == notification_id
                ),
                None,
            )
            if index is None:
                raise ValueError("notification_not_found")
            current = self._notifications[index]
            if (
                current.status is not NotificationStatus.PROCESSING
                or current.claim_token != claim_token
            ):
                raise ValueError("notification_not_claimed")
            attempts = current.attempts
            status = (
                NotificationStatus.SENT
                if succeeded
                else (
                    NotificationStatus.FAILED_FINAL
                    if delivery_ambiguous or attempts >= max_attempts
                    else NotificationStatus.PENDING
                )
            )
            updated = NotificationMessage(
                id=current.id,
                incident_id=current.incident_id,
                node_id=current.node_id,
                kind=current.kind,
                dedupe_key=current.dedupe_key,
                status=status,
                attempts=attempts,
                available_at=(
                    completed_at
                    if succeeded or status is NotificationStatus.FAILED_FINAL
                    else completed_at + retry_delay
                ),
                last_error_code=(
                    None
                    if succeeded
                    else (
                        "notification_delivery_ambiguous"
                        if delivery_ambiguous
                        else "notification_transport_failed"
                    )
                ),
                failure_delivery_outcome=current.failure_delivery_outcome,
            )
            self._notifications[index] = updated
            self._close_incident_if_complete(updated.incident_id, completed_at)
            return updated

    def _close_incident_if_complete(self, incident_id: UUID, completed_at: datetime) -> None:
        incident_index = next(
            (
                index
                for index, incident in enumerate(self._incidents)
                if incident.id == incident_id
            ),
            None,
        )
        if (
            incident_index is None
            or self._incidents[incident_index].state is not IncidentState.RECOVERED
        ):
            return
        messages = tuple(
            message for message in self._notifications if message.incident_id == incident_id
        )
        if len(messages) != 2 or any(
            message.status not in {NotificationStatus.SENT, NotificationStatus.FAILED_FINAL}
            for message in messages
        ):
            return
        incident = self._incidents[incident_index]
        self._incidents[incident_index] = NotificationIncident(
            id=incident.id,
            node_id=incident.node_id,
            state=IncidentState.CLOSED,
            opened_at=incident.opened_at,
            recovered_at=incident.recovered_at,
            closed_at=completed_at,
        )

    def save_snapshot(self, snapshot: FleetSnapshot) -> None:
        with self._lock:
            self._snapshot = snapshot

    def current_snapshot(self) -> FleetSnapshot | None:
        with self._lock:
            return self._snapshot


class PostgresObservabilityStore:
    def __init__(
        self,
        database_url: str,
        *,
        statement_timeout_ms: int | None = None,
    ) -> None:
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
            pool_timeout=(
                30 if statement_timeout_ms is None else statement_timeout_ms / 1000
            ),
            connect_args=connect_args,
        )

    def close(self) -> None:
        self._engine.dispose()

    def assert_collector_ready(self) -> None:
        with self._engine.connect() as connection:
            capabilities = connection.execute(
                text(
                    "SELECT "
                    "has_table_privilege(session_user, 'public.media_nodes', 'SELECT'), "
                    "has_function_privilege(session_user, "
                    "'public.rtsp_proxy_collector_ready()', 'EXECUTE'), "
                    "has_function_privilege(session_user, "
                    "'public.rtsp_proxy_collector_observe(uuid,boolean,boolean,"
                    "timestamp with time zone,uuid,uuid)', 'EXECUTE'), "
                    "has_function_privilege(session_user, "
                    "'public.rtsp_proxy_collector_save_snapshot("
                    "timestamp with time zone,jsonb)', 'EXECUTE')"
                )
            ).one()
            if not all(capabilities) or connection.scalar(
                text("SELECT rtsp_proxy_collector_ready()")
            ) is not True:
                raise RuntimeError("collector_capability_unavailable")

    def assert_notification_ready(self) -> None:
        with self._engine.connect() as connection:
            capabilities = connection.execute(
                text(
                    "SELECT "
                    "has_function_privilege(session_user, "
                    "'public.rtsp_proxy_notifier_ready()', 'EXECUTE'), "
                    "has_function_privilege(session_user, "
                    "'public.rtsp_proxy_notifier_claim(timestamp with time zone,"
                    "timestamp with time zone,uuid)', 'EXECUTE'), "
                    "has_function_privilege(session_user, "
                    "'public.rtsp_proxy_notifier_complete(uuid,uuid,boolean,"
                    "timestamp with time zone,integer,interval,boolean)', 'EXECUTE')"
                )
            ).one()
            if not all(capabilities) or connection.scalar(
                text("SELECT rtsp_proxy_notifier_ready()")
            ) is not True:
                raise RuntimeError("notification_capability_unavailable")

    def observe_incident(
        self,
        node: MediaNode,
        *,
        observed_at: datetime,
    ) -> NotificationIncident | None:
        with self._engine.begin() as connection:
            row = (
                connection.execute(
                    text(
                        "SELECT * FROM rtsp_proxy_collector_observe("
                        ":node_id, :failed, :recovered, :observed_at, "
                        ":incident_id, :message_id)"
                    ),
                    {
                        "node_id": node.id,
                        "failed": node.runtime_state is NodeState.FAILED,
                        "recovered": (
                            node.runtime_state is NodeState.RUNNING
                            and node.health is NodeHealth.HEALTHY
                        ),
                        "observed_at": observed_at,
                        "incident_id": uuid4(),
                        "message_id": uuid4(),
                    },
                )
                .mappings()
                .one_or_none()
            )
            return None if row is None else _incident_from_row(row)

    def list_notifications(self) -> tuple[NotificationMessage, ...]:
        with self._engine.connect() as connection:
            rows = (
                connection.execute(
                    text(
                        "SELECT id, incident_id, node_id, kind, dedupe_key, status, "
                        "attempts, available_at, last_error_code FROM notification_messages "
                        "ORDER BY created_at, id"
                    )
                )
                .mappings()
                .all()
            )
        return tuple(_notification_from_row(row) for row in rows)

    def claim_notification(
        self,
        *,
        now: datetime,
        lease_timeout: timedelta,
    ) -> NotificationMessage | None:
        lease_expired_at = now - lease_timeout
        with self._engine.begin() as connection:
            claim_token = uuid4()
            row = (
                connection.execute(
                    text(
                        "SELECT * FROM rtsp_proxy_notifier_claim("
                        ":now, :expired, :claim_token)"
                    ),
                    {
                        "now": now,
                        "expired": lease_expired_at,
                        "claim_token": claim_token,
                    },
                )
                .mappings()
                .one_or_none()
            )
        return None if row is None else _notification_from_row(row)

    def complete_notification(
        self,
        notification_id: UUID,
        *,
        claim_token: UUID,
        succeeded: bool,
        completed_at: datetime,
        max_attempts: int,
        retry_delay: timedelta,
        delivery_ambiguous: bool = False,
    ) -> NotificationMessage:
        with self._engine.begin() as connection:
            row = (
                connection.execute(
                    text(
                        "SELECT * FROM rtsp_proxy_notifier_complete("
                        ":id, :claim_token, :succeeded, :completed_at, "
                        ":max_attempts, :retry_delay, :delivery_ambiguous)"
                    ),
                    {
                        "id": notification_id,
                        "claim_token": claim_token,
                        "succeeded": succeeded,
                        "completed_at": completed_at,
                        "max_attempts": max_attempts,
                        "retry_delay": retry_delay,
                        "delivery_ambiguous": delivery_ambiguous,
                    },
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise ValueError("notification_not_claimed")
            return _notification_from_row(row)

    def save_snapshot(self, snapshot: FleetSnapshot) -> None:
        payload = _snapshot_payload(snapshot)
        with self._engine.begin() as connection:
            connection.execute(
                text(
                    "SELECT rtsp_proxy_collector_save_snapshot("
                    ":generated_at, CAST(:payload AS jsonb))"
                ),
                {
                    "generated_at": snapshot.generated_at,
                    "payload": __import__("json").dumps(payload, separators=(",", ":")),
                },
            ).one()

    def current_snapshot(self) -> FleetSnapshot | None:
        with self._engine.connect() as connection:
            row = (
                connection.execute(
                    text("SELECT payload FROM fleet_snapshots WHERE singleton = true")
                )
                .mappings()
                .one_or_none()
            )
        if row is None:
            return None
        payload = row["payload"]
        if not isinstance(payload, dict):
            raise ValueError("fleet_snapshot_invalid")
        try:
            nodes = tuple(
                NodeSnapshot(
                    node_id=UUID(item["node_id"]),
                    name=item["name"],
                    external_port=item["external_port"],
                    desired_state=NodeState(item["desired_state"]),
                    runtime_state=NodeState(item["runtime_state"]),
                    health=NodeHealth(item["health"]),
                    registered_cameras=item["registered_cameras"],
                    camera_capacity=item["camera_capacity"],
                    desired_revision=item["desired_revision"],
                    applied_revision=item["applied_revision"],
                    scrape_status=NodeScrapeStatus(item["scrape_status"]),
                    scrape_reason=item["scrape_reason"],
                    metrics=(
                        None
                        if item["metrics"] is None
                        else NodeMetricSample(**item["metrics"])
                    ),
                    metric_observed_at=(
                        None
                        if item.get("metric_observed_at") is None
                        else datetime.fromisoformat(item["metric_observed_at"])
                    ),
                    received_bitrate_bps=item.get("received_bitrate_bps"),
                    sent_bitrate_bps=item.get("sent_bitrate_bps"),
                    counters_reset=item.get("counters_reset", False),
                )
                for item in payload["nodes"]
            )
            return FleetSnapshot(
                generated_at=datetime.fromisoformat(payload["generated_at"]),
                configured_nodes=payload["configured_nodes"],
                max_nodes=payload["max_nodes"],
                registered_cameras=payload["registered_cameras"],
                external_ports_used=payload["external_ports_used"],
                external_ports_free=payload["external_ports_free"],
                nodes=nodes,
            )
        except (KeyError, TypeError, ValueError):
            raise ValueError("fleet_snapshot_invalid") from None


def _notification(
    incident: NotificationIncident,
    kind: NotificationKind,
) -> NotificationMessage:
    available_at = (
        incident.opened_at
        if kind is NotificationKind.FAILURE
        else incident.recovered_at
    )
    if available_at is None:
        raise ValueError("notification_timestamp_missing")
    return NotificationMessage(
        id=uuid4(),
        incident_id=incident.id,
        node_id=incident.node_id,
        kind=kind,
        dedupe_key=f"node-incident:{incident.id}:{kind.value}",
        status=NotificationStatus.PENDING,
        attempts=0,
        available_at=available_at,
    )


def _insert_notification(connection: Connection, notification: NotificationMessage) -> None:
    connection.execute(
        text(
            "INSERT INTO notification_messages "
            "(id, incident_id, node_id, kind, dedupe_key, status, attempts, available_at) "
            "VALUES (:id, :incident_id, :node_id, :kind, :dedupe_key, :status, "
            ":attempts, :available_at)"
        ),
        {
            "id": notification.id,
            "incident_id": notification.incident_id,
            "node_id": notification.node_id,
            "kind": notification.kind.value,
            "dedupe_key": notification.dedupe_key,
            "status": notification.status.value,
            "attempts": notification.attempts,
            "available_at": notification.available_at,
        },
    )


def _incident_from_row(row: RowMapping) -> NotificationIncident:
    return NotificationIncident(
        id=row["id"],
        node_id=row["node_id"],
        state=IncidentState(row["state"]),
        opened_at=row["opened_at"],
        recovered_at=row["recovered_at"],
        closed_at=row["closed_at"],
    )


def _notification_from_row(row: RowMapping) -> NotificationMessage:
    return NotificationMessage(
        id=row["id"],
        incident_id=row["incident_id"],
        node_id=row["node_id"],
        kind=NotificationKind(row["kind"]),
        dedupe_key=row["dedupe_key"],
        status=NotificationStatus(row["status"]),
        attempts=row["attempts"],
        available_at=row["available_at"],
        last_error_code=row["last_error_code"],
        claim_token=row.get("claim_token"),
        claimed_at=row.get("claimed_at"),
        failure_delivery_outcome=(
            None
            if row.get("failure_delivery_outcome") is None
            else NotificationStatus(row["failure_delivery_outcome"])
        ),
    )


def _snapshot_payload(snapshot: FleetSnapshot) -> dict[str, object]:
    payload = asdict(snapshot)
    payload["generated_at"] = snapshot.generated_at.isoformat()
    for node in payload["nodes"]:
        node["node_id"] = str(node["node_id"])
        node["desired_state"] = node["desired_state"].value
        node["runtime_state"] = node["runtime_state"].value
        node["health"] = node["health"].value
        node["scrape_status"] = node["scrape_status"].value
        if node["metric_observed_at"] is not None:
            node["metric_observed_at"] = node["metric_observed_at"].isoformat()
        if node["metrics"] is not None:
            node["metrics"].pop("path_counters", None)
    return payload


def parse_mediamtx_path_metrics(payload: bytes) -> NodeMetricSample:
    """Reduce pinned MediaMTX path metrics while retaining bounded path baselines."""

    if len(payload) > _MAX_METRICS_BYTES or b"\x00" in payload:
        raise ValueError("node_metrics_invalid")
    seen_paths: dict[PublicId, str] = {}
    readers: dict[PublicId, int] = {}
    inbound: dict[PublicId, int] = {}
    outbound: dict[PublicId, int] = {}
    try:
        for raw_line in payload.splitlines():
            if not raw_line or raw_line.startswith(b"#"):
                continue
            match = _METRIC_LINE.fullmatch(raw_line)
            if match is None:
                raise ValueError
            name = match.group("name").decode("ascii")
            if name not in _PATH_METRICS:
                continue
            value = int(match.group("value"))
            raw_labels = match.group("labels")
            if raw_labels is None:
                if value != 0:
                    raise ValueError
                continue
            label_pairs = _METRIC_LABEL.findall(raw_labels)
            labels = {
                key.decode("ascii"): label.decode("ascii")
                for key, label in label_pairs
            }
            if b",".join(
                b'%s="%s"' % (key, label)
                for key, label in label_pairs
            ) != raw_labels or len(labels) != len(label_pairs):
                raise ValueError
            public_id = PublicId.parse(labels["name"])
            state = labels["state"]
            if state not in {"ready", "notReady"}:
                raise ValueError
            if name == "paths":
                if value != 1 or public_id in seen_paths or set(labels) != {"name", "state"}:
                    raise ValueError
                seen_paths[public_id] = state
            elif name == "paths_readers":
                if (
                    set(labels) != {"name", "state", "readerType"}
                    or value > 1
                    or seen_paths.get(public_id) != state
                ):
                    raise ValueError
                readers[public_id] = readers.get(public_id, 0) + value
                if readers[public_id] > 1:
                    raise ValueError
            elif name == "paths_inbound_bytes":
                if (
                    set(labels) != {"name", "state"}
                    or public_id in inbound
                    or seen_paths.get(public_id) != state
                ):
                    raise ValueError
                inbound[public_id] = value
            else:
                if (
                    set(labels) != {"name", "state"}
                    or public_id in outbound
                    or seen_paths.get(public_id) != state
                ):
                    raise ValueError
                outbound[public_id] = value
        path_ids = set(seen_paths)
        if path_ids != set(readers) or path_ids != set(inbound) or path_ids != set(outbound):
            raise ValueError
        if len(path_ids) > 100:
            raise ValueError
    except (InvalidPublicId, KeyError, UnicodeError, ValueError):
        raise ValueError("node_metrics_invalid") from None
    return NodeMetricSample(
        active_sources=sum(state == "ready" for state in seen_paths.values()),
        occupied_streams=sum(readers.values()),
        received_bytes_total=sum(inbound.values()),
        sent_bytes_total=sum(outbound.values()),
        path_counters=tuple(
            PathMetricCounters(str(public_id), inbound[public_id], outbound[public_id])
            for public_id in sorted(path_ids, key=str)
        ),
    )


def _path_counters_reset(previous: NodeMetricSample, current: NodeMetricSample) -> bool:
    if previous.path_counters or current.path_counters:
        previous_paths = {counter.public_id: counter for counter in previous.path_counters}
        current_paths = {counter.public_id: counter for counter in current.path_counters}
        if previous_paths.keys() != current_paths.keys():
            return True
        return any(
            current_paths[public_id].received_bytes_total
            < previous_paths[public_id].received_bytes_total
            or current_paths[public_id].sent_bytes_total
            < previous_paths[public_id].sent_bytes_total
            for public_id in previous_paths
        )
    return (
        current.received_bytes_total < previous.received_bytes_total
        or current.sent_bytes_total < previous.sent_bytes_total
    )


def _node_process_generation(node: MediaNode) -> tuple[object, ...]:
    return (
        node.process_id,
        node.process_start_ticks,
        node.process_boot_id,
        node.observed_release_id,
    )
