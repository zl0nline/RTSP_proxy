from __future__ import annotations

import asyncio
import threading
from collections.abc import Awaitable, Callable, Coroutine, Iterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from functools import wraps
from typing import Any
from uuid import UUID

import pytest
from fastapi import FastAPI, Request, Response
from starlette.types import Message, Scope

from rtsp_proxy.app import ManagementHstsBoundary
from rtsp_proxy.identifiers import PublicId
from rtsp_proxy.live_updates import (
    CameraLiveEventResponse,
    CameraLiveEventType,
    CameraLiveTarget,
    CameraLiveUpdates,
    LiveStreamLimitReached,
    LiveUpdateUnavailable,
)
from rtsp_proxy.nodes import NodeHealth, NodeState
from rtsp_proxy.observability import (
    FleetSnapshot,
    NodeMetricSample,
    NodeScrapeStatus,
    NodeSnapshot,
    PathMetricCounters,
)

CAMERA_ID = UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
NODE_ID = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
SESSION_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
PUBLIC_ID = PublicId.parse("a" * 25 + "e")
SECOND_CAMERA_ID = UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
SECOND_PUBLIC_ID = PublicId.parse("b" * 25 + "e")
NOW = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)


def async_case(
    function: Callable[[], Coroutine[Any, Any, None]],
) -> Callable[[], None]:
    @wraps(function)
    def run() -> None:
        asyncio.run(function())

    return run


class MutableSnapshotReader:
    def __init__(self, snapshot: FleetSnapshot | None) -> None:
        self.snapshot = snapshot

    def current_snapshot(self) -> FleetSnapshot | None:
        return self.snapshot


class BlockingSnapshotReader:
    def __init__(self, snapshot: FleetSnapshot | None) -> None:
        self.snapshot = snapshot
        self.started = threading.Event()
        self.release = threading.Event()
        self.calls = 0

    def current_snapshot(self) -> FleetSnapshot | None:
        self.calls += 1
        self.started.set()
        if not self.release.wait(timeout=5):
            raise RuntimeError("snapshot_reader_test_timeout")
        return self.snapshot


class MutableAuthorizationEpochs:
    def __init__(self, versions: dict[UUID, int] | None = None) -> None:
        self.versions = {SESSION_ID: 1} if versions is None else versions
        self.calls: list[tuple[UUID, ...]] = []

    def __call__(self, session_ids: tuple[UUID, ...]) -> dict[UUID, int]:
        self.calls.append(session_ids)
        return {
            session_id: self.versions[session_id]
            for session_id in session_ids
            if session_id in self.versions
        }


class BlockingAuthorizationEpochs(MutableAuthorizationEpochs):
    def __init__(self, versions: dict[UUID, int] | None = None) -> None:
        super().__init__(versions)
        self.started = threading.Event()
        self.release = threading.Event()

    def __call__(self, session_ids: tuple[UUID, ...]) -> dict[UUID, int]:
        self.started.set()
        if not self.release.wait(timeout=5):
            raise RuntimeError("authorization_reader_test_timeout")
        return super().__call__(session_ids)


class MutableLiveTargets:
    def __init__(self, targets: dict[UUID, tuple[PublicId, UUID]]) -> None:
        self.targets = targets
        self.calls: list[tuple[UUID, ...]] = []

    def __call__(
        self,
        camera_ids: tuple[UUID, ...],
    ) -> dict[UUID, tuple[PublicId, UUID]]:
        self.calls.append(camera_ids)
        return {
            camera_id: self.targets[camera_id]
            for camera_id in camera_ids
            if camera_id in self.targets
        }


def _updates(
    reader: MutableSnapshotReader | BlockingSnapshotReader,
    *,
    epochs: MutableAuthorizationEpochs | None = None,
    **kwargs: Any,
) -> CameraLiveUpdates:
    return CameraLiveUpdates(
        reader=reader,
        authorize_sessions=epochs or MutableAuthorizationEpochs(),
        **kwargs,
    )


def _snapshot(
    *,
    generated_at: datetime = NOW,
    received_bytes: int = 1_000,
    sent_bytes: int = 2_000,
    occupied: bool = False,
    ready: bool = True,
    received_bitrate: float | None = None,
    sent_bitrate: float | None = None,
    counters_reset: bool = False,
    metric_gap: bool = False,
) -> FleetSnapshot:
    path = PathMetricCounters(
        public_id=str(PUBLIC_ID),
        received_bytes_total=received_bytes,
        sent_bytes_total=sent_bytes,
        ready=ready,
        received_bitrate_bps=received_bitrate,
        sent_bitrate_bps=sent_bitrate,
        counters_reset=counters_reset,
        metric_gap=metric_gap,
    )
    metrics = NodeMetricSample(
        active_sources=int(ready),
        occupied_streams=int(occupied),
        received_bytes_total=received_bytes,
        sent_bytes_total=sent_bytes,
        path_counters=(path,),
        occupied_public_ids=(str(PUBLIC_ID),) if occupied else (),
    )
    return FleetSnapshot(
        generated_at=generated_at,
        configured_nodes=1,
        max_nodes=50,
        registered_cameras=1,
        external_ports_used=1,
        external_ports_free=999,
        nodes=(
            NodeSnapshot(
                node_id=NODE_ID,
                name="edge-1",
                external_port=10543,
                desired_state=NodeState.RUNNING,
                runtime_state=NodeState.RUNNING,
                health=NodeHealth.HEALTHY,
                registered_cameras=1,
                camera_capacity=100,
                desired_revision=2,
                applied_revision=2,
                scrape_status=NodeScrapeStatus.FRESH,
                scrape_reason=None,
                metrics=metrics,
                metric_observed_at=generated_at,
            ),
        ),
    )


def _target() -> CameraLiveTarget:
    return CameraLiveTarget(camera_id=CAMERA_ID, public_id=PUBLIC_ID, node_id=NODE_ID)


def _second_target() -> CameraLiveTarget:
    return CameraLiveTarget(
        camera_id=SECOND_CAMERA_ID,
        public_id=SECOND_PUBLIC_ID,
        node_id=NODE_ID,
    )


@async_case
async def test_live_updates_project_and_coalesce_camera_runtime_state() -> None:
    reader = MutableSnapshotReader(_snapshot())
    epochs = MutableAuthorizationEpochs({SESSION_ID: 7})
    updates = _updates(
        reader,
        epochs=epochs,
        history_size=4,
        subscriber_queue_size=2,
    )
    authorized_versions: list[int] = []

    async def authorize() -> int:
        authorized_versions.append(7)
        return 7

    subscription = await updates.open(
        target=_target(),
        session_id=SESSION_ID,
        authz_version=7,
        authorize=authorize,
    )
    first = await asyncio.wait_for(anext(subscription), timeout=1)

    assert first.event_type is CameraLiveEventType.STATE
    assert first.event_id is not None
    assert first.data == {
        "camera_id": str(CAMERA_ID),
        "counters_reset": False,
        "metric_gap": False,
        "node_id": str(NODE_ID),
        "observed_at": NOW.isoformat(),
        "occupied": False,
        "received_bitrate_bps": None,
        "scrape_status": "fresh",
        "sent_bitrate_bps": None,
        "source_state": "ready",
    }

    await updates.refresh_once()
    assert updates.history_size_for(CAMERA_ID) == 1

    reader.snapshot = _snapshot(
        generated_at=NOW + timedelta(seconds=5),
        received_bytes=2_000,
        sent_bytes=4_000,
        occupied=True,
        received_bitrate=1_600,
        sent_bitrate=3_200,
    )
    await updates.refresh_once()
    changed = await asyncio.wait_for(anext(subscription), timeout=1)

    assert changed.event_id == first.event_id + 1
    assert changed.data["occupied"] is True
    assert changed.data["received_bitrate_bps"] == 1_600.0
    assert changed.data["sent_bitrate_bps"] == 3_200.0
    assert authorized_versions == [7]
    assert epochs.calls == []
    await subscription.aclose()


@async_case
async def test_live_updates_resume_or_require_snapshot_resynchronization() -> None:
    reader = MutableSnapshotReader(_snapshot())
    updates = _updates(reader, history_size=2, subscriber_queue_size=4)

    async def authorize() -> int:
        return 1

    first = await updates.open(
        target=_target(),
        session_id=SESSION_ID,
        authz_version=1,
        authorize=authorize,
    )
    event_one = await anext(first)
    assert event_one.event_id is not None
    await first.aclose()

    for offset in (5, 10):
        reader.snapshot = _snapshot(
            generated_at=NOW + timedelta(seconds=offset),
            received_bytes=1_000 + offset,
            sent_bytes=2_000 + offset,
            occupied=offset == 10,
        )
        await updates.refresh_once()

    resumable = await updates.open(
        target=_target(),
        session_id=SESSION_ID,
        authz_version=1,
        authorize=authorize,
        last_event_id=str(event_one.event_id + 1),
    )
    replay = await anext(resumable)
    assert replay.event_id == event_one.event_id + 2
    await resumable.aclose()

    expired = await updates.open(
        target=_target(),
        session_id=SESSION_ID,
        authz_version=1,
        authorize=authorize,
        last_event_id=str(event_one.event_id),
    )
    resync = await anext(expired)
    assert resync.event_type is CameraLiveEventType.RESYNC_REQUIRED
    assert resync.data == {"reason": "history_gap"}
    await expired.aclose()
    diagnostics = updates.diagnostics()
    assert diagnostics.resume_requests_total == 2
    assert diagnostics.resync_required_total == 1


@async_case
async def test_live_updates_revalidate_authz_and_bound_one_stream_per_session() -> None:
    reader = MutableSnapshotReader(_snapshot())
    epochs = MutableAuthorizationEpochs({SESSION_ID: 3})
    updates = _updates(
        reader,
        epochs=epochs,
        heartbeat_seconds=0.01,
        reauthorize_seconds=0.01,
    )
    async def authorize() -> int:
        return 3

    subscription = await updates.open(
        target=_target(),
        session_id=SESSION_ID,
        authz_version=3,
        authorize=authorize,
    )
    await anext(subscription)
    with pytest.raises(LiveStreamLimitReached, match="live_stream_session_limit"):
        await updates.open(
            target=_target(),
            session_id=SESSION_ID,
            authz_version=3,
            authorize=authorize,
        )

    heartbeat = await asyncio.wait_for(anext(subscription), timeout=1)
    assert heartbeat.event_type is CameraLiveEventType.HEARTBEAT
    assert heartbeat.data == {"authz_version": 3}

    epochs.versions[SESSION_ID] = 4
    authz_event = await asyncio.wait_for(anext(subscription), timeout=1)
    assert authz_event.event_type is CameraLiveEventType.AUTHZ_EPOCH
    assert authz_event.data == {"action": "reauthenticate"}
    with pytest.raises(StopAsyncIteration):
        await anext(subscription)
    assert updates.active_subscriptions == 0
    diagnostics = updates.diagnostics()
    assert diagnostics.rejected_subscriptions_total == 1
    assert diagnostics.authz_disconnects_total == 1


@async_case
async def test_live_updates_disconnect_a_subscriber_whose_bounded_queue_is_full() -> None:
    reader = MutableSnapshotReader(_snapshot())
    updates = _updates(reader, subscriber_queue_size=1)

    async def authorize() -> int:
        return 1

    subscription = await updates.open(
        target=_target(),
        session_id=SESSION_ID,
        authz_version=1,
        authorize=authorize,
    )
    assert updates.active_subscriptions == 1

    reader.snapshot = replace(
        _snapshot(generated_at=NOW + timedelta(seconds=5)),
        nodes=(_snapshot(generated_at=NOW + timedelta(seconds=5)).nodes[0],),
    )
    await updates.refresh_once()

    assert updates.active_subscriptions == 0
    assert subscription.slow_consumer
    assert updates.diagnostics().slow_consumer_disconnects_total == 1
    await subscription.aclose()


def test_live_target_and_last_event_id_are_canonical_and_bounded() -> None:
    reader = MutableSnapshotReader(None)
    updates = _updates(reader)

    with pytest.raises(ValueError, match="live_event_id_invalid"):
        updates.parse_last_event_id("01")
    with pytest.raises(ValueError, match="live_event_id_invalid"):
        updates.parse_last_event_id("9" * 21)
    assert updates.parse_last_event_id(None) is None
    assert updates.parse_last_event_id("42") == 42


@async_case
async def test_live_updates_preserve_exact_per_path_not_ready_state() -> None:
    reader = MutableSnapshotReader(_snapshot(ready=False))
    updates = _updates(reader)

    async def authorize() -> int:
        return 1

    subscription = await updates.open(
        target=_target(),
        session_id=SESSION_ID,
        authz_version=1,
        authorize=authorize,
    )
    event = await anext(subscription)

    assert event.data["source_state"] == "idle"
    assert event.data["occupied"] is False
    await subscription.aclose()


@async_case
async def test_sse_response_bounds_a_stalled_client_write_and_closes_subscription() -> None:
    reader = MutableSnapshotReader(_snapshot())
    updates = _updates(reader)

    async def authorize() -> int:
        return 1

    subscription = await updates.open(
        target=_target(),
        session_id=SESSION_ID,
        authz_version=1,
        authorize=authorize,
    )
    response = CameraLiveEventResponse(subscription, send_timeout_seconds=0.1)
    messages: list[Message] = []

    async def stalled_send(message: Message) -> None:
        messages.append(message)
        if message["type"] == "http.response.body" and message.get("more_body"):
            await asyncio.sleep(60)

    await asyncio.wait_for(response.stream_response(stalled_send), timeout=1)

    assert messages[0]["type"] == "http.response.start"
    assert updates.active_subscriptions == 0


@async_case
async def test_outer_asgi_boundary_bounds_the_actual_sse_socket_send() -> None:
    updates = _updates(MutableSnapshotReader(_snapshot()))

    async def authorize() -> int:
        return 1

    subscription = await updates.open(
        target=_target(),
        session_id=SESSION_ID,
        authz_version=1,
        authorize=authorize,
    )
    application = FastAPI()

    @application.middleware("http")
    async def buffering_middleware(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        return await call_next(request)

    @application.get("/events")
    async def events() -> CameraLiveEventResponse:
        return CameraLiveEventResponse(subscription)

    boundary = ManagementHstsBoundary(application, live_send_timeout_seconds=0.1)
    request_delivered = False

    async def receive() -> Message:
        nonlocal request_delivered
        if not request_delivered:
            request_delivered = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await asyncio.sleep(60)
        return {"type": "http.disconnect"}

    messages: list[Message] = []

    async def stalled_socket_send(message: Message) -> None:
        messages.append(message)
        if message["type"] == "http.response.body" and message.get("more_body"):
            await asyncio.sleep(60)

    scope: Scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "https",
        "path": "/events",
        "raw_path": b"/events",
        "query_string": b"",
        "headers": (),
        "client": ("127.0.0.1", 12345),
        "server": ("127.0.0.1", 443),
        "root_path": "",
    }
    await asyncio.wait_for(boundary(scope, receive, stalled_socket_send), timeout=1)

    assert any(message["type"] == "http.response.body" for message in messages)
    assert updates.active_subscriptions == 0


@async_case
async def test_live_open_cancellation_does_not_leak_subscription_admission() -> None:
    reader = BlockingSnapshotReader(_snapshot())
    updates = _updates(reader, refresh_wait_timeout_seconds=1)

    async def authorize() -> int:
        return 1

    opening = asyncio.create_task(
        updates.open(
            target=_target(),
            session_id=SESSION_ID,
            authz_version=1,
            authorize=authorize,
        )
    )
    assert await asyncio.to_thread(reader.started.wait, 1)
    opening.cancel()
    with pytest.raises(asyncio.CancelledError):
        await opening
    reader.release.set()
    await asyncio.sleep(0)

    assert updates.active_subscriptions == 0


@async_case
async def test_live_refresh_is_single_flight_for_concurrent_requests() -> None:
    reader = BlockingSnapshotReader(_snapshot())
    updates = _updates(reader, refresh_wait_timeout_seconds=1)

    requests = [asyncio.create_task(updates.current(_target())) for _ in range(16)]
    assert await asyncio.to_thread(reader.started.wait, 1)
    reader.release.set()
    events = await asyncio.gather(*requests)

    assert reader.calls == 1
    assert all(event.data["source_state"] == "ready" for event in events)


@async_case
async def test_live_refresh_waiter_has_a_bounded_deadline() -> None:
    reader = BlockingSnapshotReader(_snapshot())
    updates = _updates(reader, refresh_wait_timeout_seconds=0.05)

    with pytest.raises(LiveUpdateUnavailable, match="live_snapshot_refresh_timeout"):
        await updates.current(_target())
    reader.release.set()


@async_case
async def test_live_stop_waits_for_snapshot_worker_before_store_shutdown() -> None:
    reader = BlockingSnapshotReader(_snapshot())
    updates = _updates(reader, poll_interval_seconds=0.01)
    await updates.start()
    assert await asyncio.to_thread(reader.started.wait, 1)

    stopping = asyncio.create_task(updates.stop())
    await asyncio.sleep(0.05)
    assert not stopping.done()

    reader.release.set()
    await asyncio.wait_for(stopping, timeout=1)


@async_case
async def test_live_immediate_stop_cannot_strand_a_pre_dispatch_worker() -> None:
    for _ in range(100):
        updates = _updates(MutableSnapshotReader(_snapshot()), poll_interval_seconds=0.01)
        await updates.start()
        await asyncio.sleep(0)
        await asyncio.wait_for(updates.stop(), timeout=1)


@async_case
async def test_live_stop_waits_for_authorization_worker_before_store_shutdown() -> None:
    epochs = BlockingAuthorizationEpochs({SESSION_ID: 1})
    updates = _updates(
        MutableSnapshotReader(_snapshot()),
        epochs=epochs,
        heartbeat_seconds=0.01,
        reauthorize_seconds=0.01,
    )
    await updates.start()

    async def authorize() -> int:
        return 1

    subscription = await updates.open(
        target=_target(),
        session_id=SESSION_ID,
        authz_version=1,
        authorize=authorize,
    )
    assert (await anext(subscription)).event_type is CameraLiveEventType.STATE
    delivery = asyncio.create_task(anext(subscription))
    assert await asyncio.to_thread(epochs.started.wait, 1)

    stopping = asyncio.create_task(updates.stop())
    await asyncio.sleep(0.05)
    assert not stopping.done()

    epochs.release.set()
    await asyncio.wait_for(stopping, timeout=1)
    with pytest.raises(asyncio.CancelledError):
        await delivery


@async_case
async def test_live_channels_are_indexed_once_and_inactive_channels_expire() -> None:
    first_path = PathMetricCounters(str(PUBLIC_ID), 1_000, 2_000, ready=True)
    second_path = PathMetricCounters(str(SECOND_PUBLIC_ID), 3_000, 4_000, ready=True)

    class CountingPaths(tuple[PathMetricCounters, ...]):
        iterations = 0

        def __iter__(self) -> Iterator[PathMetricCounters]:
            type(self).iterations += 1
            return super().__iter__()

    paths = CountingPaths((first_path, second_path))
    metrics = NodeMetricSample(
        active_sources=2,
        occupied_streams=0,
        received_bytes_total=4_000,
        sent_bytes_total=6_000,
        path_counters=paths,
        occupied_public_ids=(),
    )
    CountingPaths.iterations = 0
    snapshot = replace(
        _snapshot(),
        registered_cameras=2,
        nodes=(replace(_snapshot().nodes[0], registered_cameras=2, metrics=metrics),),
    )
    now = [0.0]
    updates = _updates(
        MutableSnapshotReader(snapshot),
        channel_ttl_seconds=10,
        monotonic=lambda: now[0],
    )

    await asyncio.gather(updates.current(_target()), updates.current(_second_target()))
    assert CountingPaths.iterations == 1
    assert updates.diagnostics().tracked_cameras == 2

    now[0] = 11
    third_target = CameraLiveTarget(
        camera_id=UUID("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"),
        public_id=PublicId.parse("c" * 25 + "e"),
        node_id=NODE_ID,
    )
    await updates.current(third_target)
    assert updates.diagnostics().tracked_cameras == 1


@async_case
async def test_live_authorizes_before_replay_and_before_each_state_delivery() -> None:
    reader = MutableSnapshotReader(_snapshot())
    epochs = MutableAuthorizationEpochs({SESSION_ID: 1})
    now = [0.0]
    updates = _updates(
        reader,
        epochs=epochs,
        reauthorize_seconds=1,
        monotonic=lambda: now[0],
    )
    authz_version = 1
    checks = 0

    async def authorize() -> int:
        nonlocal checks
        checks += 1
        return authz_version

    subscription = await updates.open(
        target=_target(),
        session_id=SESSION_ID,
        authz_version=1,
        authorize=authorize,
    )
    assert checks == 1
    first = await anext(subscription)
    assert first.event_type is CameraLiveEventType.STATE
    assert checks == 1
    assert epochs.calls == []

    reader.snapshot = _snapshot(
        generated_at=NOW + timedelta(seconds=5),
        received_bytes=2_000,
        sent_bytes=4_000,
        occupied=True,
    )
    await updates.refresh_once()
    now[0] = 1.1
    epochs.versions[SESSION_ID] = 2
    terminal = await anext(subscription)
    assert terminal.event_type is CameraLiveEventType.AUTHZ_EPOCH
    assert epochs.calls == [(SESSION_ID,)]
    assert updates.active_subscriptions == 0


@async_case
async def test_live_authorization_epoch_refresh_is_one_batch_for_all_sessions() -> None:
    now = [0.0]
    session_ids = tuple(
        UUID(f"00000000-0000-4000-8000-{index:012d}") for index in range(1, 17)
    )
    epochs = MutableAuthorizationEpochs({session_id: 5 for session_id in session_ids})
    updates = _updates(
        MutableSnapshotReader(_snapshot()),
        epochs=epochs,
        reauthorize_seconds=1,
        monotonic=lambda: now[0],
    )

    async def authorize() -> int:
        return 5

    subscriptions = [
        await updates.open(
            target=_target(),
            session_id=session_id,
            authz_version=5,
            authorize=authorize,
        )
        for session_id in session_ids
    ]
    now[0] = 1.1
    events = await asyncio.gather(*(anext(subscription) for subscription in subscriptions))

    assert all(event.event_type is CameraLiveEventType.STATE for event in events)
    assert epochs.calls == [session_ids]
    await asyncio.gather(*(subscription.aclose() for subscription in subscriptions))


@async_case
async def test_live_projection_does_not_treat_missing_n_minus_one_detail_as_idle() -> None:
    legacy_metrics = NodeMetricSample(
        active_sources=0,
        occupied_streams=0,
        received_bytes_total=0,
        sent_bytes_total=0,
    )
    snapshot = replace(
        _snapshot(),
        nodes=(replace(_snapshot().nodes[0], metrics=legacy_metrics),),
    )
    event = await _updates(MutableSnapshotReader(snapshot)).current(_target())

    assert event.data["source_state"] == "unknown"
    assert event.data["occupied"] is None


@async_case
async def test_live_projection_rejects_path_evidence_from_the_wrong_node() -> None:
    other_node_id = UUID("99999999-9999-4999-8999-999999999999")
    target_node = replace(
        _snapshot().nodes[0],
        metrics=NodeMetricSample(0, 0, 0, 0, occupied_public_ids=()),
    )
    source_node = replace(
        _snapshot().nodes[0],
        node_id=other_node_id,
        name="stale-source-node",
        external_port=10544,
    )
    snapshot = replace(
        _snapshot(),
        configured_nodes=2,
        external_ports_used=2,
        external_ports_free=998,
        nodes=(target_node, source_node),
    )
    event = await _updates(MutableSnapshotReader(snapshot)).current(_target())

    assert event.data["source_state"] == "unavailable"
    assert event.data["node_id"] == str(NODE_ID)
    assert event.data["occupied"] is None


@async_case
async def test_live_refresh_discovers_move_and_starts_new_epoch_for_subscriber() -> None:
    reader = MutableSnapshotReader(_snapshot())
    targets = MutableLiveTargets({CAMERA_ID: (PUBLIC_ID, NODE_ID)})
    updates = _updates(
        reader,
        resolve_targets=targets,
        history_size=4,
        subscriber_queue_size=4,
    )

    async def authorize() -> int:
        return 1

    subscription = await updates.open(
        target=_target(),
        session_id=SESSION_ID,
        authz_version=1,
        authorize=authorize,
    )
    old_state = await anext(subscription)
    assert old_state.data["node_id"] == str(NODE_ID)
    assert old_state.event_id is not None

    reader.snapshot = _snapshot(
        generated_at=NOW + timedelta(seconds=5),
        occupied=True,
    )
    await updates.refresh_once()

    moved_node_id = UUID("99999999-9999-4999-8999-999999999999")
    targets.targets[CAMERA_ID] = (PUBLIC_ID, moved_node_id)
    await updates.refresh_once()

    resync = await anext(subscription)
    projected = await anext(subscription)
    assert resync.event_type is CameraLiveEventType.RESYNC_REQUIRED
    assert resync.data == {"reason": "camera_node_changed"}
    assert projected.event_type is CameraLiveEventType.STATE
    assert projected.data["node_id"] == str(moved_node_id)
    assert projected.data["source_state"] == "unavailable"
    assert targets.calls == [(CAMERA_ID,), (CAMERA_ID,)]

    resumed = await updates.open(
        target=replace(_target(), node_id=moved_node_id),
        session_id=UUID("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"),
        authz_version=1,
        authorize=authorize,
        last_event_id=str(old_state.event_id),
    )
    assert (await anext(resumed)).event_type is CameraLiveEventType.RESYNC_REQUIRED
    await resumed.aclose()
    await subscription.aclose()


@async_case
async def test_live_rate_uses_metric_epoch_and_marks_reset_and_gap() -> None:
    reader = MutableSnapshotReader(_snapshot())
    updates = _updates(reader, metric_interval_seconds=5)

    first = await updates.current(_target())
    assert first.data["counters_reset"] is False
    assert first.data["metric_gap"] is False

    delayed_snapshot = replace(
        _snapshot(
            generated_at=NOW + timedelta(seconds=40),
            received_bytes=2_000,
            sent_bytes=4_000,
        ),
        nodes=(
            replace(
                _snapshot().nodes[0],
                metric_observed_at=NOW + timedelta(seconds=5),
                counters_reset=True,
                metrics=_snapshot(
                    received_bytes=2_000,
                    sent_bytes=4_000,
                    counters_reset=True,
                    metric_gap=True,
                ).nodes[0].metrics,
            ),
        ),
    )
    reader.snapshot = delayed_snapshot
    await updates.refresh_once()
    reset = await updates.current(_target())

    assert reset.data["observed_at"] == (NOW + timedelta(seconds=5)).isoformat()
    assert reset.data["received_bitrate_bps"] is None
    assert reset.data["sent_bitrate_bps"] is None
    assert reset.data["counters_reset"] is True
    assert reset.data["metric_gap"] is True
    assert reset.data["source_state"] == "stale"
