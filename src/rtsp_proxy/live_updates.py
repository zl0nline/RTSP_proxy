from __future__ import annotations

import asyncio
import json
from collections import deque
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Final, Protocol, TypeVar, cast
from uuid import UUID

import anyio
from starlette.responses import StreamingResponse
from starlette.types import Message, Send

from rtsp_proxy.identifiers import PublicId
from rtsp_proxy.observability import (
    FleetSnapshot,
    NodeScrapeStatus,
    NodeSnapshot,
    PathMetricCounters,
    SnapshotReader,
)

_MAX_EVENT_ID: Final = 9_999_999_999_999_999_999
_T = TypeVar("_T")


class CameraLiveEventType(StrEnum):
    STATE = "state"
    HEARTBEAT = "heartbeat"
    AUTHZ_EPOCH = "authz_epoch"
    RESYNC_REQUIRED = "resync_required"


class CameraSourceState(StrEnum):
    READY = "ready"
    IDLE = "idle"
    STALE = "stale"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


class LiveStreamLimitReached(RuntimeError):
    """The bounded live-stream admission limit was reached."""


class LiveUpdateUnavailable(RuntimeError):
    """The live update adapter cannot safely serve a new subscription."""


class CameraLiveStream(Protocol):
    slow_consumer: bool

    def __aiter__(self) -> AsyncIterator[CameraLiveEvent]: ...

    async def __anext__(self) -> CameraLiveEvent: ...

    async def aclose(self) -> None: ...


class CameraLiveUpdateSource(Protocol):
    def diagnostics(self) -> CameraLiveDiagnostics: ...

    async def start(self) -> None: ...

    async def stop(self) -> None: ...

    async def current(self, target: CameraLiveTarget) -> CameraLiveEvent: ...

    async def open(
        self,
        *,
        target: CameraLiveTarget,
        session_id: UUID,
        authz_version: int,
        authorize: Callable[[], Awaitable[int]],
        last_event_id: str | None = None,
    ) -> CameraLiveStream: ...


class CameraLiveEventResponse(StreamingResponse):
    """SSE response with a bounded client-write deadline and exact cleanup."""

    def __init__(
        self,
        subscription: CameraLiveStream,
        *,
        send_timeout_seconds: float = 5,
    ) -> None:
        if not 0.1 <= send_timeout_seconds <= 10:
            raise ValueError("live_send_timeout_invalid")
        self._subscription = subscription
        self._send_timeout_seconds = send_timeout_seconds
        super().__init__(
            self._content(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-store, no-cache, must-revalidate",
                "X-Accel-Buffering": "no",
                "X-Content-Type-Options": "nosniff",
            },
        )

    async def _content(self) -> AsyncIterator[bytes]:
        yield b"retry: 5000\n\n"
        async for event in self._subscription:
            yield event.encode()

    async def stream_response(self, send: Send) -> None:
        try:
            await self._bounded_send(
                send,
                {
                    "type": "http.response.start",
                    "status": self.status_code,
                    "headers": self.raw_headers,
                },
            )
            async for chunk in self.body_iterator:
                if not isinstance(chunk, bytes | memoryview):
                    chunk = chunk.encode(self.charset)
                await self._bounded_send(
                    send,
                    {"type": "http.response.body", "body": chunk, "more_body": True},
                )
            await self._bounded_send(
                send,
                {"type": "http.response.body", "body": b"", "more_body": False},
            )
        except TimeoutError:
            pass
        finally:
            with anyio.CancelScope(shield=True):
                await self._subscription.aclose()

    async def _bounded_send(self, send: Send, message: Message) -> None:
        with anyio.fail_after(self._send_timeout_seconds):
            await send(message)


@dataclass(frozen=True, slots=True)
class CameraLiveTarget:
    camera_id: UUID
    public_id: PublicId
    node_id: UUID

    def __post_init__(self) -> None:
        if self.camera_id.version != 4 or self.node_id.version != 4:
            raise ValueError("camera_live_target_invalid")


@dataclass(frozen=True, slots=True)
class CameraLiveEvent:
    event_type: CameraLiveEventType
    data: Mapping[str, object]
    event_id: int | None = None

    def __post_init__(self) -> None:
        if self.event_id is not None and not 1 <= self.event_id <= _MAX_EVENT_ID:
            raise ValueError("live_event_id_invalid")

    def encode(self) -> bytes:
        lines = [] if self.event_id is None else [f"id: {self.event_id}"]
        lines.extend(
            (
                f"event: {self.event_type.value}",
                "data: "
                + json.dumps(
                    self.data,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                ),
                "",
                "",
            )
        )
        return "\n".join(lines).encode("utf-8")


@dataclass(frozen=True, slots=True)
class CameraLiveDiagnostics:
    active_subscriptions: int
    tracked_cameras: int
    opened_subscriptions_total: int
    resume_requests_total: int
    resync_required_total: int
    rejected_subscriptions_total: int
    slow_consumer_disconnects_total: int
    authz_disconnects_total: int


@dataclass(frozen=True, slots=True)
class _CameraProjection:
    data: Mapping[str, object]
    observed_at: datetime | None
    node_id: UUID
    path: PathMetricCounters | None


@dataclass(frozen=True, slots=True)
class _SnapshotIndex:
    snapshot: FleetSnapshot
    nodes: Mapping[UUID, NodeSnapshot]
    paths: Mapping[tuple[UUID, str], PathMetricCounters]
    path_nodes: Mapping[str, frozenset[UUID]]
    path_metrics_available: frozenset[UUID]


@dataclass(slots=True)
class _CameraChannel:
    target: CameraLiveTarget
    history: deque[CameraLiveEvent]
    subscribers: dict[UUID, CameraLiveSubscription] = field(default_factory=dict)
    previous_projection: _CameraProjection | None = None
    last_access: float = 0
    last_snapshot_generated_at: datetime | None = None
    target_available: bool = True


class CameraLiveSubscription:
    """A bounded, revocation-aware stream owned by one operator session."""

    def __init__(
        self,
        *,
        owner: CameraLiveUpdates,
        camera_id: UUID,
        session_id: UUID,
        authz_version: int,
        queue_size: int,
        heartbeat_seconds: float,
        reauthorize_seconds: float,
    ) -> None:
        self._owner = owner
        self._camera_id = camera_id
        self._session_id = session_id
        self._authz_version = authz_version
        self._queue: asyncio.Queue[CameraLiveEvent] = asyncio.Queue(maxsize=queue_size)
        self._heartbeat_seconds = heartbeat_seconds
        self._reauthorize_seconds = reauthorize_seconds
        now = asyncio.get_running_loop().time()
        self._next_heartbeat = now + heartbeat_seconds
        self._next_authorize = now + reauthorize_seconds
        self._closed = False
        self._terminal_event: CameraLiveEvent | None = None
        self._terminal_delivered = False
        self.slow_consumer = False

    def __aiter__(self) -> CameraLiveSubscription:
        return self

    async def __anext__(self) -> CameraLiveEvent:
        while True:
            if self._terminal_event is not None and not self._terminal_delivered:
                self._terminal_delivered = True
                return self._terminal_event
            if self._closed:
                raise StopAsyncIteration

            loop = asyncio.get_running_loop()
            now = loop.time()
            if now >= self._next_authorize:
                if not await self._authorization_current():
                    continue
                now = loop.time()

            timeout = max(
                0.0,
                min(self._next_heartbeat, self._next_authorize) - now,
            )
            try:
                event = await asyncio.wait_for(self._queue.get(), timeout=timeout)
            except TimeoutError:
                now = loop.time()
                if now >= self._next_heartbeat:
                    if not await self._authorization_current():
                        continue
                    self._next_heartbeat = now + self._heartbeat_seconds
                    return CameraLiveEvent(
                        event_type=CameraLiveEventType.HEARTBEAT,
                        data={"authz_version": self._authz_version},
                    )
                continue
            if not await self._authorization_current():
                continue
            return event

    async def _authorization_current(self) -> bool:
        if not await self._owner._authorization_current(
            self._session_id,
            self._authz_version,
        ):
            await self._close_for_authz_change()
            return False
        self._next_authorize = asyncio.get_running_loop().time() + self._reauthorize_seconds
        return True

    async def aclose(self) -> None:
        if self._closed and self._terminal_event is None:
            return
        self._terminal_event = None
        self._closed = True
        await self._owner._remove_subscription(self._camera_id, self._session_id)

    def _offer(self, event: CameraLiveEvent) -> bool:
        if self._closed:
            return False
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            self.slow_consumer = True
            self._closed = True
            return False
        return True

    def _start_new_epoch(self, event: CameraLiveEvent) -> bool:
        if self._closed:
            return False
        while not self._queue.empty():
            self._queue.get_nowait()
        return self._offer(event)

    async def _close_for_authz_change(self) -> None:
        self._terminal_event = CameraLiveEvent(
            event_type=CameraLiveEventType.AUTHZ_EPOCH,
            data={"action": "reauthenticate"},
        )
        self._closed = True
        await self._owner._remove_for_authz_change(self._camera_id, self._session_id)


class CameraLiveUpdates:
    """Project one fleet snapshot into bounded, per-camera live event streams."""

    def __init__(
        self,
        *,
        reader: SnapshotReader,
        resolve_targets: Callable[
            [tuple[UUID, ...]], Mapping[UUID, tuple[PublicId, UUID]]
        ]
        | None = None,
        authorize_sessions: Callable[[tuple[UUID, ...]], Mapping[UUID, int]] | None = None,
        poll_interval_seconds: float = 5,
        heartbeat_seconds: float = 15,
        reauthorize_seconds: float = 1,
        authorize_timeout_seconds: float = 0.75,
        history_size: int = 128,
        subscriber_queue_size: int = 8,
        max_subscriptions: int = 256,
        max_tracked_cameras: int = 10_000,
        max_snapshot_age_seconds: float | None = None,
        refresh_wait_timeout_seconds: float = 2,
        metric_interval_seconds: float = 5,
        channel_ttl_seconds: float = 300,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        monotonic: Callable[[], float] = lambda: asyncio.get_running_loop().time(),
    ) -> None:
        if not 0.01 <= poll_interval_seconds <= 30:
            raise ValueError("live_poll_interval_invalid")
        if not 0.01 <= heartbeat_seconds <= 60:
            raise ValueError("live_heartbeat_interval_invalid")
        if not 0.01 <= reauthorize_seconds <= 2:
            raise ValueError("live_reauthorize_interval_invalid")
        if (
            not 0.01 <= authorize_timeout_seconds <= 2
            or reauthorize_seconds + authorize_timeout_seconds > 2
        ):
            raise ValueError("live_authorize_timeout_invalid")
        if not 1 <= history_size <= 1024:
            raise ValueError("live_history_size_invalid")
        if not 1 <= subscriber_queue_size <= 1024:
            raise ValueError("live_subscriber_queue_size_invalid")
        if not 1 <= max_subscriptions <= 4096:
            raise ValueError("live_subscription_limit_invalid")
        if not 1 <= max_tracked_cameras <= 10_000:
            raise ValueError("live_camera_limit_invalid")
        if max_snapshot_age_seconds is not None and not 1 <= max_snapshot_age_seconds <= 300:
            raise ValueError("live_snapshot_age_invalid")
        if not 0.01 <= refresh_wait_timeout_seconds <= 5:
            raise ValueError("live_refresh_wait_timeout_invalid")
        if not 0.01 <= metric_interval_seconds <= 60:
            raise ValueError("live_metric_interval_invalid")
        if not 1 <= channel_ttl_seconds <= 3600:
            raise ValueError("live_channel_ttl_invalid")
        self._reader = reader
        self._resolve_targets = resolve_targets
        self._authorize_sessions = authorize_sessions
        self._poll_interval_seconds = poll_interval_seconds
        self._heartbeat_seconds = heartbeat_seconds
        self._reauthorize_seconds = reauthorize_seconds
        self._authorize_timeout_seconds = authorize_timeout_seconds
        self._history_size = history_size
        self._subscriber_queue_size = subscriber_queue_size
        self._max_subscriptions = max_subscriptions
        self._max_tracked_cameras = max_tracked_cameras
        self._max_snapshot_age_seconds = max_snapshot_age_seconds
        self._refresh_wait_timeout_seconds = refresh_wait_timeout_seconds
        self._metric_interval_seconds = metric_interval_seconds
        self._channel_ttl_seconds = channel_ttl_seconds
        self._clock = clock
        self._monotonic = monotonic
        self._channels: dict[UUID, _CameraChannel] = {}
        self._session_subscriptions: dict[UUID, CameraLiveSubscription] = {}
        self._lock = asyncio.Lock()
        self._refresh_task: asyncio.Task[None] | None = None
        self._authorization_refresh_task: asyncio.Task[None] | None = None
        self._authorization_epochs: dict[UUID, tuple[int, float]] = {}
        self._worker_tasks: set[asyncio.Task[object]] = set()
        self._snapshot_loaded = False
        self._latest_index: _SnapshotIndex | None = None
        self._refresh_completed_at: float | None = None
        self._next_event_id = 1
        self._opened_subscriptions_total = 0
        self._resume_requests_total = 0
        self._resync_required_total = 0
        self._rejected_subscriptions_total = 0
        self._slow_consumer_disconnects_total = 0
        self._authz_disconnects_total = 0
        self._stop_event: asyncio.Event | None = None
        self._task: asyncio.Task[None] | None = None

    @property
    def active_subscriptions(self) -> int:
        return len(self._session_subscriptions)

    def history_size_for(self, camera_id: UUID) -> int:
        channel = self._channels.get(camera_id)
        return 0 if channel is None else len(channel.history)

    def diagnostics(self) -> CameraLiveDiagnostics:
        return CameraLiveDiagnostics(
            active_subscriptions=len(self._session_subscriptions),
            tracked_cameras=len(self._channels),
            opened_subscriptions_total=self._opened_subscriptions_total,
            resume_requests_total=self._resume_requests_total,
            resync_required_total=self._resync_required_total,
            rejected_subscriptions_total=self._rejected_subscriptions_total,
            slow_consumer_disconnects_total=self._slow_consumer_disconnects_total,
            authz_disconnects_total=self._authz_disconnects_total,
        )

    @staticmethod
    def parse_last_event_id(value: str | None) -> int | None:
        return parse_last_event_id(value)

    async def start(self) -> None:
        if self._task is not None:
            raise RuntimeError("live_updates_already_started")
        self._stop_event = asyncio.Event()
        self._task = asyncio.create_task(self._run(), name="camera-live-updates")

    async def stop(self) -> None:
        task = self._task
        stop_event = self._stop_event
        if task is None or stop_event is None:
            return
        stop_event.set()
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
        refresh_task = self._refresh_task
        if refresh_task is not None and not refresh_task.done():
            refresh_task.cancel()
            with suppress(asyncio.CancelledError):
                await refresh_task
        self._refresh_task = None
        authorization_task = self._authorization_refresh_task
        if authorization_task is not None and not authorization_task.done():
            authorization_task.cancel()
            with suppress(asyncio.CancelledError):
                await authorization_task
        self._authorization_refresh_task = None
        worker_tasks = tuple(self._worker_tasks)
        if worker_tasks:
            await asyncio.gather(*worker_tasks, return_exceptions=True)
        self._task = None
        self._stop_event = None
        async with self._lock:
            subscriptions = tuple(self._session_subscriptions.values())
            self._session_subscriptions.clear()
            self._authorization_epochs.clear()
            for channel in self._channels.values():
                channel.subscribers.clear()
            for subscription in subscriptions:
                subscription._closed = True

    async def open(
        self,
        *,
        target: CameraLiveTarget,
        session_id: UUID,
        authz_version: int,
        authorize: Callable[[], Awaitable[int]],
        last_event_id: str | None = None,
    ) -> CameraLiveSubscription:
        if session_id.version != 4 or authz_version < 1:
            raise ValueError("live_subscription_identity_invalid")
        if self._authorize_sessions is None:
            raise LiveUpdateUnavailable("live_authorization_unavailable")
        resume_from = self.parse_last_event_id(last_event_id)
        await self._ensure_recent_snapshot()
        try:
            current_authz_version = await asyncio.wait_for(
                authorize(),
                timeout=self._authorize_timeout_seconds,
            )
        except Exception:
            raise LiveUpdateUnavailable("live_authorization_unavailable") from None
        if current_authz_version != authz_version:
            raise LiveUpdateUnavailable("live_authorization_changed")
        subscription: CameraLiveSubscription | None = None
        try:
            async with self._lock:
                if session_id in self._session_subscriptions:
                    self._rejected_subscriptions_total += 1
                    raise LiveStreamLimitReached("live_stream_session_limit")
                if len(self._session_subscriptions) >= self._max_subscriptions:
                    self._rejected_subscriptions_total += 1
                    raise LiveStreamLimitReached("live_stream_capacity")
                channel = self._get_or_create_channel(target)
                self._observe_channel(channel, self._latest_index)
                subscription = CameraLiveSubscription(
                    owner=self,
                    camera_id=target.camera_id,
                    session_id=session_id,
                    authz_version=authz_version,
                    queue_size=self._subscriber_queue_size,
                    heartbeat_seconds=self._heartbeat_seconds,
                    reauthorize_seconds=self._reauthorize_seconds,
                )
                channel.subscribers[session_id] = subscription
                self._session_subscriptions[session_id] = subscription
                self._authorization_epochs[session_id] = (
                    authz_version,
                    self._monotonic(),
                )
                self._opened_subscriptions_total += 1
                if resume_from is not None:
                    self._resume_requests_total += 1
                channel.last_access = self._monotonic()
                self._replay(channel, subscription, resume_from)
            return subscription
        except BaseException:
            if subscription is not None:
                with anyio.CancelScope(shield=True):
                    await subscription.aclose()
            raise

    async def current(self, target: CameraLiveTarget) -> CameraLiveEvent:
        await self._ensure_recent_snapshot()
        async with self._lock:
            channel = self._get_or_create_channel(target)
            channel.last_access = self._monotonic()
            self._observe_channel(channel, self._latest_index)
            if not channel.history:
                raise LiveUpdateUnavailable("live_snapshot_unavailable")
            return channel.history[-1]

    async def refresh_once(self) -> None:
        await self._await_refresh()

    async def _ensure_recent_snapshot(self) -> None:
        completed_at = self._refresh_completed_at
        if (
            self._snapshot_loaded
            and completed_at is not None
            and self._monotonic() - completed_at <= self._poll_interval_seconds
        ):
            return
        await self._await_refresh()

    async def _await_refresh(self) -> None:
        refresh_task = self._refresh_task
        if refresh_task is None or refresh_task.done():
            refresh_task = asyncio.create_task(
                self._refresh_from_reader(),
                name="camera-live-snapshot-refresh",
            )
            self._refresh_task = refresh_task
        try:
            await asyncio.wait_for(
                asyncio.shield(refresh_task),
                timeout=self._refresh_wait_timeout_seconds,
            )
        except TimeoutError:
            raise LiveUpdateUnavailable("live_snapshot_refresh_timeout") from None

    async def _refresh_from_reader(self) -> None:
        resolve_targets = self._resolve_targets
        async with self._lock:
            active_camera_ids = tuple(
                sorted(
                    (
                        camera_id
                        for camera_id, channel in self._channels.items()
                        if channel.subscribers
                    ),
                    key=lambda camera_id: camera_id.int,
                )
            )
        try:
            snapshot = await self._run_owned_sync(self._reader.current_snapshot)
            resolved_targets = (
                {}
                if not active_camera_ids or resolve_targets is None
                else await self._run_owned_sync(
                    lambda: resolve_targets(active_camera_ids)
                )
            )
        except Exception:
            snapshot = None
            resolved_targets = None
        async with self._lock:
            if active_camera_ids and resolve_targets is not None:
                self._observe_authoritative_targets(active_camera_ids, resolved_targets)
            self._observe(snapshot)
            self._snapshot_loaded = True
            self._refresh_completed_at = self._monotonic()

    async def _authorization_current(
        self,
        session_id: UUID,
        expected_authz_version: int,
    ) -> bool:
        observed = self._authorization_epochs.get(session_id)
        if (
            observed is not None
            and observed[0] == expected_authz_version
            and self._monotonic() - observed[1] < self._reauthorize_seconds
        ):
            return True
        try:
            await self._await_authorization_refresh()
        except LiveUpdateUnavailable:
            return False
        observed = self._authorization_epochs.get(session_id)
        return bool(observed is not None and observed[0] == expected_authz_version)

    async def _await_authorization_refresh(self) -> None:
        refresh_task = self._authorization_refresh_task
        if refresh_task is None or refresh_task.done():
            refresh_task = asyncio.create_task(
                self._refresh_authorization_epochs(),
                name="camera-live-authorization-refresh",
            )
            self._authorization_refresh_task = refresh_task
        try:
            await asyncio.wait_for(
                asyncio.shield(refresh_task),
                timeout=self._authorize_timeout_seconds,
            )
        except TimeoutError:
            raise LiveUpdateUnavailable("live_authorization_timeout") from None

    async def _refresh_authorization_epochs(self) -> None:
        authorize_sessions = self._authorize_sessions
        if authorize_sessions is None:
            raise LiveUpdateUnavailable("live_authorization_unavailable")
        async with self._lock:
            session_ids = tuple(
                sorted(self._session_subscriptions, key=lambda session_id: session_id.int)
            )
        if not session_ids:
            return
        try:
            current = await self._run_owned_sync(lambda: authorize_sessions(session_ids))
        except Exception:
            current = {}
        checked_at = self._monotonic()
        async with self._lock:
            for session_id in session_ids:
                if session_id in self._session_subscriptions:
                    self._authorization_epochs[session_id] = (
                        current.get(session_id, 0),
                        checked_at,
                    )

    async def _run_owned_sync(self, function: Callable[[], _T]) -> _T:
        async def invoke() -> object:
            return await anyio.to_thread.run_sync(function, abandon_on_cancel=True)

        worker = asyncio.create_task(invoke(), name="camera-live-sync-worker")
        self._worker_tasks.add(worker)
        worker.add_done_callback(self._worker_tasks.discard)
        return cast(_T, await asyncio.shield(worker))

    def _observe_authoritative_targets(
        self,
        camera_ids: tuple[UUID, ...],
        resolved: Mapping[UUID, tuple[PublicId, UUID]] | None,
    ) -> None:
        if resolved is None:
            for camera_id in camera_ids:
                channel = self._channels.get(camera_id)
                if channel is not None and channel.target_available:
                    channel.target_available = False
                    self._start_channel_epoch(channel, reason="camera_target_unavailable")
            return
        for camera_id in camera_ids:
            channel = self._channels.get(camera_id)
            if channel is None:
                continue
            placement = resolved.get(camera_id)
            if placement is None or placement[0] != channel.target.public_id:
                if channel.target_available:
                    channel.target_available = False
                    self._start_channel_epoch(channel, reason="camera_target_unavailable")
                continue
            target = CameraLiveTarget(
                camera_id=camera_id,
                public_id=placement[0],
                node_id=placement[1],
            )
            if not channel.target_available or target.node_id != channel.target.node_id:
                channel.target = target
                channel.target_available = True
                self._start_channel_epoch(channel, reason="camera_node_changed")

    def _start_channel_epoch(self, channel: _CameraChannel, *, reason: str) -> None:
        channel.history.clear()
        channel.previous_projection = None
        channel.last_snapshot_generated_at = None
        resync = _resync_event(reason=reason)
        for session_id, subscription in tuple(channel.subscribers.items()):
            self._resync_required_total += 1
            if not subscription._start_new_epoch(resync):
                self._slow_consumer_disconnects_total += 1
                channel.subscribers.pop(session_id, None)
                self._session_subscriptions.pop(session_id, None)
                self._authorization_epochs.pop(session_id, None)

    async def _run(self) -> None:
        assert self._stop_event is not None
        while not self._stop_event.is_set():
            with suppress(LiveUpdateUnavailable):
                await self.refresh_once()
            with suppress(TimeoutError):
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=self._poll_interval_seconds,
                )

    def _observe(self, snapshot: FleetSnapshot | None) -> None:
        if (
            snapshot is not None
            and self._max_snapshot_age_seconds is not None
            and snapshot.generated_at
            < self._clock() - timedelta(seconds=self._max_snapshot_age_seconds)
        ):
            snapshot = None
        index = None if snapshot is None else _index_snapshot(snapshot)
        self._latest_index = index
        self._expire_inactive_channels()
        for channel in tuple(self._channels.values()):
            self._observe_channel(channel, index)

    def _observe_channel(
        self,
        channel: _CameraChannel,
        index: _SnapshotIndex | None,
    ) -> None:
        if (
            index is not None
            and channel.last_snapshot_generated_at == index.snapshot.generated_at
        ):
            return
        projection = _project_camera(
            channel,
            index,
            metric_interval_seconds=self._metric_interval_seconds,
        )
        if (
            channel.previous_projection is not None
            and projection.data == channel.previous_projection.data
        ):
            return
        event = CameraLiveEvent(
            event_type=CameraLiveEventType.STATE,
            event_id=self._allocate_event_id(),
            data=projection.data,
        )
        channel.previous_projection = projection
        channel.last_snapshot_generated_at = (
            None if index is None else index.snapshot.generated_at
        )
        channel.history.append(event)
        for session_id, subscription in tuple(channel.subscribers.items()):
            if not subscription._offer(event):
                self._slow_consumer_disconnects_total += 1
                channel.subscribers.pop(session_id, None)
                self._session_subscriptions.pop(session_id, None)
                self._authorization_epochs.pop(session_id, None)

    def _allocate_event_id(self) -> int:
        event_id = self._next_event_id
        if event_id > _MAX_EVENT_ID:
            raise LiveUpdateUnavailable("live_event_id_exhausted")
        self._next_event_id += 1
        return event_id

    def _replay(
        self,
        channel: _CameraChannel,
        subscription: CameraLiveSubscription,
        resume_from: int | None,
    ) -> None:
        history = tuple(channel.history)
        if resume_from is None:
            if history:
                subscription._offer(history[-1])
            return
        if not history:
            self._resync_required_total += 1
            subscription._offer(_resync_event())
            return
        first_id = history[0].event_id
        last_id = history[-1].event_id
        assert first_id is not None and last_id is not None
        if resume_from < first_id or resume_from > last_id:
            self._resync_required_total += 1
            subscription._offer(_resync_event())
            return
        replay = tuple(
            event
            for event in history
            if event.event_id is not None and event.event_id > resume_from
        )
        if len(replay) >= self._subscriber_queue_size:
            self._resync_required_total += 1
            subscription._offer(_resync_event())
            return
        for event in replay:
            if not subscription._offer(event):
                return

    async def _remove_subscription(self, camera_id: UUID, session_id: UUID) -> None:
        async with self._lock:
            self._session_subscriptions.pop(session_id, None)
            self._authorization_epochs.pop(session_id, None)
            channel = self._channels.get(camera_id)
            if channel is not None:
                channel.subscribers.pop(session_id, None)
                channel.last_access = self._monotonic()

    async def _remove_for_authz_change(self, camera_id: UUID, session_id: UUID) -> None:
        async with self._lock:
            self._authz_disconnects_total += 1
            self._session_subscriptions.pop(session_id, None)
            self._authorization_epochs.pop(session_id, None)
            channel = self._channels.get(camera_id)
            if channel is not None:
                channel.subscribers.pop(session_id, None)
                channel.last_access = self._monotonic()

    def _expire_inactive_channels(self) -> None:
        now = self._monotonic()
        expired = tuple(
            camera_id
            for camera_id, channel in self._channels.items()
            if not channel.subscribers
            and now - channel.last_access >= self._channel_ttl_seconds
        )
        for camera_id in expired:
            self._channels.pop(camera_id, None)

    def _evict_inactive_channel(self) -> None:
        if len(self._channels) < self._max_tracked_cameras:
            return
        inactive = tuple(
            channel for channel in self._channels.values() if not channel.subscribers
        )
        if not inactive:
            return
        oldest = min(inactive, key=lambda channel: channel.last_access)
        self._channels.pop(oldest.target.camera_id, None)

    def _get_or_create_channel(self, target: CameraLiveTarget) -> _CameraChannel:
        self._expire_inactive_channels()
        channel = self._channels.get(target.camera_id)
        if channel is None:
            self._evict_inactive_channel()
            if len(self._channels) >= self._max_tracked_cameras:
                raise LiveUpdateUnavailable("live_camera_capacity")
            channel = _CameraChannel(
                target=target,
                history=deque(maxlen=self._history_size),
                last_access=self._monotonic(),
            )
            self._channels[target.camera_id] = channel
        elif channel.target.public_id != target.public_id:
            raise LiveUpdateUnavailable("live_camera_identity_changed")
        elif channel.target.node_id != target.node_id:
            channel.target = target
            channel.target_available = True
            self._start_channel_epoch(channel, reason="camera_node_changed")
        elif not channel.target_available:
            channel.target_available = True
            self._start_channel_epoch(channel, reason="camera_node_changed")
        return channel


def _project_camera(
    channel: _CameraChannel,
    index: _SnapshotIndex | None,
    *,
    metric_interval_seconds: float,
) -> _CameraProjection:
    target = channel.target
    if index is None or not channel.target_available:
        return _CameraProjection(
            data=_state_data(
                target=target,
                node_id=target.node_id,
                observed_at=None,
                source_state=CameraSourceState.UNAVAILABLE,
                scrape_status=NodeScrapeStatus.UNAVAILABLE,
                occupied=None,
                received_bitrate_bps=None,
                sent_bitrate_bps=None,
            ),
            observed_at=None,
            node_id=target.node_id,
            path=None,
        )

    snapshot = index.snapshot
    path = index.paths.get((target.node_id, str(target.public_id)))
    path_nodes = index.path_nodes.get(str(target.public_id), frozenset())
    if path is None and path_nodes and target.node_id not in path_nodes:
        return _CameraProjection(
            data=_state_data(
                target=target,
                node_id=target.node_id,
                observed_at=snapshot.generated_at,
                source_state=CameraSourceState.UNAVAILABLE,
                scrape_status=NodeScrapeStatus.UNAVAILABLE,
                occupied=None,
                received_bitrate_bps=None,
                sent_bitrate_bps=None,
            ),
            observed_at=snapshot.generated_at,
            node_id=target.node_id,
            path=None,
        )

    if path is None:
        target_node = index.nodes.get(target.node_id)
        status = (
            NodeScrapeStatus.UNAVAILABLE
            if target_node is None
            else target_node.scrape_status
        )
        detail_available = target.node_id in index.path_metrics_available
        source_state = (
            (
                CameraSourceState.UNAVAILABLE
                if detail_available
                else CameraSourceState.UNKNOWN
            )
            if status in {NodeScrapeStatus.FRESH, NodeScrapeStatus.IDLE}
            else (
                CameraSourceState.STALE
                if status is NodeScrapeStatus.STALE
                else CameraSourceState.UNAVAILABLE
            )
        )
        return _CameraProjection(
            data=_state_data(
                target=target,
                node_id=target.node_id,
                observed_at=(
                    snapshot.generated_at
                    if target_node is None or target_node.metric_observed_at is None
                    else target_node.metric_observed_at
                ),
                source_state=source_state,
                scrape_status=status,
                occupied=False if source_state is CameraSourceState.IDLE else None,
                received_bitrate_bps=None,
                sent_bitrate_bps=None,
                counters_reset=False if target_node is None else target_node.counters_reset,
            ),
            observed_at=(
                snapshot.generated_at
                if target_node is None or target_node.metric_observed_at is None
                else target_node.metric_observed_at
            ),
            node_id=target.node_id,
            path=None,
        )

    node = index.nodes[target.node_id]
    occupied = (
        None
        if node.metrics is None or node.metrics.occupied_public_ids is None
        else path.public_id in node.metrics.occupied_public_ids
    )
    observed_at = node.metric_observed_at
    metric_gap = observed_at is None or (
        snapshot.generated_at - observed_at
    ).total_seconds() > 2 * metric_interval_seconds
    counters_reset = path.counters_reset
    metric_gap = metric_gap or path.metric_gap
    received_rate = path.received_bitrate_bps
    sent_rate = path.sent_bitrate_bps
    source_state = (
        (
            CameraSourceState.READY
            if path.ready is True
            else CameraSourceState.IDLE
            if path.ready is False
            else CameraSourceState.UNKNOWN
        )
        if node.scrape_status in {NodeScrapeStatus.FRESH, NodeScrapeStatus.IDLE}
        else (
            CameraSourceState.STALE
            if node.scrape_status is NodeScrapeStatus.STALE
            else CameraSourceState.UNAVAILABLE
        )
    )
    if metric_gap and source_state in {
        CameraSourceState.READY,
        CameraSourceState.IDLE,
        CameraSourceState.UNKNOWN,
    }:
        source_state = CameraSourceState.STALE
    if source_state is not CameraSourceState.READY:
        received_rate = None
        sent_rate = None
    return _CameraProjection(
        data=_state_data(
            target=target,
            node_id=node.node_id,
            observed_at=observed_at,
            source_state=source_state,
            scrape_status=node.scrape_status,
            occupied=occupied,
            received_bitrate_bps=received_rate,
            sent_bitrate_bps=sent_rate,
            counters_reset=counters_reset,
            metric_gap=metric_gap,
        ),
        observed_at=observed_at,
        node_id=node.node_id,
        path=path,
    )


def _state_data(
    *,
    target: CameraLiveTarget,
    node_id: UUID | None,
    observed_at: datetime | None,
    source_state: CameraSourceState,
    scrape_status: NodeScrapeStatus,
    occupied: bool | None,
    received_bitrate_bps: float | None,
    sent_bitrate_bps: float | None,
    counters_reset: bool = False,
    metric_gap: bool = False,
) -> Mapping[str, object]:
    return {
        "camera_id": str(target.camera_id),
        "counters_reset": counters_reset,
        "metric_gap": metric_gap,
        "node_id": None if node_id is None else str(node_id),
        "observed_at": None if observed_at is None else observed_at.isoformat(),
        "occupied": occupied,
        "received_bitrate_bps": received_bitrate_bps,
        "scrape_status": scrape_status.value,
        "sent_bitrate_bps": sent_bitrate_bps,
        "source_state": source_state.value,
    }


def _index_snapshot(snapshot: FleetSnapshot) -> _SnapshotIndex:
    nodes = {node.node_id: node for node in snapshot.nodes}
    paths: dict[tuple[UUID, str], PathMetricCounters] = {}
    path_nodes: dict[str, set[UUID]] = {}
    path_metrics_available: set[UUID] = set()
    for node in snapshot.nodes:
        if node.metrics is None:
            continue
        if node.metrics.path_counters or node.metrics.occupied_public_ids is not None:
            path_metrics_available.add(node.node_id)
        for path in node.metrics.path_counters:
            paths[(node.node_id, path.public_id)] = path
            path_nodes.setdefault(path.public_id, set()).add(node.node_id)
    return _SnapshotIndex(
        snapshot=snapshot,
        nodes=nodes,
        paths=paths,
        path_nodes={
            public_id: frozenset(node_ids)
            for public_id, node_ids in path_nodes.items()
        },
        path_metrics_available=frozenset(path_metrics_available),
    )


def _resync_event(*, reason: str = "history_gap") -> CameraLiveEvent:
    return CameraLiveEvent(
        event_type=CameraLiveEventType.RESYNC_REQUIRED,
        data={"reason": reason},
    )


def parse_last_event_id(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    if (
        len(value) > 19
        or not value.isascii()
        or not value.isdecimal()
        or value.startswith("0")
    ):
        raise ValueError("live_event_id_invalid")
    parsed = int(value)
    if not 1 <= parsed <= _MAX_EVENT_ID:
        raise ValueError("live_event_id_invalid")
    return parsed
