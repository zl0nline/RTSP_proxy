from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from threading import Event, Thread
from uuid import UUID, uuid4

import pytest

from rtsp_proxy.probe_broker import ProbeBrokerRequest, ReceivedProbeInput
from rtsp_proxy.probe_connect_guard import ProbeConnectGuardLease
from rtsp_proxy.probe_execution import (
    ProbeExecutionBroker,
    ProbeExecutionError,
    ProbeExecutionStartupRecovery,
)
from rtsp_proxy.probe_executor import ProbeConnectGuardTarget
from rtsp_proxy.probe_ownership import OwnershipLedger
from rtsp_proxy.probe_systemd import ProbeTransientDescriptors, ProbeTransientLease
from rtsp_proxy.probes import ProbeExecutionResult, ProbeOutcome


@dataclass(frozen=True, slots=True)
class _Lease:
    name: str


class _Channels:
    def __init__(
        self,
        events: list[str],
        sealed_input_fd: int,
        *,
        close_error: BaseException | None = None,
    ) -> None:
        self.events = events
        self.sealed_input_fd = sealed_input_fd
        self.close_error = close_error
        self.descriptors = ProbeTransientDescriptors(
            run_gate_fd=101,
            sealed_input_fd=sealed_input_fd,
            output_read_fd=102,
            output_write_fd=103,
        )
        self.output_fd = 102

    def close_child_ends(self) -> None:
        self.events.append("channels.close_child_ends")

    def release_gate(self) -> None:
        self.events.append("channels.release_gate")

    def close(self) -> None:
        self.events.append("channels.close")
        if self.sealed_input_fd >= 0:
            os.close(self.sealed_input_fd)
            self.sealed_input_fd = -1
        if self.close_error is not None:
            error = self.close_error
            self.close_error = None
            raise error


class _ChannelFactory:
    def __init__(
        self,
        events: list[str],
        *,
        post_publish_error: BaseException | None = None,
        close_error: BaseException | None = None,
    ) -> None:
        self.events = events
        self.post_publish_error = post_publish_error
        self.close_error = close_error

    def create_owned(
        self,
        received: ReceivedProbeInput,
        *,
        publish: Callable[[_Channels], None],
    ) -> None:
        self.events.append("channels.create")
        channels = _Channels(
            self.events,
            os.dup(received.descriptor),
            close_error=self.close_error,
        )
        publish(channels)
        if self.post_publish_error is not None:
            raise self.post_publish_error


class _Systemd:
    def __init__(
        self,
        events: list[str],
        *,
        start_error: BaseException | None = None,
        read_error: BaseException | None = None,
        cancel_error: BaseException | None = None,
        publish_before_start_error: bool = False,
        collect_before_read_error: bool = True,
        collect_on_cancel: bool = True,
        output: bytes = b'{"streams":[]}',
        publish_on_start: bool = True,
        read_started: Event | None = None,
        read_release: Event | None = None,
        cancel_started: Event | None = None,
        cancel_release: Event | None = None,
    ) -> None:
        self.events = events
        self.start_error = start_error
        self.read_error = read_error
        self.cancel_error = cancel_error
        self.publish_before_start_error = publish_before_start_error
        self.collect_before_read_error = collect_before_read_error
        self.collect_on_cancel = collect_on_cancel
        self.output = output
        self.publish_on_start = publish_on_start
        self.read_started = read_started
        self.read_release = read_release
        self.cancel_started = cancel_started
        self.cancel_release = cancel_release
        self.lease: ProbeTransientLease | None = None

    def start_owned(
        self,
        request: ProbeBrokerRequest,
        *,
        descriptors: ProbeTransientDescriptors,
        timeout_seconds: float,
        ownership: OwnershipLedger[ProbeTransientLease],
    ) -> None:
        del descriptors
        assert timeout_seconds > 0
        self.events.append("systemd.start")
        self.lease = ProbeTransientLease(
            unit_name=f"rtsp-probe-{request.request_id.hex}.service",
            job_path="/org/freedesktop/systemd1/job/1",
            request_id=request.request_id,
            endpoint_generation=request.endpoint_generation,
            guard_target=request.target,
            deadline_unix_ms=request.deadline_unix_ms,
        )
        if self.start_error is not None and not self.publish_before_start_error:
            raise self.start_error
        if self.publish_on_start:
            ownership.publish(self.lease)
        if self.start_error is not None:
            raise self.start_error

    def read_output(
        self,
        lease: ProbeTransientLease,
        *,
        output_fd: int,
        timeout_seconds: float,
        ownership: OwnershipLedger[ProbeTransientLease],
    ) -> bytes:
        assert lease is self.lease
        assert output_fd == 102
        assert timeout_seconds > 0
        self.events.append("systemd.read_output")
        if self.read_started is not None:
            self.read_started.set()
        if self.read_release is not None:
            assert self.read_release.wait(timeout=5.0)
        if self.collect_before_read_error:
            ownership.release(lease)
        if self.read_error is not None:
            raise self.read_error
        return self.output

    def ensure_collected(
        self,
        lease: ProbeTransientLease,
        *,
        timeout_seconds: float,
        ownership: OwnershipLedger[ProbeTransientLease],
    ) -> None:
        assert lease is self.lease
        assert timeout_seconds > 0
        self.events.append("systemd.cancel")
        if self.cancel_started is not None:
            self.cancel_started.set()
        if self.cancel_release is not None:
            assert self.cancel_release.wait(timeout=5.0)
        if self.collect_on_cancel:
            ownership.release(lease)
        if self.cancel_error is not None:
            raise self.cancel_error


class _Cgroups:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def resolve(self, *, unit_name: str, timeout_seconds: float) -> Path:
        assert unit_name.startswith("rtsp-probe-")
        assert timeout_seconds > 0
        self.events.append("cgroup.resolve")
        return Path("/sys/fs/cgroup/rtsp-probe.slice") / unit_name


class _Guard:
    def __init__(
        self,
        events: list[str],
        *,
        install_error: BaseException | None = None,
        release_error: BaseException | None = None,
        publish_before_install_error: bool = False,
        release_callback: bool = True,
    ) -> None:
        self.events = events
        self.install_error = install_error
        self.release_error = release_error
        self.publish_before_install_error = publish_before_install_error
        self.release_callback = release_callback
        self.lease: ProbeConnectGuardLease | None = None

    def install_owned(
        self,
        *,
        request_id: UUID,
        unit_name: str,
        cgroup_path: Path,
        target: ProbeConnectGuardTarget,
        timeout_seconds: float,
        ownership: OwnershipLedger[ProbeConnectGuardLease],
    ) -> None:
        del cgroup_path
        kwargs = {"timeout_seconds": timeout_seconds}
        assert kwargs["timeout_seconds"] > 0
        self.events.append("guard.install")
        self.lease = ProbeConnectGuardLease(
            request_id=request_id,
            unit_name=unit_name,
            target=target,
        )
        if self.install_error is not None and not self.publish_before_install_error:
            raise self.install_error
        ownership.publish(self.lease)
        if self.install_error is not None:
            raise self.install_error

    def ensure_released(
        self,
        lease: ProbeConnectGuardLease,
        *,
        timeout_seconds: float,
        ownership: OwnershipLedger[ProbeConnectGuardLease],
    ) -> None:
        assert lease is self.lease
        assert timeout_seconds > 0
        self.events.append("guard.release")
        if self.release_callback:
            ownership.release(lease)
        if self.release_error is not None:
            raise self.release_error


class _Decoder:
    def __init__(self, result: object | None = None) -> None:
        self.result = result

    def decode(self, payload: bytes) -> ProbeExecutionResult:
        assert payload == b'{"streams":[]}'
        if isinstance(self.result, BaseException):
            raise self.result
        if self.result is not None:
            return self.result  # type: ignore[return-value]
        return ProbeExecutionResult(
            outcome=ProbeOutcome.HEALTHY,
            completed_at=datetime(2026, 8, 30, tzinfo=UTC),
            video_codec="h264",
        )


class _Recovery:
    def __init__(
        self,
        *,
        unit_unresolved: int = 0,
        guard_unresolved: int = 0,
        error: Exception | None = None,
    ) -> None:
        self.unit_unresolved = unit_unresolved
        self.guard_unresolved = guard_unresolved
        self.error = error
        self.events: list[str] = []

    def reconcile_units(self, *, timeout_seconds: float) -> int:
        assert timeout_seconds > 0
        self.events.append("recovery.units")
        if self.error is not None:
            raise self.error
        return self.unit_unresolved

    def reconcile_guards(self, *, timeout_seconds: float) -> int:
        assert timeout_seconds > 0
        self.events.append("recovery.guards")
        if self.error is not None:
            raise self.error
        return self.guard_unresolved


class _UnitStartupReconciler:
    def __init__(self, events: list[str], remaining: int) -> None:
        self.events = events
        self.remaining = remaining

    def reconcile_owned(self, *, timeout_seconds: float) -> int:
        assert timeout_seconds > 0
        self.events.append("units")
        return self.remaining


class _GuardStartupReconciler:
    def __init__(self, events: list[str], remaining: int) -> None:
        self.events = events
        self.remaining = remaining

    def reconcile_startup(self, *, timeout_seconds: float) -> int:
        assert timeout_seconds > 0
        self.events.append("guards")
        return self.remaining


def _received_request() -> ReceivedProbeInput:
    return _received_for_request(
        ProbeBrokerRequest(
            request_id=uuid4(),
            endpoint_generation=UUID("329f624b-3234-40e4-a194-0e6dd722f0de"),
            target=ProbeConnectGuardTarget(ip_address("192.0.2.10"), 8554),
            deadline_unix_ms=1_800_000_000_000,
        )
    )


def _received_for_request(request: ProbeBrokerRequest) -> ReceivedProbeInput:
    return ReceivedProbeInput(
        request=request,
        _descriptor=os.open(os.devnull, os.O_RDONLY),
    )


def _broker(
    events: list[str],
    *,
    systemd: _Systemd | None = None,
    guard: _Guard | None = None,
    channels: _ChannelFactory | None = None,
    decoder: _Decoder | None = None,
    recovery: _Recovery | None = None,
    reconcile: bool = True,
    monotonic: Callable[[], float] = lambda: 100.0,
    wall_clock_ms: Callable[[], int] = lambda: 1_799_999_999_000,
) -> ProbeExecutionBroker:
    broker = ProbeExecutionBroker(
        systemd=systemd or _Systemd(events),
        guard=guard or _Guard(events),
        cgroups=_Cgroups(events),
        channels=channels or _ChannelFactory(events),
        decoder=decoder or _Decoder(),
        recovery=recovery or _Recovery(),
        monotonic=monotonic,
        wall_clock_ms=wall_clock_ms,
    )
    if reconcile:
        assert broker.reconcile_startup(timeout_seconds=5.0) == 0
    return broker


def test_probe_execution_orders_guard_before_release_and_collects_everything() -> None:
    events: list[str] = []
    received = _received_request()

    output = _broker(events).execute(received, timeout_seconds=5.0)

    assert output == ProbeExecutionResult(
        outcome=ProbeOutcome.HEALTHY,
        completed_at=datetime(2026, 8, 30, tzinfo=UTC),
        video_codec="h264",
    )
    assert events == [
        "channels.create",
        "systemd.start",
        "channels.close_child_ends",
        "cgroup.resolve",
        "guard.install",
        "channels.release_gate",
        "systemd.read_output",
        "guard.release",
        "channels.close",
    ]
    with pytest.raises(RuntimeError, match="probe_broker_descriptor_closed"):
        _ = received.descriptor


def test_probe_execution_cancels_transient_when_guard_install_fails() -> None:
    events: list[str] = []
    received = _received_request()
    guard = _Guard(events, install_error=RuntimeError("guard failed"))

    with pytest.raises(ProbeExecutionError, match="probe_execution_failed"):
        _broker(events, guard=guard).execute(received, timeout_seconds=5.0)

    assert events == [
        "channels.create",
        "systemd.start",
        "channels.close_child_ends",
        "cgroup.resolve",
        "guard.install",
        "systemd.cancel",
        "channels.close",
    ]


def test_probe_execution_releases_guard_after_output_failure_without_double_cancel() -> None:
    events: list[str] = []
    received = _received_request()
    systemd = _Systemd(events, read_error=RuntimeError("output failed"))

    with pytest.raises(ProbeExecutionError, match="probe_execution_failed"):
        _broker(events, systemd=systemd).execute(received, timeout_seconds=5.0)

    assert events == [
        "channels.create",
        "systemd.start",
        "channels.close_child_ends",
        "cgroup.resolve",
        "guard.install",
        "channels.release_gate",
        "systemd.read_output",
        "guard.release",
        "channels.close",
    ]


def test_probe_execution_preserves_interruption_and_runs_reverse_cleanup() -> None:
    events: list[str] = []
    received = _received_request()
    guard = _Guard(events, install_error=KeyboardInterrupt("interrupted"))

    with pytest.raises(KeyboardInterrupt, match="interrupted"):
        _broker(events, guard=guard).execute(received, timeout_seconds=5.0)

    assert events[-2:] == ["systemd.cancel", "channels.close"]


def test_probe_execution_rejects_expired_authenticated_request_before_side_effects() -> None:
    events: list[str] = []
    received = _received_request()

    with pytest.raises(ProbeExecutionError, match="probe_execution_timeout"):
        _broker(
            events,
            wall_clock_ms=lambda: received.request.deadline_unix_ms,
        ).execute(received, timeout_seconds=5.0)

    assert events == []
    received.close()


@pytest.mark.parametrize("phase", ["channels", "systemd", "guard"])
def test_probe_execution_cleans_resources_published_before_interruption(
    phase: str,
) -> None:
    events: list[str] = []
    channels = _ChannelFactory(
        events,
        post_publish_error=(KeyboardInterrupt("stop") if phase == "channels" else None),
    )
    systemd = _Systemd(
        events,
        start_error=(KeyboardInterrupt("stop") if phase == "systemd" else None),
        publish_before_start_error=phase == "systemd",
    )
    guard = _Guard(
        events,
        install_error=(KeyboardInterrupt("stop") if phase == "guard" else None),
        publish_before_install_error=phase == "guard",
    )

    with pytest.raises(KeyboardInterrupt, match="probe_execution_interrupted"):
        _broker(
            events,
            channels=channels,
            systemd=systemd,
            guard=guard,
        ).execute(_received_request(), timeout_seconds=5.0)

    assert events[-1] == "channels.close"
    if phase in {"systemd", "guard"}:
        assert "systemd.cancel" in events
    if phase == "guard":
        assert events.index("systemd.cancel") < events.index("guard.release")


def test_probe_execution_never_releases_guard_until_unit_collection_is_proven() -> None:
    events: list[str] = []
    now = [100.0]
    systemd = _Systemd(
        events,
        cancel_error=RuntimeError("unit still live"),
        collect_on_cancel=False,
    )
    guard = _Guard(events)

    def expire_after_guard() -> float:
        if "guard.install" in events:
            now[0] = 110.0
        return now[0]

    broker = _broker(
        events,
        systemd=systemd,
        guard=guard,
        monotonic=expire_after_guard,
    )
    with pytest.raises(ProbeExecutionError, match="probe_execution_and_cleanup_failed"):
        broker.execute(_received_request(), timeout_seconds=5.0)

    assert "systemd.cancel" in events
    assert "guard.release" not in events
    assert "channels.close" not in events
    assert "channels.release_gate" not in events

    now[0] = 100.0
    systemd.cancel_error = None
    systemd.collect_on_cancel = True
    assert broker.retry_pending_cleanup(timeout_seconds=5.0) == 0
    assert events[-3:] == ["systemd.cancel", "guard.release", "channels.close"]


def test_probe_execution_sanitizes_adapter_cleanup_errors_in_interrupt_group() -> None:
    events: list[str] = []
    guard = _Guard(
        events,
        install_error=KeyboardInterrupt("stop"),
        release_error=RuntimeError("rtsp://user:secret@example.invalid"),
        publish_before_install_error=True,
    )

    with pytest.raises(BaseExceptionGroup) as raised:
        _broker(events, guard=guard).execute(_received_request(), timeout_seconds=5.0)

    rendered = str(raised.value)
    assert "secret" not in rendered
    assert any(isinstance(item, KeyboardInterrupt) for item in raised.value.exceptions)
    assert any(isinstance(item, ProbeExecutionError) for item in raised.value.exceptions)


@pytest.mark.parametrize("timeout", [False, 0, -1, 61, float("inf"), "5"])
def test_probe_execution_rejects_invalid_timeout_without_consuming_input(
    timeout: object,
) -> None:
    received = _received_request()

    with pytest.raises(ProbeExecutionError, match="probe_execution_timeout_invalid"):
        _broker([]).execute(received, timeout_seconds=timeout)  # type: ignore[arg-type]

    received.close()


@pytest.mark.parametrize(
    ("wall_clock", "reason"),
    [
        (lambda: True, "probe_execution_timeout"),
        (lambda: 1_799_999_900_000, "probe_execution_request_invalid"),
        (
            lambda: (_ for _ in ()).throw(OSError("clock failed")),
            "probe_execution_timeout",
        ),
    ],
)
def test_probe_execution_rejects_untrusted_wall_clock_or_deadline_window(
    wall_clock: Callable[[], int],
    reason: str,
) -> None:
    received = _received_request()

    with pytest.raises(ProbeExecutionError, match=reason):
        _broker([], wall_clock_ms=wall_clock).execute(received, timeout_seconds=5.0)

    received.close()


@pytest.mark.parametrize(
    ("output", "decoder", "reason"),
    [
        (b"", _Decoder(), "probe_execution_result_invalid"),
        (b"x" * 65_537, _Decoder(), "probe_execution_result_invalid"),
        (
            b'{"streams":[]}',
            _Decoder(ValueError("rtsp://user:secret@example.invalid")),
            "probe_execution_result_invalid",
        ),
        (b'{"streams":[]}', _Decoder(object()), "probe_execution_result_invalid"),
    ],
)
def test_probe_execution_rejects_untyped_or_unbounded_result(
    output: bytes,
    decoder: _Decoder,
    reason: str,
) -> None:
    events: list[str] = []

    with pytest.raises(ProbeExecutionError, match=reason) as raised:
        _broker(
            events,
            systemd=_Systemd(events, output=output),
            decoder=decoder,
        ).execute(_received_request(), timeout_seconds=5.0)

    assert "secret" not in str(raised.value)
    assert events[-2:] == ["guard.release", "channels.close"]


def test_probe_execution_retries_idempotent_channel_close_after_cleanup_error() -> None:
    events: list[str] = []
    channels = _ChannelFactory(
        events,
        close_error=RuntimeError("rtsp://user:secret@example.invalid"),
    )
    broker = _broker(events, channels=channels)

    with pytest.raises(ProbeExecutionError, match="probe_execution_cleanup_failed"):
        broker.execute(_received_request(), timeout_seconds=5.0)

    assert broker.retry_pending_cleanup(timeout_seconds=5.0) == 0
    assert events[-1] == "channels.close"


def test_probe_execution_rejects_duplicate_request_while_cleanup_is_pending() -> None:
    events: list[str] = []
    systemd = _Systemd(
        events,
        collect_before_read_error=False,
        collect_on_cancel=False,
    )
    broker = _broker(events, systemd=systemd)
    first = _received_request()

    with pytest.raises(ProbeExecutionError, match="probe_execution_cleanup_pending"):
        broker.execute(first, timeout_seconds=5.0)
    duplicate = _received_for_request(first.request)
    with pytest.raises(ProbeExecutionError, match="probe_execution_already_active"):
        broker.execute(duplicate, timeout_seconds=5.0)

    duplicate.close()
    systemd.collect_on_cancel = True
    assert broker.retry_pending_cleanup(timeout_seconds=5.0) == 0


def test_probe_execution_sanitizes_system_exit_and_cleanup_interruption() -> None:
    events: list[str] = []
    guard = _Guard(
        events,
        install_error=RuntimeError("primary secret"),
        release_error=SystemExit("cleanup secret"),
        publish_before_install_error=True,
    )

    with pytest.raises(BaseExceptionGroup) as raised:
        _broker(events, guard=guard).execute(_received_request(), timeout_seconds=5.0)

    assert "secret" not in str(raised.value)
    assert any(isinstance(item, ProbeExecutionError) for item in raised.value.exceptions)
    assert any(isinstance(item, SystemExit) for item in raised.value.exceptions)


def test_probe_execution_rejects_controller_that_does_not_publish_unit_ownership() -> None:
    events: list[str] = []
    systemd = _Systemd(events, publish_on_start=False)

    with pytest.raises(ProbeExecutionError, match="probe_execution_ownership_invalid"):
        _broker(events, systemd=systemd).execute(
            _received_request(),
            timeout_seconds=5.0,
        )

    assert events[-1] == "channels.close"


def test_probe_execution_keeps_guard_when_release_is_not_proven() -> None:
    events: list[str] = []
    guard = _Guard(events, release_callback=False)
    broker = _broker(events, guard=guard)

    with pytest.raises(ProbeExecutionError, match="probe_execution_cleanup_pending"):
        broker.execute(_received_request(), timeout_seconds=5.0)

    assert events[-1] == "guard.release"
    assert "channels.close" not in events
    guard.release_callback = True
    assert broker.retry_pending_cleanup(timeout_seconds=5.0) == 0
    assert events[-2:] == ["guard.release", "channels.close"]


@pytest.mark.parametrize(
    "monotonic",
    [
        lambda: float("nan"),
        lambda: (_ for _ in ()).throw(OSError("clock failed")),
    ],
)
def test_probe_execution_rejects_invalid_monotonic_clock(
    monotonic: Callable[[], float],
) -> None:
    received = _received_request()

    with pytest.raises(ProbeExecutionError, match="probe_execution_timeout_invalid"):
        _broker([], monotonic=monotonic).execute(received, timeout_seconds=5.0)

    received.close()


def test_probe_execution_rejects_non_received_value() -> None:
    with pytest.raises(ProbeExecutionError, match="probe_execution_request_invalid"):
        _broker([]).execute(object(), timeout_seconds=5.0)  # type: ignore[arg-type]


def test_cleanup_retry_ignores_an_execution_that_is_still_reading() -> None:
    events: list[str] = []
    read_started = Event()
    read_release = Event()
    systemd = _Systemd(
        events,
        read_started=read_started,
        read_release=read_release,
    )
    broker = _broker(events, systemd=systemd)
    outcome: list[ProbeExecutionResult] = []

    execution = Thread(
        target=lambda: outcome.append(
            broker.execute(_received_request(), timeout_seconds=5.0)
        )
    )
    execution.start()
    assert read_started.wait(timeout=5.0)

    assert broker.retry_pending_cleanup(timeout_seconds=1.0) == 0
    assert "systemd.cancel" not in events

    read_release.set()
    execution.join(timeout=5.0)
    assert not execution.is_alive()
    assert len(outcome) == 1


def test_probe_execution_requires_successful_unit_before_guard_startup_recovery() -> None:
    events: list[str] = []
    broker = _broker(events, reconcile=False)
    received = _received_request()

    with pytest.raises(ProbeExecutionError, match="probe_execution_recovery_required"):
        broker.execute(received, timeout_seconds=5.0)

    assert events == []
    received.close()


def test_probe_execution_startup_adapter_keeps_unit_before_guard_order() -> None:
    events: list[str] = []
    recovery = ProbeExecutionStartupRecovery(
        units=_UnitStartupReconciler(events, 0),
        guards=_GuardStartupReconciler(events, 0),
    )

    assert recovery.reconcile_units(timeout_seconds=1.0) == 0
    assert recovery.reconcile_guards(timeout_seconds=1.0) == 0
    assert events == ["units", "guards"]


def test_probe_execution_stays_disabled_while_startup_recovery_is_unresolved() -> None:
    recovery = _Recovery(unit_unresolved=1)
    broker = _broker([], recovery=recovery, reconcile=False)

    assert broker.reconcile_startup(timeout_seconds=5.0) == 1
    assert recovery.events == ["recovery.units"]
    received = _received_request()
    with pytest.raises(ProbeExecutionError, match="probe_execution_recovery_required"):
        broker.execute(received, timeout_seconds=5.0)
    received.close()

    recovery.unit_unresolved = 0
    assert broker.reconcile_startup(timeout_seconds=5.0) == 0
    assert recovery.events[-2:] == ["recovery.units", "recovery.guards"]
    assert isinstance(
        broker.execute(_received_request(), timeout_seconds=5.0),
        ProbeExecutionResult,
    )


def test_probe_execution_sanitizes_startup_recovery_failure() -> None:
    broker = _broker(
        [],
        recovery=_Recovery(error=RuntimeError("rtsp://user:secret@example.invalid")),
        reconcile=False,
    )

    with pytest.raises(ProbeExecutionError, match="probe_execution_recovery_failed") as raised:
        broker.reconcile_startup(timeout_seconds=5.0)

    assert "secret" not in str(raised.value)


def test_probe_execution_does_not_enable_until_owned_guards_are_reconciled() -> None:
    recovery = _Recovery(guard_unresolved=1)
    broker = _broker([], recovery=recovery, reconcile=False)

    assert broker.reconcile_startup(timeout_seconds=5.0) == 1
    assert recovery.events == ["recovery.units", "recovery.guards"]
    received = _received_request()
    with pytest.raises(ProbeExecutionError, match="probe_execution_recovery_required"):
        broker.execute(received, timeout_seconds=5.0)
    received.close()


def test_startup_recovery_refuses_to_race_an_active_execution() -> None:
    events: list[str] = []
    read_started = Event()
    read_release = Event()
    broker = _broker(
        events,
        systemd=_Systemd(
            events,
            read_started=read_started,
            read_release=read_release,
        ),
    )
    execution = Thread(
        target=lambda: broker.execute(_received_request(), timeout_seconds=5.0)
    )
    execution.start()
    assert read_started.wait(timeout=5.0)

    with pytest.raises(ProbeExecutionError, match="probe_execution_recovery_busy"):
        broker.reconcile_startup(timeout_seconds=1.0)

    read_release.set()
    execution.join(timeout=5.0)
    assert not execution.is_alive()


def test_only_one_cleanup_sweep_can_claim_a_pending_execution() -> None:
    events: list[str] = []
    systemd = _Systemd(
        events,
        collect_before_read_error=False,
        collect_on_cancel=False,
    )
    broker = _broker(events, systemd=systemd)
    with pytest.raises(ProbeExecutionError, match="probe_execution_cleanup_pending"):
        broker.execute(_received_request(), timeout_seconds=5.0)

    cancel_started = Event()
    cancel_release = Event()
    systemd.cancel_started = cancel_started
    systemd.cancel_release = cancel_release
    systemd.collect_on_cancel = True
    outcomes: list[int] = []
    sweep = Thread(
        target=lambda: outcomes.append(
            broker.retry_pending_cleanup(timeout_seconds=5.0)
        )
    )
    sweep.start()
    assert cancel_started.wait(timeout=5.0)

    assert broker.retry_pending_cleanup(timeout_seconds=1.0) == 1
    assert events.count("systemd.cancel") == 2

    cancel_release.set()
    sweep.join(timeout=5.0)
    assert not sweep.is_alive()
    assert outcomes == [0]


def test_execute_finalization_interruption_leaves_collected_record_retryable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    broker = _broker([])
    finalize = broker._finalize_ownership
    interrupted = False

    def interrupt_once(request_id: UUID, ownership: object) -> None:
        nonlocal interrupted
        if not interrupted:
            interrupted = True
            raise KeyboardInterrupt("between collection and ledger removal")
        finalize(request_id, ownership)  # type: ignore[arg-type]

    monkeypatch.setattr(broker, "_finalize_ownership", interrupt_once)
    with pytest.raises(KeyboardInterrupt, match="ledger removal"):
        broker.execute(_received_request(), timeout_seconds=5.0)

    monkeypatch.setattr(broker, "_finalize_ownership", finalize)
    assert broker.retry_pending_cleanup(timeout_seconds=5.0) == 0


def test_sweep_finalization_interruption_releases_claim_for_next_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    systemd = _Systemd(
        events,
        collect_before_read_error=False,
        collect_on_cancel=False,
    )
    broker = _broker(events, systemd=systemd)
    with pytest.raises(ProbeExecutionError, match="probe_execution_cleanup_pending"):
        broker.execute(_received_request(), timeout_seconds=5.0)
    systemd.collect_on_cancel = True
    finalize = broker._finalize_ownership
    interrupted = False

    def interrupt_once(request_id: UUID, ownership: object) -> None:
        nonlocal interrupted
        if not interrupted:
            interrupted = True
            raise KeyboardInterrupt("during sweep finalization")
        finalize(request_id, ownership)  # type: ignore[arg-type]

    monkeypatch.setattr(broker, "_finalize_ownership", interrupt_once)
    with pytest.raises(KeyboardInterrupt, match="sweep finalization"):
        broker.retry_pending_cleanup(timeout_seconds=5.0)

    monkeypatch.setattr(broker, "_finalize_ownership", finalize)
    assert broker.retry_pending_cleanup(timeout_seconds=5.0) == 0
