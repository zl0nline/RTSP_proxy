from __future__ import annotations

import logging
import os
import socket
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from ipaddress import ip_address, ip_network
from pathlib import Path
from threading import Event, Thread
from uuid import UUID

import pytest

from rtsp_proxy.probe_broker import (
    ProbeBrokerRequest,
    ReceivedProbeInput,
    receive_probe_broker_response,
    send_probe_broker_request,
)
from rtsp_proxy.probe_broker_service import (
    ProbeBrokerService,
    ProbeBrokerServiceError,
)
from rtsp_proxy.probe_executor import ProbeConnectGuardTarget, create_sealed_probe_input
from rtsp_proxy.probes import ProbeExecutionResult, ProbeFailureClass, ProbeOutcome

_REQUEST_ID = UUID("447a1c4e-4c79-4c50-8e51-42c4dfa5fb19")
_GENERATION = UUID("d7cbf9ca-5328-4ed2-a5eb-b9e1b0ca9914")
_NOW_MS = 1_800_000_000_000
_FFCONCAT = (
    b"ffconcat version 1.0\n"
    b"file 'rtsp://camera:secret@192.0.2.10:8554/live'\n"
    b"option rtsp_transport tcp\n"
    b"option rtsp_flags no_redirect\n"
    b"option rw_timeout 5000000\n"
)


def _request() -> ProbeBrokerRequest:
    return ProbeBrokerRequest(
        request_id=_REQUEST_ID,
        endpoint_generation=_GENERATION,
        target=ProbeConnectGuardTarget(
            address=ip_address("192.0.2.10"),
            port=8554,
        ),
        deadline_unix_ms=_NOW_MS + 10_000,
    )


class _Executor:
    def __init__(
        self,
        *,
        result: ProbeExecutionResult | None = None,
        error: Exception | None = None,
        unresolved: int = 0,
        cleanup_unresolved: int = 0,
        cleanup_error: BaseException | None = None,
        cleanup_wait_for: Event | None = None,
    ) -> None:
        self.result = result or ProbeExecutionResult(
            outcome=ProbeOutcome.HEALTHY,
            completed_at=datetime.fromtimestamp(_NOW_MS / 1_000, tz=UTC),
            video_codec="h264",
        )
        self.error = error
        self.unresolved = unresolved
        self.cleanup_unresolved = cleanup_unresolved
        self.cleanup_error = cleanup_error
        self.cleanup_wait_for = cleanup_wait_for
        self.events: list[str] = []

    def reconcile_startup(self, *, timeout_seconds: float) -> int:
        assert timeout_seconds > 0
        self.events.append("reconcile")
        return self.unresolved

    def execute(
        self,
        received: ReceivedProbeInput,
        *,
        timeout_seconds: float,
    ) -> ProbeExecutionResult:
        assert timeout_seconds > 0
        self.events.append("execute")
        close = received.close
        close()
        if self.error is not None:
            raise self.error
        return self.result

    def retry_pending_cleanup(self, *, timeout_seconds: float) -> int:
        assert timeout_seconds > 0
        self.events.append("retry")
        if self.cleanup_wait_for is not None:
            assert self.cleanup_wait_for.wait(timeout=5)
        if self.cleanup_error is not None:
            error = self.cleanup_error
            self.cleanup_error = None
            raise error
        return self.cleanup_unresolved


def _service(
    executor: _Executor,
    *,
    wall_clock_ms: Callable[[], int] = lambda: _NOW_MS,
) -> ProbeBrokerService:
    return ProbeBrokerService(
        executor=executor,
        expected_uid=os.getuid(),
        expected_gid=os.getgid(),
        allowed_networks=(ip_network("192.0.2.0/24"),),
        request_frame_timeout_seconds=1,
        response_frame_timeout_seconds=1,
        startup_timeout_seconds=5,
        cleanup_retry_timeout_seconds=1,
        max_workers=2,
        wall_clock_ms=wall_clock_ms,
    )


def _serve_once(service: ProbeBrokerService, connection: socket.socket) -> None:
    with connection:
        service.serve_connection(connection)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux AF_UNIX contract")
def test_probe_broker_service_returns_only_the_normalized_execution_result() -> None:
    executor = _Executor()
    service = _service(executor)
    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    descriptor = create_sealed_probe_input(_FFCONCAT)
    worker = Thread(target=_serve_once, args=(service, server))
    worker.start()
    try:
        send_probe_broker_request(client, _request(), descriptor, timeout_seconds=1)
        result = receive_probe_broker_response(
            client,
            expected_request=_request(),
            timeout_seconds=1,
        )
        assert result == executor.result
    finally:
        client.close()
        worker.join(timeout=2)
        server.close()
    assert executor.events == ["execute", "retry"]
    assert worker.is_alive() is False


@pytest.mark.skipif(sys.platform != "linux", reason="Linux AF_UNIX contract")
def test_probe_broker_service_maps_execution_failure_to_inconclusive(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger="rtsp_proxy.probe_broker_service")
    executor = _Executor(error=RuntimeError("secret from privileged boundary"))
    service = _service(executor)
    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    descriptor = create_sealed_probe_input(_FFCONCAT)
    worker = Thread(target=_serve_once, args=(service, server))
    worker.start()
    try:
        send_probe_broker_request(client, _request(), descriptor, timeout_seconds=1)
        result = receive_probe_broker_response(
            client,
            expected_request=_request(),
            timeout_seconds=1,
        )
        assert result == ProbeExecutionResult(
            outcome=ProbeOutcome.INCONCLUSIVE,
            completed_at=datetime.fromtimestamp(_NOW_MS / 1_000, tz=UTC),
            failure_class=ProbeFailureClass.EXECUTOR,
        )
        assert "secret" not in repr(result)
        assert "probe broker executor failure: probe_execution_failed" in caplog.text
        assert "secret from privileged boundary" not in caplog.text
    finally:
        client.close()
        worker.join(timeout=2)
        server.close()
    assert worker.is_alive() is False


@pytest.mark.skipif(sys.platform != "linux", reason="Linux AF_UNIX contract")
def test_probe_broker_service_maps_invalid_executor_result_to_inconclusive() -> None:
    executor = _Executor()
    executor.result = object()  # type: ignore[assignment]
    service = _service(executor)
    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    descriptor = create_sealed_probe_input(_FFCONCAT)
    worker = Thread(target=_serve_once, args=(service, server))
    worker.start()
    try:
        send_probe_broker_request(client, _request(), descriptor, timeout_seconds=1)
        result = receive_probe_broker_response(
            client,
            expected_request=_request(),
            timeout_seconds=1,
        )
        assert result.outcome is ProbeOutcome.INCONCLUSIVE
        assert result.failure_class is ProbeFailureClass.EXECUTOR
    finally:
        client.close()
        worker.join(timeout=2)
        server.close()
    assert executor.events == ["execute", "retry"]


@pytest.mark.skipif(sys.platform != "linux", reason="Linux AF_UNIX contract")
def test_probe_broker_service_does_not_execute_after_fatal_cleanup() -> None:
    executor = _Executor()
    service = _service(executor)
    service._publish_cleanup_failure()
    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    descriptor = create_sealed_probe_input(_FFCONCAT)
    worker = Thread(target=_serve_once, args=(service, server))
    worker.start()
    try:
        send_probe_broker_request(client, _request(), descriptor, timeout_seconds=1)
        result = receive_probe_broker_response(
            client,
            expected_request=_request(),
            timeout_seconds=1,
        )
        assert result.outcome is ProbeOutcome.INCONCLUSIVE
        assert result.failure_class is ProbeFailureClass.EXECUTOR
    finally:
        client.close()
        worker.join(timeout=2)
        server.close()
    assert executor.events == []
    assert worker.is_alive() is False


def test_probe_broker_service_refuses_readiness_until_startup_recovery_completes() -> None:
    executor = _Executor(unresolved=1)
    service = _service(executor)

    with pytest.raises(ProbeBrokerServiceError, match="probe_broker_recovery_required"):
        service.reconcile_startup()

    assert executor.events == ["reconcile"]


@pytest.mark.parametrize(
    ("expected_uid", "expected_gid", "max_workers"),
    [(-1, os.getgid(), 2), (os.getuid(), -1, 2), (os.getuid(), os.getgid(), 0)],
)
def test_probe_broker_service_rejects_invalid_policy(
    expected_uid: int,
    expected_gid: int,
    max_workers: int,
) -> None:
    with pytest.raises(ProbeBrokerServiceError, match="probe_broker_service_policy_invalid"):
        ProbeBrokerService(
            executor=_Executor(),
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            allowed_networks=(ip_network("192.0.2.0/24"),),
            request_frame_timeout_seconds=1,
            response_frame_timeout_seconds=1,
            startup_timeout_seconds=5,
            cleanup_retry_timeout_seconds=1,
            max_workers=max_workers,
        )


@pytest.mark.skipif(sys.platform != "linux", reason="Linux AF_UNIX contract")
def test_probe_broker_service_rejects_target_outside_root_owned_policy() -> None:
    executor = _Executor()
    service = ProbeBrokerService(
        executor=executor,
        expected_uid=os.getuid(),
        expected_gid=os.getgid(),
        allowed_networks=(ip_network("198.51.100.0/24"),),
        request_frame_timeout_seconds=1,
        response_frame_timeout_seconds=1,
        startup_timeout_seconds=5,
        cleanup_retry_timeout_seconds=1,
        max_workers=2,
        wall_clock_ms=lambda: _NOW_MS,
    )
    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    descriptor = create_sealed_probe_input(_FFCONCAT)
    worker = Thread(target=_serve_once, args=(service, server))
    worker.start()
    try:
        send_probe_broker_request(client, _request(), descriptor, timeout_seconds=1)
        client.shutdown(socket.SHUT_WR)
        assert client.recv(1) == b""
    finally:
        client.close()
        worker.join(timeout=2)
        server.close()
    assert executor.events == []
    assert worker.is_alive() is False


@pytest.mark.skipif(sys.platform != "linux", reason="Linux AF_UNIX contract")
def test_probe_broker_service_closes_secret_fd_when_deadline_expires_before_handoff() -> None:
    observed = [_NOW_MS, *([_NOW_MS + 9_995] * 5)]
    executor = _Executor()
    service = _service(executor, wall_clock_ms=lambda: observed.pop(0))
    baseline = len(tuple(Path("/proc/self/fd").iterdir()))
    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    descriptor = create_sealed_probe_input(_FFCONCAT)
    worker = Thread(target=_serve_once, args=(service, server))
    worker.start()
    try:
        send_probe_broker_request(client, _request(), descriptor, timeout_seconds=1)
        client.shutdown(socket.SHUT_WR)
        assert client.recv(1) == b""
    finally:
        client.close()
        worker.join(timeout=2)
        server.close()

    assert executor.events == []
    assert worker.is_alive() is False
    assert len(tuple(Path("/proc/self/fd").iterdir())) == baseline


@pytest.mark.parametrize("unresolved", [True, -1])
def test_probe_broker_service_rejects_invalid_recovery_result(
    unresolved: object,
) -> None:
    executor = _Executor()
    executor.unresolved = unresolved  # type: ignore[assignment]

    with pytest.raises(ProbeBrokerServiceError, match="probe_broker_recovery_failed"):
        _service(executor).reconcile_startup()


def test_probe_broker_service_sanitizes_recovery_failure() -> None:
    executor = _Executor()

    def fail_recovery(*, timeout_seconds: float) -> int:
        assert timeout_seconds == 5
        raise RuntimeError("privileged secret")

    executor.reconcile_startup = fail_recovery  # type: ignore[method-assign]

    with pytest.raises(ProbeBrokerServiceError, match=r"^probe_broker_recovery_failed$"):
        _service(executor).reconcile_startup()


def test_probe_broker_service_sanitizes_wall_clock_failure() -> None:
    def fail_clock() -> int:
        raise OSError("privileged clock detail")

    service = _service(_Executor(), wall_clock_ms=fail_clock)

    with pytest.raises(ProbeBrokerServiceError, match=r"^probe_broker_clock_invalid$"):
        service._remaining_request_seconds(_request().deadline_unix_ms)


def test_probe_broker_service_rejects_invalid_wall_clock_value() -> None:
    service = _service(_Executor(), wall_clock_ms=lambda: 0)

    with pytest.raises(ProbeBrokerServiceError, match=r"^probe_broker_clock_invalid$"):
        service._remaining_request_seconds(_request().deadline_unix_ms)


class _FiniteUnixListener(socket.socket):
    def __init__(self, connection: socket.socket) -> None:
        super().__init__(socket.AF_UNIX, socket.SOCK_STREAM)
        self._connection = connection
        self._accepted = False

    def accept(self) -> tuple[socket.socket, object]:
        if not self._accepted:
            self._accepted = True
            return self._connection, None
        raise KeyboardInterrupt


class _PollingUnixListener(socket.socket):
    def __init__(self, connection: socket.socket) -> None:
        super().__init__(socket.AF_UNIX, socket.SOCK_STREAM)
        self._next_connection: socket.socket | None = connection

    def accept(self) -> tuple[socket.socket, object]:
        if self._next_connection is not None:
            connection = self._next_connection
            self._next_connection = None
            return connection, None
        raise TimeoutError


class _AdmissionBarrierListener(socket.socket):
    def __init__(
        self,
        first: socket.socket,
        second: socket.socket,
        *,
        second_accept_waiting: Event,
        release_second_accept: Event,
    ) -> None:
        super().__init__(socket.AF_UNIX, socket.SOCK_STREAM)
        self._connections = [first, second]
        self._second_accept_waiting = second_accept_waiting
        self._release_second_accept = release_second_accept

    def accept(self) -> tuple[socket.socket, object]:
        if len(self._connections) == 2:
            return self._connections.pop(0), None
        if len(self._connections) == 1:
            self._second_accept_waiting.set()
            assert self._release_second_accept.wait(timeout=5)
            return self._connections.pop(0), None
        raise TimeoutError


def test_probe_broker_service_owns_worker_and_shutdown_cleanup() -> None:
    executor = _Executor()
    service = _service(executor)
    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    listener = _FiniteUnixListener(server)
    client.close()
    try:
        with pytest.raises(KeyboardInterrupt):
            service.serve_forever(listener)
    finally:
        listener.close()
        server.close()

    assert executor.events == ["reconcile", "retry"]


@pytest.mark.parametrize(
    "executor",
    [
        _Executor(cleanup_unresolved=1),
        _Executor(cleanup_error=RuntimeError("privileged secret")),
    ],
)
def test_probe_broker_service_exits_when_cleanup_cannot_be_proven(
    executor: _Executor,
) -> None:
    service = _service(executor)
    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    listener = _FiniteUnixListener(server)
    client.close()
    try:
        with pytest.raises(ProbeBrokerServiceError, match="probe_broker_cleanup_failed"):
            service.serve_forever(listener)
    finally:
        listener.close()
        server.close()

    assert executor.events[:1] == ["reconcile"]


@pytest.mark.skipif(sys.platform != "linux", reason="Linux AF_UNIX contract")
@pytest.mark.parametrize(
    "cleanup_error",
    [
        KeyboardInterrupt("cleanup interrupted"),
        BaseExceptionGroup(
            "cleanup interrupted",
            [KeyboardInterrupt("signal"), RuntimeError("privileged secret")],
        ),
    ],
)
def test_probe_broker_worker_cleanup_interruption_stops_acceptance(
    cleanup_error: BaseException,
) -> None:
    executor = _Executor(cleanup_error=cleanup_error)
    service = _service(executor)
    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    listener = _PollingUnixListener(server)
    descriptor = create_sealed_probe_input(_FFCONCAT)
    send_probe_broker_request(client, _request(), descriptor, timeout_seconds=1)
    try:
        with pytest.raises(ProbeBrokerServiceError, match="probe_broker_cleanup_failed"):
            service.serve_forever(listener)
    finally:
        client.close()
        listener.close()
        server.close()

    assert executor.events == ["reconcile", "execute", "retry", "retry"]


@pytest.mark.skipif(sys.platform != "linux", reason="Linux AF_UNIX contract")
def test_probe_broker_fatal_cleanup_atomically_closes_queued_admission() -> None:
    second_accept_waiting = Event()
    release_second_accept = Event()
    executor = _Executor(
        cleanup_error=KeyboardInterrupt("cleanup interrupted"),
        cleanup_wait_for=second_accept_waiting,
    )
    service = _service(executor)
    first_client, first_server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    second_client, second_server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    listener = _AdmissionBarrierListener(
        first_server,
        second_server,
        second_accept_waiting=second_accept_waiting,
        release_second_accept=release_second_accept,
    )
    first_descriptor = create_sealed_probe_input(_FFCONCAT)
    second_descriptor = create_sealed_probe_input(_FFCONCAT)
    send_probe_broker_request(
        first_client,
        _request(),
        first_descriptor,
        timeout_seconds=1,
    )
    send_probe_broker_request(
        second_client,
        ProbeBrokerRequest(
            request_id=UUID("86269d5a-fdb2-4afe-a0dc-c41a978b65d4"),
            endpoint_generation=_GENERATION,
            target=_request().target,
            deadline_unix_ms=_request().deadline_unix_ms,
        ),
        second_descriptor,
        timeout_seconds=1,
    )
    failures: list[BaseException] = []

    def serve() -> None:
        try:
            service.serve_forever(listener)
        except BaseException as error:
            failures.append(error)

    worker = Thread(target=serve)
    worker.start()
    try:
        assert second_accept_waiting.wait(timeout=5)
        assert service._cleanup_failed.wait(timeout=5)
        release_second_accept.set()
        worker.join(timeout=5)
        second_client.settimeout(1)
        try:
            closed = second_client.recv(1)
        except ConnectionResetError:
            closed = b""
        assert closed == b""
    finally:
        release_second_accept.set()
        first_client.close()
        second_client.close()
        listener.close()
        first_server.close()
        second_server.close()

    assert worker.is_alive() is False
    assert len(failures) == 1
    assert isinstance(failures[0], ProbeBrokerServiceError)
    assert str(failures[0]) == "probe_broker_cleanup_failed"
    assert executor.events.count("execute") == 1


def test_probe_broker_service_rejects_non_unix_listener() -> None:
    executor = _Executor()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(ProbeBrokerServiceError, match="probe_broker_listener_invalid"):
            _service(executor).serve_forever(listener)
    finally:
        listener.close()

    assert executor.events == []
