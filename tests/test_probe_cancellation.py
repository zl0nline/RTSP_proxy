from __future__ import annotations

import os
import socket
import sys
from collections.abc import Callable
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from ipaddress import ip_network
from pathlib import Path
from threading import Event, Thread
from uuid import uuid4

import pytest

import rtsp_proxy.probe_broker as broker_module
from rtsp_proxy.probe_broker import ReceivedProbeInput, receive_probe_broker_request
from rtsp_proxy.probe_broker_service import ProbeBrokerService
from rtsp_proxy.probe_client import UnixProbeBrokerClient
from rtsp_proxy.probe_security import ProbeEndpointAdmission
from rtsp_proxy.probes import ProbeExecutionResult, ProbeFailureClass, ProbeOutcome

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="Linux sealed input and peer identity"
)


def _execute(path: Path, cancelled: Callable[[], bool]) -> ProbeExecutionResult:
    endpoint = ProbeEndpointAdmission(
        site_key="test",
        allowed_networks=(ip_network("192.0.2.0/24"),),
        resolve=lambda _: ("192.0.2.10",),
    ).admit("rtsp://synthetic:canary@camera.invalid/live")
    return UnixProbeBrokerClient(
        socket_path=path,
        expected_server_uid=os.getuid(),
        expected_server_gid=os.getgid(),
    ).execute(
        request_id=uuid4(),
        endpoint=endpoint,
        deadline_at=datetime.now(UTC) + timedelta(seconds=30),
        cancelled=cancelled,
    )


@pytest.mark.parametrize("partial_frame", [b"", b"\x00", b"\x00\x00\x00\x10{"])
def test_client_cancels_waiting_and_partial_response_and_closes_socket(
    tmp_path: Path,
    partial_frame: bytes,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "broker.sock"
    cancelled = Event()
    waiting_after_prefix = Event()
    waits = 0
    expected_wait = 1 if not partial_frame else (3 if len(partial_frame) == 1 else 4)
    original_wait = broker_module._wait_until_readable

    def wait(*args: object, **kwargs: object) -> float:
        nonlocal waits
        waits += 1
        if waits == expected_wait:
            waiting_after_prefix.set()
        return original_wait(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(broker_module, "_wait_until_readable", wait)
    failures: list[BaseException] = []
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(path))
        listener.listen(1)
        listener.settimeout(3)

        def serve() -> None:
            try:
                connection, _ = listener.accept()
                with (
                    connection,
                    receive_probe_broker_request(
                        connection,
                        expected_uid=os.getuid(),
                        expected_gid=os.getgid(),
                        request_timeout_seconds=2,
                    ),
                ):
                    if partial_frame:
                        connection.sendall(partial_frame)
                    assert waiting_after_prefix.wait(2)
                    cancelled.set()
                    connection.settimeout(2)
                    # Closing a stream with unread partial response bytes may reset it.
                    with suppress(ConnectionResetError):
                        assert connection.recv(1) == b""
            except BaseException as error:
                failures.append(error)

        worker = Thread(target=serve)
        worker.start()
        try:
            result = _execute(path, cancelled.is_set)
        finally:
            cancelled.set()
            worker.join(4)
        assert not worker.is_alive()
        assert failures == []
        assert result.outcome is ProbeOutcome.INCONCLUSIVE
        assert result.failure_class is ProbeFailureClass.EXECUTOR


class _WaitingExecutor:
    def __init__(self) -> None:
        self.started = Event()
        self.finished = Event()

    def reconcile_startup(self, *, timeout_seconds: float) -> int:
        return 0

    def execute(
        self,
        received: ReceivedProbeInput,
        *,
        timeout_seconds: float,
        cancelled: Callable[[], bool] | None = None,
    ) -> ProbeExecutionResult:
        assert cancelled is not None
        self.started.set()
        deadline = datetime.now(UTC) + timedelta(seconds=3)
        try:
            while not cancelled():
                if datetime.now(UTC) >= deadline:
                    raise AssertionError("cancellation did not reach executor")
                self.finished.wait(0.01)
            return ProbeExecutionResult(
                outcome=ProbeOutcome.INCONCLUSIVE,
                completed_at=datetime.now(UTC),
                failure_class=ProbeFailureClass.EXECUTOR,
            )
        finally:
            received.close()
            self.finished.set()

    def retry_pending_cleanup(self, *, timeout_seconds: float) -> int:
        return 0


@pytest.mark.parametrize("cause", ["client", "shutdown"])
def test_cancellation_crosses_real_client_service_boundary(tmp_path: Path, cause: str) -> None:
    path = tmp_path / "broker.sock"
    executor = _WaitingExecutor()
    service = ProbeBrokerService(
        executor=executor,
        expected_uid=os.getuid(),
        expected_gid=os.getgid(),
        allowed_networks=(ip_network("192.0.2.0/24"),),
        request_frame_timeout_seconds=1,
        response_frame_timeout_seconds=1,
        startup_timeout_seconds=1,
        cleanup_retry_timeout_seconds=1,
        max_workers=1,
    )
    cancelled = Event()
    failures: list[BaseException] = []
    results: list[ProbeExecutionResult] = []
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(path))
        listener.listen(1)

        def serve() -> None:
            try:
                service.serve_forever(listener)
            except BaseException as error:
                failures.append(error)

        def call() -> None:
            try:
                results.append(_execute(path, cancelled.is_set))
            except BaseException as error:
                failures.append(error)

        server = Thread(target=serve)
        client = Thread(target=call)
        server.start()
        client.start()
        try:
            assert executor.started.wait(2)
            if cause == "client":
                cancelled.set()
            else:
                service.request_shutdown()
            assert executor.finished.wait(2)
        finally:
            cancelled.set()
            service.request_shutdown()
            client.join(4)
            server.join(4)
        assert not client.is_alive()
        assert not server.is_alive()
        assert failures == []
        assert len(results) == 1
        assert results[0].outcome is ProbeOutcome.INCONCLUSIVE
