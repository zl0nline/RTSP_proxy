from __future__ import annotations

import os
import socket
import sys
import threading
from datetime import UTC, datetime, timedelta, tzinfo
from ipaddress import ip_network
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from rtsp_proxy.probe_broker import (
    ProbeBrokerResponse,
    receive_probe_broker_request,
    send_probe_broker_response,
)
from rtsp_proxy.probe_client import ProbeClientError, UnixProbeBrokerClient
from rtsp_proxy.probe_security import AdmittedProbeEndpoint, ProbeEndpointAdmission
from rtsp_proxy.probes import ProbeExecutionResult, ProbeFailureClass, ProbeOutcome

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux sealed broker input")

NOW = datetime(2026, 8, 31, 20, 0, tzinfo=UTC)


class _BrokenTimezone(tzinfo):
    def utcoffset(self, _value: datetime | None) -> timedelta | None:
        raise ValueError("broken timezone")

    def dst(self, _value: datetime | None) -> timedelta | None:
        return None

    def tzname(self, _value: datetime | None) -> str | None:
        return "broken"


def _endpoint() -> AdmittedProbeEndpoint:
    return ProbeEndpointAdmission(
        site_key="site-a",
        allowed_networks=(ip_network("10.0.0.0/24"),),
        resolve=lambda _host: ("10.0.0.8",),
    ).admit("rtsp://camera:secret@camera.internal/live")


def _listener(path: Path) -> socket.socket:
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    listener.listen(1)
    return listener


def test_client_executes_one_admitted_endpoint_through_real_unix_transport(
    tmp_path: Path,
) -> None:
    endpoint = _endpoint()
    request_id = uuid4()
    socket_path = tmp_path / "broker.sock"
    listener = _listener(socket_path)
    failure: list[BaseException] = []

    def serve() -> None:
        try:
            connection, _ = listener.accept()
            with connection, receive_probe_broker_request(
                connection,
                expected_uid=os.geteuid(),
                expected_gid=os.getegid(),
                request_timeout_seconds=1,
                wall_clock_ms=lambda: int(NOW.timestamp() * 1_000),
            ) as received:
                assert received.request.request_id == request_id
                assert received.request.endpoint_generation == endpoint.identity.generation
                send_probe_broker_response(
                    connection,
                    ProbeBrokerResponse(
                        request_id=request_id,
                        endpoint_generation=endpoint.identity.generation,
                        result=ProbeExecutionResult(
                            outcome=ProbeOutcome.HEALTHY,
                            completed_at=NOW + timedelta(milliseconds=10),
                            video_codec="h264",
                        ),
                    ),
                    timeout_seconds=1,
                )
        except BaseException as error:
            failure.append(error)

    server = threading.Thread(target=serve)
    server.start()
    try:
        result = UnixProbeBrokerClient(
            socket_path=socket_path,
            expected_server_uid=os.geteuid(),
            expected_server_gid=os.getegid(),
            clock=lambda: NOW,
        ).execute(
            request_id=request_id,
            endpoint=endpoint,
            deadline_at=NOW + timedelta(seconds=5),
        )
    finally:
        server.join(timeout=2)
        listener.close()
    assert not server.is_alive()
    assert failure == []
    assert result.outcome is ProbeOutcome.HEALTHY
    assert result.video_codec == "h264"


def test_client_normalizes_unavailable_broker_without_exposing_endpoint(
    tmp_path: Path,
) -> None:
    endpoint = _endpoint()
    result = UnixProbeBrokerClient(
        socket_path=tmp_path / "absent.sock",
        expected_server_uid=os.geteuid(),
        expected_server_gid=os.getegid(),
        clock=lambda: NOW,
    ).execute(
        request_id=uuid4(),
        endpoint=endpoint,
        deadline_at=NOW + timedelta(seconds=5),
    )
    assert result == ProbeExecutionResult(
        outcome=ProbeOutcome.INCONCLUSIVE,
        completed_at=NOW,
        failure_class=ProbeFailureClass.EXECUTOR,
    )
    assert "secret" not in repr(endpoint)


def test_client_rejects_unexpected_broker_identity(tmp_path: Path) -> None:
    socket_path = tmp_path / "broker.sock"
    listener = _listener(socket_path)

    def serve() -> None:
        connection, _ = listener.accept()
        connection.close()

    server = threading.Thread(target=serve)
    server.start()
    try:
        result = UnixProbeBrokerClient(
            socket_path=socket_path,
            expected_server_uid=os.geteuid() + 1,
            expected_server_gid=os.getegid(),
            clock=lambda: NOW,
        ).execute(
            request_id=uuid4(),
            endpoint=_endpoint(),
            deadline_at=NOW + timedelta(seconds=5),
        )
    finally:
        server.join(timeout=2)
        listener.close()
    assert not server.is_alive()
    assert result.outcome is ProbeOutcome.INCONCLUSIVE
    assert result.failure_class is ProbeFailureClass.EXECUTOR


def test_client_rejects_response_for_another_endpoint_generation(tmp_path: Path) -> None:
    endpoint = _endpoint()
    request_id = uuid4()
    socket_path = tmp_path / "broker.sock"
    listener = _listener(socket_path)
    failure: list[BaseException] = []

    def serve() -> None:
        try:
            connection, _ = listener.accept()
            with connection, receive_probe_broker_request(
                connection,
                expected_uid=os.geteuid(),
                expected_gid=os.getegid(),
                request_timeout_seconds=1,
                wall_clock_ms=lambda: int(NOW.timestamp() * 1_000),
            ) as received:
                send_probe_broker_response(
                    connection,
                    ProbeBrokerResponse(
                        request_id=received.request.request_id,
                        endpoint_generation=uuid4(),
                        result=ProbeExecutionResult(
                            outcome=ProbeOutcome.HEALTHY,
                            completed_at=NOW + timedelta(milliseconds=10),
                            video_codec="h264",
                        ),
                    ),
                    timeout_seconds=1,
                )
        except BaseException as error:
            failure.append(error)

    server = threading.Thread(target=serve)
    server.start()
    try:
        result = UnixProbeBrokerClient(
            socket_path=socket_path,
            expected_server_uid=os.geteuid(),
            expected_server_gid=os.getegid(),
            clock=lambda: NOW,
        ).execute(
            request_id=request_id,
            endpoint=endpoint,
            deadline_at=NOW + timedelta(seconds=5),
        )
    finally:
        server.join(timeout=2)
        listener.close()
    assert not server.is_alive()
    assert failure == []
    assert result.outcome is ProbeOutcome.INCONCLUSIVE
    assert result.failure_class is ProbeFailureClass.EXECUTOR


def test_client_rejects_invalid_policy_and_deadline(tmp_path: Path) -> None:
    with pytest.raises(ProbeClientError, match="probe_client_policy_invalid"):
        UnixProbeBrokerClient(socket_path=Path("relative.sock"))
    client = UnixProbeBrokerClient(
        socket_path=tmp_path / "broker.sock",
        expected_server_uid=os.geteuid(),
        expected_server_gid=os.getegid(),
        clock=lambda: NOW,
    )
    with pytest.raises(ProbeClientError, match="probe_client_deadline_invalid"):
        client.execute(
            request_id=uuid4(),
            endpoint=_endpoint(),
            deadline_at=NOW + timedelta(seconds=61),
        )


@pytest.mark.parametrize(
    "clock",
    (
        lambda: None,
        lambda: (_ for _ in ()).throw(OSError("clock unavailable")),
        lambda: datetime(2026, 8, 31, 20, 0, tzinfo=_BrokenTimezone()),
    ),
)
def test_client_rejects_invalid_clock(
    tmp_path: Path,
    clock: object,
) -> None:
    client = UnixProbeBrokerClient(
        socket_path=tmp_path / "broker.sock",
        expected_server_uid=os.geteuid(),
        expected_server_gid=os.getegid(),
        clock=clock,  # type: ignore[arg-type]
    )
    with pytest.raises(ProbeClientError, match="probe_client_clock_invalid"):
        client.execute(
            request_id=uuid4(),
            endpoint=_endpoint(),
            deadline_at=NOW + timedelta(seconds=5),
        )


def test_client_rejects_invalid_request(tmp_path: Path) -> None:
    client = UnixProbeBrokerClient(
        socket_path=tmp_path / "broker.sock",
        expected_server_uid=os.geteuid(),
        expected_server_gid=os.getegid(),
        clock=lambda: NOW,
    )
    with pytest.raises(ProbeClientError, match="probe_client_request_invalid"):
        client.execute(
            request_id=UUID(int=0),
            endpoint=_endpoint(),
            deadline_at=NOW + timedelta(seconds=5),
        )
