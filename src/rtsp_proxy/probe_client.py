from __future__ import annotations

import math
import os
import socket
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from rtsp_proxy.probe_broker import (
    PROBE_BROKER_MAX_DEADLINE_MS,
    ProbeBrokerRequest,
    receive_probe_broker_response,
    require_probe_broker_peer,
    send_probe_broker_request,
)
from rtsp_proxy.probe_executor import ProbeConnectGuardTarget, create_sealed_probe_input
from rtsp_proxy.probe_security import AdmittedProbeEndpoint
from rtsp_proxy.probes import ProbeExecutionResult, ProbeFailureClass, ProbeOutcome

_BROKER_SOCKET = Path("/run/rtsp-proxy-probe-broker/control.sock")
_ROOT_UID = 0
_ROOT_GID = 0


class ProbeClientError(RuntimeError):
    """The unprivileged broker client policy is invalid or unavailable."""


class UnixProbeBrokerClient:
    """Execute one admitted endpoint through the authenticated local root broker."""

    def __init__(
        self,
        *,
        socket_path: Path = _BROKER_SOCKET,
        expected_server_uid: int = _ROOT_UID,
        expected_server_gid: int = _ROOT_GID,
        frame_timeout_seconds: float = 2.0,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if (
            not isinstance(socket_path, Path)
            or not socket_path.is_absolute()
            or ".." in socket_path.parts
            or len(os.fsencode(socket_path)) > 100
            or isinstance(expected_server_uid, bool)
            or not isinstance(expected_server_uid, int)
            or expected_server_uid < 0
            or isinstance(expected_server_gid, bool)
            or not isinstance(expected_server_gid, int)
            or expected_server_gid < 0
            or isinstance(frame_timeout_seconds, bool)
            or not isinstance(frame_timeout_seconds, (int, float))
            or not math.isfinite(frame_timeout_seconds)
            or not 0.01 <= frame_timeout_seconds <= 5.0
            or not callable(clock)
        ):
            raise ProbeClientError("probe_client_policy_invalid")
        self._socket_path = socket_path
        self._expected_server_uid = expected_server_uid
        self._expected_server_gid = expected_server_gid
        self._frame_timeout_seconds = float(frame_timeout_seconds)
        self._clock = clock

    def execute(
        self,
        *,
        request_id: UUID,
        endpoint: AdmittedProbeEndpoint,
        deadline_at: datetime,
        cancelled: Callable[[], bool] | None = None,
    ) -> ProbeExecutionResult:
        """Return only a normalized result; local infrastructure failures are inconclusive."""

        if (
            not isinstance(request_id, UUID)
            or request_id.version != 4
            or not isinstance(endpoint, AdmittedProbeEndpoint)
            or not isinstance(deadline_at, datetime)
            or deadline_at.tzinfo is None
        ):
            raise ProbeClientError("probe_client_request_invalid")
        started_at = self._read_clock()
        deadline_unix_ms = _unix_milliseconds(deadline_at)
        remaining_seconds = self._remaining_seconds(
            deadline_unix_ms=deadline_unix_ms,
            observed_at=started_at,
        )
        io_timeout_microseconds = max(
            100_000,
            min(30_000_000, int(remaining_seconds * 1_000_000)),
        )
        request = ProbeBrokerRequest(
            request_id=request_id,
            endpoint_generation=endpoint.identity.generation,
            target=ProbeConnectGuardTarget(
                address=endpoint.identity.address,
                port=endpoint.identity.port,
            ),
            deadline_unix_ms=deadline_unix_ms,
        )
        descriptor = -1
        connection: socket.socket | None = None
        try:
            if cancelled is not None and cancelled():
                raise ProbeClientError("probe_client_cancelled")
            descriptor = create_sealed_probe_input(
                endpoint.ffconcat_payload(
                    io_timeout_microseconds=io_timeout_microseconds,
                )
            )
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            connection.settimeout(
                min(self._frame_timeout_seconds, remaining_seconds)
            )
            connection.connect(str(self._socket_path))
            require_probe_broker_peer(
                connection,
                expected_uid=self._expected_server_uid,
                expected_gid=self._expected_server_gid,
            )
            owned_descriptor = descriptor
            descriptor = -1
            send_probe_broker_request(
                connection,
                request,
                owned_descriptor,
                timeout_seconds=min(
                    self._frame_timeout_seconds,
                    self._remaining_seconds(
                        deadline_unix_ms=deadline_unix_ms,
                        observed_at=self._read_clock(),
                    ),
                ),
            )
            return receive_probe_broker_response(
                connection,
                expected_request=request,
                cancelled=cancelled,
                timeout_seconds=self._remaining_seconds(
                    deadline_unix_ms=deadline_unix_ms,
                    observed_at=self._read_clock(),
                ),
            )
        except (OSError, RuntimeError, TimeoutError, ValueError):
            return ProbeExecutionResult(
                outcome=ProbeOutcome.INCONCLUSIVE,
                completed_at=self._read_clock(),
                failure_class=ProbeFailureClass.EXECUTOR,
            )
        finally:
            if connection is not None:
                connection.close()
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    raise ProbeClientError("probe_client_cleanup_failed") from None

    def _read_clock(self) -> datetime:
        try:
            observed_at = self._clock()
        except (ArithmeticError, OSError, TypeError, ValueError):
            raise ProbeClientError("probe_client_clock_invalid") from None
        if not isinstance(observed_at, datetime) or observed_at.tzinfo is None:
            raise ProbeClientError("probe_client_clock_invalid")
        try:
            normalized = observed_at.astimezone(UTC)
        except (OverflowError, OSError, ValueError):
            raise ProbeClientError("probe_client_clock_invalid") from None
        return normalized

    @staticmethod
    def _remaining_seconds(*, deadline_unix_ms: int, observed_at: datetime) -> float:
        remaining_ms = deadline_unix_ms - _unix_milliseconds(observed_at)
        if not 10 <= remaining_ms <= PROBE_BROKER_MAX_DEADLINE_MS:
            raise ProbeClientError("probe_client_deadline_invalid")
        return remaining_ms / 1_000


def _unix_milliseconds(value: datetime) -> int:
    try:
        return int(value.astimezone(UTC).timestamp() * 1_000)
    except (OverflowError, OSError, ValueError):
        raise ProbeClientError("probe_client_clock_invalid") from None
