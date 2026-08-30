from __future__ import annotations

import math
import socket
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from ipaddress import IPv4Network, IPv6Network
from threading import BoundedSemaphore, Event, Lock
from typing import Protocol

from rtsp_proxy.probe_broker import (
    ProbeBrokerError,
    ProbeBrokerResponse,
    ReceivedProbeInput,
    receive_probe_broker_request,
    send_probe_broker_response,
)
from rtsp_proxy.probes import ProbeExecutionResult, ProbeFailureClass, ProbeOutcome

_MAX_WORKERS = 128
_MAX_EXECUTION_SECONDS = 60.0


class ProbeBrokerServiceError(RuntimeError):
    """The installed root broker cannot safely accept probe work."""


class ProbeExecutor(Protocol):
    """Narrow coordinator seam owned by the privileged broker process."""

    def reconcile_startup(self, *, timeout_seconds: float) -> int: ...

    def execute(
        self,
        received: ReceivedProbeInput,
        *,
        timeout_seconds: float,
    ) -> ProbeExecutionResult: ...

    def retry_pending_cleanup(self, *, timeout_seconds: float) -> int: ...


class ProbeBrokerService:
    """Authenticate local requests and execute them through the fixed coordinator."""

    def __init__(
        self,
        *,
        executor: ProbeExecutor,
        expected_uid: int,
        expected_gid: int,
        allowed_networks: tuple[IPv4Network | IPv6Network, ...],
        request_frame_timeout_seconds: float,
        response_frame_timeout_seconds: float,
        startup_timeout_seconds: float,
        cleanup_retry_timeout_seconds: float,
        max_workers: int,
        wall_clock_ms: Callable[[], int] = lambda: int(time.time() * 1_000),
    ) -> None:
        if (
            not hasattr(executor, "reconcile_startup")
            or not hasattr(executor, "execute")
            or not hasattr(executor, "retry_pending_cleanup")
            or isinstance(expected_uid, bool)
            or not isinstance(expected_uid, int)
            or expected_uid < 0
            or isinstance(expected_gid, bool)
            or not isinstance(expected_gid, int)
            or expected_gid < 0
            or not self._valid_networks(allowed_networks)
            or not self._bounded_timeout(request_frame_timeout_seconds, maximum=5)
            or not self._bounded_timeout(response_frame_timeout_seconds, maximum=5)
            or not self._bounded_timeout(startup_timeout_seconds, maximum=60)
            or not self._bounded_timeout(cleanup_retry_timeout_seconds, maximum=60)
            or isinstance(max_workers, bool)
            or not isinstance(max_workers, int)
            or not 1 <= max_workers <= _MAX_WORKERS
            or not callable(wall_clock_ms)
        ):
            raise ProbeBrokerServiceError("probe_broker_service_policy_invalid")
        self._executor = executor
        self._expected_uid = expected_uid
        self._expected_gid = expected_gid
        self._allowed_networks = allowed_networks
        self._request_frame_timeout_seconds = float(request_frame_timeout_seconds)
        self._response_frame_timeout_seconds = float(response_frame_timeout_seconds)
        self._startup_timeout_seconds = float(startup_timeout_seconds)
        self._cleanup_retry_timeout_seconds = float(cleanup_retry_timeout_seconds)
        self._max_workers = max_workers
        self._wall_clock_ms = wall_clock_ms
        self._cleanup_failed = Event()
        self._admission_lock = Lock()

    def reconcile_startup(self) -> None:
        try:
            unresolved = self._executor.reconcile_startup(
                timeout_seconds=self._startup_timeout_seconds
            )
        except Exception:
            raise ProbeBrokerServiceError("probe_broker_recovery_failed") from None
        if isinstance(unresolved, bool) or not isinstance(unresolved, int) or unresolved < 0:
            raise ProbeBrokerServiceError("probe_broker_recovery_failed")
        if unresolved:
            raise ProbeBrokerServiceError("probe_broker_recovery_required")

    def serve_connection(self, connection: socket.socket) -> None:
        request = None
        execution_started = False
        received: ReceivedProbeInput | None = None
        try:
            received = receive_probe_broker_request(
                connection,
                expected_uid=self._expected_uid,
                expected_gid=self._expected_gid,
                request_timeout_seconds=self._request_frame_timeout_seconds,
                wall_clock_ms=self._wall_clock_ms,
            )
            request = received.request
            if not any(
                request.target.address in network
                for network in self._allowed_networks
                if network.version == request.target.address.version
            ):
                raise ProbeBrokerServiceError("probe_broker_target_denied")
            try:
                remaining = self._remaining_request_seconds(request.deadline_unix_ms)
                with self._admission_lock:
                    if self._cleanup_failed.is_set():
                        raise ProbeBrokerServiceError("probe_broker_cleanup_failed")
                    execution_started = True
                result = self._executor.execute(
                    received,
                    timeout_seconds=remaining,
                )
                if not isinstance(result, ProbeExecutionResult):
                    raise ProbeBrokerServiceError("probe_broker_execution_failed")
            except Exception:
                result = ProbeExecutionResult(
                    outcome=ProbeOutcome.INCONCLUSIVE,
                    completed_at=self._completed_at(),
                    failure_class=ProbeFailureClass.EXECUTOR,
                )
            response = ProbeBrokerResponse(
                request_id=request.request_id,
                endpoint_generation=request.endpoint_generation,
                result=result,
            )
            remaining = self._remaining_request_seconds(request.deadline_unix_ms)
            send_probe_broker_response(
                connection,
                response,
                timeout_seconds=min(self._response_frame_timeout_seconds, remaining),
            )
        except (ProbeBrokerError, ProbeBrokerServiceError, ValueError):
            return
        finally:
            if received is not None:
                try:
                    received.close()
                except BaseException:
                    self._publish_cleanup_failure()
            if execution_started and not self._cleanup_is_resolved():
                self._publish_cleanup_failure()

    def serve_forever(self, listener: socket.socket) -> None:
        if (
            not isinstance(listener, socket.socket)
            or listener.family != socket.AF_UNIX
            or listener.type & socket.SOCK_STREAM == 0
        ):
            raise ProbeBrokerServiceError("probe_broker_listener_invalid")
        self.reconcile_startup()
        capacity = BoundedSemaphore(self._max_workers)
        listener.settimeout(0.5)
        try:
            with ThreadPoolExecutor(
                max_workers=self._max_workers,
                thread_name_prefix="rtsp-probe-broker",
            ) as workers:
                while self._admission_is_open():
                    if not capacity.acquire(timeout=0.5):
                        continue
                    try:
                        connection, _ = listener.accept()
                    except TimeoutError:
                        capacity.release()
                        continue
                    except BaseException:
                        capacity.release()
                        raise
                    if not self._admission_is_open():
                        connection.close()
                        capacity.release()
                        break
                    workers.submit(self._serve_owned_connection, connection, capacity)
        finally:
            if not self._cleanup_is_resolved():
                self._publish_cleanup_failure()
                raise ProbeBrokerServiceError("probe_broker_cleanup_failed") from None
        if self._cleanup_failed.is_set():
            raise ProbeBrokerServiceError("probe_broker_cleanup_failed")

    def _serve_owned_connection(
        self,
        connection: socket.socket,
        capacity: BoundedSemaphore,
    ) -> None:
        try:
            with connection:
                self.serve_connection(connection)
        except BaseException:
            self._publish_cleanup_failure()
        finally:
            capacity.release()

    def _remaining_request_seconds(self, deadline_unix_ms: int) -> float:
        observed_at_unix_ms = self._read_wall_clock_ms()
        remaining_ms = deadline_unix_ms - observed_at_unix_ms
        if not 10 <= remaining_ms <= int(_MAX_EXECUTION_SECONDS * 1_000):
            raise ProbeBrokerServiceError("probe_broker_request_expired")
        return remaining_ms / 1_000

    def _completed_at(self) -> datetime:
        try:
            return datetime.fromtimestamp(self._read_wall_clock_ms() / 1_000, tz=UTC)
        except (OverflowError, OSError, ValueError):
            raise ProbeBrokerServiceError("probe_broker_clock_invalid") from None

    def _read_wall_clock_ms(self) -> int:
        try:
            observed = self._wall_clock_ms()
        except (ArithmeticError, OSError, TypeError, ValueError):
            raise ProbeBrokerServiceError("probe_broker_clock_invalid") from None
        if isinstance(observed, bool) or not isinstance(observed, int) or observed < 1:
            raise ProbeBrokerServiceError("probe_broker_clock_invalid")
        return observed

    def _cleanup_is_resolved(self) -> bool:
        try:
            unresolved = self._executor.retry_pending_cleanup(
                timeout_seconds=self._cleanup_retry_timeout_seconds
            )
        except BaseException:
            return False
        return (
            not isinstance(unresolved, bool)
            and isinstance(unresolved, int)
            and unresolved == 0
        )

    def _publish_cleanup_failure(self) -> None:
        with self._admission_lock:
            self._cleanup_failed.set()

    def _admission_is_open(self) -> bool:
        with self._admission_lock:
            return not self._cleanup_failed.is_set()

    @staticmethod
    def _bounded_timeout(value: object, *, maximum: float) -> bool:
        return (
            not isinstance(value, bool)
            and isinstance(value, (int, float))
            and math.isfinite(value)
            and 0.01 <= value <= maximum
        )

    @staticmethod
    def _valid_networks(
        networks: object,
    ) -> bool:
        if (
            not isinstance(networks, tuple)
            or not 1 <= len(networks) <= 64
            or any(not isinstance(network, (IPv4Network, IPv6Network)) for network in networks)
        ):
            return False
        return all(
            not first.overlaps(second)
            for index, first in enumerate(networks)
            for second in networks[index + 1 :]
            if first.version == second.version
        )
