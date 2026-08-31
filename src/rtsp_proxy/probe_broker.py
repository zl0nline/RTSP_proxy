from __future__ import annotations

import array
import json
import math
import os
import select
import socket
import struct
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from types import TracebackType
from uuid import UUID

from rtsp_proxy.probe_executor import (
    ProbeConnectGuardTarget,
    inspect_sealed_probe_input,
)
from rtsp_proxy.probes import ProbeExecutionResult, ProbeFailureClass, ProbeOutcome

PROBE_BROKER_SCHEMA_VERSION = 1
PROBE_BROKER_MAX_REQUEST_BYTES = 1_024
PROBE_BROKER_MAX_RESPONSE_BYTES = 512
PROBE_BROKER_MAX_DEADLINE_MS = 60_000
_FRAME_HEADER = struct.Struct("!I")
_PEER_CREDENTIALS = struct.Struct("=iII")
_SO_PEERCRED = 17
_MSG_CMSG_CLOEXEC = 0x40000000
_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def _unix_time_ms() -> int:
    return int(time.time() * 1_000)


class ProbeBrokerError(RuntimeError):
    """A bounded, secret-free broker protocol failure."""


@dataclass(frozen=True, slots=True)
class ProbeBrokerRequest:
    request_id: UUID
    endpoint_generation: UUID
    target: ProbeConnectGuardTarget
    deadline_unix_ms: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.request_id, UUID)
            or self.request_id.version != 4
            or not isinstance(self.endpoint_generation, UUID)
            or self.endpoint_generation.version != 4
            or not isinstance(self.target, ProbeConnectGuardTarget)
            or isinstance(self.deadline_unix_ms, bool)
            or not isinstance(self.deadline_unix_ms, int)
            or self.deadline_unix_ms < 1
        ):
            raise ProbeBrokerError("probe_broker_request_invalid")

    def encode(self) -> bytes:
        encoded = json.dumps(
            {
                "address": str(self.target.address),
                "deadline_unix_ms": self.deadline_unix_ms,
                "endpoint_generation": str(self.endpoint_generation),
                "port": self.target.port,
                "request_id": str(self.request_id),
                "schema_version": PROBE_BROKER_SCHEMA_VERSION,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        if len(encoded) > PROBE_BROKER_MAX_REQUEST_BYTES:
            raise ProbeBrokerError("probe_broker_request_invalid")
        return encoded

    @classmethod
    def decode(cls, payload: bytes) -> ProbeBrokerRequest:
        if (
            not isinstance(payload, bytes)
            or not 1 <= len(payload) <= PROBE_BROKER_MAX_REQUEST_BYTES
        ):
            raise ProbeBrokerError("probe_broker_request_invalid")
        try:
            raw = json.loads(payload)
        except (UnicodeError, ValueError):
            raise ProbeBrokerError("probe_broker_request_invalid") from None
        expected_keys = {
            "address",
            "deadline_unix_ms",
            "endpoint_generation",
            "port",
            "request_id",
            "schema_version",
        }
        if not isinstance(raw, dict) or set(raw) != expected_keys:
            raise ProbeBrokerError("probe_broker_request_invalid")
        schema_version = raw["schema_version"]
        address_text = raw["address"]
        port = raw["port"]
        deadline_unix_ms = raw["deadline_unix_ms"]
        request_id_text = raw["request_id"]
        generation_text = raw["endpoint_generation"]
        if (
            type(schema_version) is not int
            or schema_version != PROBE_BROKER_SCHEMA_VERSION
            or not isinstance(address_text, str)
            or type(port) is not int
            or type(deadline_unix_ms) is not int
            or not isinstance(request_id_text, str)
            or not isinstance(generation_text, str)
        ):
            raise ProbeBrokerError("probe_broker_request_invalid")
        try:
            address = ip_address(address_text)
            request_id = UUID(request_id_text)
            generation = UUID(generation_text)
            target = ProbeConnectGuardTarget(address=address, port=port)
            decoded = cls(
                request_id=request_id,
                endpoint_generation=generation,
                target=target,
                deadline_unix_ms=deadline_unix_ms,
            )
        except (RuntimeError, ValueError):
            raise ProbeBrokerError("probe_broker_request_invalid") from None
        if (
            address_text != str(address)
            or request_id_text != str(request_id)
            or generation_text != str(generation)
            or decoded.encode() != payload
        ):
            raise ProbeBrokerError("probe_broker_request_invalid")
        return decoded


@dataclass(frozen=True, slots=True)
class ProbeBrokerResponse:
    """One request-bound, normalized result returned by the root broker."""

    request_id: UUID
    endpoint_generation: UUID
    result: ProbeExecutionResult

    def __post_init__(self) -> None:
        if (
            not isinstance(self.request_id, UUID)
            or self.request_id.version != 4
            or not isinstance(self.endpoint_generation, UUID)
            or self.endpoint_generation.version != 4
            or not isinstance(self.result, ProbeExecutionResult)
        ):
            raise ProbeBrokerError("probe_broker_response_invalid")
        _ = self._completed_at_unix_us()

    def encode(self) -> bytes:
        encoded = json.dumps(
            {
                "audio_codec": self.result.audio_codec,
                "completed_at_unix_us": self._completed_at_unix_us(),
                "endpoint_generation": str(self.endpoint_generation),
                "failure_class": (
                    None
                    if self.result.failure_class is None
                    else self.result.failure_class.value
                ),
                "outcome": self.result.outcome.value,
                "request_id": str(self.request_id),
                "schema_version": PROBE_BROKER_SCHEMA_VERSION,
                "video_codec": self.result.video_codec,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        if len(encoded) > PROBE_BROKER_MAX_RESPONSE_BYTES:
            raise ProbeBrokerError("probe_broker_response_invalid")
        return encoded

    @classmethod
    def decode(cls, payload: bytes) -> ProbeBrokerResponse:
        if (
            not isinstance(payload, bytes)
            or not 1 <= len(payload) <= PROBE_BROKER_MAX_RESPONSE_BYTES
        ):
            raise ProbeBrokerError("probe_broker_response_invalid")
        try:
            raw = json.loads(payload)
        except (UnicodeError, ValueError):
            raise ProbeBrokerError("probe_broker_response_invalid") from None
        expected_keys = {
            "audio_codec",
            "completed_at_unix_us",
            "endpoint_generation",
            "failure_class",
            "outcome",
            "request_id",
            "schema_version",
            "video_codec",
        }
        if not isinstance(raw, dict) or set(raw) != expected_keys:
            raise ProbeBrokerError("probe_broker_response_invalid")
        if (
            type(raw["schema_version"]) is not int
            or raw["schema_version"] != PROBE_BROKER_SCHEMA_VERSION
            or type(raw["completed_at_unix_us"]) is not int
            or not isinstance(raw["request_id"], str)
            or not isinstance(raw["endpoint_generation"], str)
            or not isinstance(raw["outcome"], str)
            or (
                raw["failure_class"] is not None
                and not isinstance(raw["failure_class"], str)
            )
            or any(
                codec is not None and not isinstance(codec, str)
                for codec in (raw["video_codec"], raw["audio_codec"])
            )
        ):
            raise ProbeBrokerError("probe_broker_response_invalid")
        try:
            request_id = UUID(raw["request_id"])
            endpoint_generation = UUID(raw["endpoint_generation"])
            completed_at = _UNIX_EPOCH + timedelta(
                microseconds=raw["completed_at_unix_us"]
            )
            result = ProbeExecutionResult(
                outcome=ProbeOutcome(raw["outcome"]),
                completed_at=completed_at,
                failure_class=(
                    None
                    if raw["failure_class"] is None
                    else ProbeFailureClass(raw["failure_class"])
                ),
                video_codec=raw["video_codec"],
                audio_codec=raw["audio_codec"],
            )
            decoded = cls(
                request_id=request_id,
                endpoint_generation=endpoint_generation,
                result=result,
            )
        except (OverflowError, RuntimeError, ValueError):
            raise ProbeBrokerError("probe_broker_response_invalid") from None
        if (
            raw["request_id"] != str(request_id)
            or raw["endpoint_generation"] != str(endpoint_generation)
            or decoded.encode() != payload
        ):
            raise ProbeBrokerError("probe_broker_response_invalid")
        return decoded

    def _completed_at_unix_us(self) -> int:
        completed_at = self.result.completed_at
        try:
            normalized = completed_at.astimezone(UTC)
            delta = normalized - _UNIX_EPOCH
            completed_at_unix_us = (
                (delta.days * 86_400 + delta.seconds) * 1_000_000
                + delta.microseconds
            )
        except (OverflowError, TypeError, ValueError):
            raise ProbeBrokerError("probe_broker_response_invalid") from None
        if completed_at_unix_us < 1:
            raise ProbeBrokerError("probe_broker_response_invalid")
        return completed_at_unix_us


@dataclass(slots=True)
class ReceivedProbeInput:
    """One authenticated request and its owned secret descriptor."""

    request: ProbeBrokerRequest
    _descriptor: int = field(repr=False)

    @property
    def descriptor(self) -> int:
        if self._descriptor < 0:
            raise ProbeBrokerError("probe_broker_descriptor_closed")
        return self._descriptor

    def detach(self) -> int:
        descriptor = self.descriptor
        self._descriptor = -1
        return descriptor

    def close(self) -> None:
        if self._descriptor < 0:
            return
        descriptor = self._descriptor
        self._descriptor = -1
        try:
            os.close(descriptor)
        except OSError:
            raise ProbeBrokerError("probe_broker_descriptor_close_failed") from None

    def __enter__(self) -> ReceivedProbeInput:
        _ = self.descriptor
        return self

    def __exit__(
        self,
        _exception_type: type[BaseException] | None,
        exception: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        try:
            self.close()
        except BaseException as cleanup_error:
            if exception is not None:
                raise BaseExceptionGroup(
                    "probe broker request and descriptor cleanup failed",
                    [exception, cleanup_error],
                ) from None
            raise


def send_probe_broker_request(
    connection: socket.socket,
    request: ProbeBrokerRequest,
    descriptor: int,
    *,
    timeout_seconds: float,
    monotonic: Callable[[], float] = time.monotonic,
) -> None:
    """Send one request and consume the caller's sealed input descriptor."""

    if isinstance(descriptor, bool) or not isinstance(descriptor, int) or descriptor < 0:
        raise ProbeBrokerError("probe_broker_descriptor_invalid")
    primary_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    try:
        _send_probe_broker_request(
            connection,
            request,
            descriptor,
            timeout_seconds=timeout_seconds,
            monotonic=monotonic,
        )
    except BaseException as error:
        primary_error = error
    finally:
        try:
            os.close(descriptor)
        except BaseException as error:
            cleanup_error = (
                ProbeBrokerError("probe_broker_descriptor_close_failed")
                if isinstance(error, OSError)
                else error
            )
    if primary_error is not None and cleanup_error is not None:
        raise BaseExceptionGroup(
            "probe broker send and descriptor cleanup failed",
            [primary_error, cleanup_error],
        ) from None
    if primary_error is not None:
        raise primary_error from None
    if cleanup_error is not None:
        raise cleanup_error from None


def send_probe_broker_response(
    connection: socket.socket,
    response: ProbeBrokerResponse,
    *,
    timeout_seconds: float,
    monotonic: Callable[[], float] = time.monotonic,
) -> None:
    """Send one bounded normalized response without ancillary descriptors."""

    _require_unix_stream(connection)
    _require_timeout(timeout_seconds)
    if not isinstance(response, ProbeBrokerResponse):
        raise ProbeBrokerError("probe_broker_response_invalid")
    encoded = response.encode()
    frame = _FRAME_HEADER.pack(len(encoded)) + encoded
    try:
        io_deadline = _start_io_deadline(
            timeout_seconds=timeout_seconds,
            monotonic=monotonic,
        )
        _set_remaining_timeout(
            connection,
            io_deadline=io_deadline,
            monotonic=monotonic,
        )
        connection.sendall(frame)
    except (OSError, TimeoutError):
        raise ProbeBrokerError("probe_broker_unavailable") from None


def receive_probe_broker_response(
    connection: socket.socket,
    *,
    expected_request: ProbeBrokerRequest,
    timeout_seconds: float,
    monotonic: Callable[[], float] = time.monotonic,
) -> ProbeExecutionResult:
    """Receive one request-bound result and reject any descriptor smuggling."""

    _require_unix_stream(connection)
    _require_response_wait_timeout(timeout_seconds)
    if not isinstance(expected_request, ProbeBrokerRequest):
        raise ProbeBrokerError("probe_broker_request_invalid")
    response_deadline = _start_io_deadline(
        timeout_seconds=timeout_seconds,
        monotonic=monotonic,
    )
    remaining = _wait_until_readable(
        connection,
        io_deadline=response_deadline,
        monotonic=monotonic,
    )
    io_deadline = _start_io_deadline(
        timeout_seconds=min(5.0, remaining),
        monotonic=monotonic,
    )
    descriptors: list[int] = []
    try:
        try:
            header = _recv_exact(
                connection,
                _FRAME_HEADER.size,
                descriptors,
                io_deadline=io_deadline,
                monotonic=monotonic,
            )
        except ProbeBrokerError as error:
            if str(error) == "probe_broker_request_truncated":
                raise ProbeBrokerError("probe_broker_response_truncated") from None
            raise
        (payload_size,) = _FRAME_HEADER.unpack(header)
        if not 1 <= payload_size <= PROBE_BROKER_MAX_RESPONSE_BYTES:
            raise ProbeBrokerError("probe_broker_response_invalid")
        try:
            payload = _recv_exact(
                connection,
                payload_size,
                descriptors,
                io_deadline=io_deadline,
                monotonic=monotonic,
            )
        except ProbeBrokerError as error:
            if str(error) == "probe_broker_request_truncated":
                raise ProbeBrokerError("probe_broker_response_truncated") from None
            raise
        if descriptors:
            raise ProbeBrokerError("probe_broker_response_invalid")
        response = ProbeBrokerResponse.decode(payload)
        if (
            response.request_id != expected_request.request_id
            or response.endpoint_generation != expected_request.endpoint_generation
        ):
            raise ProbeBrokerError("probe_broker_response_mismatch")
        try:
            response_completed_at_us = response._completed_at_unix_us()
            deadline_us = expected_request.deadline_unix_ms * 1_000
        except (ArithmeticError, OverflowError):
            raise ProbeBrokerError("probe_broker_response_invalid") from None
        if response_completed_at_us > deadline_us:
            raise ProbeBrokerError("probe_broker_response_mismatch")
        return response.result
    except BaseException as primary_error:
        cleanup_errors: list[BaseException] = []
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except BaseException as error:
                cleanup_errors.append(error)
        if cleanup_errors:
            raise BaseExceptionGroup(
                "probe broker response and descriptor cleanup failed",
                [primary_error, *cleanup_errors],
            ) from None
        raise


def _send_probe_broker_request(
    connection: socket.socket,
    request: ProbeBrokerRequest,
    descriptor: int,
    *,
    timeout_seconds: float,
    monotonic: Callable[[], float],
) -> None:
    _require_unix_stream(connection)
    _require_timeout(timeout_seconds)
    if not isinstance(request, ProbeBrokerRequest):
        raise ProbeBrokerError("probe_broker_request_invalid")
    try:
        io_deadline = _start_io_deadline(
            timeout_seconds=timeout_seconds,
            monotonic=monotonic,
        )
        _size, input_contract = inspect_sealed_probe_input(descriptor)
    except (OSError, ValueError):
        raise ProbeBrokerError("probe_broker_descriptor_invalid") from None
    if input_contract.target != request.target:
        raise ProbeBrokerError("probe_broker_target_mismatch")
    encoded = request.encode()
    frame = _FRAME_HEADER.pack(len(encoded)) + encoded
    rights = array.array("i", [descriptor])
    try:
        _set_remaining_timeout(
            connection,
            io_deadline=io_deadline,
            monotonic=monotonic,
        )
        sent = connection.sendmsg(
            [frame],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)],
        )
        if sent <= 0:
            raise OSError("probe broker send made no progress")
        if sent < len(frame):
            _set_remaining_timeout(
                connection,
                io_deadline=io_deadline,
                monotonic=monotonic,
            )
            connection.sendall(frame[sent:])
    except (OSError, TimeoutError):
        raise ProbeBrokerError("probe_broker_unavailable") from None


def receive_probe_broker_request(
    connection: socket.socket,
    *,
    expected_uid: int,
    expected_gid: int,
    request_timeout_seconds: float,
    wall_clock_ms: Callable[[], int] = _unix_time_ms,
    monotonic: Callable[[], float] = time.monotonic,
) -> ReceivedProbeInput:
    """Authenticate, receive and revalidate one broker request and owned fd."""

    _require_unix_stream(connection)
    if (
        sys.platform != "linux"
        or isinstance(expected_uid, bool)
        or not isinstance(expected_uid, int)
        or expected_uid < 0
        or isinstance(expected_gid, bool)
        or not isinstance(expected_gid, int)
        or expected_gid < 0
    ):
        raise ProbeBrokerError("probe_broker_policy_invalid")
    _require_timeout(request_timeout_seconds)
    started_at_unix_ms = _read_wall_clock_ms(wall_clock_ms)
    io_deadline = _start_io_deadline(
        timeout_seconds=request_timeout_seconds,
        monotonic=monotonic,
    )
    require_probe_broker_peer(
        connection,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    descriptors: list[int] = []
    try:
        header = _recv_exact(
            connection,
            _FRAME_HEADER.size,
            descriptors,
            io_deadline=io_deadline,
            monotonic=monotonic,
        )
        (payload_size,) = _FRAME_HEADER.unpack(header)
        if not 1 <= payload_size <= PROBE_BROKER_MAX_REQUEST_BYTES:
            raise ProbeBrokerError("probe_broker_request_invalid")
        payload = _recv_exact(
            connection,
            payload_size,
            descriptors,
            io_deadline=io_deadline,
            monotonic=monotonic,
        )
        if len(descriptors) != 1:
            raise ProbeBrokerError("probe_broker_descriptor_count_invalid")
        descriptor = descriptors[0]
        try:
            os.set_inheritable(descriptor, False)
        except OSError:
            raise ProbeBrokerError("probe_broker_descriptor_invalid") from None
        request = ProbeBrokerRequest.decode(payload)
        observed_at_unix_ms = _read_wall_clock_ms(wall_clock_ms)
        if request.deadline_unix_ms <= observed_at_unix_ms:
            raise ProbeBrokerError("probe_broker_request_expired")
        if (
            request.deadline_unix_ms - started_at_unix_ms
            > PROBE_BROKER_MAX_DEADLINE_MS
        ):
            raise ProbeBrokerError("probe_broker_request_invalid")
        try:
            _size, input_contract = inspect_sealed_probe_input(descriptor)
        except ValueError:
            raise ProbeBrokerError("probe_broker_descriptor_invalid") from None
        if input_contract.target != request.target:
            raise ProbeBrokerError("probe_broker_target_mismatch")
        if request.deadline_unix_ms <= _read_wall_clock_ms(wall_clock_ms):
            raise ProbeBrokerError("probe_broker_request_expired")
        return ReceivedProbeInput(request=request, _descriptor=descriptor)
    except BaseException as primary_error:
        cleanup_errors: list[BaseException] = []
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except BaseException as error:
                cleanup_errors.append(error)
        if cleanup_errors:
            raise BaseExceptionGroup(
                "probe broker receive and descriptor cleanup failed",
                [primary_error, *cleanup_errors],
            ) from None
        raise


def _require_unix_stream(connection: socket.socket) -> None:
    if (
        not isinstance(connection, socket.socket)
        or connection.family != socket.AF_UNIX
        or connection.type & socket.SOCK_STREAM == 0
    ):
        raise ProbeBrokerError("probe_broker_socket_invalid")


def _require_timeout(timeout_seconds: float) -> None:
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or not 0.01 <= timeout_seconds <= 5
    ):
        raise ProbeBrokerError("probe_broker_policy_invalid")


def _require_response_wait_timeout(timeout_seconds: float) -> None:
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or not 0.01 <= timeout_seconds <= PROBE_BROKER_MAX_DEADLINE_MS / 1_000
    ):
        raise ProbeBrokerError("probe_broker_policy_invalid")


def _read_wall_clock_ms(wall_clock_ms: Callable[[], int]) -> int:
    try:
        observed = wall_clock_ms()
    except (ArithmeticError, OSError, ValueError):
        raise ProbeBrokerError("probe_broker_policy_invalid") from None
    if isinstance(observed, bool) or not isinstance(observed, int) or observed < 1:
        raise ProbeBrokerError("probe_broker_policy_invalid")
    return observed


def _start_io_deadline(
    *,
    timeout_seconds: float,
    monotonic: Callable[[], float],
) -> float:
    try:
        started = monotonic()
    except (ArithmeticError, OSError, TypeError, ValueError):
        raise ProbeBrokerError("probe_broker_policy_invalid") from None
    if (
        isinstance(started, bool)
        or not isinstance(started, (int, float))
        or not math.isfinite(started)
    ):
        raise ProbeBrokerError("probe_broker_policy_invalid")
    return started + timeout_seconds


def _set_remaining_timeout(
    connection: socket.socket,
    *,
    io_deadline: float,
    monotonic: Callable[[], float],
) -> None:
    try:
        observed = monotonic()
        remaining = io_deadline - observed
    except (ArithmeticError, OSError, TypeError, ValueError):
        raise ProbeBrokerError("probe_broker_unavailable") from None
    if (
        isinstance(observed, bool)
        or not isinstance(observed, (int, float))
        or not math.isfinite(observed)
        or not math.isfinite(remaining)
        or remaining <= 0
    ):
        raise ProbeBrokerError("probe_broker_unavailable")
    try:
        connection.settimeout(remaining)
    except (OSError, ValueError):
        raise ProbeBrokerError("probe_broker_unavailable") from None


def _wait_until_readable(
    connection: socket.socket,
    *,
    io_deadline: float,
    monotonic: Callable[[], float],
) -> float:
    try:
        observed = monotonic()
        remaining = io_deadline - observed
    except (ArithmeticError, OSError, TypeError, ValueError):
        raise ProbeBrokerError("probe_broker_unavailable") from None
    if (
        isinstance(observed, bool)
        or not isinstance(observed, (int, float))
        or not math.isfinite(observed)
        or not math.isfinite(remaining)
        or remaining <= 0
    ):
        raise ProbeBrokerError("probe_broker_unavailable")
    try:
        readable, _, _ = select.select((connection,), (), (), remaining)
    except (OSError, ValueError):
        raise ProbeBrokerError("probe_broker_unavailable") from None
    if readable != [connection]:
        raise ProbeBrokerError("probe_broker_unavailable")
    try:
        observed_after_wait = monotonic()
        remaining_after_wait = io_deadline - observed_after_wait
    except (ArithmeticError, OSError, TypeError, ValueError):
        raise ProbeBrokerError("probe_broker_unavailable") from None
    if (
        isinstance(observed_after_wait, bool)
        or not isinstance(observed_after_wait, (int, float))
        or not math.isfinite(observed_after_wait)
        or not math.isfinite(remaining_after_wait)
        or remaining_after_wait <= 0
    ):
        raise ProbeBrokerError("probe_broker_unavailable")
    return remaining_after_wait


def require_probe_broker_peer(
    connection: socket.socket,
    *,
    expected_uid: int,
    expected_gid: int,
) -> None:
    """Require one exact Linux peer without exposing its credentials."""

    _require_unix_stream(connection)
    if (
        sys.platform != "linux"
        or isinstance(expected_uid, bool)
        or not isinstance(expected_uid, int)
        or expected_uid < 0
        or isinstance(expected_gid, bool)
        or not isinstance(expected_gid, int)
        or expected_gid < 0
    ):
        raise ProbeBrokerError("probe_broker_policy_invalid")
    try:
        raw = connection.getsockopt(
            socket.SOL_SOCKET,
            _SO_PEERCRED,
            _PEER_CREDENTIALS.size,
        )
        pid, uid, gid = _PEER_CREDENTIALS.unpack(raw)
    except (OSError, struct.error):
        raise ProbeBrokerError("probe_broker_peer_invalid") from None
    if pid < 1 or uid != expected_uid or gid != expected_gid:
        raise ProbeBrokerError("probe_broker_peer_denied")


def _recv_exact(
    connection: socket.socket,
    size: int,
    descriptors: list[int],
    *,
    io_deadline: float,
    monotonic: Callable[[], float],
) -> bytes:
    payload = bytearray()
    descriptor_size = array.array("i").itemsize
    while len(payload) < size:
        _set_remaining_timeout(
            connection,
            io_deadline=io_deadline,
            monotonic=monotonic,
        )
        message: tuple[bytes, list[tuple[int, int, bytes]], int, object] | None = None
        try:
            message = connection.recvmsg(
                size - len(payload),
                socket.CMSG_SPACE(descriptor_size * 2),
                _MSG_CMSG_CLOEXEC,
            )
            chunk, ancillary, flags, _address = message
            ancillary_invalid = _register_received_rights(ancillary, descriptors)
        except (OSError, TimeoutError):
            raise ProbeBrokerError("probe_broker_unavailable") from None
        except BaseException:
            if message is not None:
                _register_received_rights(message[1], descriptors)
            raise
        if flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC) or ancillary_invalid:
            raise ProbeBrokerError("probe_broker_ancillary_invalid")
        if not chunk:
            raise ProbeBrokerError("probe_broker_request_truncated")
        payload.extend(chunk)
    return bytes(payload)


def _register_received_rights(
    ancillary: list[tuple[int, int, bytes]],
    descriptors: list[int],
) -> bool:
    ancillary_invalid = False
    descriptor_struct = struct.Struct("=i")
    for level, message_type, message_data in ancillary:
        if level != socket.SOL_SOCKET or message_type != socket.SCM_RIGHTS:
            ancillary_invalid = True
            continue
        complete_bytes = len(message_data) - len(message_data) % descriptor_struct.size
        for offset in range(0, complete_bytes, descriptor_struct.size):
            (descriptor,) = descriptor_struct.unpack_from(message_data, offset)
            if descriptor not in descriptors:
                descriptors.append(descriptor)
        if complete_bytes != len(message_data):
            ancillary_invalid = True
    return ancillary_invalid
