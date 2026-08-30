from __future__ import annotations

import fcntl
import os
import socket
import stat
import struct
import sys
from collections.abc import Callable
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import cast
from urllib.parse import quote, unquote, urlsplit

PROBE_CONNECT_GUARD_ABI_VERSION = 1
PROBE_CONNECT_GUARD_MAP_VALUE_SIZE = 32
PROBE_INPUT_MAX_BYTES = 16_384
PROBE_INPUT_REQUIRED_SEALS = 0x0001 | 0x0002 | 0x0004 | 0x0008
_F_ADD_SEALS = 1033
_F_GET_SEALS = 1034
_MFD_CLOEXEC = 0x0001
_MFD_ALLOW_SEALING = 0x0002


def _required_probe_input_seals() -> int:
    return PROBE_INPUT_REQUIRED_SEALS


def probe_credential_component_valid(value: str, *, maximum_bytes: int) -> bool:
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        return False
    return (
        bool(encoded)
        and len(encoded) <= maximum_bytes
        and not any(character in value for character in "\r\n\x00")
    )


def _validate_probe_input_payload(payload: bytes) -> None:
    parse_probe_input_payload(payload)


def create_sealed_probe_input(payload: bytes) -> int:
    """Create one anonymous, immutable and close-on-exec ffconcat input."""

    _validate_probe_input_payload(payload)
    raw_memfd_create = getattr(os, "memfd_create", None)
    if sys.platform != "linux" or not callable(raw_memfd_create):
        raise RuntimeError("probe_sealed_input_unsupported")
    memfd_create = cast(Callable[[str, int], int], raw_memfd_create)
    descriptor = -1
    try:
        descriptor = memfd_create(
            "rtsp-probe-input",
            _MFD_CLOEXEC | _MFD_ALLOW_SEALING,
        )
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("probe input write made no progress")
            remaining = remaining[written:]
        fcntl.fcntl(
            descriptor,
            _F_ADD_SEALS,
            _required_probe_input_seals(),
        )
        validate_sealed_probe_input(descriptor)
        return descriptor
    except BaseException as primary_error:
        cleanup_error: BaseException | None = None
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except BaseException as error:
                cleanup_error = error
        if isinstance(primary_error, (AttributeError, OSError)):
            primary_error = RuntimeError("probe_sealed_input_unavailable")
        if cleanup_error is not None:
            raise BaseExceptionGroup(
                "probe sealed input construction and cleanup failed",
                [primary_error, cleanup_error],
            ) from None
        raise primary_error from None


def validate_sealed_probe_input(descriptor: int) -> int:
    """Validate and rewind an immutable input without returning its secret bytes."""

    size, _contract = inspect_sealed_probe_input(descriptor)
    return size


def inspect_sealed_probe_input(descriptor: int) -> tuple[int, ProbeInputContract]:
    """Validate once, rewind and return only secret-free parsed metadata."""

    if isinstance(descriptor, bool) or not isinstance(descriptor, int) or descriptor < 0:
        raise ValueError("probe_input_descriptor_invalid")
    try:
        metadata = os.fstat(descriptor)
        seals = fcntl.fcntl(descriptor, _F_GET_SEALS)
    except (AttributeError, OSError) as error:
        raise ValueError("probe_input_descriptor_invalid") from error
    required_seals = _required_probe_input_seals()
    if seals & required_seals != required_seals:
        raise ValueError("probe_input_seals_invalid")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 0
        or not 1 <= metadata.st_size <= PROBE_INPUT_MAX_BYTES
    ):
        raise ValueError("probe_input_descriptor_invalid")
    try:
        payload = os.pread(descriptor, metadata.st_size + 1, 0)
    except OSError as error:
        raise ValueError("probe_input_descriptor_invalid") from error
    if len(payload) != metadata.st_size:
        raise ValueError("probe_input_descriptor_invalid")
    contract = parse_probe_input_payload(payload)
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
    except OSError as error:
        raise ValueError("probe_input_descriptor_invalid") from error
    return metadata.st_size, contract


@dataclass(frozen=True, slots=True)
class ProbeInputContract:
    """Secret-free metadata recovered from one canonical probe input."""

    target: ProbeConnectGuardTarget
    io_timeout_microseconds: int


def serialize_probe_input(
    *,
    address: IPv4Address | IPv6Address,
    port: int,
    path_and_query: str,
    username: str | None,
    password: str | None,
    io_timeout_microseconds: int,
) -> bytes:
    """Serialize the only ffconcat form admitted by the probe boundary."""

    if (
        not isinstance(address, (IPv4Address, IPv6Address))
        or (isinstance(address, IPv6Address) and address.ipv4_mapped is not None)
        or isinstance(port, bool)
        or not isinstance(port, int)
        or not 1 <= port <= 65_535
        or not isinstance(path_and_query, str)
        or not path_and_query.startswith("/")
        or any(
            ord(character) < 0x20 or ord(character) == 0x7F or character in "'\\#"
            for character in path_and_query
        )
        or isinstance(io_timeout_microseconds, bool)
        or not isinstance(io_timeout_microseconds, int)
        or not 100_000 <= io_timeout_microseconds <= 30_000_000
        or (username is None) != (password is None)
    ):
        raise ValueError("probe_input_payload_invalid")
    try:
        if len(path_and_query.encode("utf-8")) > 8_192:
            raise ValueError("probe_input_payload_invalid")
    except UnicodeError:
        raise ValueError("probe_input_payload_invalid") from None
    userinfo = ""
    if username is not None and password is not None:
        if not probe_credential_component_valid(
            username, maximum_bytes=64
        ) or not probe_credential_component_valid(password, maximum_bytes=256):
            raise ValueError("probe_input_payload_invalid")
        userinfo = f"{quote(username, safe='')}:{quote(password, safe='')}@"
    authority = f"[{address}]" if isinstance(address, IPv6Address) else str(address)
    payload = (
        f"ffconcat version 1.0\n"
        f"file 'rtsp://{userinfo}{authority}:{port}{path_and_query}'\n"
        "option rtsp_transport tcp\n"
        f"option rw_timeout {io_timeout_microseconds}\n"
    ).encode()
    if len(payload) > PROBE_INPUT_MAX_BYTES:
        raise ValueError("probe_input_payload_invalid")
    return payload


def parse_probe_input_payload(payload: bytes) -> ProbeInputContract:
    """Parse canonical input and return only its literal guard tuple and timeout."""

    if (
        not isinstance(payload, bytes)
        or not 1 <= len(payload) <= PROBE_INPUT_MAX_BYTES
        or b"\x00" in payload
        or b"\r" in payload
    ):
        raise ValueError("probe_input_payload_invalid")
    try:
        text = payload.decode("utf-8")
    except UnicodeError:
        raise ValueError("probe_input_payload_invalid") from None
    lines = text.splitlines(keepends=True)
    if (
        len(lines) != 4
        or lines[0] != "ffconcat version 1.0\n"
        or not lines[1].startswith("file 'rtsp://")
        or not lines[1].endswith("'\n")
        or "'" in lines[1][6:-2]
        or lines[2] != "option rtsp_transport tcp\n"
        or not lines[3].startswith("option rw_timeout ")
        or not lines[3].endswith("\n")
    ):
        raise ValueError("probe_input_payload_invalid")
    timeout_text = lines[3][len("option rw_timeout ") : -1]
    if (
        not 6 <= len(timeout_text) <= 8
        or not timeout_text.isascii()
        or not timeout_text.isdigit()
        or timeout_text.startswith("0")
    ):
        raise ValueError("probe_input_payload_invalid")
    timeout = int(timeout_text)
    if not 100_000 <= timeout <= 30_000_000 or str(timeout) != timeout_text:
        raise ValueError("probe_input_payload_invalid")
    target_url = lines[1][6:-2]
    try:
        parsed = urlsplit(target_url)
        hostname = parsed.hostname
        port = parsed.port
        address = None if hostname is None else ip_address(hostname)
        username = None if parsed.username is None else unquote(parsed.username)
        password = None if parsed.password is None else unquote(parsed.password)
    except (UnicodeError, ValueError):
        raise ValueError("probe_input_payload_invalid") from None
    if (
        parsed.scheme != "rtsp"
        or address is None
        or port is None
        or parsed.fragment
        or not parsed.path.startswith("/")
        or (username is None) != (password is None)
    ):
        raise ValueError("probe_input_payload_invalid")
    path_and_query = parsed.path
    if parsed.query:
        path_and_query += f"?{parsed.query}"
    try:
        target = ProbeConnectGuardTarget(address=address, port=port)
        canonical = serialize_probe_input(
            address=address,
            port=port,
            path_and_query=path_and_query,
            username=username,
            password=password,
            io_timeout_microseconds=timeout,
        )
    except (RuntimeError, ValueError):
        raise ValueError("probe_input_payload_invalid") from None
    if canonical != payload:
        raise ValueError("probe_input_payload_invalid")
    return ProbeInputContract(target=target, io_timeout_microseconds=timeout)


@dataclass(frozen=True, slots=True)
class ProbeConnectGuardTarget:
    """One literal destination encoded for the cgroup connect guard map."""

    address: IPv4Address | IPv6Address
    port: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.address, (IPv4Address, IPv6Address))
            or isinstance(self.port, bool)
            or not isinstance(self.port, int)
            or not 1 <= self.port <= 65_535
            or (
                isinstance(self.address, IPv6Address)
                and self.address.ipv4_mapped is not None
            )
        ):
            raise ValueError("probe_connect_guard_target_invalid")
        if sys.byteorder != "little":
            raise RuntimeError("probe_connect_guard_byte_order_unsupported")

    def map_value(self) -> bytes:
        family = socket.AF_INET if isinstance(self.address, IPv4Address) else socket.AF_INET6
        address = self.address.packed.ljust(16, b"\x00")
        encoded = struct.pack(
            "=III16sI",
            PROBE_CONNECT_GUARD_ABI_VERSION,
            family,
            socket.htons(self.port),
            address,
            0,
        )
        assert len(encoded) == PROBE_CONNECT_GUARD_MAP_VALUE_SIZE
        return encoded
