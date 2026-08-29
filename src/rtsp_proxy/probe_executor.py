from __future__ import annotations

import socket
import struct
import sys
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address

PROBE_CONNECT_GUARD_ABI_VERSION = 1
PROBE_CONNECT_GUARD_MAP_VALUE_SIZE = 32


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
