from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address
from typing import Literal

from rtsp_proxy.probe_broker import ProbeBrokerRequest
from rtsp_proxy.probe_executor import ProbeConnectGuardTarget

_PROBE_LAUNCHER = "/opt/rtsp-proxy/current/.venv/bin/rtsp-proxy-probe-launcher"
_PROBE_SLICE = "rtsp-probe.slice"
_LINUX_AF_UNSPEC = 0
_LINUX_AF_INET = 2
_LINUX_AF_INET6 = 10
_IP_PROTOCOL_ANY = 0

type _ExecStartValue = tuple[tuple[str, tuple[str, ...], bool], ...]
type _AddressFamilyFilterValue = tuple[bool, tuple[str, ...]]
type _IpAddressFilterValue = tuple[tuple[int, bytes, int], ...]
type _SocketBindFilterValue = tuple[tuple[int, int, int, int], ...]
type ProbeSystemdValue = (
    str
    | bool
    | int
    | _ExecStartValue
    | _AddressFamilyFilterValue
    | _IpAddressFilterValue
    | _SocketBindFilterValue
)
type ProbeSystemdSignature = Literal[
    "s",
    "b",
    "t",
    "u",
    "h",
    "a(sasb)",
    "(bas)",
    "a(iayu)",
    "a(iiqq)",
]


class ProbeSystemdError(RuntimeError):
    """A transient probe unit could not be represented by the fixed policy."""


@dataclass(frozen=True, slots=True)
class ProbeSystemdProperty:
    """One typed value in systemd's StartTransientUnit ``a(sv)`` array."""

    name: str
    signature: ProbeSystemdSignature
    value: ProbeSystemdValue


@dataclass(frozen=True, slots=True)
class ProbeTransientDescriptors:
    """Broker-owned input/output descriptors passed as D-Bus handles."""

    input_fd: int
    output_fd: int


@dataclass(frozen=True, slots=True)
class ProbeTransientUnit:
    """Secret-free immutable request for one direct StartTransientUnit call."""

    unit_name: str
    start_mode: Literal["fail"]
    properties: tuple[ProbeSystemdProperty, ...]
    maximum_output_bytes: int
    guard_target: ProbeConnectGuardTarget


def _property(
    name: str,
    signature: ProbeSystemdSignature,
    value: ProbeSystemdValue,
) -> ProbeSystemdProperty:
    return ProbeSystemdProperty(name=name, signature=signature, value=value)


def _fixed_properties(descriptors: ProbeTransientDescriptors) -> tuple[ProbeSystemdProperty, ...]:
    return (
        _property("Type", "s", "exec"),
        _property("Slice", "s", _PROBE_SLICE),
        _property("CollectMode", "s", "inactive-or-failed"),
        _property("ExecStart", "a(sasb)", ((_PROBE_LAUNCHER, (_PROBE_LAUNCHER,), False),)),
        _property("StandardInputFileDescriptor", "h", descriptors.input_fd),
        _property("StandardOutputFileDescriptor", "h", descriptors.output_fd),
        _property("StandardError", "s", "null"),
        _property("DynamicUser", "b", True),
        _property("NoNewPrivileges", "b", True),
        _property("ProtectProc", "s", "invisible"),
        _property("PrivateTmpEx", "s", "disconnected"),
        _property("PrivateDevices", "b", True),
        _property("ProtectSystem", "s", "strict"),
        _property("ProtectHome", "s", "yes"),
        _property("ProtectClock", "b", True),
        _property("ProtectControlGroups", "b", True),
        _property("ProtectKernelLogs", "b", True),
        _property("ProtectKernelModules", "b", True),
        _property("ProtectKernelTunables", "b", True),
        _property("RestrictSUIDSGID", "b", True),
        _property("LockPersonality", "b", True),
        _property("RestrictRealtime", "b", True),
        _property("CapabilityBoundingSet", "t", 0),
        _property("AmbientCapabilities", "t", 0),
        _property(
            "RestrictAddressFamilies",
            "(bas)",
            (True, ("AF_UNIX", "AF_INET", "AF_INET6")),
        ),
        _property(
            "SocketBindDeny",
            "a(iiqq)",
            ((_LINUX_AF_UNSPEC, _IP_PROTOCOL_ANY, 0, 0),),
        ),
        _property(
            "IPAddressDeny",
            "a(iayu)",
            (
                (_LINUX_AF_INET, bytes(4), 0),
                (_LINUX_AF_INET6, bytes(16), 0),
            ),
        ),
        _property("MemoryMax", "t", 134_217_728),
        _property("MemorySwapMax", "t", 0),
        _property("TasksMax", "t", 8),
        _property("LimitNOFILE", "t", 64),
        _property("CPUQuotaPerSecUSec", "t", 500_000),
        _property("RuntimeMaxUSec", "t", 35_000_000),
        _property("TimeoutStopUSec", "t", 5_000_000),
        _property("KillMode", "s", "control-group"),
        _property("SendSIGKILL", "b", True),
        _property("UMask", "u", 0o077),
    )


def build_probe_transient_unit(
    request: ProbeBrokerRequest,
    *,
    descriptors: ProbeTransientDescriptors,
) -> ProbeTransientUnit:
    """Build the only StartTransientUnit policy admitted by the root broker."""

    if not isinstance(request, ProbeBrokerRequest):
        raise ProbeSystemdError("probe_transient_request_invalid")
    descriptor_values = (descriptors.input_fd, descriptors.output_fd)
    if (
        any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in descriptor_values
        )
        or descriptors.input_fd == descriptors.output_fd
    ):
        raise ProbeSystemdError("probe_transient_descriptors_invalid")

    family = _LINUX_AF_INET if isinstance(request.target.address, IPv4Address) else _LINUX_AF_INET6
    prefix_length = 32 if family == _LINUX_AF_INET else 128
    properties = (
        *_fixed_properties(descriptors),
        _property(
            "IPAddressAllow",
            "a(iayu)",
            ((family, request.target.address.packed, prefix_length),),
        ),
    )
    return ProbeTransientUnit(
        unit_name=f"rtsp-probe-{request.request_id.hex}.service",
        start_mode="fail",
        properties=properties,
        maximum_output_bytes=65_536,
        guard_target=request.target,
    )
