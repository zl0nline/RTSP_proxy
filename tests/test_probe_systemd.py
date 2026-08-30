from __future__ import annotations

from ipaddress import ip_address
from typing import cast
from uuid import UUID

import pytest

from rtsp_proxy.probe_broker import ProbeBrokerRequest
from rtsp_proxy.probe_executor import ProbeConnectGuardTarget
from rtsp_proxy.probe_systemd import (
    ProbeSystemdError,
    ProbeTransientDescriptors,
    ProbeTransientUnit,
    build_probe_transient_unit,
)

_REQUEST_ID = UUID("447a1c4e-4c79-4c50-8e51-42c4dfa5fb19")
_GENERATION = UUID("d7cbf9ca-5328-4ed2-a5eb-b9e1b0ca9914")
_NOW_MS = 1_800_000_000_000
_LAUNCHER = "/opt/rtsp-proxy/current/.venv/bin/rtsp-proxy-probe-launcher"


def _request(*, address: str = "192.0.2.10") -> ProbeBrokerRequest:
    return ProbeBrokerRequest(
        request_id=_REQUEST_ID,
        endpoint_generation=_GENERATION,
        target=ProbeConnectGuardTarget(address=ip_address(address), port=8554),
        deadline_unix_ms=_NOW_MS + 10_000,
    )


def _properties(unit: ProbeTransientUnit) -> dict[str, tuple[str, object]]:
    properties = unit.properties
    assert len(properties) == len({item.name for item in properties})
    return {item.name: (item.signature, item.value) for item in properties}


def test_transient_unit_is_an_exact_typed_start_transient_unit_request() -> None:
    unit = build_probe_transient_unit(
        _request(),
        descriptors=ProbeTransientDescriptors(input_fd=7, output_fd=8),
    )

    assert unit.unit_name == "rtsp-probe-447a1c4e4c794c508e5142c4dfa5fb19.service"
    assert unit.start_mode == "fail"
    assert unit.guard_target == _request().target
    assert unit.maximum_output_bytes == 65_536
    assert _properties(unit) == {
        "Type": ("s", "exec"),
        "Slice": ("s", "rtsp-probe.slice"),
        "CollectMode": ("s", "inactive-or-failed"),
        "ExecStart": ("a(sasb)", ((_LAUNCHER, (_LAUNCHER,), False),)),
        "StandardInputFileDescriptor": ("h", 7),
        "StandardOutputFileDescriptor": ("h", 8),
        "StandardError": ("s", "null"),
        "DynamicUser": ("b", True),
        "NoNewPrivileges": ("b", True),
        "ProtectProc": ("s", "invisible"),
        "PrivateTmpEx": ("s", "disconnected"),
        "PrivateDevices": ("b", True),
        "ProtectSystem": ("s", "strict"),
        "ProtectHome": ("s", "yes"),
        "ProtectClock": ("b", True),
        "ProtectControlGroups": ("b", True),
        "ProtectKernelLogs": ("b", True),
        "ProtectKernelModules": ("b", True),
        "ProtectKernelTunables": ("b", True),
        "RestrictSUIDSGID": ("b", True),
        "LockPersonality": ("b", True),
        "RestrictRealtime": ("b", True),
        "CapabilityBoundingSet": ("t", 0),
        "AmbientCapabilities": ("t", 0),
        "RestrictAddressFamilies": ("(bas)", (True, ("AF_UNIX", "AF_INET", "AF_INET6"))),
        "SocketBindDeny": ("a(iiqq)", ((0, 0, 0, 0),)),
        "IPAddressDeny": (
            "a(iayu)",
            ((2, b"\x00" * 4, 0), (10, b"\x00" * 16, 0)),
        ),
        "IPAddressAllow": ("a(iayu)", ((2, b"\xc0\x00\x02\x0a", 32),)),
        "MemoryMax": ("t", 134_217_728),
        "MemorySwapMax": ("t", 0),
        "TasksMax": ("t", 8),
        "LimitNOFILE": ("t", 64),
        "CPUQuotaPerSecUSec": ("t", 500_000),
        "RuntimeMaxUSec": ("t", 35_000_000),
        "TimeoutStopUSec": ("t", 5_000_000),
        "KillMode": ("s", "control-group"),
        "SendSIGKILL": ("b", True),
        "UMask": ("u", 0o077),
    }

    rendered = repr((unit.unit_name, unit.start_mode, unit.properties))
    assert "systemd-run" not in rendered
    assert "--pipe" not in rendered
    assert "camera" not in rendered
    assert "secret" not in rendered
    assert "8554" not in rendered


def test_transient_unit_uses_linux_ipv6_abi_and_an_exact_host_prefix() -> None:
    unit = build_probe_transient_unit(
        _request(address="2001:db8::10"),
        descriptors=ProbeTransientDescriptors(input_fd=7, output_fd=8),
    )

    assert _properties(unit)["IPAddressAllow"] == (
        "a(iayu)",
        ((10, ip_address("2001:db8::10").packed, 128),),
    )
    assert unit.guard_target == _request(address="2001:db8::10").target


@pytest.mark.parametrize(
    ("input_fd", "output_fd"),
    [(-1, 8), (7, -1), (7, 7), (True, 8), (7, False)],
)
def test_transient_unit_rejects_invalid_broker_owned_descriptors(
    input_fd: int,
    output_fd: int,
) -> None:
    with pytest.raises(ProbeSystemdError, match="probe_transient_descriptors_invalid"):
        build_probe_transient_unit(
            _request(),
            descriptors=ProbeTransientDescriptors(input_fd=input_fd, output_fd=output_fd),
        )


def test_transient_unit_rejects_a_non_request_without_rendering_a_policy() -> None:
    with pytest.raises(ProbeSystemdError, match="probe_transient_request_invalid"):
        build_probe_transient_unit(
            cast(ProbeBrokerRequest, object()),
            descriptors=ProbeTransientDescriptors(input_fd=7, output_fd=8),
        )
