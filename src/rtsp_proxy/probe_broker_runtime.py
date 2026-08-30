from __future__ import annotations

import grp
import os
import platform
import pwd
import re
import signal
import socket
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import IPv4Network, IPv6Network, ip_network
from pathlib import Path

from rtsp_proxy.probe_broker_service import ProbeBrokerService
from rtsp_proxy.probe_connect_guard import (
    BpftoolProbeConnectGuardBackend,
    ProbeConnectGuardManager,
    trusted_probe_connect_guard_artifact_identity,
)
from rtsp_proxy.probe_execution import (
    ProbeExecutionBroker,
    ProbeExecutionStartupRecovery,
)
from rtsp_proxy.probe_execution_linux import (
    LinuxProbeExecutionChannelFactory,
    LinuxSystemdCgroupResolver,
)
from rtsp_proxy.probe_launcher import ProbeFfprobeResultDecoder
from rtsp_proxy.probe_systemd import SystemdProbeManager
from rtsp_proxy.probe_systemd_dbus import DbusNextSystemdTransport

_SYSTEMD_LISTEN_FD = 3
_EXPECTED_PEER_NAME = "rtsp-proxy"
_RELEASES_ROOT = Path("/opt/rtsp-proxy/releases")
_RELEASE_ID = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]{0,127}$")
_GUARD_OBJECT_RELATIVE = Path(
    "libexec/rtsp-proxy-probe/rtsp_probe_connect_guard.bpf.o"
)
_PIN_ROOT = Path("/sys/fs/bpf/rtsp-proxy-probe-broker")
_OWNERSHIP_ROOT = Path("/run/rtsp-proxy-probe-broker/guard-ownership")


class ProbeBrokerRuntimeError(RuntimeError):
    """The installed Linux broker boundary is unavailable or inconsistent."""


@dataclass(frozen=True, slots=True)
class ProbeBrokerRuntime:
    bpftool_path: Path
    allowed_networks: tuple[IPv4Network | IPv6Network, ...]
    guard_object_path: Path
    pin_root: Path = _PIN_ROOT
    ownership_root: Path = _OWNERSHIP_ROOT


def load_probe_broker_runtime(environment: Mapping[str, str]) -> ProbeBrokerRuntime:
    """Load the one host-specific tool path allowed by the installed service."""

    raw_path = environment.get("RTSP_PROXY_PROBE_BPFTOOL")
    raw_networks = environment.get("RTSP_PROXY_PROBE_ALLOWED_CIDRS")
    if not isinstance(raw_path, str) or not raw_path or raw_path.strip() != raw_path:
        raise ProbeBrokerRuntimeError("probe_broker_runtime_invalid")
    bpftool_path = Path(raw_path)
    if (
        not bpftool_path.is_absolute()
        or ".." in bpftool_path.parts
        or str(bpftool_path) != raw_path
    ):
        raise ProbeBrokerRuntimeError("probe_broker_runtime_invalid")
    return ProbeBrokerRuntime(
        bpftool_path=bpftool_path,
        allowed_networks=_parse_allowed_networks(raw_networks),
        guard_object_path=_installed_guard_object_path(),
    )


def _installed_guard_object_path() -> Path:
    """Derive the immutable no-symlink artifact path from the installed venv."""

    prefix = Path(sys.prefix)
    release_root = prefix.parent
    if (
        not prefix.is_absolute()
        or prefix.name != ".venv"
        or release_root.parent != _RELEASES_ROOT
        or _RELEASE_ID.fullmatch(release_root.name) is None
    ):
        raise ProbeBrokerRuntimeError("probe_broker_release_root_invalid")
    return release_root / _GUARD_OBJECT_RELATIVE


def _parse_allowed_networks(
    raw_networks: str | None,
) -> tuple[IPv4Network | IPv6Network, ...]:
    if not isinstance(raw_networks, str) or not raw_networks:
        raise ProbeBrokerRuntimeError("probe_broker_runtime_invalid")
    parts = raw_networks.split(",")
    if not 1 <= len(parts) <= 64 or any(not part or part.strip() != part for part in parts):
        raise ProbeBrokerRuntimeError("probe_broker_runtime_invalid")
    try:
        networks = tuple(ip_network(part, strict=True) for part in parts)
    except ValueError:
        raise ProbeBrokerRuntimeError("probe_broker_runtime_invalid") from None
    canonical = tuple(
        sorted(
            networks,
            key=lambda network: (
                network.version,
                int(network.network_address),
                network.prefixlen,
            ),
        )
    )
    if (
        networks != canonical
        or tuple(str(network) for network in networks) != tuple(parts)
        or any(
            first.overlaps(second)
            for index, first in enumerate(networks)
            for second in networks[index + 1 :]
            if first.version == second.version
        )
    ):
        raise ProbeBrokerRuntimeError("probe_broker_runtime_invalid")
    return networks


def resolve_probe_broker_peer() -> tuple[int, int]:
    """Resolve the fixed local scheduler identity without caller-controlled names."""

    try:
        user = pwd.getpwnam(_EXPECTED_PEER_NAME)
        group = grp.getgrnam(_EXPECTED_PEER_NAME)
    except KeyError:
        raise ProbeBrokerRuntimeError("probe_broker_peer_invalid") from None
    if (
        user.pw_name != _EXPECTED_PEER_NAME
        or group.gr_name != _EXPECTED_PEER_NAME
        or isinstance(user.pw_uid, bool)
        or not isinstance(user.pw_uid, int)
        or user.pw_uid < 1
        or isinstance(user.pw_gid, bool)
        or not isinstance(user.pw_gid, int)
        or user.pw_gid != group.gr_gid
    ):
        raise ProbeBrokerRuntimeError("probe_broker_peer_invalid")
    return user.pw_uid, group.gr_gid


def systemd_activation_listener() -> socket.socket:
    """Take ownership of exactly one systemd-provided listening Unix socket."""

    try:
        listen_pid = int(os.environ.get("LISTEN_PID", "0"))
        listen_fds = int(os.environ.get("LISTEN_FDS", "0"))
    except ValueError:
        raise ProbeBrokerRuntimeError("probe_broker_socket_activation_invalid") from None
    if listen_pid != os.getpid() or listen_fds != 1:
        raise ProbeBrokerRuntimeError("probe_broker_socket_activation_invalid")
    try:
        listener = socket.socket(fileno=_SYSTEMD_LISTEN_FD)
        valid = (
            listener.family == socket.AF_UNIX
            and listener.type & socket.SOCK_STREAM != 0
            and listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 1
        )
    except OSError:
        raise ProbeBrokerRuntimeError("probe_broker_socket_activation_invalid") from None
    if not valid:
        listener.close()
        raise ProbeBrokerRuntimeError("probe_broker_socket_activation_invalid")
    return listener


def build_probe_broker_service(
    runtime: ProbeBrokerRuntime,
    *,
    expected_uid: int,
    expected_gid: int,
) -> ProbeBrokerService:
    """Assemble the fixed root-only adapters behind the local broker socket."""

    identity = trusted_probe_connect_guard_artifact_identity(
        bpftool_path=runtime.bpftool_path,
        object_path=runtime.guard_object_path,
    )
    guard_backend = BpftoolProbeConnectGuardBackend(
        bpftool_path=runtime.bpftool_path,
        object_path=runtime.guard_object_path,
        pin_root=runtime.pin_root,
        ownership_root=runtime.ownership_root,
        artifact_identity=identity,
    )
    guard = ProbeConnectGuardManager(backend=guard_backend)
    systemd_transport = DbusNextSystemdTransport()
    systemd = SystemdProbeManager(transport=systemd_transport)
    executor = ProbeExecutionBroker(
        systemd=systemd,
        guard=guard,
        cgroups=LinuxSystemdCgroupResolver(),
        channels=LinuxProbeExecutionChannelFactory(),
        decoder=ProbeFfprobeResultDecoder(clock=lambda: datetime.now(UTC)),
        recovery=ProbeExecutionStartupRecovery(units=systemd_transport, guards=guard),
    )
    return ProbeBrokerService(
        executor=executor,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        allowed_networks=runtime.allowed_networks,
        request_frame_timeout_seconds=2,
        response_frame_timeout_seconds=2,
        startup_timeout_seconds=30,
        cleanup_retry_timeout_seconds=5,
        max_workers=16,
    )


def run_probe_broker() -> None:
    """Run the installed root broker on its single socket-activation descriptor."""

    listener: socket.socket | None = None
    previous_handlers: dict[signal.Signals, signal.Handlers] = {}
    try:
        if sys.platform != "linux" or platform.system() != "Linux" or os.geteuid() != 0:
            raise ProbeBrokerRuntimeError("probe_broker_linux_root_required")
        runtime = load_probe_broker_runtime(os.environ)
        expected_uid, expected_gid = resolve_probe_broker_peer()
        listener = systemd_activation_listener()
        service = build_probe_broker_service(
            runtime,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        for watched_signal in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[watched_signal] = signal.getsignal(watched_signal)
            signal.signal(watched_signal, _stop_probe_broker)
        service.serve_forever(listener)
    except ProbeBrokerRuntimeError as error:
        raise SystemExit(str(error)) from None
    except Exception:
        raise SystemExit("probe_broker_startup_failed") from None
    finally:
        for watched_signal, previous_handler in previous_handlers.items():
            signal.signal(watched_signal, previous_handler)
        if listener is not None:
            listener.close()


def _stop_probe_broker(_signum: int, _frame: object) -> None:
    raise SystemExit(0)
