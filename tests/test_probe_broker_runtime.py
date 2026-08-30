from __future__ import annotations

import grp
import os
import platform
import pwd
import signal
import socket
import sys
from ipaddress import ip_network
from pathlib import Path
from types import SimpleNamespace

import pytest

import rtsp_proxy.probe_broker_runtime as runtime_module
from rtsp_proxy.probe_broker_runtime import (
    ProbeBrokerRuntime,
    ProbeBrokerRuntimeError,
    build_probe_broker_service,
    load_probe_broker_runtime,
    resolve_probe_broker_peer,
    run_probe_broker,
    systemd_activation_listener,
)
from rtsp_proxy.probe_broker_service import ProbeBrokerService, ProbeBrokerServiceError


def test_probe_broker_runtime_loads_only_one_absolute_host_tool_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "prefix", "/opt/rtsp-proxy/releases/0.12.0/.venv")
    runtime = load_probe_broker_runtime(
        {
            "RTSP_PROXY_PROBE_BPFTOOL": "/usr/lib/linux-tools/current/bpftool",
            "RTSP_PROXY_PROBE_ALLOWED_CIDRS": "10.20.0.0/16,2001:db8:20::/64",
        }
    )

    assert runtime.bpftool_path == Path("/usr/lib/linux-tools/current/bpftool")
    assert runtime.guard_object_path == Path(
        "/opt/rtsp-proxy/releases/0.12.0/libexec/rtsp-proxy-probe/"
        "rtsp_probe_connect_guard.bpf.o"
    )
    assert runtime.pin_root == Path("/sys/fs/bpf/rtsp-proxy-probe-broker")
    assert runtime.ownership_root == Path(
        "/run/rtsp-proxy-probe-broker/guard-ownership"
    )
    assert tuple(str(network) for network in runtime.allowed_networks) == (
        "10.20.0.0/16",
        "2001:db8:20::/64",
    )


@pytest.mark.parametrize(
    "environment",
    [
        {},
        {
            "RTSP_PROXY_PROBE_BPFTOOL": "bpftool",
            "RTSP_PROXY_PROBE_ALLOWED_CIDRS": "10.20.0.0/16",
        },
        {
            "RTSP_PROXY_PROBE_BPFTOOL": "/usr/bin/../bin/bpftool",
            "RTSP_PROXY_PROBE_ALLOWED_CIDRS": "10.20.0.0/16",
        },
        {
            "RTSP_PROXY_PROBE_BPFTOOL": "/usr/bin/bpftool\n",
            "RTSP_PROXY_PROBE_ALLOWED_CIDRS": "10.20.0.0/16",
        },
        {
            "RTSP_PROXY_PROBE_BPFTOOL": "/usr/bin/bpftool",
            "RTSP_PROXY_PROBE_ALLOWED_CIDRS": "",
        },
        {
            "RTSP_PROXY_PROBE_BPFTOOL": "/usr/bin/bpftool",
            "RTSP_PROXY_PROBE_ALLOWED_CIDRS": "10.20.0.1/16",
        },
        {
            "RTSP_PROXY_PROBE_BPFTOOL": "/usr/bin/bpftool",
            "RTSP_PROXY_PROBE_ALLOWED_CIDRS": "10.20.0.0/16,10.20.0.0/16",
        },
    ],
)
def test_probe_broker_runtime_rejects_ambiguous_host_tool_path(
    environment: dict[str, str],
) -> None:
    with pytest.raises(ProbeBrokerRuntimeError, match="probe_broker_runtime_invalid"):
        load_probe_broker_runtime(environment)


def test_probe_broker_peer_is_fixed_to_the_service_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        pwd,
        "getpwnam",
        lambda name: SimpleNamespace(pw_name=name, pw_uid=1200, pw_gid=1200),
    )
    monkeypatch.setattr(
        grp,
        "getgrnam",
        lambda name: SimpleNamespace(gr_name=name, gr_gid=1200),
    )

    assert resolve_probe_broker_peer() == (1200, 1200)


def test_probe_broker_peer_rejects_split_primary_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        pwd,
        "getpwnam",
        lambda name: SimpleNamespace(pw_name=name, pw_uid=1200, pw_gid=1201),
    )
    monkeypatch.setattr(
        grp,
        "getgrnam",
        lambda name: SimpleNamespace(gr_name=name, gr_gid=1200),
    )

    with pytest.raises(ProbeBrokerRuntimeError, match="probe_broker_peer_invalid"):
        resolve_probe_broker_peer()


def test_systemd_activation_listener_rejects_wrong_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LISTEN_PID", str(os.getpid()))
    monkeypatch.setenv("LISTEN_FDS", "2")

    with pytest.raises(ProbeBrokerRuntimeError, match="probe_broker_socket_activation_invalid"):
        systemd_activation_listener()


def test_probe_broker_console_script_is_packaged() -> None:
    project = Path("pyproject.toml").read_text(encoding="utf-8")

    assert (
        'rtsp-proxy-probe-broker = "rtsp_proxy.probe_broker_runtime:run_probe_broker"'
        in project
    )


def test_probe_broker_systemd_units_keep_the_privileged_boundary_narrow() -> None:
    socket_unit = Path("deploy/systemd/rtsp-proxy-probe-broker.socket").read_text(
        encoding="utf-8"
    )
    service_unit = Path("deploy/systemd/rtsp-proxy-probe-broker.service").read_text(
        encoding="utf-8"
    )

    assert "ListenStream=/run/rtsp-proxy-probe-broker/control.sock" in socket_unit
    assert "SocketUser=root" in socket_unit
    assert "SocketGroup=rtsp-proxy" in socket_unit
    assert "SocketMode=0660" in socket_unit
    assert "DirectoryMode=0755" in socket_unit
    assert "ExecStart=/opt/rtsp-proxy/current/.venv/bin/rtsp-proxy-probe-broker" in service_unit
    assert "User=root" in service_unit
    assert "RestrictAddressFamilies=AF_UNIX" in service_unit
    assert "TimeoutStopSec=75s" in service_unit
    assert "RuntimeDirectoryPreserve=yes" in service_unit
    assert "RuntimeDirectoryMode=0755" in service_unit
    assert "ReadWritePaths=/sys/fs/bpf/rtsp-proxy-probe-broker" in service_unit
    assert "RTSP_PROXY_PROBE_ALLOWED_CIDRS" not in service_unit
    assert "CAP_BPF CAP_NET_ADMIN CAP_PERFMON" in service_unit
    assert "CAP_SYS_ADMIN" not in service_unit
    assert "Restart=on-failure" in service_unit
    assert "MemoryMax=256M" in service_unit
    assert "MemorySwapMax=0" in service_unit
    assert "TasksMax=64" in service_unit
    assert "LimitNOFILE=256" in service_unit
    assert "LimitCORE=0" in service_unit
    assert "CPUQuota=200%" in service_unit


@pytest.mark.parametrize(
    "prefix",
    [
        "/opt/rtsp-proxy/current/.venv",
        "/opt/rtsp-proxy/releases/0.12.0/venv",
        "/srv/rtsp-proxy/releases/0.12.0/.venv",
    ],
)
def test_probe_broker_runtime_rejects_nonimmutable_release_root(
    monkeypatch: pytest.MonkeyPatch,
    prefix: str,
) -> None:
    monkeypatch.setattr(sys, "prefix", prefix)

    with pytest.raises(ProbeBrokerRuntimeError, match="probe_broker_release_root_invalid"):
        load_probe_broker_runtime(
            {
                "RTSP_PROXY_PROBE_BPFTOOL": "/usr/lib/linux-tools/current/bpftool",
                "RTSP_PROXY_PROBE_ALLOWED_CIDRS": "10.20.0.0/16",
            }
        )


@pytest.mark.skipif(sys.platform != "linux", reason="Linux socket activation contract")
def test_socket_activation_listener_accepts_one_unix_stream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    socket_path = Path(f"/tmp/rtsp-probe-broker-{os.getpid()}.sock")
    socket_path.unlink(missing_ok=True)
    original = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    original.bind(str(socket_path))
    original.listen(1)
    monkeypatch.setenv("LISTEN_PID", str(os.getpid()))
    monkeypatch.setenv("LISTEN_FDS", "1")
    monkeypatch.setattr(runtime_module, "_SYSTEMD_LISTEN_FD", original.fileno())
    try:
        listener = systemd_activation_listener()
        assert listener.family == socket.AF_UNIX
        assert listener.type & socket.SOCK_STREAM
        assert listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 1
        assert listener.detach() == original.fileno()
    finally:
        original.close()
        socket_path.unlink(missing_ok=True)


def test_probe_broker_runtime_assembles_the_fixed_production_adapters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = object()
    backend = object()
    backend_arguments: dict[str, object] = {}

    def build_backend(**arguments: object) -> object:
        backend_arguments.update(arguments)
        return backend

    monkeypatch.setattr(
        runtime_module,
        "trusted_probe_connect_guard_artifact_identity",
        lambda **_arguments: identity,
    )
    monkeypatch.setattr(
        runtime_module,
        "BpftoolProbeConnectGuardBackend",
        build_backend,
    )
    configured = ProbeBrokerRuntime(
        bpftool_path=Path("/usr/lib/linux-tools/current/bpftool"),
        allowed_networks=(),
        guard_object_path=Path(
            "/opt/rtsp-proxy/releases/0.12.0/libexec/rtsp-proxy-probe/"
            "rtsp_probe_connect_guard.bpf.o"
        ),
    )

    with pytest.raises(
        ProbeBrokerServiceError,
        match="probe_broker_service_policy_invalid",
    ):
        build_probe_broker_service(configured, expected_uid=1200, expected_gid=1200)

    assert backend_arguments == {
        "bpftool_path": configured.bpftool_path,
        "object_path": configured.guard_object_path,
        "pin_root": configured.pin_root,
        "ownership_root": configured.ownership_root,
        "artifact_identity": identity,
    }

    configured = ProbeBrokerRuntime(
        bpftool_path=configured.bpftool_path,
        allowed_networks=(ip_network("192.0.2.0/24"),),
        guard_object_path=configured.guard_object_path,
    )
    service = build_probe_broker_service(
        configured,
        expected_uid=1200,
        expected_gid=1200,
    )

    assert isinstance(service, ProbeBrokerService)


class _RuntimeListener:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _RuntimeService:
    def __init__(self, *, failure: Exception | None = None) -> None:
        self.failure = failure
        self.listener: object | None = None

    def serve_forever(self, listener: object) -> None:
        self.listener = listener
        if self.failure is not None:
            raise self.failure


def _install_root_runtime_fakes(
    monkeypatch: pytest.MonkeyPatch,
    *,
    service: _RuntimeService,
    listener: _RuntimeListener,
) -> list[tuple[object, object]]:
    signal_events: list[tuple[object, object]] = []
    monkeypatch.setattr(sys, "prefix", "/opt/rtsp-proxy/releases/0.12.0/.venv")
    configured = load_probe_broker_runtime(
        {
            "RTSP_PROXY_PROBE_BPFTOOL": "/usr/lib/linux-tools/current/bpftool",
            "RTSP_PROXY_PROBE_ALLOWED_CIDRS": "192.0.2.0/24",
        }
    )
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(runtime_module, "load_probe_broker_runtime", lambda _env: configured)
    monkeypatch.setattr(runtime_module, "resolve_probe_broker_peer", lambda: (1200, 1200))
    monkeypatch.setattr(runtime_module, "systemd_activation_listener", lambda: listener)
    monkeypatch.setattr(
        runtime_module,
        "build_probe_broker_service",
        lambda _runtime, **_identity: service,
    )
    monkeypatch.setattr(signal, "getsignal", lambda watched: ("old", watched))
    monkeypatch.setattr(
        signal,
        "signal",
        lambda watched, handler: signal_events.append((watched, handler)),
    )
    return signal_events


def test_probe_broker_entrypoint_restores_signals_and_closes_listener(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    listener = _RuntimeListener()
    service = _RuntimeService()
    signal_events = _install_root_runtime_fakes(
        monkeypatch,
        service=service,
        listener=listener,
    )

    run_probe_broker()

    assert service.listener is listener
    assert listener.closed is True
    assert signal_events == [
        (signal.SIGINT, runtime_module._stop_probe_broker),
        (signal.SIGTERM, runtime_module._stop_probe_broker),
        (signal.SIGINT, ("old", signal.SIGINT)),
        (signal.SIGTERM, ("old", signal.SIGTERM)),
    ]


def test_probe_broker_entrypoint_sanitizes_startup_failure_and_closes_listener(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    listener = _RuntimeListener()
    service = _RuntimeService(failure=RuntimeError("privileged secret"))
    _install_root_runtime_fakes(monkeypatch, service=service, listener=listener)

    with pytest.raises(SystemExit, match=r"^probe_broker_startup_failed$"):
        run_probe_broker()

    assert listener.closed is True


def test_probe_broker_entrypoint_requires_linux_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 1200)

    with pytest.raises(SystemExit, match=r"^probe_broker_linux_root_required$"):
        run_probe_broker()


def test_probe_broker_signal_handler_requests_clean_shutdown() -> None:
    with pytest.raises(SystemExit) as raised:
        runtime_module._stop_probe_broker(15, None)

    assert raised.value.code == 0
