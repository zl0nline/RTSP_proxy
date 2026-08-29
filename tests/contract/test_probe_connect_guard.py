from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from ipaddress import ip_address
from pathlib import Path
from typing import IO

import pytest

from rtsp_proxy.probe_executor import ProbeConnectGuardTarget

pytestmark = [pytest.mark.contract]

_CHILD = """
import json
import socket
import sys

allowed_port = int(sys.argv[1])
denied_port = int(sys.argv[2])
sys.stdin.buffer.read(1)

def connected(family, host, port):
    with socket.socket(family, socket.SOCK_STREAM) as connection:
        connection.settimeout(1)
        return connection.connect_ex((host, port)) == 0

print(json.dumps({
    "allowed_ipv4": connected(socket.AF_INET, "127.0.0.1", allowed_port),
    "denied_ipv4": connected(socket.AF_INET, "127.0.0.1", denied_port),
    "allowed_ipv6": connected(socket.AF_INET6, "::1", allowed_port),
    "denied_ipv6": connected(socket.AF_INET6, "::1", denied_port),
}, sort_keys=True), flush=True)
"""


class _OwnedResources:
    def __init__(self) -> None:
        self._cleanup: list[tuple[str, Callable[[], None]]] = []

    def own(self, label: str, cleanup: Callable[[], None]) -> None:
        self._cleanup.append((label, cleanup))

    def close(self) -> list[BaseException]:
        errors: list[BaseException] = []
        while self._cleanup:
            label, cleanup = self._cleanup.pop()
            try:
                cleanup()
            except BaseException as error:
                error.add_note(f"probe guard cleanup failed: {label}")
                errors.append(error)
        return errors


@contextmanager
def _managed_resources() -> Iterator[_OwnedResources]:
    resources = _OwnedResources()
    try:
        yield resources
    except BaseException as primary_error:
        cleanup_errors = resources.close()
        if cleanup_errors:
            raise BaseExceptionGroup(
                "probe guard contract and cleanup failed",
                [primary_error, *cleanup_errors],
            ) from None
        raise
    else:
        cleanup_errors = resources.close()
        if cleanup_errors:
            raise BaseExceptionGroup("probe guard cleanup failed", cleanup_errors)


def _run(*arguments: str) -> str:
    completed = subprocess.run(
        arguments,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if completed.returncode != 0:
        diagnostic = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(
            f"probe_guard_command_failed:{Path(arguments[0]).name}:"
            f"{arguments[1]}:{diagnostic or 'no_diagnostic'}"
        )
    return completed.stdout.strip()


def _mkdir_owned(path: Path, resources: _OwnedResources) -> None:
    path.mkdir()
    resources.own(f"directory {path}", path.rmdir)


def test_command_failure_exposes_native_diagnostic() -> None:
    with pytest.raises(
        RuntimeError,
        match=r"probe_guard_command_failed:python(?:3(?:\.\d+)?)?:-c:load denied",
    ):
        _run(
            sys.executable,
            "-c",
            "import sys; sys.stderr.write('load denied\\n'); raise SystemExit(2)",
        )


def _listener(family: socket.AddressFamily, host: str, port: int) -> socket.socket:
    listener = socket.socket(family, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family is socket.AF_INET6:
        listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    listener.bind((host, port))
    listener.listen(16)
    listener.settimeout(0.2)
    return listener


def _accept(listener: socket.socket, stopping: threading.Event) -> None:
    while not stopping.is_set():
        try:
            connection, _address = listener.accept()
        except TimeoutError:
            continue
        except OSError:
            if stopping.is_set():
                return
            raise
        with connection:
            connection.sendall(b"ok")


def _free_adjacent_ports() -> tuple[int, int]:
    for allowed in range(39_000, 40_000, 2):
        listeners: list[socket.socket] = []
        try:
            for family, host in (
                (socket.AF_INET, "127.0.0.1"),
                (socket.AF_INET6, "::1"),
            ):
                listeners.append(_listener(family, host, allowed))
                listeners.append(_listener(family, host, allowed + 1))
        except OSError:
            continue
        finally:
            for listener in listeners:
                listener.close()
        if len(listeners) == 4:
            return allowed, allowed + 1
    raise AssertionError("two adjacent IPv4/IPv6 ports are required")


def _map_update(bpftool: str, map_path: Path, target: ProbeConnectGuardTarget) -> None:
    key = (0).to_bytes(4, sys.byteorder)
    _run(
        bpftool,
        "map",
        "update",
        "pinned",
        str(map_path),
        "key",
        "hex",
        *(f"{byte:02x}" for byte in key),
        "value",
        "hex",
        *(f"{byte:02x}" for byte in target.map_value()),
    )


def _terminate_child(child: subprocess.Popen[str]) -> None:
    if child.poll() is None:
        child.kill()
        child.wait(timeout=5)


def _start_child(
    cgroup: Path,
    allowed_port: int,
    denied_port: int,
    resources: _OwnedResources,
    *,
    write_cgroup: Callable[[Path, int], None] | None = None,
) -> subprocess.Popen[str]:
    child = subprocess.Popen(
        [sys.executable, "-c", _CHILD, str(allowed_port), str(denied_port)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    resources.own(f"child stderr {child.pid}", lambda: _close_pipe(child.stderr))
    resources.own(f"child stdout {child.pid}", lambda: _close_pipe(child.stdout))
    resources.own(f"child stdin {child.pid}", lambda: _close_pipe(child.stdin))
    resources.own(f"child process {child.pid}", lambda: _terminate_child(child))
    if write_cgroup is None:
        write_cgroup = _write_cgroup
    write_cgroup(cgroup, child.pid)
    return child


def _write_cgroup(cgroup: Path, pid: int) -> None:
    cgroup.joinpath("cgroup.procs").write_text(f"{pid}\n", encoding="ascii")


def _release(child: subprocess.Popen[str]) -> dict[str, bool]:
    assert child.stdin is not None
    child.stdin.write("x")
    child.stdin.flush()
    stdout, stderr = child.communicate(timeout=5)
    assert child.returncode == 0, stderr
    observed = json.loads(stdout)
    assert isinstance(observed, dict)
    return {str(key): bool(value) for key, value in observed.items()}


def _close_pipe(pipe: IO[str] | None) -> None:
    if pipe is not None:
        pipe.close()


def _join_thread(thread: threading.Thread) -> None:
    thread.join(timeout=2)
    if thread.is_alive():
        raise RuntimeError("probe_guard_listener_thread_still_running")


def _detach_if_owned(
    bpftool: str,
    cgroup: Path,
    attach_type: str,
    program_pin: Path,
) -> None:
    pinned_raw = json.loads(
        _run(bpftool, "-j", "prog", "show", "pinned", str(program_pin))
    )
    if isinstance(pinned_raw, dict):
        pinned_items = [pinned_raw]
    elif isinstance(pinned_raw, list):
        pinned_items = pinned_raw
    else:
        pinned_items = []
    if len(pinned_items) != 1 or not isinstance(pinned_items[0], dict):
        raise RuntimeError("probe_guard_pinned_program_inventory_invalid")
    program_id = pinned_items[0].get("id")
    if isinstance(program_id, bool) or not isinstance(program_id, int):
        raise RuntimeError("probe_guard_pinned_program_id_invalid")

    attached_raw = json.loads(_run(bpftool, "-j", "cgroup", "show", str(cgroup)))
    if not isinstance(attached_raw, list):
        raise RuntimeError("probe_guard_cgroup_inventory_invalid")
    matching = [
        item
        for item in attached_raw
        if isinstance(item, dict)
        and item.get("id") == program_id
        and item.get("attach_type") == attach_type
    ]
    if len(matching) > 1:
        raise RuntimeError("probe_guard_duplicate_attachment")
    if matching:
        _run(
            bpftool,
            "cgroup",
            "detach",
            str(cgroup),
            attach_type,
            "pinned",
            str(program_pin),
        )


@pytest.mark.parametrize("failed_phase", ["attach", "map_update", "cgroup_write"])
def test_owned_cleanup_preserves_primary_failure_and_runs_every_action(
    failed_phase: str,
) -> None:
    completed: list[str] = []

    def failed_detach() -> None:
        completed.append("detach")
        raise RuntimeError("detach_failed")

    with pytest.raises(ExceptionGroup) as raised, _managed_resources() as resources:
        resources.own("remove cgroup", lambda: completed.append("cgroup"))
        resources.own("detach program", failed_detach)
        resources.own("remove pins", lambda: completed.append("pins"))
        raise RuntimeError(f"{failed_phase}_failed")

    assert completed == ["pins", "detach", "cgroup"]
    assert [str(error) for error in raised.value.exceptions] == [
        f"{failed_phase}_failed",
        "detach_failed",
    ]


def test_owned_directory_collision_is_not_cleaned_up(tmp_path: Path) -> None:
    foreign = tmp_path / "foreign"
    foreign.mkdir()

    with pytest.raises(FileExistsError), _managed_resources() as resources:
        _mkdir_owned(foreign, resources)

    assert foreign.is_dir()


def test_owned_cleanup_runs_for_process_interruption() -> None:
    completed: list[str] = []

    with (
        pytest.raises(KeyboardInterrupt, match="interrupted"),
        _managed_resources() as resources,
    ):
        resources.own("first", lambda: completed.append("first"))
        resources.own("second", lambda: completed.append("second"))
        raise KeyboardInterrupt("interrupted")

    assert completed == ["second", "first"]


def test_child_is_owned_before_cgroup_write(tmp_path: Path) -> None:
    child_pid: int | None = None

    def fail_write(_cgroup: Path, pid: int) -> None:
        nonlocal child_pid
        child_pid = pid
        raise RuntimeError("cgroup_write_failed")

    with (
        pytest.raises(RuntimeError, match="cgroup_write_failed"),
        _managed_resources() as resources,
    ):
        _start_child(tmp_path, 39_000, 39_001, resources, write_cgroup=fail_write)

    assert child_pid is not None
    with pytest.raises(ProcessLookupError):
        os.kill(child_pid, 0)


@pytest.mark.skipif(
    os.environ.get("RTSP_PROXY_RUN_PROBE_BPF_CONTRACT") != "1",
    reason="privileged probe BPF contract is opt-in",
)
def test_connect_guard_allows_only_one_literal_family_address_and_port() -> None:
    if sys.platform != "linux" or os.geteuid() != 0:
        pytest.fail("probe BPF contract requires a root Linux test process")
    bpftool_raw = os.environ.get("RTSP_PROXY_BPFTOOL", "")
    bpftool_path = Path(bpftool_raw)
    object_raw = os.environ.get("RTSP_PROXY_PROBE_GUARD_BPF_OBJECT", "")
    object_path = Path(object_raw)
    if (
        not bpftool_path.is_absolute()
        or not bpftool_path.is_file()
        or not os.access(bpftool_path, os.X_OK)
        or not object_path.is_absolute()
        or not object_path.is_file()
    ):
        pytest.fail("absolute executable bpftool and BPF object are required")
    bpftool = str(bpftool_path)

    allowed_port, denied_port = _free_adjacent_ports()
    listeners: list[socket.socket] = []
    threads: list[threading.Thread] = []
    stopping = threading.Event()

    suffix = uuid.uuid4().hex[:12]
    cgroup = Path("/sys/fs/cgroup") / f"rtsp-probe-guard-{suffix}"
    pin_root = Path("/sys/fs/bpf") / f"rtsp-probe-guard-{suffix}"
    program_pins = pin_root / "programs"
    map_pins = pin_root / "maps"
    ipv4_program = program_pins / "rtsp_probe_guard_ipv4"
    ipv6_program = program_pins / "rtsp_probe_guard_ipv6"
    target_map = map_pins / "allowed_target"
    with _managed_resources() as resources:
        for family, host in (
            (socket.AF_INET, "127.0.0.1"),
            (socket.AF_INET6, "::1"),
        ):
            for port in (allowed_port, denied_port):
                listener = _listener(family, host, port)
                listeners.append(listener)
                resources.own(f"listener {host}:{port}", listener.close)
        for listener in listeners:
            thread = threading.Thread(
                target=_accept,
                args=(listener, stopping),
                daemon=True,
            )
            thread.start()
            threads.append(thread)
            resources.own(
                f"listener thread {thread.name}",
                lambda thread=thread: _join_thread(thread),
            )
        resources.own("listener stop signal", stopping.set)

        _mkdir_owned(cgroup, resources)
        _mkdir_owned(pin_root, resources)
        _mkdir_owned(program_pins, resources)
        _mkdir_owned(map_pins, resources)
        for path in (ipv4_program, ipv6_program, target_map):
            resources.own(f"pin {path}", lambda path=path: path.unlink(missing_ok=True))
        _run(
            bpftool,
            "prog",
            "loadall",
            str(object_path),
            str(program_pins),
            "pinmaps",
            str(map_pins),
        )
        resources.own(
            "IPv4 cgroup attachment",
            lambda: _detach_if_owned(
                bpftool,
                cgroup,
                "cgroup_inet4_connect",
                ipv4_program,
            ),
        )
        _run(
            bpftool,
            "cgroup",
            "attach",
            str(cgroup),
            "cgroup_inet4_connect",
            "pinned",
            str(ipv4_program),
        )
        resources.own(
            "IPv6 cgroup attachment",
            lambda: _detach_if_owned(
                bpftool,
                cgroup,
                "cgroup_inet6_connect",
                ipv6_program,
            ),
        )
        _run(
            bpftool,
            "cgroup",
            "attach",
            str(cgroup),
            "cgroup_inet6_connect",
            "pinned",
            str(ipv6_program),
        )

        _map_update(
            bpftool,
            target_map,
            ProbeConnectGuardTarget(ip_address("127.0.0.1"), allowed_port),
        )
        ipv4 = _start_child(cgroup, allowed_port, denied_port, resources)
        assert _release(ipv4) == {
            "allowed_ipv4": True,
            "denied_ipv4": False,
            "allowed_ipv6": False,
            "denied_ipv6": False,
        }

        _map_update(
            bpftool,
            target_map,
            ProbeConnectGuardTarget(ip_address("::1"), allowed_port),
        )
        ipv6 = _start_child(cgroup, allowed_port, denied_port, resources)
        assert _release(ipv6) == {
            "allowed_ipv4": False,
            "denied_ipv4": False,
            "allowed_ipv6": True,
            "denied_ipv6": False,
        }

    assert not cgroup.exists()
    assert not pin_root.exists()
    assert all(not thread.is_alive() for thread in threads)

    assert not cgroup.exists()
    assert not pin_root.exists()
