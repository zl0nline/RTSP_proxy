from __future__ import annotations

import json
import multiprocessing
import os
import platform
import selectors
import shutil
import signal
import sys
from collections.abc import Iterator
from contextlib import suppress
from dataclasses import dataclass
from hashlib import sha256
from ipaddress import ip_address
from multiprocessing.connection import Connection
from pathlib import Path
from threading import Event, Thread
from typing import Any
from uuid import UUID, uuid4

import pytest

from rtsp_proxy import probe_connect_guard
from rtsp_proxy.probe_connect_guard import (
    BpftoolProbeConnectGuardBackend,
    ProbeConnectGuardArtifactIdentity,
    ProbeConnectGuardBackend,
    ProbeConnectGuardError,
    ProbeConnectGuardManager,
    ProbeConnectGuardScope,
)
from rtsp_proxy.probe_executor import ProbeConnectGuardTarget


@dataclass(slots=True)
class _RecordingBackend(ProbeConnectGuardBackend):
    installed: list[ProbeConnectGuardScope]
    verified: list[ProbeConnectGuardScope]
    removed: list[ProbeConnectGuardScope]
    install_error: BaseException | None = None
    verify_error: BaseException | None = None
    remove_errors: list[BaseException] | None = None
    reconciled_remaining: int = 0

    def install(self, scope: ProbeConnectGuardScope, *, timeout_seconds: float) -> None:
        assert 0 < timeout_seconds <= 3.0
        self.installed.append(scope)
        if self.install_error is not None:
            raise self.install_error

    def verify(self, scope: ProbeConnectGuardScope, *, timeout_seconds: float) -> None:
        assert 0 < timeout_seconds <= 3.0
        self.verified.append(scope)
        if self.verify_error is not None:
            raise self.verify_error

    def remove(self, scope: ProbeConnectGuardScope, *, timeout_seconds: float) -> None:
        assert 0 < timeout_seconds <= 3.0
        self.removed.append(scope)
        if self.remove_errors:
            raise self.remove_errors.pop(0)

    def reconcile_owned(self, *, timeout_seconds: float) -> int:
        assert 0 < timeout_seconds <= 3.0
        return self.reconciled_remaining


def _manager() -> tuple[ProbeConnectGuardManager, _RecordingBackend]:
    backend = _RecordingBackend(installed=[], verified=[], removed=[])
    return ProbeConnectGuardManager(backend=backend), backend


def _unit_name(request_id: UUID) -> str:
    return f"rtsp-probe-{request_id.hex}.service"


def _receipt_entries(ownership_root: Path) -> list[Path]:
    return sorted(
        path
        for path in ownership_root.iterdir()
        if path.name != ".probe-connect-guard.lock"
    )


def _legacy_v2_receipt_bytes(
    backend: BpftoolProbeConnectGuardBackend,
    scope: ProbeConnectGuardScope,
    *,
    phase: int,
    scope_device: int,
    scope_inode: int,
) -> bytes:
    return (
        json.dumps(
            {
                "address": str(scope.target.address),
                "artifact_release_id": backend._artifact_release.release_id,
                "cgroup_path": str(scope.cgroup_path),
                "object_sha256": backend._artifact_release.object_sha256,
                "phase": phase,
                "port": scope.target.port,
                "request_id": str(scope.request_id),
                "scope_device": f"{scope_device:020d}",
                "scope_inode": f"{scope_inode:020d}",
                "unit_name": scope.unit_name,
                "version": 2,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _simulate_backend_process_exit(
    backend: BpftoolProbeConnectGuardBackend,
    *scopes: ProbeConnectGuardScope,
) -> None:
    for scope in scopes:
        backend._forget_scope_coordinator(scope)


def test_guard_manager_installs_verifies_and_releases_one_exact_scope(
    tmp_path: Path,
) -> None:
    manager, backend = _manager()
    request_id = uuid4()
    unit_name = _unit_name(request_id)
    cgroup_path = tmp_path / unit_name
    cgroup_path.mkdir()
    target = ProbeConnectGuardTarget(ip_address("192.0.2.20"), 8554)

    lease = manager.install(
        request_id=request_id,
        unit_name=unit_name,
        cgroup_path=cgroup_path,
        target=target,
        timeout_seconds=3.0,
    )

    assert backend.installed == backend.verified
    assert len(backend.installed) == 1
    assert backend.installed[0] == ProbeConnectGuardScope(
        request_id=request_id,
        unit_name=unit_name,
        cgroup_path=cgroup_path,
        target=target,
    )
    assert lease.request_id == request_id
    assert lease.unit_name == unit_name
    assert lease.target == target
    assert "192.0.2.20" not in repr(lease)

    manager.release(lease, timeout_seconds=3.0)

    assert backend.removed == backend.installed
    with pytest.raises(ProbeConnectGuardError, match="probe_guard_lease_invalid"):
        manager.release(lease, timeout_seconds=3.0)


def test_guard_manager_reconciles_zero_residue_before_first_install(
    tmp_path: Path,
) -> None:
    class _ReconcileCountingBackend(_RecordingBackend):
        reconcile_calls = 0

        def reconcile_owned(self, *, timeout_seconds: float) -> int:
            self.reconcile_calls += 1
            return super().reconcile_owned(timeout_seconds=timeout_seconds)

    backend = _ReconcileCountingBackend(installed=[], verified=[], removed=[])
    manager = ProbeConnectGuardManager(backend=backend)
    scope = _guard_scope(tmp_path)

    lease = manager.install(
        request_id=scope.request_id,
        unit_name=scope.unit_name,
        cgroup_path=scope.cgroup_path,
        target=scope.target,
        timeout_seconds=3.0,
    )

    assert backend.reconcile_calls == 1
    manager.release(lease, timeout_seconds=3.0)


@pytest.mark.parametrize(
    ("unit_name", "cgroup_name"),
    [
        ("rtsp-probe-wrong.service", "rtsp-probe-wrong.service"),
        ("rtsp-probe-wrong.service", "foreign.service"),
    ],
)
def test_guard_manager_rejects_unbound_unit_or_cgroup_before_kernel_mutation(
    tmp_path: Path,
    unit_name: str,
    cgroup_name: str,
) -> None:
    manager, backend = _manager()
    request_id = uuid4()
    cgroup_path = tmp_path / cgroup_name
    cgroup_path.mkdir()

    with pytest.raises(ProbeConnectGuardError, match="probe_guard_scope_invalid"):
        manager.install(
            request_id=request_id,
            unit_name=unit_name,
            cgroup_path=cgroup_path,
            target=ProbeConnectGuardTarget(ip_address("192.0.2.20"), 8554),
            timeout_seconds=3.0,
        )

    assert backend.installed == []
    assert backend.verified == []
    assert backend.removed == []


def test_guard_manager_collects_an_ambiguous_install_before_reporting_failure(
    tmp_path: Path,
) -> None:
    manager, backend = _manager()
    request_id = uuid4()
    unit_name = _unit_name(request_id)
    cgroup_path = tmp_path / unit_name
    cgroup_path.mkdir()
    backend.verify_error = RuntimeError("must-not-escape")

    with pytest.raises(ProbeConnectGuardError) as raised:
        manager.install(
            request_id=request_id,
            unit_name=unit_name,
            cgroup_path=cgroup_path,
            target=ProbeConnectGuardTarget(ip_address("192.0.2.20"), 8554),
            timeout_seconds=3.0,
        )

    assert str(raised.value) == "probe_guard_install_failed"
    assert "must-not-escape" not in repr(raised.value)
    assert backend.removed == backend.installed


def test_guard_manager_uses_one_install_and_readback_deadline(tmp_path: Path) -> None:
    backend = _RecordingBackend(installed=[], verified=[], removed=[])
    observed_times = iter([0.0, 0.0, 0.0, 4.0])
    manager = ProbeConnectGuardManager(
        backend=backend,
        monotonic=lambda: next(observed_times),
    )
    scope = _guard_scope(tmp_path)

    with pytest.raises(ProbeConnectGuardError, match="probe_guard_install_failed"):
        manager.install(
            request_id=scope.request_id,
            unit_name=scope.unit_name,
            cgroup_path=scope.cgroup_path,
            target=scope.target,
            timeout_seconds=3.0,
        )

    assert backend.installed == [scope]
    assert backend.verified == []
    assert backend.removed == [scope]


def test_guard_manager_retries_owned_cleanup_before_reusing_a_scope(
    tmp_path: Path,
) -> None:
    manager, backend = _manager()
    request_id = uuid4()
    unit_name = _unit_name(request_id)
    cgroup_path = tmp_path / unit_name
    cgroup_path.mkdir()
    backend.verify_error = RuntimeError("ambiguous")
    backend.remove_errors = [RuntimeError("first cleanup failed")]
    target = ProbeConnectGuardTarget(ip_address("192.0.2.20"), 8554)

    with pytest.raises(ProbeConnectGuardError, match="probe_guard_cleanup_pending"):
        manager.install(
            request_id=request_id,
            unit_name=unit_name,
            cgroup_path=cgroup_path,
            target=target,
            timeout_seconds=3.0,
        )
    with pytest.raises(ProbeConnectGuardError, match="probe_guard_already_active"):
        manager.install(
            request_id=request_id,
            unit_name=unit_name,
            cgroup_path=cgroup_path,
            target=target,
            timeout_seconds=3.0,
        )

    assert manager.retry_pending_cleanup(timeout_seconds=3.0) == 0
    assert backend.removed == [backend.installed[0], backend.installed[0]]


def test_guard_manager_preserves_interruption_after_successful_cleanup(
    tmp_path: Path,
) -> None:
    manager, backend = _manager()
    request_id = uuid4()
    unit_name = _unit_name(request_id)
    cgroup_path = tmp_path / unit_name
    cgroup_path.mkdir()
    backend.verify_error = KeyboardInterrupt("stop")

    with pytest.raises(KeyboardInterrupt, match="stop"):
        manager.install(
            request_id=request_id,
            unit_name=unit_name,
            cgroup_path=cgroup_path,
            target=ProbeConnectGuardTarget(ip_address("192.0.2.20"), 8554),
            timeout_seconds=3.0,
        )

    assert backend.removed == backend.installed


def test_guard_manager_preserves_cleanup_interruption_after_ordinary_failure(
    tmp_path: Path,
) -> None:
    manager, backend = _manager()
    request_id = uuid4()
    unit_name = _unit_name(request_id)
    cgroup_path = tmp_path / unit_name
    cgroup_path.mkdir()
    backend.verify_error = RuntimeError("ambiguous")
    backend.remove_errors = [KeyboardInterrupt("cleanup interrupted")]

    with pytest.raises(BaseExceptionGroup) as raised:
        manager.install(
            request_id=request_id,
            unit_name=unit_name,
            cgroup_path=cgroup_path,
            target=ProbeConnectGuardTarget(ip_address("192.0.2.20"), 8554),
            timeout_seconds=3.0,
        )

    assert any(
        isinstance(error, KeyboardInterrupt) for error in raised.value.exceptions
    )
    assert any(
        isinstance(error, ProbeConnectGuardError)
        and str(error) == "probe_guard_cleanup_pending"
        for error in raised.value.exceptions
    )


def test_guard_manager_recovers_interruption_immediately_after_registry_insert(
    tmp_path: Path,
) -> None:
    manager, backend = _manager()
    scope = _guard_scope(tmp_path)

    class _InterruptAfterInsert(dict[str, object]):
        def __setitem__(self, key: str, value: object) -> None:
            super().__setitem__(key, value)
            raise KeyboardInterrupt("after registry insert")

    manager._active = _InterruptAfterInsert()  # type: ignore[assignment]

    with pytest.raises(KeyboardInterrupt, match="after registry insert"):
        manager.install(
            request_id=scope.request_id,
            unit_name=scope.unit_name,
            cgroup_path=scope.cgroup_path,
            target=scope.target,
            timeout_seconds=3.0,
        )

    assert backend.installed == []
    assert manager.retry_pending_cleanup(timeout_seconds=3.0) == 0


@pytest.mark.parametrize("failure", ["ordinary", "interrupt"])
def test_guard_manager_cleans_a_failed_or_interrupted_receipt_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    fake = _FakeBpftool()
    backend = _bpftool_backend(tmp_path, run=fake)
    manager = ProbeConnectGuardManager(backend=backend)
    scope = _guard_scope(tmp_path)

    def failing_write(_descriptor: int, _payload: bytes) -> int:
        if failure == "interrupt":
            raise KeyboardInterrupt("receipt interrupted")
        return 0

    monkeypatch.setattr(os, "write", failing_write)
    if failure == "interrupt":
        expected_error: type[BaseException] = KeyboardInterrupt
        expected_message = "receipt interrupted"
    else:
        expected_error = ProbeConnectGuardError
        expected_message = "probe_guard_install_failed"

    with pytest.raises(expected_error, match=expected_message):
        manager.install(
            request_id=scope.request_id,
            unit_name=scope.unit_name,
            cgroup_path=scope.cgroup_path,
            target=scope.target,
            timeout_seconds=3.0,
        )

    assert fake.commands == []
    assert list((tmp_path / "pins").iterdir()) == []
    assert _receipt_entries(tmp_path / "ownership") == []


def test_guard_manager_retries_only_one_bounded_cleanup_batch(tmp_path: Path) -> None:
    manager, backend = _manager()
    backend.verify_error = RuntimeError("ambiguous")
    backend.remove_errors = [RuntimeError("cleanup failed") for _ in range(10)]
    target = ProbeConnectGuardTarget(ip_address("192.0.2.20"), 8554)

    for _index in range(10):
        request_id = uuid4()
        unit_name = _unit_name(request_id)
        cgroup_path = tmp_path / unit_name
        cgroup_path.mkdir()
        with pytest.raises(ProbeConnectGuardError, match="probe_guard_cleanup_pending"):
            manager.install(
                request_id=request_id,
                unit_name=unit_name,
                cgroup_path=cgroup_path,
                target=target,
                timeout_seconds=3.0,
            )

    assert manager.retry_pending_cleanup(timeout_seconds=3.0) == 2
    assert manager.retry_pending_cleanup(timeout_seconds=3.0) == 0


class _FakeBpftool:
    def __init__(self, *, corrupt_map_value: bool = False) -> None:
        self.commands: list[tuple[str, ...]] = []
        self.attachments: dict[str, int] = {}
        self.foreign_attachments: list[tuple[int, str]] = []
        self.corrupt_map_value = corrupt_map_value
        self.ipv4_tag = "1" * 16
        self.ipv6_tag = "2" * 16
        self.program_map_ids = [201]
        self.detach_behavior = "normal"

    def __call__(
        self,
        arguments: tuple[str, ...],
        *,
        timeout_seconds: float,
    ) -> str:
        assert 0 < timeout_seconds <= 3.0
        self.commands.append(arguments)
        command = arguments[1:]
        if command[:2] == ("prog", "loadall"):
            program_root = Path(command[3])
            map_root = Path(command[5])
            for pin in (
                program_root / "rtsp_probe_guard_ipv4",
                program_root / "rtsp_probe_guard_ipv6",
                map_root / "allowed_target",
            ):
                pin.touch()
                pin.chmod(0o600)
            return ""
        if command[:2] == ("cgroup", "attach"):
            self.attachments[str(command[3])] = (
                101 if command[3] == "cgroup_inet4_connect" else 102
            )
            return ""
        if command[:2] == ("map", "update"):
            return ""
        if command[:4] == ("-j", "prog", "show", "pinned"):
            program_id = 101 if command[4].endswith("ipv4") else 102
            return json.dumps(
                {
                    "id": program_id,
                    "type": "cgroup_sock_addr",
                    "name": "guard",
                    "tag": self.ipv4_tag if program_id == 101 else self.ipv6_tag,
                    "map_ids": self.program_map_ids,
                }
            )
        if command[:4] == ("-j", "map", "show", "pinned"):
            return json.dumps(
                {
                    "id": 201,
                    "type": "array",
                    "name": "allowed_target",
                    "flags": 0,
                    "bytes_key": 4,
                    "bytes_value": 32,
                    "max_entries": 1,
                }
            )
        if command[:4] == ("-j", "map", "lookup", "pinned"):
            value_start = next(
                index
                for index, recorded in enumerate(reversed(self.commands))
                if recorded[1:3] == ("map", "update")
            )
            update = self.commands[-1 - value_start]
            value_index = update.index("value") + 2
            value = list(update[value_index:])
            if self.corrupt_map_value:
                value[-1] = "01"
            return json.dumps(
                {
                    "key": ["0x00"] * 4,
                    "value": [f"0x{item}" for item in value],
                }
            )
        if command[:3] == ("-j", "cgroup", "show"):
            if not Path(command[3]).exists():
                raise RuntimeError("cgroup vanished")
            return json.dumps(
                [
                    {"id": program_id, "attach_type": attach_type}
                    for attach_type, program_id in sorted(self.attachments.items())
                ]
                + [
                    {"id": program_id, "attach_type": attach_type}
                    for program_id, attach_type in self.foreign_attachments
                ]
            )
        if command[:2] == ("cgroup", "detach"):
            if self.detach_behavior == "vanish":
                Path(command[2]).rmdir()
                raise RuntimeError("cgroup vanished during detach")
            if self.detach_behavior == "retain":
                return ""
            del self.attachments[str(command[3])]
            return ""
        raise AssertionError(f"unexpected bpftool command: {arguments!r}")


class _OverrideBpftool:
    def __init__(
        self,
        delegate: _FakeBpftool,
        *,
        prefix: tuple[str, ...],
        response: str | BaseException,
    ) -> None:
        self.delegate = delegate
        self.prefix = prefix
        self.response = response
        self.enabled = False

    def __call__(
        self,
        arguments: tuple[str, ...],
        *,
        timeout_seconds: float,
    ) -> str:
        if self.enabled and arguments[1 : 1 + len(self.prefix)] == self.prefix:
            if isinstance(self.response, BaseException):
                raise self.response
            return self.response
        return self.delegate(arguments, timeout_seconds=timeout_seconds)


def _bpftool_backend(
    tmp_path: Path,
    *,
    run: _FakeBpftool | _OverrideBpftool,
    create_roots: bool = True,
) -> BpftoolProbeConnectGuardBackend:
    bpftool = tmp_path / "bpftool"
    bpf_object = tmp_path / "guard.bpf.o"
    pin_root = tmp_path / "pins"
    ownership_root = tmp_path / "ownership"
    if create_roots:
        bpftool.write_bytes(b"fixture")
        bpftool.chmod(0o700)
        bpf_object.write_bytes(b"fixture")
        bpf_object.chmod(0o600)
        pin_root.mkdir()
        pin_root.chmod(0o700)
        ownership_root.mkdir()
        ownership_root.chmod(0o700)
    return BpftoolProbeConnectGuardBackend(
        bpftool_path=bpftool,
        object_path=bpf_object,
        pin_root=pin_root,
        ownership_root=ownership_root,
        artifact_identity=ProbeConnectGuardArtifactIdentity(
            bpftool_sha256=sha256(bpftool.read_bytes()).hexdigest(),
            object_sha256=sha256(bpf_object.read_bytes()).hexdigest(),
            ipv4_program_tag="1" * 16,
            ipv6_program_tag="2" * 16,
        ),
        trusted_owner_uid=os.getuid(),
        run=run,
    )


def _guard_scope(tmp_path: Path) -> ProbeConnectGuardScope:
    request_id = uuid4()
    unit_name = _unit_name(request_id)
    cgroup_path = tmp_path / unit_name
    cgroup_path.mkdir()
    return ProbeConnectGuardScope(
        request_id=request_id,
        unit_name=unit_name,
        cgroup_path=cgroup_path,
        target=ProbeConnectGuardTarget(ip_address("192.0.2.20"), 8554),
    )


def _spawned_reconcile_result(root: str, sender: Connection) -> None:
    backend = _bpftool_backend(
        Path(root),
        run=_FakeBpftool(),
        create_roots=False,
    )
    manager = ProbeConnectGuardManager(backend=backend)
    try:
        manager.reconcile_startup(timeout_seconds=0.2)
    except ProbeConnectGuardError as error:
        sender.send(("error", str(error)))
    else:
        sender.send(("success", ""))
    finally:
        sender.close()


def test_bpftool_backend_installs_reads_back_and_removes_exact_owned_state(
    tmp_path: Path,
) -> None:
    fake = _FakeBpftool()
    backend = _bpftool_backend(tmp_path, run=fake)
    manager = ProbeConnectGuardManager(backend=backend)
    request_id = uuid4()
    unit_name = _unit_name(request_id)
    cgroup_path = tmp_path / unit_name
    cgroup_path.mkdir()
    target = ProbeConnectGuardTarget(ip_address("192.0.2.20"), 8554)

    lease = manager.install(
        request_id=request_id,
        unit_name=unit_name,
        cgroup_path=cgroup_path,
        target=target,
        timeout_seconds=3.0,
    )
    scope_pin = tmp_path / "pins" / request_id.hex

    assert scope_pin.is_dir()
    assert fake.attachments == {
        "cgroup_inet4_connect": 101,
        "cgroup_inet6_connect": 102,
    }

    manager.release(lease, timeout_seconds=3.0)

    assert fake.attachments == {}
    assert not scope_pin.exists()


def test_bpftool_backend_preserves_defense_in_depth_cgroup_attachments(
    tmp_path: Path,
) -> None:
    fake = _FakeBpftool()
    fake.foreign_attachments = [
        (9001, "cgroup_inet4_connect"),
        (9002, "cgroup_inet6_connect"),
    ]
    backend = _bpftool_backend(tmp_path, run=fake)
    manager = ProbeConnectGuardManager(backend=backend)
    scope = _guard_scope(tmp_path)

    lease = manager.install(
        request_id=scope.request_id,
        unit_name=scope.unit_name,
        cgroup_path=scope.cgroup_path,
        target=scope.target,
        timeout_seconds=3.0,
    )
    manager.release(lease, timeout_seconds=3.0)

    assert fake.attachments == {}
    assert fake.foreign_attachments == [
        (9001, "cgroup_inet4_connect"),
        (9002, "cgroup_inet6_connect"),
    ]


def test_bpftool_backend_cleans_owned_pins_after_transient_cgroup_vanishes(
    tmp_path: Path,
) -> None:
    fake = _FakeBpftool()
    backend = _bpftool_backend(tmp_path, run=fake)
    manager = ProbeConnectGuardManager(backend=backend)
    scope = _guard_scope(tmp_path)
    lease = manager.install(
        request_id=scope.request_id,
        unit_name=scope.unit_name,
        cgroup_path=scope.cgroup_path,
        target=scope.target,
        timeout_seconds=3.0,
    )
    scope.cgroup_path.rmdir()

    manager.release(lease, timeout_seconds=3.0)

    assert not (tmp_path / "pins" / scope.request_id.hex).exists()


def test_bpftool_backend_refuses_an_unreceipted_pin_scope(tmp_path: Path) -> None:
    backend = _bpftool_backend(tmp_path, run=_FakeBpftool())
    scope = _guard_scope(tmp_path)
    scope_root = tmp_path / "pins" / scope.request_id.hex
    scope_root.mkdir(mode=0o700)

    with pytest.raises(
        ProbeConnectGuardError,
        match="probe_guard_ownership_invalid",
    ):
        backend.remove(scope, timeout_seconds=3.0)

    assert scope_root.is_dir()


def test_bpftool_backend_collects_receipt_after_owned_scope_disappears(
    tmp_path: Path,
) -> None:
    backend = _bpftool_backend(tmp_path, run=_FakeBpftool())
    scope = _guard_scope(tmp_path)
    backend.install(scope, timeout_seconds=3.0)
    scope_root = tmp_path / "pins" / scope.request_id.hex
    receipt = tmp_path / "ownership" / f"{scope.request_id.hex}.json"
    shutil.rmtree(scope_root)

    backend.remove(scope, timeout_seconds=3.0)

    assert not scope_root.exists()
    assert not receipt.exists()


def test_bpftool_backend_handles_cgroup_disappearance_during_detach(
    tmp_path: Path,
) -> None:
    fake = _FakeBpftool()
    fake.detach_behavior = "vanish"
    backend = _bpftool_backend(tmp_path, run=fake)
    manager = ProbeConnectGuardManager(backend=backend)
    scope = _guard_scope(tmp_path)
    lease = manager.install(
        request_id=scope.request_id,
        unit_name=scope.unit_name,
        cgroup_path=scope.cgroup_path,
        target=scope.target,
        timeout_seconds=3.0,
    )

    manager.release(lease, timeout_seconds=3.0)

    assert not (tmp_path / "pins" / scope.request_id.hex).exists()


def test_bpftool_backend_keeps_owned_state_when_detach_fails(
    tmp_path: Path,
) -> None:
    fake = _FakeBpftool()
    override = _OverrideBpftool(
        fake,
        prefix=("cgroup", "detach"),
        response=RuntimeError("detach failed"),
    )
    backend = _bpftool_backend(tmp_path, run=override)
    scope = _guard_scope(tmp_path)
    backend.install(scope, timeout_seconds=3.0)
    override.enabled = True

    with pytest.raises(
        ProbeConnectGuardError,
        match="probe_guard_kernel_operation_failed",
    ):
        backend.remove(scope, timeout_seconds=3.0)

    assert (tmp_path / "pins" / scope.request_id.hex).is_dir()


def test_bpftool_backend_retries_when_owned_attachment_survives_detach(
    tmp_path: Path,
) -> None:
    fake = _FakeBpftool()
    fake.detach_behavior = "retain"
    backend = _bpftool_backend(tmp_path, run=fake)
    manager = ProbeConnectGuardManager(backend=backend)
    scope = _guard_scope(tmp_path)
    lease = manager.install(
        request_id=scope.request_id,
        unit_name=scope.unit_name,
        cgroup_path=scope.cgroup_path,
        target=scope.target,
        timeout_seconds=3.0,
    )

    with pytest.raises(ProbeConnectGuardError, match="probe_guard_cleanup_pending"):
        manager.release(lease, timeout_seconds=3.0)

    fake.detach_behavior = "normal"
    assert manager.retry_pending_cleanup(timeout_seconds=3.0) == 0


def test_bpftool_backend_does_not_remove_a_colliding_foreign_scope(
    tmp_path: Path,
) -> None:
    fake = _FakeBpftool()
    backend = _bpftool_backend(tmp_path, run=fake)
    manager = ProbeConnectGuardManager(backend=backend)
    scope = _guard_scope(tmp_path)
    foreign_scope = tmp_path / "pins" / scope.request_id.hex
    foreign_scope.mkdir(mode=0o700)

    with pytest.raises(ProbeConnectGuardError, match="probe_guard_already_active"):
        manager.install(
            request_id=scope.request_id,
            unit_name=scope.unit_name,
            cgroup_path=scope.cgroup_path,
            target=scope.target,
            timeout_seconds=3.0,
        )

    assert foreign_scope.is_dir()
    assert list(foreign_scope.iterdir()) == []


def test_bpftool_backend_does_not_remove_scope_won_after_receipt_reservation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeBpftool()
    backend = _bpftool_backend(tmp_path, run=fake)
    manager = ProbeConnectGuardManager(backend=backend)
    scope = _guard_scope(tmp_path)
    foreign_scope = tmp_path / "pins" / scope.request_id.hex
    original_mkdir = os.mkdir
    original_rename = probe_connect_guard._rename_directory_no_replace

    def lose_scope_race(source: Path, destination: Path) -> None:
        if destination == foreign_scope:
            original_mkdir(destination, 0o700)
            raise FileExistsError(os.fspath(destination))
        original_rename(source, destination)

    monkeypatch.setattr(
        probe_connect_guard,
        "_rename_directory_no_replace",
        lose_scope_race,
    )

    with pytest.raises(ProbeConnectGuardError, match="probe_guard_already_active"):
        manager.install(
            request_id=scope.request_id,
            unit_name=scope.unit_name,
            cgroup_path=scope.cgroup_path,
            target=scope.target,
            timeout_seconds=3.0,
        )

    assert foreign_scope.is_dir()
    assert list(foreign_scope.iterdir()) == []
    assert _receipt_entries(tmp_path / "ownership") == []


def test_reconcile_collects_owned_reservation_after_scope_collision_crash(
    tmp_path: Path,
) -> None:
    backend = _bpftool_backend(tmp_path, run=_FakeBpftool())
    scope = _guard_scope(tmp_path)
    receipt = tmp_path / "ownership" / f"{scope.request_id.hex}.json"
    reservation_nonce = backend._create_receipt(scope, receipt)
    reservation_scope = backend._reservation_scope_path(scope, reservation_nonce)
    reservation_scope.mkdir(mode=0o700)
    backend._promote_receipt(scope, receipt, reservation_scope)
    foreign_scope = tmp_path / "pins" / scope.request_id.hex
    foreign_scope.mkdir(mode=0o700)

    assert backend.reconcile_owned(timeout_seconds=3.0) == 0

    assert foreign_scope.is_dir()
    assert list(foreign_scope.iterdir()) == []
    assert not reservation_scope.exists()
    assert not receipt.exists()


@pytest.mark.parametrize("interrupted", [False, True])
def test_collision_receipt_cleanup_failure_never_owns_the_foreign_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    interrupted: bool,
) -> None:
    fake = _FakeBpftool()
    backend = _bpftool_backend(tmp_path, run=fake)
    manager = ProbeConnectGuardManager(backend=backend)
    scope = _guard_scope(tmp_path)
    foreign_scope = tmp_path / "pins" / scope.request_id.hex
    receipt = tmp_path / "ownership" / f"{scope.request_id.hex}.json"
    original_mkdir = os.mkdir
    original_rename = probe_connect_guard._rename_directory_no_replace
    original_unlink = Path.unlink
    remaining_unlink_failures = 2

    def lose_scope_race(source: Path, destination: Path) -> None:
        if destination == foreign_scope:
            original_mkdir(destination, 0o700)
            raise FileExistsError(os.fspath(destination))
        original_rename(source, destination)

    def reject_receipt_unlink(
        path: Path,
        missing_ok: bool = False,
    ) -> None:
        nonlocal remaining_unlink_failures
        if path == receipt and remaining_unlink_failures:
            remaining_unlink_failures -= 1
            if interrupted:
                raise KeyboardInterrupt("receipt cleanup interrupted")
            raise OSError("ambiguous receipt cleanup")
        original_unlink(path, missing_ok=missing_ok)

    monkeypatch.setattr(
        probe_connect_guard,
        "_rename_directory_no_replace",
        lose_scope_race,
    )
    monkeypatch.setattr(Path, "unlink", reject_receipt_unlink)

    expected_error: type[BaseException] = (
        KeyboardInterrupt if interrupted else ProbeConnectGuardError
    )
    expected_message = (
        "receipt cleanup interrupted"
        if interrupted
        else "probe_guard_reconcile_required"
    )
    with pytest.raises(expected_error, match=expected_message):
        manager.install(
            request_id=scope.request_id,
            unit_name=scope.unit_name,
            cgroup_path=scope.cgroup_path,
            target=scope.target,
            timeout_seconds=3.0,
        )

    assert foreign_scope.is_dir()
    assert receipt.is_file()

    remaining_unlink_failures = 0
    with pytest.raises(ProbeConnectGuardError, match="probe_guard_already_active"):
        manager.install(
            request_id=scope.request_id,
            unit_name=scope.unit_name,
            cgroup_path=scope.cgroup_path,
            target=scope.target,
            timeout_seconds=3.0,
        )
    assert foreign_scope.is_dir()
    assert not receipt.exists()


def test_guard_manager_reconciles_receipt_proven_state_after_broker_restart(
    tmp_path: Path,
) -> None:
    fake = _FakeBpftool()
    first_backend = _bpftool_backend(tmp_path, run=fake)
    first_manager = ProbeConnectGuardManager(backend=first_backend)
    scope = _guard_scope(tmp_path)
    first_manager.install(
        request_id=scope.request_id,
        unit_name=scope.unit_name,
        cgroup_path=scope.cgroup_path,
        target=scope.target,
        timeout_seconds=3.0,
    )
    receipt = tmp_path / "ownership" / f"{scope.request_id.hex}.json"
    assert receipt.is_file()
    _simulate_backend_process_exit(first_backend, scope)

    restarted_manager = ProbeConnectGuardManager(
        backend=_bpftool_backend(tmp_path, run=fake, create_roots=False)
    )
    assert restarted_manager.reconcile_startup(timeout_seconds=3.0) == 0

    assert fake.attachments == {}
    assert not receipt.exists()
    assert not (tmp_path / "pins" / scope.request_id.hex).exists()


def test_reconcile_cleans_a_legacy_v2_active_receipt(tmp_path: Path) -> None:
    fake = _FakeBpftool()
    backend = _bpftool_backend(tmp_path, run=fake)
    scope = _guard_scope(tmp_path)
    backend.install(scope, timeout_seconds=3.0)
    scope_root = tmp_path / "pins" / scope.request_id.hex
    metadata = scope_root.stat()
    receipt = tmp_path / "ownership" / f"{scope.request_id.hex}.json"
    receipt.write_bytes(
        _legacy_v2_receipt_bytes(
            backend,
            scope,
            phase=1,
            scope_device=metadata.st_dev,
            scope_inode=metadata.st_ino,
        )
    )
    receipt.chmod(0o600)
    _simulate_backend_process_exit(backend, scope)

    restarted = _bpftool_backend(tmp_path, run=fake, create_roots=False)
    assert restarted.reconcile_owned(timeout_seconds=3.0) == 0

    assert not receipt.exists()
    assert not scope_root.exists()
    assert fake.attachments == {}


def test_reconcile_cleans_a_legacy_v2_uncommitted_receipt(tmp_path: Path) -> None:
    backend = _bpftool_backend(tmp_path, run=_FakeBpftool())
    scope = _guard_scope(tmp_path)
    receipt = tmp_path / "ownership" / f"{scope.request_id.hex}.json"
    receipt.write_bytes(
        _legacy_v2_receipt_bytes(
            backend,
            scope,
            phase=0,
            scope_device=0,
            scope_inode=0,
        )
    )
    receipt.chmod(0o600)

    assert backend.reconcile_owned(timeout_seconds=3.0) == 0
    assert not receipt.exists()


def test_reconcile_rejects_ambiguous_legacy_v2_uncommitted_scope(
    tmp_path: Path,
) -> None:
    backend = _bpftool_backend(tmp_path, run=_FakeBpftool())
    scope = _guard_scope(tmp_path)
    receipt = tmp_path / "ownership" / f"{scope.request_id.hex}.json"
    receipt.write_bytes(
        _legacy_v2_receipt_bytes(
            backend,
            scope,
            phase=0,
            scope_device=0,
            scope_inode=0,
        )
    )
    receipt.chmod(0o600)
    foreign_scope = tmp_path / "pins" / scope.request_id.hex
    foreign_scope.mkdir(mode=0o700)

    assert backend.reconcile_owned(timeout_seconds=3.0) == 1
    assert receipt.is_file()
    assert foreign_scope.is_dir()


def test_guard_manager_serializes_reconcile_against_another_broker_process(
    tmp_path: Path,
) -> None:
    fake = _FakeBpftool()
    backend = _bpftool_backend(tmp_path, run=fake)
    manager = ProbeConnectGuardManager(backend=backend)
    scope = _guard_scope(tmp_path)
    lease = manager.install(
        request_id=scope.request_id,
        unit_name=scope.unit_name,
        cgroup_path=scope.cgroup_path,
        target=scope.target,
        timeout_seconds=3.0,
    )
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(
        target=_spawned_reconcile_result,
        args=(os.fspath(tmp_path), sender),
    )
    process.start()
    sender.close()
    assert receiver.poll(3.0)
    assert receiver.recv() == ("error", "probe_guard_timeout")
    process.join(timeout=3.0)
    assert process.exitcode == 0
    receiver.close()

    manager.release(lease, timeout_seconds=3.0)


def test_bpftool_backend_stops_reconciliation_at_aggregate_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _bpftool_backend(tmp_path, run=_FakeBpftool())
    scope = _guard_scope(tmp_path)
    backend.install(scope, timeout_seconds=3.0)
    _simulate_backend_process_exit(backend, scope)
    observed = iter([0.0, 4.0])
    backend._monotonic = lambda: next(observed)

    def fail_remove(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise ProbeConnectGuardError("cleanup failed")

    monkeypatch.setattr(backend, "_remove_owned", fail_remove)

    assert backend.reconcile_owned(timeout_seconds=3.0) == 1


@pytest.mark.parametrize("interrupted", [False, True])
def test_bpftool_backend_collects_a_failed_receipt_promotion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    interrupted: bool,
) -> None:
    backend = _bpftool_backend(tmp_path, run=_FakeBpftool())
    scope = _guard_scope(tmp_path)

    def fail_promotion(*args: object, **kwargs: object) -> None:
        del args, kwargs
        if interrupted:
            raise KeyboardInterrupt("promotion interrupted")
        raise RuntimeError("promotion failed")

    monkeypatch.setattr(backend, "_promote_receipt", fail_promotion)
    expected_error: type[BaseException] = (
        probe_connect_guard.ProbeConnectGuardInstallRejectedInterruption
        if interrupted
        else probe_connect_guard.ProbeConnectGuardInstallRejected
    )

    with pytest.raises(expected_error):
        backend.install(scope, timeout_seconds=3.0)

    assert list((tmp_path / "pins").iterdir()) == []
    assert _receipt_entries(tmp_path / "ownership") == []


def test_bpftool_backend_preserves_receipt_promotion_and_cleanup_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _bpftool_backend(tmp_path, run=_FakeBpftool())
    scope = _guard_scope(tmp_path)
    original_rmdir = Path.rmdir

    def fail_promotion(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise RuntimeError("promotion failed")

    def fail_scope_cleanup(path: Path) -> None:
        if path.name.endswith(".reserved"):
            raise KeyboardInterrupt("scope cleanup interrupted")
        original_rmdir(path)

    monkeypatch.setattr(backend, "_promote_receipt", fail_promotion)
    monkeypatch.setattr(Path, "rmdir", fail_scope_cleanup)

    with pytest.raises(BaseExceptionGroup) as raised:
        backend.install(scope, timeout_seconds=3.0)

    assert any(isinstance(error, RuntimeError) for error in raised.value.exceptions)
    assert any(isinstance(error, KeyboardInterrupt) for error in raised.value.exceptions)
    assert any(path.name.endswith(".reserved") for path in (tmp_path / "pins").iterdir())


def test_bpftool_backend_refuses_an_existing_receipt_reservation(
    tmp_path: Path,
) -> None:
    backend = _bpftool_backend(tmp_path, run=_FakeBpftool())
    scope = _guard_scope(tmp_path)
    receipt = tmp_path / "ownership" / f"{scope.request_id.hex}.json"
    receipt.write_bytes(b"foreign")

    with pytest.raises(
        probe_connect_guard.ProbeConnectGuardInstallRejected,
        match="probe_guard_already_active",
    ):
        backend._create_receipt(scope, receipt)

    assert receipt.read_bytes() == b"foreign"


def test_bpftool_backend_preserves_receipt_write_and_cleanup_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _bpftool_backend(tmp_path, run=_FakeBpftool())
    scope = _guard_scope(tmp_path)
    receipt = tmp_path / "ownership" / f"{scope.request_id.hex}.json"

    def fail_fsync(descriptor: int) -> None:
        del descriptor
        raise OSError("fsync failed")

    monkeypatch.setattr(os, "fsync", fail_fsync)

    with pytest.raises(BaseExceptionGroup) as raised:
        backend._create_receipt(scope, receipt)

    assert len(raised.value.exceptions) == 2
    assert not receipt.exists()


@pytest.mark.parametrize("scope_state", ["missing", "wrong_mode"])
def test_bpftool_backend_refuses_unprovable_receipt_promotion(
    tmp_path: Path,
    scope_state: str,
) -> None:
    backend = _bpftool_backend(tmp_path, run=_FakeBpftool())
    scope = _guard_scope(tmp_path)
    receipt = tmp_path / "ownership" / f"{scope.request_id.hex}.json"
    scope_root = tmp_path / "pins" / scope.request_id.hex
    backend._create_receipt(scope, receipt)
    if scope_state == "wrong_mode":
        scope_root.mkdir(mode=0o700)
        scope_root.chmod(0o770)

    with pytest.raises(
        ProbeConnectGuardError,
        match="probe_guard_ownership_invalid",
    ):
        backend._promote_receipt(scope, receipt, scope_root)


@pytest.mark.parametrize("tamper", ["mode", "content", "temp_write_stall"])
def test_bpftool_backend_refuses_tampered_receipt_during_promotion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tamper: str,
) -> None:
    backend = _bpftool_backend(tmp_path, run=_FakeBpftool())
    scope = _guard_scope(tmp_path)
    receipt = tmp_path / "ownership" / f"{scope.request_id.hex}.json"
    reservation_nonce = backend._create_receipt(scope, receipt)
    scope_root = backend._reservation_scope_path(scope, reservation_nonce)
    scope_root.mkdir(mode=0o700)
    if tamper == "mode":
        receipt.chmod(0o644)
    elif tamper == "content":
        payload = bytearray(receipt.read_bytes())
        payload[0] = ord("[")
        receipt.write_bytes(payload)
    else:
        monkeypatch.setattr(os, "write", lambda *args: 0)

    with pytest.raises(
        ProbeConnectGuardError,
        match="probe_guard_ownership_invalid",
    ):
        backend._promote_receipt(scope, receipt, scope_root)


@pytest.mark.parametrize("interrupted", [False, True])
def test_bpftool_backend_collects_an_uncommitted_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    interrupted: bool,
) -> None:
    backend = _bpftool_backend(tmp_path, run=_FakeBpftool())
    scope = _guard_scope(tmp_path)
    original_fsync = os.fsync
    first_fsync = True

    def fail_initial_fsync(descriptor: int) -> None:
        nonlocal first_fsync
        if first_fsync:
            first_fsync = False
            if interrupted:
                raise KeyboardInterrupt("receipt fsync interrupted")
            raise OSError("receipt fsync failed")
        original_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", fail_initial_fsync)
    expected_error: type[BaseException] = (
        probe_connect_guard.ProbeConnectGuardInstallRejectedInterruption
        if interrupted
        else probe_connect_guard.ProbeConnectGuardInstallRejected
    )

    with pytest.raises(expected_error):
        backend.install(scope, timeout_seconds=3.0)

    assert list((tmp_path / "pins").iterdir()) == []
    assert _receipt_entries(tmp_path / "ownership") == []


def test_bpftool_backend_reconciles_reserved_receipt_and_empty_scope(
    tmp_path: Path,
) -> None:
    backend = _bpftool_backend(tmp_path, run=_FakeBpftool())
    scope = _guard_scope(tmp_path)
    receipt = tmp_path / "ownership" / f"{scope.request_id.hex}.json"
    reservation_nonce = backend._create_receipt(scope, receipt)
    scope_root = backend._reservation_scope_path(scope, reservation_nonce)
    scope_root.mkdir(mode=0o700)

    assert backend.reconcile_owned(timeout_seconds=3.0) == 0

    assert not receipt.exists()
    assert not scope_root.exists()


def test_bpftool_receipt_promotion_never_rewrites_committed_receipt_in_place(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _bpftool_backend(tmp_path, run=_FakeBpftool())
    scope = _guard_scope(tmp_path)
    receipt = tmp_path / "ownership" / f"{scope.request_id.hex}.json"
    scope_root = tmp_path / "pins" / scope.request_id.hex
    backend._create_receipt(scope, receipt)
    scope_root.mkdir(mode=0o700)

    def reject_in_place_write(*args: object, **kwargs: object) -> int:
        del args, kwargs
        raise AssertionError("receipt must be replaced atomically")

    monkeypatch.setattr(os, "pwrite", reject_in_place_write)

    backend._promote_receipt(scope, receipt, scope_root)
    assert json.loads(receipt.read_bytes())["phase"] == 1


def test_bpftool_backend_reconciles_a_torn_atomic_promotion_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _bpftool_backend(tmp_path, run=_FakeBpftool())
    scope = _guard_scope(tmp_path)
    receipt = tmp_path / "ownership" / f"{scope.request_id.hex}.json"
    reservation_nonce = backend._create_receipt(scope, receipt)
    reservation_scope = backend._reservation_scope_path(
        scope,
        reservation_nonce,
    )
    reservation_scope.mkdir(mode=0o700)
    original_write = os.write
    calls = 0

    def torn_write(descriptor: int, payload: bytes) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            return original_write(descriptor, payload[:1])
        raise KeyboardInterrupt("promotion write interrupted")

    monkeypatch.setattr(os, "write", torn_write)
    with pytest.raises(KeyboardInterrupt, match="promotion write interrupted"):
        backend._promote_receipt(scope, receipt, reservation_scope)
    monkeypatch.setattr(os, "write", original_write)

    assert backend.reconcile_owned(timeout_seconds=3.0) == 0
    assert _receipt_entries(tmp_path / "ownership") == []
    assert list((tmp_path / "pins").iterdir()) == []


@pytest.mark.parametrize("linked", [False, True])
def test_bpftool_backend_reconciles_a_crashed_initial_receipt_publish(
    tmp_path: Path,
    linked: bool,
) -> None:
    backend = _bpftool_backend(tmp_path, run=_FakeBpftool())
    scope = _guard_scope(tmp_path)
    nonce = "a" * 32
    temporary = backend._reservation_receipt_path(scope, nonce)
    receipt = tmp_path / "ownership" / f"{scope.request_id.hex}.json"
    if linked:
        payload = probe_connect_guard._receipt_bytes(
            scope,
            object_sha256=backend._identity.object_sha256,
            artifact_release_id=backend._artifact_release.release_id,
            phase=0,
            scope_device=0,
            scope_inode=0,
            reservation_nonce=nonce,
        )
        temporary.write_bytes(payload)
        temporary.chmod(0o600)
        os.link(temporary, receipt)
    else:
        temporary.write_bytes(b"{")
        temporary.chmod(0o600)

    assert backend.reconcile_owned(timeout_seconds=3.0) == 0
    assert _receipt_entries(tmp_path / "ownership") == []


def test_bpftool_backend_reconciles_replace_then_directory_fsync_ambiguity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _bpftool_backend(tmp_path, run=_FakeBpftool())
    scope = _guard_scope(tmp_path)
    receipt = tmp_path / "ownership" / f"{scope.request_id.hex}.json"
    reservation_nonce = backend._create_receipt(scope, receipt)
    reservation_scope = backend._reservation_scope_path(
        scope,
        reservation_nonce,
    )
    reservation_scope.mkdir(mode=0o700)
    original_fsync_directory = probe_connect_guard._fsync_directory
    fail_once = True

    def fail_after_replace(path: Path) -> None:
        nonlocal fail_once
        if fail_once and path == tmp_path / "ownership":
            fail_once = False
            raise OSError("directory fsync interrupted")
        original_fsync_directory(path)

    monkeypatch.setattr(
        probe_connect_guard,
        "_fsync_directory",
        fail_after_replace,
    )
    with pytest.raises(ProbeConnectGuardError, match="ownership_invalid"):
        backend._promote_receipt(scope, receipt, reservation_scope)

    assert json.loads(receipt.read_bytes())["phase"] == 1
    assert backend.reconcile_owned(timeout_seconds=3.0) == 0
    assert _receipt_entries(tmp_path / "ownership") == []
    assert list((tmp_path / "pins").iterdir()) == []


def test_guard_manager_reconciles_a_catalogued_previous_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeBpftool()
    previous_object_sha = "a" * 64
    current_identity = ProbeConnectGuardArtifactIdentity(
        bpftool_sha256=sha256(b"fixture").hexdigest(),
        object_sha256=sha256(b"fixture").hexdigest(),
        ipv4_program_tag="1" * 16,
        ipv6_program_tag="2" * 16,
    )
    releases: dict[str, object] = {}
    for release_id, object_sha, ipv4_tag, ipv6_tag, activation in (
        ("0.0.1", previous_object_sha, "3" * 16, "4" * 16, False),
        (
            "0.1.0",
            current_identity.object_sha256,
            current_identity.ipv4_program_tag,
            current_identity.ipv6_program_tag,
            True,
        ),
    ):
        architectures = {
            architecture: {
                "bpftool_sha256": [current_identity.bpftool_sha256],
                "object_sha256": object_sha,
                "ipv4_program_tag": ipv4_tag,
                "ipv6_program_tag": ipv6_tag,
            }
            for architecture in ("amd64", "arm64")
        }
        releases[release_id] = {
            "activation_compatible": activation,
            "cleanup_compatible": True,
            "architectures": architectures,
        }
    catalog = probe_connect_guard._parse_artifact_catalog(
        json.dumps(
            {
                "schema_version": 1,
                "current_release_id": "0.1.0",
                "releases": releases,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )
    monkeypatch.setattr(
        probe_connect_guard,
        "_test_artifact_catalog",
        lambda identity, architecture: catalog,
    )
    backend = _bpftool_backend(tmp_path, run=fake)
    scope = _guard_scope(tmp_path)
    backend.install(scope, timeout_seconds=3.0)
    receipt = tmp_path / "ownership" / f"{scope.request_id.hex}.json"
    decoded = json.loads(receipt.read_bytes())
    decoded["artifact_release_id"] = "0.0.1"
    decoded["object_sha256"] = previous_object_sha
    receipt.write_bytes(
        json.dumps(decoded, sort_keys=True, separators=(",", ":")).encode()
        + b"\n"
    )
    fake.ipv4_tag = "3" * 16
    fake.ipv6_tag = "4" * 16

    with pytest.raises(
        ProbeConnectGuardError,
        match="probe_guard_ownership_invalid",
    ):
        backend.verify(scope, timeout_seconds=3.0)

    _simulate_backend_process_exit(backend, scope)

    restarted = ProbeConnectGuardManager(
        backend=_bpftool_backend(tmp_path, run=fake, create_roots=False)
    )
    assert restarted.reconcile_startup(timeout_seconds=3.0) == 0
    assert not receipt.exists()
    assert not (tmp_path / "pins" / scope.request_id.hex).exists()


def test_bpftool_backend_receipt_does_not_own_a_replaced_scope_inode(
    tmp_path: Path,
) -> None:
    fake = _FakeBpftool()
    backend = _bpftool_backend(tmp_path, run=fake)
    scope = _guard_scope(tmp_path)
    backend.install(scope, timeout_seconds=3.0)
    owned_scope = tmp_path / "pins" / scope.request_id.hex
    displaced_scope = tmp_path / "displaced-owned-scope"
    owned_scope.rename(displaced_scope)
    owned_scope.mkdir(mode=0o700)

    with pytest.raises(ProbeConnectGuardError, match="probe_guard_ownership_invalid"):
        backend.remove(scope, timeout_seconds=3.0)

    assert owned_scope.is_dir()
    assert list(owned_scope.iterdir()) == []
    assert displaced_scope.is_dir()


def test_bpftool_backend_refuses_receipt_when_owned_scope_cannot_be_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _bpftool_backend(tmp_path, run=_FakeBpftool())
    scope = _guard_scope(tmp_path)
    backend.install(scope, timeout_seconds=3.0)
    owned_scope = tmp_path / "pins" / scope.request_id.hex
    original_lstat = Path.lstat

    def fail_scope_lstat(path: Path) -> os.stat_result:
        if path == owned_scope:
            raise OSError("scope unavailable")
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", fail_scope_lstat)

    with pytest.raises(
        ProbeConnectGuardError,
        match="probe_guard_ownership_invalid",
    ):
        backend.verify(scope, timeout_seconds=3.0)


def test_bpftool_backend_rejects_unknown_ownership_inventory(tmp_path: Path) -> None:
    backend = _bpftool_backend(tmp_path, run=_FakeBpftool())
    foreign = tmp_path / "ownership" / "foreign"
    foreign.write_bytes(b"")

    with pytest.raises(
        ProbeConnectGuardError,
        match="probe_guard_ownership_invalid",
    ):
        backend._receipt_inventory()


def test_bpftool_backend_fails_closed_when_ownership_inventory_is_unreadable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _bpftool_backend(tmp_path, run=_FakeBpftool())
    ownership_root = tmp_path / "ownership"
    original_iterdir = Path.iterdir

    def fail_inventory(path: Path) -> Iterator[Path]:
        if path == ownership_root:
            raise OSError("inventory unavailable")
        return original_iterdir(path)

    monkeypatch.setattr(Path, "iterdir", fail_inventory)

    with pytest.raises(
        ProbeConnectGuardError,
        match="probe_guard_ownership_invalid",
    ):
        backend._receipt_inventory()


@pytest.mark.parametrize("fault", ["short_read", "close"])
def test_bpftool_backend_fails_closed_on_receipt_io_fault(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    backend = _bpftool_backend(tmp_path, run=_FakeBpftool())
    scope = _guard_scope(tmp_path)
    backend.install(scope, timeout_seconds=3.0)
    receipt = tmp_path / "ownership" / f"{scope.request_id.hex}.json"
    if fault == "short_read":
        original_read = os.read

        def short_read(descriptor: int, size: int) -> bytes:
            return original_read(descriptor, max(0, size - 1))[:-1]

        monkeypatch.setattr(os, "read", short_read)
    else:
        original_close = os.close
        failed = False

        def fail_close(descriptor: int) -> None:
            nonlocal failed
            original_close(descriptor)
            if not failed:
                failed = True
                raise OSError("close failed")

        monkeypatch.setattr(os, "close", fail_close)

    with pytest.raises(
        ProbeConnectGuardError,
        match="probe_guard_ownership_invalid",
    ):
        backend._ownership_from_receipt(receipt)


def test_bpftool_backend_rejects_noncanonical_receipt_fields(tmp_path: Path) -> None:
    backend = _bpftool_backend(tmp_path, run=_FakeBpftool())
    scope = _guard_scope(tmp_path)
    backend.install(scope, timeout_seconds=3.0)
    receipt = tmp_path / "ownership" / f"{scope.request_id.hex}.json"
    decoded = json.loads(receipt.read_bytes())
    decoded["phase"] = True
    receipt.write_bytes(
        json.dumps(decoded, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    )

    with pytest.raises(
        ProbeConnectGuardError,
        match="probe_guard_ownership_invalid",
    ):
        backend._ownership_from_receipt(receipt)


def test_bpftool_backend_refuses_to_collect_an_owned_receipt_as_reserved(
    tmp_path: Path,
) -> None:
    backend = _bpftool_backend(tmp_path, run=_FakeBpftool())
    scope = _guard_scope(tmp_path)
    backend.install(scope, timeout_seconds=3.0)
    receipt = tmp_path / "ownership" / f"{scope.request_id.hex}.json"

    with pytest.raises(
        ProbeConnectGuardError,
        match="probe_guard_ownership_invalid",
    ):
        backend._remove_reserved_receipt(receipt)

    assert receipt.is_file()


@pytest.mark.parametrize(
    "tamper",
    ["scope_mode", "root_entry", "program_mode", "pin_mode", "inventory_error"],
)
def test_bpftool_backend_rejects_ambiguous_partial_pin_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tamper: str,
) -> None:
    backend = _bpftool_backend(tmp_path, run=_FakeBpftool())
    scope = _guard_scope(tmp_path)
    backend.install(scope, timeout_seconds=3.0)
    scope_root = tmp_path / "pins" / scope.request_id.hex
    programs = scope_root / "programs"
    if tamper == "scope_mode":
        scope_root.chmod(0o770)
    elif tamper == "root_entry":
        (scope_root / "foreign").write_bytes(b"")
    elif tamper == "program_mode":
        programs.chmod(0o770)
    elif tamper == "pin_mode":
        (programs / "rtsp_probe_guard_ipv4").chmod(0o660)
    else:
        original_iterdir = Path.iterdir

        def fail_inventory(path: Path) -> Iterator[Path]:
            if path == scope_root:
                raise OSError("inventory unavailable")
            return original_iterdir(path)

        monkeypatch.setattr(Path, "iterdir", fail_inventory)

    with pytest.raises(
        ProbeConnectGuardError,
        match="probe_guard_ownership_invalid",
    ):
        backend.verify(scope, timeout_seconds=3.0)


def test_guard_manager_retries_cleanup_after_receipt_unlink_fsync_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeBpftool()
    backend = _bpftool_backend(tmp_path, run=fake)
    manager = ProbeConnectGuardManager(backend=backend)
    scope = _guard_scope(tmp_path)
    lease = manager.install(
        request_id=scope.request_id,
        unit_name=scope.unit_name,
        cgroup_path=scope.cgroup_path,
        target=scope.target,
        timeout_seconds=3.0,
    )
    ownership_root = tmp_path / "ownership"
    original_fsync_directory = probe_connect_guard._fsync_directory
    reject_final_fsync = True

    def ambiguous_fsync(path: Path) -> None:
        if (
            reject_final_fsync
            and path == ownership_root
            and not _receipt_entries(path)
        ):
            raise OSError("directory fsync failed after unlink")
        original_fsync_directory(path)

    monkeypatch.setattr(probe_connect_guard, "_fsync_directory", ambiguous_fsync)

    with pytest.raises(ProbeConnectGuardError, match="probe_guard_cleanup_pending"):
        manager.release(lease, timeout_seconds=3.0)

    assert list((tmp_path / "pins").iterdir()) == []
    assert _receipt_entries(ownership_root) == []
    reject_final_fsync = False
    assert manager.retry_pending_cleanup(timeout_seconds=3.0) == 0


def test_guard_manager_reconcile_refuses_a_tampered_ownership_receipt(
    tmp_path: Path,
) -> None:
    fake = _FakeBpftool()
    backend = _bpftool_backend(tmp_path, run=fake)
    manager = ProbeConnectGuardManager(backend=backend)
    scope = _guard_scope(tmp_path)
    manager.install(
        request_id=scope.request_id,
        unit_name=scope.unit_name,
        cgroup_path=scope.cgroup_path,
        target=scope.target,
        timeout_seconds=3.0,
    )
    receipt = tmp_path / "ownership" / f"{scope.request_id.hex}.json"
    receipt.write_text("{}\n", encoding="utf-8")
    _simulate_backend_process_exit(backend, scope)

    restarted_manager = ProbeConnectGuardManager(
        backend=_bpftool_backend(tmp_path, run=fake, create_roots=False)
    )
    with pytest.raises(ProbeConnectGuardError, match="probe_guard_ownership_invalid"):
        restarted_manager.reconcile_startup(timeout_seconds=3.0)

    assert receipt.is_file()
    assert (tmp_path / "pins" / scope.request_id.hex).is_dir()


@pytest.mark.parametrize("tamper", ["mode", "trailing", "symlink"])
def test_guard_manager_reconcile_rejects_noncanonical_receipt_storage(
    tmp_path: Path,
    tamper: str,
) -> None:
    fake = _FakeBpftool()
    backend = _bpftool_backend(tmp_path, run=fake)
    scope = _guard_scope(tmp_path)
    backend.install(scope, timeout_seconds=3.0)
    receipt = tmp_path / "ownership" / f"{scope.request_id.hex}.json"
    if tamper == "mode":
        receipt.chmod(0o644)
    elif tamper == "trailing":
        receipt.write_bytes(receipt.read_bytes() + b" ")
    else:
        replacement = tmp_path / "replacement-receipt"
        replacement.write_bytes(receipt.read_bytes())
        receipt.unlink()
        receipt.symlink_to(replacement)

    _simulate_backend_process_exit(backend, scope)

    restarted_manager = ProbeConnectGuardManager(
        backend=_bpftool_backend(tmp_path, run=fake, create_roots=False)
    )
    with pytest.raises(ProbeConnectGuardError, match="probe_guard_ownership_invalid"):
        restarted_manager.reconcile_startup(timeout_seconds=3.0)

    assert (tmp_path / "pins" / scope.request_id.hex).is_dir()


def test_guard_manager_reconcile_bounds_the_durable_inventory(tmp_path: Path) -> None:
    fake = _FakeBpftool()
    backend = _bpftool_backend(tmp_path, run=fake)
    ownership_root = tmp_path / "ownership"
    for index in range(257):
        ownership_root.joinpath(f"{index:032x}.json").write_text("{}\n", encoding="utf-8")
    manager = ProbeConnectGuardManager(backend=backend)

    with pytest.raises(ProbeConnectGuardError, match="probe_guard_ownership_capacity"):
        manager.reconcile_startup(timeout_seconds=3.0)


def test_bpftool_backend_rejects_a_receipt_for_a_different_scope(
    tmp_path: Path,
) -> None:
    fake = _FakeBpftool()
    backend = _bpftool_backend(tmp_path, run=fake)
    scope = _guard_scope(tmp_path)
    backend.install(scope, timeout_seconds=3.0)
    mismatched_scope = ProbeConnectGuardScope(
        request_id=scope.request_id,
        unit_name=scope.unit_name,
        cgroup_path=scope.cgroup_path,
        target=ProbeConnectGuardTarget(ip_address("192.0.2.21"), 8554),
    )

    with pytest.raises(ProbeConnectGuardError, match="probe_guard_ownership_invalid"):
        backend.remove(mismatched_scope, timeout_seconds=3.0)

    backend.remove(scope, timeout_seconds=3.0)


def test_guard_manager_reconciles_only_one_bounded_crash_batch(
    tmp_path: Path,
) -> None:
    fake = _FakeBpftool()
    backend = _bpftool_backend(tmp_path, run=fake)
    scopes: list[ProbeConnectGuardScope] = []
    for _index in range(10):
        scope = _guard_scope(tmp_path)
        backend.install(scope, timeout_seconds=3.0)
        scopes.append(scope)

    _simulate_backend_process_exit(backend, *scopes)

    restarted_manager = ProbeConnectGuardManager(
        backend=_bpftool_backend(tmp_path, run=fake, create_roots=False)
    )

    assert restarted_manager.reconcile_startup(timeout_seconds=3.0) == 2
    assert restarted_manager.reconcile_startup(timeout_seconds=3.0) == 0


def test_guard_manager_refuses_startup_reconcile_while_a_scope_is_active(
    tmp_path: Path,
) -> None:
    manager, backend = _manager()
    scope = _guard_scope(tmp_path)
    manager.install(
        request_id=scope.request_id,
        unit_name=scope.unit_name,
        cgroup_path=scope.cgroup_path,
        target=scope.target,
        timeout_seconds=3.0,
    )

    with pytest.raises(ProbeConnectGuardError, match="probe_guard_reconcile_busy"):
        manager.reconcile_startup(timeout_seconds=3.0)

    assert backend.reconciled_remaining == 0


def test_guard_manager_does_not_admit_install_until_startup_reconcile_is_empty(
    tmp_path: Path,
) -> None:
    reconcile_started = Event()
    allow_reconcile = Event()

    class _BlockingReconcileBackend(_RecordingBackend):
        def reconcile_owned(self, *, timeout_seconds: float) -> int:
            assert 0 < timeout_seconds <= 3.0
            reconcile_started.set()
            assert allow_reconcile.wait(timeout=1.0)
            return self.reconciled_remaining

    backend = _BlockingReconcileBackend(
        installed=[],
        verified=[],
        removed=[],
        reconciled_remaining=1,
    )
    manager = ProbeConnectGuardManager(backend=backend)
    scope = _guard_scope(tmp_path)
    reconcile_result: list[int] = []

    thread = Thread(
        target=lambda: reconcile_result.append(
            manager.reconcile_startup(timeout_seconds=3.0)
        )
    )
    thread.start()
    assert reconcile_started.wait(timeout=1.0)

    with pytest.raises(ProbeConnectGuardError, match="probe_guard_reconcile_busy"):
        manager.install(
            request_id=scope.request_id,
            unit_name=scope.unit_name,
            cgroup_path=scope.cgroup_path,
            target=scope.target,
            timeout_seconds=3.0,
        )

    allow_reconcile.set()
    thread.join(timeout=1.0)
    assert not thread.is_alive()
    assert reconcile_result == [1]

    with pytest.raises(ProbeConnectGuardError, match="probe_guard_reconcile_required"):
        manager.install(
            request_id=scope.request_id,
            unit_name=scope.unit_name,
            cgroup_path=scope.cgroup_path,
            target=scope.target,
            timeout_seconds=3.0,
        )

    backend.reconciled_remaining = 0
    assert manager.reconcile_startup(timeout_seconds=3.0) == 0
    lease = manager.install(
        request_id=scope.request_id,
        unit_name=scope.unit_name,
        cgroup_path=scope.cgroup_path,
        target=scope.target,
        timeout_seconds=3.0,
    )
    manager.release(lease, timeout_seconds=3.0)


def test_bpftool_backend_removes_tampered_readback_without_issuing_a_lease(
    tmp_path: Path,
) -> None:
    fake = _FakeBpftool(corrupt_map_value=True)
    manager = ProbeConnectGuardManager(
        backend=_bpftool_backend(tmp_path, run=fake)
    )
    request_id = uuid4()
    unit_name = _unit_name(request_id)
    cgroup_path = tmp_path / unit_name
    cgroup_path.mkdir()

    with pytest.raises(ProbeConnectGuardError, match="probe_guard_install_failed"):
        manager.install(
            request_id=request_id,
            unit_name=unit_name,
            cgroup_path=cgroup_path,
            target=ProbeConnectGuardTarget(ip_address("192.0.2.20"), 8554),
            timeout_seconds=3.0,
        )

    assert fake.attachments == {}
    assert not (tmp_path / "pins" / request_id.hex).exists()


@pytest.mark.parametrize(
    ("prefix", "response"),
    [
        (("-j", "prog", "show", "pinned"), json.dumps({"id": 0})),
        (("-j", "map", "show", "pinned"), "{"),
        (("-j", "map", "show", "pinned"), "[]"),
        (("-j", "map", "show", "pinned"), "{}"),
        (("-j", "map", "lookup", "pinned"), "[]"),
        (
            ("-j", "map", "lookup", "pinned"),
            json.dumps({"key": "wrong", "value": []}),
        ),
        (
            ("-j", "map", "lookup", "pinned"),
            json.dumps({"key": ["bad"], "value": []}),
        ),
        (
            ("-j", "map", "lookup", "pinned"),
            json.dumps({"key": ["0xgg"], "value": []}),
        ),
        (("-j", "cgroup", "show"), ""),
        (("-j", "cgroup", "show"), "{"),
        (("-j", "cgroup", "show"), "{}"),
        (("-j", "cgroup", "show"), "[1]"),
        (
            ("-j", "cgroup", "show"),
            json.dumps(
                [
                    {"id": 101, "attach_type": "cgroup_inet4_connect"},
                    {"id": 101, "attach_type": "cgroup_inet4_connect"},
                ]
            ),
        ),
    ],
)
def test_bpftool_backend_rejects_malformed_or_incomplete_kernel_readback(
    tmp_path: Path,
    prefix: tuple[str, ...],
    response: str,
) -> None:
    fake = _FakeBpftool()
    override = _OverrideBpftool(fake, prefix=prefix, response=response)
    backend = _bpftool_backend(tmp_path, run=override)
    scope = _guard_scope(tmp_path)
    backend.install(scope, timeout_seconds=3.0)
    override.enabled = True

    with pytest.raises(ProbeConnectGuardError, match="probe_guard_readback_invalid"):
        backend.verify(scope, timeout_seconds=3.0)

    override.enabled = False
    backend.remove(scope, timeout_seconds=3.0)
    assert fake.attachments == {}


def test_bpftool_backend_refuses_foreign_pin_during_readback_and_cleanup(
    tmp_path: Path,
) -> None:
    fake = _FakeBpftool()
    backend = _bpftool_backend(tmp_path, run=fake)
    scope = _guard_scope(tmp_path)
    backend.install(scope, timeout_seconds=3.0)
    foreign_pin = tmp_path / "pins" / scope.request_id.hex / "programs" / "foreign"
    foreign_pin.touch()

    with pytest.raises(ProbeConnectGuardError, match="probe_guard_ownership_invalid"):
        backend.verify(scope, timeout_seconds=3.0)
    with pytest.raises(ProbeConnectGuardError, match="probe_guard_ownership_invalid"):
        backend.remove(scope, timeout_seconds=3.0)

    foreign_pin.unlink()
    backend.remove(scope, timeout_seconds=3.0)


def test_bpftool_backend_requires_the_complete_exact_pin_inventory(
    tmp_path: Path,
) -> None:
    fake = _FakeBpftool()
    backend = _bpftool_backend(tmp_path, run=fake)
    scope = _guard_scope(tmp_path)
    backend.install(scope, timeout_seconds=3.0)
    missing_pin = (
        tmp_path
        / "pins"
        / scope.request_id.hex
        / "programs"
        / "rtsp_probe_guard_ipv6"
    )
    missing_pin.unlink()

    with pytest.raises(ProbeConnectGuardError, match="probe_guard_readback_invalid"):
        backend.verify(scope, timeout_seconds=3.0)

    missing_pin.touch()
    missing_pin.chmod(0o600)
    backend.remove(scope, timeout_seconds=3.0)


def test_bpftool_backend_sanitizes_kernel_command_failure(tmp_path: Path) -> None:
    fake = _FakeBpftool()
    override = _OverrideBpftool(
        fake,
        prefix=("-j", "map", "show", "pinned"),
        response=RuntimeError("secret kernel diagnostic"),
    )
    backend = _bpftool_backend(tmp_path, run=override)
    scope = _guard_scope(tmp_path)
    backend.install(scope, timeout_seconds=3.0)
    override.enabled = True

    with pytest.raises(ProbeConnectGuardError) as raised:
        backend.verify(scope, timeout_seconds=3.0)

    assert str(raised.value) == "probe_guard_kernel_operation_failed"
    assert "secret" not in repr(raised.value)
    override.enabled = False
    backend.remove(scope, timeout_seconds=3.0)


def test_bpftool_backend_rejects_artifact_replacement_before_kernel_mutation(
    tmp_path: Path,
) -> None:
    fake = _FakeBpftool()
    backend = _bpftool_backend(tmp_path, run=fake)
    manager = ProbeConnectGuardManager(backend=backend)
    scope = _guard_scope(tmp_path)
    (tmp_path / "guard.bpf.o").write_bytes(b"replaced")

    with pytest.raises(
        ProbeConnectGuardError,
        match="probe_guard_artifact_identity_invalid",
    ):
        manager.install(
            request_id=scope.request_id,
            unit_name=scope.unit_name,
            cgroup_path=scope.cgroup_path,
            target=scope.target,
            timeout_seconds=3.0,
        )

    assert fake.commands == []
    assert list((tmp_path / "pins").iterdir()) == []
    assert _receipt_entries(tmp_path / "ownership") == []


def test_packaged_guard_catalog_rejects_a_substituted_current_artifact() -> None:
    catalog = probe_connect_guard._load_packaged_artifact_catalog()
    for architecture in ("amd64", "arm64"):
        release = catalog.cleanup_release("0.1.0", architecture=architecture)
        trusted_tool = min(release.bpftool_sha256)
        identity = ProbeConnectGuardArtifactIdentity(
            bpftool_sha256=trusted_tool,
            object_sha256=release.object_sha256,
            ipv4_program_tag=release.ipv4_program_tag,
            ipv6_program_tag=release.ipv6_program_tag,
        )

        assert catalog.activation_release(
            identity,
            architecture=architecture,
        ) == release
        with pytest.raises(
            ProbeConnectGuardError,
            match="probe_guard_artifact_identity_invalid",
        ):
            catalog.activation_release(
                ProbeConnectGuardArtifactIdentity(
                    bpftool_sha256=trusted_tool,
                    object_sha256="0" * 64,
                    ipv4_program_tag=release.ipv4_program_tag,
                    ipv6_program_tag=release.ipv6_program_tag,
                ),
                architecture=architecture,
            )


def test_guard_catalog_rejects_unknown_cleanup_release() -> None:
    catalog = probe_connect_guard._load_packaged_artifact_catalog()

    with pytest.raises(
        ProbeConnectGuardError,
        match="probe_guard_ownership_invalid",
    ):
        catalog.cleanup_release("unknown", architecture="amd64")


def test_guard_catalog_requires_both_architectures_for_every_cleanup_release() -> None:
    decoded = json.loads(
        Path("src/rtsp_proxy/artifacts/probe_connect_guard.json").read_bytes()
    )
    current = decoded["releases"][decoded["current_release_id"]]
    previous = json.loads(json.dumps(current))
    del previous["architectures"]["arm64"]
    previous["activation_compatible"] = False
    previous["cleanup_compatible"] = True
    decoded["releases"]["previous"] = previous

    with pytest.raises(
        ProbeConnectGuardError,
        match="probe_guard_artifact_identity_invalid",
    ):
        probe_connect_guard._parse_artifact_catalog(json.dumps(decoded).encode())


def test_packaged_guard_catalog_fails_closed_when_resource_is_unreadable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _UnreadableResource:
        def joinpath(self, *parts: str) -> _UnreadableResource:
            del parts
            return self

        def read_bytes(self) -> bytes:
            raise OSError("catalog unavailable")

    monkeypatch.setattr(
        probe_connect_guard,
        "files",
        lambda package: _UnreadableResource(),
    )

    with pytest.raises(
        ProbeConnectGuardError,
        match="probe_guard_artifact_identity_invalid",
    ):
        probe_connect_guard._load_packaged_artifact_catalog()


@pytest.mark.parametrize(
    "case",
    [
        "json",
        "schema",
        "current",
        "releases",
        "release_id",
        "release_shape",
        "activation",
        "cleanup",
        "architectures",
        "architecture",
        "identity_shape",
        "tools_empty",
        "tools_duplicate",
        "tool_digest",
        "object_digest",
        "ipv4_tag",
        "ipv6_tag",
        "current_not_activation_compatible",
    ],
)
def test_guard_artifact_catalog_rejects_noncanonical_content(case: str) -> None:
    if case == "json":
        payload = b"{"
    else:
        decoded = json.loads(
            Path("src/rtsp_proxy/artifacts/probe_connect_guard.json").read_bytes()
        )
        releases = decoded["releases"]
        current = releases[decoded["current_release_id"]]
        arm64 = current["architectures"]["arm64"]
        if case == "schema":
            decoded["schema_version"] = 2
        elif case == "current":
            decoded["current_release_id"] = "invalid release"
        elif case == "releases":
            decoded["releases"] = {}
        elif case == "release_id":
            releases["invalid release"] = releases.pop("0.1.0")
            decoded["current_release_id"] = "invalid release"
        elif case == "release_shape":
            current["unexpected"] = True
        elif case == "activation":
            current["activation_compatible"] = 1
        elif case == "cleanup":
            current["cleanup_compatible"] = 1
        elif case == "architectures":
            current["architectures"] = []
        elif case == "architecture":
            current["architectures"]["riscv64"] = current["architectures"].pop(
                "arm64"
            )
        elif case == "identity_shape":
            arm64["unexpected"] = True
        elif case == "tools_empty":
            arm64["bpftool_sha256"] = []
        elif case == "tools_duplicate":
            arm64["bpftool_sha256"] *= 2
        elif case == "tool_digest":
            arm64["bpftool_sha256"] = ["invalid"]
        elif case == "object_digest":
            arm64["object_sha256"] = "invalid"
        elif case == "ipv4_tag":
            arm64["ipv4_program_tag"] = "invalid"
        elif case == "ipv6_tag":
            arm64["ipv6_program_tag"] = "invalid"
        else:
            current["activation_compatible"] = False
        payload = json.dumps(decoded).encode()

    with pytest.raises(
        ProbeConnectGuardError,
        match="probe_guard_artifact_identity_invalid",
    ):
        probe_connect_guard._parse_artifact_catalog(payload)


@pytest.mark.parametrize(
    ("machine", "expected"),
    [
        ("x86_64", "amd64"),
        ("AMD64", "amd64"),
        ("aarch64", "arm64"),
        ("ARM64", "arm64"),
    ],
)
def test_guard_artifact_catalog_normalizes_linux_architecture(
    machine: str,
    expected: str,
) -> None:
    assert probe_connect_guard._linux_architecture(machine) == expected

    with pytest.raises(
        ProbeConnectGuardError,
        match="probe_guard_artifact_identity_invalid",
    ):
        probe_connect_guard._linux_architecture("riscv64")


@pytest.mark.skipif(
    not Path("/proc/self/fd").is_dir(),
    reason="verified descriptor execution is a Linux production boundary",
)
def test_bpftool_backend_executes_the_verified_inode_not_a_replaced_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bpftool = tmp_path / "bpftool"
    shutil.copyfile("/usr/bin/true", bpftool)
    bpftool.chmod(0o700)
    malicious = tmp_path / "malicious-bpftool"
    shutil.copyfile("/usr/bin/false", malicious)
    malicious.chmod(0o700)
    bpf_object = tmp_path / "guard.bpf.o"
    bpf_object.write_bytes(b"fixture")
    bpf_object.chmod(0o600)
    pin_root = tmp_path / "pins"
    pin_root.mkdir()
    pin_root.chmod(0o700)
    ownership_root = tmp_path / "ownership"
    ownership_root.mkdir()
    ownership_root.chmod(0o700)
    identity = ProbeConnectGuardArtifactIdentity(
        bpftool_sha256=sha256(bpftool.read_bytes()).hexdigest(),
        object_sha256=sha256(bpf_object.read_bytes()).hexdigest(),
        ipv4_program_tag="1" * 16,
        ipv6_program_tag="2" * 16,
    )
    backend = BpftoolProbeConnectGuardBackend(
        bpftool_path=bpftool,
        object_path=bpf_object,
        pin_root=pin_root,
        ownership_root=ownership_root,
        artifact_identity=identity,
        trusted_owner_uid=os.getuid(),
    )
    original_spawn = probe_connect_guard._spawn_owned_process
    swapped = False
    executed_paths: list[str] = []

    def swap_during_process_start(
        owner: probe_connect_guard._ProcessOwner,
        arguments: tuple[str, ...],
        **keywords: Any,
    ) -> None:
        nonlocal swapped
        executed_paths.append(arguments[0])
        if not swapped:
            swapped = True
            backup = tmp_path / "verified-bpftool"
            bpftool.rename(backup)
            malicious.rename(bpftool)
            try:
                original_spawn(
                    owner,
                    arguments,
                    **keywords,
                )
            finally:
                bpftool.rename(malicious)
                backup.rename(bpftool)
            return
        original_spawn(
            owner,
            arguments,
            **keywords,
        )

    monkeypatch.setattr(
        "rtsp_proxy.probe_connect_guard._spawn_owned_process",
        swap_during_process_start,
    )

    backend.install(_guard_scope(tmp_path), timeout_seconds=3.0)

    assert all(path != str(bpftool) for path in executed_paths)


def test_verified_command_passes_bound_root_descriptors_to_bpftool(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _bpftool_backend(tmp_path, run=_FakeBpftool())
    observed_pass_fds: tuple[int, ...] = ()

    def capture_command(
        arguments: tuple[str, ...],
        *,
        timeout_seconds: float,
        pass_fds: tuple[int, ...] = (),
    ) -> str:
        nonlocal observed_pass_fds
        del arguments, timeout_seconds
        observed_pass_fds = pass_fds
        return ""

    monkeypatch.setattr(probe_connect_guard, "_run_command", capture_command)

    backend._run_verified_command(("version",), timeout_seconds=3.0)

    assert set(backend._root_descriptors).issubset(observed_pass_fds)
    assert len(observed_pass_fds) == len(backend._root_descriptors) + 2


@pytest.mark.parametrize(
    ("command_error", "cleanup_error", "expected"),
    [
        (
            RuntimeError("command failed"),
            RuntimeError("close failed"),
            ProbeConnectGuardError,
        ),
        (
            KeyboardInterrupt("command interrupted"),
            RuntimeError("close failed"),
            BaseExceptionGroup,
        ),
        (None, RuntimeError("close failed"), ProbeConnectGuardError),
        (None, KeyboardInterrupt("close interrupted"), BaseExceptionGroup),
    ],
)
def test_bpftool_backend_preserves_verified_command_cleanup_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command_error: BaseException | None,
    cleanup_error: BaseException,
    expected: type[BaseException],
) -> None:
    backend = _bpftool_backend(tmp_path, run=_FakeBpftool())

    def run_command(*args: object, **kwargs: object) -> str:
        del args, kwargs
        if command_error is not None:
            raise command_error
        return ""

    def close_with_error(descriptors: list[int]) -> list[BaseException]:
        for descriptor in descriptors:
            os.close(descriptor)
        return [cleanup_error]

    monkeypatch.setattr(probe_connect_guard, "_run_command", run_command)
    monkeypatch.setattr(probe_connect_guard, "_close_descriptors", close_with_error)

    with pytest.raises(expected):
        backend._run_verified_command(("version",), timeout_seconds=3.0)


@pytest.mark.parametrize("drift", ["tag", "map"])
def test_bpftool_backend_binds_program_tag_and_exact_map_id(
    tmp_path: Path,
    drift: str,
) -> None:
    fake = _FakeBpftool()
    backend = _bpftool_backend(tmp_path, run=fake)
    scope = _guard_scope(tmp_path)
    backend.install(scope, timeout_seconds=3.0)
    if drift == "tag":
        fake.ipv4_tag = "f" * 16
    else:
        fake.program_map_ids = [999]

    with pytest.raises(ProbeConnectGuardError, match="probe_guard_readback_invalid"):
        backend.verify(scope, timeout_seconds=3.0)

    fake.ipv4_tag = "1" * 16
    fake.program_map_ids = [201]
    backend.remove(scope, timeout_seconds=3.0)


@pytest.mark.parametrize("output_fd", [1, 2])
def test_bpftool_backend_bounds_kernel_command_stdout_and_stderr(
    tmp_path: Path,
    output_fd: int,
) -> None:
    bpftool = tmp_path / "bpftool"
    bpftool.write_text(
        "#!/usr/bin/python3\n"
        "import os, sys\n"
        "if sys.argv[1:3] == ['prog', 'loadall']:\n"
        f"    os.write({output_fd}, b'x' * 70000)\n"
        "elif sys.argv[1:4] == ['-j', 'cgroup', 'show']:\n"
        "    print('[]')\n",
        encoding="utf-8",
    )
    bpftool.chmod(0o700)
    bpf_object = tmp_path / "guard.bpf.o"
    bpf_object.write_bytes(b"fixture")
    bpf_object.chmod(0o600)
    pin_root = tmp_path / "pins"
    pin_root.mkdir()
    pin_root.chmod(0o700)
    ownership_root = tmp_path / "ownership"
    ownership_root.mkdir()
    ownership_root.chmod(0o700)
    backend = BpftoolProbeConnectGuardBackend(
        bpftool_path=bpftool,
        object_path=bpf_object,
        pin_root=pin_root,
        ownership_root=ownership_root,
        artifact_identity=ProbeConnectGuardArtifactIdentity(
            bpftool_sha256=sha256(bpftool.read_bytes()).hexdigest(),
            object_sha256=sha256(bpf_object.read_bytes()).hexdigest(),
            ipv4_program_tag="1" * 16,
            ipv6_program_tag="2" * 16,
        ),
        trusted_owner_uid=os.getuid(),
    )
    manager = ProbeConnectGuardManager(backend=backend)
    scope = _guard_scope(tmp_path)

    with pytest.raises(ProbeConnectGuardError) as raised:
        manager.install(
            request_id=scope.request_id,
            unit_name=scope.unit_name,
            cgroup_path=scope.cgroup_path,
            target=scope.target,
            timeout_seconds=3.0,
        )

    assert str(raised.value) == "probe_guard_install_failed"
    assert list(pin_root.iterdir()) == []
    assert _receipt_entries(ownership_root) == []


def test_bpftool_command_owns_process_before_selector_setup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process_holder: list[object] = []

    class _Process:
        def __init__(self) -> None:
            self.stdout = open(os.devnull, "rb")  # noqa: SIM115 - fake process owns it
            self.stderr = open(os.devnull, "rb")  # noqa: SIM115 - fake process owns it
            self.terminated = False
            self.reaped = False
            process_holder.append(self)

        def poll(self) -> int | None:
            return None if not self.terminated else 0

        def terminate(self) -> None:
            self.terminated = True

        def kill(self) -> None:
            self.terminated = True

        def wait(self, timeout: float | None = None) -> int:
            assert timeout is not None
            self.reaped = True
            return 0

    def spawn_fake_process(
        owner: object,
        *arguments: object,
        **keywords: object,
    ) -> None:
        del arguments, keywords
        owner.process = _Process()  # type: ignore[attr-defined]

    monkeypatch.setattr(
        "rtsp_proxy.probe_connect_guard._spawn_owned_process",
        spawn_fake_process,
    )
    original_selector = selectors.DefaultSelector
    selector_calls = 0

    def interrupt_first_selector() -> object:
        nonlocal selector_calls
        selector_calls += 1
        if selector_calls == 1:
            raise KeyboardInterrupt("selector interrupted")
        return original_selector()

    monkeypatch.setattr(
        "rtsp_proxy.probe_connect_guard.selectors.DefaultSelector",
        interrupt_first_selector,
    )
    bpftool = tmp_path / "bpftool"
    bpftool.write_bytes(b"fixture")
    bpftool.chmod(0o700)
    bpf_object = tmp_path / "guard.bpf.o"
    bpf_object.write_bytes(b"fixture")
    bpf_object.chmod(0o600)
    pin_root = tmp_path / "pins"
    pin_root.mkdir()
    pin_root.chmod(0o700)
    ownership_root = tmp_path / "ownership"
    ownership_root.mkdir()
    ownership_root.chmod(0o700)
    manager = ProbeConnectGuardManager(
        backend=BpftoolProbeConnectGuardBackend(
            bpftool_path=bpftool,
            object_path=bpf_object,
            pin_root=pin_root,
            ownership_root=ownership_root,
            artifact_identity=ProbeConnectGuardArtifactIdentity(
                bpftool_sha256=sha256(bpftool.read_bytes()).hexdigest(),
                object_sha256=sha256(bpf_object.read_bytes()).hexdigest(),
                ipv4_program_tag="1" * 16,
                ipv6_program_tag="2" * 16,
            ),
            trusted_owner_uid=os.getuid(),
        )
    )
    scope = _guard_scope(tmp_path)

    with pytest.raises(BaseExceptionGroup) as raised:
        manager.install(
            request_id=scope.request_id,
            unit_name=scope.unit_name,
            cgroup_path=scope.cgroup_path,
            target=scope.target,
            timeout_seconds=1.0,
        )

    assert any(
        isinstance(error, KeyboardInterrupt)
        for error in raised.value.exceptions
    )
    assert len(process_holder) == 2
    process = process_holder[0]
    assert isinstance(process, _Process)
    assert process.terminated is True
    assert process.reaped is True
    assert process.stdout.closed
    assert process.stderr.closed


def test_bpftool_command_owns_pid_before_unblocking_process_interruption(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_spawn = os.posix_spawn
    spawned: list[int] = []

    def queue_interrupt_after_spawn(
        path: str,
        arguments: tuple[str, ...],
        environment: dict[str, str],
        **keywords: Any,
    ) -> int:
        pid = original_spawn(
            path,
            arguments,
            environment,
            **keywords,
        )
        spawned.append(pid)
        os.kill(os.getpid(), signal.SIGINT)
        return pid

    monkeypatch.setattr(os, "posix_spawn", queue_interrupt_after_spawn)
    try:
        with pytest.raises(KeyboardInterrupt):
            probe_connect_guard._run_command(
                (sys.executable, "-c", "import time; time.sleep(30)"),
                timeout_seconds=1.0,
            )

        assert len(spawned) == 1
        with pytest.raises(ChildProcessError):
            os.waitpid(spawned[0], os.WNOHANG)
    finally:
        for pid in spawned:
            with suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)
            with suppress(ChildProcessError):
                os.waitpid(pid, 0)


@pytest.mark.parametrize("failure", ["nonzero", "invalid_utf8", "timeout"])
def test_bpftool_backend_bounds_command_exit_encoding_and_deadline(
    tmp_path: Path,
    failure: str,
) -> None:
    bpftool = tmp_path / "bpftool"
    failure_body = {
        "nonzero": "raise SystemExit(7)",
        "invalid_utf8": "os.write(1, b'\\xff')",
        "timeout": "time.sleep(2)",
    }[failure]
    bpftool.write_text(
        "#!/usr/bin/python3\n"
        "import os, sys, time\n"
        "if sys.argv[1:3] == ['prog', 'loadall']:\n"
        f"    {failure_body}\n"
        "elif sys.argv[1:4] == ['-j', 'cgroup', 'show']:\n"
        "    print('[]')\n",
        encoding="utf-8",
    )
    bpftool.chmod(0o700)
    bpf_object = tmp_path / "guard.bpf.o"
    bpf_object.write_bytes(b"fixture")
    bpf_object.chmod(0o600)
    pin_root = tmp_path / "pins"
    pin_root.mkdir()
    pin_root.chmod(0o700)
    ownership_root = tmp_path / "ownership"
    ownership_root.mkdir()
    ownership_root.chmod(0o700)
    backend = BpftoolProbeConnectGuardBackend(
        bpftool_path=bpftool,
        object_path=bpf_object,
        pin_root=pin_root,
        ownership_root=ownership_root,
        artifact_identity=ProbeConnectGuardArtifactIdentity(
            bpftool_sha256=sha256(bpftool.read_bytes()).hexdigest(),
            object_sha256=sha256(bpf_object.read_bytes()).hexdigest(),
            ipv4_program_tag="1" * 16,
            ipv6_program_tag="2" * 16,
        ),
        trusted_owner_uid=os.getuid(),
    )
    manager = ProbeConnectGuardManager(backend=backend)
    scope = _guard_scope(tmp_path)

    with pytest.raises(ProbeConnectGuardError, match="probe_guard_install_failed"):
        manager.install(
            request_id=scope.request_id,
            unit_name=scope.unit_name,
            cgroup_path=scope.cgroup_path,
            target=scope.target,
            timeout_seconds=0.2 if failure == "timeout" else 1.0,
        )

    assert list(pin_root.iterdir()) == []
    assert _receipt_entries(ownership_root) == []


def test_bpftool_backend_rejects_untrusted_paths_before_mutation(
    tmp_path: Path,
) -> None:
    object_path = tmp_path / "guard.bpf.o"
    object_path.write_bytes(b"fixture")
    pin_root = tmp_path / "pins"
    pin_root.mkdir()
    ownership_root = tmp_path / "ownership"
    ownership_root.mkdir()
    identity = ProbeConnectGuardArtifactIdentity(
        bpftool_sha256=sha256(object_path.read_bytes()).hexdigest(),
        object_sha256=sha256(object_path.read_bytes()).hexdigest(),
        ipv4_program_tag="1" * 16,
        ipv6_program_tag="2" * 16,
    )

    with pytest.raises(
        ProbeConnectGuardError,
        match="probe_guard_artifact_identity_invalid",
    ):
        ProbeConnectGuardArtifactIdentity(
            bpftool_sha256="invalid",
            object_sha256="0" * 64,
            ipv4_program_tag="1" * 16,
            ipv6_program_tag="2" * 16,
        )
    with pytest.raises(
        ProbeConnectGuardError,
        match="probe_guard_artifact_identity_invalid",
    ):
        BpftoolProbeConnectGuardBackend(
            bpftool_path=object_path,
            object_path=object_path,
            pin_root=pin_root,
            ownership_root=ownership_root,
            artifact_identity=object(),  # type: ignore[arg-type]
            trusted_owner_uid=os.getuid(),
        )
    with pytest.raises(ProbeConnectGuardError, match="probe_guard_tool_invalid"):
        BpftoolProbeConnectGuardBackend(
            bpftool_path=Path("relative-bpftool"),
            object_path=object_path,
            pin_root=pin_root,
            ownership_root=ownership_root,
            artifact_identity=identity,
            trusted_owner_uid=os.getuid(),
        )
    with pytest.raises(ProbeConnectGuardError, match="probe_guard_tool_invalid"):
        BpftoolProbeConnectGuardBackend(
            bpftool_path=tmp_path / "missing",
            object_path=object_path,
            pin_root=pin_root,
            ownership_root=ownership_root,
            artifact_identity=identity,
            trusted_owner_uid=os.getuid(),
        )
    with pytest.raises(ProbeConnectGuardError, match="probe_guard_tool_invalid"):
        BpftoolProbeConnectGuardBackend(
            bpftool_path=object_path,
            object_path=object_path,
            pin_root=pin_root,
            ownership_root=ownership_root,
            artifact_identity=identity,
            trusted_owner_uid=True,
        )
    object_path.chmod(0o700)
    with pytest.raises(ProbeConnectGuardError, match="probe_guard_pin_root_invalid"):
        BpftoolProbeConnectGuardBackend(
            bpftool_path=object_path,
            object_path=object_path,
            pin_root=Path("relative-pins"),
            ownership_root=ownership_root,
            artifact_identity=identity,
            trusted_owner_uid=os.getuid(),
        )


def test_descriptor_execution_path_fails_closed_without_procfs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(Path, "is_dir", lambda path: False)
    monkeypatch.setattr(platform, "system", lambda: "Linux")

    with pytest.raises(ProbeConnectGuardError, match="probe_guard_tool_invalid"):
        probe_connect_guard._descriptor_path(7, fallback=Path("/tmp/mutable"))


def test_guard_manager_release_failure_is_retryable_and_one_shot(
    tmp_path: Path,
) -> None:
    manager, backend = _manager()
    scope = _guard_scope(tmp_path)
    lease = manager.install(
        request_id=scope.request_id,
        unit_name=scope.unit_name,
        cgroup_path=scope.cgroup_path,
        target=scope.target,
        timeout_seconds=3.0,
    )
    backend.remove_errors = [RuntimeError("must-not-escape")]

    with pytest.raises(ProbeConnectGuardError) as raised:
        manager.release(lease, timeout_seconds=3.0)

    assert str(raised.value) == "probe_guard_cleanup_pending"
    assert "must-not-escape" not in repr(raised.value)
    assert manager.retry_pending_cleanup(timeout_seconds=3.0) == 0
    with pytest.raises(ProbeConnectGuardError, match="probe_guard_lease_invalid"):
        manager.release(lease, timeout_seconds=3.0)


def test_guard_manager_preserves_release_and_retry_interruptions(
    tmp_path: Path,
) -> None:
    manager, backend = _manager()
    scope = _guard_scope(tmp_path)
    lease = manager.install(
        request_id=scope.request_id,
        unit_name=scope.unit_name,
        cgroup_path=scope.cgroup_path,
        target=scope.target,
        timeout_seconds=3.0,
    )
    backend.remove_errors = [KeyboardInterrupt("release interrupted")]

    with pytest.raises(BaseExceptionGroup) as release_error:
        manager.release(lease, timeout_seconds=3.0)
    assert any(
        isinstance(error, KeyboardInterrupt)
        for error in release_error.value.exceptions
    )

    backend.remove_errors = [KeyboardInterrupt("retry interrupted")]
    with pytest.raises(BaseExceptionGroup) as retry_error:
        manager.retry_pending_cleanup(timeout_seconds=3.0)
    assert any(
        isinstance(error, KeyboardInterrupt) for error in retry_error.value.exceptions
    )
    assert manager.retry_pending_cleanup(timeout_seconds=3.0) == 0


def test_guard_manager_rejects_invalid_lease_and_timeout(tmp_path: Path) -> None:
    manager, backend = _manager()

    with pytest.raises(ProbeConnectGuardError, match="probe_guard_lease_invalid"):
        manager.release(object(), timeout_seconds=3.0)  # type: ignore[arg-type]
    with pytest.raises(ProbeConnectGuardError, match="probe_guard_timeout_invalid"):
        manager.retry_pending_cleanup(timeout_seconds=True)

    assert backend.removed == []


def test_guard_manager_rejects_release_while_scope_operation_is_busy(
    tmp_path: Path,
) -> None:
    manager, _backend = _manager()
    scope = _guard_scope(tmp_path)
    lease = manager.install(
        request_id=scope.request_id,
        unit_name=scope.unit_name,
        cgroup_path=scope.cgroup_path,
        target=scope.target,
        timeout_seconds=3.0,
    )
    record = manager._active[scope.unit_name]
    record.operation_lock.acquire()
    try:
        with pytest.raises(
            ProbeConnectGuardError,
            match="probe_guard_cleanup_in_progress",
        ):
            manager.release(lease, timeout_seconds=3.0)
    finally:
        record.operation_lock.release()

    manager.release(lease, timeout_seconds=3.0)


def test_guard_manager_bounds_pending_cleanup_by_aggregate_deadline(
    tmp_path: Path,
) -> None:
    manager, backend = _manager()
    scope = _guard_scope(tmp_path)
    lease = manager.install(
        request_id=scope.request_id,
        unit_name=scope.unit_name,
        cgroup_path=scope.cgroup_path,
        target=scope.target,
        timeout_seconds=3.0,
    )
    backend.remove_errors = [RuntimeError("cleanup failed")]
    with pytest.raises(ProbeConnectGuardError, match="probe_guard_cleanup_pending"):
        manager.release(lease, timeout_seconds=3.0)
    observed = iter([0.0, 4.0])
    manager._monotonic = lambda: next(observed)

    assert manager.retry_pending_cleanup(timeout_seconds=3.0) == 1


def test_guard_manager_skips_busy_pending_cleanup_scope(tmp_path: Path) -> None:
    manager, backend = _manager()
    scope = _guard_scope(tmp_path)
    lease = manager.install(
        request_id=scope.request_id,
        unit_name=scope.unit_name,
        cgroup_path=scope.cgroup_path,
        target=scope.target,
        timeout_seconds=3.0,
    )
    backend.remove_errors = [RuntimeError("cleanup failed")]
    with pytest.raises(ProbeConnectGuardError, match="probe_guard_cleanup_pending"):
        manager.release(lease, timeout_seconds=3.0)
    record = manager._active[scope.unit_name]
    record.operation_lock.acquire()
    try:
        assert manager.retry_pending_cleanup(timeout_seconds=3.0) == 1
    finally:
        record.operation_lock.release()

    assert manager.retry_pending_cleanup(timeout_seconds=3.0) == 0


def test_guard_manager_serializes_cleanup_retry_callers() -> None:
    manager, _backend = _manager()
    manager._cleanup_retry_lock.acquire()
    try:
        assert manager.retry_pending_cleanup(timeout_seconds=3.0) == 0
    finally:
        manager._cleanup_retry_lock.release()


def test_guard_command_budget_rejects_invalid_or_expired_deadline() -> None:
    with pytest.raises(ProbeConnectGuardError, match="probe_guard_timeout_invalid"):
        probe_connect_guard._CommandBudget.start(0, monotonic=lambda: 0.0)

    observed = iter([0.0, 2.0])
    budget = probe_connect_guard._CommandBudget.start(
        1.0,
        monotonic=lambda: next(observed),
    )
    with pytest.raises(ProbeConnectGuardError, match="probe_guard_timeout"):
        budget.remaining()


def test_guard_manager_fails_closed_when_cgroup_metadata_is_unreadable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, backend = _manager()
    scope = _guard_scope(tmp_path)
    original_is_dir = Path.is_dir

    def fail_cgroup_read(path: Path) -> bool:
        if path == scope.cgroup_path:
            raise OSError("cgroup unavailable")
        return original_is_dir(path)

    monkeypatch.setattr(Path, "is_dir", fail_cgroup_read)

    with pytest.raises(ProbeConnectGuardError, match="probe_guard_scope_invalid"):
        manager.install(
            request_id=scope.request_id,
            unit_name=scope.unit_name,
            cgroup_path=scope.cgroup_path,
            target=scope.target,
            timeout_seconds=3.0,
        )

    assert backend.installed == []
