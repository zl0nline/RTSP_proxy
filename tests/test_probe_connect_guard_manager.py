from __future__ import annotations

import json
import os
import selectors
import shutil
import subprocess
from dataclasses import dataclass
from hashlib import sha256
from ipaddress import ip_address
from pathlib import Path
from threading import Event, Thread
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
    observed_times = iter([0.0, 0.0, 4.0])
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

    class _FailingReceiptOutput:
        def __init__(self, descriptor: int) -> None:
            self.descriptor = descriptor

        def __enter__(self) -> _FailingReceiptOutput:
            return self

        def __exit__(
            self,
            _error_type: object,
            _error: object,
            _traceback: object,
        ) -> None:
            os.close(self.descriptor)

        def write(self, _payload: bytes) -> int:
            if failure == "interrupt":
                raise KeyboardInterrupt("receipt interrupted")
            return 0

        def fileno(self) -> int:
            return self.descriptor

    def failing_open(
        path: str | Path,
        _mode: str,
        *,
        buffering: int,
        opener: object,
    ) -> _FailingReceiptOutput:
        assert buffering == 0
        assert callable(opener)
        descriptor = opener(
            os.fspath(path),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        )
        return _FailingReceiptOutput(descriptor)

    monkeypatch.setattr("builtins.open", failing_open)
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
    assert list((tmp_path / "ownership").iterdir()) == []


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

    def lose_scope_race(path: str | Path, mode: int = 0o777) -> None:
        if Path(path) == foreign_scope:
            original_mkdir(path, mode)
            raise FileExistsError(os.fspath(path))
        original_mkdir(path, mode)

    monkeypatch.setattr("rtsp_proxy.probe_connect_guard.os.mkdir", lose_scope_race)

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
    assert list((tmp_path / "ownership").iterdir()) == []


def test_collision_receipt_cleanup_failure_never_owns_the_foreign_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeBpftool()
    backend = _bpftool_backend(tmp_path, run=fake)
    manager = ProbeConnectGuardManager(backend=backend)
    scope = _guard_scope(tmp_path)
    foreign_scope = tmp_path / "pins" / scope.request_id.hex
    receipt = tmp_path / "ownership" / f"{scope.request_id.hex}.json"
    original_mkdir = os.mkdir
    original_unlink = Path.unlink
    fail_unlink = True

    def lose_scope_race(path: str | Path, mode: int = 0o777) -> None:
        if Path(path) == foreign_scope:
            original_mkdir(path, mode)
            raise FileExistsError(os.fspath(path))
        original_mkdir(path, mode)

    def reject_receipt_unlink(
        path: Path,
        missing_ok: bool = False,
    ) -> None:
        if path == receipt and fail_unlink:
            raise OSError("ambiguous receipt cleanup")
        original_unlink(path, missing_ok=missing_ok)

    monkeypatch.setattr("rtsp_proxy.probe_connect_guard.os.mkdir", lose_scope_race)
    monkeypatch.setattr(Path, "unlink", reject_receipt_unlink)

    with pytest.raises(ProbeConnectGuardError, match="probe_guard_already_active"):
        manager.install(
            request_id=scope.request_id,
            unit_name=scope.unit_name,
            cgroup_path=scope.cgroup_path,
            target=scope.target,
            timeout_seconds=3.0,
        )

    assert foreign_scope.is_dir()
    assert receipt.is_file()

    fail_unlink = False
    restarted = ProbeConnectGuardManager(
        backend=_bpftool_backend(tmp_path, run=fake, create_roots=False)
    )
    assert restarted.reconcile_startup(timeout_seconds=3.0) == 0
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

    restarted_manager = ProbeConnectGuardManager(
        backend=_bpftool_backend(tmp_path, run=fake, create_roots=False)
    )
    assert restarted_manager.reconcile_startup(timeout_seconds=3.0) == 0

    assert fake.attachments == {}
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
        if reject_final_fsync and path == ownership_root and not any(path.iterdir()):
            raise OSError("directory fsync failed after unlink")
        original_fsync_directory(path)

    monkeypatch.setattr(probe_connect_guard, "_fsync_directory", ambiguous_fsync)

    with pytest.raises(ProbeConnectGuardError, match="probe_guard_cleanup_pending"):
        manager.release(lease, timeout_seconds=3.0)

    assert list((tmp_path / "pins").iterdir()) == []
    assert list(ownership_root.iterdir()) == []
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
    for _index in range(10):
        scope = _guard_scope(tmp_path)
        backend.install(scope, timeout_seconds=3.0)

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
    assert list((tmp_path / "ownership").iterdir()) == []


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
    original_popen = subprocess.Popen
    swapped = False
    executed_paths: list[str] = []

    def swap_during_process_start(
        arguments: tuple[str, ...],
        **keywords: object,
    ) -> object:
        nonlocal swapped
        executed_paths.append(arguments[0])
        if not swapped:
            swapped = True
            backup = tmp_path / "verified-bpftool"
            bpftool.rename(backup)
            malicious.rename(bpftool)
            try:
                return original_popen(arguments, **keywords)  # type: ignore[call-overload]
            finally:
                bpftool.rename(malicious)
                backup.rename(bpftool)
        return original_popen(arguments, **keywords)  # type: ignore[call-overload]

    monkeypatch.setattr(
        "rtsp_proxy.probe_connect_guard.subprocess.Popen",
        swap_during_process_start,
    )

    backend.install(_guard_scope(tmp_path), timeout_seconds=3.0)

    assert all(path != str(bpftool) for path in executed_paths)


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
    pin_root = tmp_path / "pins"
    pin_root.mkdir()
    ownership_root = tmp_path / "ownership"
    ownership_root.mkdir()
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
    assert list(ownership_root.iterdir()) == []


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

    monkeypatch.setattr(
        "rtsp_proxy.probe_connect_guard.subprocess.Popen",
        lambda *arguments, **keywords: _Process(),
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
    pin_root = tmp_path / "pins"
    pin_root.mkdir()
    ownership_root = tmp_path / "ownership"
    ownership_root.mkdir()
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
    pin_root = tmp_path / "pins"
    pin_root.mkdir()
    ownership_root = tmp_path / "ownership"
    ownership_root.mkdir()
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
    assert list(ownership_root.iterdir()) == []


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
