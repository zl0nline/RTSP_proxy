from __future__ import annotations

import ctypes
import fcntl
import json
import logging
import os
import platform
import re
import secrets
import selectors
import signal
import socket
import stat
import subprocess
import sys
import time
import weakref
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from hashlib import sha256
from importlib.resources import files
from ipaddress import ip_address
from math import isfinite
from pathlib import Path
from threading import Lock
from typing import BinaryIO, NoReturn, Protocol, cast
from uuid import UUID

from rtsp_proxy.probe_executor import ProbeConnectGuardTarget
from rtsp_proxy.probe_ownership import OwnershipLedger

_COMMAND_OUTPUT_MAX_BYTES = 65_536
_COMMAND_CLEANUP_SECONDS = 1.0
_LOGGER = logging.getLogger(__name__)
_SPAWN_WRAPPER = """
import os
import signal
import sys

pid_descriptor = int(sys.argv[1])
gate_descriptor = int(sys.argv[2])
kept_descriptors = {0, 1, 2, pid_descriptor, gate_descriptor}
kept_descriptors.update(int(item) for item in sys.argv[3].split(",") if item)
descriptor_directory = "/proc/self/fd" if os.path.isdir("/proc/self/fd") else "/dev/fd"
upper = max((int(item) for item in os.listdir(descriptor_directory)), default=2) + 1
lower = 3
for descriptor in sorted(kept_descriptors - {0, 1, 2}):
    os.closerange(lower, descriptor)
    lower = descriptor + 1
os.closerange(lower, upper)
os.write(pid_descriptor, f"{os.getpid()}\\n".encode("ascii"))
if os.read(gate_descriptor, 1) != b"R":
    raise SystemExit(125)
restored_signal_mask = {int(item) for item in sys.argv[4].split(",") if item}
signal.pthread_sigmask(signal.SIG_SETMASK, restored_signal_mask)
os.close(pid_descriptor)
os.close(gate_descriptor)
os.execve(sys.argv[6], sys.argv[6:], os.environ)
"""


class ProbeConnectGuardError(RuntimeError):
    """An exact cgroup connect guard could not be installed or collected."""


class ProbeConnectGuardInstallRejected(ProbeConnectGuardError):
    """The kernel scope was already owned before this install mutated it."""


class ProbeConnectGuardInstallRejectedInterruption(BaseException):
    """A pre-mutation install rejection followed a process interruption."""

    def __init__(self, interruption: BaseException) -> None:
        super().__init__("probe_guard_install_rejected_interrupted")
        self.interruption = interruption


class ProbeConnectGuardInstallReconcileRequired(ProbeConnectGuardError):
    """A rejected install left receipt-proven state requiring reconciliation."""

    def __init__(self, interruption: BaseException | None = None) -> None:
        super().__init__("probe_guard_reconcile_required")
        self.interruption = interruption


@dataclass(frozen=True, slots=True)
class ProbeConnectGuardArtifactIdentity:
    """Release-bound identities required before loading a guard object."""

    bpftool_sha256: str
    object_sha256: str
    ipv4_program_tag: str
    ipv6_program_tag: str

    def __post_init__(self) -> None:
        if not all(
            re.fullmatch(r"[0-9a-f]{64}", digest)
            for digest in (self.bpftool_sha256, self.object_sha256)
        ) or not all(
            re.fullmatch(r"[0-9a-f]{16}", tag)
            for tag in (self.ipv4_program_tag, self.ipv6_program_tag)
        ):
            raise ProbeConnectGuardError("probe_guard_artifact_identity_invalid")


@dataclass(frozen=True, slots=True)
class _ProbeConnectGuardArtifactRelease:
    release_id: str
    architecture: str
    object_sha256: str
    ipv4_program_tag: str
    ipv6_program_tag: str
    bpftool_sha256: frozenset[str]
    activation_compatible: bool
    cleanup_compatible: bool


@dataclass(frozen=True, slots=True)
class _ProbeConnectGuardArtifactCatalog:
    current_release_id: str
    releases: tuple[_ProbeConnectGuardArtifactRelease, ...]

    def activation_release(
        self,
        identity: ProbeConnectGuardArtifactIdentity,
        *,
        architecture: str,
    ) -> _ProbeConnectGuardArtifactRelease:
        matches = [
            release
            for release in self.releases
            if release.release_id == self.current_release_id
            and release.architecture == architecture
            and release.activation_compatible
            and release.object_sha256 == identity.object_sha256
            and release.ipv4_program_tag == identity.ipv4_program_tag
            and release.ipv6_program_tag == identity.ipv6_program_tag
            and identity.bpftool_sha256 in release.bpftool_sha256
        ]
        if len(matches) != 1:
            raise ProbeConnectGuardError("probe_guard_artifact_identity_invalid")
        return matches[0]

    def cleanup_release(
        self,
        release_id: str,
        *,
        architecture: str,
    ) -> _ProbeConnectGuardArtifactRelease:
        matches = [
            release
            for release in self.releases
            if release.release_id == release_id
            and release.architecture == architecture
            and release.cleanup_compatible
        ]
        if len(matches) != 1:
            raise ProbeConnectGuardError("probe_guard_ownership_invalid")
        return matches[0]


def trusted_probe_connect_guard_release_identity(
    machine: str,
) -> tuple[str, str]:
    """Return the current activation release and object digest for one arch."""

    catalog = _load_packaged_artifact_catalog()
    architecture = _linux_architecture(machine)
    matches = tuple(
        release
        for release in catalog.releases
        if release.release_id == catalog.current_release_id
        and release.architecture == architecture
        and release.activation_compatible
    )
    if len(matches) != 1:
        raise ProbeConnectGuardError("probe_guard_artifact_identity_invalid")
    release = matches[0]
    return release.release_id, release.object_sha256


def trusted_probe_connect_guard_artifact_identity(
    *,
    bpftool_path: Path,
    object_path: Path,
) -> ProbeConnectGuardArtifactIdentity:
    """Bind the actual host tool and release object to the packaged catalog."""

    catalog = _load_packaged_artifact_catalog()
    architecture = _linux_architecture(platform.machine())
    matches = tuple(
        release
        for release in catalog.releases
        if release.release_id == catalog.current_release_id
        and release.architecture == architecture
        and release.activation_compatible
    )
    if len(matches) != 1:
        raise ProbeConnectGuardError("probe_guard_artifact_identity_invalid")
    release = matches[0]
    try:
        identity = ProbeConnectGuardArtifactIdentity(
            bpftool_sha256=_sha256_path(bpftool_path),
            object_sha256=_sha256_path(object_path),
            ipv4_program_tag=release.ipv4_program_tag,
            ipv6_program_tag=release.ipv6_program_tag,
        )
        catalog.activation_release(identity, architecture=architecture)
    except (OSError, ProbeConnectGuardError):
        raise ProbeConnectGuardError("probe_guard_artifact_identity_invalid") from None
    return identity

@dataclass(frozen=True, slots=True)
class ProbeConnectGuardScope:
    """Exact kernel scope owned by one probe request."""

    request_id: UUID
    unit_name: str
    cgroup_path: Path
    target: ProbeConnectGuardTarget = field(repr=False)


@dataclass(frozen=True, slots=True, eq=False)
class ProbeConnectGuardLease:
    """Opaque capability proving one guard was installed and read back."""

    request_id: UUID
    unit_name: str
    target: ProbeConnectGuardTarget = field(repr=False)


@dataclass(slots=True)
class _GuardRecord:
    scope: ProbeConnectGuardScope
    state: str = "installing"
    lease: ProbeConnectGuardLease | None = None
    ownership: OwnershipLedger[ProbeConnectGuardLease] | None = field(
        default=None,
        repr=False,
    )
    operation_lock: Lock = field(default_factory=Lock, repr=False)
    cleanup_attempt_order: int = 0


class ProbeConnectGuardBackend(Protocol):
    """Kernel adapter used behind the guard manager seam."""

    def install(
        self,
        scope: ProbeConnectGuardScope,
        *,
        timeout_seconds: float,
    ) -> None: ...

    def verify(
        self,
        scope: ProbeConnectGuardScope,
        *,
        timeout_seconds: float,
    ) -> None: ...

    def remove(
        self,
        scope: ProbeConnectGuardScope,
        *,
        timeout_seconds: float,
    ) -> None: ...

    def reconcile_owned(self, *, timeout_seconds: float) -> int: ...


class ProbeConnectGuardCommand(Protocol):
    """Bounded command adapter for the distribution bpftool."""

    def __call__(
        self,
        arguments: tuple[str, ...],
        *,
        timeout_seconds: float,
    ) -> str: ...


class _Closable(Protocol):
    def close(self) -> object: ...


class BpftoolProbeConnectGuardBackend:
    """Install and prove one exact guard through a trusted bpftool binary."""

    _IPV4_PIN = "rtsp_probe_guard_ipv4"
    _IPV6_PIN = "rtsp_probe_guard_ipv6"
    _MAP_PIN = "allowed_target"
    _IPV4_ATTACH = "cgroup_inet4_connect"
    _IPV6_ATTACH = "cgroup_inet6_connect"
    _RECONCILE_MAX_SCOPES = 8
    _OWNERSHIP_MAX_SCOPES = 256
    _COORDINATOR_NAME = ".probe-connect-guard.lock"

    def __init__(
        self,
        *,
        bpftool_path: Path,
        object_path: Path,
        pin_root: Path,
        ownership_root: Path,
        artifact_identity: ProbeConnectGuardArtifactIdentity,
        trusted_owner_uid: int = 0,
        run: ProbeConnectGuardCommand | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if isinstance(trusted_owner_uid, bool) or trusted_owner_uid < 0:
            raise ProbeConnectGuardError("probe_guard_tool_invalid")
        if not isinstance(artifact_identity, ProbeConnectGuardArtifactIdentity):
            raise ProbeConnectGuardError("probe_guard_artifact_identity_invalid")
        architecture = _linux_architecture(platform.machine())
        # Production is the root-owned, direct-command branch and must use the
        # wheel-packaged catalog. The injected command/non-root branch is the
        # explicit adapter boundary used by unprivileged unit tests only.
        catalog = (
            _test_artifact_catalog(artifact_identity, architecture=architecture)
            if run is not None or trusted_owner_uid != 0
            else _load_packaged_artifact_catalog()
        )
        activation_release = catalog.activation_release(
            artifact_identity,
            architecture=architecture,
        )
        self._identity = artifact_identity
        self._artifact_catalog = catalog
        self._artifact_release = activation_release
        self._architecture = architecture
        self._bpftool = _trusted_path(
            bpftool_path,
            owner_uid=trusted_owner_uid,
            executable=True,
            expected_sha256=artifact_identity.bpftool_sha256,
        )
        self._object = _trusted_path(
            object_path,
            owner_uid=trusted_owner_uid,
            executable=False,
            expected_sha256=artifact_identity.object_sha256,
        )
        root_descriptors: list[int] = []
        use_bound_roots = run is None and trusted_owner_uid == 0
        try:
            pin_root_descriptor = _open_trusted_directory(
                pin_root,
                owner_uid=trusted_owner_uid,
            )
            root_descriptors.append(pin_root_descriptor)
            ownership_root_descriptor = _open_trusted_directory(
                ownership_root,
                owner_uid=trusted_owner_uid,
            )
            root_descriptors.append(ownership_root_descriptor)
            self._pin_root = Path(
                _directory_descriptor_path(
                    pin_root_descriptor,
                    fallback=pin_root,
                )
                if use_bound_roots
                else pin_root
            )
            self._ownership_root = Path(
                _directory_descriptor_path(
                    ownership_root_descriptor,
                    fallback=ownership_root,
                )
                if use_bound_roots
                else ownership_root
            )
        except BaseException:
            _close_descriptors(root_descriptors)
            raise
        self._owner_uid = trusted_owner_uid
        self._run = run
        self._monotonic = monotonic
        self._scope_lock_guard = Lock()
        self._scope_locks: dict[UUID, int] = {}
        self._root_descriptors = tuple(root_descriptors)
        self._root_finalizer = weakref.finalize(
            self,
            _close_backend_descriptors,
            self._root_descriptors,
            self._scope_locks,
        )
        self._coordinator_path = self._ownership_root / self._COORDINATOR_NAME
        self._ensure_coordinator_file()

    def install(
        self,
        scope: ProbeConnectGuardScope,
        *,
        timeout_seconds: float,
    ) -> None:
        try:
            self._require_artifact_identity()
        except ProbeConnectGuardError:
            raise ProbeConnectGuardInstallRejected(
                "probe_guard_artifact_identity_invalid"
            ) from None
        paths = self._paths(scope)
        budget = _CommandBudget.start(timeout_seconds, monotonic=self._monotonic)
        coordinator = self._acquire_coordinator(shared=True, budget=budget)
        retain_coordinator = False
        try:
            if paths.scope.exists() or paths.receipt.exists():
                raise ProbeConnectGuardInstallRejected(
                    "probe_guard_already_active"
                )
            reservation_nonce = self._create_receipt(scope, paths.receipt)
            retain_coordinator = True
            reservation_scope = self._reservation_scope_path(
                scope,
                reservation_nonce,
            )
            try:
                os.mkdir(reservation_scope, mode=0o700)
                self._promote_receipt(
                    scope,
                    paths.receipt,
                    reservation_scope,
                )
                _rename_directory_no_replace(reservation_scope, paths.scope)
                _fsync_directory(self._pin_root)
                self._finalize_receipt(scope, paths.receipt, paths.scope)
            except BaseException as primary_error:
                cleanup_errors: list[BaseException] = []
                try:
                    self._cleanup_preload_reservation(
                        scope,
                        paths.receipt,
                        reservation_scope,
                    )
                except BaseException as cleanup_error:
                    cleanup_errors.append(_sanitize_cleanup_error(cleanup_error))
                if cleanup_errors:
                    if isinstance(primary_error, FileExistsError):
                        interruption = next(
                            (
                                error
                                for error in cleanup_errors
                                if not isinstance(error, Exception)
                            ),
                            None,
                        )
                        retain_coordinator = False
                        raise ProbeConnectGuardInstallReconcileRequired(
                            interruption
                        ) from None
                    raise BaseExceptionGroup(
                        "probe guard ownership promotion and cleanup failed",
                        [primary_error, *cleanup_errors],
                    ) from None
                retain_coordinator = False
                if isinstance(primary_error, FileExistsError):
                    raise ProbeConnectGuardInstallRejected(
                        "probe_guard_already_active"
                    ) from None
                if not isinstance(primary_error, Exception):
                    raise ProbeConnectGuardInstallRejectedInterruption(
                        primary_error
                    ) from None
                raise ProbeConnectGuardInstallRejected(
                    "probe_guard_install_failed"
                ) from None
            self._remember_scope_coordinator(scope, coordinator)
            coordinator = -1
            for path in (paths.programs, paths.maps):
                os.mkdir(path, mode=0o700)
            self._install_command(
                "load",
                "prog",
                "loadall",
                str(self._object),
                str(paths.programs),
                "pinmaps",
                str(paths.maps),
                budget=budget,
            )
            self._install_command(
                "attach4",
                "cgroup",
                "attach",
                str(scope.cgroup_path),
                self._IPV4_ATTACH,
                "pinned",
                str(paths.ipv4),
                "multi",
                budget=budget,
            )
            self._install_command(
                "attach6",
                "cgroup",
                "attach",
                str(scope.cgroup_path),
                self._IPV6_ATTACH,
                "pinned",
                str(paths.ipv6),
                "multi",
                budget=budget,
            )
            key = (0).to_bytes(4, "little")
            self._install_command(
                "map",
                "map",
                "update",
                "pinned",
                str(paths.target_map),
                "key",
                "hex",
                *_hex_bytes(key),
                "value",
                "hex",
                *_hex_bytes(scope.target.map_value()),
                budget=budget,
            )
        except ProbeConnectGuardInstallRejected:
            retain_coordinator = False
            raise
        finally:
            if coordinator >= 0:
                os.close(coordinator)
            if not retain_coordinator:
                self._forget_scope_coordinator(scope)

    def verify(
        self,
        scope: ProbeConnectGuardScope,
        *,
        timeout_seconds: float,
    ) -> None:
        self._require_artifact_identity()
        paths = self._paths(scope)
        budget = _CommandBudget.start(timeout_seconds, monotonic=self._monotonic)
        self._require_receipt(scope, paths.receipt, require_current=True)
        self._require_exact_pin_inventory(paths)
        map_inventory = self._json_command(
            "-j",
            "map",
            "show",
            "pinned",
            str(paths.target_map),
            budget=budget,
        )
        map_id = _map_inventory_id(map_inventory)
        if map_id is None:
            raise ProbeConnectGuardError("probe_guard_readback_invalid")
        ipv4_id = self._program_id(
            paths.ipv4,
            expected_tag=self._identity.ipv4_program_tag,
            expected_map_id=map_id,
            budget=budget,
        )
        ipv6_id = self._program_id(
            paths.ipv6,
            expected_tag=self._identity.ipv6_program_tag,
            expected_map_id=map_id,
            budget=budget,
        )
        key = (0).to_bytes(4, "little")
        lookup = self._json_command(
            "-j",
            "map",
            "lookup",
            "pinned",
            str(paths.target_map),
            "key",
            "hex",
            *_hex_bytes(key),
            budget=budget,
        )
        if _json_bytes(lookup, "key") != key or _json_bytes(
            lookup, "value"
        ) != scope.target.map_value():
            raise ProbeConnectGuardError("probe_guard_readback_invalid")
        attachments = (
            self._attachments(scope.cgroup_path, budget=budget)
            if scope.cgroup_path.exists()
            else set()
        )
        expected = {
            (ipv4_id, self._IPV4_ATTACH),
            (ipv6_id, self._IPV6_ATTACH),
        }
        owned_program_ids = {ipv4_id, ipv6_id}
        owned_attachments = {
            attachment
            for attachment in attachments
            if attachment[0] in owned_program_ids
        }
        if owned_attachments != expected:
            raise ProbeConnectGuardError("probe_guard_readback_invalid")

    def remove(
        self,
        scope: ProbeConnectGuardScope,
        *,
        timeout_seconds: float,
    ) -> None:
        budget = _CommandBudget.start(timeout_seconds, monotonic=self._monotonic)
        coordinator = self._scope_coordinator(scope)
        if coordinator is None:
            coordinator = self._acquire_coordinator(shared=True, budget=budget)
            self._remember_scope_coordinator(scope, coordinator)
        try:
            self._remove_owned(scope, budget=budget)
        except BaseException:
            raise
        else:
            self._forget_scope_coordinator(scope)

    def _remove_owned(
        self,
        scope: ProbeConnectGuardScope,
        *,
        budget: _CommandBudget,
        allow_legacy_cleanup: bool = False,
    ) -> None:
        self._require_artifact_identity()
        paths = self._paths(scope)
        if not _path_lexists(paths.receipt):
            if not _path_lexists(paths.scope):
                return
            raise ProbeConnectGuardError("probe_guard_ownership_invalid")
        ownership = self._ownership_from_receipt(paths.receipt)
        if ownership.scope != scope or not (
            (ownership.receipt_version == 3 and ownership.phase == 2)
            or (
                allow_legacy_cleanup
                and ownership.receipt_version == 2
                and ownership.phase == 1
            )
        ):
            raise ProbeConnectGuardError("probe_guard_ownership_invalid")
        if not _path_lexists(paths.scope):
            self._remove_receipt(paths.receipt)
            return
        ownership = self._require_receipt(
            scope,
            paths.receipt,
            allow_legacy_cleanup=allow_legacy_cleanup,
        )
        self._require_exact_partial_inventory(paths)
        program_ids: dict[str, int] = {}
        for attach_type, program_path in (
            (self._IPV4_ATTACH, paths.ipv4),
            (self._IPV6_ATTACH, paths.ipv6),
        ):
            if program_path.exists():
                program_ids[attach_type] = self._program_id(
                    program_path,
                    expected_tag=(
                        ownership.artifact_release.ipv4_program_tag
                        if attach_type == self._IPV4_ATTACH
                        else ownership.artifact_release.ipv6_program_tag
                    ),
                    expected_map_id=None,
                    budget=budget,
                )
        attachments = (
            self._attachments(scope.cgroup_path, budget=budget)
            if scope.cgroup_path.exists()
            else set()
        )
        for attach_type, program_id in program_ids.items():
            if (program_id, attach_type) in attachments:
                program_path = (
                    paths.ipv4 if attach_type == self._IPV4_ATTACH else paths.ipv6
                )
                try:
                    self._command(
                        "cgroup",
                        "detach",
                        str(scope.cgroup_path),
                        attach_type,
                        "pinned",
                        str(program_path),
                        budget=budget,
                    )
                except ProbeConnectGuardError:
                    if scope.cgroup_path.exists():
                        raise
                    break
        remaining = (
            self._attachments(scope.cgroup_path, budget=budget)
            if scope.cgroup_path.exists()
            else set()
        )
        if any(
            (program_id, attach_type) in remaining
            for attach_type, program_id in program_ids.items()
        ):
            raise ProbeConnectGuardError("probe_guard_cleanup_failed")
        for path in (paths.target_map, paths.ipv6, paths.ipv4):
            path.unlink(missing_ok=True)
        for path in (paths.maps, paths.programs, paths.scope):
            if path.exists():
                path.rmdir()
        self._remove_receipt(paths.receipt)

    def reconcile_owned(self, *, timeout_seconds: float) -> int:
        """Collect a bounded batch of receipt-proven scopes after broker restart."""

        budget = _CommandBudget.start(timeout_seconds, monotonic=self._monotonic)
        coordinator = self._acquire_coordinator(shared=False, budget=budget)
        try:
            self._cleanup_promotion_temps()
            receipts = self._receipt_inventory()
            for receipt in receipts[: self._RECONCILE_MAX_SCOPES]:
                ownership = self._ownership_from_receipt(receipt)
                try:
                    if ownership.phase == 0:
                        self._cleanup_reserved_scope(ownership, receipt)
                    else:
                        self._cleanup_staged_owned_scope(
                            ownership,
                            receipt,
                            budget=budget,
                        )
                except ProbeConnectGuardError:
                    if budget.deadline - self._monotonic() <= 0:
                        break
            return len(self._receipt_inventory())
        finally:
            os.close(coordinator)

    def _paths(self, scope: ProbeConnectGuardScope) -> _GuardPaths:
        scope_root = self._pin_root / scope.request_id.hex
        programs = scope_root / "programs"
        maps = scope_root / "maps"
        return _GuardPaths(
            scope=scope_root,
            programs=programs,
            maps=maps,
            ipv4=programs / self._IPV4_PIN,
            ipv6=programs / self._IPV6_PIN,
            target_map=maps / self._MAP_PIN,
            receipt=self._ownership_root / f"{scope.request_id.hex}.json",
        )

    def _create_receipt(self, scope: ProbeConnectGuardScope, path: Path) -> str:
        reservation_nonce = secrets.token_hex(16)
        payload = _receipt_bytes(
            scope,
            object_sha256=self._identity.object_sha256,
            artifact_release_id=self._artifact_release.release_id,
            phase=0,
            scope_device=0,
            scope_inode=0,
            reservation_nonce=reservation_nonce,
        )
        temporary = self._reservation_receipt_path(
            scope,
            reservation_nonce,
        )
        linked = False
        try:
            _write_exclusive_file(temporary, payload, mode=0o600)
            os.link(temporary, path, follow_symlinks=False)
            linked = True
            temporary.unlink()
            _fsync_directory(self._ownership_root)
        except FileExistsError:
            temporary.unlink(missing_ok=True)
            raise ProbeConnectGuardInstallRejected(
                "probe_guard_already_active"
            ) from None
        except BaseException as primary_error:
            cleanup_errors: list[BaseException] = []
            try:
                temporary.unlink(missing_ok=True)
                if linked:
                    path.unlink(missing_ok=True)
                _fsync_directory(self._ownership_root)
            except BaseException as error:
                cleanup_errors.append(_sanitize_cleanup_error(error))
            if cleanup_errors:
                raise BaseExceptionGroup(
                    "probe guard receipt creation and cleanup failed",
                    [primary_error, *cleanup_errors],
                ) from None
            if not isinstance(primary_error, Exception):
                raise ProbeConnectGuardInstallRejectedInterruption(
                    primary_error
                ) from None
            raise ProbeConnectGuardInstallRejected(
                "probe_guard_install_failed"
            ) from None
        return reservation_nonce

    def _promote_receipt(
        self,
        scope: ProbeConnectGuardScope,
        path: Path,
        scope_path: Path,
    ) -> None:
        try:
            scope_metadata = scope_path.lstat()
        except OSError:
            raise ProbeConnectGuardError("probe_guard_ownership_invalid") from None
        if not _owned_directory_metadata_valid(
            scope_metadata,
            owner_uid=self._owner_uid,
        ):
            raise ProbeConnectGuardError("probe_guard_ownership_invalid")
        ownership = self._ownership_from_receipt(path)
        if ownership.scope != scope or ownership.phase != 0:
            raise ProbeConnectGuardError("probe_guard_ownership_invalid")
        reservation_nonce = _require_reservation_nonce(ownership)
        replacement = _receipt_bytes(
            scope,
            object_sha256=self._identity.object_sha256,
            artifact_release_id=self._artifact_release.release_id,
            phase=1,
            scope_device=scope_metadata.st_dev,
            scope_inode=scope_metadata.st_ino,
            reservation_nonce=reservation_nonce,
        )
        temporary = self._promotion_receipt_path(
            scope,
            reservation_nonce,
        )
        try:
            _write_exclusive_file(temporary, replacement, mode=0o600)
            os.replace(temporary, path)
            _fsync_directory(self._ownership_root)
        except (OSError, ProbeConnectGuardError):
            raise ProbeConnectGuardError("probe_guard_ownership_invalid") from None

    def _finalize_receipt(
        self,
        scope: ProbeConnectGuardScope,
        path: Path,
        scope_path: Path,
    ) -> None:
        ownership = self._ownership_from_receipt(path)
        try:
            scope_metadata = scope_path.lstat()
        except OSError:
            raise ProbeConnectGuardError("probe_guard_ownership_invalid") from None
        if (
            ownership.scope != scope
            or ownership.phase != 1
            or ownership.receipt_version != 3
            or not _owned_directory_metadata_valid(
                scope_metadata,
                owner_uid=self._owner_uid,
            )
            or scope_metadata.st_dev != ownership.scope_device
            or scope_metadata.st_ino != ownership.scope_inode
        ):
            raise ProbeConnectGuardError("probe_guard_ownership_invalid")
        reservation_nonce = _require_reservation_nonce(ownership)
        replacement = _receipt_bytes(
            scope,
            object_sha256=self._identity.object_sha256,
            artifact_release_id=self._artifact_release.release_id,
            phase=2,
            scope_device=ownership.scope_device,
            scope_inode=ownership.scope_inode,
            reservation_nonce=reservation_nonce,
        )
        temporary = self._promotion_receipt_path(
            scope,
            reservation_nonce,
        )
        try:
            _write_exclusive_file(temporary, replacement, mode=0o600)
            os.replace(temporary, path)
            _fsync_directory(self._ownership_root)
        except (OSError, ProbeConnectGuardError):
            raise ProbeConnectGuardError("probe_guard_ownership_invalid") from None

    def _require_receipt(
        self,
        scope: ProbeConnectGuardScope,
        path: Path,
        *,
        require_current: bool = False,
        allow_legacy_cleanup: bool = False,
    ) -> _GuardOwnership:
        ownership = self._ownership_from_receipt(path)
        if (
            ownership.scope != scope
            or not (
                (ownership.receipt_version == 3 and ownership.phase == 2)
                or (
                    allow_legacy_cleanup
                    and ownership.receipt_version == 2
                    and ownership.phase == 1
                )
            )
            or (
                require_current
                and ownership.artifact_release.release_id
                != self._artifact_release.release_id
            )
        ):
            raise ProbeConnectGuardError("probe_guard_ownership_invalid")
        try:
            scope_metadata = self._paths(scope).scope.lstat()
        except OSError:
            raise ProbeConnectGuardError("probe_guard_ownership_invalid") from None
        if (
            not _owned_directory_metadata_valid(
                scope_metadata,
                owner_uid=self._owner_uid,
            )
            or scope_metadata.st_dev != ownership.scope_device
            or scope_metadata.st_ino != ownership.scope_inode
        ):
            raise ProbeConnectGuardError("probe_guard_ownership_invalid")
        return ownership

    def _ownership_from_receipt(self, path: Path) -> _GuardOwnership:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = -1
        try:
            descriptor = os.open(path, flags)
            metadata = os.fstat(descriptor)
            if not _receipt_metadata_valid(
                metadata,
                owner_uid=self._owner_uid,
            ):
                raise ProbeConnectGuardError("probe_guard_ownership_invalid")
            payload = os.read(descriptor, 2_049)
            if len(payload) != metadata.st_size:
                raise ProbeConnectGuardError("probe_guard_ownership_invalid")
            decoded = json.loads(payload)
        except (OSError, UnicodeError, json.JSONDecodeError):
            raise ProbeConnectGuardError("probe_guard_ownership_invalid") from None
        finally:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    raise ProbeConnectGuardError(
                        "probe_guard_ownership_invalid"
                    ) from None
        try:
            if not isinstance(decoded, dict):
                raise ValueError
            version = decoded["version"]
            request_id = UUID(decoded["request_id"])
            target = ProbeConnectGuardTarget(
                address=ip_address(decoded["address"]),
                port=decoded["port"],
            )
            scope = ProbeConnectGuardScope(
                request_id=request_id,
                unit_name=decoded["unit_name"],
                cgroup_path=Path(decoded["cgroup_path"]),
                target=target,
            )
            phase = decoded["phase"]
            scope_device_raw = decoded["scope_device"]
            scope_inode_raw = decoded["scope_inode"]
            artifact_release_id = decoded["artifact_release_id"]
            if (
                isinstance(phase, bool)
                or not isinstance(phase, int)
                or not isinstance(scope_device_raw, str)
                or not re.fullmatch(r"[0-9]{20}", scope_device_raw)
                or not isinstance(scope_inode_raw, str)
                or not re.fullmatch(r"[0-9]{20}", scope_inode_raw)
                or not isinstance(artifact_release_id, str)
                or not re.fullmatch(
                    r"[0-9A-Za-z][0-9A-Za-z._-]{0,63}",
                    artifact_release_id,
                )
            ):
                raise ValueError
            scope_device = int(scope_device_raw)
            scope_inode = int(scope_inode_raw)
            artifact_release = self._artifact_catalog.cleanup_release(
                artifact_release_id,
                architecture=self._architecture,
            )
            if version == 3:
                reservation_nonce: str | None = decoded["reservation_nonce"]
                if (
                    phase not in {0, 1, 2}
                    or not isinstance(reservation_nonce, str)
                    or not re.fullmatch(r"[0-9a-f]{32}", reservation_nonce)
                    or set(decoded)
                    != {
                        "address",
                        "artifact_release_id",
                        "cgroup_path",
                        "object_sha256",
                        "phase",
                        "port",
                        "request_id",
                        "reservation_nonce",
                        "scope_device",
                        "scope_inode",
                        "unit_name",
                        "version",
                    }
                    or _receipt_bytes(
                        scope,
                        object_sha256=artifact_release.object_sha256,
                        artifact_release_id=artifact_release.release_id,
                        phase=phase,
                        scope_device=scope_device,
                        scope_inode=scope_inode,
                        reservation_nonce=reservation_nonce,
                    )
                    != payload
                ):
                    raise ValueError
            elif version == 2:
                reservation_nonce = None
                if (
                    phase not in {0, 1}
                    or set(decoded)
                    != {
                        "address",
                        "artifact_release_id",
                        "cgroup_path",
                        "object_sha256",
                        "phase",
                        "port",
                        "request_id",
                        "scope_device",
                        "scope_inode",
                        "unit_name",
                        "version",
                    }
                    or _receipt_bytes_v2(
                        scope,
                        object_sha256=artifact_release.object_sha256,
                        artifact_release_id=artifact_release.release_id,
                        phase=phase,
                        scope_device=scope_device,
                        scope_inode=scope_inode,
                    )
                    != payload
                ):
                    raise ValueError
            else:
                raise ValueError
        except (KeyError, TypeError, ValueError, RuntimeError):
            raise ProbeConnectGuardError("probe_guard_ownership_invalid") from None
        if (
            decoded["object_sha256"] != artifact_release.object_sha256
            or (phase == 0 and (scope_device != 0 or scope_inode != 0))
            or (phase in {1, 2} and (scope_device == 0 or scope_inode == 0))
            or scope.request_id.version != 4
            or scope.unit_name != f"rtsp-probe-{scope.request_id.hex}.service"
            or not scope.cgroup_path.is_absolute()
            or scope.cgroup_path.name != scope.unit_name
        ):
            raise ProbeConnectGuardError("probe_guard_ownership_invalid")
        return _GuardOwnership(
            scope=scope,
            phase=phase,
            scope_device=scope_device,
            scope_inode=scope_inode,
            reservation_nonce=reservation_nonce,
            artifact_release=artifact_release,
            receipt_version=version,
        )

    def _receipt_inventory(self) -> list[Path]:
        try:
            entries: list[Path] = []
            for entry in self._ownership_root.iterdir():
                if entry.name == self._COORDINATOR_NAME:
                    continue
                entries.append(entry)
                if len(entries) > self._OWNERSHIP_MAX_SCOPES:
                    raise ProbeConnectGuardError("probe_guard_ownership_capacity")
        except OSError:
            raise ProbeConnectGuardError("probe_guard_ownership_invalid") from None
        entries.sort()
        if any(
            not re.fullmatch(r"[0-9a-f]{32}\.json", entry.name)
            for entry in entries
        ):
            raise ProbeConnectGuardError("probe_guard_ownership_invalid")
        return entries

    def _remove_receipt(self, path: Path) -> None:
        path.unlink(missing_ok=False)
        _fsync_directory(self._ownership_root)

    def _remove_reserved_receipt(self, path: Path) -> None:
        if self._ownership_from_receipt(path).phase != 0:
            raise ProbeConnectGuardError("probe_guard_ownership_invalid")
        self._remove_receipt(path)

    def _reservation_scope_path(
        self,
        scope: ProbeConnectGuardScope,
        reservation_nonce: str,
    ) -> Path:
        return self._pin_root / (
            f"rtsp_probe_reservation_{scope.request_id.hex}_{reservation_nonce}"
        )

    def _promotion_receipt_path(
        self,
        scope: ProbeConnectGuardScope,
        reservation_nonce: str,
    ) -> Path:
        return self._ownership_root / (
            f".{scope.request_id.hex}.{reservation_nonce}.next"
        )

    def _reservation_receipt_path(
        self,
        scope: ProbeConnectGuardScope,
        reservation_nonce: str,
    ) -> Path:
        return self._ownership_root / (
            f".{scope.request_id.hex}.{reservation_nonce}.reserve"
        )

    def _cleanup_preload_reservation(
        self,
        scope: ProbeConnectGuardScope,
        receipt: Path,
        reservation_scope: Path,
    ) -> None:
        ownership = self._ownership_from_receipt(receipt)
        if ownership.scope != scope:
            raise ProbeConnectGuardError("probe_guard_ownership_invalid")
        reservation_nonce = _require_reservation_nonce(ownership)
        final_scope = self._paths(scope).scope
        candidates = [reservation_scope]
        if ownership.phase in {1, 2}:
            candidates.append(final_scope)
        for candidate in candidates:
            if not _path_lexists(candidate):
                continue
            metadata = candidate.lstat()
            if (
                candidate == final_scope
                and ownership.phase in {1, 2}
                and (
                    metadata.st_dev != ownership.scope_device
                    or metadata.st_ino != ownership.scope_inode
                )
            ):
                continue
            if (
                not _owned_directory_metadata_valid(
                    metadata,
                    owner_uid=self._owner_uid,
                )
                or list(candidate.iterdir())
                or (
                    ownership.phase in {1, 2}
                    and (
                        metadata.st_dev != ownership.scope_device
                        or metadata.st_ino != ownership.scope_inode
                    )
                )
            ):
                raise ProbeConnectGuardError("probe_guard_ownership_invalid")
            candidate.rmdir()
        temporary = self._promotion_receipt_path(
            scope,
            reservation_nonce,
        )
        temporary.unlink(missing_ok=True)
        self._remove_receipt(receipt)
        _fsync_directory(self._pin_root)

    def _cleanup_reserved_scope(
        self,
        ownership: _GuardOwnership,
        receipt: Path,
    ) -> None:
        if ownership.receipt_version == 2:
            if _path_lexists(self._paths(ownership.scope).scope):
                raise ProbeConnectGuardError("probe_guard_ownership_invalid")
            self._remove_receipt(receipt)
            return
        reservation_nonce = _require_reservation_nonce(ownership)
        reservation_scope = self._reservation_scope_path(
            ownership.scope,
            reservation_nonce,
        )
        if _path_lexists(reservation_scope):
            metadata = reservation_scope.lstat()
            if (
                not _owned_directory_metadata_valid(
                    metadata,
                    owner_uid=self._owner_uid,
                )
                or list(reservation_scope.iterdir())
            ):
                raise ProbeConnectGuardError("probe_guard_ownership_invalid")
            reservation_scope.rmdir()
            _fsync_directory(self._pin_root)
        temporary = self._promotion_receipt_path(
            ownership.scope,
            reservation_nonce,
        )
        temporary.unlink(missing_ok=True)
        self._remove_reserved_receipt(receipt)

    def _cleanup_staged_owned_scope(
        self,
        ownership: _GuardOwnership,
        receipt: Path,
        *,
        budget: _CommandBudget,
    ) -> None:
        paths = self._paths(ownership.scope)
        reservation_scope = (
            self._reservation_scope_path(
                ownership.scope,
                _require_reservation_nonce(ownership),
            )
            if ownership.receipt_version == 3
            else None
        )
        if _path_lexists(paths.scope):
            metadata = paths.scope.lstat()
            inode_matches = (
                metadata.st_dev == ownership.scope_device
                and metadata.st_ino == ownership.scope_inode
            )
            if reservation_scope is not None and _path_lexists(reservation_scope):
                reservation_metadata = reservation_scope.lstat()
                if (
                    inode_matches
                    or not _owned_directory_metadata_valid(
                        reservation_metadata,
                        owner_uid=self._owner_uid,
                    )
                    or reservation_metadata.st_dev != ownership.scope_device
                    or reservation_metadata.st_ino != ownership.scope_inode
                    or list(reservation_scope.iterdir())
                ):
                    raise ProbeConnectGuardError("probe_guard_ownership_invalid")
                reservation_scope.rmdir()
                _fsync_directory(self._pin_root)
                self._remove_receipt(receipt)
                return
            if ownership.phase == 1:
                if inode_matches:
                    if ownership.receipt_version == 2:
                        self._remove_owned(
                            ownership.scope,
                            budget=budget,
                            allow_legacy_cleanup=True,
                        )
                        return
                    if (
                        not _owned_directory_metadata_valid(
                            metadata,
                            owner_uid=self._owner_uid,
                        )
                        or list(paths.scope.iterdir())
                    ):
                        raise ProbeConnectGuardError(
                            "probe_guard_ownership_invalid"
                        )
                    paths.scope.rmdir()
                    _fsync_directory(self._pin_root)
                self._remove_receipt(receipt)
                return
            self._remove_owned(
                ownership.scope,
                budget=budget,
            )
            return
        if reservation_scope is not None and _path_lexists(reservation_scope):
            metadata = reservation_scope.lstat()
            if (
                not _owned_directory_metadata_valid(
                    metadata,
                    owner_uid=self._owner_uid,
                )
                or metadata.st_dev != ownership.scope_device
                or metadata.st_ino != ownership.scope_inode
                or list(reservation_scope.iterdir())
            ):
                raise ProbeConnectGuardError("probe_guard_ownership_invalid")
            reservation_scope.rmdir()
            _fsync_directory(self._pin_root)
        self._remove_receipt(receipt)

    def _cleanup_promotion_temps(self) -> None:
        try:
            entries = list(self._ownership_root.iterdir())
        except OSError:
            raise ProbeConnectGuardError("probe_guard_ownership_invalid") from None
        reservation_pattern = re.compile(
            r"\.([0-9a-f]{32})\.([0-9a-f]{32})\.reserve"
        )
        for entry in entries:
            if reservation_pattern.fullmatch(entry.name) is None:
                continue
            metadata = entry.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != self._owner_uid
                or metadata.st_nlink not in {1, 2}
                or metadata.st_mode & 0o177
                or metadata.st_size > 2_048
            ):
                raise ProbeConnectGuardError("probe_guard_ownership_invalid")
            entry.unlink()
            _fsync_directory(self._ownership_root)
        entries = list(self._ownership_root.iterdir())
        pattern = re.compile(r"\.([0-9a-f]{32})\.([0-9a-f]{32})\.next")
        for entry in entries:
            match = pattern.fullmatch(entry.name)
            if match is None:
                continue
            receipt = self._ownership_root / f"{match.group(1)}.json"
            ownership = self._ownership_from_receipt(receipt)
            metadata = entry.lstat()
            if (
                ownership.phase not in {0, 1, 2}
                or ownership.scope.request_id.hex != match.group(1)
                or ownership.receipt_version != 3
                or ownership.reservation_nonce != match.group(2)
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != self._owner_uid
                or metadata.st_nlink != 1
                or metadata.st_mode & 0o177
                or metadata.st_size > 2_048
            ):
                raise ProbeConnectGuardError("probe_guard_ownership_invalid")
            entry.unlink()
            _fsync_directory(self._ownership_root)

    def _ensure_coordinator_file(self) -> None:
        flags = os.O_RDWR | os.O_CLOEXEC | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = -1
        try:
            descriptor = os.open(self._coordinator_path, flags, 0o600)
            metadata = os.fstat(descriptor)
            if not _coordinator_metadata_valid(metadata, owner_uid=self._owner_uid):
                raise ProbeConnectGuardError("probe_guard_ownership_invalid")
            _fsync_directory(self._ownership_root)
        except OSError:
            raise ProbeConnectGuardError("probe_guard_ownership_invalid") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _acquire_coordinator(
        self,
        *,
        shared: bool,
        budget: _CommandBudget,
    ) -> int:
        flags = os.O_RDWR | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = -1
        try:
            descriptor = os.open(self._coordinator_path, flags)
            if not _coordinator_metadata_valid(
                os.fstat(descriptor),
                owner_uid=self._owner_uid,
            ):
                raise ProbeConnectGuardError("probe_guard_ownership_invalid")
            operation = fcntl.LOCK_SH if shared else fcntl.LOCK_EX
            while True:
                try:
                    fcntl.flock(descriptor, operation | fcntl.LOCK_NB)
                    result = descriptor
                    descriptor = -1
                    return result
                except BlockingIOError:
                    remaining = budget.remaining()
                    time.sleep(min(0.01, remaining))
        except OSError:
            raise ProbeConnectGuardError("probe_guard_ownership_invalid") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _remember_scope_coordinator(
        self,
        scope: ProbeConnectGuardScope,
        descriptor: int,
    ) -> None:
        with self._scope_lock_guard:
            if scope.request_id in self._scope_locks:
                raise ProbeConnectGuardError("probe_guard_state_invalid")
            self._scope_locks[scope.request_id] = descriptor

    def _scope_coordinator(self, scope: ProbeConnectGuardScope) -> int | None:
        with self._scope_lock_guard:
            return self._scope_locks.get(scope.request_id)

    def _forget_scope_coordinator(self, scope: ProbeConnectGuardScope) -> None:
        with self._scope_lock_guard:
            descriptor = self._scope_locks.pop(scope.request_id, None)
        if descriptor is not None:
            os.close(descriptor)

    def _command(self, *arguments: str, budget: _CommandBudget) -> str:
        try:
            if self._run is not None:
                return self._run(
                    (str(self._bpftool), *arguments),
                    timeout_seconds=budget.remaining(),
                )
            return self._run_verified_command(
                arguments,
                timeout_seconds=budget.remaining(),
            )
        except BaseException as error:
            if not isinstance(error, Exception):
                raise
            raise ProbeConnectGuardError("probe_guard_kernel_operation_failed") from None

    def _install_command(
        self,
        stage: str,
        *arguments: str,
        budget: _CommandBudget,
    ) -> str:
        try:
            return self._command(*arguments, budget=budget)
        except Exception:
            _LOGGER.warning("probe guard install failure: %s", stage)
            raise

    def _run_verified_command(
        self,
        arguments: tuple[str, ...],
        *,
        timeout_seconds: float,
    ) -> str:
        descriptors: list[int] = []
        try:
            bpftool_descriptor = _open_trusted_path(
                self._bpftool,
                owner_uid=self._owner_uid,
                executable=True,
                expected_sha256=self._identity.bpftool_sha256,
            )
            descriptors.append(bpftool_descriptor)
            object_descriptor = _open_trusted_path(
                self._object,
                owner_uid=self._owner_uid,
                executable=False,
                expected_sha256=self._identity.object_sha256,
            )
            descriptors.append(object_descriptor)
            bpftool_fd_path = _descriptor_path(
                bpftool_descriptor,
                fallback=self._bpftool,
            )
            object_fd_path = _descriptor_path(
                object_descriptor,
                fallback=self._object,
            )
            bound_arguments = tuple(
                object_fd_path if value == str(self._object) else value
                for value in arguments
            )
            result = _run_command(
                (bpftool_fd_path, *bound_arguments),
                timeout_seconds=timeout_seconds,
                pass_fds=(
                    *self._root_descriptors,
                    bpftool_descriptor,
                    object_descriptor,
                ),
            )
        except BaseException as primary_error:
            cleanup_errors = _close_descriptors(descriptors)
            if cleanup_errors and (
                not isinstance(primary_error, Exception)
                or any(not isinstance(error, Exception) for error in cleanup_errors)
            ):
                raise BaseExceptionGroup(
                    "probe guard artifact command cleanup was interrupted",
                    [primary_error, *cleanup_errors],
                ) from None
            if cleanup_errors:
                raise ProbeConnectGuardError(
                    "probe_guard_command_cleanup_failed"
                ) from None
            raise
        cleanup_errors = _close_descriptors(descriptors)
        if cleanup_errors:
            if any(not isinstance(error, Exception) for error in cleanup_errors):
                raise BaseExceptionGroup(
                    "probe guard artifact descriptor cleanup was interrupted",
                    cleanup_errors,
                ) from None
            raise ProbeConnectGuardError("probe_guard_command_cleanup_failed")
        return result

    def _json_command(self, *arguments: str, budget: _CommandBudget) -> object:
        raw = self._command(*arguments, budget=budget)
        try:
            return json.loads(raw)
        except (UnicodeError, json.JSONDecodeError):
            raise ProbeConnectGuardError("probe_guard_readback_invalid") from None

    def _program_id(
        self,
        path: Path,
        *,
        expected_tag: str,
        expected_map_id: int | None,
        budget: _CommandBudget,
    ) -> int:
        raw = self._json_command(
            "-j",
            "prog",
            "show",
            "pinned",
            str(path),
            budget=budget,
        )
        item = _one_json_object(raw)
        program_id = item.get("id")
        map_ids = item.get("map_ids")
        if (
            item.get("type") != "cgroup_sock_addr"
            or item.get("tag") != expected_tag
            or isinstance(program_id, bool)
            or not isinstance(program_id, int)
            or program_id < 1
            or not isinstance(map_ids, list)
            or any(isinstance(map_id, bool) or not isinstance(map_id, int) for map_id in map_ids)
            or (expected_map_id is not None and map_ids != [expected_map_id])
        ):
            raise ProbeConnectGuardError("probe_guard_readback_invalid")
        return program_id

    def _require_artifact_identity(self) -> None:
        _trusted_path(
            self._bpftool,
            owner_uid=self._owner_uid,
            executable=True,
            expected_sha256=self._identity.bpftool_sha256,
        )
        _trusted_path(
            self._object,
            owner_uid=self._owner_uid,
            executable=False,
            expected_sha256=self._identity.object_sha256,
        )

    def _attachments(
        self,
        cgroup_path: Path,
        *,
        budget: _CommandBudget,
    ) -> set[tuple[int, str]]:
        encoded = self._command(
            "-j",
            "cgroup",
            "show",
            str(cgroup_path),
            budget=budget,
        )
        if not encoded.strip():
            return set()
        try:
            raw = json.loads(encoded)
        except (UnicodeError, json.JSONDecodeError):
            raise ProbeConnectGuardError("probe_guard_readback_invalid") from None
        if not isinstance(raw, list):
            raise ProbeConnectGuardError("probe_guard_readback_invalid")
        result: set[tuple[int, str]] = set()
        for item in raw:
            if not isinstance(item, dict):
                raise ProbeConnectGuardError("probe_guard_readback_invalid")
            program_id = item.get("id")
            attach_type = item.get("attach_type")
            if (
                isinstance(program_id, bool)
                or not isinstance(program_id, int)
                or program_id < 1
                or not isinstance(attach_type, str)
                or (program_id, attach_type) in result
            ):
                raise ProbeConnectGuardError("probe_guard_readback_invalid")
            result.add((program_id, attach_type))
        return result

    def _require_exact_pin_inventory(self, paths: _GuardPaths) -> None:
        self._require_exact_partial_inventory(paths)
        if set(paths.programs.iterdir()) != {paths.ipv4, paths.ipv6} or set(
            paths.maps.iterdir()
        ) != {paths.target_map}:
            raise ProbeConnectGuardError("probe_guard_readback_invalid")

    def _require_exact_partial_inventory(self, paths: _GuardPaths) -> None:
        try:
            if not _owned_directory_valid(paths.scope, owner_uid=self._owner_uid):
                raise ProbeConnectGuardError("probe_guard_ownership_invalid")
            root_entries = set(paths.scope.iterdir())
            if not root_entries.issubset({paths.programs, paths.maps}):
                raise ProbeConnectGuardError("probe_guard_ownership_invalid")
            for directory, allowed in (
                (paths.programs, {paths.ipv4, paths.ipv6}),
                (paths.maps, {paths.target_map}),
            ):
                if directory.exists():
                    if not _owned_directory_valid(
                        directory,
                        owner_uid=self._owner_uid,
                    ):
                        raise ProbeConnectGuardError("probe_guard_ownership_invalid")
                    entries = set(directory.iterdir())
                    if not entries.issubset(allowed) or any(
                        not _owned_pin_valid(entry, owner_uid=self._owner_uid)
                        for entry in entries
                    ):
                        raise ProbeConnectGuardError("probe_guard_ownership_invalid")
        except OSError:
            raise ProbeConnectGuardError("probe_guard_ownership_invalid") from None


@dataclass(frozen=True, slots=True)
class _GuardPaths:
    scope: Path
    programs: Path
    maps: Path
    ipv4: Path
    ipv6: Path
    target_map: Path
    receipt: Path


@dataclass(frozen=True, slots=True)
class _GuardOwnership:
    scope: ProbeConnectGuardScope
    phase: int
    scope_device: int
    scope_inode: int
    reservation_nonce: str | None
    artifact_release: _ProbeConnectGuardArtifactRelease
    receipt_version: int


def _require_reservation_nonce(ownership: _GuardOwnership) -> str:
    if ownership.receipt_version != 3 or ownership.reservation_nonce is None:
        raise ProbeConnectGuardError("probe_guard_ownership_invalid")
    return ownership.reservation_nonce


@dataclass(frozen=True, slots=True)
class _CommandBudget:
    deadline: float
    monotonic: Callable[[], float] = field(repr=False)

    @classmethod
    def start(
        cls,
        timeout_seconds: float,
        *,
        monotonic: Callable[[], float],
    ) -> _CommandBudget:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise ProbeConnectGuardError("probe_guard_timeout_invalid")
        return cls(deadline=monotonic() + timeout_seconds, monotonic=monotonic)

    def remaining(self) -> float:
        remaining = self.deadline - self.monotonic()
        if remaining <= 0:
            raise ProbeConnectGuardError("probe_guard_timeout")
        return remaining


@dataclass(slots=True)
class _SpawnedProcess:
    arguments: tuple[str, ...]
    pid: int | None = None
    stdout: _OwnedPipeReader | None = None
    stderr: _OwnedPipeReader | None = None
    returncode: int | None = None
    wait_lock: Lock = field(default_factory=Lock, repr=False)

    def poll(self) -> int | None:
        with self.wait_lock:
            if self.returncode is not None:
                return self.returncode
            if self.pid is None:
                return None
            waited_pid, status = os.waitpid(self.pid, os.WNOHANG)
            if waited_pid == 0:
                return None
            self.returncode = os.waitstatus_to_exitcode(status)
            return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            returncode = self.poll()
            if returncode is not None:
                return returncode
            if deadline is not None and deadline - time.monotonic() <= 0:
                assert timeout is not None
                raise subprocess.TimeoutExpired(self.arguments, timeout)
            time.sleep(
                0.01
                if deadline is None
                else min(0.01, max(0.0, deadline - time.monotonic()))
            )

    def terminate(self) -> None:
        if self.pid is None:
            raise ProcessLookupError
        os.kill(self.pid, signal.SIGTERM)

    def kill(self) -> None:
        if self.pid is None:
            raise ProcessLookupError
        os.kill(self.pid, signal.SIGKILL)


@dataclass(slots=True)
class _ProcessOwner:
    process: _SpawnedProcess | None = None


class _OwnedSpawnPipe:
    """Object-owned local channel safe across allocation and close interruption."""

    def __init__(self) -> None:
        self._read_socket: socket.socket | None = None
        self._write_socket: socket.socket | None = None
        self._read_transferred = False

    def acquire(self) -> None:
        if self._read_socket is not None or self._write_socket is not None:
            raise ProbeConnectGuardError("probe_guard_kernel_operation_failed")
        self._read_socket, self._write_socket = socket.socketpair(
            socket.AF_UNIX,
            socket.SOCK_STREAM,
        )

    @property
    def read_descriptor(self) -> int:
        if self._read_socket is None:
            raise ProbeConnectGuardError("probe_guard_kernel_operation_failed")
        return self._read_socket.fileno()

    @property
    def write_descriptor(self) -> int:
        if self._write_socket is None:
            raise ProbeConnectGuardError("probe_guard_kernel_operation_failed")
        return self._write_socket.fileno()

    def close_read(self) -> None:
        self._close(0)

    def close_write(self) -> None:
        self._close(1)

    def transfer_read(self) -> None:
        self._read_transferred = True

    def close_transferred_read(self) -> None:
        self._read_transferred = False
        self._close(0)

    def close(self) -> list[BaseException]:
        errors: list[BaseException] = []
        indexes = (1,) if self._read_transferred else (1, 0)
        for index in indexes:
            try:
                self._close(index)
            except BaseException as error:
                errors.append(_sanitize_cleanup_error(error))
        return errors

    def _close(self, index: int) -> None:
        endpoint = self._read_socket if index == 0 else self._write_socket
        if endpoint is None:
            return
        endpoint.close()
        if index == 0:
            self._read_socket = None
        else:
            self._write_socket = None


class _OwnedPipeReader:
    def __init__(self, pipe: _OwnedSpawnPipe) -> None:
        self._pipe = pipe

    def fileno(self) -> int:
        return self._pipe.read_descriptor

    def close(self) -> None:
        self._pipe.close_transferred_read()


class _OwnedThreadChildInventory:
    """Pre-spawn ownership of the calling thread's Linux child inventory."""

    def __init__(self) -> None:
        self._stream: BinaryIO | None = None

    def acquire(self) -> None:
        if self._stream is not None:
            raise ProbeConnectGuardError("probe_guard_kernel_operation_failed")
        if sys.platform != "linux":
            return
        try:
            self._stream = Path("/proc/thread-self/children").open(  # noqa: SIM115
                "rb",
                buffering=0,
            )
        except OSError:
            raise ProbeConnectGuardError(
                "probe_guard_kernel_operation_failed"
            ) from None

    def snapshot(self, *, deadline: float | None = None) -> set[int] | None:
        if self._stream is None:
            return None
        while True:
            try:
                payload = os.pread(self._stream.fileno(), 8_193, 0)
                break
            except OSError:
                if deadline is None:
                    raise ProbeConnectGuardError(
                        "probe_guard_kernel_operation_failed"
                    ) from None
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ProbeConnectGuardError(
                        "probe_guard_kernel_operation_failed"
                    ) from None
                time.sleep(min(0.01, remaining))
        if len(payload) > 8_192:
            raise ProbeConnectGuardError("probe_guard_kernel_operation_failed")
        try:
            child_pids = {
                int(item) for item in payload.decode("ascii").split()
            }
        except (UnicodeDecodeError, ValueError):
            raise ProbeConnectGuardError(
                "probe_guard_kernel_operation_failed"
            ) from None
        if any(child_pid <= 0 for child_pid in child_pids):
            raise ProbeConnectGuardError("probe_guard_kernel_operation_failed")
        return child_pids

    def close(self) -> None:
        if self._stream is None:
            return
        self._stream.close()
        self._stream = None


class ProbeConnectGuardManager:
    """Own install/read-back/release for exact per-probe cgroup guards."""

    _CLEANUP_RETRY_MAX_SCOPES = 8

    def __init__(
        self,
        *,
        backend: ProbeConnectGuardBackend,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._backend = backend
        self._active: dict[str, _GuardRecord] = {}
        self._lock = Lock()
        self._cleanup_retry_lock = Lock()
        self._cleanup_attempt_sequence = 0
        self._reconcile_in_progress = False
        self._reconcile_ready = False
        self._monotonic = monotonic

    def install(
        self,
        *,
        request_id: UUID,
        unit_name: str,
        cgroup_path: Path,
        target: ProbeConnectGuardTarget,
        timeout_seconds: float,
    ) -> ProbeConnectGuardLease:
        lease = self._install(
            request_id=request_id,
            unit_name=unit_name,
            cgroup_path=cgroup_path,
            target=target,
            timeout_seconds=timeout_seconds,
            ownership=None,
        )
        assert lease is not None
        return lease

    def install_owned(
        self,
        *,
        request_id: UUID,
        unit_name: str,
        cgroup_path: Path,
        target: ProbeConnectGuardTarget,
        timeout_seconds: float,
        ownership: OwnershipLedger[ProbeConnectGuardLease],
    ) -> None:
        """Publish a verified guard lease or remove it before failure returns."""

        _ = self._install(
            request_id=request_id,
            unit_name=unit_name,
            cgroup_path=cgroup_path,
            target=target,
            timeout_seconds=timeout_seconds,
            ownership=ownership,
        )

    def _install(
        self,
        *,
        request_id: UUID,
        unit_name: str,
        cgroup_path: Path,
        target: ProbeConnectGuardTarget,
        timeout_seconds: float,
        ownership: OwnershipLedger[ProbeConnectGuardLease] | None,
    ) -> ProbeConnectGuardLease | None:
        self._validate_scope(
            request_id=request_id,
            unit_name=unit_name,
            cgroup_path=cgroup_path,
            target=target,
            timeout_seconds=timeout_seconds,
        )
        scope = ProbeConnectGuardScope(
            request_id=request_id,
            unit_name=unit_name,
            cgroup_path=cgroup_path,
            target=target,
        )
        record = _GuardRecord(scope=scope)
        deadline = self._monotonic() + timeout_seconds
        with self._lock:
            reconcile_required = not self._reconcile_ready
            reconcile_busy = self._reconcile_in_progress
        if reconcile_busy:
            raise ProbeConnectGuardError("probe_guard_reconcile_busy")
        if reconcile_required:
            remaining = self.reconcile_startup(
                timeout_seconds=self._remaining(deadline)
            )
            if remaining:
                raise ProbeConnectGuardError("probe_guard_reconcile_required")
        operation_acquired = False
        published_owned = False
        publication_uncertain = False
        try:
            record.operation_lock.acquire()
            operation_acquired = True
            with self._lock:
                if self._reconcile_in_progress:
                    raise ProbeConnectGuardError("probe_guard_reconcile_busy")
                if not self._reconcile_ready:
                    raise ProbeConnectGuardError("probe_guard_reconcile_required")
                if unit_name in self._active:
                    raise ProbeConnectGuardError("probe_guard_already_active")
                self._active[unit_name] = record
            try:
                self._backend.install(
                    scope,
                    timeout_seconds=self._remaining(deadline),
                )
                self._backend.verify(
                    scope,
                    timeout_seconds=self._remaining(deadline),
                )
                lease = ProbeConnectGuardLease(
                    request_id=request_id,
                    unit_name=unit_name,
                    target=target,
                )
                with self._lock:
                    if (
                        self._active.get(unit_name) is not record
                        or record.state != "installing"
                    ):
                        raise ProbeConnectGuardError("probe_guard_state_invalid")
                    record.lease = lease
                    record.state = "active"
                if ownership is None:
                    return lease
                record.ownership = ownership
                try:
                    publication_uncertain = True
                    ownership.publish(lease)
                except BaseException as publish_error:
                    try:
                        published_owned = ownership.owns(lease)
                    except BaseException as ownership_error:
                        publication_uncertain = True
                        raise BaseExceptionGroup(
                            "probe guard lease publication ownership is uncertain",
                            [
                                _sanitize_cleanup_error(publish_error),
                                _sanitize_cleanup_error(ownership_error),
                            ],
                        ) from None
                    publication_uncertain = published_owned
                    raise
                published_owned = True
                publication_uncertain = False
                return None
            except BaseException as primary_error:
                if published_owned or publication_uncertain:
                    raise
                self._cleanup_failed_install(
                    record,
                    deadline=deadline,
                    cleanup_timeout_seconds=timeout_seconds,
                    primary_error=primary_error,
                )
        finally:
            if operation_acquired:
                self._release_operation(
                    record,
                    preserve_active=(
                        ownership is None or published_owned
                    ),
                )

    def release(
        self,
        lease: ProbeConnectGuardLease,
        *,
        timeout_seconds: float,
    ) -> None:
        self._release(
            lease,
            timeout_seconds=timeout_seconds,
            ownership=None,
        )

    def ensure_released(
        self,
        lease: ProbeConnectGuardLease,
        *,
        timeout_seconds: float,
        ownership: OwnershipLedger[ProbeConnectGuardLease],
    ) -> None:
        """Remove one exact owned guard and release its caller ledger slot."""

        self._release(
            lease,
            timeout_seconds=timeout_seconds,
            ownership=ownership,
        )

    def _release(
        self,
        lease: ProbeConnectGuardLease,
        *,
        timeout_seconds: float,
        ownership: OwnershipLedger[ProbeConnectGuardLease] | None,
    ) -> None:
        if not isinstance(lease, ProbeConnectGuardLease):
            raise ProbeConnectGuardError("probe_guard_lease_invalid")
        self._validate_timeout(timeout_seconds)
        with self._lock:
            record = self._active.get(lease.unit_name)
            if (
                record is None
                or record.lease is not lease
                or (
                    record.state != "active"
                    and not (
                        ownership is not None
                        and record.ownership is ownership
                        and record.state in {"cleanup_pending", "released"}
                    )
                )
            ):
                raise ProbeConnectGuardError("probe_guard_lease_invalid")
        operation_acquired = False
        try:
            if not record.operation_lock.acquire(blocking=False):
                raise ProbeConnectGuardError("probe_guard_cleanup_in_progress")
            operation_acquired = True
            with self._lock:
                if (
                    self._active.get(lease.unit_name) is not record
                    or record.lease is not lease
                    or (
                        record.state != "active"
                        and not (
                            ownership is not None
                            and record.ownership is ownership
                            and record.state in {"cleanup_pending", "released"}
                        )
                    )
                ):
                    raise ProbeConnectGuardError("probe_guard_lease_invalid")
                already_released = record.state == "released"
                if not already_released:
                    record.state = "cleaning"
            if already_released:
                assert ownership is not None
                self._release_owned_record(record, lease, ownership)
                return
            try:
                self._backend.remove(record.scope, timeout_seconds=timeout_seconds)
            except BaseException as error:
                if isinstance(error, Exception):
                    raise ProbeConnectGuardError("probe_guard_cleanup_pending") from None
                raise BaseExceptionGroup(
                    "probe guard release was interrupted and cleanup remains pending",
                    [error, ProbeConnectGuardError("probe_guard_cleanup_pending")],
                ) from None
            with self._lock:
                if self._active.get(lease.unit_name) is not record:
                    raise ProbeConnectGuardError("probe_guard_state_invalid")
                if ownership is None:
                    del self._active[lease.unit_name]
                else:
                    record.state = "released"
            if ownership is not None:
                self._release_owned_record(record, lease, ownership)
        finally:
            if operation_acquired:
                self._release_operation(record)

    def _release_owned_record(
        self,
        record: _GuardRecord,
        lease: ProbeConnectGuardLease,
        ownership: OwnershipLedger[ProbeConnectGuardLease],
    ) -> None:
        try:
            ownership.release(lease)
        except BaseException:
            if not ownership.owns(lease):
                self._remove_active_record(record)
            raise
        self._remove_active_record(record)

    def _remove_active_record(self, record: _GuardRecord) -> None:
        with self._lock:
            if self._active.get(record.scope.unit_name) is not record:
                raise ProbeConnectGuardError("probe_guard_state_invalid")
            del self._active[record.scope.unit_name]

    def retry_pending_cleanup(self, *, timeout_seconds: float) -> int:
        """Retry cleanup for every currently unresolved owned scope."""

        self._validate_timeout(timeout_seconds)
        if not self._cleanup_retry_lock.acquire(blocking=False):
            return self._pending_count()
        try:
            deadline = self._monotonic() + timeout_seconds
            with self._lock:
                pending = sorted(
                    (
                        record
                        for record in self._active.values()
                        if record.state in {"cleanup_pending", "released"}
                    ),
                    key=lambda record: record.cleanup_attempt_order,
                )[: self._CLEANUP_RETRY_MAX_SCOPES]
            interruptions: list[BaseException] = []
            for record in pending:
                try:
                    remaining = self._remaining(deadline)
                except ProbeConnectGuardError:
                    break
                operation_acquired = False
                try:
                    if not record.operation_lock.acquire(blocking=False):
                        continue
                    operation_acquired = True
                    with self._lock:
                        if (
                            self._active.get(record.scope.unit_name) is not record
                            or record.state not in {"cleanup_pending", "released"}
                        ):
                            continue
                        if record.ownership is not None and record.lease is not None:
                            try:
                                caller_owns = record.ownership.owns(record.lease)
                            except BaseException as error:
                                if not isinstance(error, Exception):
                                    interruptions.append(error)
                                continue
                            if caller_owns:
                                continue
                        if record.state == "released":
                            del self._active[record.scope.unit_name]
                            continue
                        record.state = "cleaning"
                    try:
                        self._backend.remove(
                            record.scope,
                            timeout_seconds=remaining,
                        )
                    except BaseException as error:
                        if not isinstance(error, Exception):
                            interruptions.append(error)
                    else:
                        with self._lock:
                            if self._active.get(record.scope.unit_name) is record:
                                del self._active[record.scope.unit_name]
                finally:
                    if operation_acquired:
                        self._release_operation(record)
            if interruptions:
                raise BaseExceptionGroup(
                    "probe guard cleanup retry was interrupted",
                    interruptions,
                ) from None
            return self._pending_count()
        finally:
            self._cleanup_retry_lock.release()

    def reconcile_startup(self, *, timeout_seconds: float) -> int:
        """Collect receipt-proven crash residue before accepting new probes."""

        self._validate_timeout(timeout_seconds)
        with self._lock:
            if self._active or self._reconcile_in_progress:
                raise ProbeConnectGuardError("probe_guard_reconcile_busy")
            self._reconcile_in_progress = True
            self._reconcile_ready = False
        try:
            remaining = self._backend.reconcile_owned(
                timeout_seconds=timeout_seconds
            )
        except BaseException:
            with self._lock:
                self._reconcile_in_progress = False
            raise
        with self._lock:
            self._reconcile_in_progress = False
            self._reconcile_ready = remaining == 0
        return remaining

    def _cleanup_failed_install(
        self,
        record: _GuardRecord,
        *,
        deadline: float,
        cleanup_timeout_seconds: float,
        primary_error: BaseException,
    ) -> NoReturn:
        if isinstance(primary_error, ProbeConnectGuardInstallReconcileRequired):
            with self._lock:
                if self._active.get(record.scope.unit_name) is record:
                    del self._active[record.scope.unit_name]
                self._reconcile_ready = False
            if primary_error.interruption is not None:
                raise primary_error.interruption from None
            try:
                remaining = self.reconcile_startup(
                    timeout_seconds=self._remaining(deadline)
                )
            except BaseException as error:
                if not isinstance(error, Exception):
                    raise
                raise ProbeConnectGuardError(
                    "probe_guard_reconcile_required"
                ) from None
            if remaining:
                raise ProbeConnectGuardError(
                    "probe_guard_reconcile_required"
                ) from None
            raise ProbeConnectGuardError("probe_guard_already_active") from None
        if isinstance(primary_error, ProbeConnectGuardInstallRejectedInterruption):
            with self._lock:
                if self._active.get(record.scope.unit_name) is record:
                    del self._active[record.scope.unit_name]
            raise primary_error.interruption from None
        if isinstance(primary_error, ProbeConnectGuardInstallRejected):
            with self._lock:
                if self._active.get(record.scope.unit_name) is record:
                    del self._active[record.scope.unit_name]
            raise ProbeConnectGuardError(str(primary_error)) from None
        with self._lock:
            if self._active.get(record.scope.unit_name) is record:
                record.state = "cleaning"
        try:
            self._backend.remove(
                record.scope,
                timeout_seconds=cleanup_timeout_seconds,
            )
        except BaseException as cleanup_error:
            with self._lock:
                if self._active.get(record.scope.unit_name) is record:
                    self._mark_cleanup_pending_locked(record)
            if isinstance(primary_error, Exception) and isinstance(
                cleanup_error, Exception
            ):
                raise ProbeConnectGuardError("probe_guard_cleanup_pending") from None
            raise BaseExceptionGroup(
                "probe guard install was interrupted and cleanup remains pending",
                [
                    (
                        ProbeConnectGuardError("probe_guard_install_failed")
                        if isinstance(primary_error, Exception)
                        else primary_error
                    ),
                    _sanitize_cleanup_error(cleanup_error),
                    ProbeConnectGuardError("probe_guard_cleanup_pending"),
                ],
            ) from None
        with self._lock:
            if self._active.get(record.scope.unit_name) is record:
                del self._active[record.scope.unit_name]
        if isinstance(primary_error, Exception):
            raise ProbeConnectGuardError("probe_guard_install_failed") from None
        raise primary_error from None

    def _release_operation(
        self,
        record: _GuardRecord,
        *,
        preserve_active: bool = False,
    ) -> None:
        try:
            with self._lock:
                if self._active.get(record.scope.unit_name) is record and (
                    record.state in {"installing", "cleaning"}
                    or (record.state == "active" and not preserve_active)
                ):
                    self._mark_cleanup_pending_locked(record)
        finally:
            record.operation_lock.release()

    def _mark_cleanup_pending_locked(self, record: _GuardRecord) -> None:
        self._cleanup_attempt_sequence += 1
        record.cleanup_attempt_order = self._cleanup_attempt_sequence
        record.state = "cleanup_pending"

    def _pending_count(self) -> int:
        with self._lock:
            return sum(
                record.state in {"cleanup_pending", "released"}
                for record in self._active.values()
            )

    def _remaining(self, deadline: float) -> float:
        remaining = deadline - self._monotonic()
        if remaining <= 0:
            raise ProbeConnectGuardError("probe_guard_timeout")
        return remaining

    @staticmethod
    def _validate_scope(
        *,
        request_id: UUID,
        unit_name: str,
        cgroup_path: Path,
        target: ProbeConnectGuardTarget,
        timeout_seconds: float,
    ) -> None:
        ProbeConnectGuardManager._validate_timeout(timeout_seconds)
        expected_unit = (
            f"rtsp-probe-{request_id.hex}.service"
            if isinstance(request_id, UUID) and request_id.version == 4
            else ""
        )
        try:
            cgroup_valid = (
                isinstance(cgroup_path, Path)
                and cgroup_path.is_absolute()
                and cgroup_path.is_dir()
                and not cgroup_path.is_symlink()
                and cgroup_path.name == unit_name
            )
        except OSError:
            cgroup_valid = False
        if (
            not expected_unit
            or unit_name != expected_unit
            or not cgroup_valid
            or not isinstance(target, ProbeConnectGuardTarget)
        ):
            raise ProbeConnectGuardError("probe_guard_scope_invalid")

    @staticmethod
    def _validate_timeout(timeout_seconds: float) -> None:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= 60
        ):
            raise ProbeConnectGuardError("probe_guard_timeout_invalid")


def _sanitize_cleanup_error(error: BaseException) -> BaseException:
    if isinstance(error, Exception):
        return ProbeConnectGuardError("probe_guard_cleanup_failed")
    return error


def _receipt_bytes(
    scope: ProbeConnectGuardScope,
    *,
    object_sha256: str,
    artifact_release_id: str,
    phase: int,
    scope_device: int,
    scope_inode: int,
    reservation_nonce: str,
) -> bytes:
    return (
        json.dumps(
            {
                "address": str(scope.target.address),
                "artifact_release_id": artifact_release_id,
                "cgroup_path": str(scope.cgroup_path),
                "object_sha256": object_sha256,
                "phase": phase,
                "port": scope.target.port,
                "request_id": str(scope.request_id),
                "reservation_nonce": reservation_nonce,
                "scope_device": f"{scope_device:020d}",
                "scope_inode": f"{scope_inode:020d}",
                "unit_name": scope.unit_name,
                "version": 3,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _receipt_bytes_v2(
    scope: ProbeConnectGuardScope,
    *,
    object_sha256: str,
    artifact_release_id: str,
    phase: int,
    scope_device: int,
    scope_inode: int,
) -> bytes:
    """Serialize the cleanup-only receipt emitted before nonce reservations."""

    return (
        json.dumps(
            {
                "address": str(scope.target.address),
                "artifact_release_id": artifact_release_id,
                "cgroup_path": str(scope.cgroup_path),
                "object_sha256": object_sha256,
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


def _linux_architecture(machine: str) -> str:
    aliases = {
        "amd64": "amd64",
        "x86_64": "amd64",
        "arm64": "arm64",
        "aarch64": "arm64",
    }
    try:
        return aliases[machine.strip().lower()]
    except (AttributeError, KeyError):
        raise ProbeConnectGuardError(
            "probe_guard_artifact_identity_invalid"
        ) from None


def _load_packaged_artifact_catalog() -> _ProbeConnectGuardArtifactCatalog:
    try:
        resource = files("rtsp_proxy").joinpath(
            "artifacts",
            "probe_connect_guard.json",
        )
        payload = resource.read_bytes()
    except (OSError, AttributeError):
        raise ProbeConnectGuardError(
            "probe_guard_artifact_identity_invalid"
        ) from None
    return _parse_artifact_catalog(payload)


def _parse_artifact_catalog(payload: bytes) -> _ProbeConnectGuardArtifactCatalog:
    try:
        decoded = json.loads(payload)
        if (
            not isinstance(decoded, dict)
            or set(decoded) != {"current_release_id", "releases", "schema_version"}
            or decoded["schema_version"] != 1
            or not isinstance(decoded["current_release_id"], str)
            or not re.fullmatch(
                r"[0-9A-Za-z][0-9A-Za-z._-]{0,63}",
                decoded["current_release_id"],
            )
            or not isinstance(decoded["releases"], dict)
            or not decoded["releases"]
        ):
            raise ValueError
        releases: list[_ProbeConnectGuardArtifactRelease] = []
        for release_id, raw_release in decoded["releases"].items():
            if (
                not isinstance(release_id, str)
                or not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z._-]{0,63}", release_id)
                or not isinstance(raw_release, dict)
                or set(raw_release)
                != {
                    "activation_compatible",
                    "architectures",
                    "cleanup_compatible",
                }
                or not isinstance(raw_release["activation_compatible"], bool)
                or not isinstance(raw_release["cleanup_compatible"], bool)
                or not isinstance(raw_release["architectures"], dict)
                or not raw_release["architectures"]
            ):
                raise ValueError
            for architecture, raw_identity in raw_release["architectures"].items():
                if (
                    architecture not in {"amd64", "arm64"}
                    or not isinstance(raw_identity, dict)
                    or set(raw_identity)
                    != {
                        "bpftool_sha256",
                        "ipv4_program_tag",
                        "ipv6_program_tag",
                        "object_sha256",
                    }
                ):
                    raise ValueError
                tool_digests = raw_identity["bpftool_sha256"]
                if (
                    not isinstance(tool_digests, list)
                    or not tool_digests
                    or len(tool_digests) != len(set(tool_digests))
                    or any(
                        not isinstance(digest, str)
                        or not re.fullmatch(r"[0-9a-f]{64}", digest)
                        for digest in tool_digests
                    )
                    or not isinstance(raw_identity["object_sha256"], str)
                    or not re.fullmatch(
                        r"[0-9a-f]{64}",
                        raw_identity["object_sha256"],
                    )
                    or not isinstance(raw_identity["ipv4_program_tag"], str)
                    or not re.fullmatch(
                        r"[0-9a-f]{16}",
                        raw_identity["ipv4_program_tag"],
                    )
                    or not isinstance(raw_identity["ipv6_program_tag"], str)
                    or not re.fullmatch(
                        r"[0-9a-f]{16}",
                        raw_identity["ipv6_program_tag"],
                    )
                ):
                    raise ValueError
                releases.append(
                    _ProbeConnectGuardArtifactRelease(
                        release_id=release_id,
                        architecture=architecture,
                        object_sha256=raw_identity["object_sha256"],
                        ipv4_program_tag=raw_identity["ipv4_program_tag"],
                        ipv6_program_tag=raw_identity["ipv6_program_tag"],
                        bpftool_sha256=frozenset(tool_digests),
                        activation_compatible=raw_release["activation_compatible"],
                        cleanup_compatible=raw_release["cleanup_compatible"],
                    )
                )
        catalog = _ProbeConnectGuardArtifactCatalog(
            current_release_id=decoded["current_release_id"],
            releases=tuple(releases),
        )
        cleanup_release_ids = {
            release.release_id
            for release in catalog.releases
            if release.cleanup_compatible
        }
        if any(
            {
                release.architecture
                for release in catalog.releases
                if release.release_id == release_id
                and release.cleanup_compatible
            }
            != {"amd64", "arm64"}
            for release_id in cleanup_release_ids
        ):
            raise ValueError
        current_architectures = {
            release.architecture
            for release in catalog.releases
            if release.release_id == catalog.current_release_id
            and release.activation_compatible
            and release.cleanup_compatible
        }
        if current_architectures != {"amd64", "arm64"}:
            raise ValueError
        return catalog
    except (
        UnicodeError,
        json.JSONDecodeError,
        KeyError,
        TypeError,
        ValueError,
    ):
        raise ProbeConnectGuardError(
            "probe_guard_artifact_identity_invalid"
        ) from None


def _test_artifact_catalog(
    identity: ProbeConnectGuardArtifactIdentity,
    *,
    architecture: str,
) -> _ProbeConnectGuardArtifactCatalog:
    return _ProbeConnectGuardArtifactCatalog(
        current_release_id="test-fixture",
        releases=(
            _ProbeConnectGuardArtifactRelease(
                release_id="test-fixture",
                architecture=architecture,
                object_sha256=identity.object_sha256,
                ipv4_program_tag=identity.ipv4_program_tag,
                ipv6_program_tag=identity.ipv6_program_tag,
                bpftool_sha256=frozenset({identity.bpftool_sha256}),
                activation_compatible=True,
                cleanup_compatible=True,
            ),
        ),
    )


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _trusted_path(
    path: Path,
    *,
    owner_uid: int,
    executable: bool,
    expected_sha256: str,
) -> Path:
    descriptor = -1
    try:
        descriptor = _open_trusted_path(
            path,
            owner_uid=owner_uid,
            executable=executable,
            expected_sha256=expected_sha256,
        )
    except ProbeConnectGuardError:
        raise
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        raise ProbeConnectGuardError("probe_guard_tool_invalid") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return path


def _open_trusted_path(
    path: Path,
    *,
    owner_uid: int,
    executable: bool,
    expected_sha256: str,
) -> int:
    if not isinstance(path, Path) or not path.is_absolute() or path.name in {"", ".", ".."}:
        raise ProbeConnectGuardError("probe_guard_tool_invalid")
    directory_descriptor = -1
    descriptor = -1
    try:
        directory_flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_DIRECTORY"):
            directory_flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            directory_flags |= os.O_NOFOLLOW
        directory_descriptor = os.open(path.anchor, directory_flags)
        for component in path.parts[1:-1]:
            if component in {"", ".", ".."}:
                raise ProbeConnectGuardError("probe_guard_tool_invalid")
            next_descriptor = os.open(
                component,
                directory_flags,
                dir_fd=directory_descriptor,
            )
            metadata = os.fstat(next_descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                os.close(next_descriptor)
                raise ProbeConnectGuardError("probe_guard_tool_invalid")
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
        file_flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            file_flags |= os.O_NOFOLLOW
        descriptor = os.open(
            path.name,
            file_flags,
            dir_fd=directory_descriptor,
        )
        metadata = os.fstat(descriptor)
        digest = _sha256_descriptor(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != owner_uid
            or metadata.st_mode & 0o022
            or (executable and metadata.st_mode & 0o111 == 0)
            or digest != expected_sha256
        ):
            raise ProbeConnectGuardError("probe_guard_tool_invalid")
        os.lseek(descriptor, 0, os.SEEK_SET)
        result = descriptor
        descriptor = -1
        return result
    except (OSError, ValueError):
        raise ProbeConnectGuardError("probe_guard_tool_invalid") from None
    finally:
        for opened in (descriptor, directory_descriptor):
            if opened >= 0:
                os.close(opened)


def _sha256_path(path: Path) -> str:
    digest = sha256()
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        while True:
            chunk = os.read(descriptor, 65_536)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _sha256_descriptor(descriptor: int) -> str:
    digest = sha256()
    offset = 0
    while True:
        chunk = os.pread(descriptor, 65_536, offset)
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()


def _descriptor_path(descriptor: int, *, fallback: Path) -> str:
    descriptor_root = Path("/proc/self/fd")
    if descriptor_root.is_dir():
        return str(descriptor_root / str(descriptor))
    if platform.system() != "Linux":
        return str(fallback)
    raise ProbeConnectGuardError("probe_guard_tool_invalid")


def _directory_descriptor_path(descriptor: int, *, fallback: Path) -> str:
    proc_path = Path("/proc/self/fd")
    if proc_path.is_dir():
        return str(proc_path / str(descriptor))
    if platform.system() != "Linux":
        return str(fallback)
    raise ProbeConnectGuardError("probe_guard_pin_root_invalid")


def _open_trusted_directory(path: Path, *, owner_uid: int) -> int:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ProbeConnectGuardError("probe_guard_pin_root_invalid") from None
    descriptor = -1
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path.anchor, flags)
        for component in path.parts[1:]:
            if component in {"", ".", ".."}:
                raise ProbeConnectGuardError("probe_guard_pin_root_invalid")
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != owner_uid
            or metadata.st_mode & 0o022
        ):
            raise ProbeConnectGuardError("probe_guard_pin_root_invalid")
        result = descriptor
        descriptor = -1
        return result
    except (OSError, ValueError):
        raise ProbeConnectGuardError("probe_guard_pin_root_invalid") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _write_exclusive_file(path: Path, payload: bytes, *, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(path, flags, mode)
        written = 0
        while written < len(payload):
            count = os.write(descriptor, payload[written:])
            if count <= 0:
                raise OSError("file write made no progress")
            written += count
        os.fsync(descriptor)
    except OSError:
        raise ProbeConnectGuardError("probe_guard_ownership_invalid") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _rename_directory_no_replace(source: Path, destination: Path) -> None:
    if destination.exists():
        raise FileExistsError(os.fspath(destination))
    if platform.system() != "Linux":
        os.rename(source, destination)
        return
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise ProbeConnectGuardError("probe_guard_ownership_invalid")
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    if renameat2(
        -100,
        os.fsencode(source),
        -100,
        os.fsencode(destination),
        1,
    ) != 0:
        error_number = ctypes.get_errno()
        if error_number == 17:
            raise FileExistsError(os.fspath(destination))
        raise OSError(error_number, os.strerror(error_number))


def _coordinator_metadata_valid(
    metadata: os.stat_result,
    *,
    owner_uid: int,
) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == owner_uid
        and metadata.st_nlink == 1
        and metadata.st_mode & 0o177 == 0
        and metadata.st_size == 0
    )


def _close_backend_descriptors(
    root_descriptors: tuple[int, ...],
    scope_descriptors: dict[UUID, int],
) -> None:
    descriptors = [*scope_descriptors.values(), *root_descriptors]
    scope_descriptors.clear()
    for descriptor in descriptors:
        with suppress(OSError):
            os.close(descriptor)


def _owned_directory_valid(path: Path, *, owner_uid: int) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return _owned_directory_metadata_valid(metadata, owner_uid=owner_uid)


def _owned_directory_metadata_valid(
    metadata: os.stat_result,
    *,
    owner_uid: int,
) -> bool:
    return (
        not stat.S_ISLNK(metadata.st_mode)
        and stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == owner_uid
        and metadata.st_mode & 0o077 == 0
    )


def _receipt_metadata_valid(metadata: os.stat_result, *, owner_uid: int) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == owner_uid
        and metadata.st_nlink == 1
        and metadata.st_mode & 0o177 == 0
        and 0 < metadata.st_size <= 2_048
    )


def _path_lexists(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        raise ProbeConnectGuardError("probe_guard_ownership_invalid") from None
    return True


def _owned_pin_valid(path: Path, *, owner_uid: int) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return (
        not stat.S_ISLNK(metadata.st_mode)
        and stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == owner_uid
        and metadata.st_nlink == 1
        and metadata.st_mode & 0o022 == 0
    )


def _run_command(
    arguments: tuple[str, ...],
    *,
    timeout_seconds: float,
    pass_fds: tuple[int, ...] = (),
) -> str:
    owner = _ProcessOwner()
    selector: selectors.BaseSelector | None = None
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not isfinite(timeout_seconds)
        or timeout_seconds <= 0
    ):
        raise ProbeConnectGuardError("probe_guard_kernel_operation_failed")
    deadline = time.monotonic() + timeout_seconds
    try:
        try:
            _spawn_owned_process(
                owner,
                arguments,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin"},
                pass_fds=pass_fds,
                deadline=deadline,
            )
        except OSError:
            raise ProbeConnectGuardError(
                "probe_guard_kernel_operation_failed"
            ) from None
        process = owner.process
        if process is None:
            raise ProbeConnectGuardError("probe_guard_kernel_operation_failed")
        stdout = bytearray()
        stderr = bytearray()
        selector = selectors.DefaultSelector()
        if process.stdout is None or process.stderr is None:
            raise ProbeConnectGuardError("probe_guard_kernel_operation_failed")
        for stream, output in ((process.stdout, stdout), (process.stderr, stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, output)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProbeConnectGuardError("probe_guard_kernel_operation_failed")
            events = selector.select(remaining)
            if not events:
                raise ProbeConnectGuardError("probe_guard_kernel_operation_failed")
            for key, _mask in events:
                output = cast(bytearray, key.data)
                chunk = os.read(key.fd, 8_192)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if len(output) + len(chunk) > _COMMAND_OUTPUT_MAX_BYTES:
                    raise ProbeConnectGuardError("probe_guard_kernel_operation_failed")
                output.extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProbeConnectGuardError("probe_guard_kernel_operation_failed")
        returncode = process.wait(timeout=remaining)
    except BaseException as primary_error:
        cleanup_errors: list[BaseException] = []
        process = owner.process
        if process is not None:
            process_cleanup_error = _terminate_and_reap(process)
            if process_cleanup_error is not None:
                cleanup_errors.append(process_cleanup_error)
        cleanup_errors.extend(
            _close_command_resources(
                selector,
                getattr(process, "stdout", None) if process is not None else None,
                getattr(process, "stderr", None) if process is not None else None,
            )
        )
        if cleanup_errors and (
            not isinstance(primary_error, Exception)
            or any(not isinstance(error, Exception) for error in cleanup_errors)
        ):
            raise BaseExceptionGroup(
                "probe guard command was interrupted during cleanup",
                [primary_error, *cleanup_errors],
            ) from None
        if cleanup_errors:
            raise ProbeConnectGuardError(
                "probe_guard_command_cleanup_failed"
            ) from None
        if not isinstance(primary_error, Exception):
            raise
        raise ProbeConnectGuardError("probe_guard_kernel_operation_failed") from None
    process = owner.process
    assert process is not None
    cleanup_errors = _close_command_resources(
        selector,
        process.stdout,
        process.stderr,
    )
    if cleanup_errors:
        if any(not isinstance(error, Exception) for error in cleanup_errors):
            raise BaseExceptionGroup(
                "probe guard command resource cleanup was interrupted",
                cleanup_errors,
            ) from None
        raise ProbeConnectGuardError("probe_guard_command_cleanup_failed")
    if returncode != 0:
        raise ProbeConnectGuardError("probe_guard_kernel_operation_failed")
    try:
        return stdout.decode("utf-8")
    except UnicodeDecodeError:
        raise ProbeConnectGuardError("probe_guard_kernel_operation_failed") from None


def _spawn_owned_process(
    owner: _ProcessOwner,
    arguments: tuple[str, ...],
    *,
    stdin: int,
    stdout: int,
    stderr: int,
    text: bool,
    env: dict[str, str],
    pass_fds: tuple[int, ...],
    deadline: float,
) -> None:
    """Spawn with signals blocked until the kernel PID is ledger-owned."""

    if (
        stdin != subprocess.DEVNULL
        or stdout != subprocess.PIPE
        or stderr != subprocess.PIPE
        or text is not False
        or not arguments
    ):
        raise ProbeConnectGuardError("probe_guard_kernel_operation_failed")
    previous_mask: set[int | signal.Signals] | None = None
    process: _SpawnedProcess | None = None
    child_inventory = _OwnedThreadChildInventory()
    pipes = tuple(_OwnedSpawnPipe() for _index in range(4))
    stdout_pipe, stderr_pipe, pid_pipe, gate_pipe = pipes
    blocked_signals = {signal.SIGHUP, signal.SIGINT, signal.SIGTERM}
    primary_error: BaseException | None = None
    try:
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        signal.pthread_sigmask(signal.SIG_BLOCK, blocked_signals)
        child_signal_mask = tuple(int(item) for item in previous_mask)
        guarded_child_signal_mask = tuple(
            sorted({*child_signal_mask, *(int(item) for item in blocked_signals)})
        )
        for pipe in pipes:
            pipe.acquire()
        child_inventory.acquire()
        child_pids_before_spawn = child_inventory.snapshot()
        process = _SpawnedProcess(arguments=arguments)
        owner.process = process
        child_descriptors = (*pass_fds, pid_pipe.write_descriptor, gate_pipe.read_descriptor)
        occupied_descriptors = {
            0,
            1,
            2,
            *child_descriptors,
            *(descriptor for pipe in pipes for descriptor in (
                pipe.read_descriptor,
                pipe.write_descriptor,
            )),
        }
        descriptor_mapping: dict[int, int] = {}
        next_descriptor = 64
        for descriptor in child_descriptors:
            while next_descriptor in occupied_descriptors:
                next_descriptor += 1
            descriptor_mapping[descriptor] = next_descriptor
            occupied_descriptors.add(next_descriptor)
            next_descriptor += 1
        bound_arguments = tuple(
            _replace_descriptor_argument(argument, descriptor_mapping)
            for argument in arguments
        )
        pid_descriptor = descriptor_mapping[pid_pipe.write_descriptor]
        gate_descriptor = descriptor_mapping[gate_pipe.read_descriptor]
        spawn_nonce = secrets.token_hex(16)
        wrapper_executable = (
            "/proc/self/exe" if Path("/proc/self/exe").exists() else sys.executable
        )
        wrapper_arguments = (
            wrapper_executable,
            "-I",
            "-S",
            "-c",
            _SPAWN_WRAPPER,
            str(pid_descriptor),
            str(gate_descriptor),
            ",".join(str(item) for item in sorted(descriptor_mapping.values())),
            ",".join(str(item) for item in sorted(child_signal_mask)),
            spawn_nonce,
            *bound_arguments,
        )
        file_actions = [
            (os.POSIX_SPAWN_OPEN, 0, os.devnull, os.O_RDONLY, 0o600),
            (os.POSIX_SPAWN_DUP2, stdout_pipe.write_descriptor, 1),
            (os.POSIX_SPAWN_DUP2, stderr_pipe.write_descriptor, 2),
            *(
                (os.POSIX_SPAWN_DUP2, source, destination)
                for source, destination in descriptor_mapping.items()
            ),
        ]
        try:
            spawned_pid = os.posix_spawn(
                wrapper_arguments[0],
                wrapper_arguments,
                env,
                file_actions=file_actions,
                setsigmask=guarded_child_signal_mask,
            )
            process.pid = spawned_pid
        except BaseException:
            pid_pipe.close_write()
            gate_pipe.close_read()
            recovery_deadline = time.monotonic() + _COMMAND_CLEANUP_SECONDS
            try:
                recovered_pid = _recover_gated_spawn_pid(
                    spawn_nonce,
                    child_inventory=child_inventory,
                    child_pids_before_spawn=child_pids_before_spawn,
                    deadline=recovery_deadline,
                )
            except ProbeConnectGuardError:
                recovered_pid = None
            if recovered_pid is None:
                recovered_pid = _read_reported_spawn_pid(
                    pid_pipe,
                    required=False,
                    deadline=time.monotonic() + _COMMAND_CLEANUP_SECONDS,
                )
            if recovered_pid is not None:
                process.pid = recovered_pid
            gate_pipe.close_write()
            raise
        pid_pipe.close_write()
        gate_pipe.close_read()
        reported_pid = _read_reported_spawn_pid(
            pid_pipe,
            required=True,
            deadline=deadline,
        )
        if reported_pid != process.pid:
            raise ProbeConnectGuardError("probe_guard_kernel_operation_failed")
        os.write(gate_pipe.write_descriptor, b"R")
        gate_pipe.close_write()
        stdout_pipe.close_write()
        stderr_pipe.close_write()
        process.stdout = _OwnedPipeReader(stdout_pipe)
        stdout_pipe.transfer_read()
        process.stderr = _OwnedPipeReader(stderr_pipe)
        stderr_pipe.transfer_read()
    except BaseException as error:
        primary_error = error
        raise
    finally:
        cleanup_errors = [error for pipe in reversed(pipes) for error in pipe.close()]
        try:
            child_inventory.close()
        except BaseException as error:
            cleanup_errors.append(_sanitize_cleanup_error(error))
        if previous_mask is not None:
            try:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            except BaseException as error:
                cleanup_errors.append(_sanitize_cleanup_error(error))
        if cleanup_errors:
            if primary_error is not None and (
                not isinstance(primary_error, Exception)
                or any(not isinstance(error, Exception) for error in cleanup_errors)
            ):
                raise BaseExceptionGroup(
                    "probe guard spawn cleanup was interrupted",
                    [primary_error, *cleanup_errors],
                ) from None
            if (
                primary_error is None
                and len(cleanup_errors) == 1
                and not isinstance(cleanup_errors[0], Exception)
            ):
                raise cleanup_errors[0]
            if any(not isinstance(error, Exception) for error in cleanup_errors):
                raise BaseExceptionGroup(
                    "probe guard spawn cleanup was interrupted",
                    cleanup_errors,
                ) from None
            raise ProbeConnectGuardError("probe_guard_command_cleanup_failed")


def _read_reported_spawn_pid(
    pipe: _OwnedSpawnPipe,
    *,
    required: bool,
    deadline: float,
) -> int | None:
    descriptor = pipe.read_descriptor
    selector = selectors.DefaultSelector()
    payload = bytearray()
    try:
        selector.register(descriptor, selectors.EVENT_READ)
        while b"\n" not in payload:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                if required:
                    raise ProbeConnectGuardError(
                        "probe_guard_kernel_operation_failed"
                    )
                return None
            chunk = os.read(descriptor, 32 - len(payload))
            if not chunk:
                break
            payload.extend(chunk)
            if len(payload) >= 32 and b"\n" not in payload:
                break
    finally:
        selector.close()
        pipe.close_read()
    if not payload:
        if required:
            raise ProbeConnectGuardError("probe_guard_kernel_operation_failed")
        return None
    try:
        decoded = payload.decode("ascii")
        if not re.fullmatch(r"[1-9][0-9]{0,9}\n", decoded):
            raise ValueError
        return int(decoded)
    except (UnicodeDecodeError, ValueError):
        raise ProbeConnectGuardError("probe_guard_kernel_operation_failed") from None


def _recover_gated_spawn_pid(
    spawn_nonce: str,
    *,
    child_inventory: _OwnedThreadChildInventory,
    child_pids_before_spawn: set[int] | None,
    deadline: float,
) -> int | None:
    child_pids_after_spawn = child_inventory.snapshot(deadline=deadline)
    if child_pids_before_spawn is None or child_pids_after_spawn is None:
        return None
    candidate_pids = child_pids_after_spawn.difference(child_pids_before_spawn)
    if len(candidate_pids) == 1:
        return next(iter(candidate_pids))
    expected_nonce = spawn_nonce.encode("ascii")
    matches: list[int] = []
    for child_pid in candidate_pids:
        try:
            with Path(f"/proc/{child_pid}/cmdline").open("rb") as stream:
                command_line = stream.read(65_537)
        except FileNotFoundError:
            continue
        except OSError:
            raise ProbeConnectGuardError(
                "probe_guard_kernel_operation_failed"
            ) from None
        if len(command_line) > 65_536:
            raise ProbeConnectGuardError("probe_guard_kernel_operation_failed")
        if expected_nonce in command_line.split(b"\0"):
            matches.append(child_pid)
    if len(matches) > 1:
        raise ProbeConnectGuardError("probe_guard_kernel_operation_failed")
    return matches[0] if matches else None


def _replace_descriptor_argument(
    argument: str,
    descriptor_mapping: dict[int, int],
) -> str:
    for source, destination in descriptor_mapping.items():
        prefix = f"/proc/self/fd/{source}"
        if argument == prefix or argument.startswith(f"{prefix}/"):
            return f"/proc/self/fd/{destination}{argument[len(prefix):]}"
    return argument


def _terminate_and_reap(process: _SpawnedProcess) -> BaseException | None:
    try:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=_COMMAND_CLEANUP_SECONDS / 2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=_COMMAND_CLEANUP_SECONDS / 2)
        else:
            process.wait(timeout=0)
    except BaseException as error:
        return _sanitize_cleanup_error(error)
    return None


def _close_command_resources(
    selector: _Closable | None,
    stdout: _Closable | None,
    stderr: _Closable | None,
) -> list[BaseException]:
    errors: list[BaseException] = []
    for resource in (selector, stdout, stderr):
        if resource is None:
            continue
        try:
            resource.close()
        except BaseException as error:
            errors.append(_sanitize_cleanup_error(error))
    return errors


def _close_descriptors(descriptors: list[int]) -> list[BaseException]:
    errors: list[BaseException] = []
    while descriptors:
        descriptor = descriptors.pop()
        try:
            os.close(descriptor)
        except BaseException as error:
            errors.append(_sanitize_cleanup_error(error))
    return errors


def _hex_bytes(value: bytes) -> tuple[str, ...]:
    return tuple(f"{byte:02x}" for byte in value)


def _one_json_object(raw: object) -> dict[str, object]:
    if isinstance(raw, dict):
        item = raw
    elif isinstance(raw, list) and len(raw) == 1 and isinstance(raw[0], dict):
        item = raw[0]
    else:
        raise ProbeConnectGuardError("probe_guard_readback_invalid")
    return cast(dict[str, object], item)


def _map_inventory_id(raw: object) -> int | None:
    item = _one_json_object(raw)
    map_id = item.get("id")
    if not (
        item.get("type") == "array"
        and item.get("name") == "allowed_target"
        and item.get("flags") == 0
        and item.get("bytes_key") == 4
        and item.get("bytes_value") == 32
        and item.get("max_entries") == 1
        and isinstance(map_id, int)
        and not isinstance(map_id, bool)
        and map_id > 0
    ):
        return None
    return map_id


def _json_bytes(raw: object, key: str) -> bytes:
    if not isinstance(raw, dict):
        raise ProbeConnectGuardError("probe_guard_readback_invalid")
    value = raw.get(key)
    if not isinstance(value, list):
        raise ProbeConnectGuardError("probe_guard_readback_invalid")
    result = bytearray()
    for item in value:
        if (
            not isinstance(item, str)
            or len(item) != 4
            or not item.startswith("0x")
        ):
            raise ProbeConnectGuardError("probe_guard_readback_invalid")
        try:
            result.append(int(item[2:], 16))
        except ValueError:
            raise ProbeConnectGuardError("probe_guard_readback_invalid") from None
    return bytes(result)
