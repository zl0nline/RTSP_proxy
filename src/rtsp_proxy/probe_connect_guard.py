from __future__ import annotations

import json
import os
import re
import selectors
import stat
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from hashlib import sha256
from ipaddress import ip_address
from math import isfinite
from pathlib import Path
from threading import Lock
from typing import NoReturn, Protocol, cast
from uuid import UUID

from rtsp_proxy.probe_executor import ProbeConnectGuardTarget

_COMMAND_OUTPUT_MAX_BYTES = 65_536
_COMMAND_CLEANUP_SECONDS = 1.0


class ProbeConnectGuardError(RuntimeError):
    """An exact cgroup connect guard could not be installed or collected."""


class ProbeConnectGuardInstallRejected(ProbeConnectGuardError):
    """The kernel scope was already owned before this install mutated it."""


class ProbeConnectGuardInstallRejectedInterruption(BaseException):
    """A pre-mutation install rejection followed a process interruption."""

    def __init__(self, interruption: BaseException) -> None:
        super().__init__("probe_guard_install_rejected_interrupted")
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
        self._identity = artifact_identity
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
        self._pin_root = _trusted_directory(pin_root, owner_uid=trusted_owner_uid)
        self._ownership_root = _trusted_directory(
            ownership_root,
            owner_uid=trusted_owner_uid,
        )
        self._owner_uid = trusted_owner_uid
        self._run = run
        self._monotonic = monotonic

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
        if paths.scope.exists() or paths.receipt.exists():
            raise ProbeConnectGuardInstallRejected(
                "probe_guard_already_active"
            )
        self._create_receipt(scope, paths.receipt)
        try:
            os.mkdir(paths.scope, mode=0o700)
        except FileExistsError:
            try:
                self._remove_reserved_receipt(paths.receipt)
            except BaseException as error:
                if not isinstance(error, Exception):
                    raise ProbeConnectGuardInstallRejectedInterruption(error) from None
            raise ProbeConnectGuardInstallRejected(
                "probe_guard_already_active"
            ) from None
        try:
            self._promote_receipt(scope, paths.receipt, paths.scope)
        except BaseException as primary_error:
            cleanup_errors: list[BaseException] = []
            try:
                paths.scope.rmdir()
                self._remove_reserved_receipt(paths.receipt)
            except BaseException as cleanup_error:
                cleanup_errors.append(_sanitize_cleanup_error(cleanup_error))
            if cleanup_errors:
                raise BaseExceptionGroup(
                    "probe guard ownership promotion and cleanup failed",
                    [primary_error, *cleanup_errors],
                ) from None
            if not isinstance(primary_error, Exception):
                raise ProbeConnectGuardInstallRejectedInterruption(
                    primary_error
                ) from None
            raise ProbeConnectGuardInstallRejected(
                "probe_guard_install_failed"
            ) from None
        for path in (paths.programs, paths.maps):
            os.mkdir(path, mode=0o700)
        self._command(
            "prog",
            "loadall",
            str(self._object),
            str(paths.programs),
            "pinmaps",
            str(paths.maps),
            budget=budget,
        )
        self._command(
            "cgroup",
            "attach",
            str(scope.cgroup_path),
            self._IPV4_ATTACH,
            "pinned",
            str(paths.ipv4),
            budget=budget,
        )
        self._command(
            "cgroup",
            "attach",
            str(scope.cgroup_path),
            self._IPV6_ATTACH,
            "pinned",
            str(paths.ipv6),
            budget=budget,
        )
        key = (0).to_bytes(4, "little")
        self._command(
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

    def verify(
        self,
        scope: ProbeConnectGuardScope,
        *,
        timeout_seconds: float,
    ) -> None:
        self._require_artifact_identity()
        paths = self._paths(scope)
        budget = _CommandBudget.start(timeout_seconds, monotonic=self._monotonic)
        self._require_receipt(scope, paths.receipt)
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
        self._require_artifact_identity()
        paths = self._paths(scope)
        budget = _CommandBudget.start(timeout_seconds, monotonic=self._monotonic)
        if not _path_lexists(paths.receipt):
            if not _path_lexists(paths.scope):
                return
            raise ProbeConnectGuardError("probe_guard_ownership_invalid")
        ownership = self._ownership_from_receipt(paths.receipt)
        if ownership.scope != scope or ownership.phase != 1:
            raise ProbeConnectGuardError("probe_guard_ownership_invalid")
        if not _path_lexists(paths.scope):
            self._remove_receipt(paths.receipt)
            return
        self._require_receipt(scope, paths.receipt)
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
                        self._identity.ipv4_program_tag
                        if attach_type == self._IPV4_ATTACH
                        else self._identity.ipv6_program_tag
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
            matches = [
                item for item in attachments if item == (program_id, attach_type)
            ]
            if len(matches) > 1:
                raise ProbeConnectGuardError("probe_guard_ownership_invalid")
            if matches:
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
        receipts = self._receipt_inventory()
        for receipt in receipts[: self._RECONCILE_MAX_SCOPES]:
            ownership = self._ownership_from_receipt(receipt)
            try:
                if ownership.phase == 0:
                    self._remove_reserved_receipt(receipt)
                else:
                    self.remove(
                        ownership.scope,
                        timeout_seconds=budget.remaining(),
                    )
            except ProbeConnectGuardError:
                if budget.deadline - self._monotonic() <= 0:
                    break
        return len(self._receipt_inventory())

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

    def _create_receipt(self, scope: ProbeConnectGuardScope, path: Path) -> None:
        payload = _receipt_bytes(
            scope,
            object_sha256=self._identity.object_sha256,
            phase=0,
            scope_device=0,
            scope_inode=0,
        )
        try:
            with open(
                path,
                "xb",
                buffering=0,
                opener=_receipt_opener,
            ) as output:
                written = 0
                while written < len(payload):
                    count = output.write(payload[written:])
                    if count is None or count <= 0:
                        raise OSError("receipt write made no progress")
                    written += count
                os.fsync(output.fileno())
        except FileExistsError:
            raise ProbeConnectGuardInstallRejected(
                "probe_guard_already_active"
            ) from None
        except BaseException as primary_error:
            cleanup_errors: list[BaseException] = []
            try:
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
        _fsync_directory(self._ownership_root)

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
        expected = _receipt_bytes(
            scope,
            object_sha256=self._identity.object_sha256,
            phase=0,
            scope_device=0,
            scope_inode=0,
        )
        replacement = _receipt_bytes(
            scope,
            object_sha256=self._identity.object_sha256,
            phase=1,
            scope_device=scope_metadata.st_dev,
            scope_inode=scope_metadata.st_ino,
        )
        if len(replacement) != len(expected):
            raise ProbeConnectGuardError("probe_guard_ownership_invalid")
        flags = os.O_RDWR | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = -1
        try:
            descriptor = os.open(path, flags)
            metadata = os.fstat(descriptor)
            if not _receipt_metadata_valid(metadata, owner_uid=self._owner_uid):
                raise ProbeConnectGuardError("probe_guard_ownership_invalid")
            if os.pread(descriptor, len(expected) + 1, 0) != expected:
                raise ProbeConnectGuardError("probe_guard_ownership_invalid")
            written = 0
            while written < len(replacement):
                count = os.pwrite(descriptor, replacement[written:], written)
                if count <= 0:
                    raise OSError("receipt promotion made no progress")
                written += count
            os.fsync(descriptor)
        except OSError:
            raise ProbeConnectGuardError("probe_guard_ownership_invalid") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _require_receipt(self, scope: ProbeConnectGuardScope, path: Path) -> None:
        ownership = self._ownership_from_receipt(path)
        if ownership.scope != scope or ownership.phase != 1:
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
            if (
                isinstance(phase, bool)
                or not isinstance(phase, int)
                or phase not in {0, 1}
                or not isinstance(scope_device_raw, str)
                or not re.fullmatch(r"[0-9]{20}", scope_device_raw)
                or not isinstance(scope_inode_raw, str)
                or not re.fullmatch(r"[0-9]{20}", scope_inode_raw)
            ):
                raise ValueError
            scope_device = int(scope_device_raw)
            scope_inode = int(scope_inode_raw)
        except (KeyError, TypeError, ValueError, RuntimeError):
            raise ProbeConnectGuardError("probe_guard_ownership_invalid") from None
        if (
            not isinstance(decoded, dict)
            or set(decoded) != {
                "address",
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
            or decoded["version"] != 2
            or decoded["object_sha256"] != self._identity.object_sha256
            or _receipt_bytes(
                scope,
                object_sha256=self._identity.object_sha256,
                phase=phase,
                scope_device=scope_device,
                scope_inode=scope_inode,
            )
            != payload
            or (phase == 0 and (scope_device != 0 or scope_inode != 0))
            or (phase == 1 and scope_inode == 0)
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
        )

    def _receipt_inventory(self) -> list[Path]:
        try:
            entries: list[Path] = []
            for entry in self._ownership_root.iterdir():
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
                pass_fds=(bpftool_descriptor, object_descriptor),
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
        self._reconcile_ready = True
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
        operation_acquired = False
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
                return lease
            except BaseException as primary_error:
                self._cleanup_failed_install(
                    record,
                    timeout_seconds=timeout_seconds,
                    primary_error=primary_error,
                )
        finally:
            if operation_acquired:
                self._release_operation(record, preserve_active=True)

    def release(
        self,
        lease: ProbeConnectGuardLease,
        *,
        timeout_seconds: float,
    ) -> None:
        if not isinstance(lease, ProbeConnectGuardLease):
            raise ProbeConnectGuardError("probe_guard_lease_invalid")
        self._validate_timeout(timeout_seconds)
        with self._lock:
            record = self._active.get(lease.unit_name)
            if record is None or record.lease is not lease or record.state != "active":
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
                    or record.state != "active"
                ):
                    raise ProbeConnectGuardError("probe_guard_lease_invalid")
                record.state = "cleaning"
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
                del self._active[lease.unit_name]
        finally:
            if operation_acquired:
                self._release_operation(record)

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
                        if record.state == "cleanup_pending"
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
                            or record.state != "cleanup_pending"
                        ):
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
        timeout_seconds: float,
        primary_error: BaseException,
    ) -> NoReturn:
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
            self._backend.remove(record.scope, timeout_seconds=timeout_seconds)
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
                record.state == "cleanup_pending" for record in self._active.values()
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
    phase: int,
    scope_device: int,
    scope_inode: int,
) -> bytes:
    return (
        json.dumps(
            {
                "address": str(scope.target.address),
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


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _receipt_opener(path: str, flags: int) -> int:
    flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return os.open(path, flags, 0o600)


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
    proc_path = Path("/proc/self/fd")
    if proc_path.is_dir():
        return str(proc_path / str(descriptor))
    return str(fallback)


def _trusted_directory(path: Path, *, owner_uid: int) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ProbeConnectGuardError("probe_guard_pin_root_invalid")
    try:
        metadata = path.lstat()
    except OSError:
        raise ProbeConnectGuardError("probe_guard_pin_root_invalid") from None
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != owner_uid
        or metadata.st_mode & 0o022
    ):
        raise ProbeConnectGuardError("probe_guard_pin_root_invalid")
    return path


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
    try:
        process = subprocess.Popen(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin"},
            pass_fds=pass_fds,
        )
    except OSError:
        raise ProbeConnectGuardError("probe_guard_kernel_operation_failed") from None
    selector: selectors.BaseSelector | None = None
    try:
        stdout = bytearray()
        stderr = bytearray()
        selector = selectors.DefaultSelector()
        deadline = time.monotonic() + timeout_seconds
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
        process_cleanup_error = _terminate_and_reap(process)
        if process_cleanup_error is not None:
            cleanup_errors.append(process_cleanup_error)
        cleanup_errors.extend(
            _close_command_resources(
                selector,
                process.stdout,
                process.stderr,
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


def _terminate_and_reap(process: subprocess.Popen[bytes]) -> BaseException | None:
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
