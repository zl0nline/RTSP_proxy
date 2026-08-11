from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import stat
import subprocess
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from rtsp_proxy.load_evidence import (
    BootId,
    GeneratorCounters,
    GeneratorHeadroomSummary,
    KernelClockProof,
    RuntimeProcessBinding,
    normalize_linux_ephemeral_port_range,
    normalize_linux_reserved_ports,
    parse_linux_ephemeral_port_settings,
    prove_linux_clock,
    read_linux_generator_counters,
)
from rtsp_proxy.load_profile import LoadProfile, canonical_profile_bytes
from rtsp_proxy.release import ReleaseVerificationError, normalize_linux_arch

Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
SafeHost = Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9._-]{1,253}$")]
LimitValue = Annotated[int, Field(gt=0)] | Literal["unlimited"]
RUNTIME_MANIFEST_MAX_LEAD_MS = 300_000

_SYSCTL_PATHS = (
    "fs/file-max",
    "net/core/rmem_max",
    "net/core/somaxconn",
    "net/core/wmem_max",
    "net/ipv4/ip_local_port_range",
    "net/ipv4/ip_local_reserved_ports",
    "net/ipv4/tcp_fin_timeout",
    "net/ipv4/tcp_keepalive_time",
    "net/ipv4/tcp_max_syn_backlog",
    "net/ipv4/tcp_tw_reuse",
)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)


class RuntimeSetting(StrictModel):
    name: Annotated[str, StringConstraints(pattern=r"^[a-z0-9_.-]{1,128}$")]
    value: Annotated[str, StringConstraints(max_length=1024)]

    @model_validator(mode="after")
    def require_typed_canonical_value(self) -> Self:
        if _normalize_runtime_sysctl(self.name, self.value) != self.value:
            raise ValueError("runtime_sysctl_not_canonical")
        return self


class RuntimeProcess(StrictModel):
    pid: Annotated[int, Field(gt=0)]
    executable_sha256: Sha256
    start_time_ticks: Annotated[int, Field(gt=0)]
    max_open_files_soft: Annotated[int, Field(gt=0)]
    max_open_files_hard: Annotated[int, Field(gt=0)]
    max_processes_soft: LimitValue
    max_processes_hard: LimitValue

    @model_validator(mode="after")
    def require_ordered_limits(self) -> Self:
        if self.max_open_files_soft > self.max_open_files_hard or (
            isinstance(self.max_processes_soft, int)
            and isinstance(self.max_processes_hard, int)
            and self.max_processes_soft > self.max_processes_hard
        ):
            raise ValueError("runtime_process_soft_limit_exceeds_hard")
        if self.max_processes_soft == "unlimited" and self.max_processes_hard != "unlimited":
            raise ValueError("runtime_process_soft_limit_exceeds_hard")
        return self

    @property
    def binding(self) -> RuntimeProcessBinding:
        return RuntimeProcessBinding(
            pid=self.pid,
            executable_sha256=self.executable_sha256,
            start_time_ticks=self.start_time_ticks,
        )


class RuntimeLibrary(StrictModel):
    path: Annotated[str, StringConstraints(pattern=r"^/[^\x00\r\n]{1,1023}$")]
    sha256: Sha256
    size_bytes: Annotated[int, Field(gt=0)]
    device_major: Annotated[int, Field(ge=0)]
    device_minor: Annotated[int, Field(ge=0)]
    inode: Annotated[int, Field(gt=0)]
    process_ids: tuple[Annotated[int, Field(gt=0)], ...]

    @model_validator(mode="after")
    def require_canonical_process_ids(self) -> Self:
        if not self.process_ids or tuple(sorted(set(self.process_ids))) != self.process_ids:
            raise ValueError("runtime_library_process_ids_not_canonical")
        return self


class RuntimePackage(StrictModel):
    name: Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9+.-]{1,128}$")]
    version: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    architecture: Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9_-]{1,32}$")]


class GStreamerRuntime(StrictModel):
    version: Annotated[str, StringConstraints(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")]
    package_build_id: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    gst_launch_path: Annotated[str, StringConstraints(pattern=r"^/[^\x00\r\n]{1,1023}$")]
    gst_launch_sha256: Sha256
    packages: tuple[RuntimePackage, ...]
    packages_sha256: Sha256
    loaded_libraries: tuple[RuntimeLibrary, ...]

    @model_validator(mode="after")
    def require_canonical_inventory(self) -> Self:
        package_keys = tuple((item.name, item.architecture) for item in self.packages)
        library_paths = tuple(item.path for item in self.loaded_libraries)
        expected_package_digest = _canonical_sha256(
            [item.model_dump(mode="json") for item in self.packages]
        )
        if (
            not self.packages
            or tuple(sorted(set(package_keys))) != package_keys
            or not self.loaded_libraries
            or tuple(sorted(set(library_paths))) != library_paths
            or self.packages_sha256 != expected_package_digest
        ):
            raise ValueError("gstreamer_runtime_inventory_not_canonical")
        return self


class LinuxRuntimeManifest(StrictModel):
    schema_version: Literal[1]
    profile_sha256: Sha256
    role: Literal["generator", "sut"]
    host: SafeHost
    architecture: Literal["amd64", "arm64"]
    capture_started_clock: KernelClockProof
    capture_completed_clock: KernelClockProof
    machine_id_sha256: Sha256
    boot_id: BootId
    kernel_release: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    os_release_sha256: Sha256
    cpu_model: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    logical_cpu_count: Annotated[int, Field(gt=0)]
    memory_total_bytes: Annotated[int, Field(gt=0)]
    network_interface: Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9_.:-]{1,15}$")]
    interface_mtu_bytes: Annotated[int, Field(ge=576, le=9216)]
    nic_link_speed_bits_per_second: Annotated[int, Field(gt=0)]
    sysctls: tuple[RuntimeSetting, ...]
    cgroup_path_sha256: Sha256
    cgroup_cpu_capacity_cores: Annotated[float, Field(gt=0)]
    cgroup_memory_limit_bytes: Annotated[int, Field(gt=0)]
    cgroup_pids_limit: Annotated[int, Field(gt=0)]
    cgroup_constraint_chain_sha256: Sha256
    processes: tuple[RuntimeProcess, ...]
    gstreamer: GStreamerRuntime | None

    @model_validator(mode="after")
    def require_canonical_host_inventory(self) -> Self:
        setting_names = tuple(item.name for item in self.sysctls)
        process_ids = tuple(item.pid for item in self.processes)
        if (
            setting_names != tuple(sorted(set(setting_names)))
            or set(setting_names) != {path.replace("/", ".") for path in _SYSCTL_PATHS}
            or not self.processes
            or process_ids != tuple(sorted(set(process_ids)))
            or (self.role == "generator") != (self.gstreamer is not None)
            or self.capture_completed_clock.observed_at_unix_ms
            < self.capture_started_clock.observed_at_unix_ms
        ):
            raise ValueError("linux_runtime_manifest_not_canonical")
        if self.gstreamer is not None:
            manifest_pids = set(process_ids)
            observed_pids = {
                pid for library in self.gstreamer.loaded_libraries for pid in library.process_ids
            }
            core_pids = {
                pid
                for library in self.gstreamer.loaded_libraries
                if PurePosixPath(library.path).name.startswith("libgstreamer-1.0.so")
                for pid in library.process_ids
            }
            if observed_pids != manifest_pids or core_pids != manifest_pids:
                raise ValueError("gstreamer_runtime_process_coverage_incomplete")
        return self


def capture_generator_runtime(
    profile: LoadProfile,
    *,
    host: str,
    pids: tuple[int, ...],
    cgroup: str,
    expected_executables: dict[int, str],
    gst_launch_binary: Path,
    root: Path = Path("/"),
) -> LinuxRuntimeManifest:
    generator = next((item for item in profile.generator_hosts if item.name == host), None)
    if generator is None:
        raise ValueError("unknown_generator_host")
    return _capture_linux_runtime(
        profile,
        role="generator",
        host=host,
        expected_architecture=generator.architecture,
        pids=pids,
        cgroup=cgroup,
        expected_executables=expected_executables,
        gst_launch_binary=gst_launch_binary,
        root=root,
    )


def capture_sut_runtime(
    profile: LoadProfile,
    *,
    pid: int,
    cgroup: str,
    root: Path = Path("/"),
) -> LinuxRuntimeManifest:
    return _capture_linux_runtime(
        profile,
        role="sut",
        host=profile.sut_rtsp_host,
        expected_architecture=profile.sut_architecture,
        pids=(pid,),
        cgroup=cgroup,
        expected_executables={pid: profile.artifacts.mediamtx_sha256},
        gst_launch_binary=None,
        root=root,
    )


def validate_runtime_manifest(
    profile: LoadProfile,
    manifest: LinuxRuntimeManifest,
    *,
    role: Literal["generator", "sut"],
    host: str,
    expected_architecture: Literal["amd64", "arm64"],
    coordinated_anchor_start_unix_ms: int,
    coordinated_measurement_start_unix_ms: int,
    resource_summary: GeneratorHeadroomSummary | None,
) -> None:
    _, profile_sha256 = canonical_profile_bytes(profile)
    observed_bindings = tuple(item.binding for item in manifest.processes)
    started_at = manifest.capture_started_clock.observed_at_unix_ms
    completed_at = manifest.capture_completed_clock.observed_at_unix_ms
    clocks = (manifest.capture_started_clock, manifest.capture_completed_clock)
    if (
        manifest.profile_sha256 != profile_sha256
        or manifest.role != role
        or manifest.host != host
        or manifest.architecture != expected_architecture
        or manifest.network_interface != profile.network.interface
        or manifest.interface_mtu_bytes != profile.network.mtu_bytes
        or any(
            not clock.synchronized
            or clock.max_error_ms > profile.evidence_sampling.maximum_clock_error_ms
            for clock in clocks
        )
        or started_at < coordinated_anchor_start_unix_ms - RUNTIME_MANIFEST_MAX_LEAD_MS
        or completed_at > coordinated_measurement_start_unix_ms
    ):
        raise ValueError("runtime_manifest_binding_invalid")
    if resource_summary is None:
        raise ValueError("runtime_manifest_requires_resource_summary")
    settings = {item.name: item.value for item in manifest.sysctls}
    port_start, port_end, port_capacity, reserved_sha256 = parse_linux_ephemeral_port_settings(
        settings["net.ipv4.ip_local_port_range"],
        settings["net.ipv4.ip_local_reserved_ports"],
    )
    if (
        manifest.host != resource_summary.generator_host
        or manifest.machine_id_sha256 != resource_summary.machine_id_sha256
        or manifest.boot_id != resource_summary.boot_id
        or manifest.interface_mtu_bytes != resource_summary.interface_mtu_bytes
        or manifest.memory_total_bytes != resource_summary.memory_total_bytes
        or manifest.nic_link_speed_bits_per_second
        != resource_summary.nic_link_speed_bits_per_second
        or manifest.cgroup_path_sha256 != resource_summary.cgroup_path_sha256
        or manifest.cgroup_cpu_capacity_cores != resource_summary.cgroup_cpu_capacity_cores
        or manifest.cgroup_memory_limit_bytes != resource_summary.cgroup_memory_limit_bytes
        or manifest.cgroup_pids_limit != resource_summary.cgroup_pids_limit
        or manifest.cgroup_constraint_chain_sha256
        != resource_summary.cgroup_constraint_chain_sha256
        or port_start != resource_summary.ephemeral_port_start
        or port_end != resource_summary.ephemeral_port_end
        or port_capacity != resource_summary.ephemeral_port_capacity
        or reserved_sha256 != resource_summary.reserved_ports_sha256
        or observed_bindings != resource_summary.workload_processes
        or tuple((item.pid, item.max_open_files_soft) for item in manifest.processes)
        != tuple(
            (item.pid, item.max_open_files) for item in resource_summary.workload_process_limits
        )
    ):
        raise ValueError("runtime_manifest_resource_series_binding_invalid")
    if role == "generator":
        runtime = manifest.gstreamer
        if (
            runtime is None
            or runtime.version != profile.artifacts.gstreamer_version
            or runtime.package_build_id != profile.artifacts.gstreamer_build_id
            or any(
                set(library.process_ids) - {item.pid for item in manifest.processes}
                for library in runtime.loaded_libraries
            )
        ):
            raise ValueError("runtime_manifest_gstreamer_binding_invalid")
    elif manifest.gstreamer is not None:
        raise ValueError("runtime_manifest_sut_has_gstreamer_inventory")


def validate_runtime_comparison_pair(
    proxy: LinuxRuntimeManifest, direct: LinuxRuntimeManifest
) -> None:
    if _runtime_comparison_identity(proxy) != _runtime_comparison_identity(direct):
        raise ValueError("runtime_comparison_environment_differs")


def _runtime_comparison_identity(manifest: LinuxRuntimeManifest) -> dict[str, object]:
    gstreamer: dict[str, object] | None = None
    if manifest.gstreamer is not None:
        gstreamer = manifest.gstreamer.model_dump(mode="json")
        process_fingerprints = {
            item.pid: _canonical_sha256(
                {
                    key: value
                    for key, value in item.model_dump(mode="json").items()
                    if key not in {"pid", "start_time_ticks"}
                }
            )
            for item in manifest.processes
        }
        gstreamer["loaded_libraries"] = [
            {
                **{
                    key: value
                    for key, value in library.model_dump(mode="json").items()
                    if key != "process_ids"
                },
                "process_fingerprints": sorted(
                    process_fingerprints[pid] for pid in library.process_ids
                ),
            }
            for library in manifest.gstreamer.loaded_libraries
        ]
    return {
        "role": manifest.role,
        "host": manifest.host,
        "architecture": manifest.architecture,
        "machine_id_sha256": manifest.machine_id_sha256,
        "boot_id": manifest.boot_id,
        "kernel_release": manifest.kernel_release,
        "os_release_sha256": manifest.os_release_sha256,
        "cpu_model": manifest.cpu_model,
        "logical_cpu_count": manifest.logical_cpu_count,
        "memory_total_bytes": manifest.memory_total_bytes,
        "network_interface": manifest.network_interface,
        "interface_mtu_bytes": manifest.interface_mtu_bytes,
        "nic_link_speed_bits_per_second": manifest.nic_link_speed_bits_per_second,
        "sysctls": [item.model_dump(mode="json") for item in manifest.sysctls],
        "cgroup_path_sha256": manifest.cgroup_path_sha256,
        "cgroup_cpu_capacity_cores": manifest.cgroup_cpu_capacity_cores,
        "cgroup_memory_limit_bytes": manifest.cgroup_memory_limit_bytes,
        "cgroup_pids_limit": manifest.cgroup_pids_limit,
        "cgroup_constraint_chain_sha256": manifest.cgroup_constraint_chain_sha256,
        "processes": sorted(
            (
                {
                    "executable_sha256": item.executable_sha256,
                    "max_open_files_soft": item.max_open_files_soft,
                    "max_open_files_hard": item.max_open_files_hard,
                    "max_processes_soft": item.max_processes_soft,
                    "max_processes_hard": item.max_processes_hard,
                }
                for item in manifest.processes
            ),
            key=lambda item: (
                str(item["executable_sha256"]),
                int(item["max_open_files_soft"]),
            ),
        ),
        "gstreamer": gstreamer,
    }


def _capture_linux_runtime(
    profile: LoadProfile,
    *,
    role: Literal["generator", "sut"],
    host: str,
    expected_architecture: Literal["amd64", "arm64"],
    pids: tuple[int, ...],
    cgroup: str,
    expected_executables: dict[int, str],
    gst_launch_binary: Path | None,
    root: Path,
) -> LinuxRuntimeManifest:
    if platform.system() != "Linux":
        raise ValueError("runtime_manifest_requires_linux")
    try:
        architecture = normalize_linux_arch(platform.machine()).value
    except ReleaseVerificationError as error:
        raise ValueError("runtime_manifest_architecture_unsupported") from error
    if architecture != expected_architecture:
        raise ValueError("runtime_manifest_architecture_mismatch")
    capture_started_clock = prove_linux_clock(profile.evidence_sampling.maximum_clock_error_ms)
    counters = read_linux_generator_counters(
        root,
        interface=profile.network.interface,
        pids=pids,
        cgroup=cgroup,
        expected_executables=expected_executables,
        expected_mtu_bytes=profile.network.mtu_bytes,
    )
    process_bindings = {item.pid: item for item in counters.processes}
    processes = tuple(
        _read_process_runtime(
            root,
            RuntimeProcessBinding(
                pid=process_bindings[pid].pid,
                executable_sha256=process_bindings[pid].executable_sha256,
                start_time_ticks=process_bindings[pid].start_time_ticks,
            ),
        )
        for pid in sorted(pids)
    )
    sysctls = tuple(
        RuntimeSetting(
            name=relative.replace("/", "."),
            value=_normalize_runtime_sysctl(
                relative.replace("/", "."),
                _read_bounded_text(root / "proc/sys" / relative),
            ),
        )
        for relative in _SYSCTL_PATHS
    )
    cpu_model, logical_cpu_count = _read_cpu_inventory(root)
    profile_sha256 = canonical_profile_bytes(profile)[1]
    gstreamer = (
        _read_gstreamer_runtime(
            root,
            pids=tuple(sorted(pids)),
            gst_launch_binary=gst_launch_binary,
            expected_version=profile.artifacts.gstreamer_version,
            expected_build_id=profile.artifacts.gstreamer_build_id,
            expected_architecture=expected_architecture,
        )
        if role == "generator" and gst_launch_binary is not None
        else None
    )
    if role == "generator" and gstreamer is None:
        raise ValueError("gstreamer_runtime_required")
    kernel_release = _read_bounded_text(root / "proc/sys/kernel/osrelease")
    os_release_sha256 = _read_os_release_sha256(root)
    completed_counters = read_linux_generator_counters(
        root,
        interface=profile.network.interface,
        pids=pids,
        cgroup=cgroup,
        expected_executables=expected_executables,
        expected_mtu_bytes=profile.network.mtu_bytes,
    )
    if _runtime_counter_identity(counters) != _runtime_counter_identity(completed_counters):
        raise ValueError("runtime_process_or_limit_identity_changed_during_capture")
    capture_completed_clock = prove_linux_clock(profile.evidence_sampling.maximum_clock_error_ms)
    return LinuxRuntimeManifest(
        schema_version=1,
        profile_sha256=profile_sha256,
        role=role,
        host=host,
        architecture=architecture,
        capture_started_clock=capture_started_clock,
        capture_completed_clock=capture_completed_clock,
        machine_id_sha256=counters.machine_id_sha256,
        boot_id=counters.boot_id,
        kernel_release=kernel_release,
        os_release_sha256=os_release_sha256,
        cpu_model=cpu_model,
        logical_cpu_count=logical_cpu_count,
        memory_total_bytes=counters.host.memory_total_bytes,
        network_interface=profile.network.interface,
        interface_mtu_bytes=counters.host.interface_mtu_bytes,
        nic_link_speed_bits_per_second=counters.host.nic_bits_per_second,
        sysctls=sysctls,
        cgroup_path_sha256=counters.cgroup_path_sha256,
        cgroup_cpu_capacity_cores=counters.cgroup.cpu_capacity_cores,
        cgroup_memory_limit_bytes=counters.cgroup.memory_limit_bytes,
        cgroup_pids_limit=counters.cgroup.pids_limit,
        cgroup_constraint_chain_sha256=counters.cgroup.constraint_chain_sha256,
        processes=processes,
        gstreamer=gstreamer,
    )


def _runtime_counter_identity(counters: GeneratorCounters) -> tuple[object, ...]:
    # Keep the capture bracket tied to the same host, workload processes and
    # effective denominator set without treating changing usage counters as identity.
    return (
        counters.machine_id_sha256,
        counters.boot_id,
        counters.cgroup_path_sha256,
        counters.host.memory_total_bytes,
        counters.host.nic_bits_per_second,
        counters.host.interface_mtu_bytes,
        counters.host.ephemeral_port_start,
        counters.host.ephemeral_port_end,
        counters.host.ephemeral_port_capacity,
        counters.host.reserved_ports_sha256,
        counters.cgroup.cpu_capacity_cores,
        counters.cgroup.memory_limit_bytes,
        counters.cgroup.pids_limit,
        counters.cgroup.constraint_chain_sha256,
        tuple(
            (
                item.pid,
                item.executable_sha256,
                item.start_time_ticks,
                item.max_file_descriptors,
            )
            for item in counters.processes
        ),
    )


def _read_process_runtime(root: Path, binding: RuntimeProcessBinding) -> RuntimeProcess:
    body = (root / "proc" / str(binding.pid) / "limits").read_text(encoding="utf-8")
    nofile = _read_limit(body, "Max open files")
    processes = _read_limit(body, "Max processes")
    if not isinstance(nofile[0], int) or not isinstance(nofile[1], int):
        raise ValueError("finite_process_open_file_limit_required")
    return RuntimeProcess(
        pid=binding.pid,
        executable_sha256=binding.executable_sha256,
        start_time_ticks=binding.start_time_ticks,
        max_open_files_soft=nofile[0],
        max_open_files_hard=nofile[1],
        max_processes_soft=processes[0],
        max_processes_hard=processes[1],
    )


def _read_limit(body: str, name: str) -> tuple[LimitValue, LimitValue]:
    match = re.search(
        rf"^{re.escape(name)}\s+(\d+|unlimited)\s+(\d+|unlimited)(?:\s+\S+)?$",
        body,
        re.MULTILINE,
    )
    if match is None:
        raise ValueError("runtime_process_limit_missing")
    return tuple("unlimited" if value == "unlimited" else int(value) for value in match.groups())  # type: ignore[return-value]


def _read_cpu_inventory(root: Path) -> tuple[str, int]:
    body = (root / "proc/cpuinfo").read_text(encoding="utf-8")
    logical_cpu_count = len(re.findall(r"^processor\s*:\s*\d+\s*$", body, re.MULTILINE))
    model = next(
        (
            match.group(1).strip()
            for key in ("model name", "Model", "Hardware")
            if (match := re.search(rf"^{re.escape(key)}\s*:\s*(.+)$", body, re.MULTILINE))
        ),
        "",
    )
    if not model:
        arm_fields = tuple(
            (key, match.group(1).strip())
            for key in ("CPU implementer", "CPU architecture", "CPU variant", "CPU part")
            if (match := re.search(rf"^{re.escape(key)}\s*:\s*(.+)$", body, re.MULTILINE))
        )
        if {key for key, _ in arm_fields} >= {"CPU implementer", "CPU part"}:
            model = " ".join(f"{key}={value}" for key, value in arm_fields)
    if not model:
        for path in (
            root / "proc/device-tree/model",
            root / "sys/devices/virtual/dmi/id/product_name",
        ):
            try:
                model = path.read_bytes().rstrip(b"\x00\r\n").decode("utf-8").strip()
            except FileNotFoundError:
                continue
            if model:
                break
    if logical_cpu_count < 1 or not model or len(model) > 256:
        raise ValueError("runtime_cpu_inventory_invalid")
    return model, logical_cpu_count


def _read_gstreamer_runtime(
    root: Path,
    *,
    pids: tuple[int, ...],
    gst_launch_binary: Path,
    expected_version: str,
    expected_build_id: str,
    expected_architecture: Literal["amd64", "arm64"],
) -> GStreamerRuntime:
    logical_binary, physical_binary = _rooted_absolute(root, gst_launch_binary)
    binary_sha256, _, _ = _sha256_regular_file(physical_binary, executable=True)
    try:
        result = subprocess.run(
            [str(physical_binary), "--version"],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            env={"LC_ALL": "C", "PATH": os.defpath},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("gstreamer_version_probe_failed") from error
    version_match = re.search(r"^GStreamer\s+(\d+\.\d+\.\d+)\s*$", result.stdout, re.MULTILINE)
    if (
        result.returncode != 0
        or version_match is None
        or version_match.group(1) != expected_version
    ):
        raise ValueError("gstreamer_version_mismatch")
    packages = _read_dpkg_gstreamer_packages(root / "var/lib/dpkg/status")
    core = [item for item in packages if item.name == "libgstreamer1.0-0"]
    expected_dpkg_arch = "amd64" if expected_architecture == "amd64" else "arm64"
    if (
        len(core) != 1
        or core[0].version != expected_build_id
        or core[0].architecture != expected_dpkg_arch
    ):
        raise ValueError("gstreamer_package_build_mismatch")
    libraries = _read_loaded_gstreamer_libraries(root, pids)
    return GStreamerRuntime(
        version=expected_version,
        package_build_id=expected_build_id,
        gst_launch_path=logical_binary.as_posix(),
        gst_launch_sha256=binary_sha256,
        packages=packages,
        packages_sha256=_canonical_sha256([item.model_dump(mode="json") for item in packages]),
        loaded_libraries=libraries,
    )


def _read_dpkg_gstreamer_packages(path: Path) -> tuple[RuntimePackage, ...]:
    body = path.read_text(encoding="utf-8")
    packages: list[RuntimePackage] = []
    for paragraph in re.split(r"\n\s*\n", body.strip()):
        fields: dict[str, str] = {}
        for line in paragraph.splitlines():
            key, separator, value = line.partition(":")
            if separator and not line.startswith((" ", "\t")):
                fields[key] = value.strip()
        name = fields.get("Package", "")
        if fields.get("Status") == "install ok installed" and re.match(
            r"^(?:gstreamer1\.0-|libgstreamer|libgst)", name
        ):
            try:
                packages.append(
                    RuntimePackage(
                        name=name,
                        version=fields["Version"],
                        architecture=fields["Architecture"],
                    )
                )
            except KeyError as error:
                raise ValueError("gstreamer_package_inventory_invalid") from error
    if not packages:
        raise ValueError("gstreamer_package_inventory_empty")
    return tuple(sorted(packages, key=lambda item: (item.name, item.architecture)))


def _read_loaded_gstreamer_libraries(
    root: Path, pids: tuple[int, ...]
) -> tuple[RuntimeLibrary, ...]:
    observed: dict[str, tuple[str, int, int, int, int, set[int]]] = {}
    covered: dict[int, bool] = {pid: False for pid in pids}
    for pid in pids:
        for line in (root / "proc" / str(pid) / "maps").read_text(encoding="utf-8").splitlines():
            fields = line.split(maxsplit=5)
            if len(fields) != 6 or not fields[5].startswith("/"):
                continue
            logical_path = fields[5]
            is_gstreamer = (
                PurePosixPath(logical_path).name.startswith("libgst")
                or "/gstreamer-1.0/" in logical_path
            )
            if not is_gstreamer:
                continue
            if logical_path.endswith(" (deleted)"):
                raise ValueError("mapped_gstreamer_library_deleted")
            device_fields = fields[3].split(":")
            if len(device_fields) != 2 or not fields[4].isdigit():
                raise ValueError("mapped_gstreamer_library_identity_invalid")
            physical = _rooted_absolute(root, Path(logical_path))[1]
            digest, size, file_stat = _sha256_regular_file(physical)
            device_major = int(device_fields[0], 16)
            device_minor = int(device_fields[1], 16)
            inode = int(fields[4])
            if (
                os.major(file_stat.st_dev) != device_major
                or os.minor(file_stat.st_dev) != device_minor
                or file_stat.st_ino != inode
            ):
                raise ValueError("mapped_gstreamer_library_changed")
            current = observed.get(logical_path)
            identity = (digest, size, device_major, device_minor, inode)
            if current is not None and current[:5] != identity:
                raise ValueError("mapped_gstreamer_library_identity_changed")
            process_ids = current[5] if current is not None else set()
            process_ids.add(pid)
            observed[logical_path] = (*identity, process_ids)
            if PurePosixPath(logical_path).name.startswith("libgstreamer-1.0.so"):
                covered[pid] = True
    if not all(covered.values()):
        raise ValueError("gstreamer_core_library_not_mapped_by_every_process")
    return tuple(
        RuntimeLibrary(
            path=path,
            sha256=values[0],
            size_bytes=values[1],
            device_major=values[2],
            device_minor=values[3],
            inode=values[4],
            process_ids=tuple(sorted(values[5])),
        )
        for path, values in sorted(observed.items())
    )


def _rooted_absolute(root: Path, path: Path) -> tuple[PurePosixPath, Path]:
    logical = PurePosixPath(path.as_posix())
    if not logical.is_absolute() or ".." in logical.parts:
        raise ValueError("runtime_path_must_be_absolute")
    return logical, root / Path(*logical.parts[1:])


def _read_bounded_text(path: Path) -> str:
    value = path.read_text(encoding="utf-8").strip()
    if "\x00" in value or len(value) > 1024:
        raise ValueError("runtime_text_value_invalid")
    return value


def _normalize_runtime_sysctl(name: str, value: str) -> str:
    stripped = value.strip()
    if name == "net.ipv4.ip_local_port_range":
        return normalize_linux_ephemeral_port_range(stripped)
    if name == "net.ipv4.ip_local_reserved_ports":
        return normalize_linux_reserved_ports(stripped)
    if name not in {path.replace("/", ".") for path in _SYSCTL_PATHS}:
        raise ValueError("runtime_sysctl_name_invalid")
    if re.fullmatch(r"\d+", stripped) is None:
        raise ValueError("runtime_sysctl_value_invalid")
    number = int(stripped)
    if name == "net.ipv4.tcp_tw_reuse":
        if number not in {0, 1, 2}:
            raise ValueError("runtime_sysctl_value_invalid")
    elif number <= 0:
        raise ValueError("runtime_sysctl_value_invalid")
    return str(number)


def _read_os_release_sha256(root: Path) -> str:
    for path in (root / "usr/lib/os-release", root / "etc/os-release"):
        try:
            return _sha256_regular_file(path)[0]
        except FileNotFoundError:
            continue
    raise ValueError("runtime_os_release_missing")


def _sha256_regular_file(
    path: Path, *, executable: bool = False
) -> tuple[str, int, os.stat_result]:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or (executable and before.st_mode & 0o111 == 0):
            raise ValueError("runtime_file_type_or_mode_invalid")
        digest = hashlib.sha256()
        with os.fdopen(os.dup(descriptor), "rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
        ):
            raise ValueError("runtime_file_changed_during_hash")
        return digest.hexdigest(), before.st_size, before
    finally:
        os.close(descriptor)


def _canonical_sha256(payload: object) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
