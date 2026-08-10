from __future__ import annotations

import hashlib
import itertools
import json
import math
import os
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

Percent = Annotated[float, Field(ge=0, le=100)]
Timestamp = Annotated[
    str,
    StringConstraints(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$"),
]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
BootId = Annotated[
    str,
    StringConstraints(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),
]


class ResourceObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    generator_host: Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9._-]{1,253}$")]
    machine_id_sha256: Sha256
    boot_id: BootId
    timestamp: Timestamp
    interval_seconds: Annotated[float, Field(gt=0, le=180)]
    host_cpu_percent: Percent
    host_ram_percent: Percent
    max_process_cpu_percent: Percent
    cgroup_cpu_percent: Percent
    cgroup_ram_percent: Percent
    max_process_fd_percent: Percent
    cgroup_pids_percent: Percent
    network_percent: Percent
    network_packets_per_second: Annotated[float, Field(ge=0)]
    packet_rate_percent: Percent
    interface_mtu_bytes: Annotated[int, Field(ge=576, le=9216)]
    process_count: Annotated[int, Field(gt=0)]
    workload_processes_sha256: Sha256
    cgroup_path_sha256: Sha256


class GeneratorHeadroomSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    generator_host: str
    observations_sha256: Sha256
    machine_id_sha256: Sha256
    boot_id: BootId
    observation_count: int
    elapsed_seconds: Annotated[float, Field(ge=0)]
    max_observation_gap_seconds: Annotated[float, Field(ge=0)]
    max_host_cpu_percent: Percent
    max_host_ram_percent: Percent
    max_process_cpu_percent: Percent
    max_cgroup_cpu_percent: Percent
    max_cgroup_ram_percent: Percent
    max_process_fd_percent: Percent
    max_cgroup_pids_percent: Percent
    max_network_percent: Percent
    max_network_packets_per_second: Annotated[float, Field(ge=0)]
    max_packet_rate_percent: Percent
    interface_mtu_bytes: Annotated[int, Field(ge=576, le=9216)]
    process_count: Annotated[int, Field(gt=0)]
    workload_processes_sha256: Sha256
    cgroup_path_sha256: Sha256
    valid: bool
    invalid_reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class HostCounters:
    cpu_total_ticks: int
    cpu_idle_ticks: int
    memory_total_bytes: int
    memory_available_bytes: int
    network_rx_bytes: int
    network_tx_bytes: int
    network_rx_packets: int
    network_tx_packets: int
    nic_bits_per_second: int
    interface_mtu_bytes: int


@dataclass(frozen=True, slots=True)
class ProcessCounters:
    pid: int
    cpu_ticks: int
    rss_bytes: int
    open_file_descriptors: int
    max_file_descriptors: int
    executable_sha256: str
    start_time_ticks: int


@dataclass(frozen=True, slots=True)
class CgroupCounters:
    cpu_usage_usec: int
    cpu_capacity_cores: float
    memory_current_bytes: int
    memory_limit_bytes: int
    pids_current: int
    pids_limit: int


@dataclass(frozen=True, slots=True)
class GeneratorCounters:
    host: HostCounters
    processes: tuple[ProcessCounters, ...]
    cgroup: CgroupCounters
    machine_id_sha256: str
    boot_id: str
    clock_ticks_per_second: int
    cgroup_path_sha256: str

    def observation_since(
        self,
        previous: GeneratorCounters,
        *,
        generator_host: str,
        elapsed_seconds: float,
        timestamp: str,
    ) -> ResourceObservation:
        total_delta = self.host.cpu_total_ticks - previous.host.cpu_total_ticks
        idle_delta = self.host.cpu_idle_ticks - previous.host.cpu_idle_ticks
        rx_delta = self.host.network_rx_bytes - previous.host.network_rx_bytes
        tx_delta = self.host.network_tx_bytes - previous.host.network_tx_bytes
        rx_packets_delta = self.host.network_rx_packets - previous.host.network_rx_packets
        tx_packets_delta = self.host.network_tx_packets - previous.host.network_tx_packets
        previous_processes = {item.pid: item for item in previous.processes}
        if (
            elapsed_seconds <= 0
            or total_delta <= 0
            or idle_delta < 0
            or idle_delta > total_delta
            or rx_delta < 0
            or tx_delta < 0
            or rx_packets_delta < 0
            or tx_packets_delta < 0
            or self.host.memory_total_bytes <= 0
            or not 0 <= self.host.memory_available_bytes <= self.host.memory_total_bytes
            or self.host.nic_bits_per_second <= 0
            or not 576 <= self.host.interface_mtu_bytes <= 9216
            or self.host.interface_mtu_bytes != previous.host.interface_mtu_bytes
            or self.machine_id_sha256 != previous.machine_id_sha256
            or self.boot_id != previous.boot_id
            or self.clock_ticks_per_second <= 0
            or self.cgroup_path_sha256 != previous.cgroup_path_sha256
            or {item.pid for item in self.processes} != set(previous_processes)
            or self.cgroup.cpu_capacity_cores <= 0
            or self.cgroup.memory_limit_bytes <= 0
            or self.cgroup.pids_limit <= 0
        ):
            raise ValueError("invalid_or_non_monotonic_generator_counters")

        process_cpu: list[float] = []
        fd_percent: list[float] = []
        for process in self.processes:
            prior = previous_processes[process.pid]
            tick_delta = process.cpu_ticks - prior.cpu_ticks
            if (
                tick_delta < 0
                or process.rss_bytes < 0
                or process.max_file_descriptors <= 0
                or process.executable_sha256 != prior.executable_sha256
                or process.start_time_ticks != prior.start_time_ticks
                or not 0 <= process.open_file_descriptors <= process.max_file_descriptors
            ):
                raise ValueError("invalid_or_non_monotonic_generator_counters")
            process_cpu.append(tick_delta / self.clock_ticks_per_second / elapsed_seconds * 100)
            fd_percent.append(process.open_file_descriptors / process.max_file_descriptors * 100)

        cgroup_cpu_delta = self.cgroup.cpu_usage_usec - previous.cgroup.cpu_usage_usec
        if (
            cgroup_cpu_delta < 0
            or not 0 <= self.cgroup.memory_current_bytes <= self.cgroup.memory_limit_bytes
            or not 0 <= self.cgroup.pids_current <= self.cgroup.pids_limit
        ):
            raise ValueError("invalid_or_non_monotonic_generator_counters")
        host_cpu = (total_delta - idle_delta) / total_delta * 100
        host_ram = (
            (self.host.memory_total_bytes - self.host.memory_available_bytes)
            / self.host.memory_total_bytes
            * 100
        )
        cgroup_cpu = (
            cgroup_cpu_delta / 1_000_000 / elapsed_seconds / self.cgroup.cpu_capacity_cores * 100
        )
        network = (
            max(rx_delta, tx_delta) * 8 / elapsed_seconds / self.host.nic_bits_per_second * 100
        )
        network_packets_per_second = max(rx_packets_delta, tx_packets_delta) / elapsed_seconds
        line_rate_packets_per_second = self.host.nic_bits_per_second / (
            (self.host.interface_mtu_bytes + 38) * 8
        )
        process_binding = [
            {
                "pid": item.pid,
                "executable_sha256": item.executable_sha256,
                "start_time_ticks": item.start_time_ticks,
            }
            for item in sorted(self.processes, key=lambda item: item.pid)
        ]
        processes_sha256 = hashlib.sha256(
            json.dumps(process_binding, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return ResourceObservation(
            generator_host=generator_host,
            machine_id_sha256=self.machine_id_sha256,
            boot_id=self.boot_id,
            timestamp=timestamp,
            interval_seconds=elapsed_seconds,
            host_cpu_percent=min(host_cpu, 100),
            host_ram_percent=min(host_ram, 100),
            max_process_cpu_percent=min(max(process_cpu, default=0), 100),
            cgroup_cpu_percent=min(cgroup_cpu, 100),
            cgroup_ram_percent=(
                self.cgroup.memory_current_bytes / self.cgroup.memory_limit_bytes * 100
            ),
            max_process_fd_percent=max(fd_percent, default=0),
            cgroup_pids_percent=self.cgroup.pids_current / self.cgroup.pids_limit * 100,
            network_percent=min(network, 100),
            network_packets_per_second=network_packets_per_second,
            packet_rate_percent=min(
                network_packets_per_second / line_rate_packets_per_second * 100,
                100,
            ),
            interface_mtu_bytes=self.host.interface_mtu_bytes,
            process_count=len(self.processes),
            workload_processes_sha256=processes_sha256,
            cgroup_path_sha256=self.cgroup_path_sha256,
        )


def summarize_generator_headroom(
    observations: list[ResourceObservation] | tuple[ResourceObservation, ...],
    *,
    expected_generator_host: str | None = None,
    minimum_duration_seconds: float = 1,
    expected_interval_seconds: float = 1,
    maximum_gap_factor: float = 1.5,
    observations_sha256: str,
) -> GeneratorHeadroomSummary:
    if (
        not observations
        or minimum_duration_seconds < 0
        or expected_interval_seconds <= 0
        or maximum_gap_factor < 1
    ):
        raise ValueError("generator_observations_empty")
    hosts = {item.generator_host for item in observations}
    machines = {item.machine_id_sha256 for item in observations}
    boots = {item.boot_id for item in observations}
    bindings = {item.workload_processes_sha256 for item in observations}
    mtus = {item.interface_mtu_bytes for item in observations}
    process_counts = {item.process_count for item in observations}
    cgroups = {item.cgroup_path_sha256 for item in observations}
    if (
        len(hosts) != 1
        or len(machines) != 1
        or len(boots) != 1
        or len(bindings) != 1
        or len(mtus) != 1
        or len(process_counts) != 1
        or len(cgroups) != 1
    ):
        raise ValueError("generator_observation_identity_changed")
    generator_host = next(iter(hosts))
    if expected_generator_host is not None and generator_host != expected_generator_host:
        raise ValueError("generator_observation_host_mismatch")
    timestamps = [datetime.fromisoformat(item.timestamp) for item in observations]
    if timestamps != sorted(timestamps) or len(timestamps) != len(set(timestamps)):
        raise ValueError("generator_observation_timestamps_not_monotonic")
    timestamp_gaps = [
        (current - previous).total_seconds() for previous, current in itertools.pairwise(timestamps)
    ]
    maximum_allowed_gap = expected_interval_seconds * maximum_gap_factor
    max_gap = max(
        [*(item.interval_seconds for item in observations), *timestamp_gaps],
        default=0,
    )
    elapsed_seconds = sum(item.interval_seconds for item in observations)
    expected_count = math.ceil(minimum_duration_seconds / expected_interval_seconds)
    reasons: list[str] = []
    if len(observations) < max(2, expected_count) or elapsed_seconds < minimum_duration_seconds:
        reasons.append("generator_observation_window_too_short")
    if max_gap > maximum_allowed_gap:
        reasons.append("generator_observation_gap_too_large")

    maxima = {
        "host_cpu": max(item.host_cpu_percent for item in observations),
        "host_ram": max(item.host_ram_percent for item in observations),
        "process_cpu": max(item.max_process_cpu_percent for item in observations),
        "cgroup_cpu": max(item.cgroup_cpu_percent for item in observations),
        "cgroup_ram": max(item.cgroup_ram_percent for item in observations),
        "process_fd": max(item.max_process_fd_percent for item in observations),
        "cgroup_pids": max(item.cgroup_pids_percent for item in observations),
        "network": max(item.network_percent for item in observations),
        "packet_rate": max(item.packet_rate_percent for item in observations),
    }
    for resource, value in maxima.items():
        if value >= 70:
            reasons.append(f"generator_{resource}_headroom_below_30_percent")
    return GeneratorHeadroomSummary(
        generator_host=generator_host,
        observations_sha256=observations_sha256,
        machine_id_sha256=next(iter(machines)),
        boot_id=next(iter(boots)),
        observation_count=len(observations),
        elapsed_seconds=elapsed_seconds,
        max_observation_gap_seconds=max_gap,
        max_host_cpu_percent=maxima["host_cpu"],
        max_host_ram_percent=maxima["host_ram"],
        max_process_cpu_percent=maxima["process_cpu"],
        max_cgroup_cpu_percent=maxima["cgroup_cpu"],
        max_cgroup_ram_percent=maxima["cgroup_ram"],
        max_process_fd_percent=maxima["process_fd"],
        max_cgroup_pids_percent=maxima["cgroup_pids"],
        max_network_percent=maxima["network"],
        max_network_packets_per_second=max(
            item.network_packets_per_second for item in observations
        ),
        max_packet_rate_percent=maxima["packet_rate"],
        interface_mtu_bytes=next(iter(mtus)),
        process_count=next(iter(process_counts)),
        workload_processes_sha256=next(iter(bindings)),
        cgroup_path_sha256=next(iter(cgroups)),
        valid=not reasons,
        invalid_reasons=tuple(reasons),
    )


def load_observations(path: Path) -> tuple[ResourceObservation, ...]:
    observations: list[ResourceObservation] = []
    with path.open(encoding="utf-8") as source:
        for line in source:
            if not line.strip():
                raise ValueError("blank_observation_line")
            observations.append(ResourceObservation.model_validate(json.loads(line)))
    if not observations:
        raise ValueError("generator_observations_empty")
    return tuple(observations)


def _read_integer(path: Path) -> int:
    return int(path.read_text(encoding="utf-8").strip())


def _read_host_counters(root: Path, *, interface: str) -> HostCounters:
    if re.fullmatch(r"[a-zA-Z0-9_.:-]{1,15}", interface) is None:
        raise ValueError("invalid_network_interface")
    cpu_line = (root / "proc/stat").read_text(encoding="utf-8").splitlines()[0]
    cpu_fields = cpu_line.split()
    if not cpu_fields or cpu_fields[0] != "cpu" or len(cpu_fields) < 6:
        raise ValueError("invalid_proc_stat")
    cpu_values = [int(value) for value in cpu_fields[1:]]
    memory: dict[str, int] = {}
    for line in (root / "proc/meminfo").read_text(encoding="utf-8").splitlines():
        name, separator, raw_value = line.partition(":")
        if separator and name in {"MemTotal", "MemAvailable"}:
            fields = raw_value.split()
            if len(fields) != 2 or fields[1] != "kB":
                raise ValueError("invalid_proc_meminfo")
            memory[name] = int(fields[0]) * 1024
    if set(memory) != {"MemTotal", "MemAvailable"}:
        raise ValueError("invalid_proc_meminfo")
    interface_root = root / "sys/class/net" / interface
    return HostCounters(
        cpu_total_ticks=sum(cpu_values),
        cpu_idle_ticks=cpu_values[3] + cpu_values[4],
        memory_total_bytes=memory["MemTotal"],
        memory_available_bytes=memory["MemAvailable"],
        network_rx_bytes=_read_integer(interface_root / "statistics/rx_bytes"),
        network_tx_bytes=_read_integer(interface_root / "statistics/tx_bytes"),
        network_rx_packets=_read_integer(interface_root / "statistics/rx_packets"),
        network_tx_packets=_read_integer(interface_root / "statistics/tx_packets"),
        nic_bits_per_second=_read_integer(interface_root / "speed") * 1_000_000,
        interface_mtu_bytes=_read_integer(interface_root / "mtu"),
    )


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_process_counters(root: Path, pid: int) -> ProcessCounters:
    if pid < 1:
        raise ValueError("invalid_generator_pid")
    process_root = root / "proc" / str(pid)
    stat_body = (process_root / "stat").read_text(encoding="utf-8")
    close = stat_body.rfind(")")
    if close < 1:
        raise ValueError("invalid_process_stat")
    fields = stat_body[close + 2 :].split()
    if len(fields) < 13:
        raise ValueError("invalid_process_stat")
    cpu_ticks = int(fields[11]) + int(fields[12])
    start_time_ticks = int(fields[19])
    rss_match = re.search(
        r"^VmRSS:\s+(\d+)\s+kB$",
        (process_root / "status").read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    limit_match = re.search(
        r"^Max open files\s+(\d+)\s+\d+\s+\S+$",
        (process_root / "limits").read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    if rss_match is None or limit_match is None:
        raise ValueError("invalid_process_limits_or_status")
    return ProcessCounters(
        pid=pid,
        cpu_ticks=cpu_ticks,
        rss_bytes=int(rss_match.group(1)) * 1024,
        open_file_descriptors=len(tuple((process_root / "fd").iterdir())),
        max_file_descriptors=int(limit_match.group(1)),
        executable_sha256=_hash_file((process_root / "exe").resolve(strict=True)),
        start_time_ticks=start_time_ticks,
    )


def _safe_cgroup_root(root: Path, cgroup: str) -> Path:
    value = PurePosixPath(cgroup)
    if value.is_absolute() or value == PurePosixPath(".") or ".." in value.parts:
        raise ValueError("invalid_cgroup_path")
    return root / "sys/fs/cgroup" / Path(*value.parts)


def _read_cgroup_counters(root: Path, cgroup: str) -> CgroupCounters:
    cgroup_root = _safe_cgroup_root(root, cgroup)
    cpu_stat = {
        fields[0]: int(fields[1])
        for line in (cgroup_root / "cpu.stat").read_text(encoding="utf-8").splitlines()
        if len(fields := line.split()) == 2
    }
    cpu_max = (cgroup_root / "cpu.max").read_text(encoding="utf-8").split()
    if "usage_usec" not in cpu_stat or len(cpu_max) != 2 or cpu_max[0] == "max":
        raise ValueError("finite_cgroup_cpu_limit_required")
    memory_max = (cgroup_root / "memory.max").read_text(encoding="utf-8").strip()
    pids_max = (cgroup_root / "pids.max").read_text(encoding="utf-8").strip()
    if memory_max == "max" or pids_max == "max":
        raise ValueError("finite_cgroup_memory_and_pids_limits_required")
    return CgroupCounters(
        cpu_usage_usec=cpu_stat["usage_usec"],
        cpu_capacity_cores=int(cpu_max[0]) / int(cpu_max[1]),
        memory_current_bytes=_read_integer(cgroup_root / "memory.current"),
        memory_limit_bytes=int(memory_max),
        pids_current=_read_integer(cgroup_root / "pids.current"),
        pids_limit=int(pids_max),
    )


def read_linux_generator_counters(
    root: Path,
    *,
    interface: str,
    pids: tuple[int, ...],
    cgroup: str,
    expected_executables: dict[int, str],
    expected_mtu_bytes: int,
) -> GeneratorCounters:
    if re.fullmatch(r"[a-zA-Z0-9_.:-]{1,15}", interface) is None:
        raise ValueError("invalid_network_interface")
    if not pids or len(set(pids)) != len(pids):
        raise ValueError("generator_pids_empty_or_duplicate")
    if set(pids) != set(expected_executables):
        raise ValueError("generator_executable_binding_incomplete")
    cgroup_root = _safe_cgroup_root(root, cgroup)
    cgroup_pids = {
        int(line)
        for line in (cgroup_root / "cgroup.procs").read_text(encoding="utf-8").splitlines()
        if line
    }
    if cgroup_pids != set(pids):
        raise ValueError("generator_cgroup_process_set_mismatch")
    expected_cgroup = "/" + PurePosixPath(cgroup).as_posix()
    for pid in pids:
        membership = (root / "proc" / str(pid) / "cgroup").read_text(encoding="utf-8").splitlines()
        if membership != [f"0::{expected_cgroup}"]:
            raise ValueError("generator_process_cgroup_membership_mismatch")
    machine_id = (root / "etc/machine-id").read_text(encoding="utf-8").strip()
    boot_id = (root / "proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
    host = _read_host_counters(root, interface=interface)
    if host.interface_mtu_bytes != expected_mtu_bytes:
        raise ValueError("generator_interface_mtu_mismatch")
    processes = tuple(_read_process_counters(root, pid) for pid in sorted(pids))
    if any(process.executable_sha256 != expected_executables[process.pid] for process in processes):
        raise ValueError("generator_process_executable_digest_mismatch")
    return GeneratorCounters(
        host=host,
        processes=processes,
        cgroup=_read_cgroup_counters(root, cgroup),
        machine_id_sha256=hashlib.sha256(machine_id.encode()).hexdigest(),
        boot_id=boot_id,
        clock_ticks_per_second=int(os.sysconf("SC_CLK_TCK")),
        cgroup_path_sha256=hashlib.sha256(expected_cgroup.encode()).hexdigest(),
    )


def sample_linux_generator_resources(
    *,
    root: Path,
    generator_host: str,
    interface: str,
    pids: tuple[int, ...],
    cgroup: str,
    expected_executables: dict[int, str],
    expected_mtu_bytes: int,
    output: Path,
    duration_seconds: int,
    interval_seconds: float,
) -> int:
    if duration_seconds < 1 or interval_seconds <= 0:
        raise ValueError("invalid_sampling_duration")
    try:
        output.parent.mkdir(mode=0o750, parents=False, exist_ok=False)
        output.parent.chmod(0o750)
    except FileExistsError:
        if not output.parent.is_dir():
            raise
    previous = read_linux_generator_counters(
        root,
        interface=interface,
        pids=pids,
        cgroup=cgroup,
        expected_executables=expected_executables,
        expected_mtu_bytes=expected_mtu_bytes,
    )
    previous_at = time.monotonic()
    deadline = previous_at + duration_seconds
    observation_count = 0
    with output.open("x", encoding="utf-8") as destination:
        output.chmod(0o640)
        while previous_at < deadline:
            time.sleep(min(interval_seconds, deadline - previous_at))
            observed_at = time.monotonic()
            current = read_linux_generator_counters(
                root,
                interface=interface,
                pids=pids,
                cgroup=cgroup,
                expected_executables=expected_executables,
                expected_mtu_bytes=expected_mtu_bytes,
            )
            timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
            observation = current.observation_since(
                previous,
                generator_host=generator_host,
                elapsed_seconds=observed_at - previous_at,
                timestamp=timestamp,
            )
            destination.write(json.dumps(observation.model_dump(mode="json")) + "\n")
            destination.flush()
            os.fsync(destination.fileno())
            observation_count += 1
            previous = current
            previous_at = observed_at
    return observation_count
