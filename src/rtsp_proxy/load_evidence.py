from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

Percent = Annotated[float, Field(ge=0, le=100)]
Timestamp = Annotated[
    str,
    StringConstraints(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$"),
]


class ResourceObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    timestamp: Timestamp
    cpu_percent: Percent
    ram_percent: Percent
    fd_percent: Percent
    network_percent: Percent


class GeneratorHeadroomSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    observation_count: int
    elapsed_seconds: Annotated[float, Field(ge=0)]
    max_cpu_percent: Percent
    max_ram_percent: Percent
    max_fd_percent: Percent
    max_network_percent: Percent
    valid: bool
    invalid_reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class HostCounters:
    cpu_total_ticks: int
    cpu_idle_ticks: int
    memory_total_bytes: int
    memory_available_bytes: int
    allocated_file_descriptors: int
    max_file_descriptors: int
    network_rx_bytes: int
    network_tx_bytes: int
    nic_bits_per_second: int

    def observation_since(
        self,
        previous: HostCounters,
        *,
        elapsed_seconds: float,
        timestamp: str,
    ) -> ResourceObservation:
        total_delta = self.cpu_total_ticks - previous.cpu_total_ticks
        idle_delta = self.cpu_idle_ticks - previous.cpu_idle_ticks
        rx_delta = self.network_rx_bytes - previous.network_rx_bytes
        tx_delta = self.network_tx_bytes - previous.network_tx_bytes
        if (
            elapsed_seconds <= 0
            or total_delta <= 0
            or idle_delta < 0
            or idle_delta > total_delta
            or rx_delta < 0
            or tx_delta < 0
            or self.memory_total_bytes <= 0
            or not 0 <= self.memory_available_bytes <= self.memory_total_bytes
            or self.max_file_descriptors <= 0
            or not 0 <= self.allocated_file_descriptors <= self.max_file_descriptors
            or self.nic_bits_per_second <= 0
        ):
            raise ValueError("invalid_or_non_monotonic_host_counters")

        cpu_percent = (total_delta - idle_delta) / total_delta * 100
        ram_percent = (
            (self.memory_total_bytes - self.memory_available_bytes)
            / self.memory_total_bytes
            * 100
        )
        fd_percent = self.allocated_file_descriptors / self.max_file_descriptors * 100
        network_percent = (
            max(rx_delta, tx_delta)
            * 8
            / elapsed_seconds
            / self.nic_bits_per_second
            * 100
        )
        return ResourceObservation(
            timestamp=timestamp,
            cpu_percent=cpu_percent,
            ram_percent=ram_percent,
            fd_percent=fd_percent,
            network_percent=min(network_percent, 100),
        )


def summarize_generator_headroom(
    observations: list[ResourceObservation] | tuple[ResourceObservation, ...],
    *,
    minimum_duration_seconds: float = 1,
) -> GeneratorHeadroomSummary:
    if not observations or minimum_duration_seconds < 0:
        raise ValueError("generator_observations_empty")
    timestamps = [datetime.fromisoformat(item.timestamp) for item in observations]
    if timestamps != sorted(timestamps):
        raise ValueError("generator_observation_timestamps_not_monotonic")
    elapsed_seconds = (timestamps[-1] - timestamps[0]).total_seconds()
    max_cpu = max(item.cpu_percent for item in observations)
    max_ram = max(item.ram_percent for item in observations)
    max_fd = max(item.fd_percent for item in observations)
    max_network = max(item.network_percent for item in observations)
    reasons: list[str] = []
    if len(observations) < 2 or elapsed_seconds < minimum_duration_seconds:
        reasons.append("generator_observation_window_too_short")
    for value, reason in (
        (max_cpu, "generator_cpu_headroom_below_30_percent"),
        (max_ram, "generator_ram_headroom_below_30_percent"),
        (max_fd, "generator_fd_headroom_below_30_percent"),
        (max_network, "generator_network_headroom_below_30_percent"),
    ):
        if value >= 70:
            reasons.append(reason)
    return GeneratorHeadroomSummary(
        observation_count=len(observations),
        elapsed_seconds=elapsed_seconds,
        max_cpu_percent=max_cpu,
        max_ram_percent=max_ram,
        max_fd_percent=max_fd,
        max_network_percent=max_network,
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


def read_linux_host_counters(root: Path, *, interface: str) -> HostCounters:
    if re.fullmatch(r"[a-zA-Z0-9_.:-]{1,15}", interface) is None:
        raise ValueError("invalid_network_interface")

    cpu_line = (root / "proc/stat").read_text(encoding="utf-8").splitlines()[0]
    cpu_fields = cpu_line.split()
    if not cpu_fields or cpu_fields[0] != "cpu" or len(cpu_fields) < 6:
        raise ValueError("invalid_proc_stat")
    cpu_values = [int(value) for value in cpu_fields[1:]]
    cpu_total_ticks = sum(cpu_values)
    cpu_idle_ticks = cpu_values[3] + cpu_values[4]

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

    file_nr = (root / "proc/sys/fs/file-nr").read_text(encoding="utf-8").split()
    if len(file_nr) != 3:
        raise ValueError("invalid_file_nr")
    max_file_descriptors = _read_integer(root / "proc/sys/fs/file-max")
    if int(file_nr[2]) != max_file_descriptors:
        raise ValueError("file_descriptor_limit_mismatch")

    interface_root = root / "sys/class/net" / interface
    nic_megabits_per_second = _read_integer(interface_root / "speed")
    return HostCounters(
        cpu_total_ticks=cpu_total_ticks,
        cpu_idle_ticks=cpu_idle_ticks,
        memory_total_bytes=memory["MemTotal"],
        memory_available_bytes=memory["MemAvailable"],
        allocated_file_descriptors=int(file_nr[0]),
        max_file_descriptors=max_file_descriptors,
        network_rx_bytes=_read_integer(interface_root / "statistics/rx_bytes"),
        network_tx_bytes=_read_integer(interface_root / "statistics/tx_bytes"),
        nic_bits_per_second=nic_megabits_per_second * 1_000_000,
    )


def sample_linux_host_resources(
    *,
    root: Path,
    interface: str,
    output: Path,
    duration_seconds: int,
    interval_seconds: float = 1,
) -> int:
    if duration_seconds < 1 or interval_seconds <= 0:
        raise ValueError("invalid_sampling_duration")
    try:
        output.parent.mkdir(mode=0o750, parents=False, exist_ok=False)
        output.parent.chmod(0o750)
    except FileExistsError:
        if not output.parent.is_dir():
            raise
    previous = read_linux_host_counters(root, interface=interface)
    previous_at = time.monotonic()
    deadline = previous_at + duration_seconds + interval_seconds
    observation_count = 0
    with output.open("x", encoding="utf-8") as destination:
        output.chmod(0o640)
        while previous_at < deadline:
            time.sleep(interval_seconds)
            observed_at = time.monotonic()
            current = read_linux_host_counters(root, interface=interface)
            timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
            observation = current.observation_since(
                previous,
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
