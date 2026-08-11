from __future__ import annotations

import ctypes
import hashlib
import itertools
import json
import math
import os
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal, Self, cast

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

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
SutMetricFamily = Literal[
    "paths",
    "paths_inbound_frames_in_error",
    "rtsp_sessions",
    "rtsp_sessions_inbound_rtp_packets",
    "rtsp_sessions_inbound_rtcp_packets_in_error",
    "rtsp_sessions_inbound_rtp_packets_in_error",
    "rtsp_sessions_inbound_rtp_packets_lost",
    "rtsp_sessions_outbound_rtp_packets",
    "rtsp_sessions_outbound_rtp_packets_discarded",
    "rtsp_sessions_outbound_rtp_packets_reported_lost",
    "rtsp_sessions_rtcp_packets_in_error",
    "rtsp_sessions_rtp_packets_in_error",
    "rtsp_sessions_rtp_packets_lost",
]
REQUIRED_SUT_METRIC_FAMILIES: tuple[SutMetricFamily, ...] = (
    "paths",
    "paths_inbound_frames_in_error",
    "rtsp_sessions",
    "rtsp_sessions_inbound_rtcp_packets_in_error",
    "rtsp_sessions_inbound_rtp_packets",
    "rtsp_sessions_inbound_rtp_packets_in_error",
    "rtsp_sessions_inbound_rtp_packets_lost",
    "rtsp_sessions_outbound_rtp_packets",
    "rtsp_sessions_outbound_rtp_packets_discarded",
    "rtsp_sessions_outbound_rtp_packets_reported_lost",
    "rtsp_sessions_rtcp_packets_in_error",
    "rtsp_sessions_rtp_packets_in_error",
    "rtsp_sessions_rtp_packets_lost",
)

SessionCounterField = Literal[
    "inbound_rtcp_packets_in_error",
    "inbound_rtp_packets",
    "inbound_rtp_packets_in_error",
    "inbound_rtp_packets_lost",
    "outbound_rtp_packets",
    "outbound_rtp_packets_discarded",
    "outbound_rtp_packets_reported_lost",
    "rtcp_packets_in_error",
    "rtp_packets_in_error",
    "rtp_packets_lost",
]
SESSION_COUNTER_FIELDS: tuple[SessionCounterField, ...] = (
    "inbound_rtcp_packets_in_error",
    "inbound_rtp_packets",
    "inbound_rtp_packets_in_error",
    "inbound_rtp_packets_lost",
    "outbound_rtp_packets",
    "outbound_rtp_packets_discarded",
    "outbound_rtp_packets_reported_lost",
    "rtcp_packets_in_error",
    "rtp_packets_in_error",
    "rtp_packets_lost",
)


class KernelClockProof(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    observed_at_unix_ms: Annotated[int, Field(gt=0)]
    synchronized: bool
    state: Annotated[int, Field(ge=0)]
    status: Annotated[int, Field(ge=0)]
    max_error_ms: Annotated[float, Field(ge=0)]


class _Timeval(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]


class _Timex(ctypes.Structure):
    _fields_ = [
        ("modes", ctypes.c_uint),
        ("offset", ctypes.c_long),
        ("freq", ctypes.c_long),
        ("maxerror", ctypes.c_long),
        ("esterror", ctypes.c_long),
        ("status", ctypes.c_int),
        ("constant", ctypes.c_long),
        ("precision", ctypes.c_long),
        ("tolerance", ctypes.c_long),
        ("time", _Timeval),
        ("tick", ctypes.c_long),
        ("ppsfreq", ctypes.c_long),
        ("jitter", ctypes.c_long),
        ("shift", ctypes.c_int),
        ("stabil", ctypes.c_long),
        ("jitcnt", ctypes.c_long),
        ("calcnt", ctypes.c_long),
        ("errcnt", ctypes.c_long),
        ("stbcnt", ctypes.c_long),
        ("tai", ctypes.c_int),
        ("padding", ctypes.c_int * 11),
    ]


def prove_linux_clock(maximum_error_ms: float) -> KernelClockProof:
    """Return a fail-closed kernel synchronization proof for this Linux host."""
    if sys.platform != "linux" or maximum_error_ms <= 0:
        raise ValueError("linux_clock_proof_unavailable")
    libc = ctypes.CDLL(None, use_errno=True)
    adjtimex = libc.adjtimex
    adjtimex.argtypes = [ctypes.POINTER(_Timex)]
    adjtimex.restype = ctypes.c_int
    value = _Timex()
    state = int(adjtimex(ctypes.byref(value)))
    if state < 0:
        raise ValueError("linux_clock_proof_failed")
    max_error_ms = float(max(value.maxerror, value.esterror)) / 1000
    synchronized = state != 5 and value.status & 0x0040 == 0 and max_error_ms <= maximum_error_ms
    proof = KernelClockProof(
        observed_at_unix_ms=time.time_ns() // 1_000_000,
        synchronized=synchronized,
        state=state,
        status=int(value.status),
        max_error_ms=max_error_ms,
    )
    if not synchronized:
        raise ValueError("linux_clock_not_synchronized")
    return proof


class SessionMetricSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    identity_sha256: Sha256
    state: Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9_-]{1,32}$")]
    observed_counter_fields: tuple[SessionCounterField, ...]
    inbound_rtcp_packets_in_error: Annotated[int, Field(ge=0)]
    inbound_rtp_packets: Annotated[int, Field(ge=0)]
    outbound_rtp_packets: Annotated[int, Field(ge=0)]
    inbound_rtp_packets_lost: Annotated[int, Field(ge=0)]
    inbound_rtp_packets_in_error: Annotated[int, Field(ge=0)]
    outbound_rtp_packets_discarded: Annotated[int, Field(ge=0)]
    outbound_rtp_packets_reported_lost: Annotated[int, Field(ge=0)]
    rtcp_packets_in_error: Annotated[int, Field(ge=0)]
    rtp_packets_in_error: Annotated[int, Field(ge=0)]
    rtp_packets_lost: Annotated[int, Field(ge=0)]

    @model_validator(mode="after")
    def validate_counter_set(self) -> Self:
        if self.state not in {"idle", "publish", "read"}:
            raise ValueError("sut_session_state_invalid")
        if tuple(sorted(set(self.observed_counter_fields))) != self.observed_counter_fields or set(
            self.observed_counter_fields
        ) != set(SESSION_COUNTER_FIELDS):
            raise ValueError("sut_session_counter_set_incomplete")
        return self


class PathMetricSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    identity_sha256: Sha256
    state: Literal["notReady", "ready"]
    inbound_frames_in_error: Annotated[int, Field(ge=0)]


class RuntimeProcessBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    pid: Annotated[int, Field(gt=0)]
    executable_sha256: Sha256
    start_time_ticks: Annotated[int, Field(gt=0)]


class RuntimeProcessLimit(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    pid: Annotated[int, Field(gt=0)]
    max_open_files: Annotated[int, Field(gt=0)]


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
    socket_percent: Percent
    ephemeral_port_start: Annotated[int, Field(ge=1, le=65535)]
    ephemeral_port_end: Annotated[int, Field(ge=1, le=65535)]
    ephemeral_port_capacity: Annotated[int, Field(gt=0, le=65535)]
    reserved_ports_sha256: Sha256
    cgroup_pids_percent: Percent
    network_percent: Percent
    network_packets_per_second: Annotated[float, Field(ge=0)]
    packet_rate_percent: Percent
    interface_mtu_bytes: Annotated[int, Field(ge=576, le=9216)]
    memory_total_bytes: Annotated[int, Field(gt=0)]
    nic_link_speed_bits_per_second: Annotated[int, Field(gt=0)]
    cgroup_cpu_capacity_cores: Annotated[float, Field(gt=0)]
    cgroup_memory_limit_bytes: Annotated[int, Field(gt=0)]
    cgroup_pids_limit: Annotated[int, Field(gt=0)]
    process_count: Annotated[int, Field(gt=0)]
    workload_processes: tuple[RuntimeProcessBinding, ...]
    workload_processes_sha256: Sha256
    workload_process_limits: tuple[RuntimeProcessLimit, ...]
    cgroup_path_sha256: Sha256
    cgroup_constraint_chain_sha256: Sha256

    @model_validator(mode="after")
    def validate_ephemeral_range(self) -> Self:
        if (
            self.ephemeral_port_end < self.ephemeral_port_start
            or self.ephemeral_port_capacity
            > self.ephemeral_port_end - self.ephemeral_port_start + 1
        ):
            raise ValueError("ephemeral_port_range_invalid")
        if (
            len(self.workload_processes) != self.process_count
            or tuple(sorted(self.workload_processes, key=lambda item: item.pid))
            != self.workload_processes
            or len({item.pid for item in self.workload_processes}) != self.process_count
            or _process_bindings_sha256(self.workload_processes) != self.workload_processes_sha256
            or tuple(item.pid for item in self.workload_process_limits)
            != tuple(item.pid for item in self.workload_processes)
        ):
            raise ValueError("workload_process_binding_invalid")
        return self


class GeneratorHeadroomSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    generator_host: str
    headroom_policy: Literal["functional-under-70", "spike0-capacity"]
    observations_sha256: Sha256
    machine_id_sha256: Sha256
    boot_id: BootId
    observation_count: int
    elapsed_seconds: Annotated[float, Field(ge=0)]
    measurement_start_unix_ms: Annotated[int, Field(gt=0)] | None
    measurement_end_unix_ms: Annotated[int, Field(gt=0)] | None
    soak_end_unix_ms: Annotated[int, Field(gt=0)] | None
    soak_observation_count: Annotated[int, Field(ge=0)]
    soak_elapsed_seconds: Annotated[float, Field(ge=0)]
    soak_maxima_percent: dict[str, Percent]
    max_observation_gap_seconds: Annotated[float, Field(ge=0)]
    max_host_cpu_percent: Percent
    max_host_ram_percent: Percent
    max_process_cpu_percent: Percent
    max_cgroup_cpu_percent: Percent
    max_cgroup_ram_percent: Percent
    max_process_fd_percent: Percent
    max_socket_percent: Percent
    ephemeral_port_start: Annotated[int, Field(ge=1, le=65535)]
    ephemeral_port_end: Annotated[int, Field(ge=1, le=65535)]
    ephemeral_port_capacity: Annotated[int, Field(gt=0, le=65535)]
    reserved_ports_sha256: Sha256
    max_cgroup_pids_percent: Percent
    max_network_percent: Percent
    max_network_packets_per_second: Annotated[float, Field(ge=0)]
    max_packet_rate_percent: Percent
    interface_mtu_bytes: Annotated[int, Field(ge=576, le=9216)]
    memory_total_bytes: Annotated[int, Field(gt=0)]
    nic_link_speed_bits_per_second: Annotated[int, Field(gt=0)]
    cgroup_cpu_capacity_cores: Annotated[float, Field(gt=0)]
    cgroup_memory_limit_bytes: Annotated[int, Field(gt=0)]
    cgroup_pids_limit: Annotated[int, Field(gt=0)]
    process_count: Annotated[int, Field(gt=0)]
    workload_processes: tuple[RuntimeProcessBinding, ...]
    workload_processes_sha256: Sha256
    workload_process_limits: tuple[RuntimeProcessLimit, ...]
    cgroup_path_sha256: Sha256
    cgroup_constraint_chain_sha256: Sha256
    valid: bool
    invalid_reasons: tuple[str, ...]

    @model_validator(mode="after")
    def validate_ephemeral_range(self) -> Self:
        if (
            self.ephemeral_port_end < self.ephemeral_port_start
            or self.ephemeral_port_capacity
            > self.ephemeral_port_end - self.ephemeral_port_start + 1
        ):
            raise ValueError("ephemeral_port_range_invalid")
        expected_resources = {
            "host_cpu",
            "host_ram",
            "process_cpu",
            "cgroup_cpu",
            "cgroup_ram",
            "process_fd",
            "socket",
            "cgroup_pids",
            "network",
            "packet_rate",
        }
        if self.soak_maxima_percent and set(self.soak_maxima_percent) != expected_resources:
            raise ValueError("soak_resource_set_invalid")
        if (
            len(self.workload_processes) != self.process_count
            or _process_bindings_sha256(self.workload_processes) != self.workload_processes_sha256
            or tuple(item.pid for item in self.workload_process_limits)
            != tuple(item.pid for item in self.workload_processes)
        ):
            raise ValueError("workload_process_binding_invalid")
        return self


class SutObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    sut_host: Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9._:-]{1,253}$")]
    timestamp: Timestamp
    clock_proof: KernelClockProof
    resource: ResourceObservation
    mediamtx_rss_bytes: Annotated[int, Field(ge=0)]
    mediamtx_open_file_descriptors: Annotated[int, Field(ge=0)]
    metrics_families: tuple[SutMetricFamily, ...]
    total_rtsp_sessions: Annotated[int, Field(ge=0)]
    ready_runtime_paths: Annotated[int, Field(ge=0)]
    active_session_counters: tuple[SessionMetricSnapshot, ...]
    active_path_counters: tuple[PathMetricSnapshot, ...]
    cumulative_inbound_rtp_packets: Annotated[int, Field(ge=0)]
    cumulative_outbound_rtp_packets: Annotated[int, Field(ge=0)]
    inbound_rtp_packets_lost: Annotated[int, Field(ge=0)]
    inbound_rtp_packets_in_error: Annotated[int, Field(ge=0)]
    inbound_rtcp_packets_in_error: Annotated[int, Field(ge=0)]
    outbound_rtp_packets_discarded: Annotated[int, Field(ge=0)]
    outbound_rtp_packets_reported_lost: Annotated[int, Field(ge=0)]
    rtcp_packets_in_error: Annotated[int, Field(ge=0)]
    rtp_packets_in_error: Annotated[int, Field(ge=0)]
    rtp_packets_lost: Annotated[int, Field(ge=0)]
    path_inbound_frames_in_error: Annotated[int, Field(ge=0)]

    @model_validator(mode="after")
    def validate_resource_binding(self) -> Self:
        if (
            self.resource.generator_host != self.sut_host
            or self.resource.timestamp != self.timestamp
            or self.resource.process_count != 1
            or tuple(sorted(set(self.metrics_families))) != self.metrics_families
            or not self.clock_proof.synchronized
            or abs(
                self.clock_proof.observed_at_unix_ms
                - int(datetime.fromisoformat(self.timestamp).timestamp() * 1000)
            )
            > 1000
            or tuple(sorted(self.active_session_counters, key=lambda item: item.identity_sha256))
            != self.active_session_counters
            or len({item.identity_sha256 for item in self.active_session_counters})
            != len(self.active_session_counters)
            or self.total_rtsp_sessions != len(self.active_session_counters)
            or tuple(sorted(self.active_path_counters, key=lambda item: item.identity_sha256))
            != self.active_path_counters
            or len({item.identity_sha256 for item in self.active_path_counters})
            != len(self.active_path_counters)
        ):
            raise ValueError("sut_resource_binding_invalid")
        return self


class SutCapacitySummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    sut_host: str
    observations_sha256: Sha256
    resource_summary: GeneratorHeadroomSummary
    observation_count: Annotated[int, Field(gt=0)]
    measurement_start_unix_ms: Annotated[int, Field(gt=0)]
    measurement_end_unix_ms: Annotated[int, Field(gt=0)]
    soak_end_unix_ms: Annotated[int, Field(gt=0)]
    measurement_max_rolling_6h_rss_slope_percent_per_hour: float | None
    soak_max_rolling_6h_rss_slope_percent_per_hour: float | None
    combined_max_rolling_6h_rss_slope_percent_per_hour: float | None
    file_descriptor_delta: int
    file_descriptor_leak_limit: Annotated[int, Field(ge=10)]
    final_total_rtsp_sessions: Annotated[int, Field(ge=0)]
    final_ready_runtime_paths: Annotated[int, Field(ge=0)]
    inbound_rtp_packets_delta: Annotated[int, Field(ge=0)]
    outbound_rtp_packets_delta: Annotated[int, Field(ge=0)]
    inbound_rtp_packets_lost_delta: Annotated[int, Field(ge=0)]
    inbound_rtp_packets_in_error_delta: Annotated[int, Field(ge=0)]
    inbound_rtcp_packets_in_error_delta: Annotated[int, Field(ge=0)]
    outbound_rtp_packets_discarded_delta: Annotated[int, Field(ge=0)]
    outbound_rtp_packets_reported_lost_delta: Annotated[int, Field(ge=0)]
    rtcp_packets_in_error_delta: Annotated[int, Field(ge=0)]
    rtp_packets_in_error_delta: Annotated[int, Field(ge=0)]
    rtp_packets_lost_delta: Annotated[int, Field(ge=0)]
    path_inbound_frames_in_error_delta: Annotated[int, Field(ge=0)]
    valid: bool
    invalid_reasons: tuple[str, ...]


def _process_bindings_sha256(bindings: tuple[RuntimeProcessBinding, ...]) -> str:
    return hashlib.sha256(
        json.dumps(
            [item.model_dump(mode="json") for item in bindings],
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


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
    ephemeral_port_start: int
    ephemeral_port_end: int
    ephemeral_port_capacity: int
    reserved_ports_sha256: str
    tcp_ephemeral_ports_in_use: int


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
class CgroupConstraintCounters:
    path_sha256: str
    cpu_usage_usec: int
    cpu_capacity_cores: float
    memory_current_bytes: int
    memory_limit_bytes: int | None
    pids_current: int
    pids_limit: int | None


@dataclass(frozen=True, slots=True)
class CgroupCounters:
    cpu_usage_usec: int
    cpu_capacity_cores: float
    memory_current_bytes: int
    memory_limit_bytes: int
    pids_current: int
    pids_limit: int
    constraint_chain_sha256: str
    constraints: tuple[CgroupConstraintCounters, ...]


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
            or self.host.memory_total_bytes != previous.host.memory_total_bytes
            or not 0 <= self.host.memory_available_bytes <= self.host.memory_total_bytes
            or self.host.nic_bits_per_second <= 0
            or self.host.nic_bits_per_second != previous.host.nic_bits_per_second
            or not 576 <= self.host.interface_mtu_bytes <= 9216
            or self.host.interface_mtu_bytes != previous.host.interface_mtu_bytes
            or self.host.ephemeral_port_start != previous.host.ephemeral_port_start
            or self.host.ephemeral_port_end != previous.host.ephemeral_port_end
            or self.host.ephemeral_port_capacity != previous.host.ephemeral_port_capacity
            or self.host.reserved_ports_sha256 != previous.host.reserved_ports_sha256
            or not 1 <= self.host.ephemeral_port_start <= self.host.ephemeral_port_end <= 65535
            or self.host.ephemeral_port_capacity <= 0
            or self.host.ephemeral_port_capacity
            > self.host.ephemeral_port_end - self.host.ephemeral_port_start + 1
            or self.host.tcp_ephemeral_ports_in_use < 0
            or self.machine_id_sha256 != previous.machine_id_sha256
            or self.boot_id != previous.boot_id
            or self.clock_ticks_per_second <= 0
            or self.cgroup_path_sha256 != previous.cgroup_path_sha256
            or self.cgroup.constraint_chain_sha256 != previous.cgroup.constraint_chain_sha256
            or {item.pid for item in self.processes} != set(previous_processes)
            or self.cgroup.cpu_capacity_cores <= 0
            or self.cgroup.cpu_capacity_cores != previous.cgroup.cpu_capacity_cores
            or self.cgroup.memory_limit_bytes <= 0
            or self.cgroup.memory_limit_bytes != previous.cgroup.memory_limit_bytes
            or self.cgroup.pids_limit <= 0
            or self.cgroup.pids_limit != previous.cgroup.pids_limit
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
                or process.max_file_descriptors != prior.max_file_descriptors
                or process.executable_sha256 != prior.executable_sha256
                or process.start_time_ticks != prior.start_time_ticks
                or not 0 <= process.open_file_descriptors <= process.max_file_descriptors
            ):
                raise ValueError("invalid_or_non_monotonic_generator_counters")
            process_cpu.append(tick_delta / self.clock_ticks_per_second / elapsed_seconds * 100)
            fd_percent.append(process.open_file_descriptors / process.max_file_descriptors * 100)

        previous_constraints = {item.path_sha256: item for item in previous.cgroup.constraints}
        if not self.cgroup.constraints or {
            item.path_sha256 for item in self.cgroup.constraints
        } != set(previous_constraints):
            raise ValueError("invalid_or_non_monotonic_generator_counters")
        cgroup_cpu_percentages: list[float] = []
        cgroup_ram_percentages: list[float] = []
        cgroup_pids_percentages: list[float] = []
        for constraint in self.cgroup.constraints:
            prior_constraint = previous_constraints[constraint.path_sha256]
            cpu_delta = constraint.cpu_usage_usec - prior_constraint.cpu_usage_usec
            if (
                cpu_delta < 0
                or constraint.cpu_capacity_cores <= 0
                or constraint.cpu_capacity_cores != prior_constraint.cpu_capacity_cores
                or constraint.memory_limit_bytes != prior_constraint.memory_limit_bytes
                or constraint.pids_limit != prior_constraint.pids_limit
                or constraint.memory_current_bytes < 0
                or constraint.pids_current < 0
                or (
                    constraint.memory_limit_bytes is not None
                    and constraint.memory_current_bytes > constraint.memory_limit_bytes
                )
                or (
                    constraint.pids_limit is not None
                    and constraint.pids_current > constraint.pids_limit
                )
            ):
                raise ValueError("invalid_or_non_monotonic_generator_counters")
            cgroup_cpu_percentages.append(
                cpu_delta / 1_000_000 / elapsed_seconds / constraint.cpu_capacity_cores * 100
            )
            if constraint.memory_limit_bytes is not None:
                cgroup_ram_percentages.append(
                    constraint.memory_current_bytes / constraint.memory_limit_bytes * 100
                )
            if constraint.pids_limit is not None:
                cgroup_pids_percentages.append(
                    constraint.pids_current / constraint.pids_limit * 100
                )
        if not cgroup_ram_percentages or not cgroup_pids_percentages:
            raise ValueError("invalid_or_non_monotonic_generator_counters")
        host_cpu = (total_delta - idle_delta) / total_delta * 100
        host_ram = (
            (self.host.memory_total_bytes - self.host.memory_available_bytes)
            / self.host.memory_total_bytes
            * 100
        )
        cgroup_cpu = max(cgroup_cpu_percentages)
        network = (
            max(rx_delta, tx_delta) * 8 / elapsed_seconds / self.host.nic_bits_per_second * 100
        )
        network_packets_per_second = max(rx_packets_delta, tx_packets_delta) / elapsed_seconds
        line_rate_packets_per_second = self.host.nic_bits_per_second / (
            (self.host.interface_mtu_bytes + 38) * 8
        )
        process_bindings = tuple(
            RuntimeProcessBinding(
                pid=item.pid,
                executable_sha256=item.executable_sha256,
                start_time_ticks=item.start_time_ticks,
            )
            for item in sorted(self.processes, key=lambda item: item.pid)
        )
        processes_sha256 = _process_bindings_sha256(process_bindings)
        process_limits = tuple(
            RuntimeProcessLimit(pid=item.pid, max_open_files=item.max_file_descriptors)
            for item in sorted(self.processes, key=lambda item: item.pid)
        )
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
            cgroup_ram_percent=min(max(cgroup_ram_percentages), 100),
            max_process_fd_percent=max(fd_percent, default=0),
            socket_percent=min(
                self.host.tcp_ephemeral_ports_in_use / self.host.ephemeral_port_capacity * 100,
                100,
            ),
            ephemeral_port_start=self.host.ephemeral_port_start,
            ephemeral_port_end=self.host.ephemeral_port_end,
            ephemeral_port_capacity=self.host.ephemeral_port_capacity,
            reserved_ports_sha256=self.host.reserved_ports_sha256,
            cgroup_pids_percent=min(max(cgroup_pids_percentages), 100),
            network_percent=min(network, 100),
            network_packets_per_second=network_packets_per_second,
            packet_rate_percent=min(
                network_packets_per_second / line_rate_packets_per_second * 100,
                100,
            ),
            interface_mtu_bytes=self.host.interface_mtu_bytes,
            memory_total_bytes=self.host.memory_total_bytes,
            nic_link_speed_bits_per_second=self.host.nic_bits_per_second,
            cgroup_cpu_capacity_cores=self.cgroup.cpu_capacity_cores,
            cgroup_memory_limit_bytes=self.cgroup.memory_limit_bytes,
            cgroup_pids_limit=self.cgroup.pids_limit,
            process_count=len(self.processes),
            workload_processes=process_bindings,
            workload_processes_sha256=processes_sha256,
            workload_process_limits=process_limits,
            cgroup_path_sha256=self.cgroup_path_sha256,
            cgroup_constraint_chain_sha256=self.cgroup.constraint_chain_sha256,
        )


@dataclass(frozen=True, slots=True)
class MediaMetricsCounters:
    observed_families: tuple[SutMetricFamily, ...]
    total_rtsp_sessions: int
    ready_runtime_paths: int
    active_sessions: tuple[SessionMetricSnapshot, ...]
    active_paths: tuple[PathMetricSnapshot, ...]
    inbound_rtp_packets: int
    outbound_rtp_packets: int
    inbound_rtp_packets_lost: int
    inbound_rtp_packets_in_error: int
    inbound_rtcp_packets_in_error: int
    outbound_rtp_packets_discarded: int
    outbound_rtp_packets_reported_lost: int
    rtcp_packets_in_error: int
    rtp_packets_in_error: int
    rtp_packets_lost: int
    path_inbound_frames_in_error: int


_CUMULATIVE_SESSION_FIELDS = SESSION_COUNTER_FIELDS


class _MetricHistory:
    def __init__(self) -> None:
        self._session_last: dict[str, dict[str, int]] = {}
        self._session_totals: dict[str, dict[str, int]] = {}
        self._active_sessions: set[str] = set()
        self._path_last: dict[str, int] = {}
        self._path_totals: dict[str, int] = {}
        self._path_states: dict[str, str] = {}
        self._active_paths: set[str] = set()

    def update(
        self,
        sessions: tuple[SessionMetricSnapshot, ...],
        paths: tuple[PathMetricSnapshot, ...],
    ) -> dict[str, int]:
        current_sessions = {session.identity_sha256 for session in sessions}
        for session in sessions:
            last = self._session_last.setdefault(session.identity_sha256, {})
            totals = self._session_totals.setdefault(session.identity_sha256, {})
            continued = session.identity_sha256 in self._active_sessions
            for field in _CUMULATIVE_SESSION_FIELDS:
                if field in session.observed_counter_fields:
                    value = getattr(session, field)
                    previous = last.get(field)
                    if previous is None:
                        totals[field] = value
                    elif not continued:
                        totals[field] = totals.get(field, 0) + value
                    elif value < previous:
                        raise ValueError("sut_session_counter_reset_while_active")
                    else:
                        totals[field] = totals.get(field, 0) + value - previous
                    last[field] = value
        self._active_sessions = current_sessions
        current_paths = {path.identity_sha256 for path in paths}
        for path in paths:
            previous = self._path_last.get(path.identity_sha256)
            continued = path.identity_sha256 in self._active_paths
            same_generation = (
                continued and self._path_states.get(path.identity_sha256) == path.state
            )
            if previous is None:
                self._path_totals[path.identity_sha256] = path.inbound_frames_in_error
            elif not same_generation:
                self._path_totals[path.identity_sha256] += path.inbound_frames_in_error
            elif path.inbound_frames_in_error < previous:
                raise ValueError("sut_path_counter_reset_while_active")
            else:
                self._path_totals[path.identity_sha256] += path.inbound_frames_in_error - previous
            self._path_last[path.identity_sha256] = path.inbound_frames_in_error
            self._path_states[path.identity_sha256] = path.state
        self._active_paths = current_paths
        return {
            **{
                field: sum(history.get(field, 0) for history in self._session_totals.values())
                for field in _CUMULATIVE_SESSION_FIELDS
            },
            "path_inbound_frames_in_error": sum(self._path_totals.values()),
        }


def _observation_cumulative_values(observation: SutObservation) -> dict[str, int]:
    return {
        "inbound_rtp_packets": observation.cumulative_inbound_rtp_packets,
        "outbound_rtp_packets": observation.cumulative_outbound_rtp_packets,
        "inbound_rtp_packets_lost": observation.inbound_rtp_packets_lost,
        "inbound_rtp_packets_in_error": observation.inbound_rtp_packets_in_error,
        "inbound_rtcp_packets_in_error": observation.inbound_rtcp_packets_in_error,
        "outbound_rtp_packets_discarded": observation.outbound_rtp_packets_discarded,
        "outbound_rtp_packets_reported_lost": observation.outbound_rtp_packets_reported_lost,
        "rtcp_packets_in_error": observation.rtcp_packets_in_error,
        "rtp_packets_in_error": observation.rtp_packets_in_error,
        "rtp_packets_lost": observation.rtp_packets_lost,
        "path_inbound_frames_in_error": observation.path_inbound_frames_in_error,
    }


_SUT_METRIC_FAMILIES = {
    "rtsp_sessions_inbound_rtcp_packets_in_error": "inbound_rtcp_packets_in_error",
    "rtsp_sessions_inbound_rtp_packets": "inbound_rtp_packets",
    "rtsp_sessions_inbound_rtp_packets_lost": "inbound_rtp_packets_lost",
    "rtsp_sessions_inbound_rtp_packets_in_error": "inbound_rtp_packets_in_error",
    "rtsp_sessions_outbound_rtp_packets_discarded": "outbound_rtp_packets_discarded",
    "rtsp_sessions_outbound_rtp_packets_reported_lost": "outbound_rtp_packets_reported_lost",
    "rtsp_sessions_outbound_rtp_packets": "outbound_rtp_packets",
    "rtsp_sessions_rtcp_packets_in_error": "rtcp_packets_in_error",
    "rtsp_sessions_rtp_packets_in_error": "rtp_packets_in_error",
    "rtsp_sessions_rtp_packets_lost": "rtp_packets_lost",
    "paths_inbound_frames_in_error": "path_inbound_frames_in_error",
}


def _prometheus_labels(metric: str) -> dict[str, str]:
    start = metric.find("{")
    if start < 0 or not metric.endswith("}"):
        return {}
    body = metric[start + 1 : -1]
    labels: dict[str, str] = {}
    cursor = 0
    while cursor < len(body):
        match = re.match(r'([a-zA-Z_][a-zA-Z0-9_]*)="([^"\\]*)"(?:,|$)', body[cursor:])
        if match is None:
            raise ValueError("sut_metrics_invalid")
        name, value = match.group(1), match.group(2)
        if name in labels:
            raise ValueError("sut_metrics_invalid")
        labels[name] = value
        cursor += match.end()
    return labels


def read_mediamtx_metrics(metrics_url: str, *, timeout_seconds: float = 2) -> MediaMetricsCounters:
    try:
        with urllib.request.urlopen(metrics_url, timeout=timeout_seconds) as response:
            body = response.read().decode("utf-8")
    except (OSError, UnicodeError, urllib.error.URLError) as error:
        raise ValueError("sut_metrics_unavailable") from error
    values = {field: 0 for field in _SUT_METRIC_FAMILIES.values()}
    total_sessions = 0
    ready_paths = 0
    sessions: dict[str, dict[str, int | str | bool]] = {}
    paths: dict[str, dict[str, int | str]] = {}
    observed_families: set[SutMetricFamily] = set()
    zero_sentinel_families: set[str] = set()
    labeled_families: set[str] = set()
    for line in body.splitlines():
        if not line or line.startswith("#"):
            continue
        metric, separator, raw_value = line.rpartition(" ")
        if not separator:
            raise ValueError("sut_metrics_invalid")
        family = metric.partition("{")[0]
        try:
            value = float(raw_value)
        except ValueError as error:
            raise ValueError("sut_metrics_invalid") from error
        if not math.isfinite(value) or value < 0 or not value.is_integer():
            raise ValueError("sut_metrics_invalid")
        integer_value = int(value)
        labels = _prometheus_labels(metric)
        relevant = family in {"paths", "rtsp_sessions", *_SUT_METRIC_FAMILIES}
        if relevant and not labels:
            if metric != family or integer_value != 0:
                raise ValueError("sut_metrics_invalid")
            if family in zero_sentinel_families:
                raise ValueError("sut_metrics_invalid")
            observed_families.add(cast(SutMetricFamily, family))
            zero_sentinel_families.add(family)
            continue
        if relevant:
            labeled_families.add(family)
        if family == "paths":
            if set(labels) != {"name", "state"}:
                raise ValueError("sut_metrics_invalid")
            path_name = labels.get("name")
            state = labels.get("state")
            if path_name is None or state not in {"notReady", "ready"} or integer_value != 1:
                raise ValueError("sut_metrics_invalid")
            identity = hashlib.sha256(path_name.encode("utf-8")).hexdigest()
            path_fields = paths.setdefault(identity, {"state": state, "path_seen": False})
            if path_fields.get("state") != state or path_fields.get("path_seen") is True:
                raise ValueError("sut_metrics_invalid")
            path_fields["path_seen"] = True
            if state == "ready":
                ready_paths += 1
            observed_families.add("paths")
        if family == "rtsp_sessions":
            if set(labels) != {"id", "path", "remoteAddr", "state"}:
                raise ValueError("sut_metrics_invalid")
            observed_families.add("rtsp_sessions")
            session_id = labels.get("id")
            session_path = labels.get("path")
            remote_address = labels.get("remoteAddr")
            state = labels.get("state")
            if (
                session_id is None
                or session_path is None
                or remote_address is None
                or state not in {"idle", "publish", "read"}
                or integer_value != 1
            ):
                raise ValueError("sut_metrics_invalid")
            identity = hashlib.sha256(f"{session_id}\0{remote_address}".encode()).hexdigest()
            session = sessions.setdefault(
                identity,
                {
                    "id": session_id,
                    "path": session_path,
                    "remoteAddr": remote_address,
                    "state": state,
                    "session_seen": False,
                },
            )
            if session.get("state") != state or session.get("session_seen") is True:
                raise ValueError("sut_metrics_invalid")
            session["session_seen"] = True
            total_sessions += 1
        field = _SUT_METRIC_FAMILIES.get(family)
        if field is not None:
            values[field] += integer_value
            observed_families.add(cast(SutMetricFamily, family))
            if family.startswith("rtsp_sessions_"):
                if set(labels) != {"id", "path", "remoteAddr", "state"}:
                    raise ValueError("sut_metrics_invalid")
                session_id = labels.get("id")
                session_path = labels.get("path")
                remote_address = labels.get("remoteAddr")
                state = labels.get("state")
                if (
                    session_id is None
                    or session_path is None
                    or remote_address is None
                    or state not in {"idle", "publish", "read"}
                ):
                    raise ValueError("sut_metrics_invalid")
                identity = hashlib.sha256(f"{session_id}\0{remote_address}".encode()).hexdigest()
                session = sessions.setdefault(
                    identity,
                    {
                        "id": session_id,
                        "path": session_path,
                        "remoteAddr": remote_address,
                        "state": state,
                        "session_seen": False,
                    },
                )
                if (
                    session.get("id") != session_id
                    or session.get("path") != session_path
                    or session.get("remoteAddr") != remote_address
                    or session.get("state") != state
                    or field in session
                ):
                    raise ValueError("sut_metrics_invalid")
                session[field] = integer_value
            elif family == "paths_inbound_frames_in_error":
                if set(labels) != {"name", "state"}:
                    raise ValueError("sut_metrics_invalid")
                path_name = labels.get("name")
                state = labels.get("state")
                if path_name is None or state not in {"notReady", "ready"}:
                    raise ValueError("sut_metrics_invalid")
                identity = hashlib.sha256(path_name.encode("utf-8")).hexdigest()
                path_fields = paths.setdefault(identity, {"state": state})
                if path_fields.get("state") != state or field in path_fields:
                    raise ValueError("sut_metrics_invalid")
                path_fields[field] = integer_value
    if (
        zero_sentinel_families & labeled_families
        or any(item.get("session_seen") is not True for item in sessions.values())
        or any(item.get("path_seen") is not True for item in paths.values())
    ):
        raise ValueError("sut_metrics_invalid")
    session_snapshots = tuple(
        SessionMetricSnapshot(
            identity_sha256=identity,
            state=str(fields["state"]),
            observed_counter_fields=tuple(
                field for field in SESSION_COUNTER_FIELDS if field in fields
            ),
            inbound_rtcp_packets_in_error=int(fields.get("inbound_rtcp_packets_in_error", 0)),
            inbound_rtp_packets=int(fields.get("inbound_rtp_packets", 0)),
            outbound_rtp_packets=int(fields.get("outbound_rtp_packets", 0)),
            inbound_rtp_packets_lost=int(fields.get("inbound_rtp_packets_lost", 0)),
            inbound_rtp_packets_in_error=int(fields.get("inbound_rtp_packets_in_error", 0)),
            outbound_rtp_packets_discarded=int(fields.get("outbound_rtp_packets_discarded", 0)),
            outbound_rtp_packets_reported_lost=int(
                fields.get("outbound_rtp_packets_reported_lost", 0)
            ),
            rtcp_packets_in_error=int(fields.get("rtcp_packets_in_error", 0)),
            rtp_packets_in_error=int(fields.get("rtp_packets_in_error", 0)),
            rtp_packets_lost=int(fields.get("rtp_packets_lost", 0)),
        )
        for identity, fields in sorted(sessions.items())
    )
    path_snapshots = tuple(
        PathMetricSnapshot(
            identity_sha256=identity,
            state=cast(Literal["notReady", "ready"], fields["state"]),
            inbound_frames_in_error=int(fields["path_inbound_frames_in_error"]),
        )
        for identity, fields in sorted(paths.items())
        if "path_inbound_frames_in_error" in fields
    )
    if len(path_snapshots) != len(paths):
        raise ValueError("sut_metrics_invalid")
    return MediaMetricsCounters(
        observed_families=tuple(sorted(observed_families)),
        total_rtsp_sessions=total_sessions,
        ready_runtime_paths=ready_paths,
        active_sessions=session_snapshots,
        active_paths=path_snapshots,
        inbound_rtp_packets=values["inbound_rtp_packets"],
        outbound_rtp_packets=values["outbound_rtp_packets"],
        inbound_rtp_packets_lost=values["inbound_rtp_packets_lost"],
        inbound_rtp_packets_in_error=values["inbound_rtp_packets_in_error"],
        inbound_rtcp_packets_in_error=values["inbound_rtcp_packets_in_error"],
        outbound_rtp_packets_discarded=values["outbound_rtp_packets_discarded"],
        outbound_rtp_packets_reported_lost=values["outbound_rtp_packets_reported_lost"],
        rtcp_packets_in_error=values["rtcp_packets_in_error"],
        rtp_packets_in_error=values["rtp_packets_in_error"],
        rtp_packets_lost=values["rtp_packets_lost"],
        path_inbound_frames_in_error=values["path_inbound_frames_in_error"],
    )


def summarize_generator_headroom(
    observations: list[ResourceObservation] | tuple[ResourceObservation, ...],
    *,
    expected_generator_host: str | None = None,
    minimum_duration_seconds: float = 1,
    expected_interval_seconds: float = 1,
    maximum_gap_factor: float = 1.5,
    observations_sha256: str,
    capacity_gate: bool = False,
    measurement_start_unix_ms: int | None = None,
    measurement_end_unix_ms: int | None = None,
    soak_end_unix_ms: int | None = None,
) -> GeneratorHeadroomSummary:
    if (
        not observations
        or minimum_duration_seconds < 0
        or expected_interval_seconds <= 0
        or maximum_gap_factor < 1
        or ((measurement_start_unix_ms is None) != (measurement_end_unix_ms is None))
        or (
            measurement_start_unix_ms is not None
            and (
                measurement_end_unix_ms is None
                or measurement_end_unix_ms <= measurement_start_unix_ms
                or (soak_end_unix_ms is not None and soak_end_unix_ms < measurement_end_unix_ms)
            )
        )
    ):
        raise ValueError("generator_observations_empty")
    hosts = {item.generator_host for item in observations}
    machines = {item.machine_id_sha256 for item in observations}
    boots = {item.boot_id for item in observations}
    bindings = {item.workload_processes_sha256 for item in observations}
    process_bindings = {item.workload_processes for item in observations}
    mtus = {item.interface_mtu_bytes for item in observations}
    port_ranges = {
        (
            item.ephemeral_port_start,
            item.ephemeral_port_end,
            item.ephemeral_port_capacity,
            item.reserved_ports_sha256,
        )
        for item in observations
    }
    process_counts = {item.process_count for item in observations}
    cgroups = {item.cgroup_path_sha256 for item in observations}
    cgroup_chains = {item.cgroup_constraint_chain_sha256 for item in observations}
    resource_limits = {
        (
            item.memory_total_bytes,
            item.nic_link_speed_bits_per_second,
            item.cgroup_cpu_capacity_cores,
            item.cgroup_memory_limit_bytes,
            item.cgroup_pids_limit,
            item.workload_process_limits,
        )
        for item in observations
    }
    if (
        len(hosts) != 1
        or len(machines) != 1
        or len(boots) != 1
        or len(bindings) != 1
        or len(process_bindings) != 1
        or len(mtus) != 1
        or len(port_ranges) != 1
        or len(process_counts) != 1
        or len(cgroups) != 1
        or len(cgroup_chains) != 1
        or len(resource_limits) != 1
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

    def window_items(start_ms: int, end_ms: int) -> tuple[ResourceObservation, ...]:
        return tuple(
            item
            for item, timestamp in zip(observations, timestamps, strict=True)
            if int(timestamp.timestamp() * 1000) > start_ms
            and int((timestamp.timestamp() - item.interval_seconds) * 1000) < end_ms
        )

    measured = (
        tuple(observations)
        if measurement_start_unix_ms is None or measurement_end_unix_ms is None
        else window_items(measurement_start_unix_ms, measurement_end_unix_ms)
    )
    soak = (
        ()
        if measurement_end_unix_ms is None
        or soak_end_unix_ms is None
        or soak_end_unix_ms == measurement_end_unix_ms
        else window_items(measurement_end_unix_ms, soak_end_unix_ms)
    )
    elapsed_seconds = sum(item.interval_seconds for item in measured)
    expected_count = math.ceil(minimum_duration_seconds / expected_interval_seconds)
    reasons: list[str] = []
    if len(measured) < max(2, expected_count) or elapsed_seconds < minimum_duration_seconds:
        reasons.append("generator_observation_window_too_short")
    if max_gap > maximum_allowed_gap:
        reasons.append("generator_observation_gap_too_large")
    if (
        measurement_end_unix_ms is not None
        and soak_end_unix_ms is not None
        and soak_end_unix_ms > measurement_end_unix_ms
    ):
        required_soak_seconds = (soak_end_unix_ms - measurement_end_unix_ms) / 1000
        if (
            len(soak) < max(2, math.ceil(required_soak_seconds / expected_interval_seconds))
            or sum(item.interval_seconds for item in soak) < required_soak_seconds
        ):
            reasons.append("generator_soak_observation_window_too_short")

    def resource_maxima(items: tuple[ResourceObservation, ...]) -> dict[str, float]:
        return {
            "host_cpu": max(item.host_cpu_percent for item in items),
            "host_ram": max(item.host_ram_percent for item in items),
            "process_cpu": max(item.max_process_cpu_percent for item in items),
            "cgroup_cpu": max(item.cgroup_cpu_percent for item in items),
            "cgroup_ram": max(item.cgroup_ram_percent for item in items),
            "process_fd": max(item.max_process_fd_percent for item in items),
            "socket": max(item.socket_percent for item in items),
            "cgroup_pids": max(item.cgroup_pids_percent for item in items),
            "network": max(item.network_percent for item in items),
            "packet_rate": max(item.packet_rate_percent for item in items),
        }

    if not measured:
        raise ValueError("generator_measurement_observations_empty")
    maxima = resource_maxima(measured)
    soak_maxima = resource_maxima(soak) if soak else {}
    ceilings = {
        resource: (
            65
            if capacity_gate and resource in {"host_cpu", "process_cpu", "cgroup_cpu"}
            else 60
            if capacity_gate and resource in {"network", "packet_rate"}
            else 70
        )
        for resource in maxima
    }
    for resource, value in maxima.items():
        ceiling = ceilings[resource]
        exceeds = value > ceiling if capacity_gate and ceiling in {60, 65} else value >= ceiling
        if exceeds:
            suffix = "capacity_ceiling_exceeded" if capacity_gate else "headroom_below_30_percent"
            reasons.append(f"generator_{resource}_{suffix}")
    for resource, value in soak_maxima.items():
        ceiling = ceilings[resource]
        exceeds = value > ceiling if capacity_gate and ceiling in {60, 65} else value >= ceiling
        if exceeds:
            suffix = "capacity_ceiling_exceeded" if capacity_gate else "headroom_below_30_percent"
            reasons.append(f"generator_soak_{resource}_{suffix}")
    return GeneratorHeadroomSummary(
        generator_host=generator_host,
        headroom_policy="spike0-capacity" if capacity_gate else "functional-under-70",
        observations_sha256=observations_sha256,
        machine_id_sha256=next(iter(machines)),
        boot_id=next(iter(boots)),
        observation_count=len(measured),
        elapsed_seconds=elapsed_seconds,
        measurement_start_unix_ms=measurement_start_unix_ms,
        measurement_end_unix_ms=measurement_end_unix_ms,
        soak_end_unix_ms=soak_end_unix_ms,
        soak_observation_count=len(soak),
        soak_elapsed_seconds=sum(item.interval_seconds for item in soak),
        soak_maxima_percent=soak_maxima,
        max_observation_gap_seconds=max_gap,
        max_host_cpu_percent=maxima["host_cpu"],
        max_host_ram_percent=maxima["host_ram"],
        max_process_cpu_percent=maxima["process_cpu"],
        max_cgroup_cpu_percent=maxima["cgroup_cpu"],
        max_cgroup_ram_percent=maxima["cgroup_ram"],
        max_process_fd_percent=maxima["process_fd"],
        max_socket_percent=maxima["socket"],
        ephemeral_port_start=next(iter(port_ranges))[0],
        ephemeral_port_end=next(iter(port_ranges))[1],
        ephemeral_port_capacity=next(iter(port_ranges))[2],
        reserved_ports_sha256=next(iter(port_ranges))[3],
        max_cgroup_pids_percent=maxima["cgroup_pids"],
        max_network_percent=maxima["network"],
        max_network_packets_per_second=max(item.network_packets_per_second for item in measured),
        max_packet_rate_percent=maxima["packet_rate"],
        interface_mtu_bytes=next(iter(mtus)),
        memory_total_bytes=next(iter(resource_limits))[0],
        nic_link_speed_bits_per_second=next(iter(resource_limits))[1],
        cgroup_cpu_capacity_cores=next(iter(resource_limits))[2],
        cgroup_memory_limit_bytes=next(iter(resource_limits))[3],
        cgroup_pids_limit=next(iter(resource_limits))[4],
        process_count=next(iter(process_counts)),
        workload_processes=next(iter(process_bindings)),
        workload_processes_sha256=next(iter(bindings)),
        workload_process_limits=next(iter(resource_limits))[5],
        cgroup_path_sha256=next(iter(cgroups)),
        cgroup_constraint_chain_sha256=next(iter(cgroup_chains)),
        valid=not reasons,
        invalid_reasons=tuple(reasons),
    )


def _maximum_rolling_rss_slope_percent_per_hour(
    observations: tuple[SutObservation, ...], *, window_hours: float = 6
) -> float | None:
    """Maximum least-squares slope over every minimally covering rolling window."""
    if len(observations) < 2:
        return None
    timestamps = [datetime.fromisoformat(item.timestamp).timestamp() for item in observations]
    if timestamps[-1] - timestamps[0] < window_hours * 3600:
        return None
    x_values = [(timestamp - timestamps[0]) / 3600 for timestamp in timestamps]
    y_values = [float(item.mediamtx_rss_bytes) for item in observations]

    def prefix(values: list[float]) -> list[float]:
        result = [0.0]
        for value in values:
            result.append(result[-1] + value)
        return result

    sum_x = prefix(x_values)
    sum_y = prefix(y_values)
    sum_xx = prefix([value * value for value in x_values])
    sum_xy = prefix([x * y for x, y in zip(x_values, y_values, strict=True)])

    def slope(start: int, end: int) -> float | None:
        count = end - start + 1
        sx = sum_x[end + 1] - sum_x[start]
        sy = sum_y[end + 1] - sum_y[start]
        sxx = sum_xx[end + 1] - sum_xx[start]
        sxy = sum_xy[end + 1] - sum_xy[start]
        denominator = count * sxx - sx * sx
        baseline = y_values[start]
        if denominator <= 0 or baseline <= 0:
            return None
        bytes_per_hour = (count * sxy - sx * sy) / denominator
        return bytes_per_hour / baseline * 100

    candidates: list[float] = []
    start = 0
    for end in range(1, len(observations)):
        while start + 1 < end and x_values[end] - x_values[start + 1] >= window_hours:
            start += 1
        if x_values[end] - x_values[start] >= window_hours:
            observed = slope(start, end)
            if observed is not None:
                candidates.append(observed)
    full = slope(0, len(observations) - 1)
    if full is not None:
        candidates.append(full)
    return max(candidates) if candidates else None


def summarize_sut_capacity(
    observations: list[SutObservation] | tuple[SutObservation, ...],
    *,
    expected_sut_host: str,
    expected_interval_seconds: float,
    maximum_gap_factor: float,
    observations_sha256: str,
    measurement_start_unix_ms: int,
    measurement_end_unix_ms: int,
    soak_end_unix_ms: int,
    maximum_clock_error_ms: float,
    capacity_gate: bool = True,
) -> SutCapacitySummary:
    if not observations:
        raise ValueError("sut_observations_empty")
    typed = tuple(observations)
    if {item.sut_host for item in typed} != {expected_sut_host}:
        raise ValueError("sut_observation_host_mismatch")
    resources = tuple(item.resource for item in typed)
    resource_summary = summarize_generator_headroom(
        resources,
        expected_generator_host=expected_sut_host,
        minimum_duration_seconds=(measurement_end_unix_ms - measurement_start_unix_ms) / 1000,
        expected_interval_seconds=expected_interval_seconds,
        maximum_gap_factor=maximum_gap_factor,
        observations_sha256=observations_sha256,
        capacity_gate=capacity_gate,
        measurement_start_unix_ms=measurement_start_unix_ms,
        measurement_end_unix_ms=measurement_end_unix_ms,
        soak_end_unix_ms=soak_end_unix_ms,
    )
    timestamps = [datetime.fromisoformat(item.timestamp) for item in typed]

    def window(start_ms: int, end_ms: int) -> tuple[SutObservation, ...]:
        return tuple(
            item
            for item, timestamp in zip(typed, timestamps, strict=True)
            if int(timestamp.timestamp() * 1000) > start_ms
            and int((timestamp.timestamp() - item.resource.interval_seconds) * 1000) < end_ms
        )

    measurement = window(measurement_start_unix_ms, measurement_end_unix_ms)
    soak = (
        window(measurement_end_unix_ms, soak_end_unix_ms)
        if soak_end_unix_ms > measurement_end_unix_ms
        else ()
    )
    gated_timestamps = {item.timestamp for item in (*measurement, *soak)}
    gated = tuple(item for item in typed if item.timestamp in gated_timestamps)
    if not gated:
        raise ValueError("sut_measurement_observations_empty")
    initial_fds = typed[0].mediamtx_open_file_descriptors
    final_fds = typed[-1].mediamtx_open_file_descriptors
    fd_delta = final_fds - initial_fds
    fd_limit = max(10, math.ceil(initial_fds * 0.001))
    measurement_slope = _maximum_rolling_rss_slope_percent_per_hour(measurement)
    soak_slope = _maximum_rolling_rss_slope_percent_per_hour(soak)
    combined_slope = _maximum_rolling_rss_slope_percent_per_hour(gated)
    counter_fields = (
        "cumulative_inbound_rtp_packets",
        "cumulative_outbound_rtp_packets",
        "inbound_rtp_packets_lost",
        "inbound_rtp_packets_in_error",
        "inbound_rtcp_packets_in_error",
        "outbound_rtp_packets_discarded",
        "outbound_rtp_packets_reported_lost",
        "rtcp_packets_in_error",
        "rtp_packets_in_error",
        "rtp_packets_lost",
        "path_inbound_frames_in_error",
    )
    metric_history = _MetricHistory()
    for item in typed:
        recomputed = metric_history.update(item.active_session_counters, item.active_path_counters)
        if recomputed != _observation_cumulative_values(item):
            raise ValueError("sut_cumulative_counter_not_reproducible")
    baseline_candidates = tuple(
        item
        for item, timestamp in zip(typed, timestamps, strict=True)
        if int(timestamp.timestamp() * 1000) <= measurement_start_unix_ms
    )
    if not baseline_candidates:
        raise ValueError("sut_counter_baseline_missing")
    baseline = baseline_candidates[-1]
    maxima = {
        field: max(getattr(item, field) for item in gated) - getattr(baseline, field)
        for field in counter_fields
    }
    reasons = list(resource_summary.invalid_reasons)
    if measurement_slope is not None and measurement_slope > 1:
        reasons.append("sut_measurement_rss_slope_above_1_percent_per_hour")
    if soak_end_unix_ms - measurement_end_unix_ms >= 6 * 3600 * 1000 and (
        soak_slope is None or soak_slope > 1
    ):
        reasons.append("sut_soak_rss_slope_above_1_percent_per_hour")
    if soak_end_unix_ms - measurement_start_unix_ms >= 6 * 3600 * 1000 and (
        combined_slope is None or combined_slope > 1
    ):
        reasons.append("sut_combined_rss_slope_above_1_percent_per_hour")
    if fd_delta > fd_limit:
        reasons.append("sut_file_descriptor_leak_above_limit")
    if typed[-1].total_rtsp_sessions != 0 or typed[-1].ready_runtime_paths != 0:
        reasons.append("sut_sessions_not_drained_after_workload")
    if any(
        maxima[field]
        for field in (
            "inbound_rtp_packets_lost",
            "inbound_rtp_packets_in_error",
            "inbound_rtcp_packets_in_error",
            "outbound_rtp_packets_discarded",
            "outbound_rtp_packets_reported_lost",
            "rtcp_packets_in_error",
            "rtp_packets_in_error",
            "rtp_packets_lost",
            "path_inbound_frames_in_error",
        )
    ):
        reasons.append("sut_added_packet_loss_or_error_observed")
    if any(item.metrics_families != REQUIRED_SUT_METRIC_FAMILIES for item in typed):
        reasons.append("sut_loss_metric_family_set_incomplete")
    if any(
        not item.clock_proof.synchronized or item.clock_proof.max_error_ms > maximum_clock_error_ms
        for item in typed
    ):
        reasons.append("sut_clock_proof_invalid")
    return SutCapacitySummary(
        sut_host=expected_sut_host,
        observations_sha256=observations_sha256,
        resource_summary=resource_summary,
        observation_count=len(typed),
        measurement_start_unix_ms=measurement_start_unix_ms,
        measurement_end_unix_ms=measurement_end_unix_ms,
        soak_end_unix_ms=soak_end_unix_ms,
        measurement_max_rolling_6h_rss_slope_percent_per_hour=measurement_slope,
        soak_max_rolling_6h_rss_slope_percent_per_hour=soak_slope,
        combined_max_rolling_6h_rss_slope_percent_per_hour=combined_slope,
        file_descriptor_delta=fd_delta,
        file_descriptor_leak_limit=fd_limit,
        final_total_rtsp_sessions=typed[-1].total_rtsp_sessions,
        final_ready_runtime_paths=typed[-1].ready_runtime_paths,
        inbound_rtp_packets_delta=maxima["cumulative_inbound_rtp_packets"],
        outbound_rtp_packets_delta=maxima["cumulative_outbound_rtp_packets"],
        inbound_rtp_packets_lost_delta=maxima["inbound_rtp_packets_lost"],
        inbound_rtp_packets_in_error_delta=maxima["inbound_rtp_packets_in_error"],
        inbound_rtcp_packets_in_error_delta=maxima["inbound_rtcp_packets_in_error"],
        outbound_rtp_packets_discarded_delta=maxima["outbound_rtp_packets_discarded"],
        outbound_rtp_packets_reported_lost_delta=maxima["outbound_rtp_packets_reported_lost"],
        rtcp_packets_in_error_delta=maxima["rtcp_packets_in_error"],
        rtp_packets_in_error_delta=maxima["rtp_packets_in_error"],
        rtp_packets_lost_delta=maxima["rtp_packets_lost"],
        path_inbound_frames_in_error_delta=maxima["path_inbound_frames_in_error"],
        valid=not reasons,
        invalid_reasons=tuple(reasons),
    )


def load_sut_observations(path: Path) -> tuple[SutObservation, ...]:
    observations: list[SutObservation] = []
    with path.open(encoding="utf-8") as source:
        for line in source:
            if not line.strip():
                raise ValueError("blank_sut_observation_line")
            observations.append(SutObservation.model_validate(json.loads(line)))
    if not observations:
        raise ValueError("sut_observations_empty")
    return tuple(observations)


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


def normalize_linux_ephemeral_port_range(port_range: str) -> str:
    range_fields = port_range.split()
    if len(range_fields) != 2:
        raise ValueError("invalid_ephemeral_port_range")
    start, end = (int(value) for value in range_fields)
    if not 1 <= start <= end <= 65535:
        raise ValueError("invalid_ephemeral_port_range")
    return f"{start} {end}"


def normalize_linux_reserved_ports(reserved_ports: str) -> str:
    reserved_body = reserved_ports.strip()
    reserved: set[int] = set()
    if reserved_body:
        for token in reserved_body.split(","):
            if re.fullmatch(r"\d+(?:-\d+)?", token) is None:
                raise ValueError("invalid_reserved_port_range")
            bounds = [int(value) for value in token.split("-", 1)]
            reserved_start = bounds[0]
            reserved_end = bounds[-1]
            if not 1 <= reserved_start <= reserved_end <= 65535:
                raise ValueError("invalid_reserved_port_range")
            reserved.update(range(reserved_start, reserved_end + 1))
    canonical_tokens: list[str] = []
    for _, group in itertools.groupby(enumerate(sorted(reserved)), lambda item: item[1] - item[0]):
        ports = [item[1] for item in group]
        canonical_tokens.append(
            str(ports[0]) if ports[0] == ports[-1] else f"{ports[0]}-{ports[-1]}"
        )
    return ",".join(canonical_tokens)


def parse_linux_ephemeral_port_settings(
    port_range: str, reserved_ports: str
) -> tuple[int, int, int, str]:
    canonical_range = normalize_linux_ephemeral_port_range(port_range)
    start, end = (int(value) for value in canonical_range.split())
    reserved_body = normalize_linux_reserved_ports(reserved_ports)
    reserved: set[int] = set()
    if reserved_body:
        for token in reserved_body.split(","):
            bounds = [int(value) for value in token.split("-", 1)]
            reserved.update(range(bounds[0], bounds[-1] + 1))
    capacity = end - start + 1 - sum(start <= port <= end for port in reserved)
    if capacity <= 0:
        raise ValueError("ephemeral_port_capacity_exhausted_by_reservations")
    reserved_sha256 = hashlib.sha256(reserved_body.encode()).hexdigest()
    return start, end, capacity, reserved_sha256


def _read_ephemeral_socket_counters(root: Path) -> tuple[int, int, int, str, int]:
    range_body = (root / "proc/sys/net/ipv4/ip_local_port_range").read_text(encoding="utf-8")
    reserved_body = (root / "proc/sys/net/ipv4/ip_local_reserved_ports").read_text(encoding="utf-8")
    start, end, capacity, reserved_sha256 = parse_linux_ephemeral_port_settings(
        range_body, reserved_body
    )
    in_use = 0
    for table_name in ("tcp", "tcp6"):
        for line in (root / "proc/net" / table_name).read_text(encoding="utf-8").splitlines()[1:]:
            fields = line.split()
            if len(fields) < 4:
                raise ValueError("invalid_proc_tcp")
            local_port = int(fields[1].rsplit(":", 1)[1], 16)
            if start <= local_port <= end and fields[3] != "0A":
                in_use += 1
    return start, end, capacity, reserved_sha256, in_use


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
    (
        ephemeral_start,
        ephemeral_end,
        ephemeral_capacity,
        reserved_sha256,
        ephemeral_in_use,
    ) = _read_ephemeral_socket_counters(root)
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
        ephemeral_port_start=ephemeral_start,
        ephemeral_port_end=ephemeral_end,
        ephemeral_port_capacity=ephemeral_capacity,
        reserved_ports_sha256=reserved_sha256,
        tcp_ephemeral_ports_in_use=ephemeral_in_use,
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
        r"^Max open files\s+(\d+)\s+\d+\s+\S+[ \t]*$",
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
    mount_root = root / "sys/fs/cgroup"
    chain: list[dict[str, str]] = []
    current = cgroup_root
    while True:
        try:
            relative = current.relative_to(mount_root).as_posix() or "/"
        except ValueError as error:
            raise ValueError("invalid_cgroup_path") from error
        chain.append(
            {
                "path": "/" if relative == "." else f"/{relative}",
                "cpu.max": (current / "cpu.max").read_text(encoding="utf-8").strip(),
                "memory.max": (current / "memory.max").read_text(encoding="utf-8").strip(),
                "pids.max": (current / "pids.max").read_text(encoding="utf-8").strip(),
                "cpuset.cpus.effective": (current / "cpuset.cpus.effective")
                .read_text(encoding="utf-8")
                .strip(),
            }
        )
        if current == mount_root:
            break
        current = current.parent
    chain.reverse()
    constraints: list[CgroupConstraintCounters] = []
    cpu_capacities: list[float] = []
    memory_limits: list[int] = []
    pids_limits: list[int] = []
    for item in chain:
        cpu_fields = item["cpu.max"].split()
        if (
            len(cpu_fields) != 2
            or not cpu_fields[1].isdigit()
            or int(cpu_fields[1]) <= 0
            or (cpu_fields[0] != "max" and not cpu_fields[0].isdigit())
        ):
            raise ValueError("invalid_cgroup_cpu_limit")
        quota_capacity = None if cpu_fields[0] == "max" else int(cpu_fields[0]) / int(cpu_fields[1])
        if quota_capacity is not None and quota_capacity <= 0:
            raise ValueError("invalid_cgroup_cpu_limit")
        cpuset_capacity = _count_linux_cpu_list(item["cpuset.cpus.effective"])
        cpu_capacity = min(
            float(cpuset_capacity),
            quota_capacity if quota_capacity is not None else float(cpuset_capacity),
        )
        cpu_capacities.append(cpu_capacity)
        finite_values: dict[str, int | None] = {}
        for field, destination in (
            ("memory.max", memory_limits),
            ("pids.max", pids_limits),
        ):
            value = item[field]
            parsed: int | None = None
            if value != "max":
                if not value.isdigit() or int(value) <= 0:
                    raise ValueError("invalid_cgroup_limit")
                parsed = int(value)
                destination.append(parsed)
            finite_values[field] = parsed
        constraint_root = mount_root / item["path"].lstrip("/")
        cpu_stat = {
            fields[0]: int(fields[1])
            for line in (constraint_root / "cpu.stat").read_text(encoding="utf-8").splitlines()
            if len(fields := line.split()) == 2
        }
        if "usage_usec" not in cpu_stat:
            raise ValueError("invalid_cgroup_cpu_stat")
        constraints.append(
            CgroupConstraintCounters(
                path_sha256=hashlib.sha256(item["path"].encode()).hexdigest(),
                cpu_usage_usec=cpu_stat["usage_usec"],
                cpu_capacity_cores=cpu_capacity,
                memory_current_bytes=_read_integer(constraint_root / "memory.current"),
                memory_limit_bytes=finite_values["memory.max"],
                pids_current=_read_integer(constraint_root / "pids.current"),
                pids_limit=finite_values["pids.max"],
            )
        )
    if not memory_limits or not pids_limits:
        raise ValueError("finite_effective_cgroup_limits_required")
    constraint_chain_sha256 = hashlib.sha256(
        json.dumps(chain, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return CgroupCounters(
        cpu_usage_usec=constraints[-1].cpu_usage_usec,
        cpu_capacity_cores=min(cpu_capacities),
        memory_current_bytes=_read_integer(cgroup_root / "memory.current"),
        memory_limit_bytes=min(memory_limits),
        pids_current=_read_integer(cgroup_root / "pids.current"),
        pids_limit=min(pids_limits),
        constraint_chain_sha256=constraint_chain_sha256,
        constraints=tuple(constraints),
    )


def _count_linux_cpu_list(value: str) -> int:
    cpus: set[int] = set()
    if not value:
        raise ValueError("effective_cgroup_cpuset_empty")
    for token in value.split(","):
        if re.fullmatch(r"\d+(?:-\d+)?", token) is None:
            raise ValueError("effective_cgroup_cpuset_invalid")
        bounds = tuple(int(item) for item in token.split("-", 1))
        start, end = bounds[0], bounds[-1]
        if start > end:
            raise ValueError("effective_cgroup_cpuset_invalid")
        cpus.update(range(start, end + 1))
    if not cpus:
        raise ValueError("effective_cgroup_cpuset_empty")
    return len(cpus)


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
    sampling_started_at = previous_at
    next_sample_at = sampling_started_at + interval_seconds
    deadline = previous_at + duration_seconds
    observation_count = 0
    with output.open("x", encoding="utf-8") as destination:
        output.chmod(0o640)
        while previous_at < deadline:
            target_at = min(next_sample_at, deadline)
            time.sleep(max(0, target_at - time.monotonic()))
            current = read_linux_generator_counters(
                root,
                interface=interface,
                pids=pids,
                cgroup=cgroup,
                expected_executables=expected_executables,
                expected_mtu_bytes=expected_mtu_bytes,
            )
            observed_at = time.monotonic()
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
            next_sample_at += interval_seconds
    return observation_count


def sample_linux_sut_resources(
    *,
    root: Path,
    sut_host: str,
    interface: str,
    mediamtx_pid: int,
    cgroup: str,
    expected_mediamtx_sha256: str,
    expected_mtu_bytes: int,
    metrics_url: str,
    output: Path,
    duration_seconds: int,
    interval_seconds: float,
    maximum_clock_error_ms: float,
) -> int:
    if duration_seconds < 1 or interval_seconds <= 0:
        raise ValueError("invalid_sampling_duration")
    try:
        output.parent.mkdir(mode=0o750, parents=False, exist_ok=False)
        output.parent.chmod(0o750)
    except FileExistsError:
        if not output.parent.is_dir():
            raise
    expected_executables = {mediamtx_pid: expected_mediamtx_sha256}
    prove_linux_clock(maximum_clock_error_ms)
    metric_history = _MetricHistory()
    previous = read_linux_generator_counters(
        root,
        interface=interface,
        pids=(mediamtx_pid,),
        cgroup=cgroup,
        expected_executables=expected_executables,
        expected_mtu_bytes=expected_mtu_bytes,
    )
    previous_at = time.monotonic()
    next_sample_at = previous_at + interval_seconds
    deadline = previous_at + duration_seconds
    observation_count = 0
    with output.open("x", encoding="utf-8") as destination:
        output.chmod(0o640)
        while previous_at < deadline:
            target_at = min(next_sample_at, deadline)
            time.sleep(max(0, target_at - time.monotonic()))
            metrics = read_mediamtx_metrics(metrics_url)
            cumulative = metric_history.update(metrics.active_sessions, metrics.active_paths)
            current = read_linux_generator_counters(
                root,
                interface=interface,
                pids=(mediamtx_pid,),
                cgroup=cgroup,
                expected_executables=expected_executables,
                expected_mtu_bytes=expected_mtu_bytes,
            )
            observed_at = time.monotonic()
            clock_proof = prove_linux_clock(maximum_clock_error_ms)
            timestamp = (
                datetime.fromtimestamp(clock_proof.observed_at_unix_ms / 1000, UTC)
                .isoformat()
                .replace("+00:00", "Z")
            )
            resource = current.observation_since(
                previous,
                generator_host=sut_host,
                elapsed_seconds=observed_at - previous_at,
                timestamp=timestamp,
            )
            process = current.processes[0]
            observation = SutObservation(
                sut_host=sut_host,
                timestamp=timestamp,
                clock_proof=clock_proof,
                resource=resource,
                mediamtx_rss_bytes=process.rss_bytes,
                mediamtx_open_file_descriptors=process.open_file_descriptors,
                metrics_families=metrics.observed_families,
                total_rtsp_sessions=metrics.total_rtsp_sessions,
                ready_runtime_paths=metrics.ready_runtime_paths,
                active_session_counters=metrics.active_sessions,
                active_path_counters=metrics.active_paths,
                cumulative_inbound_rtp_packets=cumulative["inbound_rtp_packets"],
                cumulative_outbound_rtp_packets=cumulative["outbound_rtp_packets"],
                inbound_rtp_packets_lost=cumulative["inbound_rtp_packets_lost"],
                inbound_rtp_packets_in_error=cumulative["inbound_rtp_packets_in_error"],
                inbound_rtcp_packets_in_error=cumulative["inbound_rtcp_packets_in_error"],
                outbound_rtp_packets_discarded=cumulative["outbound_rtp_packets_discarded"],
                outbound_rtp_packets_reported_lost=cumulative["outbound_rtp_packets_reported_lost"],
                rtcp_packets_in_error=cumulative["rtcp_packets_in_error"],
                rtp_packets_in_error=cumulative["rtp_packets_in_error"],
                rtp_packets_lost=cumulative["rtp_packets_lost"],
                path_inbound_frames_in_error=cumulative["path_inbound_frames_in_error"],
            )
            destination.write(json.dumps(observation.model_dump(mode="json")) + "\n")
            destination.flush()
            os.fsync(destination.fileno())
            observation_count += 1
            previous = current
            previous_at = observed_at
            next_sample_at += interval_seconds
    return observation_count
