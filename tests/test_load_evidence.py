from __future__ import annotations

import ctypes
import hashlib
import json
import sys
import time
import urllib.request
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

import rtsp_proxy.load_evidence as load_evidence_module
from rtsp_proxy.load_evidence import (
    REQUIRED_SUT_METRIC_FAMILIES,
    SESSION_COUNTER_FIELDS,
    CgroupConstraintCounters,
    CgroupCounters,
    GeneratorCounters,
    HostCounters,
    KernelClockProof,
    MediaMetricsCounters,
    PathMetricSnapshot,
    ProcessCounters,
    ResourceObservation,
    RuntimeProcessBinding,
    RuntimeProcessLimit,
    SessionMetricSnapshot,
    SutObservation,
    load_observations,
    load_sut_observations,
    prove_linux_clock,
    read_linux_generator_counters,
    read_mediamtx_metrics,
    sample_linux_generator_resources,
    sample_linux_sut_resources,
    summarize_generator_headroom,
    summarize_sut_capacity,
)

TEST_PROCESS_BINDINGS = (
    RuntimeProcessBinding(
        pid=123,
        executable_sha256="d" * 64,
        start_time_ticks=1000,
    ),
)
TEST_PROCESS_BINDINGS_SHA256 = hashlib.sha256(
    json.dumps(
        [item.model_dump(mode="json") for item in TEST_PROCESS_BINDINGS],
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
).hexdigest()


def test_linux_clock_proof_uses_kernel_state_and_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeAdjtimex:
        argtypes: object = None
        restype: object = None
        state = 0
        status = 0
        maxerror = 5_000
        esterror = 0

        def __call__(self, pointer: Any) -> int:
            value = ctypes.cast(pointer, ctypes.POINTER(load_evidence_module._Timex)).contents
            value.status = self.status
            value.maxerror = self.maxerror
            value.esterror = self.esterror
            return self.state

    class FakeLibc:
        adjtimex = FakeAdjtimex()

    fake_libc = FakeLibc()
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(ctypes, "CDLL", lambda *args, **kwargs: fake_libc)
    monkeypatch.setattr(time, "time_ns", lambda: 2_000_000_000_000)

    proof = prove_linux_clock(10)

    assert proof.synchronized is True
    assert proof.max_error_ms == 5
    fake_libc.adjtimex.state = 5
    with pytest.raises(ValueError, match="linux_clock_not_synchronized"):
        prove_linux_clock(10)
    fake_libc.adjtimex.state = 0
    fake_libc.adjtimex.esterror = 11_000
    with pytest.raises(ValueError, match="linux_clock_not_synchronized"):
        prove_linux_clock(10)
    monkeypatch.setattr(sys, "platform", "darwin")
    with pytest.raises(ValueError, match="linux_clock_proof_unavailable"):
        prove_linux_clock(10)


def observation(
    *,
    timestamp: str,
    cpu: float = 20,
    ram: float = 30,
    fd: float = 10,
    socket: float = 10,
    network: float = 40,
) -> ResourceObservation:
    return ResourceObservation(
        generator_host="generator-a",
        machine_id_sha256="a" * 64,
        boot_id="11111111-1111-1111-1111-111111111111",
        timestamp=timestamp,
        interval_seconds=1,
        host_cpu_percent=cpu,
        host_ram_percent=ram,
        max_process_cpu_percent=cpu,
        cgroup_cpu_percent=cpu,
        cgroup_ram_percent=ram,
        max_process_fd_percent=fd,
        socket_percent=socket,
        ephemeral_port_start=8000,
        ephemeral_port_end=8999,
        ephemeral_port_capacity=1000,
        reserved_ports_sha256="f" * 64,
        cgroup_pids_percent=fd,
        network_percent=network,
        network_packets_per_second=1000,
        packet_rate_percent=10,
        interface_mtu_bytes=1500,
        memory_total_bytes=1_000,
        nic_link_speed_bits_per_second=8_000,
        cgroup_cpu_capacity_cores=1,
        cgroup_memory_limit_bytes=1_000,
        cgroup_pids_limit=100,
        process_count=1,
        workload_processes=TEST_PROCESS_BINDINGS,
        workload_processes_sha256=TEST_PROCESS_BINDINGS_SHA256,
        workload_process_limits=(RuntimeProcessLimit(pid=123, max_open_files=1_000),),
        cgroup_path_sha256="e" * 64,
        cgroup_constraint_chain_sha256="c" * 64,
    )


def generator_counters(
    *,
    cpu_total: int,
    cpu_idle: int,
    process_ticks: int,
    network_rx: int,
    network_tx: int,
) -> GeneratorCounters:
    return GeneratorCounters(
        host=HostCounters(
            cpu_total_ticks=cpu_total,
            cpu_idle_ticks=cpu_idle,
            memory_total_bytes=1_000,
            memory_available_bytes=500,
            network_rx_bytes=network_rx,
            network_tx_bytes=network_tx,
            network_rx_packets=100,
            network_tx_packets=200,
            nic_bits_per_second=8_000,
            interface_mtu_bytes=1500,
            ephemeral_port_start=8000,
            ephemeral_port_end=8999,
            ephemeral_port_capacity=1000,
            reserved_ports_sha256="f" * 64,
            tcp_ephemeral_ports_in_use=100,
        ),
        processes=(
            ProcessCounters(
                pid=123,
                cpu_ticks=process_ticks,
                rss_bytes=200,
                open_file_descriptors=200,
                max_file_descriptors=1_000,
                executable_sha256="d" * 64,
                start_time_ticks=10,
            ),
        ),
        cgroup=CgroupCounters(
            cpu_usage_usec=process_ticks * 10_000,
            cpu_capacity_cores=1,
            memory_current_bytes=300,
            memory_limit_bytes=1_000,
            pids_current=20,
            pids_limit=100,
            constraint_chain_sha256="c" * 64,
            constraints=(
                CgroupConstraintCounters(
                    path_sha256="b" * 64,
                    cpu_usage_usec=process_ticks * 10_000,
                    cpu_capacity_cores=1,
                    memory_current_bytes=300,
                    memory_limit_bytes=1_000,
                    pids_current=20,
                    pids_limit=100,
                ),
            ),
        ),
        machine_id_sha256="a" * 64,
        boot_id="11111111-1111-1111-1111-111111111111",
        clock_ticks_per_second=100,
        cgroup_path_sha256="e" * 64,
    )


def test_generator_counter_delta_uses_process_cgroup_and_nic_hard_limits() -> None:
    before = generator_counters(
        cpu_total=1_000,
        cpu_idle=600,
        process_ticks=100,
        network_rx=1_000,
        network_tx=2_000,
    )
    after = generator_counters(
        cpu_total=1_200,
        cpu_idle=700,
        process_ticks=150,
        network_rx=1_400,
        network_tx=2_600,
    )

    measured = after.observation_since(
        before,
        generator_host="generator-a",
        elapsed_seconds=1,
        timestamp="2026-08-10T12:00:00Z",
    )

    assert measured.host_cpu_percent == 50
    assert measured.host_ram_percent == 50
    assert measured.max_process_cpu_percent == 50
    assert measured.cgroup_cpu_percent == 50
    assert measured.cgroup_ram_percent == 30
    assert measured.max_process_fd_percent == 20
    assert measured.socket_percent == 10
    assert measured.cgroup_pids_percent == 20
    assert measured.network_percent == 60
    assert measured.network_packets_per_second == 0
    assert measured.interface_mtu_bytes == 1500


def test_generator_counter_delta_gates_shared_ancestor_cgroup_usage() -> None:
    before = generator_counters(
        cpu_total=1_000,
        cpu_idle=600,
        process_ticks=100,
        network_rx=1_000,
        network_tx=2_000,
    )
    after = generator_counters(
        cpu_total=1_200,
        cpu_idle=700,
        process_ticks=110,
        network_rx=1_100,
        network_tx=2_100,
    )
    parent_path = "9" * 64
    before = replace(
        before,
        cgroup=replace(
            before.cgroup,
            constraints=(
                CgroupConstraintCounters(
                    path_sha256=parent_path,
                    cpu_usage_usec=1_000_000,
                    cpu_capacity_cores=1,
                    memory_current_bytes=800,
                    memory_limit_bytes=1_000,
                    pids_current=80,
                    pids_limit=100,
                ),
                *before.cgroup.constraints,
            ),
        ),
    )
    after = replace(
        after,
        cgroup=replace(
            after.cgroup,
            constraints=(
                CgroupConstraintCounters(
                    path_sha256=parent_path,
                    cpu_usage_usec=1_900_000,
                    cpu_capacity_cores=1,
                    memory_current_bytes=900,
                    memory_limit_bytes=1_000,
                    pids_current=90,
                    pids_limit=100,
                ),
                *after.cgroup.constraints,
            ),
        ),
    )

    measured = after.observation_since(
        before,
        generator_host="generator-a",
        elapsed_seconds=1,
        timestamp="2026-08-10T12:00:01Z",
    )

    assert measured.cgroup_cpu_percent == 90
    assert measured.cgroup_ram_percent == 90
    assert measured.cgroup_pids_percent == 90


def test_generator_headroom_requires_every_resource_to_stay_below_70_percent() -> None:
    summary = summarize_generator_headroom(
        [
            observation(timestamp="2026-08-10T12:00:00Z"),
            observation(timestamp="2026-08-10T12:00:01Z", cpu=69.9, ram=60, fd=50),
        ],
        observations_sha256="b" * 64,
    )

    assert summary.valid is True
    assert summary.invalid_reasons == ()
    assert summary.max_host_cpu_percent == 69.9
    assert summary.elapsed_seconds == 2

    invalid = summarize_generator_headroom(
        [
            observation(timestamp="2026-08-10T12:00:00Z"),
            observation(timestamp="2026-08-10T12:00:01Z", network=70),
        ],
        observations_sha256="b" * 64,
    )
    assert invalid.valid is False
    assert invalid.invalid_reasons == ("generator_network_headroom_below_30_percent",)

    socket_invalid = summarize_generator_headroom(
        [
            observation(timestamp="2026-08-10T12:00:00Z"),
            observation(timestamp="2026-08-10T12:00:01Z", socket=70),
        ],
        observations_sha256="b" * 64,
    )
    assert socket_invalid.invalid_reasons == ("generator_socket_headroom_below_30_percent",)


def test_capacity_headroom_uses_spike_zero_cpu_and_network_ceilings() -> None:
    passing = summarize_generator_headroom(
        [
            observation(timestamp="2026-08-10T12:00:00Z", cpu=65, network=60),
            observation(timestamp="2026-08-10T12:00:01Z", cpu=65, network=60),
        ],
        observations_sha256="b" * 64,
        capacity_gate=True,
    )
    assert passing.valid is True
    assert passing.headroom_policy == "spike0-capacity"

    failing = summarize_generator_headroom(
        [
            observation(timestamp="2026-08-10T12:00:00Z", cpu=65.1, network=60.1),
            observation(timestamp="2026-08-10T12:00:01Z", cpu=65.1, network=60.1),
        ],
        observations_sha256="b" * 64,
        capacity_gate=True,
    )
    assert failing.invalid_reasons == (
        "generator_host_cpu_capacity_ceiling_exceeded",
        "generator_process_cpu_capacity_ceiling_exceeded",
        "generator_cgroup_cpu_capacity_ceiling_exceeded",
        "generator_network_capacity_ceiling_exceeded",
    )


def test_headroom_gates_measurement_and_soak_as_separate_windows() -> None:
    summary = summarize_generator_headroom(
        [
            observation(timestamp="2026-08-10T12:00:01Z"),
            observation(timestamp="2026-08-10T12:00:02Z"),
            observation(timestamp="2026-08-10T12:00:03Z", network=70),
            observation(timestamp="2026-08-10T12:00:04Z", network=70),
        ],
        minimum_duration_seconds=2,
        observations_sha256="b" * 64,
        measurement_start_unix_ms=1_786_363_200_000,
        measurement_end_unix_ms=1_786_363_202_000,
        soak_end_unix_ms=1_786_363_204_000,
    )

    assert summary.observation_count == 2
    assert summary.soak_observation_count == 2
    assert summary.max_network_percent == 40
    assert summary.soak_maxima_percent["network"] == 70
    assert summary.invalid_reasons == ("generator_soak_network_headroom_below_30_percent",)


def test_headroom_summary_rejects_an_unmeasured_run() -> None:
    summary = summarize_generator_headroom(
        [observation(timestamp="2026-08-10T12:00:00Z")],
        observations_sha256="b" * 64,
    )

    assert summary.valid is False
    assert summary.invalid_reasons == ("generator_observation_window_too_short",)

    too_short = summarize_generator_headroom(
        [
            observation(timestamp="2026-08-10T12:00:00Z"),
            observation(timestamp="2026-08-10T12:00:01Z"),
        ],
        minimum_duration_seconds=3,
        observations_sha256="b" * 64,
    )
    assert too_short.valid is False
    assert too_short.invalid_reasons == ("generator_observation_window_too_short",)


def test_headroom_phase_and_identity_inputs_fail_closed() -> None:
    samples = [
        observation(timestamp="2026-08-10T12:00:00Z"),
        observation(timestamp="2026-08-10T12:00:01Z"),
    ]
    with pytest.raises(ValueError, match="generator_observations_empty"):
        summarize_generator_headroom(
            samples,
            observations_sha256="b" * 64,
            measurement_start_unix_ms=1000,
        )
    with pytest.raises(ValueError, match="generator_observation_host_mismatch"):
        summarize_generator_headroom(
            samples,
            observations_sha256="b" * 64,
            expected_generator_host="generator-b",
        )
    with pytest.raises(ValueError, match="generator_observation_identity_changed"):
        summarize_generator_headroom(
            [samples[0], samples[1].model_copy(update={"generator_host": "generator-b"})],
            observations_sha256="b" * 64,
        )
    with pytest.raises(ValueError, match="generator_observation_timestamps_not_monotonic"):
        summarize_generator_headroom(
            [samples[0], samples[0]],
            observations_sha256="b" * 64,
        )


def test_observation_rejects_non_finite_or_out_of_range_utilization() -> None:
    with pytest.raises(ValidationError):
        observation(timestamp="2026-08-10T12:00:00Z", cpu=float("nan"))
    with pytest.raises(ValidationError):
        observation(timestamp="2026-08-10T12:00:00Z", ram=101)


def test_raw_jsonl_loader_is_strict_and_preserves_all_observations(tmp_path: Path) -> None:
    raw_path = tmp_path / "generator.jsonl"
    expected = [
        observation(timestamp="2026-08-10T12:00:00Z"),
        observation(timestamp="2026-08-10T12:00:01Z", cpu=25),
    ]
    raw_path.write_text(
        "".join(json.dumps(item.model_dump(mode="json")) + "\n" for item in expected),
        encoding="utf-8",
    )

    assert load_observations(raw_path) == tuple(expected)

    raw_path.write_text('{"timestamp":"truncated"}', encoding="utf-8")
    with pytest.raises(ValidationError):
        load_observations(raw_path)


def test_linux_counter_reader_uses_procfs_cgroup_process_limits_and_nic(
    tmp_path: Path,
) -> None:
    (tmp_path / "proc/123/fd").mkdir(parents=True)
    (tmp_path / "proc/123/limits").write_text(
        "Max open files            1000                 1000                 files     \n",
        encoding="utf-8",
    )
    (tmp_path / "proc/123/stat").write_text(
        "123 (load reader) S 1 1 1 0 0 0 0 0 0 0 10 5 0 0 0 0 0 0 0 0 0 0\n",
        encoding="utf-8",
    )
    (tmp_path / "proc/123/status").write_text("VmRSS:\t200 kB\n", encoding="utf-8")
    (tmp_path / "proc/123/cgroup").write_text("0::/tenant.slice/load.slice\n", encoding="utf-8")
    executable = tmp_path / "load-reader"
    executable.write_bytes(b"load-reader")
    (tmp_path / "proc/123/exe").symlink_to(executable)
    (tmp_path / "proc/123/fd/0").touch()
    (tmp_path / "proc/123/fd/1").touch()
    (tmp_path / "sys/class/net/camera0/statistics").mkdir(parents=True)
    (tmp_path / "sys/fs/cgroup/tenant.slice/load.slice").mkdir(parents=True)
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/machine-id").write_text("machine-a\n", encoding="utf-8")
    (tmp_path / "proc/sys/kernel/random").mkdir(parents=True)
    (tmp_path / "proc/sys/kernel/random/boot_id").write_text(
        "11111111-1111-1111-1111-111111111111\n", encoding="utf-8"
    )
    (tmp_path / "proc/sys/net/ipv4").mkdir(parents=True)
    (tmp_path / "proc/sys/net/ipv4/ip_local_port_range").write_text(
        "8000\t8009\n", encoding="utf-8"
    )
    (tmp_path / "proc/sys/net/ipv4/ip_local_reserved_ports").write_text("8009\n", encoding="utf-8")
    (tmp_path / "proc/net").mkdir()
    tcp_header = "  sl  local_address rem_address st\n"
    (tmp_path / "proc/net/tcp").write_text(
        tcp_header + "0: 0100007F:1F40 0100007F:270F 01\n", encoding="utf-8"
    )
    (tmp_path / "proc/net/tcp6").write_text(tcp_header, encoding="utf-8")
    (tmp_path / "proc/stat").write_text(
        "cpu  100 20 30 400 50 6 7 8 0 0\n",
        encoding="utf-8",
    )
    (tmp_path / "proc/meminfo").write_text(
        "MemTotal:       1000 kB\nMemAvailable:    600 kB\n",
        encoding="utf-8",
    )
    (tmp_path / "sys/class/net/camera0/statistics/rx_bytes").write_text("1234\n", encoding="utf-8")
    (tmp_path / "sys/class/net/camera0/statistics/tx_bytes").write_text("5678\n", encoding="utf-8")
    (tmp_path / "sys/class/net/camera0/statistics/rx_packets").write_text("123\n", encoding="utf-8")
    (tmp_path / "sys/class/net/camera0/statistics/tx_packets").write_text("456\n", encoding="utf-8")
    (tmp_path / "sys/class/net/camera0/speed").write_text("1000\n", encoding="utf-8")
    (tmp_path / "sys/class/net/camera0/mtu").write_text("1500\n", encoding="utf-8")
    cgroup = tmp_path / "sys/fs/cgroup/tenant.slice/load.slice"
    (cgroup / "cpu.stat").write_text("usage_usec 1234\n", encoding="utf-8")
    (cgroup / "cpu.max").write_text("100000 100000\n", encoding="utf-8")
    (cgroup / "cpuset.cpus.effective").write_text("0-3\n", encoding="utf-8")
    (cgroup / "memory.current").write_text("100000\n", encoding="utf-8")
    (cgroup / "memory.max").write_text("1000000\n", encoding="utf-8")
    (cgroup / "pids.current").write_text("10\n", encoding="utf-8")
    (cgroup / "pids.max").write_text("100\n", encoding="utf-8")
    (cgroup / "cgroup.procs").write_text("123\n", encoding="utf-8")
    cgroup_parent = cgroup.parent
    (cgroup_parent / "cpu.max").write_text("200000 100000\n", encoding="utf-8")
    (cgroup_parent / "memory.max").write_text("2000000\n", encoding="utf-8")
    (cgroup_parent / "pids.max").write_text("200\n", encoding="utf-8")
    (cgroup_parent / "cpuset.cpus.effective").write_text("0-7\n", encoding="utf-8")
    (cgroup_parent / "cpu.stat").write_text("usage_usec 2234\n", encoding="utf-8")
    (cgroup_parent / "memory.current").write_text("200000\n", encoding="utf-8")
    (cgroup_parent / "pids.current").write_text("20\n", encoding="utf-8")

    counters = read_linux_generator_counters(
        tmp_path,
        interface="camera0",
        pids=(123,),
        cgroup="tenant.slice/load.slice",
        expected_executables={123: hashlib.sha256(b"load-reader").hexdigest()},
        expected_mtu_bytes=1500,
    )

    assert counters.host.cpu_total_ticks == 621
    assert counters.host.cpu_idle_ticks == 450
    assert counters.host.memory_total_bytes == 1_024_000
    assert counters.processes[0].cpu_ticks == 15
    assert counters.processes[0].rss_bytes == 204_800
    assert counters.processes[0].open_file_descriptors == 2
    assert counters.cgroup.memory_limit_bytes == 1_000_000
    assert len(counters.cgroup.constraints) == 2
    assert counters.host.nic_bits_per_second == 1_000_000_000
    assert counters.host.ephemeral_port_start == 8000
    assert counters.host.ephemeral_port_end == 8009
    assert counters.host.ephemeral_port_capacity == 9
    assert counters.host.reserved_ports_sha256 == hashlib.sha256(b"8009").hexdigest()
    assert counters.host.tcp_ephemeral_ports_in_use == 1


def test_linux_counter_reader_rejects_an_unsafe_interface_name(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="invalid_network_interface"):
        read_linux_generator_counters(
            tmp_path,
            interface="../secret",
            pids=(123,),
            cgroup="load.slice",
            expected_executables={123: "a" * 64},
            expected_mtu_bytes=1500,
        )


def test_linux_sampler_writes_exclusive_raw_observations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    counters = iter(
        [
            generator_counters(
                cpu_total=1000,
                cpu_idle=600,
                process_ticks=100,
                network_rx=1000,
                network_tx=2000,
            ),
            generator_counters(
                cpu_total=1200,
                cpu_idle=700,
                process_ticks=120,
                network_rx=1400,
                network_tx=2600,
            ),
            generator_counters(
                cpu_total=1400,
                cpu_idle=800,
                process_ticks=140,
                network_rx=1800,
                network_tx=3200,
            ),
        ]
    )
    monotonic_values = iter([0.0, 1.0, 2.0])
    monkeypatch.setattr(
        load_evidence_module,
        "read_linux_generator_counters",
        lambda root, *, interface, pids, cgroup, expected_executables, expected_mtu_bytes: next(
            counters
        ),
    )
    monkeypatch.setattr(time, "monotonic", lambda: next(monotonic_values))
    monkeypatch.setattr(time, "sleep", lambda _: None)
    output = tmp_path / "raw" / "generator.jsonl"

    count = sample_linux_generator_resources(
        root=tmp_path,
        generator_host="generator-a",
        interface="camera0",
        pids=(123,),
        cgroup="load.slice",
        expected_executables={123: "d" * 64},
        expected_mtu_bytes=1500,
        output=output,
        duration_seconds=1,
        interval_seconds=1,
    )

    assert count == 1
    assert len(load_observations(output)) == 1
    assert output.stat().st_mode & 0o777 == 0o640
    assert output.parent.stat().st_mode & 0o777 == 0o750


def test_linux_sampler_uses_absolute_cadence_with_nonzero_collection_cost(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    counters = iter(
        [
            generator_counters(
                cpu_total=1000,
                cpu_idle=600,
                process_ticks=100,
                network_rx=1000,
                network_tx=2000,
            ),
            generator_counters(
                cpu_total=1200,
                cpu_idle=700,
                process_ticks=120,
                network_rx=1400,
                network_tx=2600,
            ),
            generator_counters(
                cpu_total=1400,
                cpu_idle=800,
                process_ticks=140,
                network_rx=1800,
                network_tx=3200,
            ),
        ]
    )
    monotonic_values = iter((0.0, 0.0, 1.4, 1.4, 2.4))
    sleeps: list[float] = []
    monkeypatch.setattr(
        load_evidence_module,
        "read_linux_generator_counters",
        lambda root, *, interface, pids, cgroup, expected_executables, expected_mtu_bytes: next(
            counters
        ),
    )
    monkeypatch.setattr(time, "monotonic", lambda: next(monotonic_values))
    monkeypatch.setattr(time, "sleep", sleeps.append)
    output = tmp_path / "raw" / "generator.jsonl"

    count = sample_linux_generator_resources(
        root=tmp_path,
        generator_host="generator-a",
        interface="camera0",
        pids=(123,),
        cgroup="load.slice",
        expected_executables={123: "d" * 64},
        expected_mtu_bytes=1500,
        output=output,
        duration_seconds=2,
        interval_seconds=1,
    )

    observations = load_observations(output)
    assert count == 2
    assert sleeps == pytest.approx([1.0, 0.6])
    assert [item.interval_seconds for item in observations] == pytest.approx([1.4, 1.0])


def test_mediamtx_metrics_parser_and_sut_capacity_gates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class MetricsResponse:
        def __enter__(self) -> MetricsResponse:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            labels = 'id="1",path="path",remoteAddr="127.0.0.1:5000",state="read"'
            session_metrics = {
                "rtsp_sessions": 1,
                "rtsp_sessions_inbound_rtcp_packets_in_error": 0,
                "rtsp_sessions_inbound_rtp_packets": 0,
                "rtsp_sessions_inbound_rtp_packets_lost": 0,
                "rtsp_sessions_inbound_rtp_packets_in_error": 0,
                "rtsp_sessions_outbound_rtp_packets": 100,
                "rtsp_sessions_outbound_rtp_packets_discarded": 0,
                "rtsp_sessions_outbound_rtp_packets_reported_lost": 0,
                "rtsp_sessions_rtcp_packets_in_error": 0,
                "rtsp_sessions_rtp_packets_in_error": 0,
                "rtsp_sessions_rtp_packets_lost": 0,
            }
            body = 'paths{name="path",state="ready"} 1\n'
            body += "".join(
                f"{family}{{{labels}}} {value}\n" for family, value in session_metrics.items()
            )
            body += 'paths_inbound_frames_in_error{name="path",state="ready"} 0\n'
            return body.encode("ascii")

    monkeypatch.setattr(urllib.request, "urlopen", lambda *args, **kwargs: MetricsResponse())
    metrics = read_mediamtx_metrics("http://127.0.0.1:9998/metrics")
    assert metrics.total_rtsp_sessions == 1
    assert metrics.ready_runtime_paths == 1
    assert metrics.outbound_rtp_packets_reported_lost == 0

    measurement_start = datetime(2026, 8, 10, tzinfo=UTC)
    measurement_start_ms = int(measurement_start.timestamp() * 1000)
    measurement_end_ms = measurement_start_ms + 1800 * 1000
    soak_end_ms = measurement_end_ms + 86400 * 1000
    observations: list[SutObservation] = []
    for offset_seconds in range(0, 1800 + 86400 + 1, 180):
        timestamp = (
            (measurement_start + timedelta(seconds=offset_seconds))
            .isoformat()
            .replace("+00:00", "Z")
        )
        resource_payload = observation(timestamp=timestamp).model_dump(mode="json")
        resource_payload.update(
            generator_host="proxy.load.internal",
            interval_seconds=180,
        )
        is_final = offset_seconds == 1800 + 86400
        counter_value = offset_seconds + 1 - (180 if is_final else 0)
        active_sessions = (
            ()
            if is_final
            else (
                SessionMetricSnapshot(
                    identity_sha256="1" * 64,
                    state="read",
                    observed_counter_fields=SESSION_COUNTER_FIELDS,
                    inbound_rtcp_packets_in_error=0,
                    inbound_rtp_packets=0,
                    outbound_rtp_packets=counter_value,
                    inbound_rtp_packets_lost=0,
                    inbound_rtp_packets_in_error=0,
                    outbound_rtp_packets_discarded=0,
                    outbound_rtp_packets_reported_lost=0,
                    rtcp_packets_in_error=0,
                    rtp_packets_in_error=0,
                    rtp_packets_lost=0,
                ),
            )
        )
        active_paths = (
            ()
            if is_final
            else (
                PathMetricSnapshot(
                    identity_sha256="2" * 64,
                    state="ready",
                    inbound_frames_in_error=0,
                ),
            )
        )
        observations.append(
            SutObservation(
                sut_host="proxy.load.internal",
                timestamp=timestamp,
                clock_proof=KernelClockProof(
                    observed_at_unix_ms=int(
                        (measurement_start + timedelta(seconds=offset_seconds)).timestamp() * 1000
                    ),
                    synchronized=True,
                    state=0,
                    status=0,
                    max_error_ms=1,
                ),
                resource=ResourceObservation.model_validate(resource_payload),
                mediamtx_rss_bytes=1_000_000 + offset_seconds,
                mediamtx_open_file_descriptors=100,
                metrics_families=REQUIRED_SUT_METRIC_FAMILIES,
                total_rtsp_sessions=0 if is_final else 1,
                ready_runtime_paths=0 if is_final else 1,
                active_session_counters=active_sessions,
                active_path_counters=active_paths,
                cumulative_inbound_rtp_packets=0,
                cumulative_outbound_rtp_packets=counter_value,
                inbound_rtp_packets_lost=0,
                inbound_rtp_packets_in_error=0,
                inbound_rtcp_packets_in_error=0,
                outbound_rtp_packets_discarded=0,
                outbound_rtp_packets_reported_lost=0,
                rtcp_packets_in_error=0,
                rtp_packets_in_error=0,
                rtp_packets_lost=0,
                path_inbound_frames_in_error=0,
            )
        )

    summary = summarize_sut_capacity(
        observations,
        expected_sut_host="proxy.load.internal",
        expected_interval_seconds=180,
        maximum_gap_factor=1.5,
        observations_sha256="a" * 64,
        measurement_start_unix_ms=measurement_start_ms,
        measurement_end_unix_ms=measurement_end_ms,
        soak_end_unix_ms=soak_end_ms,
        maximum_clock_error_ms=10,
    )

    assert summary.valid is True
    assert summary.soak_max_rolling_6h_rss_slope_percent_per_hour is not None
    assert summary.final_total_rtsp_sessions == 0

    transitioned = list(observations)
    first_session = transitioned[0].active_session_counters[0]
    transitioned[0] = transitioned[0].model_copy(
        update={
            "active_session_counters": (
                first_session.model_copy(
                    update={
                        "state": "idle",
                        "observed_counter_fields": SESSION_COUNTER_FIELDS,
                        "outbound_rtp_packets": 0,
                    }
                ),
            ),
            "cumulative_outbound_rtp_packets": 0,
        }
    )
    assert summarize_sut_capacity(
        transitioned,
        expected_sut_host="proxy.load.internal",
        expected_interval_seconds=180,
        maximum_gap_factor=1.5,
        observations_sha256="9" * 64,
        measurement_start_unix_ms=measurement_start_ms,
        measurement_end_unix_ms=measurement_end_ms,
        soak_end_unix_ms=soak_end_ms,
        maximum_clock_error_ms=10,
    ).valid

    tampered = list(observations)
    tampered[1] = tampered[1].model_copy(update={"cumulative_outbound_rtp_packets": 0})
    with pytest.raises(ValueError, match="sut_cumulative_counter_not_reproducible"):
        summarize_sut_capacity(
            tampered,
            expected_sut_host="proxy.load.internal",
            expected_interval_seconds=180,
            maximum_gap_factor=1.5,
            observations_sha256="8" * 64,
            measurement_start_unix_ms=measurement_start_ms,
            measurement_end_unix_ms=measurement_end_ms,
            soak_end_unix_ms=soak_end_ms,
            maximum_clock_error_ms=10,
        )

    lossy = list(observations)
    lossy[20:] = [
        item.model_copy(
            update={
                "active_session_counters": tuple(
                    session.model_copy(update={"outbound_rtp_packets_reported_lost": 1})
                    for session in item.active_session_counters
                ),
                "outbound_rtp_packets_reported_lost": 1,
            }
        )
        for item in lossy[20:]
    ]
    rejected = summarize_sut_capacity(
        lossy,
        expected_sut_host="proxy.load.internal",
        expected_interval_seconds=180,
        maximum_gap_factor=1.5,
        observations_sha256="b" * 64,
        measurement_start_unix_ms=measurement_start_ms,
        measurement_end_unix_ms=measurement_end_ms,
        soak_end_unix_ms=soak_end_ms,
        maximum_clock_error_ms=10,
    )
    assert "sut_added_packet_loss_or_error_observed" in rejected.invalid_reasons

    leaking = [
        item.model_copy(
            update={
                "mediamtx_rss_bytes": 1_000_000 + min(max(0, offset_seconds - 1800), 6 * 3600) * 20
            }
        )
        for item, offset_seconds in zip(
            observations,
            range(0, 1800 + 86400 + 1, 180),
            strict=True,
        )
    ]
    leak_summary = summarize_sut_capacity(
        leaking,
        expected_sut_host="proxy.load.internal",
        expected_interval_seconds=180,
        maximum_gap_factor=1.5,
        observations_sha256="c" * 64,
        measurement_start_unix_ms=measurement_start_ms,
        measurement_end_unix_ms=measurement_end_ms,
        soak_end_unix_ms=soak_end_ms,
        maximum_clock_error_ms=10,
    )
    assert "sut_soak_rss_slope_above_1_percent_per_hour" in leak_summary.invalid_reasons

    undrained = list(observations)
    undrained[-1] = undrained[-1].model_copy(update={"ready_runtime_paths": 1})
    drain_summary = summarize_sut_capacity(
        undrained,
        expected_sut_host="proxy.load.internal",
        expected_interval_seconds=180,
        maximum_gap_factor=1.5,
        observations_sha256="d" * 64,
        measurement_start_unix_ms=measurement_start_ms,
        measurement_end_unix_ms=measurement_end_ms,
        soak_end_unix_ms=soak_end_ms,
        maximum_clock_error_ms=10,
    )
    assert "sut_sessions_not_drained_after_workload" in drain_summary.invalid_reasons

    bad_clock = list(observations)
    bad_clock[10] = bad_clock[10].model_copy(
        update={"clock_proof": bad_clock[10].clock_proof.model_copy(update={"max_error_ms": 20})}
    )
    clock_summary = summarize_sut_capacity(
        bad_clock,
        expected_sut_host="proxy.load.internal",
        expected_interval_seconds=180,
        maximum_gap_factor=1.5,
        observations_sha256="e" * 64,
        measurement_start_unix_ms=measurement_start_ms,
        measurement_end_unix_ms=measurement_end_ms,
        soak_end_unix_ms=soak_end_ms,
        maximum_clock_error_ms=10,
    )
    assert "sut_clock_proof_invalid" in clock_summary.invalid_reasons

    incomplete_families = list(observations)
    incomplete_families[25] = incomplete_families[25].model_copy(
        update={"metrics_families": REQUIRED_SUT_METRIC_FAMILIES[:-1]}
    )
    family_summary = summarize_sut_capacity(
        incomplete_families,
        expected_sut_host="proxy.load.internal",
        expected_interval_seconds=180,
        maximum_gap_factor=1.5,
        observations_sha256="f" * 64,
        measurement_start_unix_ms=measurement_start_ms,
        measurement_end_unix_ms=measurement_end_ms,
        soak_end_unix_ms=soak_end_ms,
        maximum_clock_error_ms=10,
    )
    assert "sut_loss_metric_family_set_incomplete" in family_summary.invalid_reasons


def test_mediamtx_metrics_parser_accepts_only_exact_unlabeled_zero_sentinels(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class MetricsResponse:
        def __enter__(self) -> MetricsResponse:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            return "".join(f"{family} 0\n" for family in REQUIRED_SUT_METRIC_FAMILIES).encode(
                "ascii"
            )

    monkeypatch.setattr(urllib.request, "urlopen", lambda *args, **kwargs: MetricsResponse())
    counters = read_mediamtx_metrics("http://127.0.0.1:9998/metrics")

    assert counters.observed_families == REQUIRED_SUT_METRIC_FAMILIES
    assert counters.total_rtsp_sessions == 0
    assert counters.ready_runtime_paths == 0
    assert counters.active_sessions == ()
    assert counters.active_paths == ()

    class InvalidMetricsResponse(MetricsResponse):
        def read(self) -> bytes:
            return b"rtsp_sessions 1\n"

    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda *args, **kwargs: InvalidMetricsResponse(),
    )
    with pytest.raises(ValueError, match="sut_metrics_invalid"):
        read_mediamtx_metrics("http://127.0.0.1:9998/metrics")

    class DuplicateZeroMetricsResponse(MetricsResponse):
        def read(self) -> bytes:
            return b"rtsp_sessions 0\nrtsp_sessions 0\n"

    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda *args, **kwargs: DuplicateZeroMetricsResponse(),
    )
    with pytest.raises(ValueError, match="sut_metrics_invalid"):
        read_mediamtx_metrics("http://127.0.0.1:9998/metrics")

    class MixedMetricsResponse(MetricsResponse):
        def read(self) -> bytes:
            return (
                b"rtsp_sessions 0\n"
                b'rtsp_sessions{id="1",path="path",remoteAddr="127.0.0.1:5000",state="idle"} 1\n'
            )

    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda *args, **kwargs: MixedMetricsResponse(),
    )
    with pytest.raises(ValueError, match="sut_metrics_invalid"):
        read_mediamtx_metrics("http://127.0.0.1:9998/metrics")


@pytest.mark.parametrize(
    "invalid_line",
    [
        (
            'rtsp_sessions_outbound_rtp_packets{id="1",path="other",'
            'remoteAddr="127.0.0.1:5000",state="read"} 1'
        ),
        (
            'rtsp_sessions_outbound_rtp_packets{id="1",path="path",'
            'remoteAddr="127.0.0.1:5001",state="read"} 1'
        ),
        (
            'rtsp_sessions_outbound_rtp_packets{id="1",path="path",'
            'remoteAddr="127.0.0.1:5000",state="read",extra="x"} 1'
        ),
        (
            'rtsp_sessions_outbound_rtp_packets{id="1",path="path",'
            'remoteAddr="127.0.0.1:5000",state="unknown"} 1'
        ),
        'paths{name="path",state="ready"} 1',
    ],
)
def test_mediamtx_metrics_parser_rejects_identity_or_label_drift(
    monkeypatch: pytest.MonkeyPatch,
    invalid_line: str,
) -> None:
    labels = 'id="1",path="path",remoteAddr="127.0.0.1:5000",state="read"'
    session_families = tuple(
        family for family in REQUIRED_SUT_METRIC_FAMILIES if family.startswith("rtsp_sessions_")
    )
    body = [
        'paths{name="path",state="ready"} 1',
        'paths_inbound_frames_in_error{name="path",state="ready"} 0',
        f"rtsp_sessions{{{labels}}} 1",
        *(f"{family}{{{labels}}} 0" for family in session_families),
        invalid_line,
    ]

    class MetricsResponse:
        def __enter__(self) -> MetricsResponse:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            return ("\n".join(body) + "\n").encode("ascii")

    monkeypatch.setattr(urllib.request, "urlopen", lambda *args, **kwargs: MetricsResponse())

    with pytest.raises(ValueError, match="sut_metrics_invalid"):
        read_mediamtx_metrics("http://127.0.0.1:9998/metrics")


def test_mediamtx_session_identity_survives_idle_read_path_transition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def metrics_body(*, session_path: str, state: str, outbound_packets: int) -> bytes:
        labels = f'id="1",path="{session_path}",remoteAddr="127.0.0.1:5000",state="{state}"'
        session_families = tuple(
            family for family in REQUIRED_SUT_METRIC_FAMILIES if family.startswith("rtsp_sessions_")
        )
        outbound_family = "rtsp_sessions_outbound_rtp_packets"
        return (
            "\n".join(
                [
                    'paths{name="path",state="ready"} 1',
                    'paths_inbound_frames_in_error{name="path",state="ready"} 0',
                    f"rtsp_sessions{{{labels}}} 1",
                    *(
                        f"{family}{{{labels}}} "
                        f"{outbound_packets if family == outbound_family else 0}"
                        for family in session_families
                    ),
                ]
            )
            + "\n"
        ).encode("ascii")

    bodies = iter(
        (
            metrics_body(session_path="", state="idle", outbound_packets=5),
            metrics_body(session_path="path", state="read", outbound_packets=10),
        )
    )

    class MetricsResponse:
        def __init__(self, body: bytes) -> None:
            self.body = body

        def __enter__(self) -> MetricsResponse:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            return self.body

    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda *args, **kwargs: MetricsResponse(next(bodies)),
    )
    idle = read_mediamtx_metrics("http://127.0.0.1:9998/metrics")
    reading = read_mediamtx_metrics("http://127.0.0.1:9998/metrics")

    assert idle.active_sessions[0].identity_sha256 == reading.active_sessions[0].identity_sha256
    history = load_evidence_module._MetricHistory()
    assert history.update(idle.active_sessions, idle.active_paths)["outbound_rtp_packets"] == 5
    assert (
        history.update(reading.active_sessions, reading.active_paths)["outbound_rtp_packets"] == 10
    )


def test_sut_metric_history_fails_continuous_resets_and_accumulates_reappearance() -> None:
    def session(value: int) -> SessionMetricSnapshot:
        return SessionMetricSnapshot(
            identity_sha256="1" * 64,
            state="read",
            observed_counter_fields=SESSION_COUNTER_FIELDS,
            inbound_rtcp_packets_in_error=0,
            inbound_rtp_packets=0,
            outbound_rtp_packets=value,
            inbound_rtp_packets_lost=0,
            inbound_rtp_packets_in_error=0,
            outbound_rtp_packets_discarded=0,
            outbound_rtp_packets_reported_lost=0,
            rtcp_packets_in_error=0,
            rtp_packets_in_error=0,
            rtp_packets_lost=0,
        )

    history = load_evidence_module._MetricHistory()
    history.update(
        (session(10),),
        (
            PathMetricSnapshot(
                identity_sha256="2" * 64,
                state="ready",
                inbound_frames_in_error=10,
            ),
        ),
    )
    with pytest.raises(ValueError, match="sut_session_counter_reset_while_active"):
        history.update((session(9),), ())

    path_history = load_evidence_module._MetricHistory()
    path_history.update(
        (),
        (
            PathMetricSnapshot(
                identity_sha256="2" * 64,
                state="ready",
                inbound_frames_in_error=10,
            ),
        ),
    )
    with pytest.raises(ValueError, match="sut_path_counter_reset_while_active"):
        path_history.update(
            (),
            (
                PathMetricSnapshot(
                    identity_sha256="2" * 64,
                    state="ready",
                    inbound_frames_in_error=9,
                ),
            ),
        )

    reappeared = load_evidence_module._MetricHistory()
    assert (
        reappeared.update(
            (session(10),),
            (
                PathMetricSnapshot(
                    identity_sha256="2" * 64,
                    state="ready",
                    inbound_frames_in_error=10,
                ),
            ),
        )["outbound_rtp_packets"]
        == 10
    )
    reappeared.update((), ())
    totals = reappeared.update(
        (session(2),),
        (
            PathMetricSnapshot(
                identity_sha256="2" * 64,
                state="ready",
                inbound_frames_in_error=3,
            ),
        ),
    )
    assert totals["outbound_rtp_packets"] == 12
    assert totals["path_inbound_frames_in_error"] == 13

    transitioned_path = load_evidence_module._MetricHistory()
    transitioned_path.update(
        (),
        (
            PathMetricSnapshot(
                identity_sha256="2" * 64,
                state="ready",
                inbound_frames_in_error=10,
            ),
        ),
    )
    transitioned_path.update(
        (),
        (
            PathMetricSnapshot(
                identity_sha256="2" * 64,
                state="notReady",
                inbound_frames_in_error=0,
            ),
        ),
    )
    transitioned_totals = transitioned_path.update(
        (),
        (
            PathMetricSnapshot(
                identity_sha256="2" * 64,
                state="ready",
                inbound_frames_in_error=2,
            ),
        ),
    )
    assert transitioned_totals["path_inbound_frames_in_error"] == 12


def test_linux_sut_sampler_binds_mediamtx_process_and_metrics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    counters = iter(
        [
            generator_counters(
                cpu_total=1000,
                cpu_idle=600,
                process_ticks=100,
                network_rx=1000,
                network_tx=2000,
            ),
            generator_counters(
                cpu_total=1200,
                cpu_idle=700,
                process_ticks=120,
                network_rx=1400,
                network_tx=2600,
            ),
        ]
    )
    monotonic_values = iter((0.0, 1.0, 2.0))
    monkeypatch.setattr(
        load_evidence_module,
        "read_linux_generator_counters",
        lambda root, *, interface, pids, cgroup, expected_executables, expected_mtu_bytes: next(
            counters
        ),
    )
    monkeypatch.setattr(
        load_evidence_module,
        "read_mediamtx_metrics",
        lambda url: MediaMetricsCounters(
            observed_families=REQUIRED_SUT_METRIC_FAMILIES,
            total_rtsp_sessions=1,
            ready_runtime_paths=1,
            active_sessions=(
                SessionMetricSnapshot(
                    identity_sha256="1" * 64,
                    state="read",
                    observed_counter_fields=SESSION_COUNTER_FIELDS,
                    inbound_rtcp_packets_in_error=0,
                    inbound_rtp_packets=0,
                    outbound_rtp_packets=100,
                    inbound_rtp_packets_lost=0,
                    inbound_rtp_packets_in_error=0,
                    outbound_rtp_packets_discarded=0,
                    outbound_rtp_packets_reported_lost=0,
                    rtcp_packets_in_error=0,
                    rtp_packets_in_error=0,
                    rtp_packets_lost=0,
                ),
            ),
            active_paths=(
                PathMetricSnapshot(
                    identity_sha256="2" * 64,
                    state="ready",
                    inbound_frames_in_error=0,
                ),
            ),
            inbound_rtp_packets=0,
            outbound_rtp_packets=100,
            inbound_rtp_packets_lost=0,
            inbound_rtp_packets_in_error=0,
            inbound_rtcp_packets_in_error=0,
            outbound_rtp_packets_discarded=0,
            outbound_rtp_packets_reported_lost=0,
            rtcp_packets_in_error=0,
            rtp_packets_in_error=0,
            rtp_packets_lost=0,
            path_inbound_frames_in_error=0,
        ),
    )
    monkeypatch.setattr(time, "monotonic", lambda: next(monotonic_values))
    monkeypatch.setattr(time, "sleep", lambda _: None)
    monkeypatch.setattr(
        load_evidence_module,
        "prove_linux_clock",
        lambda _: KernelClockProof(
            observed_at_unix_ms=2_000_000,
            synchronized=True,
            state=0,
            status=0,
            max_error_ms=1,
        ),
    )
    output = tmp_path / "raw" / "sut.jsonl"

    count = sample_linux_sut_resources(
        root=tmp_path,
        sut_host="proxy.load.internal",
        interface="camera0",
        mediamtx_pid=123,
        cgroup="mediamtx.service",
        expected_mediamtx_sha256="d" * 64,
        expected_mtu_bytes=1500,
        metrics_url="http://127.0.0.1:9998/metrics",
        output=output,
        duration_seconds=1,
        interval_seconds=1,
        maximum_clock_error_ms=10,
    )

    observations = load_sut_observations(output)
    assert count == 1
    assert observations[0].total_rtsp_sessions == 1
    assert observations[0].resource.process_count == 1
