from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

import rtsp_proxy.load_evidence as load_evidence_module
from rtsp_proxy.load_evidence import (
    CgroupCounters,
    GeneratorCounters,
    HostCounters,
    ProcessCounters,
    ResourceObservation,
    load_observations,
    read_linux_generator_counters,
    sample_linux_generator_resources,
    summarize_generator_headroom,
)


def observation(
    *,
    timestamp: str,
    cpu: float = 20,
    ram: float = 30,
    fd: float = 10,
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
        cgroup_pids_percent=fd,
        network_percent=network,
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
            nic_bits_per_second=8_000,
        ),
        processes=(
            ProcessCounters(
                pid=123,
                cpu_ticks=process_ticks,
                rss_bytes=200,
                open_file_descriptors=200,
                max_file_descriptors=1_000,
            ),
        ),
        cgroup=CgroupCounters(
            cpu_usage_usec=process_ticks * 10_000,
            cpu_capacity_cores=1,
            memory_current_bytes=300,
            memory_limit_bytes=1_000,
            pids_current=20,
            pids_limit=100,
        ),
        machine_id_sha256="a" * 64,
        boot_id="11111111-1111-1111-1111-111111111111",
        clock_ticks_per_second=100,
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
    assert measured.cgroup_pids_percent == 20
    assert measured.network_percent == 60


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
        "Max open files            1000                 1000                 files\n",
        encoding="utf-8",
    )
    (tmp_path / "proc/123/stat").write_text(
        "123 (load reader) S 1 1 1 0 0 0 0 0 0 0 10 5 0 0 0 0 0 0 0 0 0 0\n",
        encoding="utf-8",
    )
    (tmp_path / "proc/123/status").write_text("VmRSS:\t200 kB\n", encoding="utf-8")
    (tmp_path / "proc/123/fd/0").touch()
    (tmp_path / "proc/123/fd/1").touch()
    (tmp_path / "sys/class/net/camera0/statistics").mkdir(parents=True)
    (tmp_path / "sys/fs/cgroup/load.slice").mkdir(parents=True)
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/machine-id").write_text("machine-a\n", encoding="utf-8")
    (tmp_path / "proc/sys/kernel/random").mkdir(parents=True)
    (tmp_path / "proc/sys/kernel/random/boot_id").write_text(
        "11111111-1111-1111-1111-111111111111\n", encoding="utf-8"
    )
    (tmp_path / "proc/stat").write_text(
        "cpu  100 20 30 400 50 6 7 8 0 0\n",
        encoding="utf-8",
    )
    (tmp_path / "proc/meminfo").write_text(
        "MemTotal:       1000 kB\nMemAvailable:    600 kB\n",
        encoding="utf-8",
    )
    (tmp_path / "sys/class/net/camera0/statistics/rx_bytes").write_text(
        "1234\n", encoding="utf-8"
    )
    (tmp_path / "sys/class/net/camera0/statistics/tx_bytes").write_text(
        "5678\n", encoding="utf-8"
    )
    (tmp_path / "sys/class/net/camera0/speed").write_text("1000\n", encoding="utf-8")
    cgroup = tmp_path / "sys/fs/cgroup/load.slice"
    (cgroup / "cpu.stat").write_text("usage_usec 1234\n", encoding="utf-8")
    (cgroup / "cpu.max").write_text("100000 100000\n", encoding="utf-8")
    (cgroup / "memory.current").write_text("100000\n", encoding="utf-8")
    (cgroup / "memory.max").write_text("1000000\n", encoding="utf-8")
    (cgroup / "pids.current").write_text("10\n", encoding="utf-8")
    (cgroup / "pids.max").write_text("100\n", encoding="utf-8")

    counters = read_linux_generator_counters(
        tmp_path,
        interface="camera0",
        pids=(123,),
        cgroup="load.slice",
    )

    assert counters.host.cpu_total_ticks == 621
    assert counters.host.cpu_idle_ticks == 450
    assert counters.host.memory_total_bytes == 1_024_000
    assert counters.processes[0].cpu_ticks == 15
    assert counters.processes[0].rss_bytes == 204_800
    assert counters.processes[0].open_file_descriptors == 2
    assert counters.cgroup.memory_limit_bytes == 1_000_000
    assert counters.host.nic_bits_per_second == 1_000_000_000


def test_linux_counter_reader_rejects_an_unsafe_interface_name(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="invalid_network_interface"):
        read_linux_generator_counters(
            tmp_path, interface="../secret", pids=(123,), cgroup="load.slice"
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
        lambda root, *, interface, pids, cgroup: next(counters),
    )
    monkeypatch.setattr(load_evidence_module.time, "monotonic", lambda: next(monotonic_values))
    monkeypatch.setattr(load_evidence_module.time, "sleep", lambda _: None)
    output = tmp_path / "raw" / "generator.jsonl"

    count = sample_linux_generator_resources(
        root=tmp_path,
        generator_host="generator-a",
        interface="camera0",
        pids=(123,),
        cgroup="load.slice",
        output=output,
        duration_seconds=1,
        interval_seconds=1,
    )

    assert count == 1
    assert len(load_observations(output)) == 1
    assert output.stat().st_mode & 0o777 == 0o640
    assert output.parent.stat().st_mode & 0o777 == 0o750
