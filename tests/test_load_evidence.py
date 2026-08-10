from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

import rtsp_proxy.load_evidence as load_evidence_module
from rtsp_proxy.load_evidence import (
    HostCounters,
    ResourceObservation,
    load_observations,
    read_linux_host_counters,
    sample_linux_host_resources,
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
        timestamp=timestamp,
        cpu_percent=cpu,
        ram_percent=ram,
        fd_percent=fd,
        network_percent=network,
    )


def test_host_counter_delta_uses_hard_limits_and_full_duplex_nic_rate() -> None:
    before = HostCounters(
        cpu_total_ticks=1_000,
        cpu_idle_ticks=600,
        memory_total_bytes=1_000,
        memory_available_bytes=600,
        allocated_file_descriptors=100,
        max_file_descriptors=1_000,
        network_rx_bytes=1_000,
        network_tx_bytes=2_000,
        nic_bits_per_second=8_000,
    )
    after = HostCounters(
        cpu_total_ticks=1_200,
        cpu_idle_ticks=700,
        memory_total_bytes=1_000,
        memory_available_bytes=500,
        allocated_file_descriptors=200,
        max_file_descriptors=1_000,
        network_rx_bytes=1_400,
        network_tx_bytes=2_600,
        nic_bits_per_second=8_000,
    )

    measured = after.observation_since(
        before,
        elapsed_seconds=1,
        timestamp="2026-08-10T12:00:00Z",
    )

    assert measured.cpu_percent == 50
    assert measured.ram_percent == 50
    assert measured.fd_percent == 20
    assert measured.network_percent == 60


def test_generator_headroom_requires_every_resource_to_stay_below_70_percent() -> None:
    summary = summarize_generator_headroom(
        [
            observation(timestamp="2026-08-10T12:00:00Z"),
            observation(timestamp="2026-08-10T12:00:01Z", cpu=69.9, ram=60, fd=50),
        ]
    )

    assert summary.valid is True
    assert summary.invalid_reasons == ()
    assert summary.max_cpu_percent == 69.9
    assert summary.elapsed_seconds == 1

    invalid = summarize_generator_headroom(
        [
            observation(timestamp="2026-08-10T12:00:00Z"),
            observation(timestamp="2026-08-10T12:00:01Z", network=70),
        ]
    )
    assert invalid.valid is False
    assert invalid.invalid_reasons == ("generator_network_headroom_below_30_percent",)


def test_headroom_summary_rejects_an_unmeasured_run() -> None:
    summary = summarize_generator_headroom(
        [observation(timestamp="2026-08-10T12:00:00Z")]
    )

    assert summary.valid is False
    assert summary.invalid_reasons == ("generator_observation_window_too_short",)

    too_short = summarize_generator_headroom(
        [
            observation(timestamp="2026-08-10T12:00:00Z"),
            observation(timestamp="2026-08-10T12:00:01Z"),
        ],
        minimum_duration_seconds=2,
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


def test_linux_counter_reader_uses_procfs_sysfs_and_interface_speed(tmp_path: Path) -> None:
    (tmp_path / "proc/sys/fs").mkdir(parents=True)
    (tmp_path / "sys/class/net/camera0/statistics").mkdir(parents=True)
    (tmp_path / "proc/stat").write_text(
        "cpu  100 20 30 400 50 6 7 8 0 0\n",
        encoding="utf-8",
    )
    (tmp_path / "proc/meminfo").write_text(
        "MemTotal:       1000 kB\nMemAvailable:    600 kB\n",
        encoding="utf-8",
    )
    (tmp_path / "proc/sys/fs/file-nr").write_text("100\t0\t1000\n", encoding="utf-8")
    (tmp_path / "proc/sys/fs/file-max").write_text("1000\n", encoding="utf-8")
    (tmp_path / "sys/class/net/camera0/statistics/rx_bytes").write_text(
        "1234\n", encoding="utf-8"
    )
    (tmp_path / "sys/class/net/camera0/statistics/tx_bytes").write_text(
        "5678\n", encoding="utf-8"
    )
    (tmp_path / "sys/class/net/camera0/speed").write_text("1000\n", encoding="utf-8")

    counters = read_linux_host_counters(tmp_path, interface="camera0")

    assert counters == HostCounters(
        cpu_total_ticks=621,
        cpu_idle_ticks=450,
        memory_total_bytes=1_024_000,
        memory_available_bytes=614_400,
        allocated_file_descriptors=100,
        max_file_descriptors=1_000,
        network_rx_bytes=1_234,
        network_tx_bytes=5_678,
        nic_bits_per_second=1_000_000_000,
    )


def test_linux_counter_reader_rejects_an_unsafe_interface_name(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="invalid_network_interface"):
        read_linux_host_counters(tmp_path, interface="../secret")


def test_linux_sampler_writes_exclusive_raw_observations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    counters = iter(
        [
            HostCounters(1000, 600, 1000, 600, 100, 1000, 1000, 2000, 8000),
            HostCounters(1200, 700, 1000, 500, 200, 1000, 1400, 2600, 8000),
            HostCounters(1400, 800, 1000, 500, 200, 1000, 1800, 3200, 8000),
        ]
    )
    monotonic_values = iter([0.0, 1.0, 2.0])
    monkeypatch.setattr(
        load_evidence_module,
        "read_linux_host_counters",
        lambda root, *, interface: next(counters),
    )
    monkeypatch.setattr(load_evidence_module.time, "monotonic", lambda: next(monotonic_values))
    monkeypatch.setattr(load_evidence_module.time, "sleep", lambda _: None)
    output = tmp_path / "raw" / "generator.jsonl"

    count = sample_linux_host_resources(
        root=tmp_path,
        interface="camera0",
        output=output,
        duration_seconds=1,
        interval_seconds=1,
    )

    assert count == 2
    assert len(load_observations(output)) == 2
    assert output.stat().st_mode & 0o777 == 0o640
    assert output.parent.stat().st_mode & 0o777 == 0o750
