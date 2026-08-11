from __future__ import annotations

import ctypes
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import pytest
from pydantic import ValidationError

import rtsp_proxy.load_evidence as load_evidence_module
from rtsp_proxy.load_catalog import build_direct_reader_plan
from rtsp_proxy.load_cli import main as load_cli_main
from rtsp_proxy.load_evidence import (
    REQUIRED_SUT_METRIC_FAMILIES,
    KernelClockProof,
    ResourceObservation,
    RuntimeProcessBinding,
    RuntimeProcessLimit,
    SutObservation,
    summarize_generator_headroom,
)
from rtsp_proxy.load_profile import (
    LoadProfile,
    canonical_profile_bytes,
    finalize_run_directory,
    initialize_run_directory,
    lifecycle_start_unix_ms,
    measurement_end_unix_ms,
    measurement_start_unix_ms,
    ramp_end_unix_ms,
    sut_sampling_end_unix_ms,
    validate_comparison_pair,
    verify_run_directory,
    warm_anchor_start_unix_ms,
    workload_end_unix_ms,
)
from rtsp_proxy.load_results import summarize_reader_events
from rtsp_proxy.load_run import (
    FixtureManifest,
    inspect_fixture,
    load_stored_profile,
    prepare_run_directory,
    sha256_file,
    validate_fixture_manifest,
    write_summary,
)
from rtsp_proxy.load_runtime import (
    GStreamerRuntime,
    LinuxRuntimeManifest,
    RuntimeLibrary,
    RuntimePackage,
    RuntimeProcess,
    RuntimeSetting,
    capture_generator_runtime,
    validate_runtime_comparison_pair,
    validate_runtime_manifest,
)


def runtime_process_bindings(count: int = 2) -> tuple[RuntimeProcessBinding, ...]:
    return tuple(
        RuntimeProcessBinding(
            pid=100 + index,
            executable_sha256=("a" if index == 0 else "b") * 64,
            start_time_ticks=1000 + index,
        )
        for index in range(count)
    )


def runtime_process_bindings_sha256(bindings: tuple[RuntimeProcessBinding, ...]) -> str:
    return hashlib.sha256(
        json.dumps(
            [item.model_dump(mode="json") for item in bindings],
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def runtime_manifest(
    profile: LoadProfile,
    *,
    role: Literal["generator", "sut"],
    host: str,
    architecture: Literal["amd64", "arm64"],
    processes: tuple[RuntimeProcessBinding, ...],
    machine_id_sha256: str,
    boot_id: str,
    observed_at_unix_ms: int,
) -> LinuxRuntimeManifest:
    typed_processes = tuple(
        RuntimeProcess(
            pid=item.pid,
            executable_sha256=item.executable_sha256,
            start_time_ticks=item.start_time_ticks,
            max_open_files_soft=65536,
            max_open_files_hard=65536,
            max_processes_soft="unlimited",
            max_processes_hard="unlimited",
        )
        for item in processes
    )
    package = RuntimePackage(
        name="libgstreamer1.0-0",
        version=profile.artifacts.gstreamer_build_id,
        architecture="amd64" if architecture == "amd64" else "arm64",
    )
    package_digest = hashlib.sha256(
        json.dumps(
            [package.model_dump(mode="json")],
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    gstreamer = (
        GStreamerRuntime(
            version=profile.artifacts.gstreamer_version,
            package_build_id=profile.artifacts.gstreamer_build_id,
            gst_launch_path="/usr/bin/gst-launch-1.0",
            gst_launch_sha256="9" * 64,
            packages=(package,),
            packages_sha256=package_digest,
            loaded_libraries=(
                RuntimeLibrary(
                    path="/usr/lib/libgstreamer-1.0.so.0",
                    sha256="8" * 64,
                    size_bytes=1024,
                    device_major=8,
                    device_minor=1,
                    inode=42,
                    process_ids=tuple(item.pid for item in processes),
                ),
            ),
        )
        if role == "generator"
        else None
    )
    return LinuxRuntimeManifest(
        schema_version=1,
        profile_sha256=canonical_profile_bytes(profile)[1],
        role=role,
        host=host,
        architecture=architecture,
        capture_started_clock=KernelClockProof(
            observed_at_unix_ms=observed_at_unix_ms,
            synchronized=True,
            state=0,
            status=0,
            max_error_ms=1,
        ),
        capture_completed_clock=KernelClockProof(
            observed_at_unix_ms=observed_at_unix_ms + 1,
            synchronized=True,
            state=0,
            status=0,
            max_error_ms=1,
        ),
        machine_id_sha256=machine_id_sha256,
        boot_id=boot_id,
        kernel_release="6.8.0-test",
        os_release_sha256="7" * 64,
        cpu_model="test cpu",
        logical_cpu_count=8,
        memory_total_bytes=16 * 1024**3,
        network_interface=profile.network.interface,
        interface_mtu_bytes=profile.network.mtu_bytes,
        nic_link_speed_bits_per_second=10_000_000_000,
        sysctls=tuple(
            RuntimeSetting(
                name=name,
                value=(
                    "32768 60999"
                    if name == "net.ipv4.ip_local_port_range"
                    else ""
                    if name == "net.ipv4.ip_local_reserved_ports"
                    else "1"
                ),
            )
            for name in (
                "fs.file-max",
                "net.core.rmem_max",
                "net.core.somaxconn",
                "net.core.wmem_max",
                "net.ipv4.ip_local_port_range",
                "net.ipv4.ip_local_reserved_ports",
                "net.ipv4.tcp_fin_timeout",
                "net.ipv4.tcp_keepalive_time",
                "net.ipv4.tcp_max_syn_backlog",
                "net.ipv4.tcp_tw_reuse",
            )
        ),
        cgroup_path_sha256="c" * 64,
        cgroup_cpu_capacity_cores=4,
        cgroup_memory_limit_bytes=8 * 1024**3,
        cgroup_pids_limit=100000,
        cgroup_constraint_chain_sha256="5" * 64,
        processes=typed_processes,
        gstreamer=gstreamer,
    )


def write_fixture_manifest(profile: LoadProfile) -> None:
    fixture_path = Path(profile.fixture.path)
    manifest = FixtureManifest(
        schema_version=1,
        fixture_sha256=profile.fixture.sha256,
        fixture_size_bytes=fixture_path.stat().st_size,
        codec=profile.fixture.codec,
        fps=profile.fixture.fps,
        frame_count=profile.fixture.gop_frames * 2,
        duration_seconds=(profile.fixture.gop_frames * 2) / profile.fixture.fps,
        measured_bitrate_bps=profile.fixture.bitrate_bps,
        keyframe_indices=(0, profile.fixture.gop_frames),
        keyframe_intervals=(profile.fixture.gop_frames,),
        loop_keyframe_interval_frames=profile.fixture.gop_frames,
        audio=profile.fixture.audio,
        ffmpeg_version=profile.artifacts.ffmpeg_version,
        ffmpeg_sha256=profile.artifacts.ffmpeg_sha256,
        ffprobe_version="ffprobe test build",
        ffprobe_sha256=profile.artifacts.ffprobe_sha256,
    )
    Path(f"{fixture_path}.manifest.json").write_text(
        json.dumps(manifest.model_dump(mode="json")),
        encoding="utf-8",
    )


def valid_profile(*, tier: str = "smoke") -> dict[str, object]:
    duration = {
        "warmup_seconds": 5 if tier == "smoke" else 900,
        "measurement_seconds": 10 if tier == "smoke" else 1800,
        "soak_seconds": 0 if tier == "smoke" else 86400,
    }
    hosts = [
        {
            "name": "generator-a",
            "architecture": "arm64",
            "rtsp_host": "generator-a.load.internal",
            "rtsp_port": 8554,
            "source_start": 0,
            "source_count": 4 if tier == "smoke" else 2,
        }
    ]
    if tier == "capacity":
        hosts.append(
            {
                "name": "generator-b",
                "architecture": "amd64",
                "rtsp_host": "generator-b.load.internal",
                "rtsp_port": 8554,
                "source_start": 2,
                "source_count": 2,
            }
        )
    return {
        "schema_version": 1,
        "tier": tier,
        "seed": 52545350,
        "comparison_id": "warm-lan-gop50-a",
        "sut_architecture": "amd64",
        "sut_rtsp_host": "proxy.load.internal",
        "sut_rtsp_port": 9999,
        "reader_credentials_file": "/run/rtsp-load/external-basic.txt",
        "artifacts": {
            "git_commit": "a" * 40,
            "mediamtx_version": "v1.20.0",
            "mediamtx_sha256": "b" * 64,
            "ffmpeg_version": "n8.1.2-34-g9b6c8969e0-20260810",
            "ffmpeg_sha256": "c" * 64,
            "ffprobe_sha256": "d" * 64,
            "gstreamer_version": "1.24.2",
            "gstreamer_build_id": "1.24.2-1ubuntu0.1",
            "pull_server_sha256": "f" * 64,
            "load_reader_sha256": "1" * 64,
        },
        "fixture": {
            "source_mode": "rtsp-pull",
            "path": "/srv/rtsp-load/fixture-0.h264",
            "sha256": "e" * 64,
            "codec": "h264",
            "bitrate_bps": 2_000_000,
            "fps": 25,
            "gop_frames": 50,
            "rtp_mtu_bytes": 1200,
            "audio": "none",
        },
        "generator_hosts": hosts,
        "network": {
            "profile": "lan",
            "interface": "camera0",
            "mtu_bytes": 1500,
            "rtt_ms": 0,
            "jitter_ms": 0,
            "loss_percent": 0,
        },
        "workload": {
            "endpoint_mode": "proxy",
            "session_temperature": "warm",
            "registered_paths": 4,
            "active_sources": 4,
            "total_readers": 8,
            "connect_rate_per_second": 10,
            "minimum_rtp_packets_per_second": 100,
            "probe_rate_per_second": 0,
            "crud_rate_per_second": 0,
        },
        "reader_lifecycle": {
            "mode": "single",
            "disconnect_rate_per_second": 0,
            "reconnect_attempts": 0,
            "backoff_base_ms": 250,
            "backoff_max_ms": 30000,
            "outage_percent": 0,
        },
        "evidence_sampling": {
            "interval_seconds": 1,
            "maximum_gap_factor": 1.5,
            "maximum_clock_error_ms": 10,
            "maximum_start_lateness_ms": 250,
        },
        "duration": duration,
    }


def test_valid_profile_keeps_independent_load_axes_and_pull_contract() -> None:
    profile = LoadProfile.model_validate(valid_profile())

    assert profile.fixture.source_mode == "rtsp-pull"
    assert profile.workload.registered_paths == 4
    assert profile.workload.active_sources == 4
    assert profile.workload.total_readers == 8
    assert profile.fixture.gop_seconds == 2


def test_run_phase_epochs_are_explicit_and_non_overlapping() -> None:
    profile = LoadProfile.model_validate(valid_profile())
    start = 2_000_000

    assert ramp_end_unix_ms(profile, start) == start + 300
    assert measurement_start_unix_ms(profile, start) == start + 300 + 5_000
    assert measurement_end_unix_ms(profile, start) == start + 300 + 15_000
    assert lifecycle_start_unix_ms(profile, start) == measurement_start_unix_ms(profile, start)
    assert workload_end_unix_ms(profile, start) == measurement_end_unix_ms(profile, start)


@pytest.mark.parametrize(
    ("duration_field", "value", "error"),
    [
        ("warmup_seconds", 899, "capacity_requires_15m_warmup"),
        ("measurement_seconds", 1799, "capacity_requires_30m_measurement"),
    ],
)
def test_capacity_profile_rejects_short_evidence_windows(
    duration_field: str, value: int, error: str
) -> None:
    raw = valid_profile(tier="capacity")
    duration = raw["duration"]
    assert isinstance(duration, dict)
    duration[duration_field] = value

    with pytest.raises(ValidationError, match=error):
        LoadProfile.model_validate(raw)


def test_lifecycle_window_must_cover_ready_budget_and_backoff() -> None:
    raw = valid_profile()
    lifecycle = raw["reader_lifecycle"]
    assert isinstance(lifecycle, dict)
    lifecycle.update(
        mode="outage",
        reconnect_attempts=1,
        backoff_max_ms=9000,
        outage_percent=25,
    )

    with pytest.raises(
        ValidationError, match="lifecycle_window_does_not_cover_ready_budget_and_backoff"
    ):
        LoadProfile.model_validate(raw)


def test_cold_profile_is_one_single_lifecycle_reader_per_active_path() -> None:
    raw = valid_profile()
    workload = raw["workload"]
    assert isinstance(workload, dict)
    workload["session_temperature"] = "cold"
    with pytest.raises(ValidationError, match="cold_requires_one_reader_per_active_source"):
        LoadProfile.model_validate(raw)

    workload["total_readers"] = workload["active_sources"]
    lifecycle = raw["reader_lifecycle"]
    assert isinstance(lifecycle, dict)
    lifecycle.update(
        mode="steady",
        disconnect_rate_per_second=10,
        reconnect_attempts=1,
        backoff_max_ms=1000,
    )
    with pytest.raises(ValidationError, match="cold_requires_single_lifecycle"):
        LoadProfile.model_validate(raw)

    warm_without_measured = valid_profile()
    warm_workload = warm_without_measured["workload"]
    assert isinstance(warm_workload, dict)
    warm_workload["total_readers"] = warm_workload["active_sources"]
    with pytest.raises(ValidationError, match="warm_requires_anchor_and_measured_readers"):
        LoadProfile.model_validate(warm_without_measured)

    warm_workload["endpoint_mode"] = "direct-control"
    with pytest.raises(ValidationError, match="warm_requires_anchor_and_measured_readers"):
        LoadProfile.model_validate(warm_without_measured)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_mode", "rtsp-push"),
        ("codec", "vp9"),
        ("sha256", "not-a-sha256"),
        ("gop_frames", 0),
    ],
)
def test_fixture_contract_rejects_non_reproducible_or_wrong_path_inputs(
    field: str, value: object
) -> None:
    raw = valid_profile()
    fixture = raw["fixture"]
    assert isinstance(fixture, dict)
    fixture[field] = value

    with pytest.raises(ValidationError):
        LoadProfile.model_validate(raw)


def test_fixture_rejects_audio_the_native_pull_server_cannot_generate() -> None:
    raw = valid_profile()
    fixture = raw["fixture"]
    assert isinstance(fixture, dict)
    fixture["audio"] = "aac"

    with pytest.raises(ValidationError):
        LoadProfile.model_validate(raw)


def test_profile_rejects_collapsed_or_impossible_workload_axes() -> None:
    raw = valid_profile()
    workload = raw["workload"]
    assert isinstance(workload, dict)
    workload["active_sources"] = 5

    with pytest.raises(ValidationError, match="active_sources_exceed_registered_paths"):
        LoadProfile.model_validate(raw)


def test_readers_require_at_least_one_active_source() -> None:
    no_active = valid_profile()
    no_active_workload = no_active["workload"]
    assert isinstance(no_active_workload, dict)
    no_active_workload["active_sources"] = 0
    no_active_workload["total_readers"] = 1
    with pytest.raises(ValidationError, match="readers_require_active_sources"):
        LoadProfile.model_validate(no_active)


def test_capacity_profile_requires_two_generator_hosts_and_full_soak() -> None:
    one_host = valid_profile(tier="capacity")
    hosts = one_host["generator_hosts"]
    assert isinstance(hosts, list)
    hosts.pop()

    with pytest.raises(ValidationError, match="capacity_requires_two_generator_hosts"):
        LoadProfile.model_validate(one_host)

    short_soak = valid_profile(tier="capacity")
    duration = short_soak["duration"]
    assert isinstance(duration, dict)
    duration["soak_seconds"] = 3600

    with pytest.raises(ValidationError, match="capacity_requires_24h_soak"):
        LoadProfile.model_validate(short_soak)

    empty_load = valid_profile(tier="capacity")
    workload = empty_load["workload"]
    assert isinstance(workload, dict)
    workload.update(
        active_sources=0,
        total_readers=0,
        minimum_rtp_packets_per_second=0,
    )
    with pytest.raises(ValidationError, match="capacity_requires_reader_load"):
        LoadProfile.model_validate(empty_load)


@pytest.mark.parametrize(
    ("mode", "connect_rate", "disconnect_rate", "outage_percent"),
    [
        ("steady", 10, 10, 0),
        ("steady", 100, 100, 0),
        ("ramp", 100, 0, 0),
        ("burst", 1000, 0, 0),
        ("outage", 100, 0, 10),
        ("outage", 100, 0, 25),
        ("outage", 100, 0, 100),
    ],
)
def test_consensus_reader_lifecycle_profiles_are_executable(
    mode: str, connect_rate: int, disconnect_rate: int, outage_percent: int
) -> None:
    raw = valid_profile()
    workload = raw["workload"]
    lifecycle = raw["reader_lifecycle"]
    assert isinstance(workload, dict)
    assert isinstance(lifecycle, dict)
    workload["connect_rate_per_second"] = connect_rate
    if mode == "burst":
        workload["total_readers"] = 1004
    if mode == "outage":
        workload["total_readers"] = 100
    lifecycle.update(
        mode=mode,
        disconnect_rate_per_second=disconnect_rate,
        reconnect_attempts=3 if mode in {"steady", "burst", "outage"} else 0,
        backoff_max_ms=5000,
        outage_percent=outage_percent,
    )
    duration = raw["duration"]
    assert isinstance(duration, dict)
    duration["warmup_seconds"] = 7

    assert LoadProfile.model_validate(raw).reader_lifecycle.mode == mode


def test_invalid_lifecycle_shape_fails_closed() -> None:
    raw = valid_profile()
    lifecycle = raw["reader_lifecycle"]
    assert isinstance(lifecycle, dict)
    lifecycle.update(mode="outage", outage_percent=12, reconnect_attempts=3)

    with pytest.raises(ValidationError):
        LoadProfile.model_validate(raw)


def test_ipv6_sut_literal_fails_closed_until_native_sources_are_dual_stack() -> None:
    raw = valid_profile()
    raw["sut_rtsp_host"] = "2001:db8::10"
    with pytest.raises(ValidationError, match="string_pattern_mismatch"):
        LoadProfile.model_validate(raw)


def test_ipv6_generator_literal_fails_closed_until_native_sources_are_dual_stack() -> None:
    raw = valid_profile()
    hosts = raw["generator_hosts"]
    assert isinstance(hosts, list) and isinstance(hosts[0], dict)
    hosts[0]["rtsp_host"] = "2001:db8::20"
    with pytest.raises(ValidationError, match="string_pattern_mismatch"):
        LoadProfile.model_validate(raw)


def test_cold_preflight_rejects_path_sets_above_proven_parallel_bound() -> None:
    raw = valid_profile()
    workload = raw["workload"]
    hosts = raw["generator_hosts"]
    assert isinstance(workload, dict) and isinstance(hosts, list)
    assert isinstance(hosts[0], dict)
    workload.update(
        session_temperature="cold",
        registered_paths=513,
        active_sources=513,
        total_readers=513,
    )
    hosts[0]["source_count"] = 513
    with pytest.raises(ValidationError, match="cold_preflight_path_count_exceeds_safety_cap"):
        LoadProfile.model_validate(raw)


def test_generator_source_ranges_must_cover_active_sources_without_overlap() -> None:
    raw = valid_profile(tier="capacity")
    hosts = raw["generator_hosts"]
    assert isinstance(hosts, list)
    second = hosts[1]
    assert isinstance(second, dict)
    second["source_start"] = 1

    with pytest.raises(ValidationError, match="generator_source_ranges_overlap"):
        LoadProfile.model_validate(raw)


def test_wan_profile_fails_closed_until_netem_driver_is_implemented() -> None:
    raw = valid_profile()
    raw["network"] = {
        "profile": "wan",
        "interface": "camera0",
        "mtu_bytes": 1500,
        "rtt_ms": 50,
        "jitter_ms": 10,
        "loss_percent": 0.5,
    }
    with pytest.raises(ValidationError, match="network_impairment_driver_not_implemented"):
        LoadProfile.model_validate(raw)

    network = raw["network"]
    assert isinstance(network, dict)
    network["rtt_ms"] = 0
    with pytest.raises(ValidationError, match="wan_profile_below_consensus_impairment"):
        LoadProfile.model_validate(raw)


def test_unimplemented_workload_drivers_fail_closed() -> None:
    raw = valid_profile()
    workload = raw["workload"]
    assert isinstance(workload, dict)
    workload["probe_rate_per_second"] = 1
    with pytest.raises(ValidationError, match="probe_crud_drivers_not_implemented"):
        LoadProfile.model_validate(raw)


@pytest.mark.parametrize(
    ("machine", "architecture", "cpuinfo", "expected_cpu_model"),
    [
        (
            "x86_64",
            "amd64",
            "processor : 0\nmodel name : Test CPU\nprocessor : 1\n",
            "Test CPU",
        ),
        (
            "aarch64",
            "arm64",
            (
                "processor : 0\nCPU implementer : 0x41\nCPU architecture : 8\n"
                "CPU variant : 0x3\nCPU part : 0xd0c\nprocessor : 1\n"
            ),
            "CPU implementer=0x41 CPU architecture=8 CPU variant=0x3 CPU part=0xd0c",
        ),
    ],
)
def test_runtime_manifest_captures_and_binds_actual_linux_gstreamer_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    machine: str,
    architecture: Literal["amd64", "arm64"],
    cpuinfo: str,
    expected_cpu_model: str,
) -> None:
    raw = valid_profile()
    hosts = raw["generator_hosts"]
    artifacts = raw["artifacts"]
    assert isinstance(hosts, list)
    assert isinstance(hosts[0], dict)
    assert isinstance(artifacts, dict)
    hosts[0]["architecture"] = architecture
    artifacts["gstreamer_build_id"] = "1.24.2-1ubuntu0.1"
    source_binary = tmp_path / "opt/rtsp-pull-server"
    reader_binary = tmp_path / "opt/rtsp-load-reader"
    source_binary.parent.mkdir(parents=True)
    source_binary.write_bytes(b"pull-server")
    reader_binary.write_bytes(b"load-reader")
    artifacts["pull_server_sha256"] = hashlib.sha256(b"pull-server").hexdigest()
    artifacts["load_reader_sha256"] = hashlib.sha256(b"load-reader").hexdigest()
    profile = LoadProfile.model_validate(raw)
    pids = (101, 202)
    executables = (source_binary, reader_binary)
    bindings = tuple(
        RuntimeProcessBinding(
            pid=pid,
            executable_sha256=(
                profile.artifacts.pull_server_sha256
                if pid == 101
                else profile.artifacts.load_reader_sha256
            ),
            start_time_ticks=1000 + index,
        )
        for index, pid in enumerate(pids)
    )
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(platform, "machine", lambda: machine)
    observed_at = 4_102_444_799_000

    class FakeAdjtimex:
        argtypes: object = None
        restype: object = None

        def __call__(self, pointer: Any) -> int:
            value = ctypes.cast(pointer, ctypes.POINTER(load_evidence_module._Timex)).contents
            value.status = 0
            value.maxerror = 1_000
            value.esterror = 0
            return 0

    class FakeLibc:
        adjtimex = FakeAdjtimex()

    clock_values = iter((observed_at * 1_000_000, (observed_at + 1) * 1_000_000))
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(ctypes, "CDLL", lambda *args, **kwargs: FakeLibc())
    monkeypatch.setattr(time, "time_ns", lambda: next(clock_values))
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 0, stdout="gst-launch-1.0 version 1.24.2\nGStreamer 1.24.2\n"
        ),
    )

    for relative_path, body in {
        "etc/os-release": "ID=ubuntu\nVERSION_ID=24.04\n",
        "etc/machine-id": "machine-a\n",
        "proc/sys/kernel/osrelease": "6.8.0-test\n",
        "proc/sys/kernel/random/boot_id": "11111111-1111-1111-1111-111111111111\n",
        "proc/cpuinfo": cpuinfo,
        "proc/stat": "cpu  100 20 30 400 50 6 7 8 0 0\n",
        "proc/meminfo": "MemTotal: 16777216 kB\nMemAvailable: 8388608 kB\n",
        "proc/net/tcp": "  sl  local_address rem_address st\n",
        "proc/net/tcp6": "  sl  local_address rem_address st\n",
        "var/lib/dpkg/status": (
            "Package: libgstreamer1.0-0\n"
            "Status: install ok installed\n"
            f"Architecture: {architecture}\n"
            "Version: 1.24.2-1ubuntu0.1\n\n"
            "Package: gstreamer1.0-plugins-good\n"
            "Status: install ok installed\n"
            f"Architecture: {architecture}\n"
            "Version: 1.24.2-1ubuntu0.1\n"
        ),
    }.items():
        destination = tmp_path / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(body, encoding="utf-8")
    for relative in (
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
    ):
        sysctl_path = tmp_path / "proc/sys" / relative
        sysctl_path.parent.mkdir(parents=True, exist_ok=True)
        sysctl_path.write_text("32768 60999\n" if relative.endswith("port_range") else "1\n")
    interface = tmp_path / "sys/class/net/camera0"
    (interface / "statistics").mkdir(parents=True)
    for name in ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets"):
        (interface / "statistics" / name).write_text("1\n", encoding="utf-8")
    (interface / "speed").write_text("10000\n", encoding="utf-8")
    (interface / "mtu").write_text("1500\n", encoding="utf-8")
    cgroup_mount = tmp_path / "sys/fs/cgroup"
    cgroup = cgroup_mount / "rtsp-load.slice"
    cgroup.mkdir(parents=True)
    for target, values in ((cgroup, ("400000 100000", str(8 * 1024**3), "100000", "0-7")),):
        for name, value in zip(
            ("cpu.max", "memory.max", "pids.max", "cpuset.cpus.effective"),
            values,
            strict=True,
        ):
            (target / name).write_text(value + "\n", encoding="utf-8")
    (cgroup / "cpu.stat").write_text("usage_usec 1\n", encoding="utf-8")
    (cgroup / "memory.current").write_text("1024\n", encoding="utf-8")
    (cgroup / "pids.current").write_text("2\n", encoding="utf-8")
    (cgroup / "cgroup.procs").write_text("101\n202\n", encoding="utf-8")
    gst_launch = tmp_path / "usr/bin/gst-launch-1.0"
    gst_launch.parent.mkdir(parents=True)
    gst_launch.write_bytes(b"gst-launch")
    gst_launch.chmod(0o755)
    library = tmp_path / "usr/lib/libgstreamer-1.0.so.0"
    library.parent.mkdir(parents=True)
    library.write_bytes(b"gstreamer-core")
    library_stat = library.stat()
    device = f"{os.major(library_stat.st_dev):02x}:{os.minor(library_stat.st_dev):02x}"
    for index, (pid, executable) in enumerate(zip(pids, executables, strict=True)):
        process_root = tmp_path / "proc" / str(pid)
        (process_root / "fd").mkdir(parents=True)
        (process_root / "fd/0").touch()
        fields = ["S", *("0" for _ in range(21))]
        fields[11] = "1"
        fields[12] = "1"
        fields[19] = str(1000 + index)
        (process_root / "stat").write_text(
            f"{pid} (load process) {' '.join(fields)}\n", encoding="utf-8"
        )
        (process_root / "status").write_text("VmRSS: 1 kB\n", encoding="utf-8")
        (process_root / "cgroup").write_text("0::/rtsp-load.slice\n", encoding="utf-8")
        (process_root / "exe").symlink_to(executable)
        (process_root / "limits").write_text(
            "Max open files            65536                65536                files     \n"
            "Max processes unlimited unlimited processes     \n",
            encoding="utf-8",
        )
        (process_root / "maps").write_text(
            f"00001000-00002000 r-xp 00000000 {device} {library_stat.st_ino} "
            "/usr/lib/libgstreamer-1.0.so.0\n",
            encoding="utf-8",
        )

    manifest = capture_generator_runtime(
        profile,
        host="generator-a",
        pids=pids,
        cgroup="rtsp-load.slice",
        expected_executables={item.pid: item.executable_sha256 for item in bindings},
        gst_launch_binary=Path("/usr/bin/gst-launch-1.0"),
        root=tmp_path,
    )

    assert manifest.architecture == architecture
    assert manifest.cpu_model == expected_cpu_model
    assert manifest.logical_cpu_count == 2
    assert manifest.gstreamer is not None
    assert manifest.gstreamer.package_build_id == "1.24.2-1ubuntu0.1"
    assert manifest.gstreamer.loaded_libraries[0].process_ids == pids
    assert manifest.capture_started_clock.observed_at_unix_ms == observed_at
    assert manifest.capture_completed_clock.observed_at_unix_ms == observed_at + 1

    monkeypatch.setattr(time, "time_ns", lambda: observed_at * 1_000_000)
    with pytest.raises(ValueError, match="runtime_path_must_be_absolute"):
        capture_generator_runtime(
            profile,
            host="generator-a",
            pids=pids,
            cgroup="rtsp-load.slice",
            expected_executables={item.pid: item.executable_sha256 for item in bindings},
            gst_launch_binary=Path("usr/bin/gst-launch-1.0"),
            root=tmp_path,
        )
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 0, stdout="gst-launch-1.0 version 1.23.0\nGStreamer 1.23.0\n"
        ),
    )
    with pytest.raises(ValueError, match="gstreamer_version_mismatch"):
        capture_generator_runtime(
            profile,
            host="generator-a",
            pids=pids,
            cgroup="rtsp-load.slice",
            expected_executables={item.pid: item.executable_sha256 for item in bindings},
            gst_launch_binary=Path("/usr/bin/gst-launch-1.0"),
            root=tmp_path,
        )
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 0, stdout="gst-launch-1.0 version 1.24.2\nGStreamer 1.24.2\n"
        ),
    )
    (tmp_path / "var/lib/dpkg/status").write_text(
        "Package: libgstreamer1.0-0\n"
        "Status: install ok installed\n"
        f"Architecture: {architecture}\n"
        "Version: unexpected-build\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="gstreamer_package_build_mismatch"):
        capture_generator_runtime(
            profile,
            host="generator-a",
            pids=pids,
            cgroup="rtsp-load.slice",
            expected_executables={item.pid: item.executable_sha256 for item in bindings},
            gst_launch_binary=Path("/usr/bin/gst-launch-1.0"),
            root=tmp_path,
        )


def test_cold_runtime_pair_rejects_environment_drift_but_not_process_identity() -> None:
    proxy_profile = LoadProfile.model_validate(valid_profile())
    direct_raw = valid_profile()
    direct_workload = direct_raw["workload"]
    assert isinstance(direct_workload, dict)
    direct_workload["endpoint_mode"] = "direct-control"
    direct_profile = LoadProfile.model_validate(direct_raw)
    proxy = runtime_manifest(
        proxy_profile,
        role="generator",
        host="generator-a",
        architecture="amd64",
        processes=runtime_process_bindings(),
        machine_id_sha256="a" * 64,
        boot_id="11111111-1111-1111-1111-111111111111",
        observed_at_unix_ms=4_102_444_799_000,
    )
    direct = runtime_manifest(
        direct_profile,
        role="generator",
        host="generator-a",
        architecture="amd64",
        processes=tuple(
            item.model_copy(update={"pid": item.pid + 1000, "start_time_ticks": 9999})
            for item in runtime_process_bindings()
        ),
        machine_id_sha256="a" * 64,
        boot_id="11111111-1111-1111-1111-111111111111",
        observed_at_unix_ms=4_102_444_800_000,
    )

    validate_runtime_comparison_pair(proxy, direct)

    changed = direct.model_copy(
        update={
            "sysctls": tuple(
                item.model_copy(update={"value": "2"}) if index == 0 else item
                for index, item in enumerate(direct.sysctls)
            )
        }
    )
    with pytest.raises(ValueError, match="runtime_comparison_environment_differs"):
        validate_runtime_comparison_pair(proxy, changed)

    source_pid, reader_pid = (item.pid for item in direct.processes)
    plugin = RuntimeLibrary(
        path="/usr/lib/gstreamer-1.0/libgsttest.so",
        sha256="6" * 64,
        size_bytes=2048,
        device_major=8,
        device_minor=1,
        inode=43,
        process_ids=(source_pid,),
    )
    proxy_runtime = proxy.gstreamer
    direct_runtime = direct.gstreamer
    assert proxy_runtime is not None and direct_runtime is not None
    proxy_with_plugin = proxy.model_copy(
        update={
            "gstreamer": proxy_runtime.model_copy(
                update={
                    "loaded_libraries": (
                        *proxy_runtime.loaded_libraries,
                        plugin.model_copy(update={"process_ids": (proxy.processes[0].pid,)}),
                    )
                }
            )
        }
    )
    direct_with_swapped_plugin = direct.model_copy(
        update={
            "gstreamer": direct_runtime.model_copy(
                update={
                    "loaded_libraries": (
                        *direct_runtime.loaded_libraries,
                        plugin.model_copy(update={"process_ids": (reader_pid,)}),
                    )
                }
            )
        }
    )
    with pytest.raises(ValueError, match="runtime_comparison_environment_differs"):
        validate_runtime_comparison_pair(proxy_with_plugin, direct_with_swapped_plugin)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("net.ipv4.ip_local_port_range", "garbage"),
        ("net.ipv4.ip_local_port_range", "60999 32768"),
        ("net.ipv4.ip_local_reserved_ports", "9000,8000"),
        ("net.core.somaxconn", "not-a-number"),
        ("net.core.unknown", "1"),
        ("net.core.somaxconn", "0"),
        ("net.ipv4.tcp_tw_reuse", "3"),
    ],
)
def test_runtime_setting_rejects_untyped_or_noncanonical_sysctls(name: str, value: str) -> None:
    with pytest.raises(ValidationError):
        RuntimeSetting(name=name, value=value)


def test_runtime_models_reject_noncanonical_limits_libraries_and_inventory() -> None:
    process = RuntimeProcess(
        pid=1,
        executable_sha256="a" * 64,
        start_time_ticks=1,
        max_open_files_soft=100,
        max_open_files_hard=200,
        max_processes_soft=100,
        max_processes_hard=200,
    )
    for update in (
        {"max_open_files_soft": 201},
        {"max_processes_soft": 201},
        {"max_processes_soft": "unlimited", "max_processes_hard": 200},
    ):
        with pytest.raises(ValidationError, match="runtime_process_soft_limit_exceeds_hard"):
            RuntimeProcess.model_validate({**process.model_dump(mode="json"), **update})

    library = RuntimeLibrary(
        path="/usr/lib/libgstreamer-1.0.so.0",
        sha256="b" * 64,
        size_bytes=1,
        device_major=8,
        device_minor=1,
        inode=1,
        process_ids=(1,),
    )
    with pytest.raises(ValidationError, match="runtime_library_process_ids_not_canonical"):
        RuntimeLibrary.model_validate({**library.model_dump(mode="json"), "process_ids": [1, 1]})

    package = RuntimePackage(name="libgstreamer1.0-0", version="1", architecture="amd64")
    with pytest.raises(ValidationError, match="gstreamer_runtime_inventory_not_canonical"):
        GStreamerRuntime(
            version="1.24.2",
            package_build_id="1",
            gst_launch_path="/usr/bin/gst-launch-1.0",
            gst_launch_sha256="c" * 64,
            packages=(package,),
            packages_sha256="d" * 64,
            loaded_libraries=(library,),
        )

    profile = LoadProfile.model_validate(valid_profile())
    manifest = runtime_manifest(
        profile,
        role="generator",
        host="generator-a",
        architecture="amd64",
        processes=runtime_process_bindings(),
        machine_id_sha256="a" * 64,
        boot_id="11111111-1111-1111-1111-111111111111",
        observed_at_unix_ms=4_102_444_799_000,
    )
    manifest_payload = manifest.model_dump(mode="json")
    completed_clock = manifest.capture_completed_clock.model_copy(
        update={"observed_at_unix_ms": manifest.capture_started_clock.observed_at_unix_ms - 1}
    )
    with pytest.raises(ValidationError, match="linux_runtime_manifest_not_canonical"):
        LinuxRuntimeManifest.model_validate(
            {**manifest_payload, "capture_completed_clock": completed_clock.model_dump(mode="json")}
        )
    runtime = manifest.gstreamer
    assert runtime is not None
    incomplete_library = runtime.loaded_libraries[0].model_copy(update={"process_ids": (100,)})
    with pytest.raises(ValidationError, match="gstreamer_runtime_process_coverage_incomplete"):
        LinuxRuntimeManifest.model_validate(
            {
                **manifest_payload,
                "gstreamer": runtime.model_copy(
                    update={"loaded_libraries": (incomplete_library,)}
                ).model_dump(mode="json"),
            }
        )


def test_runtime_capture_rejects_unknown_host_and_linux_platform_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = LoadProfile.model_validate(valid_profile())
    arguments: dict[str, Any] = {
        "pids": (1,),
        "cgroup": "load.slice",
        "expected_executables": {1: "a" * 64},
        "gst_launch_binary": Path("/usr/bin/gst-launch-1.0"),
        "root": tmp_path,
    }
    with pytest.raises(ValueError, match="unknown_generator_host"):
        capture_generator_runtime(profile, host="unknown", **arguments)

    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    with pytest.raises(ValueError, match="runtime_manifest_requires_linux"):
        capture_generator_runtime(profile, host="generator-a", **arguments)
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(platform, "machine", lambda: "mips64")
    with pytest.raises(ValueError, match="runtime_manifest_architecture_unsupported"):
        capture_generator_runtime(profile, host="generator-a", **arguments)
    monkeypatch.setattr(platform, "machine", lambda: "x86_64")
    with pytest.raises(ValueError, match="runtime_manifest_architecture_mismatch"):
        capture_generator_runtime(profile, host="generator-a", **arguments)


@pytest.mark.parametrize(
    ("location", "field", "value", "reason"),
    [
        ("workload", "registered_paths", 10001, "registered_paths_exceed_native_limit"),
        ("workload", "total_readers", 100001, "readers_exceed_native_limit"),
        ("fixture", "fps", 241, "fixture_fps_exceeds_native_limit"),
    ],
)
def test_profile_rejects_values_above_native_limits(
    location: str, field: str, value: int, reason: str
) -> None:
    raw = valid_profile()
    section = raw[location]
    assert isinstance(section, dict)
    section[field] = value
    if location == "workload" and field == "registered_paths":
        hosts = raw["generator_hosts"]
        assert isinstance(hosts, list) and isinstance(hosts[0], dict)
        hosts[0]["source_count"] = value
    with pytest.raises(ValidationError, match=reason):
        LoadProfile.model_validate(raw)


def test_outage_cohort_and_burst_size_must_be_exactly_executable() -> None:
    raw = valid_profile()
    workload = raw["workload"]
    lifecycle = raw["reader_lifecycle"]
    assert isinstance(workload, dict) and isinstance(lifecycle, dict)
    workload.update(total_readers=7, connect_rate_per_second=100)
    lifecycle.update(mode="outage", reconnect_attempts=3, outage_percent=10)
    with pytest.raises(ValidationError, match="outage_cohort_not_exactly_representable"):
        LoadProfile.model_validate(raw)


def test_profile_rejects_all_remaining_non_executable_cross_field_shapes() -> None:
    cases: list[tuple[dict[str, object], str]] = []

    raw = valid_profile()
    assert isinstance(raw["fixture"], dict)
    raw["fixture"]["path"] = "relative.h264"
    cases.append((raw, "fixture_path_must_be_absolute"))

    raw = valid_profile()
    assert isinstance(raw["network"], dict)
    raw["network"]["rtt_ms"] = 1
    cases.append((raw, "lan_profile_must_not_inject_impairment"))

    raw = valid_profile()
    assert isinstance(raw["workload"], dict)
    raw["workload"].update(active_sources=0, total_readers=0)
    cases.append((raw, "rtp_packet_rate_must_match_reader_presence"))

    for mode, changes, reason in (
        ("single", {"reconnect_attempts": 1}, "single_lifecycle_has_reconnect_controls"),
        ("steady", {}, "steady_lifecycle_must_use_consensus_rate"),
        ("ramp", {"reconnect_attempts": 1}, "one_shot_lifecycle_has_reconnect_controls"),
        ("burst", {}, "burst_lifecycle_requires_failure_backoff"),
        ("outage", {}, "outage_lifecycle_invalid_cohort"),
    ):
        raw = valid_profile()
        lifecycle = raw["reader_lifecycle"]
        assert isinstance(lifecycle, dict)
        lifecycle.update(mode=mode, **changes)
        cases.append((raw, reason))

    raw = valid_profile()
    raw["duration"] = {
        "warmup_seconds": 0,
        "measurement_seconds": 172801,
        "soak_seconds": 0,
    }
    cases.append((raw, "duration_exceeds_native_limit"))

    raw = valid_profile()
    raw["reader_credentials_file"] = "relative-secret"
    cases.append((raw, "reader_credentials_path_must_be_absolute"))

    raw = valid_profile()
    hosts = raw["generator_hosts"]
    assert isinstance(hosts, list) and isinstance(hosts[0], dict)
    hosts.append({**hosts[0], "source_start": 4})
    cases.append((raw, "generator_host_names_not_unique"))

    raw = valid_profile()
    hosts = raw["generator_hosts"]
    assert isinstance(hosts, list) and isinstance(hosts[0], dict)
    hosts[0]["source_start"] = 1
    cases.append((raw, "generator_source_ranges_have_gap"))

    raw = valid_profile()
    hosts = raw["generator_hosts"]
    assert isinstance(hosts, list) and isinstance(hosts[0], dict)
    hosts[0]["source_count"] = 3
    cases.append((raw, "generator_source_ranges_do_not_cover_registered_paths"))

    raw = valid_profile()
    workload = raw["workload"]
    lifecycle = raw["reader_lifecycle"]
    assert isinstance(workload, dict) and isinstance(lifecycle, dict)
    workload["connect_rate_per_second"] = 100
    lifecycle.update(mode="steady", disconnect_rate_per_second=10, reconnect_attempts=3)
    cases.append((raw, "steady_connect_disconnect_rates_differ"))

    raw = valid_profile()
    lifecycle = raw["reader_lifecycle"]
    assert isinstance(lifecycle, dict)
    lifecycle["mode"] = "ramp"
    cases.append((raw, "ramp_requires_100_readers_per_second"))

    raw = valid_profile()
    lifecycle = raw["reader_lifecycle"]
    assert isinstance(lifecycle, dict)
    lifecycle.update(mode="burst", reconnect_attempts=3)
    cases.append((raw, "burst_requires_1000_readers_per_second"))

    raw = valid_profile()
    lifecycle = raw["reader_lifecycle"]
    assert isinstance(lifecycle, dict)
    lifecycle.update(mode="steady", disconnect_rate_per_second=10, reconnect_attempts=3)
    cases.append((raw, "lifecycle_duration_does_not_cover_backoff_recovery"))

    for payload, reason in cases:
        with pytest.raises(ValidationError, match=reason):
            LoadProfile.model_validate(payload)

    raw = valid_profile()
    workload = raw["workload"]
    lifecycle = raw["reader_lifecycle"]
    assert isinstance(workload, dict) and isinstance(lifecycle, dict)
    workload.update(total_readers=999, connect_rate_per_second=1000)
    lifecycle.update(mode="burst", reconnect_attempts=3)
    with pytest.raises(ValidationError, match="burst_requires_at_least_1000_readers"):
        LoadProfile.model_validate(raw)


def test_unknown_fields_fail_closed() -> None:
    raw = valid_profile()
    raw["container_image"] = "not-part-of-direct-linux-contract"

    with pytest.raises(ValidationError, match="extra_forbidden"):
        LoadProfile.model_validate(raw)


def test_canonical_profile_and_digest_are_stable() -> None:
    profile = LoadProfile.model_validate(valid_profile())

    first_body, first_sha256 = canonical_profile_bytes(profile)
    second_body, second_sha256 = canonical_profile_bytes(profile)

    assert first_body == second_body
    assert first_sha256 == second_sha256
    assert len(first_sha256) == 64
    assert first_body.endswith(b"\n")
    assert json.loads(first_body)["fixture"]["source_mode"] == "rtsp-pull"


def test_fixture_inspector_binds_probe_semantics_and_pinned_tools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ffmpeg = tmp_path / "ffmpeg"
    ffprobe = tmp_path / "ffprobe"
    fixture = tmp_path / "fixture.h264"
    ffmpeg.write_bytes(b"ffmpeg")
    ffprobe.write_bytes(b"ffprobe")
    fixture.write_bytes(b"x" * 1_000_000)
    ffmpeg.chmod(0o750)
    ffprobe.chmod(0o750)
    raw = valid_profile()
    artifacts = raw["artifacts"]
    fixture_profile = raw["fixture"]
    assert isinstance(artifacts, dict)
    assert isinstance(fixture_profile, dict)
    artifacts.update(
        ffmpeg_version="test-ffmpeg",
        ffmpeg_sha256=hashlib.sha256(b"ffmpeg").hexdigest(),
        ffprobe_sha256=hashlib.sha256(b"ffprobe").hexdigest(),
    )
    fixture_profile.update(
        path=str(fixture),
        sha256=hashlib.sha256(fixture.read_bytes()).hexdigest(),
    )
    profile = LoadProfile.model_validate(raw)

    def fake_run(
        argv: list[str],
        *,
        check: bool,
        capture_output: bool,
        text: bool,
        timeout: int,
    ) -> subprocess.CompletedProcess[str]:
        del check, capture_output, text, timeout
        if "-show_frames" in argv:
            frames = [{"key_frame": 1 if index in {0, 50} else 0} for index in range(100)]
            stdout = json.dumps(
                {
                    "streams": [{"codec_name": "h264", "r_frame_rate": "25/1"}],
                    "frames": frames,
                }
            )
        elif argv[0] == str(ffmpeg):
            stdout = "ffmpeg version test-ffmpeg\n"
        else:
            stdout = "ffprobe version test-build\n"
        return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    destination = tmp_path / "fixture-manifest.json"

    manifest = inspect_fixture(
        profile,
        ffmpeg_binary=ffmpeg,
        ffprobe_binary=ffprobe,
        destination=destination,
    )

    assert manifest.measured_bitrate_bps == 2_000_000
    assert manifest.keyframe_intervals == (50,)
    assert manifest.loop_keyframe_interval_frames == 50
    assert FixtureManifest.model_validate_json(destination.read_text(encoding="utf-8")) == manifest
    with pytest.raises(ValueError, match="fixture_manifest_does_not_match_profile"):
        validate_fixture_manifest(
            profile,
            manifest.model_copy(update={"measured_bitrate_bps": 1}),
        )
    with pytest.raises(ValidationError, match="fixture_manifest_semantics_invalid"):
        FixtureManifest.model_validate(
            {**manifest.model_dump(mode="json"), "keyframe_intervals": [49]}
        )
    cyclic_tail = FixtureManifest.model_validate(
        {
            **manifest.model_dump(mode="json"),
            "frame_count": 200,
            "duration_seconds": 8,
            "loop_keyframe_interval_frames": 150,
        }
    )
    with pytest.raises(ValueError, match="fixture_manifest_does_not_match_profile"):
        validate_fixture_manifest(
            profile,
            cyclic_tail,
        )

    profile_path = tmp_path / "profile.json"
    profile_path.write_bytes(canonical_profile_bytes(profile)[0])
    cli_destination = tmp_path / "fixture-manifest-cli.json"
    assert (
        load_cli_main(
            [
                "inspect-fixture",
                str(profile_path),
                "--ffmpeg-binary",
                str(ffmpeg),
                "--ffprobe-binary",
                str(ffprobe),
                "--output",
                str(cli_destination),
            ]
        )
        == 0
    )
    assert cli_destination.is_file()


def test_functional_proxy_finalization_recomputes_real_sut_evidence_seam(
    tmp_path: Path,
) -> None:
    pull_server = tmp_path / "rtsp-pull-server"
    load_reader = tmp_path / "rtsp-load-reader"
    fixture = tmp_path / "fixture.h264"
    pull_server.write_bytes(b"pull-server")
    load_reader.write_bytes(b"load-reader")
    fixture.write_bytes(b"fixture")
    pull_server.chmod(0o750)
    load_reader.chmod(0o750)
    raw = valid_profile()
    artifacts = raw["artifacts"]
    fixture_profile = raw["fixture"]
    workload = raw["workload"]
    assert isinstance(artifacts, dict)
    assert isinstance(fixture_profile, dict)
    assert isinstance(workload, dict)
    artifacts["pull_server_sha256"] = hashlib.sha256(b"pull-server").hexdigest()
    artifacts["load_reader_sha256"] = hashlib.sha256(b"load-reader").hexdigest()
    fixture_profile.update(path=str(fixture), sha256=hashlib.sha256(b"fixture").hexdigest())
    workload.update(
        active_sources=0,
        total_readers=0,
        connect_rate_per_second=0,
        minimum_rtp_packets_per_second=0,
        endpoint_mode="proxy",
        session_temperature="warm",
    )
    raw["duration"] = {
        "warmup_seconds": 0,
        "measurement_seconds": 1,
        "soak_seconds": 0,
    }
    profile = LoadProfile.model_validate(raw)
    write_fixture_manifest(profile)
    scheduled_start_ms = 4_102_444_800_000
    run_directory = tmp_path / "proxy-functional"
    prepare_run_directory(
        profile,
        run_directory,
        pull_server_binary=pull_server,
        load_reader_binary=load_reader,
        coordinated_start_unix_ms=scheduled_start_ms,
    )

    def timestamp(unix_ms: int) -> str:
        return (
            datetime.fromtimestamp(unix_ms / 1000, UTC)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )

    def resource(
        *,
        host: str,
        machine: str,
        observed_at_ms: int,
        processes: tuple[RuntimeProcessBinding, ...],
    ) -> ResourceObservation:
        return ResourceObservation(
            generator_host=host,
            machine_id_sha256=machine,
            boot_id="11111111-1111-1111-1111-111111111111",
            timestamp=timestamp(observed_at_ms),
            interval_seconds=1,
            host_cpu_percent=10,
            host_ram_percent=10,
            max_process_cpu_percent=10,
            cgroup_cpu_percent=10,
            cgroup_ram_percent=10,
            max_process_fd_percent=10,
            socket_percent=10,
            ephemeral_port_start=32768,
            ephemeral_port_end=60999,
            ephemeral_port_capacity=28232,
            reserved_ports_sha256=hashlib.sha256(b"").hexdigest(),
            cgroup_pids_percent=10,
            network_percent=10,
            network_packets_per_second=1000,
            packet_rate_percent=10,
            interface_mtu_bytes=1500,
            memory_total_bytes=16 * 1024**3,
            nic_link_speed_bits_per_second=10_000_000_000,
            cgroup_cpu_capacity_cores=4,
            cgroup_memory_limit_bytes=8 * 1024**3,
            cgroup_pids_limit=100000,
            process_count=len(processes),
            workload_processes=processes,
            workload_processes_sha256=runtime_process_bindings_sha256(processes),
            workload_process_limits=tuple(
                RuntimeProcessLimit(pid=item.pid, max_open_files=65536) for item in processes
            ),
            cgroup_path_sha256="c" * 64,
            cgroup_constraint_chain_sha256="5" * 64,
        )

    generator_processes = tuple(
        RuntimeProcessBinding(
            pid=100 + index,
            executable_sha256=profile.artifacts.pull_server_sha256,
            start_time_ticks=1000 + index,
        )
        for index in range(1)
    )
    generator_observations = tuple(
        resource(
            host="generator-a",
            machine="a" * 64,
            observed_at_ms=scheduled_start_ms + offset,
            processes=generator_processes,
        )
        for offset in (0, 500, 1000)
    )
    generator_raw = run_directory / "raw/generator-generator-a.jsonl"
    generator_raw.write_text(
        "".join(item.model_dump_json() + "\n" for item in generator_observations),
        encoding="utf-8",
    )
    write_summary(
        run_directory / "summary/generator-generator-a.json",
        summarize_generator_headroom(
            generator_observations,
            expected_generator_host="generator-a",
            minimum_duration_seconds=1,
            expected_interval_seconds=1,
            maximum_gap_factor=1.5,
            observations_sha256=sha256_file(generator_raw),
            measurement_start_unix_ms=scheduled_start_ms,
            measurement_end_unix_ms=scheduled_start_ms + 1000,
            soak_end_unix_ms=scheduled_start_ms + 1000,
        ),
    )
    write_summary(
        run_directory / "raw/runtime-generator-generator-a.json",
        runtime_manifest(
            profile,
            role="generator",
            host="generator-a",
            architecture=profile.generator_hosts[0].architecture,
            processes=generator_processes,
            machine_id_sha256="a" * 64,
            boot_id="11111111-1111-1111-1111-111111111111",
            observed_at_unix_ms=scheduled_start_ms - 1000,
        ),
    )

    sut_processes = (
        RuntimeProcessBinding(
            pid=200,
            executable_sha256=profile.artifacts.mediamtx_sha256,
            start_time_ticks=2000,
        ),
    )
    sampling_end_ms = sut_sampling_end_unix_ms(profile, scheduled_start_ms)
    sut_offsets = (0, 500, *range(1000, sampling_end_ms - scheduled_start_ms + 1, 1000))
    sut_observations = tuple(
        SutObservation(
            sut_host=profile.sut_rtsp_host,
            timestamp=timestamp(scheduled_start_ms + offset),
            clock_proof=KernelClockProof(
                observed_at_unix_ms=scheduled_start_ms + offset,
                synchronized=True,
                state=0,
                status=0,
                max_error_ms=1,
            ),
            resource=resource(
                host=profile.sut_rtsp_host,
                machine="b" * 64,
                observed_at_ms=scheduled_start_ms + offset,
                processes=sut_processes,
            ),
            mediamtx_rss_bytes=1024,
            mediamtx_open_file_descriptors=10,
            metrics_families=REQUIRED_SUT_METRIC_FAMILIES,
            total_rtsp_sessions=0,
            ready_runtime_paths=0,
            active_session_counters=(),
            active_path_counters=(),
            cumulative_inbound_rtp_packets=0,
            cumulative_outbound_rtp_packets=0,
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
        for offset in sut_offsets
    )
    sut_raw = run_directory / "raw/sut.jsonl"
    sut_raw.write_text(
        "".join(item.model_dump_json() + "\n" for item in sut_observations),
        encoding="utf-8",
    )
    assert (
        load_cli_main(
            [
                "summarize-sut",
                str(run_directory),
                str(sut_raw),
                str(run_directory / "summary/sut.json"),
            ]
        )
        == 0
    )
    write_summary(
        run_directory / "raw/runtime-sut.json",
        runtime_manifest(
            profile,
            role="sut",
            host=profile.sut_rtsp_host,
            architecture=profile.sut_architecture,
            processes=sut_processes,
            machine_id_sha256="b" * 64,
            boot_id="11111111-1111-1111-1111-111111111111",
            observed_at_unix_ms=scheduled_start_ms - 1000,
        ),
    )

    finalize_run_directory(run_directory)
    verify_run_directory(run_directory)


def test_load_cli_rejects_inapplicable_or_incomplete_runtime_commands_via_public_seam(
    tmp_path: Path,
) -> None:
    raw = valid_profile()
    workload = raw["workload"]
    assert isinstance(workload, dict)
    workload["endpoint_mode"] = "direct-control"
    profile = LoadProfile.model_validate(raw)
    run_directory = tmp_path / "direct-run"
    initialize_run_directory(profile, run_directory)
    (run_directory / "raw").mkdir()
    (run_directory / "summary").mkdir()
    (run_directory / "launch-plan.json").write_text(
        json.dumps(
            {
                "coordinated_start_unix_ms": 4_102_444_800_000,
                "source_servers": [{"generator_host": "generator-a"}],
                "readers": [{"generator_host": "generator-a"}],
            }
        ),
        encoding="utf-8",
    )

    commands = (
        [
            "capture-generator-runtime",
            str(run_directory),
            "--generator-host",
            "generator-a",
            "--source-pid",
            "101",
            "--cgroup",
            "rtsp-load.slice",
            "--gst-launch-binary",
            "/usr/bin/gst-launch-1.0",
        ],
        [
            "capture-sut-runtime",
            str(run_directory),
            "--mediamtx-pid",
            "201",
            "--cgroup",
            "mediamtx.service",
        ],
        [
            "capture-generator-runtime",
            str(run_directory),
            "--generator-host",
            "generator-a",
            "--source-pid",
            "101",
            "--reader-pid",
            "102",
            "--cgroup",
            "rtsp-load.slice",
            "--gst-launch-binary",
            "/usr/bin/gst-launch-1.0",
        ],
        [
            "sample-sut",
            str(run_directory),
            str(run_directory / "raw/sut.jsonl"),
            "--mediamtx-pid",
            "201",
            "--cgroup",
            "mediamtx.service",
            "--metrics-url",
            "http://127.0.0.1:9998/metrics",
        ],
        [
            "summarize-sut",
            str(run_directory),
            str(run_directory / "raw/sut.jsonl"),
            str(run_directory / "summary/sut.json"),
        ],
        [
            "sample-generator",
            str(run_directory),
            str(run_directory / "raw/unknown.jsonl"),
            "--generator-host",
            "unknown",
            "--source-pid",
            "101",
            "--cgroup",
            "rtsp-load.slice",
        ],
    )
    assert [load_cli_main(command) for command in commands] == [2, 2, 2, 2, 2, 2]

    generator_output = run_directory / "raw/generator.jsonl"
    generator_output.write_text("", encoding="utf-8")
    assert (
        load_cli_main(
            [
                "sample-generator",
                str(run_directory),
                str(tmp_path / "outside.jsonl"),
                "--generator-host",
                "generator-a",
                "--source-pid",
                "101",
                "--reader-pid",
                "102",
                "--cgroup",
                "rtsp-load.slice",
            ]
        )
        == 2
    )
    assert (
        load_cli_main(
            [
                "sample-generator",
                str(run_directory),
                str(generator_output),
                "--generator-host",
                "generator-a",
                "--source-pid",
                "101",
                "--cgroup",
                "rtsp-load.slice",
            ]
        )
        == 2
    )
    (run_directory / "launch-plan.json").write_text(
        json.dumps(
            {
                "coordinated_start_unix_ms": None,
                "source_servers": [{"generator_host": "generator-a"}],
                "readers": [{"generator_host": "generator-a"}],
            }
        ),
        encoding="utf-8",
    )
    exact_generator_arguments = [
        "--generator-host",
        "generator-a",
        "--source-pid",
        "101",
        "--reader-pid",
        "102",
        "--cgroup",
        "rtsp-load.slice",
    ]
    assert (
        load_cli_main(
            [
                "sample-generator",
                str(run_directory),
                str(generator_output),
                *exact_generator_arguments,
            ]
        )
        == 2
    )
    assert (
        load_cli_main(
            [
                "summarize-generator",
                str(run_directory),
                str(generator_output),
                str(run_directory / "summary/generator.json"),
                "--generator-host",
                "generator-a",
            ]
        )
        == 2
    )
    assert (
        load_cli_main(
            [
                "apply-paths",
                str(run_directory),
                "--api-url",
                "http://192.0.2.1:9997",
            ]
        )
        == 2
    )
    assert (
        load_cli_main(
            [
                "preflight-cold",
                str(run_directory),
                "--api-url",
                "http://127.0.0.1:9997",
            ]
        )
        == 2
    )

    proxy_run = tmp_path / "proxy-run"
    initialize_run_directory(LoadProfile.model_validate(valid_profile()), proxy_run)
    (proxy_run / "raw").mkdir()
    (proxy_run / "summary").mkdir()
    (proxy_run / "launch-plan.json").write_text(
        json.dumps({"coordinated_start_unix_ms": None}), encoding="utf-8"
    )
    sut_observations = proxy_run / "raw/sut.jsonl"
    sut_observations.write_text("", encoding="utf-8")
    assert (
        load_cli_main(
            [
                "capture-sut-runtime",
                str(proxy_run),
                "--mediamtx-pid",
                "201",
                "--cgroup",
                "mediamtx.service",
            ]
        )
        == 2
    )
    assert (
        load_cli_main(
            [
                "sample-sut",
                str(proxy_run),
                str(sut_observations),
                "--mediamtx-pid",
                "201",
                "--cgroup",
                "mediamtx.service",
                "--metrics-url",
                "http://127.0.0.1:9998/metrics",
            ]
        )
        == 2
    )
    assert (
        load_cli_main(
            [
                "summarize-sut",
                str(proxy_run),
                str(sut_observations),
                str(proxy_run / "summary/sut.json"),
            ]
        )
        == 2
    )


def test_cold_finalization_requires_typed_inactive_path_preflight(tmp_path: Path) -> None:
    pull_server = tmp_path / "rtsp-pull-server"
    load_reader = tmp_path / "rtsp-load-reader"
    fixture = tmp_path / "fixture.h264"
    pull_server.write_bytes(b"pull-server")
    load_reader.write_bytes(b"load-reader")
    fixture.write_bytes(b"fixture")
    pull_server.chmod(0o750)
    load_reader.chmod(0o750)
    raw = valid_profile()
    artifacts = raw["artifacts"]
    fixture_profile = raw["fixture"]
    workload = raw["workload"]
    assert isinstance(artifacts, dict)
    assert isinstance(fixture_profile, dict)
    assert isinstance(workload, dict)
    artifacts["pull_server_sha256"] = hashlib.sha256(b"pull-server").hexdigest()
    artifacts["load_reader_sha256"] = hashlib.sha256(b"load-reader").hexdigest()
    fixture_profile.update(path=str(fixture), sha256=hashlib.sha256(b"fixture").hexdigest())
    workload.update(session_temperature="cold", total_readers=4)
    profile = LoadProfile.model_validate(raw)
    write_fixture_manifest(profile)
    run_directory = tmp_path / "cold-run"
    prepare_run_directory(
        profile,
        run_directory,
        pull_server_binary=pull_server,
        load_reader_binary=load_reader,
        coordinated_start_unix_ms=4_102_444_800_000,
    )
    (run_directory / "raw" / "placeholder.jsonl").write_text("{}\n", encoding="utf-8")
    (run_directory / "summary" / "placeholder.json").write_text("{}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="cold_preflight_evidence_missing"):
        finalize_run_directory(run_directory)

    (run_directory / "raw" / "cold-preflight.json").write_text("[]\n", encoding="utf-8")
    with pytest.raises(ValueError, match="cold_preflight_evidence_invalid"):
        finalize_run_directory(run_directory)


def test_run_directory_finalization_hashes_and_seals_every_evidence_file(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    pull_server = tmp_path / "rtsp-pull-server"
    load_reader = tmp_path / "rtsp-load-reader"
    fixture = tmp_path / "fixture.h264"
    pull_server.write_bytes(b"pull-server")
    load_reader.write_bytes(b"load-reader")
    fixture.write_bytes(b"fixture")
    pull_server.chmod(0o750)
    load_reader.chmod(0o750)
    raw_profile = valid_profile()
    artifacts = raw_profile["artifacts"]
    fixture_profile = raw_profile["fixture"]
    workload = raw_profile["workload"]
    assert isinstance(artifacts, dict)
    assert isinstance(fixture_profile, dict)
    assert isinstance(workload, dict)
    artifacts["pull_server_sha256"] = hashlib.sha256(b"pull-server").hexdigest()
    artifacts["load_reader_sha256"] = hashlib.sha256(b"load-reader").hexdigest()
    fixture_profile["path"] = str(fixture)
    fixture_profile["sha256"] = hashlib.sha256(b"fixture").hexdigest()
    workload["total_readers"] = 4
    workload["endpoint_mode"] = "direct-control"
    workload["session_temperature"] = "cold"
    raw_profile["duration"] = {
        "warmup_seconds": 0,
        "measurement_seconds": 1,
        "soak_seconds": 0,
    }
    profile = LoadProfile.model_validate(raw_profile)
    write_fixture_manifest(profile)
    run_directory = tmp_path / "run-001"
    scheduled_start_ms = 4_102_444_800_000
    prepare_run_directory(
        profile,
        run_directory,
        pull_server_binary=pull_server,
        load_reader_binary=load_reader,
        coordinated_start_unix_ms=scheduled_start_ms,
    )

    stored_profile = (run_directory / "profile.json").read_bytes()
    stored_manifest = json.loads((run_directory / "run-manifest.json").read_text(encoding="utf-8"))
    assert stored_manifest["status"] == "initialized"
    assert stored_profile == canonical_profile_bytes(profile)[0]
    assert run_directory.stat().st_mode & 0o777 == 0o750
    assert (run_directory / "profile.json").stat().st_mode & 0o777 == 0o640

    plan = build_direct_reader_plan(profile, "generator-a")
    expected_paths = {
        reader_id: target.path
        for target in plan.targets
        for reader_id in range(target.reader_id_start, target.reader_id_start + target.reader_count)
    }
    events: list[dict[str, object]] = []
    for reader_id in range(4):
        path = expected_paths[reader_id]
        handshake = (reader_id + 1) * 10
        events.extend(
            [
                {
                    "event": "reader_started",
                    "reader_id": reader_id,
                    "cycle": 0,
                    "path": path,
                    "at_monotonic_ms": reader_id * 100,
                    "at_unix_ms": scheduled_start_ms + reader_id * 100,
                },
                {
                    "event": "play_sent",
                    "reader_id": reader_id,
                    "cycle": 0,
                    "path": path,
                    "at_monotonic_ms": reader_id * 100 + handshake,
                    "describe_to_play_ms": handshake,
                },
                {
                    "event": "first_decodable_frame",
                    "reader_id": reader_id,
                    "cycle": 0,
                    "path": path,
                    "at_monotonic_ms": reader_id * 100 + handshake + 100,
                    "describe_to_first_decodable_ms": handshake + 100,
                    "play_to_first_decodable_ms": 100,
                    "access_unit": True,
                },
            ]
        )
        events.append(
            {
                "event": "reader_rtp_segment",
                "reader_id": reader_id,
                "cycle": 0,
                "path": path,
                "track": "video",
                "phase": "measurement",
                "first_at_monotonic_ms": max(
                    measurement_start_unix_ms(profile, scheduled_start_ms) - scheduled_start_ms,
                    reader_id * 100 + handshake + 100,
                ),
                "last_at_monotonic_ms": measurement_end_unix_ms(profile, scheduled_start_ms)
                - scheduled_start_ms
                - 1,
                "received_packets": 250,
                "sequence_expected_packets": 250,
                "sequence_gaps": 0,
            }
        )
        events.append(
            {
                "event": "reader_rtp_phase",
                "reader_id": reader_id,
                "path": path,
                "at_monotonic_ms": 1000,
                "audio_expected": False,
                "quiesced": True,
                "video_parse_failures": 0,
                "audio_parse_failures": 0,
                "measurement_video_rtp_packets": 250,
                "measurement_video_rtp_sequence_gaps": 0,
                "soak_video_rtp_packets": 0,
                "soak_video_rtp_sequence_gaps": 0,
                "measurement_audio_rtp_packets": 0,
                "measurement_audio_rtp_sequence_gaps": 0,
                "soak_audio_rtp_packets": 0,
                "soak_audio_rtp_sequence_gaps": 0,
            }
        )
    events.append(
        {
            "event": "run_completed",
            "at_monotonic_ms": 1000,
            "started_readers": 4,
            "ready_readers": 4,
            "failed_attempts": 0,
            "normal_completion": True,
            "interrupted": False,
            "lifecycle_complete": True,
            "exit_code": 0,
            "schedule_shard_index": 0,
            "schedule_shards": 1,
            "generator_host": "generator-a",
            "profile_sha256": canonical_profile_bytes(profile)[1],
            "reader_plan_sha256": sha256_file(run_directory / "reader-plan-generator-a.tsv"),
            "anchor_start_unix_ms": warm_anchor_start_unix_ms(profile, scheduled_start_ms),
            "scheduled_start_unix_ms": scheduled_start_ms,
            "ramp_end_unix_ms": ramp_end_unix_ms(profile, scheduled_start_ms),
            "lifecycle_start_unix_ms": lifecycle_start_unix_ms(profile, scheduled_start_ms),
            "measurement_start_unix_ms": measurement_start_unix_ms(profile, scheduled_start_ms),
            "measurement_end_unix_ms": measurement_end_unix_ms(profile, scheduled_start_ms),
            "scheduled_workload_end_unix_ms": workload_end_unix_ms(profile, scheduled_start_ms),
            "process_start_unix_ms": scheduled_start_ms - 100,
            "workload_end_unix_ms": workload_end_unix_ms(profile, scheduled_start_ms),
            "process_end_unix_ms": workload_end_unix_ms(profile, scheduled_start_ms) + 100,
            "clock_synchronized": True,
            "clock_max_error_ms": 1,
            "lifecycle_scheduled_slots": 0,
            "injected_disconnects": 0,
            "rtp_packets": 1000,
            "measurement_rtp_packets": 1000,
            "soak_rtp_packets": 0,
            "measurement_rtp_sequence_gaps": 0,
            "soak_rtp_sequence_gaps": 0,
        }
    )
    reader_events = run_directory / "raw" / "readers.jsonl"
    reader_events.write_text(
        "".join(json.dumps(event) + "\n" for event in events), encoding="utf-8"
    )
    write_summary(
        run_directory / "summary" / "readers.json",
        summarize_reader_events(profile, reader_events),
    )

    process_bindings = (
        RuntimeProcessBinding(
            pid=100,
            executable_sha256=profile.artifacts.pull_server_sha256,
            start_time_ticks=1000,
        ),
        RuntimeProcessBinding(
            pid=101,
            executable_sha256=profile.artifacts.load_reader_sha256,
            start_time_ticks=1001,
        ),
    )
    observations = [
        ResourceObservation(
            generator_host="generator-a",
            machine_id_sha256="a" * 64,
            boot_id="11111111-1111-1111-1111-111111111111",
            timestamp=datetime.fromtimestamp(scheduled_start_ms / 1000 + offset, UTC)
            .isoformat()
            .replace("+00:00", "Z"),
            interval_seconds=1,
            host_cpu_percent=10,
            host_ram_percent=20,
            max_process_cpu_percent=10,
            cgroup_cpu_percent=10,
            cgroup_ram_percent=20,
            max_process_fd_percent=10,
            socket_percent=10,
            ephemeral_port_start=32768,
            ephemeral_port_end=60999,
            ephemeral_port_capacity=28232,
            reserved_ports_sha256=hashlib.sha256(b"").hexdigest(),
            cgroup_pids_percent=10,
            network_percent=10,
            network_packets_per_second=1000,
            packet_rate_percent=10,
            interface_mtu_bytes=1500,
            memory_total_bytes=16 * 1024**3,
            nic_link_speed_bits_per_second=10_000_000_000,
            cgroup_cpu_capacity_cores=4,
            cgroup_memory_limit_bytes=8 * 1024**3,
            cgroup_pids_limit=100000,
            process_count=2,
            workload_processes=process_bindings,
            workload_processes_sha256=runtime_process_bindings_sha256(process_bindings),
            workload_process_limits=(
                RuntimeProcessLimit(pid=100, max_open_files=65536),
                RuntimeProcessLimit(pid=101, max_open_files=65536),
            ),
            cgroup_path_sha256="c" * 64,
            cgroup_constraint_chain_sha256="5" * 64,
        )
        for offset in (0, 1, 2)
    ]
    generator_events = run_directory / "raw" / "generator-generator-a.jsonl"
    generator_events.write_text(
        "".join(json.dumps(item.model_dump(mode="json")) + "\n" for item in observations),
        encoding="utf-8",
    )
    write_summary(
        run_directory / "summary" / "generator-generator-a.json",
        summarize_generator_headroom(
            observations,
            expected_generator_host="generator-a",
            minimum_duration_seconds=1,
            expected_interval_seconds=1,
            maximum_gap_factor=1.5,
            observations_sha256=sha256_file(generator_events),
            measurement_start_unix_ms=measurement_start_unix_ms(profile, scheduled_start_ms),
            measurement_end_unix_ms=measurement_end_unix_ms(profile, scheduled_start_ms),
            soak_end_unix_ms=workload_end_unix_ms(profile, scheduled_start_ms),
        ),
    )
    write_summary(
        run_directory / "raw" / "runtime-generator-generator-a.json",
        runtime_manifest(
            profile,
            role="generator",
            host="generator-a",
            architecture=profile.generator_hosts[0].architecture,
            processes=process_bindings,
            machine_id_sha256="a" * 64,
            boot_id="11111111-1111-1111-1111-111111111111",
            observed_at_unix_ms=scheduled_start_ms,
        ),
    )

    wrong_bindings = (
        process_bindings[0].model_copy(update={"executable_sha256": "0" * 64}),
        process_bindings[1],
    )
    wrong_observations = [
        item.model_copy(
            update={
                "workload_processes": wrong_bindings,
                "workload_processes_sha256": runtime_process_bindings_sha256(wrong_bindings),
            }
        )
        for item in observations
    ]
    generator_events.write_text(
        "".join(json.dumps(item.model_dump(mode="json")) + "\n" for item in wrong_observations),
        encoding="utf-8",
    )
    wrong_summary = summarize_generator_headroom(
        wrong_observations,
        expected_generator_host="generator-a",
        minimum_duration_seconds=1,
        expected_interval_seconds=1,
        maximum_gap_factor=1.5,
        observations_sha256=sha256_file(generator_events),
        measurement_start_unix_ms=measurement_start_unix_ms(profile, scheduled_start_ms),
        measurement_end_unix_ms=measurement_end_unix_ms(profile, scheduled_start_ms),
        soak_end_unix_ms=workload_end_unix_ms(profile, scheduled_start_ms),
    )
    (run_directory / "summary" / "generator-generator-a.json").write_text(
        wrong_summary.model_dump_json() + "\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="generator_workload_process_count_mismatch"):
        finalize_run_directory(run_directory)

    generator_events.write_text(
        "".join(json.dumps(item.model_dump(mode="json")) + "\n" for item in observations),
        encoding="utf-8",
    )
    restored_summary = summarize_generator_headroom(
        observations,
        expected_generator_host="generator-a",
        minimum_duration_seconds=1,
        expected_interval_seconds=1,
        maximum_gap_factor=1.5,
        observations_sha256=sha256_file(generator_events),
        measurement_start_unix_ms=measurement_start_unix_ms(profile, scheduled_start_ms),
        measurement_end_unix_ms=measurement_end_unix_ms(profile, scheduled_start_ms),
        soak_end_unix_ms=workload_end_unix_ms(profile, scheduled_start_ms),
    )
    (run_directory / "summary" / "generator-generator-a.json").write_text(
        restored_summary.model_dump_json() + "\n", encoding="utf-8"
    )

    runtime_path = run_directory / "raw" / "runtime-generator-generator-a.json"
    stored_runtime = LinuxRuntimeManifest.model_validate_json(
        runtime_path.read_text(encoding="utf-8")
    )
    validation_arguments: dict[str, Any] = {
        "role": "generator",
        "host": "generator-a",
        "expected_architecture": profile.generator_hosts[0].architecture,
        "coordinated_anchor_start_unix_ms": warm_anchor_start_unix_ms(profile, scheduled_start_ms),
        "coordinated_measurement_start_unix_ms": measurement_start_unix_ms(
            profile, scheduled_start_ms
        ),
        "resource_summary": restored_summary,
    }
    validate_runtime_manifest(profile, stored_runtime, **validation_arguments)
    with pytest.raises(ValueError, match="runtime_manifest_binding_invalid"):
        validate_runtime_manifest(
            profile,
            stored_runtime.model_copy(update={"host": "wrong-host"}),
            **validation_arguments,
        )
    with pytest.raises(ValueError, match="runtime_manifest_requires_resource_summary"):
        validate_runtime_manifest(
            profile,
            stored_runtime,
            **{**validation_arguments, "resource_summary": None},
        )
    runtime = stored_runtime.gstreamer
    assert runtime is not None
    with pytest.raises(ValueError, match="runtime_manifest_gstreamer_binding_invalid"):
        validate_runtime_manifest(
            profile,
            stored_runtime.model_copy(
                update={"gstreamer": runtime.model_copy(update={"version": "1.23.0"})}
            ),
            **validation_arguments,
        )
    with pytest.raises(ValueError, match="runtime_manifest_sut_has_gstreamer_inventory"):
        validate_runtime_manifest(
            profile,
            stored_runtime.model_copy(update={"role": "sut"}),
            **{**validation_arguments, "role": "sut"},
        )
    runtime_path.write_text(
        stored_runtime.model_copy(update={"machine_id_sha256": "5" * 64}).model_dump_json() + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="runtime_manifest_resource_series_binding_invalid"):
        finalize_run_directory(run_directory)
    runtime_path.write_text(stored_runtime.model_dump_json() + "\n", encoding="utf-8")

    changed_sysctls = tuple(
        item.model_copy(update={"value": "32769 60999"})
        if item.name == "net.ipv4.ip_local_port_range"
        else item
        for item in stored_runtime.sysctls
    )
    runtime_path.write_text(
        stored_runtime.model_copy(update={"sysctls": changed_sysctls}).model_dump_json() + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="runtime_manifest_resource_series_binding_invalid"):
        finalize_run_directory(run_directory)
    runtime_path.write_text(stored_runtime.model_dump_json() + "\n", encoding="utf-8")

    (run_directory / "final-manifest.json").write_text('{"schema_version":', encoding="utf-8")
    assert load_cli_main(["finalize", str(run_directory)]) == 0
    finalized_output = capsys.readouterr()
    assert finalized_output.out == f"FINALIZED directory={run_directory}\n"
    final_manifest = json.loads((run_directory / "final-manifest.json").read_text(encoding="utf-8"))

    assert final_manifest["status"] == "finalized"
    assert {
        "reader-plan-generator-a.tsv",
        "raw/generator-generator-a.jsonl",
        "raw/runtime-generator-generator-a.json",
        "raw/readers.jsonl",
        "summary/generator-generator-a.json",
        "summary/readers.json",
    }.issubset(final_manifest["files"])
    assert (run_directory / "final-manifest.json").stat().st_mode & 0o777 == 0o440
    assert (run_directory / "raw" / "readers.jsonl").stat().st_mode & 0o777 == 0o440
    assert run_directory.stat().st_mode & 0o777 == 0o550
    assert load_cli_main(["verify", str(run_directory)]) == 0
    verified_output = capsys.readouterr()
    assert verified_output.out == f"VERIFIED directory={run_directory}\n"
    verify_run_directory(run_directory)

    (run_directory / "raw" / "readers.jsonl").chmod(0o640)
    with pytest.raises(ValueError, match="evidence_file_mode_invalid"):
        verify_run_directory(run_directory)
    (run_directory / "raw" / "readers.jsonl").chmod(0o440)

    run_directory.chmod(0o750)
    with pytest.raises(ValueError, match="evidence_directory_mode_invalid"):
        verify_run_directory(run_directory)
    finalize_run_directory(run_directory)
    assert run_directory.stat().st_mode & 0o777 == 0o550
    verify_run_directory(run_directory)

    (run_directory / "summary" / "readers.json").chmod(0o640)
    (run_directory / "summary" / "readers.json").write_text(
        json.dumps(
            {
                "valid": False,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="evidence_digest_mismatch"):
        verify_run_directory(run_directory)

    with pytest.raises(FileExistsError):
        initialize_run_directory(profile, run_directory)


def test_finalization_rejects_fabricated_green_summaries(tmp_path: Path) -> None:
    profile = LoadProfile.model_validate(valid_profile())
    run_directory = tmp_path / "fabricated"
    initialize_run_directory(profile, run_directory)
    (run_directory / "path-catalog.json").write_text("{}\n", encoding="utf-8")
    (run_directory / "launch-plan.json").write_text("{}\n", encoding="utf-8")
    (run_directory / "raw").mkdir()
    (run_directory / "summary").mkdir()
    (run_directory / "raw" / "readers.jsonl").write_text(
        '{"event":"run_started"}\n', encoding="utf-8"
    )
    (run_directory / "summary" / "readers.json").write_text('{"valid":true}\n', encoding="utf-8")

    assert load_cli_main(["finalize", str(run_directory)]) == 2


def test_proxy_and_direct_profiles_must_be_a_compatible_pair() -> None:
    proxy_raw = valid_profile()
    direct_raw = valid_profile()
    direct_workload = direct_raw["workload"]
    assert isinstance(direct_workload, dict)
    direct_workload["endpoint_mode"] = "direct-control"
    proxy = LoadProfile.model_validate(proxy_raw)
    direct = LoadProfile.model_validate(direct_raw)

    validate_comparison_pair(proxy, direct)

    incompatible_raw = valid_profile()
    incompatible_workload = incompatible_raw["workload"]
    assert isinstance(incompatible_workload, dict)
    incompatible_workload["endpoint_mode"] = "direct-control"
    incompatible_raw["seed"] = 1
    incompatible = LoadProfile.model_validate(incompatible_raw)
    with pytest.raises(ValueError, match="comparison_profiles_differ"):
        validate_comparison_pair(proxy, incompatible)


def test_load_cli_validates_and_prepares_a_digest_bound_run_without_overwrite(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pull_server = tmp_path / "rtsp-pull-server"
    load_reader = tmp_path / "rtsp-load-reader"
    fixture = tmp_path / "fixture.h264"
    pull_server.write_bytes(b"pull-server")
    load_reader.write_bytes(b"load-reader")
    fixture.write_bytes(b"fixture")
    pull_server.chmod(0o750)
    load_reader.chmod(0o750)
    raw = valid_profile()
    artifacts = raw["artifacts"]
    fixture_profile = raw["fixture"]
    assert isinstance(artifacts, dict)
    assert isinstance(fixture_profile, dict)
    artifacts["pull_server_sha256"] = hashlib.sha256(b"pull-server").hexdigest()
    artifacts["load_reader_sha256"] = hashlib.sha256(b"load-reader").hexdigest()
    fixture_profile["path"] = str(fixture)
    fixture_profile["sha256"] = hashlib.sha256(b"fixture").hexdigest()
    profile_path = tmp_path / "profile.json"
    write_fixture_manifest(LoadProfile.model_validate(raw))
    profile_path.write_text(json.dumps(raw), encoding="utf-8")
    run_directory = tmp_path / "run-001"

    assert load_cli_main(["validate", str(profile_path)]) == 0
    validation_output = capsys.readouterr()
    assert validation_output.err == ""
    assert validation_output.out.startswith("VALID profile_sha256=")

    prepare_args = [
        "prepare",
        str(profile_path),
        str(run_directory),
        "--pull-server-binary",
        str(pull_server),
        "--load-reader-binary",
        str(load_reader),
        "--start-unix-ms",
        "4102444800000",
    ]
    assert load_cli_main(prepare_args) == 0
    init_output = capsys.readouterr()
    assert init_output.err == ""
    assert init_output.out.startswith(f"PREPARED directory={run_directory}")
    launch_plan = json.loads((run_directory / "launch-plan.json").read_text(encoding="utf-8"))
    assert (
        launch_plan["verified_artifacts"]["load_reader_sha256"] == artifacts["load_reader_sha256"]
    )
    assert (run_directory / "reader-plan.tsv").is_file()

    assert load_cli_main(prepare_args) == 2
    failure_output = capsys.readouterr()
    assert failure_output.out == ""
    assert failure_output.err == "load_profile_error: destination_exists\n"


def test_direct_control_prepare_writes_one_coordinated_reader_shard_per_host(
    tmp_path: Path,
) -> None:
    pull_server = tmp_path / "rtsp-pull-server"
    load_reader = tmp_path / "rtsp-load-reader"
    fixture = tmp_path / "fixture.h264"
    pull_server.write_bytes(b"pull-server")
    load_reader.write_bytes(b"load-reader")
    fixture.write_bytes(b"fixture")
    pull_server.chmod(0o750)
    load_reader.chmod(0o750)
    raw = valid_profile(tier="capacity")
    artifacts = raw["artifacts"]
    fixture_profile = raw["fixture"]
    workload = raw["workload"]
    assert isinstance(artifacts, dict)
    assert isinstance(fixture_profile, dict)
    assert isinstance(workload, dict)
    artifacts["pull_server_sha256"] = hashlib.sha256(b"pull-server").hexdigest()
    artifacts["load_reader_sha256"] = hashlib.sha256(b"load-reader").hexdigest()
    fixture_profile["path"] = str(fixture)
    fixture_profile["sha256"] = hashlib.sha256(b"fixture").hexdigest()
    workload["endpoint_mode"] = "direct-control"
    profile = LoadProfile.model_validate(raw)
    write_fixture_manifest(profile)
    run_directory = tmp_path / "direct-run"

    launch_plan = prepare_run_directory(
        profile,
        run_directory,
        pull_server_binary=pull_server,
        load_reader_binary=load_reader,
    )

    assert len(launch_plan["readers"]) == 2
    for shard_index, launch in enumerate(launch_plan["readers"]):
        arguments = launch["argv"]
        assert "--schedule-shards" in arguments
        assert arguments[arguments.index("--schedule-shards") + 1] == "2"
        assert arguments[arguments.index("--schedule-shard-index") + 1] == str(shard_index)
        assert arguments[arguments.index("--global-reader-count") + 1] == "8"
    assert (run_directory / "reader-plan-generator-a.tsv").is_file()
    assert (run_directory / "reader-plan-generator-b.tsv").is_file()


def test_run_preparation_rejects_unpinned_binary_paths_and_tampered_manifest(
    tmp_path: Path,
) -> None:
    profile = LoadProfile.model_validate(valid_profile())
    binary = tmp_path / "binary"
    binary.write_bytes(b"wrong")

    with pytest.raises(ValueError, match="path_must_be_absolute"):
        prepare_run_directory(
            profile,
            tmp_path / "relative-failure",
            pull_server_binary=Path("relative-binary"),
            load_reader_binary=binary,
        )

    with pytest.raises(ValueError, match="type_or_mode_invalid"):
        prepare_run_directory(
            profile,
            tmp_path / "mode-failure",
            pull_server_binary=binary,
            load_reader_binary=binary,
        )

    binary.chmod(0o750)
    with pytest.raises(ValueError, match="digest_mismatch"):
        prepare_run_directory(
            profile,
            tmp_path / "digest-failure",
            pull_server_binary=binary,
            load_reader_binary=binary,
        )

    run_directory = tmp_path / "tampered-run"
    initialize_run_directory(profile, run_directory)
    manifest_path = run_directory / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["profile_sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="stored_profile_manifest_mismatch"):
        load_stored_profile(run_directory)


def test_load_cli_summarizes_generator_headroom_and_returns_nonzero_when_invalid(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    raw_profile = valid_profile()
    raw_profile["duration"] = {
        "warmup_seconds": 0,
        "measurement_seconds": 1,
        "soak_seconds": 0,
    }
    profile = LoadProfile.model_validate(raw_profile)
    run_directory = tmp_path / "run"
    initialize_run_directory(profile, run_directory)
    (run_directory / "raw").mkdir()
    (run_directory / "summary").mkdir()
    coordinated_start_ms = int(datetime(2026, 8, 10, 12, 0, tzinfo=UTC).timestamp() * 1000)
    (run_directory / "launch-plan.json").write_text(
        json.dumps({"coordinated_start_unix_ms": coordinated_start_ms}),
        encoding="utf-8",
    )
    observations_path = run_directory / "raw" / "generator.jsonl"
    process_bindings = runtime_process_bindings()
    process_binding_payload = [item.model_dump(mode="json") for item in process_bindings]
    process_binding_sha256 = runtime_process_bindings_sha256(process_bindings)

    def write_observations(network_percent: float) -> None:
        observations_path.write_text(
            "".join(
                json.dumps(
                    {
                        "generator_host": "generator-a",
                        "machine_id_sha256": "a" * 64,
                        "boot_id": "11111111-1111-1111-1111-111111111111",
                        "timestamp": timestamp,
                        "interval_seconds": 1,
                        "host_cpu_percent": 10,
                        "host_ram_percent": 20,
                        "max_process_cpu_percent": 10,
                        "cgroup_cpu_percent": 10,
                        "cgroup_ram_percent": 20,
                        "max_process_fd_percent": 30,
                        "socket_percent": 10,
                        "ephemeral_port_start": 32768,
                        "ephemeral_port_end": 60999,
                        "ephemeral_port_capacity": 28232,
                        "reserved_ports_sha256": "d" * 64,
                        "cgroup_pids_percent": 30,
                        "network_percent": network_percent,
                        "network_packets_per_second": 1000,
                        "packet_rate_percent": 10,
                        "interface_mtu_bytes": 1500,
                        "memory_total_bytes": 16 * 1024**3,
                        "nic_link_speed_bits_per_second": 10_000_000_000,
                        "cgroup_cpu_capacity_cores": 4,
                        "cgroup_memory_limit_bytes": 8 * 1024**3,
                        "cgroup_pids_limit": 100000,
                        "process_count": 2,
                        "workload_processes": process_binding_payload,
                        "workload_processes_sha256": process_binding_sha256,
                        "workload_process_limits": [
                            {"pid": item.pid, "max_open_files": 65536} for item in process_bindings
                        ],
                        "cgroup_path_sha256": "c" * 64,
                        "cgroup_constraint_chain_sha256": "5" * 64,
                    }
                )
                + "\n"
                for timestamp in (
                    "2026-08-10T12:00:00Z",
                    "2026-08-10T12:00:01Z",
                    "2026-08-10T12:00:02Z",
                )
            ),
            encoding="utf-8",
        )

    write_observations(40)
    valid_summary_path = run_directory / "summary" / "valid.json"
    assert (
        load_cli_main(
            [
                "summarize-generator",
                str(run_directory),
                str(observations_path),
                str(valid_summary_path),
                "--generator-host",
                "generator-a",
            ]
        )
        == 0
    )
    capsys.readouterr()
    valid_output = json.loads(valid_summary_path.read_text(encoding="utf-8"))
    assert valid_output["valid"] is True

    write_observations(70)
    invalid_summary_path = run_directory / "summary" / "invalid.json"
    assert (
        load_cli_main(
            [
                "summarize-generator",
                str(run_directory),
                str(observations_path),
                str(invalid_summary_path),
                "--generator-host",
                "generator-a",
            ]
        )
        == 3
    )
    capsys.readouterr()
    invalid_output = json.loads(invalid_summary_path.read_text(encoding="utf-8"))
    assert invalid_output["invalid_reasons"] == ["generator_network_headroom_below_30_percent"]


def test_versioned_smoke_profile_example_fails_until_placeholders_are_replaced() -> None:
    payload = json.loads(Path("tools/load/profiles/smoke.example.json").read_text(encoding="utf-8"))

    with pytest.raises(ValidationError, match="artifact_placeholder_not_replaced"):
        LoadProfile.model_validate(payload)
