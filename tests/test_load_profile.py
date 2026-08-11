from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

import rtsp_proxy.load_cli as load_cli_module
from rtsp_proxy.load_catalog import build_direct_reader_plan
from rtsp_proxy.load_cli import main as load_cli_main
from rtsp_proxy.load_evidence import (
    ResourceObservation,
    RuntimeProcessBinding,
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
            "gstreamer_build_id": "ubuntu-1.24.2-1ubuntu0.1",
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


def test_load_cli_samples_and_summarizes_required_capacity_sut_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    profile = LoadProfile.model_validate(valid_profile(tier="capacity"))
    run_directory = tmp_path / "capacity-run"
    initialize_run_directory(profile, run_directory)
    raw_directory = run_directory / "raw"
    summary_directory = run_directory / "summary"
    raw_directory.mkdir()
    summary_directory.mkdir()
    scheduled_start = 4_102_444_800_000
    (run_directory / "launch-plan.json").write_text(
        json.dumps({"coordinated_start_unix_ms": scheduled_start}),
        encoding="utf-8",
    )
    sampled: dict[str, object] = {}

    def fake_sample(**kwargs: object) -> int:
        sampled.update(kwargs)
        return 7

    class FakeSummary:
        valid = True

        def model_dump(self, *, mode: str) -> dict[str, object]:
            assert mode == "json"
            return {"valid": True}

    monkeypatch.setattr(load_cli_module, "sample_linux_sut_resources", fake_sample)
    output = raw_directory / "sut.jsonl"
    assert (
        load_cli_main(
            [
                "sample-sut",
                str(run_directory),
                str(output),
                "--mediamtx-pid",
                "321",
                "--cgroup",
                "mediamtx.service",
                "--metrics-url",
                "http://127.0.0.1:9998/metrics",
            ]
        )
        == 0
    )
    assert sampled["mediamtx_pid"] == 321
    assert sampled["expected_mediamtx_sha256"] == profile.artifacts.mediamtx_sha256
    capsys.readouterr()

    output.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(load_cli_module, "load_sut_observations", lambda path: ())
    monkeypatch.setattr(
        load_cli_module, "summarize_sut_capacity", lambda *args, **kwargs: FakeSummary()
    )
    summary = summary_directory / "sut.json"
    assert (
        load_cli_main(
            [
                "summarize-sut",
                str(run_directory),
                str(output),
                str(summary),
            ]
        )
        == 0
    )
    assert json.loads(summary.read_text(encoding="utf-8")) == {"valid": True}


def test_load_cli_copies_and_binds_cold_direct_reference(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proxy_raw = valid_profile()
    proxy_workload = proxy_raw["workload"]
    assert isinstance(proxy_workload, dict)
    proxy_workload.update(
        active_sources=4,
        total_readers=4,
        session_temperature="cold",
        endpoint_mode="proxy",
    )
    direct_raw = json.loads(json.dumps(proxy_raw))
    direct_workload = direct_raw["workload"]
    assert isinstance(direct_workload, dict)
    direct_workload["endpoint_mode"] = "direct-control"
    proxy = LoadProfile.model_validate(proxy_raw)
    direct = LoadProfile.model_validate(direct_raw)
    proxy_run = tmp_path / "proxy"
    direct_run = tmp_path / "direct"
    initialize_run_directory(proxy, proxy_run)
    initialize_run_directory(direct, direct_run)
    (proxy_run / "raw").mkdir()
    (proxy_run / "summary").mkdir()
    (direct_run / "raw").mkdir()
    proxy_events = proxy_run / "raw" / "readers.jsonl"
    direct_events = direct_run / "raw" / "readers.jsonl"
    proxy_events.write_text("{}\n", encoding="utf-8")
    direct_events.write_text("{}\n", encoding="utf-8")
    (direct_run / "final-manifest.json").write_text("{}\n", encoding="utf-8")

    class FakeComparison:
        valid = True

        def model_dump(self, *, mode: str) -> dict[str, object]:
            assert mode == "json"
            return {"valid": True}

    monkeypatch.setattr(load_cli_module, "verify_run_directory", lambda path: {})
    monkeypatch.setattr(
        load_cli_module,
        "summarize_cold_comparison",
        lambda *args, **kwargs: FakeComparison(),
    )
    output = proxy_run / "summary" / "cold-comparison.json"

    assert (
        load_cli_main(
            [
                "compare-cold",
                str(proxy_run),
                str(proxy_events),
                str(direct_run),
                str(direct_events),
                str(output),
            ]
        )
        == 0
    )
    assert json.loads(output.read_text(encoding="utf-8")) == {"valid": True}
    assert (proxy_run / "reference" / "direct-final-manifest.json").is_file()


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
                        measurement_start_unix_ms(profile, scheduled_start_ms)
                        - scheduled_start_ms,
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
            reserved_ports_sha256="d" * 64,
            cgroup_pids_percent=10,
            network_percent=10,
            network_packets_per_second=1000,
            packet_rate_percent=10,
            interface_mtu_bytes=1500,
            process_count=2,
            workload_processes=process_bindings,
            workload_processes_sha256=runtime_process_bindings_sha256(process_bindings),
            cgroup_path_sha256="c" * 64,
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

    (run_directory / "final-manifest.json").write_text('{"schema_version":', encoding="utf-8")
    assert load_cli_main(["finalize", str(run_directory)]) == 0
    finalized_output = capsys.readouterr()
    assert finalized_output.out == f"FINALIZED directory={run_directory}\n"
    final_manifest = json.loads((run_directory / "final-manifest.json").read_text(encoding="utf-8"))

    assert final_manifest["status"] == "finalized"
    assert {
        "reader-plan-generator-a.tsv",
        "raw/generator-generator-a.jsonl",
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
                        "process_count": 2,
                        "workload_processes": process_binding_payload,
                        "workload_processes_sha256": process_binding_sha256,
                        "cgroup_path_sha256": "c" * 64,
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


def test_load_cli_binds_generator_sampler_to_launch_processes_and_mtu(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    profile = LoadProfile.model_validate(valid_profile())
    run_directory = tmp_path / "run"
    initialize_run_directory(profile, run_directory)
    (run_directory / "raw").mkdir()
    future_start = 4_102_444_800_000
    (run_directory / "launch-plan.json").write_text(
        json.dumps(
            {
                "coordinated_start_unix_ms": future_start,
                "source_servers": [{"generator_host": "generator-a"}],
                "readers": [{"generator_host": "generator-a"}],
            }
        ),
        encoding="utf-8",
    )
    captured: dict[str, object] = {}

    def sample(**kwargs: object) -> int:
        captured.update(kwargs)
        return 7

    monkeypatch.setattr(load_cli_module, "sample_linux_generator_resources", sample)
    output = run_directory / "raw" / "generator-generator-a.jsonl"

    assert (
        load_cli_main(
            [
                "sample-generator",
                str(run_directory),
                str(output),
                "--generator-host",
                "generator-a",
                "--source-pid",
                "101",
                "--reader-pid",
                "202",
                "--cgroup",
                "rtsp-load.slice",
            ]
        )
        == 0
    )
    assert capsys.readouterr().out == f"SAMPLED observations=7 output={output}\n"
    assert captured["pids"] == (101, 202)
    assert captured["expected_executables"] == {
        101: profile.artifacts.pull_server_sha256,
        202: profile.artifacts.load_reader_sha256,
    }
    assert captured["expected_mtu_bytes"] == 1500
    captured_duration = captured["duration_seconds"]
    assert isinstance(captured_duration, int)
    assert captured_duration > profile.duration.total_seconds


def test_versioned_smoke_profile_example_fails_until_placeholders_are_replaced() -> None:
    payload = json.loads(Path("tools/load/profiles/smoke.example.json").read_text(encoding="utf-8"))

    with pytest.raises(ValidationError, match="artifact_placeholder_not_replaced"):
        LoadProfile.model_validate(payload)
