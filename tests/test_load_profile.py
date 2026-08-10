from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from rtsp_proxy.load_cli import main as load_cli_main
from rtsp_proxy.load_profile import (
    LoadProfile,
    canonical_profile_bytes,
    finalize_run_directory,
    initialize_run_directory,
    validate_comparison_pair,
    verify_run_directory,
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
            "audio": "none",
        },
        "generator_hosts": hosts,
        "network": {
            "profile": "lan",
            "interface": "camera0",
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
    lifecycle.update(
        mode=mode,
        disconnect_rate_per_second=disconnect_rate,
        reconnect_attempts=3 if mode in {"steady", "burst", "outage"} else 0,
        outage_percent=outage_percent,
    )

    assert LoadProfile.model_validate(raw).reader_lifecycle.mode == mode


def test_invalid_lifecycle_shape_fails_closed() -> None:
    raw = valid_profile()
    lifecycle = raw["reader_lifecycle"]
    assert isinstance(lifecycle, dict)
    lifecycle.update(mode="outage", outage_percent=12, reconnect_attempts=3)

    with pytest.raises(ValidationError):
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


def test_wan_profile_has_the_consensus_ingress_impairment() -> None:
    raw = valid_profile()
    raw["network"] = {
        "profile": "wan",
        "interface": "camera0",
        "rtt_ms": 50,
        "jitter_ms": 10,
        "loss_percent": 0.5,
    }
    assert LoadProfile.model_validate(raw).network.profile == "wan"

    network = raw["network"]
    assert isinstance(network, dict)
    network["rtt_ms"] = 0
    with pytest.raises(ValidationError, match="wan_profile_below_consensus_impairment"):
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


def test_run_directory_finalization_hashes_and_seals_every_evidence_file(
    tmp_path: Path,
) -> None:
    profile = LoadProfile.model_validate(valid_profile())
    run_directory = tmp_path / "run-001"

    manifest = initialize_run_directory(profile, run_directory)

    stored_profile = (run_directory / "profile.json").read_bytes()
    stored_manifest = json.loads(
        (run_directory / "run-manifest.json").read_text(encoding="utf-8")
    )
    assert manifest == stored_manifest
    assert stored_manifest == {
        "schema_version": 1,
        "status": "initialized",
        "profile_sha256": canonical_profile_bytes(profile)[1],
        "git_commit": "a" * 40,
        "sut_architecture": "amd64",
    }
    assert stored_profile == canonical_profile_bytes(profile)[0]
    assert run_directory.stat().st_mode & 0o777 == 0o750
    assert (run_directory / "profile.json").stat().st_mode & 0o777 == 0o640

    (run_directory / "path-catalog.json").write_text("{}\n", encoding="utf-8")
    (run_directory / "launch-plan.json").write_text("{}\n", encoding="utf-8")
    (run_directory / "raw").mkdir()
    (run_directory / "raw" / "readers.jsonl").write_text(
        '{"event":"run_started"}\n', encoding="utf-8"
    )
    (run_directory / "raw" / "generator.jsonl").write_text(
        '{"cpu":1}\n', encoding="utf-8"
    )
    reader_digest = hashlib.sha256(
        (run_directory / "raw" / "readers.jsonl").read_bytes()
    ).hexdigest()
    generator_digest = hashlib.sha256(
        (run_directory / "raw" / "generator.jsonl").read_bytes()
    ).hexdigest()
    (run_directory / "summary").mkdir()
    (run_directory / "summary" / "readers.json").write_text(
        json.dumps(
            {
                "valid": True,
                "expected_concurrent_readers": 8,
                "events_sha256": reader_digest,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (run_directory / "summary" / "generator.json").write_text(
        json.dumps(
            {
                "valid": True,
                "generator_host": "generator-a",
                "observations_sha256": generator_digest,
            }
        )
        + "\n",
        encoding="utf-8",
    )

    final_manifest = finalize_run_directory(run_directory)

    assert final_manifest["status"] == "finalized"
    assert set(final_manifest["files"]) == {
        "path-catalog.json",
        "launch-plan.json",
        "profile.json",
        "raw/generator.jsonl",
        "raw/readers.jsonl",
        "run-manifest.json",
        "summary/generator.json",
        "summary/readers.json",
    }
    assert (run_directory / "final-manifest.json").stat().st_mode & 0o777 == 0o440
    assert (run_directory / "raw" / "readers.jsonl").stat().st_mode & 0o777 == 0o440
    assert run_directory.stat().st_mode & 0o777 == 0o550
    verify_run_directory(run_directory)

    (run_directory / "summary" / "readers.json").chmod(0o640)
    (run_directory / "summary" / "readers.json").write_text(
        '{"valid":false}\n', encoding="utf-8"
    )
    with pytest.raises(ValueError, match="evidence_digest_mismatch"):
        verify_run_directory(run_directory)

    with pytest.raises(FileExistsError):
        initialize_run_directory(profile, run_directory)


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
    ]
    assert load_cli_main(prepare_args) == 0
    init_output = capsys.readouterr()
    assert init_output.err == ""
    assert init_output.out.startswith(f"PREPARED directory={run_directory}")
    launch_plan = json.loads(
        (run_directory / "launch-plan.json").read_text(encoding="utf-8")
    )
    assert launch_plan["verified_artifacts"]["load_reader_sha256"] == artifacts[
        "load_reader_sha256"
    ]
    assert (run_directory / "reader-plan.tsv").is_file()

    assert load_cli_main(prepare_args) == 2
    failure_output = capsys.readouterr()
    assert failure_output.out == ""
    assert failure_output.err == "load_profile_error: destination_exists\n"

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
    observations_path = run_directory / "raw" / "generator.jsonl"

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
                        "cgroup_pids_percent": 30,
                        "network_percent": network_percent,
                    }
                )
                + "\n"
                for timestamp in (
                    "2026-08-10T12:00:00Z",
                    "2026-08-10T12:00:01Z",
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
    assert invalid_output["invalid_reasons"] == [
        "generator_network_headroom_below_30_percent"
    ]


def test_versioned_smoke_profile_example_fails_until_placeholders_are_replaced() -> None:
    payload = json.loads(
        Path("tools/load/profiles/smoke.example.json").read_text(encoding="utf-8")
    )

    with pytest.raises(ValidationError, match="artifact_placeholder_not_replaced"):
        LoadProfile.model_validate(payload)
