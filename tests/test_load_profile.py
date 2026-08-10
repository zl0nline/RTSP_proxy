from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from rtsp_proxy.load_cli import main as load_cli_main
from rtsp_proxy.load_profile import (
    LoadProfile,
    canonical_profile_bytes,
    initialize_run_directory,
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
        "sut_architecture": "amd64",
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


def test_profile_rejects_collapsed_or_impossible_workload_axes() -> None:
    raw = valid_profile()
    workload = raw["workload"]
    assert isinstance(workload, dict)
    workload["active_sources"] = 5

    with pytest.raises(ValidationError, match="active_sources_exceed_registered_paths"):
        LoadProfile.model_validate(raw)


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


def test_run_directory_is_immutable_and_starts_with_a_bound_manifest(tmp_path: Path) -> None:
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

    with pytest.raises(FileExistsError):
        initialize_run_directory(profile, run_directory)


def test_load_cli_validates_and_initializes_without_overwrite(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(json.dumps(valid_profile()), encoding="utf-8")
    run_directory = tmp_path / "run-001"

    assert load_cli_main(["validate", str(profile_path)]) == 0
    validation_output = capsys.readouterr()
    assert validation_output.err == ""
    assert validation_output.out.startswith("VALID profile_sha256=")

    assert load_cli_main(["init", str(profile_path), str(run_directory)]) == 0
    init_output = capsys.readouterr()
    assert init_output.err == ""
    assert init_output.out == f"INITIALIZED directory={run_directory}\n"

    assert load_cli_main(["init", str(profile_path), str(run_directory)]) == 2
    failure_output = capsys.readouterr()
    assert failure_output.out == ""
    assert failure_output.err == "load_profile_error: destination_exists\n"

    catalog_path = tmp_path / "catalog.json"
    assert load_cli_main(["render-catalog", str(profile_path), str(catalog_path)]) == 0
    catalog_output = capsys.readouterr()
    assert catalog_output.err == ""
    assert catalog_output.out.startswith(f"CATALOG path={catalog_path} sha256=")


def test_load_cli_summarizes_generator_headroom_and_returns_nonzero_when_invalid(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    raw_profile = valid_profile()
    raw_profile["duration"] = {
        "warmup_seconds": 0,
        "measurement_seconds": 1,
        "soak_seconds": 0,
    }
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(json.dumps(raw_profile), encoding="utf-8")
    observations_path = tmp_path / "generator.jsonl"

    def write_observations(network_percent: float) -> None:
        observations_path.write_text(
            "".join(
                json.dumps(
                    {
                        "timestamp": timestamp,
                        "cpu_percent": 10,
                        "ram_percent": 20,
                        "fd_percent": 30,
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
    assert (
        load_cli_main(
            ["summarize-generator", str(profile_path), str(observations_path)]
        )
        == 0
    )
    valid_output = json.loads(capsys.readouterr().out)
    assert valid_output["valid"] is True

    write_observations(70)
    assert (
        load_cli_main(
            ["summarize-generator", str(profile_path), str(observations_path)]
        )
        == 3
    )
    invalid_output = json.loads(capsys.readouterr().out)
    assert invalid_output["invalid_reasons"] == [
        "generator_network_headroom_below_30_percent"
    ]


def test_versioned_smoke_profile_example_matches_the_strict_schema() -> None:
    payload = json.loads(
        Path("tools/load/profiles/smoke.example.json").read_text(encoding="utf-8")
    )

    profile = LoadProfile.model_validate(payload)

    assert profile.tier == "smoke"
    assert profile.fixture.source_mode == "rtsp-pull"
