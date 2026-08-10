from __future__ import annotations

import pytest
from pydantic import ValidationError

from rtsp_proxy.load_profile import LoadProfile


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
            "source_start": 0,
            "source_count": 4 if tier == "smoke" else 2,
        }
    ]
    if tier == "capacity":
        hosts.append(
            {
                "name": "generator-b",
                "architecture": "amd64",
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
            "mediamtx_sha256": "b" * 64,
            "ffmpeg_sha256": "c" * 64,
            "ffprobe_sha256": "d" * 64,
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
