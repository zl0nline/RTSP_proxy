from __future__ import annotations

import json
from pathlib import Path

import pytest

from rtsp_proxy.identifiers import PublicId
from rtsp_proxy.load_catalog import (
    build_direct_reader_plan,
    build_load_catalog,
    build_proxy_reader_plan,
    load_public_id,
    write_direct_reader_paths,
    write_load_catalog,
    write_reader_paths,
)
from rtsp_proxy.load_profile import LoadProfile
from tests.test_load_profile import valid_profile


def test_load_public_ids_are_deterministic_canonical_and_index_specific() -> None:
    first = load_public_id(seed=1234, index=0)
    repeated = load_public_id(seed=1234, index=0)
    second = load_public_id(seed=1234, index=1)

    assert isinstance(first, PublicId)
    assert len(str(first)) == 25
    assert first == repeated
    assert first != second


def test_catalog_maps_every_registered_path_to_its_generator_range() -> None:
    profile = LoadProfile.model_validate(valid_profile(tier="capacity"))

    catalog = build_load_catalog(profile)

    assert catalog.schema_version == 1
    assert catalog.source_mode == "rtsp-pull"
    assert len(catalog.paths) == 4
    assert catalog.paths[0].source_url == ("rtsp://generator-a.load.internal:8554/source-00000")
    assert catalog.paths[1].source_url.endswith("/source-00001")
    assert catalog.paths[2].source_url == ("rtsp://generator-b.load.internal:8554/source-00002")
    assert len({path.public_id for path in catalog.paths}) == 4


def test_catalog_write_is_exclusive_and_contains_no_userinfo(tmp_path: Path) -> None:
    profile = LoadProfile.model_validate(valid_profile())
    destination = tmp_path / "path-catalog.json"

    catalog_sha256 = write_load_catalog(profile, destination)

    payload = destination.read_text(encoding="utf-8")
    stored = json.loads(payload)
    assert len(catalog_sha256) == 64
    assert stored["source_mode"] == "rtsp-pull"
    assert "@" not in payload
    assert destination.stat().st_mode & 0o777 == 0o640

    try:
        write_load_catalog(profile, destination)
    except FileExistsError:
        pass
    else:
        raise AssertionError("load catalog was overwritten")


def test_proxy_reader_plan_is_bound_to_the_catalog_without_urls(tmp_path: Path) -> None:
    profile = LoadProfile.model_validate(valid_profile())
    destination = tmp_path / "reader-paths.txt"

    plan = build_proxy_reader_plan(profile)
    paths_sha256 = write_reader_paths(plan, destination)

    assert len(paths_sha256) == 64
    assert destination.read_text(encoding="utf-8").splitlines() == [
        f"{target.path}\t{target.reader_count}\t{target.reader_id_start}\t"
        f"{target.warm_anchor_count}\t{target.measured_schedule_start}"
        for target in plan.targets
    ]
    assert "rtsp://" not in destination.read_text(encoding="utf-8")


def test_reader_paths_include_only_active_sources(tmp_path: Path) -> None:
    raw = valid_profile()
    workload = raw["workload"]
    assert isinstance(workload, dict)
    workload["active_sources"] = 2
    workload["total_readers"] = 4
    profile = LoadProfile.model_validate(raw)
    destination = tmp_path / "reader-paths.txt"

    write_reader_paths(build_proxy_reader_plan(profile), destination)

    assert len(destination.read_text(encoding="utf-8").splitlines()) == 2


def test_direct_control_paths_are_rendered_per_generator_host(tmp_path: Path) -> None:
    raw = valid_profile(tier="capacity")
    workload = raw["workload"]
    assert isinstance(workload, dict)
    workload["endpoint_mode"] = "direct-control"
    profile = LoadProfile.model_validate(raw)
    first = tmp_path / "generator-a.txt"
    second = tmp_path / "generator-b.txt"

    write_direct_reader_paths(profile, "generator-a", first)
    write_direct_reader_paths(profile, "generator-b", second)

    assert first.read_text(encoding="utf-8").splitlines() == [
        "source-00000\t2\t0\t1\t0",
        "source-00001\t2\t4\t1\t2",
    ]
    assert second.read_text(encoding="utf-8").splitlines() == [
        "source-00002\t2\t2\t1\t1",
        "source-00003\t2\t6\t1\t3",
    ]

    with pytest.raises(ValueError, match="unknown_generator_host"):
        write_direct_reader_paths(profile, "missing", tmp_path / "missing.txt")


def test_wan_direct_control_rotates_readers_to_remote_source_hosts() -> None:
    raw = valid_profile(tier="capacity")
    workload = raw["workload"]
    network = raw["network"]
    hosts = raw["generator_hosts"]
    assert isinstance(workload, dict) and isinstance(network, dict) and isinstance(hosts, list)
    workload["endpoint_mode"] = "direct-control"
    network.update(
        profile="wan",
        rtt_ms=50,
        jitter_ms=10,
        loss_percent=0.5,
        ifb_interface="rtspifb0",
        netem_queue_limit_packets=1000,
    )
    for index, host in enumerate(hosts):
        assert isinstance(host, dict)
        host["rtsp_host"] = f"192.0.2.{10 + index}"
    profile = LoadProfile.model_validate(raw)

    first = build_direct_reader_plan(profile, "generator-a")
    second = build_direct_reader_plan(profile, "generator-b")

    assert [target.path for target in first.targets] == ["source-00002", "source-00003"]
    assert [target.path for target in second.targets] == ["source-00000", "source-00001"]


def test_reader_plan_preserves_independent_active_and_reader_axes() -> None:
    raw = valid_profile()
    workload = raw["workload"]
    assert isinstance(workload, dict)
    workload["active_sources"] = 3
    workload["total_readers"] = 8
    profile = LoadProfile.model_validate(raw)

    plan = build_proxy_reader_plan(profile)

    assert len(plan.targets) == 3
    assert sum(target.reader_count for target in plan.targets) == 8
    assert [target.reader_count for target in plan.targets] == [3, 3, 2]
    ids = {
        reader_id
        for target in plan.targets
        for reader_id in range(
            target.reader_id_start,
            target.reader_id_start + target.reader_count,
        )
    }
    assert ids == set(range(8))
