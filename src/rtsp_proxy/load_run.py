from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from pathlib import Path
from typing import Any, cast

from rtsp_proxy.load_catalog import (
    ReaderPlan,
    build_direct_reader_plan,
    build_load_catalog,
    build_proxy_reader_plan,
    write_load_catalog,
    write_reader_paths,
)
from rtsp_proxy.load_profile import (
    LoadProfile,
    canonical_profile_bytes,
    initialize_run_directory,
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_pinned_file(path: Path, expected_sha256: str, *, executable: bool) -> None:
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("pinned_artifact_path_must_be_absolute_regular_file")
    mode = path.stat().st_mode
    if not stat.S_ISREG(mode) or (executable and mode & 0o111 == 0):
        raise ValueError("pinned_artifact_type_or_mode_invalid")
    if sha256_file(path) != expected_sha256:
        raise ValueError("pinned_artifact_digest_mismatch")


def _write_json_exclusive(path: Path, payload: object) -> str:
    body = (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    with path.open("xb") as output:
        output.write(body)
        output.flush()
        os.fsync(output.fileno())
    path.chmod(0o640)
    return hashlib.sha256(body).hexdigest()


def _canonical_json_bytes(payload: object) -> bytes:
    return (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )


def _reader_plan_bytes(plan: ReaderPlan) -> bytes:
    return "".join(
        f"{target.path}\t{target.reader_count}\t{target.reader_id_start}\n"
        for target in plan.targets
    ).encode("ascii")


def load_stored_profile(run_directory: Path) -> LoadProfile:
    profile_path = run_directory / "profile.json"
    manifest_path = run_directory / "run-manifest.json"
    if profile_path.is_symlink() or manifest_path.is_symlink():
        raise ValueError("stored_run_contains_symlink")
    profile = LoadProfile.model_validate(json.loads(profile_path.read_text(encoding="utf-8")))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    _, digest = canonical_profile_bytes(profile)
    if manifest.get("profile_sha256") != digest:
        raise ValueError("stored_profile_manifest_mismatch")
    return profile


def _reader_arguments(
    profile: LoadProfile,
    *,
    load_reader_binary: Path,
    host: str,
    port: int,
    plan_path: Path,
    events_path: Path,
    generator_host: str,
    reader_plan_sha256: str,
    coordinated_start_unix_ms: int,
) -> list[str]:
    lifecycle = profile.reader_lifecycle
    arguments = [
        str(load_reader_binary),
        "--host",
        host,
        "--port",
        str(port),
        "--reader-plan",
        str(plan_path),
        "--codec",
        profile.fixture.codec,
        "--connect-rate",
        str(profile.workload.connect_rate_per_second),
        "--hold-seconds",
        str(profile.duration.total_seconds),
        "--events-file",
        str(events_path),
        "--lifecycle",
        lifecycle.mode,
        "--disconnect-rate",
        str(lifecycle.disconnect_rate_per_second),
        "--reconnect-attempts",
        str(lifecycle.reconnect_attempts),
        "--backoff-base-ms",
        str(lifecycle.backoff_base_ms),
        "--backoff-max-ms",
        str(lifecycle.backoff_max_ms),
        "--outage-percent",
        str(lifecycle.outage_percent),
        "--seed",
        str(profile.seed),
        "--generator-host",
        generator_host,
        "--profile-sha256",
        canonical_profile_bytes(profile)[1],
        "--reader-plan-sha256",
        reader_plan_sha256,
        "--start-unix-ms",
        str(coordinated_start_unix_ms),
    ]
    if profile.workload.endpoint_mode == "proxy" and profile.reader_credentials_file:
        arguments.extend(["--credentials-file", profile.reader_credentials_file])
    return arguments


def prepare_run_directory(
    profile: LoadProfile,
    destination: Path,
    *,
    pull_server_binary: Path,
    load_reader_binary: Path,
    coordinated_start_unix_ms: int | None = None,
) -> dict[str, Any]:
    if not destination.is_absolute():
        raise ValueError("run_directory_must_be_absolute")
    _require_pinned_file(
        pull_server_binary,
        profile.artifacts.pull_server_sha256,
        executable=True,
    )
    _require_pinned_file(
        load_reader_binary,
        profile.artifacts.load_reader_sha256,
        executable=True,
    )
    _require_pinned_file(Path(profile.fixture.path), profile.fixture.sha256, executable=False)
    if coordinated_start_unix_ms is None:
        coordinated_start_unix_ms = time.time_ns() // 1_000_000 + 120_000
    if coordinated_start_unix_ms <= time.time_ns() // 1_000_000:
        raise ValueError("coordinated_start_must_be_in_future")

    initialize_run_directory(profile, destination)
    raw_directory = destination / "raw"
    summary_directory = destination / "summary"
    raw_directory.mkdir(mode=0o750)
    summary_directory.mkdir(mode=0o750)
    catalog_path = destination / "path-catalog.json"
    write_load_catalog(profile, catalog_path)

    source_launches: list[dict[str, object]] = []
    for host in profile.generator_hosts:
        arguments = [
            str(pull_server_binary),
            "--address",
            "0.0.0.0",
            "--port",
            str(host.rtsp_port),
            "--source-start",
            str(host.source_start),
            "--source-count",
            str(host.source_count),
            "--fixture",
            profile.fixture.path,
            "--codec",
            profile.fixture.codec,
            "--fps",
            str(profile.fixture.fps),
        ]
        if profile.fixture.audio == "opus":
            arguments.append("--audio")
        source_launches.append({"generator_host": host.name, "argv": arguments})

    reader_launches: list[dict[str, object]] = []
    if profile.workload.endpoint_mode == "proxy":
        for host in profile.generator_hosts:
            plan = build_proxy_reader_plan(profile, host.name)
            if not plan.targets:
                continue
            plan_path = destination / (
                "reader-plan.tsv"
                if len(profile.generator_hosts) == 1
                else f"reader-plan-{host.name}.tsv"
            )
            events_path = raw_directory / (
                "readers.jsonl"
                if len(profile.generator_hosts) == 1
                else f"readers-{host.name}.jsonl"
            )
            plan_sha256 = write_reader_paths(plan, plan_path)
            reader_launches.append(
                {
                    "generator_host": host.name,
                    "argv": _reader_arguments(
                        profile,
                        load_reader_binary=load_reader_binary,
                        host=profile.sut_rtsp_host,
                        port=profile.sut_rtsp_port,
                        plan_path=plan_path,
                        events_path=events_path,
                        generator_host=host.name,
                        reader_plan_sha256=plan_sha256,
                        coordinated_start_unix_ms=coordinated_start_unix_ms,
                    ),
                }
            )
    else:
        for host in profile.generator_hosts:
            plan = build_direct_reader_plan(profile, host.name)
            if not plan.targets:
                continue
            plan_path = destination / f"reader-plan-{host.name}.tsv"
            plan_sha256 = write_reader_paths(plan, plan_path)
            reader_launches.append(
                {
                    "generator_host": host.name,
                    "argv": _reader_arguments(
                        profile,
                        load_reader_binary=load_reader_binary,
                        host=host.rtsp_host,
                        port=host.rtsp_port,
                        plan_path=plan_path,
                        events_path=raw_directory / f"readers-{host.name}.jsonl",
                        generator_host=host.name,
                        reader_plan_sha256=plan_sha256,
                        coordinated_start_unix_ms=coordinated_start_unix_ms,
                    ),
                }
            )

    for shard_index, reader_launch in enumerate(reader_launches):
        arguments = cast(list[str], reader_launch["argv"])
        arguments.extend(
            [
                "--schedule-shards",
                str(len(reader_launches)),
                "--schedule-shard-index",
                str(shard_index),
                "--global-reader-count",
                str(profile.workload.total_readers),
            ]
        )

    launch_plan: dict[str, Any] = {
        "schema_version": 1,
        "profile_sha256": canonical_profile_bytes(profile)[1],
        "coordinated_start_unix_ms": coordinated_start_unix_ms,
        "verified_artifacts": {
            "fixture_sha256": profile.fixture.sha256,
            "pull_server_sha256": profile.artifacts.pull_server_sha256,
            "load_reader_sha256": profile.artifacts.load_reader_sha256,
        },
        "source_servers": source_launches,
        "readers": reader_launches,
    }
    _write_json_exclusive(destination / "launch-plan.json", launch_plan)
    return launch_plan


def validate_prepared_run_directory(run_directory: Path, profile: LoadProfile) -> dict[str, Any]:
    catalog_path = run_directory / "path-catalog.json"
    launch_path = run_directory / "launch-plan.json"
    expected_catalog = _canonical_json_bytes(build_load_catalog(profile).model_dump(mode="json"))
    if catalog_path.read_bytes() != expected_catalog:
        raise ValueError("prepared_catalog_mismatch")
    launch = cast(
        dict[str, Any], json.loads(launch_path.read_text(encoding="utf-8"))
    )
    if set(launch) != {
        "schema_version",
        "profile_sha256",
        "coordinated_start_unix_ms",
        "verified_artifacts",
        "source_servers",
        "readers",
    }:
        raise ValueError("prepared_launch_plan_shape_invalid")
    coordinated_start = launch["coordinated_start_unix_ms"]
    if not isinstance(coordinated_start, int) or coordinated_start <= 0:
        raise ValueError("prepared_launch_start_invalid")
    expected_artifacts = {
        "fixture_sha256": profile.fixture.sha256,
        "pull_server_sha256": profile.artifacts.pull_server_sha256,
        "load_reader_sha256": profile.artifacts.load_reader_sha256,
    }
    if (
        launch["schema_version"] != 1
        or launch["profile_sha256"] != canonical_profile_bytes(profile)[1]
        or launch["verified_artifacts"] != expected_artifacts
    ):
        raise ValueError("prepared_launch_binding_mismatch")
    source_launches = cast(list[dict[str, object]], launch["source_servers"])
    reader_launches = cast(list[dict[str, object]], launch["readers"])
    if len(source_launches) != len(profile.generator_hosts) or not source_launches:
        raise ValueError("prepared_source_launch_set_mismatch")
    first_source_argv = cast(list[str], source_launches[0].get("argv"))
    if not first_source_argv:
        raise ValueError("prepared_source_launch_invalid")
    pull_server_binary = Path(first_source_argv[0])
    _require_pinned_file(pull_server_binary, profile.artifacts.pull_server_sha256, executable=True)
    _require_pinned_file(Path(profile.fixture.path), profile.fixture.sha256, executable=False)

    expected_sources: list[dict[str, object]] = []
    for host in profile.generator_hosts:
        arguments = [
            str(pull_server_binary),
            "--address",
            "0.0.0.0",
            "--port",
            str(host.rtsp_port),
            "--source-start",
            str(host.source_start),
            "--source-count",
            str(host.source_count),
            "--fixture",
            profile.fixture.path,
            "--codec",
            profile.fixture.codec,
            "--fps",
            str(profile.fixture.fps),
        ]
        if profile.fixture.audio == "opus":
            arguments.append("--audio")
        expected_sources.append({"generator_host": host.name, "argv": arguments})
    if source_launches != expected_sources:
        raise ValueError("prepared_source_launch_set_mismatch")

    plans: list[tuple[str, ReaderPlan, Path, Path]] = []
    for host in profile.generator_hosts:
        plan = (
            build_proxy_reader_plan(profile, host.name)
            if profile.workload.endpoint_mode == "proxy"
            else build_direct_reader_plan(profile, host.name)
        )
        if not plan.targets:
            continue
        if profile.workload.endpoint_mode == "proxy":
            plan_path = run_directory / (
                "reader-plan.tsv"
                if len(profile.generator_hosts) == 1
                else f"reader-plan-{host.name}.tsv"
            )
            events_path = (
                run_directory
                / "raw"
                / (
                    "readers.jsonl"
                    if len(profile.generator_hosts) == 1
                    else f"readers-{host.name}.jsonl"
                )
            )
        else:
            plan_path = run_directory / f"reader-plan-{host.name}.tsv"
            events_path = run_directory / "raw" / f"readers-{host.name}.jsonl"
        plan_body = _reader_plan_bytes(plan)
        if plan_path.read_bytes() != plan_body:
            raise ValueError("prepared_reader_plan_mismatch")
        plans.append((host.name, plan, plan_path, events_path))
    if len(reader_launches) != len(plans):
        raise ValueError("prepared_reader_launch_set_mismatch")
    load_reader_binary: Path | None = None
    if plans:
        first_reader_argv = cast(list[str], reader_launches[0].get("argv"))
        if not first_reader_argv:
            raise ValueError("prepared_reader_launch_invalid")
        load_reader_binary = Path(first_reader_argv[0])
        _require_pinned_file(
            load_reader_binary, profile.artifacts.load_reader_sha256, executable=True
        )
    expected_readers: list[dict[str, object]] = []
    for shard_index, (host_name, plan, plan_path, events_path) in enumerate(plans):
        assert load_reader_binary is not None
        host = next(item for item in profile.generator_hosts if item.name == host_name)
        arguments = _reader_arguments(
            profile,
            load_reader_binary=load_reader_binary,
            host=(
                profile.sut_rtsp_host
                if profile.workload.endpoint_mode == "proxy"
                else host.rtsp_host
            ),
            port=(
                profile.sut_rtsp_port
                if profile.workload.endpoint_mode == "proxy"
                else host.rtsp_port
            ),
            plan_path=plan_path,
            events_path=events_path,
            generator_host=host_name,
            reader_plan_sha256=hashlib.sha256(_reader_plan_bytes(plan)).hexdigest(),
            coordinated_start_unix_ms=coordinated_start,
        )
        arguments.extend(
            [
                "--schedule-shards",
                str(len(plans)),
                "--schedule-shard-index",
                str(shard_index),
                "--global-reader-count",
                str(profile.workload.total_readers),
            ]
        )
        expected_readers.append({"generator_host": host_name, "argv": arguments})
    if reader_launches != expected_readers:
        raise ValueError("prepared_reader_launch_set_mismatch")
    return launch


def write_summary(path: Path, summary: object) -> str:
    if hasattr(summary, "model_dump"):
        payload = cast(Any, summary).model_dump(mode="json")
    else:
        payload = summary
    return _write_json_exclusive(path, payload)
