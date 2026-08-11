from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import time
from fractions import Fraction
from itertools import pairwise
from pathlib import Path
from typing import Annotated, Any, Literal, Self, cast

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

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
    evidence_grace_seconds,
    initialize_run_directory,
    lifecycle_start_unix_ms,
    measurement_end_unix_ms,
    measurement_start_unix_ms,
    ramp_end_unix_ms,
    warm_anchor_start_unix_ms,
    workload_end_unix_ms,
)

Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


class FixtureManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    schema_version: Literal[1]
    fixture_sha256: Sha256
    fixture_size_bytes: Annotated[int, Field(gt=0)]
    codec: Literal["h264", "h265"]
    fps: Annotated[int, Field(gt=0, le=240)]
    frame_count: Annotated[int, Field(gt=1)]
    duration_seconds: Annotated[float, Field(gt=0)]
    measured_bitrate_bps: Annotated[int, Field(gt=0)]
    keyframe_indices: tuple[Annotated[int, Field(ge=0)], ...]
    keyframe_intervals: tuple[Annotated[int, Field(gt=0)], ...]
    loop_keyframe_interval_frames: Annotated[int, Field(gt=0)]
    audio: Literal["none", "opus"]
    ffmpeg_version: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    ffmpeg_sha256: Sha256
    ffprobe_version: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    ffprobe_sha256: Sha256

    @model_validator(mode="after")
    def validate_keyframe_proof(self) -> Self:
        if (
            len(self.keyframe_indices) < 2
            or self.keyframe_indices[0] != 0
            or tuple(sorted(set(self.keyframe_indices))) != self.keyframe_indices
            or self.keyframe_indices[-1] >= self.frame_count
            or tuple(current - previous for previous, current in pairwise(self.keyframe_indices))
            != self.keyframe_intervals
            or self.loop_keyframe_interval_frames != self.frame_count - self.keyframe_indices[-1]
            or abs(self.duration_seconds - self.frame_count / self.fps) > 1 / self.fps
        ):
            raise ValueError("fixture_manifest_semantics_invalid")
        return self


def _fixture_manifest_path(profile: LoadProfile) -> Path:
    return Path(f"{profile.fixture.path}.manifest.json")


def _load_fixture_manifest(path: Path) -> FixtureManifest:
    if path.is_symlink() or not path.is_file() or not stat.S_ISREG(path.stat().st_mode):
        raise ValueError("fixture_manifest_must_be_regular_file")
    return FixtureManifest.model_validate_json(path.read_text(encoding="utf-8"))


def validate_fixture_manifest(profile: LoadProfile, manifest: FixtureManifest) -> None:
    bitrate_error = abs(manifest.measured_bitrate_bps - profile.fixture.bitrate_bps)
    if (
        manifest.fixture_sha256 != profile.fixture.sha256
        or manifest.codec != profile.fixture.codec
        or manifest.fps != profile.fixture.fps
        or manifest.audio != profile.fixture.audio
        or manifest.ffmpeg_version != profile.artifacts.ffmpeg_version
        or manifest.ffmpeg_sha256 != profile.artifacts.ffmpeg_sha256
        or manifest.ffprobe_sha256 != profile.artifacts.ffprobe_sha256
        or not manifest.keyframe_intervals
        or any(interval != profile.fixture.gop_frames for interval in manifest.keyframe_intervals)
        or manifest.loop_keyframe_interval_frames != profile.fixture.gop_frames
        or bitrate_error > profile.fixture.bitrate_bps * 0.15
    ):
        raise ValueError("fixture_manifest_does_not_match_profile")


def inspect_fixture(
    profile: LoadProfile,
    *,
    ffmpeg_binary: Path,
    ffprobe_binary: Path,
    destination: Path | None = None,
) -> FixtureManifest:
    _require_pinned_file(ffmpeg_binary, profile.artifacts.ffmpeg_sha256, executable=True)
    _require_pinned_file(ffprobe_binary, profile.artifacts.ffprobe_sha256, executable=True)
    fixture_path = Path(profile.fixture.path)
    _require_pinned_file(fixture_path, profile.fixture.sha256, executable=False)

    ffmpeg_version_output = subprocess.run(
        [str(ffmpeg_binary), "-version"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.splitlines()
    ffprobe_version_output = subprocess.run(
        [str(ffprobe_binary), "-version"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.splitlines()
    if (
        not ffmpeg_version_output
        or profile.artifacts.ffmpeg_version not in ffmpeg_version_output[0]
        or not ffprobe_version_output
    ):
        raise ValueError("fixture_tool_version_mismatch")
    probe = subprocess.run(
        [
            str(ffprobe_binary),
            "-v",
            "error",
            "-f",
            "h264" if profile.fixture.codec == "h264" else "hevc",
            "-select_streams",
            "v:0",
            "-show_streams",
            "-show_frames",
            "-show_entries",
            "stream=codec_name,r_frame_rate:frame=key_frame",
            "-of",
            "json",
            str(fixture_path),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    payload = json.loads(probe.stdout)
    streams = payload.get("streams")
    frames = payload.get("frames")
    if (
        not isinstance(streams, list)
        or len(streams) != 1
        or not isinstance(streams[0], dict)
        or not isinstance(frames, list)
        or not frames
    ):
        raise ValueError("fixture_probe_output_invalid")
    stream = streams[0]
    try:
        probed_fps = Fraction(str(stream["r_frame_rate"]))
    except (KeyError, ValueError, ZeroDivisionError) as error:
        raise ValueError("fixture_probe_output_invalid") from error
    if probed_fps != profile.fixture.fps or stream.get("codec_name") != profile.fixture.codec:
        raise ValueError("fixture_probe_output_invalid")
    keyframes = tuple(
        index
        for index, frame in enumerate(frames)
        if isinstance(frame, dict) and frame.get("key_frame") == 1
    )
    frame_count = len(frames)
    duration_seconds = frame_count / profile.fixture.fps
    manifest = FixtureManifest(
        schema_version=1,
        fixture_sha256=profile.fixture.sha256,
        fixture_size_bytes=fixture_path.stat().st_size,
        codec=profile.fixture.codec,
        fps=profile.fixture.fps,
        frame_count=frame_count,
        duration_seconds=duration_seconds,
        measured_bitrate_bps=round(fixture_path.stat().st_size * 8 / duration_seconds),
        keyframe_indices=keyframes,
        keyframe_intervals=tuple(current - previous for previous, current in pairwise(keyframes)),
        loop_keyframe_interval_frames=frame_count - keyframes[-1] if keyframes else 0,
        audio=profile.fixture.audio,
        ffmpeg_version=profile.artifacts.ffmpeg_version,
        ffmpeg_sha256=profile.artifacts.ffmpeg_sha256,
        ffprobe_version=ffprobe_version_output[0],
        ffprobe_sha256=profile.artifacts.ffprobe_sha256,
    )
    validate_fixture_manifest(profile, manifest)
    _write_json_exclusive(
        destination or _fixture_manifest_path(profile), manifest.model_dump(mode="json")
    )
    return manifest


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
        f"{target.path}\t{target.reader_count}\t{target.reader_id_start}\t"
        f"{target.warm_anchor_count}\t{target.measured_schedule_start}\n"
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
    coordinated_anchor_start_unix_ms: int,
    coordinated_ramp_end_unix_ms: int,
    coordinated_lifecycle_start_unix_ms: int,
    coordinated_measurement_start_unix_ms: int,
    coordinated_measurement_end_unix_ms: int,
    coordinated_workload_end_unix_ms: int,
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
        "--anchor-start-unix-ms",
        str(coordinated_anchor_start_unix_ms),
        "--ramp-end-unix-ms",
        str(coordinated_ramp_end_unix_ms),
        "--lifecycle-start-unix-ms",
        str(coordinated_lifecycle_start_unix_ms),
        "--measurement-start-unix-ms",
        str(coordinated_measurement_start_unix_ms),
        "--measurement-end-unix-ms",
        str(coordinated_measurement_end_unix_ms),
        "--workload-end-unix-ms",
        str(coordinated_workload_end_unix_ms),
        "--evidence-grace-seconds",
        str(evidence_grace_seconds(profile)),
    ]
    if profile.workload.endpoint_mode == "proxy" and profile.reader_credentials_file:
        arguments.extend(["--credentials-file", profile.reader_credentials_file])
    if profile.fixture.audio == "opus":
        arguments.append("--audio")
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
    fixture_path = Path(profile.fixture.path)
    _require_pinned_file(fixture_path, profile.fixture.sha256, executable=False)
    fixture_manifest = _load_fixture_manifest(_fixture_manifest_path(profile))
    validate_fixture_manifest(profile, fixture_manifest)
    if fixture_manifest.fixture_size_bytes != fixture_path.stat().st_size:
        raise ValueError("fixture_manifest_size_mismatch")
    if coordinated_start_unix_ms is None:
        coordinated_start_unix_ms = time.time_ns() // 1_000_000 + 120_000
    if coordinated_start_unix_ms <= time.time_ns() // 1_000_000:
        raise ValueError("coordinated_start_must_be_in_future")

    initialize_run_directory(profile, destination)
    coordinated_lifecycle_start = lifecycle_start_unix_ms(profile, coordinated_start_unix_ms)
    coordinated_anchor_start = warm_anchor_start_unix_ms(profile, coordinated_start_unix_ms)
    if coordinated_anchor_start <= time.time_ns() // 1_000_000:
        raise ValueError("coordinated_anchor_start_must_be_in_future")
    coordinated_ramp_end = ramp_end_unix_ms(profile, coordinated_start_unix_ms)
    coordinated_measurement_start = measurement_start_unix_ms(profile, coordinated_start_unix_ms)
    coordinated_measurement_end = measurement_end_unix_ms(profile, coordinated_start_unix_ms)
    coordinated_workload_end = workload_end_unix_ms(profile, coordinated_start_unix_ms)
    raw_directory = destination / "raw"
    summary_directory = destination / "summary"
    raw_directory.mkdir(mode=0o750)
    summary_directory.mkdir(mode=0o750)
    fixture_manifest_sha256 = _write_json_exclusive(
        destination / "fixture-manifest.json",
        fixture_manifest.model_dump(mode="json"),
    )
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
            "--fixture-sha256",
            profile.fixture.sha256,
            "--codec",
            profile.fixture.codec,
            "--fps",
            str(profile.fixture.fps),
            "--rtp-mtu",
            str(profile.fixture.rtp_mtu_bytes),
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
                        coordinated_anchor_start_unix_ms=coordinated_anchor_start,
                        coordinated_ramp_end_unix_ms=coordinated_ramp_end,
                        coordinated_lifecycle_start_unix_ms=coordinated_lifecycle_start,
                        coordinated_measurement_start_unix_ms=coordinated_measurement_start,
                        coordinated_measurement_end_unix_ms=coordinated_measurement_end,
                        coordinated_workload_end_unix_ms=coordinated_workload_end,
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
                        coordinated_anchor_start_unix_ms=coordinated_anchor_start,
                        coordinated_ramp_end_unix_ms=coordinated_ramp_end,
                        coordinated_lifecycle_start_unix_ms=coordinated_lifecycle_start,
                        coordinated_measurement_start_unix_ms=coordinated_measurement_start,
                        coordinated_measurement_end_unix_ms=coordinated_measurement_end,
                        coordinated_workload_end_unix_ms=coordinated_workload_end,
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
        "coordinated_anchor_start_unix_ms": coordinated_anchor_start,
        "coordinated_ramp_end_unix_ms": coordinated_ramp_end,
        "coordinated_lifecycle_start_unix_ms": coordinated_lifecycle_start,
        "coordinated_measurement_start_unix_ms": coordinated_measurement_start,
        "coordinated_measurement_end_unix_ms": coordinated_measurement_end,
        "coordinated_workload_end_unix_ms": coordinated_workload_end,
        "verified_artifacts": {
            "fixture_sha256": profile.fixture.sha256,
            "fixture_manifest_sha256": fixture_manifest_sha256,
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
    launch = cast(dict[str, Any], json.loads(launch_path.read_text(encoding="utf-8")))
    if set(launch) != {
        "schema_version",
        "profile_sha256",
        "coordinated_start_unix_ms",
        "coordinated_anchor_start_unix_ms",
        "coordinated_ramp_end_unix_ms",
        "coordinated_lifecycle_start_unix_ms",
        "coordinated_measurement_start_unix_ms",
        "coordinated_measurement_end_unix_ms",
        "coordinated_workload_end_unix_ms",
        "verified_artifacts",
        "source_servers",
        "readers",
    }:
        raise ValueError("prepared_launch_plan_shape_invalid")
    coordinated_start = launch["coordinated_start_unix_ms"]
    if not isinstance(coordinated_start, int) or coordinated_start <= 0:
        raise ValueError("prepared_launch_start_invalid")
    coordinated_anchor_start = launch["coordinated_anchor_start_unix_ms"]
    if coordinated_anchor_start != warm_anchor_start_unix_ms(profile, coordinated_start):
        raise ValueError("prepared_anchor_start_invalid")
    coordinated_lifecycle_start = launch["coordinated_lifecycle_start_unix_ms"]
    if coordinated_lifecycle_start != lifecycle_start_unix_ms(profile, coordinated_start):
        raise ValueError("prepared_lifecycle_start_invalid")
    coordinated_ramp_end = launch["coordinated_ramp_end_unix_ms"]
    if coordinated_ramp_end != ramp_end_unix_ms(profile, coordinated_start):
        raise ValueError("prepared_ramp_end_invalid")
    coordinated_measurement_start = launch["coordinated_measurement_start_unix_ms"]
    if coordinated_measurement_start != measurement_start_unix_ms(profile, coordinated_start):
        raise ValueError("prepared_measurement_start_invalid")
    coordinated_measurement_end = launch["coordinated_measurement_end_unix_ms"]
    if coordinated_measurement_end != measurement_end_unix_ms(profile, coordinated_start):
        raise ValueError("prepared_measurement_end_invalid")
    coordinated_workload_end = launch["coordinated_workload_end_unix_ms"]
    if coordinated_workload_end != workload_end_unix_ms(profile, coordinated_start):
        raise ValueError("prepared_workload_end_invalid")
    expected_artifacts = {
        "fixture_sha256": profile.fixture.sha256,
        "fixture_manifest_sha256": sha256_file(run_directory / "fixture-manifest.json"),
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
    fixture_path = Path(profile.fixture.path)
    _require_pinned_file(fixture_path, profile.fixture.sha256, executable=False)
    fixture_manifest = _load_fixture_manifest(run_directory / "fixture-manifest.json")
    validate_fixture_manifest(profile, fixture_manifest)
    if fixture_manifest.fixture_size_bytes != fixture_path.stat().st_size:
        raise ValueError("fixture_manifest_size_mismatch")

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
            "--fixture-sha256",
            profile.fixture.sha256,
            "--codec",
            profile.fixture.codec,
            "--fps",
            str(profile.fixture.fps),
            "--rtp-mtu",
            str(profile.fixture.rtp_mtu_bytes),
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
            coordinated_anchor_start_unix_ms=coordinated_anchor_start,
            coordinated_ramp_end_unix_ms=coordinated_ramp_end,
            coordinated_lifecycle_start_unix_ms=coordinated_lifecycle_start,
            coordinated_measurement_start_unix_ms=coordinated_measurement_start,
            coordinated_measurement_end_unix_ms=coordinated_measurement_end,
            coordinated_workload_end_unix_ms=coordinated_workload_end,
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
