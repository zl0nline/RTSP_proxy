from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal, Self, cast

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

Architecture = Literal["amd64", "arm64"]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
GitCommit = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
SafeName = Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9._-]{1,128}$")]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)


class ArtifactPins(StrictModel):
    git_commit: GitCommit
    mediamtx_version: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    mediamtx_sha256: Sha256
    ffmpeg_version: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    ffmpeg_sha256: Sha256
    ffprobe_sha256: Sha256
    gstreamer_version: Annotated[
        str, StringConstraints(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    ]
    gstreamer_build_id: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    pull_server_sha256: Sha256
    load_reader_sha256: Sha256

    @model_validator(mode="after")
    def reject_template_placeholders(self) -> Self:
        hashes = (
            self.mediamtx_sha256,
            self.ffmpeg_sha256,
            self.ffprobe_sha256,
            self.pull_server_sha256,
            self.load_reader_sha256,
        )
        if (
            self.git_commit == "0" * 40
            or any(value == "0" * 64 for value in hashes)
            or self.gstreamer_build_id.startswith("replace-")
        ):
            raise ValueError("artifact_placeholder_not_replaced")
        return self


class FixtureProfile(StrictModel):
    source_mode: Literal["rtsp-pull"]
    path: str
    sha256: Sha256
    codec: Literal["h264", "h265"]
    bitrate_bps: Annotated[int, Field(gt=0)]
    fps: Annotated[int, Field(gt=0)]
    gop_frames: Annotated[int, Field(gt=0)]
    audio: Literal["none", "opus"]

    @model_validator(mode="after")
    def require_absolute_fixture_path(self) -> Self:
        path = PurePosixPath(self.path)
        if not path.is_absolute() or ".." in path.parts:
            raise ValueError("fixture_path_must_be_absolute")
        if self.sha256 == "0" * 64:
            raise ValueError("fixture_placeholder_not_replaced")
        return self

    @property
    def gop_seconds(self) -> float:
        return self.gop_frames / self.fps


class GeneratorHost(StrictModel):
    name: Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9._-]{1,253}$")]
    architecture: Architecture
    rtsp_host: Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9._:-]{1,253}$")]
    rtsp_port: Annotated[int, Field(ge=1, le=65535)]
    source_start: Annotated[int, Field(ge=0)]
    source_count: Annotated[int, Field(gt=0)]


class NetworkProfile(StrictModel):
    profile: Literal["lan", "wan", "chaos"]
    interface: Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9_.:-]{1,15}$")]
    rtt_ms: Annotated[float, Field(ge=0)]
    jitter_ms: Annotated[float, Field(ge=0)]
    loss_percent: Annotated[float, Field(ge=0, lt=100)]

    @model_validator(mode="after")
    def validate_named_network_profile(self) -> Self:
        if self.profile == "lan" and any((self.rtt_ms, self.jitter_ms, self.loss_percent)):
            raise ValueError("lan_profile_must_not_inject_impairment")
        if self.profile == "wan" and (
            self.rtt_ms < 50 or self.jitter_ms < 10 or self.loss_percent < 0.5
        ):
            raise ValueError("wan_profile_below_consensus_impairment")
        return self


class WorkloadAxes(StrictModel):
    endpoint_mode: Literal["proxy", "direct-control"]
    session_temperature: Literal["warm", "cold"]
    registered_paths: Annotated[int, Field(gt=0)]
    active_sources: Annotated[int, Field(ge=0)]
    total_readers: Annotated[int, Field(ge=0)]
    connect_rate_per_second: Annotated[int, Field(ge=0, le=1000)]
    probe_rate_per_second: Annotated[float, Field(ge=0)]
    crud_rate_per_second: Annotated[float, Field(ge=0)]

    @model_validator(mode="after")
    def keep_axes_physically_possible(self) -> Self:
        if self.active_sources > self.registered_paths:
            raise ValueError("active_sources_exceed_registered_paths")
        if self.total_readers < self.active_sources:
            raise ValueError("readers_below_active_sources")
        if self.active_sources == 0 and self.total_readers != 0:
            raise ValueError("readers_require_active_sources")
        return self


class ReaderLifecycle(StrictModel):
    mode: Literal["single", "steady", "ramp", "burst", "outage"]
    disconnect_rate_per_second: Annotated[int, Field(ge=0, le=10000)]
    reconnect_attempts: Annotated[int, Field(ge=0, le=100)]
    backoff_base_ms: Annotated[int, Field(ge=1, le=60000)]
    backoff_max_ms: Annotated[int, Field(ge=1, le=300000)]
    outage_percent: Literal[0, 10, 25, 100]

    @model_validator(mode="after")
    def validate_lifecycle_shape(self) -> Self:
        if self.backoff_max_ms < self.backoff_base_ms:
            raise ValueError("backoff_max_below_base")
        if self.mode == "single" and any(
            (self.disconnect_rate_per_second, self.reconnect_attempts, self.outage_percent)
        ):
            raise ValueError("single_lifecycle_has_reconnect_controls")
        if self.mode == "steady" and (
            self.disconnect_rate_per_second not in {10, 100}
            or self.reconnect_attempts < 1
            or self.outage_percent != 0
        ):
            raise ValueError("steady_lifecycle_must_use_consensus_rate")
        if self.mode == "ramp" and any(
            (self.disconnect_rate_per_second, self.reconnect_attempts, self.outage_percent)
        ):
            raise ValueError("one_shot_lifecycle_has_reconnect_controls")
        if self.mode == "burst" and (
            self.disconnect_rate_per_second != 0
            or self.reconnect_attempts < 1
            or self.outage_percent != 0
        ):
            raise ValueError("burst_lifecycle_requires_failure_backoff")
        if self.mode == "outage" and (
            self.disconnect_rate_per_second != 0
            or self.reconnect_attempts < 1
            or self.outage_percent not in {10, 25, 100}
        ):
            raise ValueError("outage_lifecycle_invalid_cohort")
        return self


class EvidenceSampling(StrictModel):
    interval_seconds: Annotated[float, Field(ge=0.1, le=60)]
    maximum_gap_factor: Annotated[float, Field(ge=1, le=3)]


class RunDuration(StrictModel):
    warmup_seconds: Annotated[int, Field(ge=0)]
    measurement_seconds: Annotated[int, Field(gt=0)]
    soak_seconds: Annotated[int, Field(ge=0)]

    @property
    def total_seconds(self) -> int:
        return self.warmup_seconds + self.measurement_seconds + self.soak_seconds


class LoadProfile(StrictModel):
    schema_version: Literal[1]
    tier: Literal["smoke", "nightly", "capacity"]
    seed: Annotated[int, Field(ge=0, le=2147483647)]
    comparison_id: SafeName
    sut_architecture: Architecture
    sut_rtsp_host: Annotated[
        str, StringConstraints(pattern=r"^[a-zA-Z0-9._:-]{1,253}$")
    ]
    sut_rtsp_port: Annotated[int, Field(ge=1, le=65535)]
    reader_credentials_file: str | None
    artifacts: ArtifactPins
    fixture: FixtureProfile
    generator_hosts: Annotated[tuple[GeneratorHost, ...], Field(min_length=1)]
    network: NetworkProfile
    workload: WorkloadAxes
    reader_lifecycle: ReaderLifecycle
    evidence_sampling: EvidenceSampling
    duration: RunDuration

    @model_validator(mode="after")
    def validate_cross_field_contract(self) -> Self:
        if self.reader_credentials_file is not None:
            credentials = PurePosixPath(self.reader_credentials_file)
            if not credentials.is_absolute() or ".." in credentials.parts:
                raise ValueError("reader_credentials_path_must_be_absolute")
        names = [host.name for host in self.generator_hosts]
        if len(names) != len(set(names)):
            raise ValueError("generator_host_names_not_unique")
        if self.tier == "capacity" and len(self.generator_hosts) < 2:
            raise ValueError("capacity_requires_two_generator_hosts")

        cursor = 0
        for host in sorted(self.generator_hosts, key=lambda item: item.source_start):
            if host.source_start < cursor:
                raise ValueError("generator_source_ranges_overlap")
            if host.source_start > cursor:
                raise ValueError("generator_source_ranges_have_gap")
            cursor += host.source_count
        if cursor != self.workload.registered_paths:
            raise ValueError("generator_source_ranges_do_not_cover_registered_paths")

        rate = self.workload.connect_rate_per_second
        mode = self.reader_lifecycle.mode
        if mode == "steady" and rate != self.reader_lifecycle.disconnect_rate_per_second:
            raise ValueError("steady_connect_disconnect_rates_differ")
        if mode == "ramp" and rate != 100:
            raise ValueError("ramp_requires_100_readers_per_second")
        if mode == "burst" and rate != 1000:
            raise ValueError("burst_requires_1000_readers_per_second")
        if mode in {"steady", "burst", "outage"} and (
            self.duration.total_seconds * 1000
            <= self.reader_lifecycle.backoff_max_ms + 2000
        ):
            raise ValueError("lifecycle_duration_does_not_cover_backoff_recovery")

        if self.tier == "capacity":
            if self.duration.warmup_seconds < 900:
                raise ValueError("capacity_requires_15m_warmup")
            if self.duration.measurement_seconds < 1800:
                raise ValueError("capacity_requires_30m_measurement")
            if self.duration.soak_seconds < 86400:
                raise ValueError("capacity_requires_24h_soak")
        return self


def canonical_profile_bytes(profile: LoadProfile) -> tuple[bytes, str]:
    body = (
        json.dumps(
            profile.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    return body, hashlib.sha256(body).hexdigest()


def validate_comparison_pair(proxy: LoadProfile, direct: LoadProfile) -> None:
    if proxy.workload.endpoint_mode != "proxy":
        raise ValueError("comparison_proxy_profile_has_wrong_endpoint_mode")
    if direct.workload.endpoint_mode != "direct-control":
        raise ValueError("comparison_direct_profile_has_wrong_endpoint_mode")
    proxy_payload = proxy.model_dump(mode="json")
    direct_payload = direct.model_dump(mode="json")
    cast(dict[str, object], proxy_payload["workload"])["endpoint_mode"] = "paired"
    cast(dict[str, object], direct_payload["workload"])["endpoint_mode"] = "paired"
    if proxy_payload != direct_payload:
        raise ValueError("comparison_profiles_differ")


def _write_exclusive_file(path: Path, body: bytes, *, mode: int = 0o640) -> None:
    with path.open("xb") as destination:
        destination.write(body)
        destination.flush()
        os.fsync(destination.fileno())
    path.chmod(mode)


def initialize_run_directory(profile: LoadProfile, destination: Path) -> dict[str, object]:
    profile_body, profile_sha256 = canonical_profile_bytes(profile)
    manifest: dict[str, object] = {
        "schema_version": 1,
        "status": "initialized",
        "profile_sha256": profile_sha256,
        "git_commit": profile.artifacts.git_commit,
        "sut_architecture": profile.sut_architecture,
    }
    manifest_body = (
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")

    destination.mkdir(mode=0o750, parents=False, exist_ok=False)
    destination.chmod(0o750)
    _write_exclusive_file(destination / "profile.json", profile_body)
    _write_exclusive_file(destination / "run-manifest.json", manifest_body)
    return manifest


def _evidence_files(destination: Path) -> dict[str, Path]:
    files: dict[str, Path] = {}
    for candidate in sorted(destination.rglob("*")):
        relative = candidate.relative_to(destination).as_posix()
        if relative == "final-manifest.json":
            continue
        mode = candidate.lstat().st_mode
        if stat.S_ISLNK(mode) or (not stat.S_ISDIR(mode) and not stat.S_ISREG(mode)):
            raise ValueError("evidence_contains_unsafe_file_type")
        if stat.S_ISREG(mode):
            files[relative] = candidate
    return files


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def finalize_run_directory(destination: Path) -> dict[str, object]:
    if (destination / "final-manifest.json").exists():
        raise FileExistsError("run_already_finalized")
    files = _evidence_files(destination)
    required = {
        "profile.json",
        "run-manifest.json",
        "path-catalog.json",
        "launch-plan.json",
    }
    if not required.issubset(files):
        raise ValueError("evidence_required_input_missing")
    if not any(name.startswith("raw/") for name in files):
        raise ValueError("evidence_raw_artifact_missing")
    if not any(name.startswith("summary/") for name in files):
        raise ValueError("evidence_summary_missing")

    initial = json.loads(files["run-manifest.json"].read_text(encoding="utf-8"))
    profile = LoadProfile.model_validate(
        json.loads(files["profile.json"].read_text(encoding="utf-8"))
    )
    profile_sha256, _ = _hash_file(files["profile.json"])
    if initial.get("profile_sha256") != profile_sha256:
        raise ValueError("evidence_profile_digest_mismatch")
    raw_hashes = {
        _hash_file(path)[0]
        for name, path in files.items()
        if name.startswith("raw/")
    }
    generator_summaries: set[str] = set()
    reader_summary_seen = False
    cold_comparison_seen = False
    for name, path in files.items():
        if not name.startswith("summary/") or not name.endswith(".json"):
            continue
        summary = json.loads(path.read_text(encoding="utf-8"))
        if summary.get("valid") is not True:
            raise ValueError("evidence_contains_invalid_summary")
        if isinstance(summary.get("generator_host"), str):
            if summary.get("observations_sha256") not in raw_hashes:
                raise ValueError("generator_summary_raw_digest_missing")
            generator_summaries.add(summary["generator_host"])
        if "expected_concurrent_readers" in summary:
            if summary.get("events_sha256") not in raw_hashes:
                raise ValueError("reader_summary_raw_digest_missing")
            reader_summary_seen = True
        if "proxy_overhead_slo_pass" in summary:
            if summary.get("proxy_events_sha256") not in raw_hashes:
                raise ValueError("cold_comparison_proxy_raw_digest_missing")
            if summary.get("proxy_overhead_slo_pass") is not True:
                raise ValueError("cold_comparison_slo_failed")
            cold_comparison_seen = True
    expected_generators = {host.name for host in profile.generator_hosts}
    if generator_summaries != expected_generators:
        raise ValueError("generator_summary_set_incomplete")
    if profile.workload.total_readers > 0 and not reader_summary_seen:
        raise ValueError("reader_summary_missing")
    if (
        profile.workload.total_readers > 0
        and profile.workload.endpoint_mode == "proxy"
        and profile.workload.session_temperature == "cold"
        and not cold_comparison_seen
    ):
        raise ValueError("cold_comparison_summary_missing")
    file_entries = {
        name: {"sha256": digest, "size_bytes": size}
        for name, path in files.items()
        for digest, size in (_hash_file(path),)
    }
    manifest: dict[str, object] = {
        "schema_version": 1,
        "status": "finalized",
        "profile_sha256": profile_sha256,
        "git_commit": initial.get("git_commit"),
        "sut_architecture": initial.get("sut_architecture"),
        "finalized_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "files": file_entries,
    }
    body = (
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    _write_exclusive_file(destination / "final-manifest.json", body, mode=0o440)
    for path in files.values():
        path.chmod(0o440)
    directories = sorted(
        (path for path in destination.rglob("*") if path.is_dir()),
        key=lambda path: len(path.parts),
        reverse=True,
    )
    for directory in directories:
        directory.chmod(0o550)
    destination.chmod(0o550)
    return manifest


def verify_run_directory(destination: Path) -> dict[str, object]:
    manifest_path = destination / "final-manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise ValueError("final_manifest_missing")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("status") != "finalized" or not isinstance(manifest.get("files"), dict):
        raise ValueError("final_manifest_invalid")
    expected = cast(dict[str, dict[str, object]], manifest["files"])
    observed = _evidence_files(destination)
    if set(expected) != set(observed):
        raise ValueError("evidence_file_set_mismatch")
    for name, path in observed.items():
        digest, size = _hash_file(path)
        if expected[name] != {"sha256": digest, "size_bytes": size}:
            raise ValueError("evidence_digest_mismatch")
    return cast(dict[str, object], manifest)
