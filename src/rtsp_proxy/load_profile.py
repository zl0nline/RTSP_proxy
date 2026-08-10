from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

Architecture = Literal["amd64", "arm64"]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
GitCommit = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ArtifactPins(StrictModel):
    git_commit: GitCommit
    mediamtx_version: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    mediamtx_sha256: Sha256
    ffmpeg_version: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    ffmpeg_sha256: Sha256
    ffprobe_sha256: Sha256
    gstreamer_version: Annotated[str, StringConstraints(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")]
    gstreamer_build_id: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    pull_server_sha256: Sha256


class FixtureProfile(StrictModel):
    source_mode: Literal["rtsp-pull"]
    path: str
    sha256: Sha256
    codec: Literal["h264", "h265"]
    bitrate_bps: Annotated[int, Field(gt=0)]
    fps: Annotated[int, Field(gt=0)]
    gop_frames: Annotated[int, Field(gt=0)]
    audio: Literal["none", "opus", "aac"]

    @model_validator(mode="after")
    def require_absolute_fixture_path(self) -> Self:
        path = PurePosixPath(self.path)
        if not path.is_absolute() or ".." in path.parts:
            raise ValueError("fixture_path_must_be_absolute")
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
    registered_paths: Annotated[int, Field(gt=0)]
    active_sources: Annotated[int, Field(ge=0)]
    total_readers: Annotated[int, Field(ge=0)]
    connect_rate_per_second: Annotated[float, Field(ge=0)]
    probe_rate_per_second: Annotated[float, Field(ge=0)]
    crud_rate_per_second: Annotated[float, Field(ge=0)]

    @model_validator(mode="after")
    def keep_axes_physically_possible(self) -> Self:
        if self.active_sources > self.registered_paths:
            raise ValueError("active_sources_exceed_registered_paths")
        if self.total_readers < self.active_sources:
            raise ValueError("readers_below_active_sources")
        return self


class RunDuration(StrictModel):
    warmup_seconds: Annotated[int, Field(ge=0)]
    measurement_seconds: Annotated[int, Field(gt=0)]
    soak_seconds: Annotated[int, Field(ge=0)]


class LoadProfile(StrictModel):
    schema_version: Literal[1]
    tier: Literal["smoke", "nightly", "capacity"]
    seed: Annotated[int, Field(ge=0)]
    sut_architecture: Architecture
    artifacts: ArtifactPins
    fixture: FixtureProfile
    generator_hosts: Annotated[tuple[GeneratorHost, ...], Field(min_length=1)]
    network: NetworkProfile
    workload: WorkloadAxes
    duration: RunDuration

    @model_validator(mode="after")
    def validate_cross_field_contract(self) -> Self:
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


def _write_immutable_file(path: Path, body: bytes) -> None:
    with path.open("xb") as destination:
        destination.write(body)
        destination.flush()
        os.fsync(destination.fileno())
    path.chmod(0o640)


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
    _write_immutable_file(destination / "profile.json", profile_body)
    _write_immutable_file(destination / "run-manifest.json", manifest_body)
    return manifest
