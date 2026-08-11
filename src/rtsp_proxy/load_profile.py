from __future__ import annotations

import hashlib
import json
import math
import os
import stat
import tempfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal, Self, cast

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

Architecture = Literal["amd64", "arm64"]
MAX_COLD_PREFLIGHT_PATHS = 512
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
GitCommit = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
SafeName = Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9._-]{1,128}$")]
WARM_ANCHOR_LEAD_MS = 60_000


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)


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
    rtp_mtu_bytes: Annotated[int, Field(ge=256, le=9000)]
    audio: Literal["none", "opus"]

    @model_validator(mode="after")
    def require_absolute_fixture_path(self) -> Self:
        path = PurePosixPath(self.path)
        if not path.is_absolute() or ".." in path.parts:
            raise ValueError("fixture_path_must_be_absolute")
        if self.sha256 == "0" * 64:
            raise ValueError("fixture_placeholder_not_replaced")
        if self.fps > 240:
            raise ValueError("fixture_fps_exceeds_native_limit")
        return self

    @property
    def gop_seconds(self) -> float:
        return self.gop_frames / self.fps


class GeneratorHost(StrictModel):
    name: Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9._-]{1,253}$")]
    architecture: Architecture
    rtsp_host: Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9._-]{1,253}$")]
    rtsp_port: Annotated[int, Field(ge=1, le=65535)]
    source_start: Annotated[int, Field(ge=0)]
    source_count: Annotated[int, Field(gt=0)]


class NetworkProfile(StrictModel):
    profile: Literal["lan", "wan", "chaos"]
    interface: Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9_.:-]{1,15}$")]
    mtu_bytes: Annotated[int, Field(ge=576, le=9216)]
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
        if self.profile != "lan":
            raise ValueError("network_impairment_driver_not_implemented")
        return self


class WorkloadAxes(StrictModel):
    endpoint_mode: Literal["proxy", "direct-control"]
    session_temperature: Literal["warm", "cold"]
    registered_paths: Annotated[int, Field(gt=0)]
    active_sources: Annotated[int, Field(ge=0)]
    total_readers: Annotated[int, Field(ge=0)]
    connect_rate_per_second: Annotated[int, Field(ge=0, le=1000)]
    minimum_rtp_packets_per_second: Annotated[int, Field(ge=0)]
    probe_rate_per_second: Annotated[float, Field(ge=0)]
    crud_rate_per_second: Annotated[float, Field(ge=0)]

    @model_validator(mode="after")
    def keep_axes_physically_possible(self) -> Self:
        if self.registered_paths > 10000:
            raise ValueError("registered_paths_exceed_native_limit")
        if self.active_sources > 10000:
            raise ValueError("active_sources_exceed_native_limit")
        if self.total_readers > 100000:
            raise ValueError("readers_exceed_native_limit")
        if self.active_sources > self.registered_paths:
            raise ValueError("active_sources_exceed_registered_paths")
        if self.total_readers < self.active_sources:
            raise ValueError("readers_below_active_sources")
        if self.active_sources == 0 and self.total_readers != 0:
            raise ValueError("readers_require_active_sources")
        if self.session_temperature == "cold" and self.total_readers != self.active_sources:
            raise ValueError("cold_requires_one_reader_per_active_source")
        if (self.total_readers == 0) != (self.minimum_rtp_packets_per_second == 0):
            raise ValueError("rtp_packet_rate_must_match_reader_presence")
        if self.probe_rate_per_second != 0 or self.crud_rate_per_second != 0:
            raise ValueError("probe_crud_drivers_not_implemented")
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
    maximum_clock_error_ms: Annotated[float, Field(gt=0, le=1000)]
    maximum_start_lateness_ms: Annotated[float, Field(gt=0, le=5000)]


class RunDuration(StrictModel):
    warmup_seconds: Annotated[int, Field(ge=0)]
    measurement_seconds: Annotated[int, Field(gt=0)]
    soak_seconds: Annotated[int, Field(ge=0)]

    @property
    def total_seconds(self) -> int:
        return self.warmup_seconds + self.measurement_seconds + self.soak_seconds

    @model_validator(mode="after")
    def enforce_native_duration_limit(self) -> Self:
        if self.total_seconds > 172800:
            raise ValueError("duration_exceeds_native_limit")
        return self


class LoadProfile(StrictModel):
    schema_version: Literal[1]
    tier: Literal["smoke", "nightly", "capacity"]
    seed: Annotated[int, Field(ge=0, le=2147483647)]
    comparison_id: SafeName
    sut_architecture: Architecture
    # Phase 0B source listeners are IPv4-only. Accepting an IPv6 literal here
    # would create a prepared run that the native source process cannot execute.
    sut_rtsp_host: Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9._-]{1,253}$")]
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
        if self.fixture.rtp_mtu_bytes > self.network.mtu_bytes - 40:
            raise ValueError("rtp_mtu_exceeds_network_payload_budget")
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
        if self.workload.session_temperature == "cold" and mode != "single":
            raise ValueError("cold_requires_single_lifecycle")
        if (
            self.workload.session_temperature == "cold"
            and self.workload.active_sources > MAX_COLD_PREFLIGHT_PATHS
        ):
            raise ValueError("cold_preflight_path_count_exceeds_safety_cap")
        if (
            self.workload.session_temperature == "warm"
            and self.workload.total_readers > 0
            and self.workload.total_readers <= self.workload.active_sources
        ):
            raise ValueError("warm_requires_anchor_and_measured_readers")
        if mode == "steady" and rate != self.reader_lifecycle.disconnect_rate_per_second:
            raise ValueError("steady_connect_disconnect_rates_differ")
        if mode == "ramp" and rate != 100:
            raise ValueError("ramp_requires_100_readers_per_second")
        if mode == "burst" and rate != 1000:
            raise ValueError("burst_requires_1000_readers_per_second")
        warm_anchors = (
            self.workload.active_sources
            if self.workload.session_temperature == "warm" and self.workload.total_readers > 0
            else 0
        )
        if mode == "burst" and self.workload.total_readers - warm_anchors < 1000:
            raise ValueError("burst_requires_at_least_1000_readers")
        if (
            mode == "outage"
            and self.workload.total_readers * self.reader_lifecycle.outage_percent % 100 != 0
        ):
            raise ValueError("outage_cohort_not_exactly_representable")
        if mode in {"steady", "burst", "outage"} and (
            self.duration.total_seconds * 1000 <= self.reader_lifecycle.backoff_max_ms + 2000
        ):
            raise ValueError("lifecycle_duration_does_not_cover_backoff_recovery")
        if mode in {"steady", "outage"} and (
            self.duration.total_seconds * 1000
            <= math.ceil(self.fixture.gop_seconds * 1000)
            + 5000
            + self.reader_lifecycle.backoff_max_ms
        ):
            raise ValueError("lifecycle_window_does_not_cover_ready_budget_and_backoff")
        if mode in {"steady", "outage"} and (
            self.duration.warmup_seconds * 1000 < math.ceil(self.fixture.gop_seconds * 1000) + 5000
        ):
            raise ValueError("lifecycle_warmup_does_not_cover_decodable_ready_budget")

        if self.tier == "capacity":
            if self.workload.total_readers == 0:
                raise ValueError("capacity_requires_reader_load")
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


def initial_ramp_milliseconds(profile: LoadProfile) -> int:
    rate = profile.workload.connect_rate_per_second
    measured_readers = profile.workload.total_readers - warm_anchor_reader_count(profile)
    return (
        0 if rate == 0 or measured_readers < 2 else math.ceil((measured_readers - 1) * 1000 / rate)
    )


def warm_anchor_reader_count(profile: LoadProfile) -> int:
    if profile.workload.session_temperature != "warm":
        return 0
    return profile.workload.active_sources


def warm_anchor_start_unix_ms(profile: LoadProfile, coordinated_start_unix_ms: int) -> int:
    if warm_anchor_reader_count(profile) == 0:
        return coordinated_start_unix_ms
    return coordinated_start_unix_ms - WARM_ANCHOR_LEAD_MS


def ramp_end_unix_ms(profile: LoadProfile, coordinated_start_unix_ms: int) -> int:
    return coordinated_start_unix_ms + initial_ramp_milliseconds(profile)


def measurement_start_unix_ms(profile: LoadProfile, coordinated_start_unix_ms: int) -> int:
    return ramp_end_unix_ms(profile, coordinated_start_unix_ms) + (
        profile.duration.warmup_seconds * 1000
    )


def measurement_end_unix_ms(profile: LoadProfile, coordinated_start_unix_ms: int) -> int:
    return measurement_start_unix_ms(profile, coordinated_start_unix_ms) + (
        profile.duration.measurement_seconds * 1000
    )


def lifecycle_start_unix_ms(profile: LoadProfile, coordinated_start_unix_ms: int) -> int:
    """Start injected lifecycle work at the measured-window boundary."""
    return measurement_start_unix_ms(profile, coordinated_start_unix_ms)


def workload_end_unix_ms(profile: LoadProfile, coordinated_start_unix_ms: int) -> int:
    return measurement_end_unix_ms(profile, coordinated_start_unix_ms) + (
        profile.duration.soak_seconds * 1000
    )


def evidence_grace_seconds(profile: LoadProfile) -> int:
    """Keep reader PIDs observable after workload teardown until sampling is complete."""
    return math.ceil(profile.evidence_sampling.interval_seconds * 2) + 5


def generator_sampling_end_unix_ms(profile: LoadProfile, coordinated_start_unix_ms: int) -> int:
    post_workload_sample_ms = math.ceil((profile.evidence_sampling.interval_seconds + 2) * 1000)
    return workload_end_unix_ms(profile, coordinated_start_unix_ms) + post_workload_sample_ms


def sut_sampling_end_unix_ms(profile: LoadProfile, coordinated_start_unix_ms: int) -> int:
    """Cover the pinned 10s on-demand close timer and a final sampler interval."""
    return (
        workload_end_unix_ms(profile, coordinated_start_unix_ms)
        + 30_000
        + math.ceil((profile.evidence_sampling.interval_seconds + 2) * 1000)
    )


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


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publish_completion_marker(path: Path, body: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.parent.name}.final-manifest-", dir=path.parent.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(body)
            destination.flush()
            os.fsync(destination.fileno())
        temporary.chmod(0o440)
        os.link(temporary, path)
        _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


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
    from rtsp_proxy.load_catalog import (
        validate_cold_preflight_payload,
        validate_warm_preflight_payload,
    )
    from rtsp_proxy.load_evidence import (
        GeneratorHeadroomSummary,
        SutCapacitySummary,
        load_observations,
        load_sut_observations,
        summarize_generator_headroom,
        summarize_sut_capacity,
    )
    from rtsp_proxy.load_results import (
        ColdComparisonSummary,
        ReaderRunCompletedEvent,
        ReaderRunSummary,
        load_reader_events,
        summarize_cold_comparison,
        summarize_reader_events,
    )
    from rtsp_proxy.load_run import validate_prepared_run_directory

    final_manifest_path = destination / "final-manifest.json"
    files = _evidence_files(destination)
    required = {
        "profile.json",
        "run-manifest.json",
        "fixture-manifest.json",
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
    expected_initial = {
        "schema_version": 1,
        "status": "initialized",
        "profile_sha256": profile_sha256,
        "git_commit": profile.artifacts.git_commit,
        "sut_architecture": profile.sut_architecture,
    }
    if initial != expected_initial:
        raise ValueError("evidence_initial_manifest_binding_invalid")
    prepared_launch = validate_prepared_run_directory(destination, profile)

    expected_summary_names = {
        f"summary/generator-{host.name}.json" for host in profile.generator_hosts
    }
    if profile.tier == "capacity":
        expected_summary_names.add("summary/sut.json")
    reader_events_path = destination / "raw" / "readers.jsonl"
    if profile.workload.total_readers > 0:
        expected_summary_names.add("summary/readers.json")
    cold_required = (
        profile.workload.total_readers > 0
        and profile.workload.endpoint_mode == "proxy"
        and profile.workload.session_temperature == "cold"
    )
    if cold_required:
        expected_summary_names.add("summary/cold-comparison.json")
        cold_preflight_name = "raw/cold-preflight.json"
        if cold_preflight_name not in files:
            raise ValueError("cold_preflight_evidence_missing")
        cold_preflight = json.loads(files[cold_preflight_name].read_text(encoding="utf-8"))
        if not isinstance(cold_preflight, dict):
            raise ValueError("cold_preflight_evidence_invalid")
        validate_cold_preflight_payload(
            profile,
            cold_preflight,
            scheduled_start_unix_ms=prepared_launch["coordinated_start_unix_ms"],
        )
    warm_required = (
        profile.workload.total_readers > 0
        and profile.workload.endpoint_mode == "proxy"
        and profile.workload.session_temperature == "warm"
    )
    if warm_required:
        warm_preflight_name = "raw/warm-preflight.json"
        if warm_preflight_name not in files:
            raise ValueError("warm_preflight_evidence_missing")
        warm_preflight = json.loads(files[warm_preflight_name].read_text(encoding="utf-8"))
        if not isinstance(warm_preflight, dict):
            raise ValueError("warm_preflight_evidence_invalid")
        validate_warm_preflight_payload(
            profile,
            warm_preflight,
            scheduled_start_unix_ms=prepared_launch["coordinated_start_unix_ms"],
        )
    observed_summary_names = {name for name in files if name.startswith("summary/")}
    if observed_summary_names != expected_summary_names:
        raise ValueError("evidence_summary_set_invalid")

    completions: tuple[ReaderRunCompletedEvent, ...] = ()
    if profile.workload.total_readers > 0:
        expected_reader_summary = summarize_reader_events(profile, reader_events_path)
        stored_reader_summary = ReaderRunSummary.model_validate_json(
            files["summary/readers.json"].read_text(encoding="utf-8")
        )
        if stored_reader_summary != expected_reader_summary or not stored_reader_summary.valid:
            raise ValueError("reader_summary_not_reproducible_or_invalid")
        completions = tuple(
            event
            for event in load_reader_events(reader_events_path)
            if isinstance(event, ReaderRunCompletedEvent)
        )
        if any(
            item.scheduled_start_unix_ms != prepared_launch["coordinated_start_unix_ms"]
            for item in completions
        ):
            raise ValueError("reader_completion_start_not_bound_to_launch")

    generator_machine_ids: set[str] = set()
    for host in profile.generator_hosts:
        raw_name = f"raw/generator-{host.name}.jsonl"
        summary_name = f"summary/generator-{host.name}.json"
        if raw_name not in files:
            raise ValueError("generator_raw_evidence_missing")
        observations = load_observations(files[raw_name])
        expected_generator_summary = summarize_generator_headroom(
            observations,
            expected_generator_host=host.name,
            minimum_duration_seconds=profile.duration.measurement_seconds,
            expected_interval_seconds=profile.evidence_sampling.interval_seconds,
            maximum_gap_factor=profile.evidence_sampling.maximum_gap_factor,
            observations_sha256=_hash_file(files[raw_name])[0],
            capacity_gate=profile.tier == "capacity",
            measurement_start_unix_ms=prepared_launch["coordinated_measurement_start_unix_ms"],
            measurement_end_unix_ms=prepared_launch["coordinated_measurement_end_unix_ms"],
            soak_end_unix_ms=prepared_launch["coordinated_workload_end_unix_ms"],
        )
        stored_generator_summary = GeneratorHeadroomSummary.model_validate_json(
            files[summary_name].read_text(encoding="utf-8")
        )
        if (
            stored_generator_summary != expected_generator_summary
            or not stored_generator_summary.valid
            or stored_generator_summary.interface_mtu_bytes != profile.network.mtu_bytes
        ):
            raise ValueError("generator_summary_not_reproducible_or_invalid")
        expected_process_count = sum(
            item.get("generator_host") == host.name
            for category in ("source_servers", "readers")
            for item in prepared_launch[category]
        )
        expected_process_digests = sorted(
            [
                profile.artifacts.pull_server_sha256
                for item in prepared_launch["source_servers"]
                if item.get("generator_host") == host.name
            ]
            + [
                profile.artifacts.load_reader_sha256
                for item in prepared_launch["readers"]
                if item.get("generator_host") == host.name
            ]
        )
        observed_process_digests = sorted(
            item.executable_sha256 for item in stored_generator_summary.workload_processes
        )
        if (
            stored_generator_summary.process_count != expected_process_count
            or observed_process_digests != expected_process_digests
        ):
            raise ValueError("generator_workload_process_count_mismatch")
        generator_machine_ids.add(stored_generator_summary.machine_id_sha256)
        first_sample_ms = int(datetime.fromisoformat(observations[0].timestamp).timestamp() * 1000)
        last_sample_ms = int(datetime.fromisoformat(observations[-1].timestamp).timestamp() * 1000)
        if (
            first_sample_ms > prepared_launch["coordinated_anchor_start_unix_ms"]
            or last_sample_ms < prepared_launch["coordinated_workload_end_unix_ms"]
        ):
            raise ValueError("generator_observation_window_does_not_cover_load")
    if profile.tier == "capacity" and len(generator_machine_ids) != len(profile.generator_hosts):
        raise ValueError("capacity_generator_machine_id_not_unique")

    if profile.tier == "capacity":
        sut_raw_name = "raw/sut.jsonl"
        sut_summary_name = "summary/sut.json"
        if sut_raw_name not in files:
            raise ValueError("sut_raw_evidence_missing")
        sut_observations = load_sut_observations(files[sut_raw_name])
        expected_sut_summary = summarize_sut_capacity(
            sut_observations,
            expected_sut_host=profile.sut_rtsp_host,
            expected_interval_seconds=profile.evidence_sampling.interval_seconds,
            maximum_gap_factor=profile.evidence_sampling.maximum_gap_factor,
            observations_sha256=_hash_file(files[sut_raw_name])[0],
            measurement_start_unix_ms=prepared_launch["coordinated_measurement_start_unix_ms"],
            measurement_end_unix_ms=prepared_launch["coordinated_measurement_end_unix_ms"],
            soak_end_unix_ms=prepared_launch["coordinated_workload_end_unix_ms"],
            maximum_clock_error_ms=profile.evidence_sampling.maximum_clock_error_ms,
        )
        stored_sut_summary = SutCapacitySummary.model_validate_json(
            files[sut_summary_name].read_text(encoding="utf-8")
        )
        if (
            stored_sut_summary != expected_sut_summary
            or not stored_sut_summary.valid
            or stored_sut_summary.resource_summary.interface_mtu_bytes != profile.network.mtu_bytes
            or stored_sut_summary.resource_summary.process_count != 1
            or tuple(
                item.executable_sha256
                for item in stored_sut_summary.resource_summary.workload_processes
            )
            != (profile.artifacts.mediamtx_sha256,)
            or stored_sut_summary.resource_summary.machine_id_sha256 in generator_machine_ids
        ):
            raise ValueError("sut_summary_not_reproducible_or_invalid")
        first_sut_sample_ms = int(
            datetime.fromisoformat(sut_observations[0].timestamp).timestamp() * 1000
        )
        last_sut_sample_ms = int(
            datetime.fromisoformat(sut_observations[-1].timestamp).timestamp() * 1000
        )
        if first_sut_sample_ms > prepared_launch[
            "coordinated_anchor_start_unix_ms"
        ] or last_sut_sample_ms < sut_sampling_end_unix_ms(
            profile, prepared_launch["coordinated_start_unix_ms"]
        ):
            raise ValueError("sut_observation_window_does_not_cover_load")

    if cold_required:
        reference_profile_path = destination / "reference" / "direct-profile.json"
        reference_events_path = destination / "reference" / "direct-readers.jsonl"
        reference_manifest_path = destination / "reference" / "direct-final-manifest.json"
        reference_manifest = json.loads(reference_manifest_path.read_text(encoding="utf-8"))
        reference_files = reference_manifest.get("files")
        reference_profile_sha256, reference_profile_size = _hash_file(reference_profile_path)
        reference_events_sha256, reference_events_size = _hash_file(reference_events_path)
        if (
            reference_manifest.get("status") != "finalized"
            or not isinstance(reference_files, dict)
            or reference_files.get("profile.json", {}).get("sha256") != reference_profile_sha256
            or reference_files.get("profile.json", {}).get("size_bytes") != reference_profile_size
            or reference_files.get("raw/readers.jsonl", {}).get("sha256") != reference_events_sha256
            or reference_files.get("raw/readers.jsonl", {}).get("size_bytes")
            != reference_events_size
        ):
            raise ValueError("direct_reference_manifest_binding_invalid")
        direct_profile = LoadProfile.model_validate_json(
            reference_profile_path.read_text(encoding="utf-8")
        )
        expected_cold = summarize_cold_comparison(
            profile,
            reader_events_path,
            direct_profile,
            reference_events_path,
            direct_final_manifest_sha256=_hash_file(reference_manifest_path)[0],
        )
        stored_cold = ColdComparisonSummary.model_validate_json(
            files["summary/cold-comparison.json"].read_text(encoding="utf-8")
        )
        if stored_cold != expected_cold or not stored_cold.valid:
            raise ValueError("cold_comparison_not_reproducible_or_invalid")
    file_entries = {
        name: {"sha256": digest, "size_bytes": size}
        for name, path in files.items()
        for digest, size in (_hash_file(path),)
    }
    manifest: dict[str, object] = {
        "schema_version": 1,
        "status": "finalized",
        "profile_sha256": profile_sha256,
        "git_commit": profile.artifacts.git_commit,
        "sut_architecture": profile.sut_architecture,
        "finalized_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "files": file_entries,
    }
    body = (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    for path in files.values():
        path.chmod(0o440)
    directories = sorted(
        (path for path in destination.rglob("*") if path.is_dir()),
        key=lambda path: len(path.parts),
        reverse=True,
    )
    for directory in directories:
        directory.chmod(0o550)
    if final_manifest_path.exists():
        if final_manifest_path.is_symlink() or not final_manifest_path.is_file():
            raise ValueError("final_manifest_invalid")
        try:
            existing = json.loads(final_manifest_path.read_text(encoding="utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            # A pre-existing non-JSON regular marker can only be an interrupted
            # publication from an older finalizer. It is not completion evidence.
            final_manifest_path.unlink()
            _fsync_directory(destination)
            existing = None
        if existing is None:
            _publish_completion_marker(final_manifest_path, body)
            final_manifest_path.chmod(0o440)
            destination.chmod(0o550)
            return manifest
        if not isinstance(existing, dict):
            raise ValueError("final_manifest_invalid")
        existing_finalized_at = existing.get("finalized_at")
        if not isinstance(existing_finalized_at, str):
            raise ValueError("final_manifest_invalid")
        try:
            datetime.fromisoformat(existing_finalized_at)
        except ValueError as error:
            raise ValueError("final_manifest_invalid") from error
        manifest["finalized_at"] = existing_finalized_at
        if existing != manifest:
            raise ValueError("final_manifest_content_mismatch")
        final_manifest_path.chmod(0o440)
    else:
        _publish_completion_marker(final_manifest_path, body)
    destination.chmod(0o550)
    return manifest


def verify_run_directory(destination: Path) -> dict[str, object]:
    manifest_path = destination / "final-manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise ValueError("final_manifest_missing")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if (
        set(manifest)
        != {
            "schema_version",
            "status",
            "profile_sha256",
            "git_commit",
            "sut_architecture",
            "finalized_at",
            "files",
        }
        or manifest.get("schema_version") != 1
        or manifest.get("status") != "finalized"
        or not isinstance(manifest.get("files"), dict)
        or not isinstance(manifest.get("finalized_at"), str)
    ):
        raise ValueError("final_manifest_invalid")
    try:
        datetime.fromisoformat(cast(str, manifest["finalized_at"]))
    except ValueError as error:
        raise ValueError("final_manifest_invalid") from error
    expected = cast(dict[str, dict[str, object]], manifest["files"])
    observed = _evidence_files(destination)
    if set(expected) != set(observed):
        raise ValueError("evidence_file_set_mismatch")
    for name, path in observed.items():
        digest, size = _hash_file(path)
        if expected[name] != {"sha256": digest, "size_bytes": size}:
            raise ValueError("evidence_digest_mismatch")
        if stat.S_IMODE(path.stat().st_mode) != 0o440:
            raise ValueError("evidence_file_mode_invalid")
    if stat.S_IMODE(manifest_path.stat().st_mode) != 0o440:
        raise ValueError("evidence_file_mode_invalid")
    directories = [destination, *(path for path in destination.rglob("*") if path.is_dir())]
    if any(stat.S_IMODE(path.stat().st_mode) != 0o550 for path in directories):
        raise ValueError("evidence_directory_mode_invalid")
    return cast(dict[str, object], manifest)
