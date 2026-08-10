from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from rtsp_proxy.load_catalog import (
    ReaderPlan,
    build_direct_reader_plan,
    build_proxy_reader_plan,
)
from rtsp_proxy.load_profile import (
    LoadProfile,
    canonical_profile_bytes,
    validate_comparison_pair,
)

LatencyGate = Literal[
    "warm_proxy_p99",
    "requires_direct_control_decomposition",
    "direct_control_reference",
]
EventName = Literal[
    "reader_started",
    "play_sent",
    "first_decodable_frame",
    "reader_error",
    "reader_disconnected",
    "reconnect_scheduled",
]


class ReaderEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    event: EventName
    reader_id: Annotated[int, Field(ge=0, lt=100000)]
    cycle: Annotated[int, Field(ge=0, le=1000000)]
    path: Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9_.:-]{1,128}$")]
    at_monotonic_ms: Annotated[float, Field(ge=0)]
    at_unix_ms: Annotated[int, Field(ge=0)] | None = None
    describe_to_play_ms: Annotated[float, Field(ge=0)] | None = None
    describe_to_first_decodable_ms: Annotated[float, Field(ge=0)] | None = None
    play_to_first_decodable_ms: Annotated[float, Field(ge=0)] | None = None
    backoff_ms: Annotated[float, Field(ge=0)] | None = None
    injected: bool | None = None
    reason: Literal["gstreamer_error", "unexpected_eos", "state_change_failure"] | None = None

    @model_validator(mode="after")
    def validate_event_shape(self) -> Self:
        populated = {
            "at_unix_ms": self.at_unix_ms,
            "describe_to_play_ms": self.describe_to_play_ms,
            "describe_to_first_decodable_ms": self.describe_to_first_decodable_ms,
            "play_to_first_decodable_ms": self.play_to_first_decodable_ms,
            "backoff_ms": self.backoff_ms,
            "injected": self.injected,
            "reason": self.reason,
        }
        expected: set[str]
        if self.event == "play_sent":
            expected = {"describe_to_play_ms"}
        elif self.event == "first_decodable_frame":
            expected = {
                "describe_to_first_decodable_ms",
                "play_to_first_decodable_ms",
            }
        elif self.event == "reader_error":
            expected = {"reason"}
        elif self.event == "reader_disconnected":
            expected = {"injected"}
        elif self.event == "reconnect_scheduled":
            expected = {"backoff_ms"}
        else:
            expected = {"at_unix_ms"} if self.event == "reader_started" else set()
        actual = {name for name, value in populated.items() if value is not None}
        if actual != expected:
            raise ValueError("invalid_reader_event_shape")
        return self


class ReaderRunCompletedEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    event: Literal["run_completed"]
    at_monotonic_ms: Annotated[float, Field(ge=0)]
    started_readers: Annotated[int, Field(ge=0, le=100000)]
    ready_readers: Annotated[int, Field(ge=0, le=100000)]
    failed_attempts: Annotated[int, Field(ge=0)]
    normal_completion: bool
    interrupted: bool
    lifecycle_complete: bool
    exit_code: Annotated[int, Field(ge=0, le=255)]
    schedule_shard_index: Annotated[int, Field(ge=0, lt=10000)]
    schedule_shards: Annotated[int, Field(gt=0, le=10000)]
    generator_host: Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9._-]{1,253}$")]
    profile_sha256: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
    reader_plan_sha256: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
    scheduled_start_unix_ms: Annotated[int, Field(gt=0)]
    process_start_unix_ms: Annotated[int, Field(gt=0)]
    process_end_unix_ms: Annotated[int, Field(gt=0)]
    clock_synchronized: bool
    clock_max_error_ms: Annotated[float, Field(ge=0)]
    rtp_packets: Annotated[int, Field(ge=0)]

    @model_validator(mode="after")
    def validate_process_window(self) -> Self:
        if self.process_end_unix_ms <= self.process_start_unix_ms:
            raise ValueError("reader_process_window_invalid")
        return self


class ReaderRunSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    expected_concurrent_readers: int
    events_sha256: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
    establishment_attempts: int
    decodable_establishments: int
    failed_establishments: int
    observed_rtp_packets: int
    observed_rtp_packets_per_second: float
    minimum_rtp_packets_per_second: int
    packet_rate_slo_pass: bool
    establishment_success_percent: float
    describe_to_play_p50_ms: float | None
    describe_to_play_p95_ms: float | None
    describe_to_play_p99_ms: float | None
    first_decodable_p50_ms: float | None
    first_decodable_p95_ms: float | None
    first_decodable_p99_ms: float | None
    latency_slo_ms: float | None
    latency_slo_pass: bool | None
    latency_gate: LatencyGate
    valid: bool
    invalid_reasons: tuple[str, ...]


class ColdComparisonSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    comparison_id: str
    proxy_events_sha256: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
    direct_events_sha256: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
    direct_final_manifest_sha256: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
    compared_establishments: int
    proxy_overhead_p50_ms: float
    proxy_overhead_p95_ms: float
    proxy_overhead_p99_ms: float
    direct_wait_for_decodable_p99_ms: float
    proxy_wait_for_decodable_p99_ms: float
    proxy_overhead_slo_ms: float
    proxy_overhead_slo_pass: bool
    valid: bool
    invalid_reasons: tuple[str, ...]


def _nearest_rank(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[math.ceil(percentile * len(ordered)) - 1]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


RawReaderEvent = ReaderEvent | ReaderRunCompletedEvent


def _load_reader_events(path: Path) -> tuple[RawReaderEvent, ...]:
    events: list[RawReaderEvent] = []
    with path.open(encoding="utf-8") as source:
        for line in source:
            if not line.strip():
                raise ValueError("blank_reader_event_line")
            payload = json.loads(line)
            if payload.get("event") == "run_completed":
                events.append(ReaderRunCompletedEvent.model_validate(payload))
            else:
                events.append(ReaderEvent.model_validate(payload))
    if not events:
        raise ValueError("reader_events_empty")
    return tuple(events)


def load_reader_events(path: Path) -> tuple[RawReaderEvent, ...]:
    return _load_reader_events(path)


def merge_reader_event_files(paths: tuple[Path, ...], destination: Path) -> int:
    if not paths:
        raise ValueError("reader_event_inputs_empty")
    events = [event for path in paths for event in _load_reader_events(path)]
    event_order = {
        "reader_started": 0,
        "play_sent": 1,
        "first_decodable_frame": 2,
        "reader_error": 3,
        "reader_disconnected": 4,
        "reconnect_scheduled": 5,
        "run_completed": 6,
    }
    events.sort(
        key=lambda event: (
            event.reader_id if isinstance(event, ReaderEvent) else 100000,
            event.cycle if isinstance(event, ReaderEvent) else event.schedule_shard_index,
            event_order[event.event],
        ),
    )
    identities = [
        (event.reader_id, event.cycle, event.event)
        for event in events
        if isinstance(event, ReaderEvent)
    ]
    if len(identities) != len(set(identities)):
        raise ValueError("duplicate_reader_event_across_inputs")
    completion_shards = [
        event.schedule_shard_index for event in events if isinstance(event, ReaderRunCompletedEvent)
    ]
    if len(completion_shards) != len(set(completion_shards)):
        raise ValueError("duplicate_reader_completion_across_inputs")
    with destination.open("x", encoding="utf-8") as output:
        destination.chmod(0o640)
        for event in events:
            output.write(json.dumps(event.model_dump(mode="json"), sort_keys=True) + "\n")
        output.flush()
        os.fsync(output.fileno())
    return len(events)


def _event_maps(
    profile: LoadProfile, path: Path
) -> tuple[
    tuple[ReaderEvent, ...],
    tuple[ReaderRunCompletedEvent, ...],
    set[tuple[int, int]],
    dict[tuple[int, int], float],
    dict[tuple[int, int], tuple[float, float]],
    set[tuple[int, int]],
]:
    raw_events = _load_reader_events(path)
    events = tuple(event for event in raw_events if isinstance(event, ReaderEvent))
    completions = tuple(event for event in raw_events if isinstance(event, ReaderRunCompletedEvent))
    starts: set[tuple[int, int]] = set()
    plays: dict[tuple[int, int], float] = {}
    frames: dict[tuple[int, int], tuple[float, float]] = {}
    failures: set[tuple[int, int]] = set()
    seen_events: set[tuple[int, int, str]] = set()
    for event in events:
        if event.reader_id >= profile.workload.total_readers:
            raise ValueError("reader_event_id_out_of_range")
        key = (event.reader_id, event.cycle)
        event_key = (*key, event.event)
        if event_key in seen_events:
            raise ValueError("duplicate_reader_event")
        seen_events.add(event_key)
        if event.event == "reader_started":
            starts.add(key)
        elif event.event == "play_sent":
            assert event.describe_to_play_ms is not None
            plays[key] = event.describe_to_play_ms
        elif event.event == "first_decodable_frame":
            assert event.describe_to_first_decodable_ms is not None
            assert event.play_to_first_decodable_ms is not None
            frames[key] = (
                event.describe_to_first_decodable_ms,
                event.play_to_first_decodable_ms,
            )
        elif event.event == "reader_error":
            failures.add(key)
    if not starts:
        raise ValueError("reader_start_events_missing")
    if not set(plays).issubset(starts) or not set(frames).issubset(starts):
        raise ValueError("reader_event_without_start")
    return events, completions, starts, plays, frames, failures


def _plan_body_sha256(plan: ReaderPlan) -> str:
    targets = plan.targets
    body = "".join(
        f"{target.path}\t{target.reader_count}\t{target.reader_id_start}\n" for target in targets
    ).encode("ascii")
    return hashlib.sha256(body).hexdigest()


def _expected_reader_contract(
    profile: LoadProfile,
) -> tuple[dict[int, str], dict[str, tuple[int, str]]]:
    expected_paths: dict[int, str] = {}
    shard_contract: dict[str, tuple[int, str]] = {}
    plans = []
    for host in profile.generator_hosts:
        plan = (
            build_proxy_reader_plan(profile, host.name)
            if profile.workload.endpoint_mode == "proxy"
            else build_direct_reader_plan(profile, host.name)
        )
        if plan.targets:
            plans.append((host.name, plan))
    for shard_index, (host_name, plan) in enumerate(plans):
        shard_contract[host_name] = (shard_index, _plan_body_sha256(plan))
        for target in plan.targets:
            for reader_id in range(
                target.reader_id_start,
                target.reader_id_start + target.reader_count,
            ):
                if reader_id in expected_paths:
                    raise ValueError("reader_plan_duplicate_global_id")
                expected_paths[reader_id] = target.path
    return expected_paths, shard_contract


def summarize_reader_events(profile: LoadProfile, path: Path) -> ReaderRunSummary:
    events, completions, starts, plays, frames, failures = _event_maps(profile, path)
    handshake_latencies = list(plays.values())
    frame_latencies = [value[0] for value in frames.values()]
    success_percent = len(frames) / len(starts) * 100
    reasons: list[str] = []
    expected_paths, shard_contract = _expected_reader_contract(profile)
    if any(expected_paths.get(event.reader_id) != event.path for event in events):
        reasons.append("reader_path_plan_mismatch")
    if success_percent < 99.9:
        reasons.append("session_establishment_below_99_9_percent")
    if failures:
        reasons.append("reader_errors_observed")
    initial_starts = sorted(
        (event for event in events if event.event == "reader_started" and event.cycle == 0),
        key=lambda event: event.reader_id,
    )
    if {event.reader_id for event in initial_starts} != set(range(profile.workload.total_readers)):
        reasons.append("initial_reader_set_incomplete")
    if any(event.event == "reader_disconnected" and event.injected is False for event in events):
        reasons.append("unexpected_healthy_disconnect")
    expected_shards = len(shard_contract)
    completion_indices = {item.schedule_shard_index for item in completions}
    scheduled_starts = {item.scheduled_start_unix_ms for item in completions}
    profile_sha256 = canonical_profile_bytes(profile)[1]
    completion_valid = (
        len(completions) == expected_shards
        and completion_indices == set(range(expected_shards))
        and all(item.schedule_shards == expected_shards for item in completions)
        and all(
            item.normal_completion
            and not item.interrupted
            and item.lifecycle_complete
            and item.exit_code == 0
            for item in completions
        )
        and sum(item.started_readers for item in completions) == profile.workload.total_readers
        and sum(item.ready_readers for item in completions) == profile.workload.total_readers
        and len(scheduled_starts) == 1
        and all(
            item.generator_host in shard_contract
            and shard_contract[item.generator_host]
            == (item.schedule_shard_index, item.reader_plan_sha256)
            and item.profile_sha256 == profile_sha256
            and item.clock_synchronized
            and item.clock_max_error_ms <= profile.evidence_sampling.maximum_clock_error_ms
            and item.process_start_unix_ms <= item.scheduled_start_unix_ms
            for item in completions
        )
    )
    if not completion_valid:
        reasons.append("reader_process_completion_missing_or_invalid")

    if len(scheduled_starts) == 1:
        schedule_start = next(iter(scheduled_starts))
        rate = profile.workload.connect_rate_per_second
        tolerance = profile.evidence_sampling.maximum_clock_error_ms + 5
        for event in initial_starts:
            assert event.at_unix_ms is not None
            expected_at = (
                schedule_start if rate == 0 else schedule_start + (event.reader_id * 1000 / rate)
            )
            if event.at_unix_ms + tolerance < expected_at:
                reasons.append("initial_connect_rate_exceeded")
                break
        if rate > 0 and len(initial_starts) > 1:
            actual_starts = sorted(
                event.at_unix_ms for event in initial_starts if event.at_unix_ms is not None
            )
            window = min(rate, len(actual_starts) - 1)
            minimum_span_ms = window * 1000 / rate
            if (
                any(
                    actual_starts[index + window] - actual_starts[index] + tolerance
                    < minimum_span_ms
                    for index in range(len(actual_starts) - window)
                )
                and "initial_connect_rate_exceeded" not in reasons
            ):
                reasons.append("initial_connect_rate_exceeded")
    elif initial_starts:
        reasons.append("reader_schedule_epoch_inconsistent")

    observed_rtp_packets = sum(item.rtp_packets for item in completions)
    if completions and len(scheduled_starts) == 1:
        measurement_seconds = max(
            0.001,
            (max(item.process_end_unix_ms for item in completions) - next(iter(scheduled_starts)))
            / 1000,
        )
        observed_rtp_rate = observed_rtp_packets / measurement_seconds
    else:
        observed_rtp_rate = 0.0
    packet_rate_pass = observed_rtp_rate >= profile.workload.minimum_rtp_packets_per_second
    if not packet_rate_pass:
        reasons.append("rtp_packet_rate_below_profile_minimum")

    p95 = _nearest_rank(handshake_latencies, 0.95)
    p99 = _nearest_rank(handshake_latencies, 0.99)
    latency_slo_ms: float | None = None
    latency_slo_pass: bool | None = None
    latency_gate: LatencyGate
    if profile.workload.endpoint_mode == "direct-control":
        latency_gate = "direct_control_reference"
    elif profile.workload.session_temperature == "cold":
        latency_gate = "requires_direct_control_decomposition"
    else:
        latency_gate = "warm_proxy_p99"
        latency_slo_ms = 500
        latency_slo_pass = p99 is not None and p99 <= latency_slo_ms
        if not latency_slo_pass:
            reasons.append("warm_proxy_p99_above_500ms")

    return ReaderRunSummary(
        expected_concurrent_readers=profile.workload.total_readers,
        events_sha256=_sha256_file(path),
        establishment_attempts=len(starts),
        decodable_establishments=len(frames),
        failed_establishments=len(failures),
        observed_rtp_packets=observed_rtp_packets,
        observed_rtp_packets_per_second=observed_rtp_rate,
        minimum_rtp_packets_per_second=profile.workload.minimum_rtp_packets_per_second,
        packet_rate_slo_pass=packet_rate_pass,
        establishment_success_percent=success_percent,
        describe_to_play_p50_ms=_nearest_rank(handshake_latencies, 0.50),
        describe_to_play_p95_ms=p95,
        describe_to_play_p99_ms=p99,
        first_decodable_p50_ms=_nearest_rank(frame_latencies, 0.50),
        first_decodable_p95_ms=_nearest_rank(frame_latencies, 0.95),
        first_decodable_p99_ms=_nearest_rank(frame_latencies, 0.99),
        latency_slo_ms=latency_slo_ms,
        latency_slo_pass=latency_slo_pass,
        latency_gate=latency_gate,
        valid=not reasons,
        invalid_reasons=tuple(reasons),
    )


def summarize_cold_comparison(
    proxy_profile: LoadProfile,
    proxy_events: Path,
    direct_profile: LoadProfile,
    direct_events: Path,
    *,
    direct_final_manifest_sha256: str,
) -> ColdComparisonSummary:
    validate_comparison_pair(proxy_profile, direct_profile)
    if proxy_profile.workload.session_temperature != "cold":
        raise ValueError("cold_comparison_requires_cold_profiles")
    proxy_summary = summarize_reader_events(proxy_profile, proxy_events)
    direct_summary = summarize_reader_events(direct_profile, direct_events)
    _, _, _, proxy_plays, proxy_frames, _ = _event_maps(proxy_profile, proxy_events)
    _, _, _, direct_plays, direct_frames, _ = _event_maps(direct_profile, direct_events)
    if set(proxy_frames) != set(direct_frames):
        raise ValueError("comparison_establishments_differ")
    if set(proxy_plays) != set(direct_plays) or set(proxy_plays) != set(proxy_frames):
        raise ValueError("comparison_handshakes_differ")
    overhead = [proxy_plays[key] - direct_plays[key] for key in sorted(proxy_plays)]
    direct_wait = [value[1] for value in direct_frames.values()]
    proxy_wait = [value[1] for value in proxy_frames.values()]
    if not overhead:
        raise ValueError("comparison_has_no_establishments")
    p50 = _nearest_rank(overhead, 0.50)
    p95 = _nearest_rank(overhead, 0.95)
    p99 = _nearest_rank(overhead, 0.99)
    direct_wait_p99 = _nearest_rank(direct_wait, 0.99)
    proxy_wait_p99 = _nearest_rank(proxy_wait, 0.99)
    assert p50 is not None and p95 is not None and p99 is not None
    assert direct_wait_p99 is not None
    assert proxy_wait_p99 is not None
    slo_pass = p99 <= 1000
    reasons: list[str] = []
    if not proxy_summary.valid:
        reasons.append("proxy_reader_run_invalid")
    if not direct_summary.valid:
        reasons.append("direct_reader_run_invalid")
    if not slo_pass:
        reasons.append("cold_proxy_overhead_p99_above_1000ms")
    return ColdComparisonSummary(
        comparison_id=proxy_profile.comparison_id,
        proxy_events_sha256=_sha256_file(proxy_events),
        direct_events_sha256=_sha256_file(direct_events),
        direct_final_manifest_sha256=direct_final_manifest_sha256,
        compared_establishments=len(overhead),
        proxy_overhead_p50_ms=p50,
        proxy_overhead_p95_ms=p95,
        proxy_overhead_p99_ms=p99,
        direct_wait_for_decodable_p99_ms=direct_wait_p99,
        proxy_wait_for_decodable_p99_ms=proxy_wait_p99,
        proxy_overhead_slo_ms=1000,
        proxy_overhead_slo_pass=slo_pass,
        valid=not reasons,
        invalid_reasons=tuple(reasons),
    )
