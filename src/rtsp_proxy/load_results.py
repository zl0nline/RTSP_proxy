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
    lifecycle_start_unix_ms,
    measurement_end_unix_ms,
    measurement_start_unix_ms,
    ramp_end_unix_ms,
    validate_comparison_pair,
    warm_anchor_reader_count,
    warm_anchor_start_unix_ms,
    workload_end_unix_ms,
)

LatencyGate = Literal[
    "warm_proxy_p99",
    "requires_direct_control_decomposition",
    "direct_control_reference",
]
RtpTrack = Literal["audio", "video"]
RtpPhase = Literal["measurement", "soak"]
RtpSegmentKey = tuple[int, int, RtpTrack, RtpPhase]
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
    at_monotonic_ms: float
    at_unix_ms: Annotated[int, Field(ge=0)] | None = None
    describe_to_play_ms: Annotated[float, Field(ge=0)] | None = None
    describe_to_first_decodable_ms: Annotated[float, Field(ge=0)] | None = None
    play_to_first_decodable_ms: Annotated[float, Field(ge=0)] | None = None
    access_unit: Literal[True] | None = None
    backoff_ms: Annotated[float, Field(ge=0)] | None = None
    injected: bool | None = None
    lifecycle_slot: Annotated[int, Field(ge=0)] | None = None
    reason: Literal["gstreamer_error", "unexpected_eos", "state_change_failure"] | None = None

    @model_validator(mode="after")
    def validate_event_shape(self) -> Self:
        populated = {
            "at_unix_ms": self.at_unix_ms,
            "describe_to_play_ms": self.describe_to_play_ms,
            "describe_to_first_decodable_ms": self.describe_to_first_decodable_ms,
            "play_to_first_decodable_ms": self.play_to_first_decodable_ms,
            "access_unit": self.access_unit,
            "backoff_ms": self.backoff_ms,
            "injected": self.injected,
            "lifecycle_slot": self.lifecycle_slot,
            "reason": self.reason,
        }
        expected: set[str]
        if self.event == "play_sent":
            expected = {"describe_to_play_ms"}
        elif self.event == "first_decodable_frame":
            expected = {
                "describe_to_first_decodable_ms",
                "play_to_first_decodable_ms",
                "access_unit",
            }
        elif self.event == "reader_error":
            expected = {"reason"}
        elif self.event == "reader_disconnected":
            expected = {"at_unix_ms", "injected", "lifecycle_slot"}
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
    anchor_start_unix_ms: Annotated[int, Field(gt=0)]
    scheduled_start_unix_ms: Annotated[int, Field(gt=0)]
    ramp_end_unix_ms: Annotated[int, Field(gt=0)]
    lifecycle_start_unix_ms: Annotated[int, Field(gt=0)]
    measurement_start_unix_ms: Annotated[int, Field(gt=0)]
    measurement_end_unix_ms: Annotated[int, Field(gt=0)]
    scheduled_workload_end_unix_ms: Annotated[int, Field(gt=0)]
    process_start_unix_ms: Annotated[int, Field(gt=0)]
    workload_end_unix_ms: Annotated[int, Field(gt=0)]
    process_end_unix_ms: Annotated[int, Field(gt=0)]
    clock_synchronized: bool
    clock_max_error_ms: Annotated[float, Field(ge=0)]
    lifecycle_scheduled_slots: Annotated[int, Field(ge=0)]
    injected_disconnects: Annotated[int, Field(ge=0)]
    rtp_packets: Annotated[int, Field(ge=0)]
    measurement_rtp_packets: Annotated[int, Field(ge=0)]
    soak_rtp_packets: Annotated[int, Field(ge=0)]
    measurement_rtp_sequence_gaps: Annotated[int, Field(ge=0)]
    soak_rtp_sequence_gaps: Annotated[int, Field(ge=0)]

    @model_validator(mode="after")
    def validate_process_window(self) -> Self:
        if not (
            self.process_start_unix_ms
            <= self.anchor_start_unix_ms
            <= self.scheduled_start_unix_ms
            <= self.ramp_end_unix_ms
            <= self.measurement_start_unix_ms
            < self.measurement_end_unix_ms
            <= self.scheduled_workload_end_unix_ms
            <= self.workload_end_unix_ms
            < self.process_end_unix_ms
        ):
            raise ValueError("reader_process_window_invalid")
        if self.measurement_rtp_packets + self.soak_rtp_packets > self.rtp_packets:
            raise ValueError("reader_phase_rtp_counters_invalid")
        return self


class ReaderRtpPhaseEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    event: Literal["reader_rtp_phase"]
    reader_id: Annotated[int, Field(ge=0, lt=100000)]
    path: Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9_.:-]{1,128}$")]
    at_monotonic_ms: Annotated[float, Field(ge=0)]
    audio_expected: bool
    quiesced: bool
    video_parse_failures: Annotated[int, Field(ge=0)]
    audio_parse_failures: Annotated[int, Field(ge=0)]
    measurement_video_rtp_packets: Annotated[int, Field(ge=0)]
    measurement_video_rtp_sequence_gaps: Annotated[int, Field(ge=0)]
    soak_video_rtp_packets: Annotated[int, Field(ge=0)]
    soak_video_rtp_sequence_gaps: Annotated[int, Field(ge=0)]
    measurement_audio_rtp_packets: Annotated[int, Field(ge=0)]
    measurement_audio_rtp_sequence_gaps: Annotated[int, Field(ge=0)]
    soak_audio_rtp_packets: Annotated[int, Field(ge=0)]
    soak_audio_rtp_sequence_gaps: Annotated[int, Field(ge=0)]


class ReaderRtpSegmentEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    event: Literal["reader_rtp_segment"]
    reader_id: Annotated[int, Field(ge=0, lt=100000)]
    cycle: Annotated[int, Field(ge=0, le=1000000)]
    path: Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9_.:-]{1,128}$")]
    track: RtpTrack
    phase: RtpPhase
    first_at_monotonic_ms: float
    last_at_monotonic_ms: float
    received_packets: Annotated[int, Field(gt=0)]
    sequence_expected_packets: Annotated[int, Field(ge=0)]
    sequence_gaps: Annotated[int, Field(ge=0)]

    @model_validator(mode="after")
    def validate_segment_window(self) -> Self:
        if self.last_at_monotonic_ms < self.first_at_monotonic_ms:
            raise ValueError("reader_rtp_segment_window_invalid")
        return self


class ReaderRunSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    expected_concurrent_readers: int
    warm_anchor_readers: int
    ramp_establishment_attempts: int
    measurement_start_unix_ms: int | None
    measurement_end_unix_ms: int | None
    soak_end_unix_ms: int | None
    measurement_failed_establishments: int
    soak_failed_establishments: int
    events_sha256: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
    establishment_attempts: int
    decodable_establishments: int
    failed_establishments: int
    observed_rtp_packets: int
    observed_rtp_packets_per_second: float
    soak_observed_rtp_packets: int
    soak_observed_rtp_packets_per_second: float | None
    measurement_expected_rtp_packets: int
    measurement_rtp_sequence_gaps: int
    soak_expected_rtp_packets: int
    soak_rtp_sequence_gaps: int
    packet_loss_slo_pass: bool
    per_reader_packet_rate_slo_pass: bool
    readers_with_measurement_progress: int
    readers_with_soak_progress: int
    readers_with_audio_progress: int
    minimum_rtp_packets_per_second: int
    packet_rate_slo_pass: bool
    soak_packet_rate_slo_pass: bool | None
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


def injected_reconnect_backoff_ms(
    profile: LoadProfile,
    reader_id: int,
    cycle: int,
) -> int:
    if profile.reader_lifecycle.mode != "outage":
        return profile.reader_lifecycle.backoff_base_ms
    mask = (1 << 32) - 1
    value = (profile.seed ^ (reader_id * 2654435761 & mask) ^ (cycle * 2246822519 & mask)) & mask
    value ^= value >> 16
    value = value * 2246822519 & mask
    value ^= value >> 13
    span = profile.reader_lifecycle.backoff_max_ms - profile.reader_lifecycle.backoff_base_ms + 1
    return profile.reader_lifecycle.backoff_base_ms + value % span


RawReaderEvent = ReaderEvent | ReaderRtpPhaseEvent | ReaderRtpSegmentEvent | ReaderRunCompletedEvent


def _load_reader_events(path: Path) -> tuple[RawReaderEvent, ...]:
    events: list[RawReaderEvent] = []
    with path.open(encoding="utf-8") as source:
        for line in source:
            if not line.strip():
                raise ValueError("blank_reader_event_line")
            payload = json.loads(line)
            if payload.get("event") == "run_completed":
                events.append(ReaderRunCompletedEvent.model_validate(payload))
            elif payload.get("event") == "reader_rtp_phase":
                events.append(ReaderRtpPhaseEvent.model_validate(payload))
            elif payload.get("event") == "reader_rtp_segment":
                events.append(ReaderRtpSegmentEvent.model_validate(payload))
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
        "reader_rtp_segment": 6,
        "reader_rtp_phase": 7,
        "run_completed": 8,
    }
    events.sort(
        key=lambda event: (
            event.reader_id
            if isinstance(event, (ReaderEvent, ReaderRtpPhaseEvent, ReaderRtpSegmentEvent))
            else 100000,
            event.cycle
            if isinstance(event, ReaderEvent)
            else event.cycle
            if isinstance(event, ReaderRtpSegmentEvent)
            else 0
            if isinstance(event, ReaderRtpPhaseEvent)
            else event.schedule_shard_index,
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
    rtp_reader_ids = [event.reader_id for event in events if isinstance(event, ReaderRtpPhaseEvent)]
    if len(rtp_reader_ids) != len(set(rtp_reader_ids)):
        raise ValueError("duplicate_reader_rtp_phase_across_inputs")
    segment_keys = [
        (event.reader_id, event.cycle, event.track, event.phase)
        for event in events
        if isinstance(event, ReaderRtpSegmentEvent)
    ]
    if len(segment_keys) != len(set(segment_keys)):
        raise ValueError("duplicate_reader_rtp_segment_across_inputs")
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
    dict[tuple[int, int], ReaderEvent],
    tuple[ReaderRtpPhaseEvent, ...],
    tuple[ReaderRtpSegmentEvent, ...],
]:
    raw_events = _load_reader_events(path)
    events = tuple(event for event in raw_events if isinstance(event, ReaderEvent))
    completions = tuple(event for event in raw_events if isinstance(event, ReaderRunCompletedEvent))
    rtp_phases = tuple(event for event in raw_events if isinstance(event, ReaderRtpPhaseEvent))
    rtp_segments = tuple(event for event in raw_events if isinstance(event, ReaderRtpSegmentEvent))
    starts: set[tuple[int, int]] = set()
    plays: dict[tuple[int, int], float] = {}
    frames: dict[tuple[int, int], tuple[float, float]] = {}
    failures: dict[tuple[int, int], ReaderEvent] = {}
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
            failures[key] = event
    if not starts:
        raise ValueError("reader_start_events_missing")
    if not set(plays).issubset(starts) or not set(frames).issubset(starts):
        raise ValueError("reader_event_without_start")
    return events, completions, starts, plays, frames, failures, rtp_phases, rtp_segments


def _plan_body_sha256(plan: ReaderPlan) -> str:
    targets = plan.targets
    body = "".join(
        f"{target.path}\t{target.reader_count}\t{target.reader_id_start}\t"
        f"{target.warm_anchor_count}\t{target.measured_schedule_start}\n"
        for target in targets
    ).encode("ascii")
    return hashlib.sha256(body).hexdigest()


def _expected_reader_contract(
    profile: LoadProfile,
) -> tuple[
    dict[int, str],
    dict[str, tuple[int, str, int]],
    set[int],
    dict[int, int],
]:
    expected_paths: dict[int, str] = {}
    shard_contract: dict[str, tuple[int, str, int]] = {}
    anchor_ids: set[int] = set()
    measured_positions: dict[int, int] = {}
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
        reader_count = sum(target.reader_count for target in plan.targets)
        shard_contract[host_name] = (shard_index, _plan_body_sha256(plan), reader_count)
        for target in plan.targets:
            for offset, reader_id in enumerate(
                range(
                    target.reader_id_start,
                    target.reader_id_start + target.reader_count,
                )
            ):
                if reader_id in expected_paths:
                    raise ValueError("reader_plan_duplicate_global_id")
                expected_paths[reader_id] = target.path
                if offset < target.warm_anchor_count:
                    anchor_ids.add(reader_id)
                else:
                    measured_positions[reader_id] = (
                        target.measured_schedule_start + offset - target.warm_anchor_count
                    )
    return expected_paths, shard_contract, anchor_ids, measured_positions


def summarize_reader_events(profile: LoadProfile, path: Path) -> ReaderRunSummary:
    (
        events,
        completions,
        starts,
        plays,
        frames,
        failures,
        rtp_phases,
        rtp_segments,
    ) = _event_maps(profile, path)
    expected_paths, shard_contract, anchor_ids, measured_positions = _expected_reader_contract(
        profile
    )
    ramp_keys = {key for key in starts if key[0] not in anchor_ids and key[1] == 0}
    handshake_latencies = [value for key, value in plays.items() if key in ramp_keys]
    frame_latencies = [value[0] for key, value in frames.items() if key in ramp_keys]
    success_percent = len(frames) / len(starts) * 100
    reasons: list[str] = []
    if any(expected_paths.get(event.reader_id) != event.path for event in events):
        reasons.append("reader_path_plan_mismatch")
    if success_percent < 99.9:
        reasons.append("session_establishment_below_99_9_percent")
    if failures:
        reasons.append("reader_errors_observed")
    if set(starts) != set(plays) or set(plays) != set(frames):
        reasons.append("reader_handshake_chain_incomplete")
    if any(
        event.event != "reader_started" and (event.reader_id, event.cycle) not in starts
        for event in events
    ):
        reasons.append("reader_event_cycle_without_start")
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
        and len(scheduled_starts) == 1
        and all(
            item.generator_host in shard_contract
            and shard_contract[item.generator_host][:2]
            == (item.schedule_shard_index, item.reader_plan_sha256)
            and item.started_readers == shard_contract[item.generator_host][2]
            and item.ready_readers == shard_contract[item.generator_host][2]
            and item.profile_sha256 == profile_sha256
            and item.clock_synchronized
            and item.clock_max_error_ms <= profile.evidence_sampling.maximum_clock_error_ms
            and item.process_start_unix_ms <= item.anchor_start_unix_ms
            and item.anchor_start_unix_ms
            == warm_anchor_start_unix_ms(profile, item.scheduled_start_unix_ms)
            and item.ramp_end_unix_ms == ramp_end_unix_ms(profile, item.scheduled_start_unix_ms)
            and item.lifecycle_start_unix_ms
            == lifecycle_start_unix_ms(profile, item.scheduled_start_unix_ms)
            and item.measurement_start_unix_ms
            == measurement_start_unix_ms(profile, item.scheduled_start_unix_ms)
            and item.measurement_end_unix_ms
            == measurement_end_unix_ms(profile, item.scheduled_start_unix_ms)
            and item.scheduled_workload_end_unix_ms
            == workload_end_unix_ms(profile, item.scheduled_start_unix_ms)
            and item.workload_end_unix_ms
            <= item.scheduled_workload_end_unix_ms
            + profile.evidence_sampling.maximum_start_lateness_ms
            for item in completions
        )
    )
    if not completion_valid:
        reasons.append("reader_process_completion_missing_or_invalid")

    early_tolerance = profile.evidence_sampling.maximum_clock_error_ms + 5
    late_tolerance = profile.evidence_sampling.maximum_start_lateness_ms
    if len(scheduled_starts) == 1:
        schedule_start = next(iter(scheduled_starts))
        anchor_start = warm_anchor_start_unix_ms(profile, schedule_start)
        rate = profile.workload.connect_rate_per_second
        for event in initial_starts:
            assert event.at_unix_ms is not None
            expected_at = (
                anchor_start
                if event.reader_id in anchor_ids
                else schedule_start
                if rate == 0
                else schedule_start + (measured_positions[event.reader_id] * 1000 / rate)
            )
            if (
                event.at_unix_ms + early_tolerance < expected_at
                or event.at_unix_ms > expected_at + late_tolerance
            ):
                reasons.append("initial_connect_schedule_deviation")
                break
        measured_initial_starts = [
            event for event in initial_starts if event.reader_id not in anchor_ids
        ]
        if rate > 0 and len(measured_initial_starts) > 1:
            actual_starts = sorted(
                event.at_unix_ms
                for event in measured_initial_starts
                if event.at_unix_ms is not None
            )
            window = min(rate, len(actual_starts) - 1)
            minimum_span_ms = window * 1000 / rate
            if (
                any(
                    actual_starts[index + window] - actual_starts[index] + early_tolerance
                    < minimum_span_ms
                    for index in range(len(actual_starts) - window)
                )
                and "initial_connect_rate_exceeded" not in reasons
            ):
                reasons.append("initial_connect_rate_exceeded")
    elif initial_starts:
        reasons.append("reader_schedule_epoch_inconsistent")

    if anchor_ids and len(scheduled_starts) == 1:
        schedule_start = next(iter(scheduled_starts))
        anchor_frames = {
            event.reader_id: event
            for event in events
            if event.event == "first_decodable_frame"
            and event.cycle == 0
            and event.reader_id in anchor_ids
        }
        if set(anchor_frames) != anchor_ids or any(
            schedule_start + event.at_monotonic_ms > schedule_start
            for event in anchor_frames.values()
        ):
            reasons.append("warm_anchor_not_decodable_before_ramp")

    injected_disconnects = sorted(
        (event.lifecycle_slot, event.at_unix_ms, event.reader_id)
        for event in events
        if event.event == "reader_disconnected"
        and event.injected is True
        and event.lifecycle_slot is not None
        and event.at_unix_ms is not None
    )
    reported_slots = sum(item.lifecycle_scheduled_slots for item in completions)
    reported_disconnects = sum(item.injected_disconnects for item in completions)
    lifecycle_mode = profile.reader_lifecycle.mode
    if reported_disconnects != len(injected_disconnects):
        reasons.append("lifecycle_disconnect_count_mismatch")
    injected_events = [
        event for event in events if event.event == "reader_disconnected" and event.injected is True
    ]
    event_index = {(event.reader_id, event.cycle, event.event): event for event in events}
    reconnect_chain_valid = True
    scheduled_events = [event for event in events if event.event == "reconnect_scheduled"]
    for reader_id, cycle in starts:
        if cycle == 0:
            continue
        predecessor_key = (reader_id, cycle - 1)
        predecessors = [
            candidate
            for candidate in (
                event_index.get((*predecessor_key, "reader_disconnected")),
                event_index.get((*predecessor_key, "reader_error")),
            )
            if candidate is not None
        ]
        scheduled = event_index.get((*predecessor_key, "reconnect_scheduled"))
        started = event_index.get((reader_id, cycle, "reader_started"))
        if len(predecessors) != 1 or scheduled is None or started is None:
            reconnect_chain_valid = False
            break
        predecessor = predecessors[0]
        assert scheduled.backoff_ms is not None
        expected_start = scheduled.at_monotonic_ms + scheduled.backoff_ms
        if (
            not (
                profile.reader_lifecycle.backoff_base_ms
                <= scheduled.backoff_ms
                <= profile.reader_lifecycle.backoff_max_ms
            )
            or scheduled.at_monotonic_ms < predecessor.at_monotonic_ms
            or started.at_monotonic_ms + early_tolerance < expected_start
            or started.at_monotonic_ms > expected_start + late_tolerance
        ):
            reconnect_chain_valid = False
            break
    if reconnect_chain_valid:
        for scheduled in scheduled_events:
            predecessor_key = (scheduled.reader_id, scheduled.cycle)
            predecessors = [
                candidate
                for candidate in (
                    event_index.get((*predecessor_key, "reader_disconnected")),
                    event_index.get((*predecessor_key, "reader_error")),
                )
                if candidate is not None
            ]
            if len(predecessors) != 1 or (scheduled.reader_id, scheduled.cycle + 1) not in starts:
                reconnect_chain_valid = False
                break
    if reconnect_chain_valid:
        for disconnect in injected_events:
            scheduled = event_index.get(
                (disconnect.reader_id, disconnect.cycle, "reconnect_scheduled")
            )
            expected_backoff = injected_reconnect_backoff_ms(
                profile,
                disconnect.reader_id,
                disconnect.cycle,
            )
            if scheduled is None or scheduled.backoff_ms != expected_backoff:
                reconnect_chain_valid = False
                break
    if reconnect_chain_valid:
        for key in starts:
            started = event_index.get((*key, "reader_started"))
            played = event_index.get((*key, "play_sent"))
            decodable = event_index.get((*key, "first_decodable_frame"))
            if (
                started is None
                or played is None
                or decodable is None
                or played.at_monotonic_ms < started.at_monotonic_ms
                or decodable.at_monotonic_ms < played.at_monotonic_ms
            ):
                reconnect_chain_valid = False
                break
    if not reconnect_chain_valid:
        reasons.append("reader_reconnect_chain_invalid")
    if lifecycle_mode in {"steady", "outage"}:
        readiness_epochs = {item.lifecycle_start_unix_ms for item in completions}
        initial_frames = [
            event for event in events if event.event == "first_decodable_frame" and event.cycle == 0
        ]
        if (
            len(readiness_epochs) != 1
            or len(scheduled_starts) != 1
            or {event.reader_id for event in initial_frames}
            != set(range(profile.workload.total_readers))
            or any(
                next(iter(scheduled_starts)) + event.at_monotonic_ms > next(iter(readiness_epochs))
                for event in initial_frames
            )
        ):
            reasons.append("lifecycle_readiness_deadline_missed")
    if lifecycle_mode == "steady":
        rate = profile.reader_lifecycle.disconnect_rate_per_second
        lifecycle_epochs = {item.lifecycle_start_unix_ms for item in completions}
        lifecycle_ends = {item.scheduled_workload_end_unix_ms for item in completions}
        lifecycle_epoch = next(iter(lifecycle_epochs), 0)
        lifecycle_end = next(iter(lifecycle_ends), 0)
        expected_slots = math.ceil(
            max(
                0,
                lifecycle_end - lifecycle_epoch - profile.reader_lifecycle.backoff_base_ms,
            )
            * rate
            / 1000
        )
        if (
            reported_slots != expected_slots
            or reported_slots == 0
            or reported_slots != reported_disconnects
            or len(lifecycle_epochs) != 1
            or len(lifecycle_ends) != 1
            or [slot for slot, _, _ in injected_disconnects] != list(range(expected_slots))
        ):
            reasons.append("steady_lifecycle_schedule_incomplete")
        else:
            for slot, observed_at, _ in injected_disconnects:
                expected_at = lifecycle_epoch + slot * 1000 / rate
                if (
                    observed_at + early_tolerance < expected_at
                    or observed_at > expected_at + late_tolerance
                ):
                    reasons.append("steady_lifecycle_rate_deviation")
                    break
    elif lifecycle_mode == "outage":
        expected_disconnects = (
            profile.workload.total_readers * profile.reader_lifecycle.outage_percent // 100
        )
        lifecycle_epochs = {item.lifecycle_start_unix_ms for item in completions}
        lifecycle_epoch = next(iter(lifecycle_epochs), 0)
        cohort_start = profile.seed % profile.workload.total_readers
        expected_cohort = {
            ((cohort_start + slot) % profile.workload.total_readers, slot)
            for slot in range(expected_disconnects)
        }
        observed_cohort = {(reader_id, slot) for slot, _, reader_id in injected_disconnects}
        if (
            reported_slots != expected_disconnects
            or reported_disconnects != expected_disconnects
            or len(lifecycle_epochs) != 1
            or len(observed_cohort) != len(injected_disconnects)
            or observed_cohort != expected_cohort
        ):
            reasons.append("outage_lifecycle_cohort_incomplete")
        elif any(
            observed_at + early_tolerance < lifecycle_epoch
            or observed_at > lifecycle_epoch + late_tolerance
            for _, observed_at, _ in injected_disconnects
        ):
            reasons.append("outage_lifecycle_epoch_deviation")
    elif reported_slots != 0 or reported_disconnects != 0:
        reasons.append("unexpected_lifecycle_disconnects")

    observed_rtp_packets = sum(item.measurement_rtp_packets for item in completions)
    soak_observed_rtp_packets = sum(item.soak_rtp_packets for item in completions)
    measurement_rtp_sequence_gaps = sum(item.measurement_rtp_sequence_gaps for item in completions)
    soak_rtp_sequence_gaps = sum(item.soak_rtp_sequence_gaps for item in completions)
    rtp_by_reader = {item.reader_id: item for item in rtp_phases}
    expected_audio = profile.fixture.audio == "opus"
    rtp_phase_set_valid = (
        len(rtp_phases) == profile.workload.total_readers
        and set(rtp_by_reader) == set(expected_paths)
        and all(
            item.path == expected_paths[item.reader_id]
            and item.audio_expected is expected_audio
            and item.quiesced
            and item.video_parse_failures == 0
            and item.audio_parse_failures == 0
            for item in rtp_phases
        )
    )
    if not rtp_phase_set_valid:
        reasons.append("reader_rtp_phase_set_incomplete")
    video_measurement_from_readers = sum(item.measurement_video_rtp_packets for item in rtp_phases)
    video_soak_from_readers = sum(item.soak_video_rtp_packets for item in rtp_phases)
    video_measurement_gaps_from_readers = sum(
        item.measurement_video_rtp_sequence_gaps for item in rtp_phases
    )
    video_soak_gaps_from_readers = sum(item.soak_video_rtp_sequence_gaps for item in rtp_phases)
    if (
        video_measurement_from_readers != observed_rtp_packets
        or video_soak_from_readers != soak_observed_rtp_packets
        or video_measurement_gaps_from_readers != measurement_rtp_sequence_gaps
        or video_soak_gaps_from_readers != soak_rtp_sequence_gaps
    ):
        reasons.append("reader_rtp_phase_aggregate_mismatch")
    audio_measurement_from_readers = sum(item.measurement_audio_rtp_packets for item in rtp_phases)
    audio_soak_from_readers = sum(item.soak_audio_rtp_packets for item in rtp_phases)
    audio_measurement_gaps_from_readers = sum(
        item.measurement_audio_rtp_sequence_gaps for item in rtp_phases
    )
    audio_soak_gaps_from_readers = sum(item.soak_audio_rtp_sequence_gaps for item in rtp_phases)
    measurement_seconds = profile.duration.measurement_seconds
    observed_rtp_rate = (
        observed_rtp_packets / measurement_seconds if completions and measurement_seconds > 0 else 0
    )
    packet_rate_pass = observed_rtp_rate >= profile.workload.minimum_rtp_packets_per_second
    if not packet_rate_pass:
        reasons.append("rtp_packet_rate_below_profile_minimum")
    soak_seconds = profile.duration.soak_seconds
    soak_observed_rtp_rate = (
        soak_observed_rtp_packets / soak_seconds if completions and soak_seconds > 0 else None
    )
    soak_packet_rate_pass = (
        None
        if soak_observed_rtp_rate is None
        else soak_observed_rtp_rate >= profile.workload.minimum_rtp_packets_per_second
    )
    if soak_packet_rate_pass is False:
        reasons.append("soak_rtp_packet_rate_below_profile_minimum")

    schedule_epoch = next(iter(scheduled_starts), 0)
    phase_bounds: dict[RtpPhase, tuple[float, float]] = {
        "measurement": (
            measurement_start_unix_ms(profile, schedule_epoch) - schedule_epoch,
            measurement_end_unix_ms(profile, schedule_epoch) - schedule_epoch,
        ),
        "soak": (
            measurement_end_unix_ms(profile, schedule_epoch) - schedule_epoch,
            workload_end_unix_ms(profile, schedule_epoch) - schedule_epoch,
        ),
    }
    frame_events = {
        (event.reader_id, event.cycle): event
        for event in events
        if event.event == "first_decodable_frame"
    }
    termination_times: dict[tuple[int, int], float] = {}
    for event in events:
        if event.event in {"reader_disconnected", "reader_error"}:
            key = (event.reader_id, event.cycle)
            termination_times[key] = min(
                event.at_monotonic_ms,
                termination_times.get(key, event.at_monotonic_ms),
            )
    expected_segment_windows: dict[RtpSegmentKey, tuple[float, float]] = {}
    workload_end_relative = workload_end_unix_ms(profile, schedule_epoch) - schedule_epoch
    expected_tracks: tuple[RtpTrack, ...] = ("video", "audio") if expected_audio else ("video",)
    for key, frame in frame_events.items():
        connected_end = termination_times.get(key, workload_end_relative)
        if connected_end < frame.at_monotonic_ms:
            reasons.append("reader_connected_interval_invalid")
            continue
        for phase, (phase_start, phase_end) in phase_bounds.items():
            connected_start = max(frame.at_monotonic_ms, phase_start)
            connected_phase_end = min(connected_end, phase_end)
            if connected_phase_end > connected_start:
                for track in expected_tracks:
                    expected_segment_windows[(*key, track, phase)] = (
                        connected_start,
                        connected_phase_end,
                    )

    segment_by_key = {
        (item.reader_id, item.cycle, item.track, item.phase): item for item in rtp_segments
    }
    segment_set_valid = (
        len(segment_by_key) == len(rtp_segments)
        and set(expected_segment_windows) == set(segment_by_key)
        and {
            key[0]
            for key in expected_segment_windows
            if key[2] == "video" and key[3] == "measurement"
        }
        == set(expected_paths)
        and (
            profile.duration.soak_seconds == 0
            or {
                key[0] for key in expected_segment_windows if key[2] == "video" and key[3] == "soak"
            }
            == set(expected_paths)
        )
        and all(
            item.path == expected_paths.get(item.reader_id)
            and (item.track == "video" or expected_audio)
            and expected_segment_windows[segment_key][0] <= item.first_at_monotonic_ms
            and item.last_at_monotonic_ms <= expected_segment_windows[segment_key][1]
            for segment_key, item in segment_by_key.items()
        )
    )
    if not segment_set_valid:
        reasons.append("reader_rtp_segment_set_incomplete")

    segment_received = {
        (track, phase): sum(
            item.received_packets
            for item in rtp_segments
            if item.track == track and item.phase == phase
        )
        for track in ("video", "audio")
        for phase in ("measurement", "soak")
    }
    segment_gaps = {
        (track, phase): sum(
            item.sequence_gaps
            for item in rtp_segments
            if item.track == track and item.phase == phase
        )
        for track in ("video", "audio")
        for phase in ("measurement", "soak")
    }
    segment_expected = {
        (track, phase): sum(
            item.sequence_expected_packets
            for item in rtp_segments
            if item.track == track and item.phase == phase
        )
        for track in ("video", "audio")
        for phase in ("measurement", "soak")
    }
    segment_aggregates_valid = (
        segment_received[("video", "measurement")] == video_measurement_from_readers
        and segment_received[("video", "soak")] == video_soak_from_readers
        and segment_gaps[("video", "measurement")] == video_measurement_gaps_from_readers
        and segment_gaps[("video", "soak")] == video_soak_gaps_from_readers
        and segment_received[("audio", "measurement")] == audio_measurement_from_readers
        and segment_received[("audio", "soak")] == audio_soak_from_readers
        and segment_gaps[("audio", "measurement")] == audio_measurement_gaps_from_readers
        and segment_gaps[("audio", "soak")] == audio_soak_gaps_from_readers
    )
    if not segment_aggregates_valid:
        reasons.append("reader_rtp_segment_aggregate_mismatch")

    per_reader_rate = (
        profile.workload.minimum_rtp_packets_per_second / profile.workload.total_readers
    )
    segment_rate_valid: dict[RtpSegmentKey, bool] = {}
    for segment_key, (connected_start, connected_end) in expected_segment_windows.items():
        segment = segment_by_key.get(segment_key)
        track = segment_key[2]
        connected_seconds = (connected_end - connected_start) / 1000
        minimum_rate = 40 if track == "audio" else max(per_reader_rate, profile.fixture.fps * 0.8)
        freshness_ms = 1000
        segment_rate_valid[segment_key] = (
            segment is not None
            and segment.received_packets >= math.ceil(minimum_rate * connected_seconds)
            and segment.received_packets == segment.sequence_expected_packets
            and segment.sequence_gaps == 0
            and segment.first_at_monotonic_ms <= connected_start + freshness_ms
            and segment.last_at_monotonic_ms >= connected_end - freshness_ms
        )
    per_reader_packet_rate_pass = (
        rtp_phase_set_valid
        and segment_set_valid
        and segment_aggregates_valid
        and all(segment_rate_valid.values())
    )
    readers_with_measurement_progress = sum(
        all(
            valid
            for key, valid in segment_rate_valid.items()
            if key[0] == reader_id and key[3] == "measurement" and key[2] == "video"
        )
        and any(
            key[0] == reader_id and key[3] == "measurement" and key[2] == "video"
            for key in segment_rate_valid
        )
        for reader_id in expected_paths
    )
    readers_with_soak_progress = sum(
        not any(key[0] == reader_id and key[3] == "soak" for key in segment_rate_valid)
        or all(
            valid
            for key, valid in segment_rate_valid.items()
            if key[0] == reader_id and key[3] == "soak" and key[2] == "video"
        )
        for reader_id in expected_paths
    )
    readers_with_audio_progress = sum(
        not expected_audio
        or (
            all(
                valid
                for key, valid in segment_rate_valid.items()
                if key[0] == reader_id and key[2] == "audio"
            )
            and any(key[0] == reader_id and key[2] == "audio" for key in segment_rate_valid)
        )
        for reader_id in expected_paths
    )
    if not per_reader_packet_rate_pass:
        reasons.append("per_reader_track_packet_rate_below_minimum")

    packet_loss_pass = (
        rtp_phase_set_valid
        and segment_set_valid
        and segment_aggregates_valid
        and measurement_rtp_sequence_gaps == 0
        and soak_rtp_sequence_gaps == 0
        and all(
            item.sequence_gaps == 0 and item.received_packets == item.sequence_expected_packets
            for item in rtp_segments
        )
    )
    if not packet_loss_pass:
        reasons.append("rtp_sequence_or_sent_received_mismatch")

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

    summary_phase_start = next(iter(scheduled_starts)) if len(scheduled_starts) == 1 else None
    measurement_start = (
        measurement_start_unix_ms(profile, summary_phase_start)
        if summary_phase_start is not None
        else None
    )
    measurement_end = (
        measurement_end_unix_ms(profile, summary_phase_start)
        if summary_phase_start is not None
        else None
    )
    soak_end = (
        workload_end_unix_ms(profile, summary_phase_start)
        if summary_phase_start is not None
        else None
    )
    measurement_failures = 0
    soak_failures = 0
    if (
        summary_phase_start is not None
        and measurement_start is not None
        and measurement_end is not None
        and soak_end is not None
    ):
        for failure in failures.values():
            event_at = summary_phase_start + failure.at_monotonic_ms
            if measurement_start <= event_at < measurement_end:
                measurement_failures += 1
            elif measurement_end <= event_at <= soak_end:
                soak_failures += 1
    return ReaderRunSummary(
        expected_concurrent_readers=profile.workload.total_readers,
        warm_anchor_readers=warm_anchor_reader_count(profile),
        ramp_establishment_attempts=len(ramp_keys),
        measurement_start_unix_ms=measurement_start,
        measurement_end_unix_ms=measurement_end,
        soak_end_unix_ms=soak_end,
        measurement_failed_establishments=measurement_failures,
        soak_failed_establishments=soak_failures,
        events_sha256=_sha256_file(path),
        establishment_attempts=len(starts),
        decodable_establishments=len(frames),
        failed_establishments=len(failures),
        observed_rtp_packets=observed_rtp_packets,
        observed_rtp_packets_per_second=observed_rtp_rate,
        soak_observed_rtp_packets=soak_observed_rtp_packets,
        soak_observed_rtp_packets_per_second=soak_observed_rtp_rate,
        measurement_expected_rtp_packets=segment_expected[("video", "measurement")],
        measurement_rtp_sequence_gaps=measurement_rtp_sequence_gaps,
        soak_expected_rtp_packets=segment_expected[("video", "soak")],
        soak_rtp_sequence_gaps=soak_rtp_sequence_gaps,
        packet_loss_slo_pass=packet_loss_pass,
        per_reader_packet_rate_slo_pass=per_reader_packet_rate_pass,
        readers_with_measurement_progress=readers_with_measurement_progress,
        readers_with_soak_progress=readers_with_soak_progress,
        readers_with_audio_progress=readers_with_audio_progress,
        minimum_rtp_packets_per_second=profile.workload.minimum_rtp_packets_per_second,
        packet_rate_slo_pass=packet_rate_pass,
        soak_packet_rate_slo_pass=soak_packet_rate_pass,
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
    _, _, _, proxy_plays, proxy_frames, _, _, _ = _event_maps(proxy_profile, proxy_events)
    _, _, _, direct_plays, direct_frames, _, _, _ = _event_maps(direct_profile, direct_events)
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
