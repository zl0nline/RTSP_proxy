from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from rtsp_proxy.load_catalog import build_direct_reader_plan, build_proxy_reader_plan
from rtsp_proxy.load_cli import main as load_cli_main
from rtsp_proxy.load_profile import (
    LoadProfile,
    canonical_profile_bytes,
    initialize_run_directory,
    lifecycle_start_unix_ms,
    measurement_end_unix_ms,
    measurement_start_unix_ms,
    ramp_end_unix_ms,
    warm_anchor_start_unix_ms,
    workload_end_unix_ms,
)
from rtsp_proxy.load_results import (
    ReaderEvent,
    injected_reconnect_backoff_ms,
    merge_reader_event_files,
    summarize_cold_comparison,
    summarize_reader_events,
)
from tests.test_load_profile import valid_profile


def reader_profile(*, temperature: str = "warm", endpoint_mode: str = "proxy") -> LoadProfile:
    raw = valid_profile()
    workload = raw["workload"]
    assert isinstance(workload, dict)
    workload["total_readers"] = 4
    workload["active_sources"] = 4 if temperature == "cold" else 2
    workload["session_temperature"] = temperature
    workload["endpoint_mode"] = endpoint_mode
    return LoadProfile.model_validate(raw)


def write_events(path: Path, events: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )


def successful_events(
    *,
    endpoint_mode: str = "proxy",
    temperature: str = "warm",
    schedule_start_unix_ms: int = 2_000_000,
    handshake_offset_ms: float = 0,
    decodable_offset_ms: float = 0,
) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    profile = reader_profile(temperature=temperature, endpoint_mode=endpoint_mode)
    plan = (
        build_proxy_reader_plan(profile, "generator-a")
        if endpoint_mode == "proxy"
        else build_direct_reader_plan(profile, "generator-a")
    )
    expected_paths = {
        reader_id: target.path
        for target in plan.targets
        for reader_id in range(target.reader_id_start, target.reader_id_start + target.reader_count)
    }
    anchor_ids = {
        target.reader_id_start + offset
        for target in plan.targets
        for offset in range(target.warm_anchor_count)
    }
    measured_positions = {
        target.reader_id_start + offset: target.measured_schedule_start
        + offset
        - target.warm_anchor_count
        for target in plan.targets
        for offset in range(target.warm_anchor_count, target.reader_count)
    }
    plan_body = "".join(
        f"{target.path}\t{target.reader_count}\t{target.reader_id_start}\t"
        f"{target.warm_anchor_count}\t{target.measured_schedule_start}\n"
        for target in plan.targets
    ).encode("ascii")
    for reader_id, base_handshake_ms in enumerate((100, 200, 300, 400)):
        handshake_ms = base_handshake_ms + handshake_offset_ms
        path = expected_paths[reader_id]
        started_unix_ms = (
            warm_anchor_start_unix_ms(profile, schedule_start_unix_ms)
            if reader_id in anchor_ids
            else schedule_start_unix_ms + measured_positions[reader_id] * 100
        )
        started_monotonic_ms = started_unix_ms - schedule_start_unix_ms
        events.extend(
            [
                {
                    "event": "reader_started",
                    "reader_id": reader_id,
                    "cycle": 0,
                    "path": path,
                    "at_monotonic_ms": started_monotonic_ms,
                    "at_unix_ms": started_unix_ms,
                },
                {
                    "event": "play_sent",
                    "reader_id": reader_id,
                    "cycle": 0,
                    "path": path,
                    "at_monotonic_ms": started_monotonic_ms + handshake_ms,
                    "describe_to_play_ms": handshake_ms,
                },
                {
                    "event": "first_decodable_frame",
                    "reader_id": reader_id,
                    "cycle": 0,
                    "path": path,
                    "at_monotonic_ms": started_monotonic_ms + handshake_ms + 500,
                    "describe_to_first_decodable_ms": handshake_ms + 500 + decodable_offset_ms,
                    "play_to_first_decodable_ms": 500 + decodable_offset_ms,
                    "access_unit": True,
                },
            ]
        )
    measurement_start_relative = (
        measurement_start_unix_ms(profile, schedule_start_unix_ms) - schedule_start_unix_ms
    )
    measurement_end_relative = (
        measurement_end_unix_ms(profile, schedule_start_unix_ms) - schedule_start_unix_ms
    )
    events.extend(
        {
            "event": "reader_rtp_segment",
            "reader_id": reader_id,
            "cycle": 0,
            "path": expected_paths[reader_id],
            "track": "video",
            "phase": "measurement",
            "first_at_monotonic_ms": measurement_start_relative,
            "last_at_monotonic_ms": measurement_end_relative - 1,
            "received_packets": 500,
            "sequence_expected_packets": 500,
            "sequence_gaps": 0,
        }
        for reader_id in range(4)
    )
    events.extend(
        {
            "event": "reader_rtp_phase",
            "reader_id": reader_id,
            "path": expected_paths[reader_id],
            "at_monotonic_ms": workload_end_unix_ms(profile, schedule_start_unix_ms)
            - schedule_start_unix_ms,
            "audio_expected": False,
            "quiesced": True,
            "video_parse_failures": 0,
            "audio_parse_failures": 0,
            "measurement_video_rtp_packets": 500,
            "measurement_video_rtp_sequence_gaps": 0,
            "soak_video_rtp_packets": 0,
            "soak_video_rtp_sequence_gaps": 0,
            "measurement_audio_rtp_packets": 0,
            "measurement_audio_rtp_sequence_gaps": 0,
            "soak_audio_rtp_packets": 0,
            "soak_audio_rtp_sequence_gaps": 0,
        }
        for reader_id in range(4)
    )
    events.append(
        {
            "event": "run_completed",
            "at_monotonic_ms": 1000,
            "started_readers": 4,
            "ready_readers": 4,
            "failed_attempts": 0,
            "normal_completion": True,
            "interrupted": False,
            "lifecycle_complete": True,
            "exit_code": 0,
            "schedule_shard_index": 0,
            "schedule_shards": 1,
            "generator_host": "generator-a",
            "profile_sha256": canonical_profile_bytes(profile)[1],
            "reader_plan_sha256": hashlib.sha256(plan_body).hexdigest(),
            "anchor_start_unix_ms": warm_anchor_start_unix_ms(profile, schedule_start_unix_ms),
            "scheduled_start_unix_ms": schedule_start_unix_ms,
            "ramp_end_unix_ms": ramp_end_unix_ms(profile, schedule_start_unix_ms),
            "lifecycle_start_unix_ms": lifecycle_start_unix_ms(profile, schedule_start_unix_ms),
            "measurement_start_unix_ms": measurement_start_unix_ms(profile, schedule_start_unix_ms),
            "measurement_end_unix_ms": measurement_end_unix_ms(profile, schedule_start_unix_ms),
            "scheduled_workload_end_unix_ms": workload_end_unix_ms(profile, schedule_start_unix_ms),
            "process_start_unix_ms": warm_anchor_start_unix_ms(profile, schedule_start_unix_ms)
            - 100,
            "workload_end_unix_ms": workload_end_unix_ms(profile, schedule_start_unix_ms),
            "process_end_unix_ms": workload_end_unix_ms(profile, schedule_start_unix_ms) + 100,
            "clock_synchronized": True,
            "clock_max_error_ms": 1,
            "lifecycle_scheduled_slots": 0,
            "injected_disconnects": 0,
            "rtp_packets": 2000,
            "measurement_rtp_packets": 2000,
            "soak_rtp_packets": 0,
            "measurement_rtp_sequence_gaps": 0,
            "soak_rtp_sequence_gaps": 0,
        }
    )
    return events


@pytest.mark.parametrize(
    "payload",
    [
        {
            "event": "play_sent",
            "reader_id": 0,
            "cycle": 0,
            "path": "a" * 25,
            "at_monotonic_ms": 1,
            "at_unix_ms": 1,
        },
        {
            "event": "reader_started",
            "reader_id": 0,
            "cycle": 0,
            "path": "a" * 25,
            "at_monotonic_ms": 1,
            "at_unix_ms": 1,
            "reason": "gstreamer_error",
        },
    ],
)
def test_reader_event_shapes_fail_closed(payload: dict[str, object]) -> None:
    with pytest.raises(ValidationError, match="invalid_reader_event_shape"):
        ReaderEvent.model_validate(payload)


def test_reader_event_merge_rejects_duplicate_cross_host_events(tmp_path: Path) -> None:
    first = tmp_path / "first.jsonl"
    second = tmp_path / "second.jsonl"
    event = successful_events()[0]
    write_events(first, [event])
    write_events(second, [event])

    with pytest.raises(ValueError, match="duplicate_reader_event_across_inputs"):
        merge_reader_event_files((first, second), tmp_path / "merged.jsonl")


def test_warm_reader_summary_gates_describe_to_play_not_first_rtp(tmp_path: Path) -> None:
    events_path = tmp_path / "readers.jsonl"
    write_events(events_path, successful_events())

    summary = summarize_reader_events(reader_profile(), events_path)

    assert summary.valid is True
    assert summary.expected_concurrent_readers == 4
    assert summary.establishment_attempts == 4
    assert summary.decodable_establishments == 4
    assert summary.establishment_success_percent == 100
    assert summary.describe_to_play_p50_ms == 200
    assert summary.describe_to_play_p95_ms == 400
    assert summary.describe_to_play_p99_ms == 400
    assert summary.first_decodable_p99_ms == 900
    assert summary.latency_slo_ms == 500
    assert summary.latency_slo_pass is True


def test_reader_summary_rejects_missing_completion_and_rate_overshoot(
    tmp_path: Path,
) -> None:
    events_path = tmp_path / "readers.jsonl"
    events = successful_events()
    for event in events:
        if event["event"] == "reader_started":
            event["at_monotonic_ms"] = 0
            event["at_unix_ms"] = 2_000_000
    write_events(events_path, events)

    summary = summarize_reader_events(reader_profile(), events_path)

    assert summary.valid is False
    assert "initial_connect_rate_exceeded" in summary.invalid_reasons
    missing_path = tmp_path / "missing-completion.jsonl"
    write_events(missing_path, successful_events()[:-1])
    missing = summarize_reader_events(reader_profile(), missing_path)
    assert "reader_process_completion_missing_or_invalid" in missing.invalid_reasons


def test_reader_summary_rejects_late_absolute_start(tmp_path: Path) -> None:
    events = successful_events()
    late = next(
        event for event in events if event["event"] == "reader_started" and event["reader_id"] == 2
    )
    late["at_unix_ms"] = 2_000_451
    events_path = tmp_path / "late.jsonl"
    write_events(events_path, events)

    summary = summarize_reader_events(reader_profile(), events_path)

    assert "initial_connect_schedule_deviation" in summary.invalid_reasons


def test_reader_summary_requires_anchor_decodable_before_measured_ramp(tmp_path: Path) -> None:
    events = successful_events()
    anchor_frame = next(
        event
        for event in events
        if event["event"] == "first_decodable_frame" and event["reader_id"] == 0
    )
    anchor_frame["at_monotonic_ms"] = 1
    events_path = tmp_path / "late-anchor.jsonl"
    write_events(events_path, events)

    summary = summarize_reader_events(reader_profile(), events_path)

    assert "warm_anchor_not_decodable_before_ramp" in summary.invalid_reasons


def test_reader_summary_uses_phase_rtp_counters_not_anchor_lead_traffic(
    tmp_path: Path,
) -> None:
    events = successful_events()
    completion = events[-1]
    completion.update(
        rtp_packets=100_000,
        measurement_rtp_packets=0,
        soak_rtp_packets=0,
        measurement_rtp_sequence_gaps=0,
        soak_rtp_sequence_gaps=0,
    )
    for event in events:
        if event["event"] == "reader_rtp_phase":
            event["measurement_video_rtp_packets"] = 0
    events_path = tmp_path / "anchor-traffic.jsonl"
    write_events(events_path, events)

    summary = summarize_reader_events(reader_profile(), events_path)

    assert summary.observed_rtp_packets == 0
    assert summary.packet_rate_slo_pass is False
    assert "rtp_packet_rate_below_profile_minimum" in summary.invalid_reasons


def test_reader_summary_rejects_one_stalled_reader_despite_green_aggregate(
    tmp_path: Path,
) -> None:
    events = successful_events()
    phases = [event for event in events if event["event"] == "reader_rtp_phase"]
    segments = [event for event in events if event["event"] == "reader_rtp_segment"]
    phases[0]["measurement_video_rtp_packets"] = 0
    phases[1]["measurement_video_rtp_packets"] = 1000
    events.remove(segments[0])
    segments[1]["received_packets"] = 1000
    segments[1]["sequence_expected_packets"] = 1000
    events_path = tmp_path / "one-stalled-reader.jsonl"
    write_events(events_path, events)

    summary = summarize_reader_events(reader_profile(), events_path)

    assert summary.packet_rate_slo_pass is True
    assert summary.per_reader_packet_rate_slo_pass is False
    assert summary.readers_with_measurement_progress == 3
    assert "per_reader_track_packet_rate_below_minimum" in summary.invalid_reasons


def test_reader_summary_rejects_gap_free_trailing_stall_using_fixture_fps(
    tmp_path: Path,
) -> None:
    raw = valid_profile()
    workload = raw["workload"]
    assert isinstance(workload, dict)
    workload.update(total_readers=4, active_sources=2, minimum_rtp_packets_per_second=1)
    profile = LoadProfile.model_validate(raw)
    events = successful_events()
    completion = events[-1]
    completion.update(
        profile_sha256=canonical_profile_bytes(profile)[1],
        rtp_packets=1503,
        measurement_rtp_packets=1503,
    )
    phase = next(
        event
        for event in events
        if event["event"] == "reader_rtp_phase" and event["reader_id"] == 0
    )
    phase["measurement_video_rtp_packets"] = 3
    segment = next(
        event
        for event in events
        if event["event"] == "reader_rtp_segment" and event["reader_id"] == 0
    )
    first_at = segment["first_at_monotonic_ms"]
    assert isinstance(first_at, (int, float))
    segment.update(
        last_at_monotonic_ms=float(first_at) + 100,
        received_packets=3,
        sequence_expected_packets=3,
    )
    events_path = tmp_path / "gap-free-trailing-stall.jsonl"
    write_events(events_path, events)

    summary = summarize_reader_events(profile, events_path)

    assert summary.packet_rate_slo_pass is True
    assert summary.packet_loss_slo_pass is True
    assert summary.per_reader_packet_rate_slo_pass is False
    assert "per_reader_track_packet_rate_below_minimum" in summary.invalid_reasons


def test_reader_summary_requires_opus_progress_for_every_reader(tmp_path: Path) -> None:
    raw = valid_profile()
    workload = raw["workload"]
    fixture = raw["fixture"]
    assert isinstance(workload, dict) and isinstance(fixture, dict)
    workload.update(total_readers=4, active_sources=2)
    fixture["audio"] = "opus"
    profile = LoadProfile.model_validate(raw)
    events = successful_events()
    completion = events[-1]
    completion["profile_sha256"] = canonical_profile_bytes(profile)[1]
    phases = [event for event in events if event["event"] == "reader_rtp_phase"]
    for event in phases:
        event["audio_expected"] = True
        event["measurement_audio_rtp_packets"] = 500
    phases[0]["measurement_audio_rtp_packets"] = 0
    measurement_start_relative = measurement_start_unix_ms(profile, 2_000_000) - 2_000_000
    measurement_end_relative = measurement_end_unix_ms(profile, 2_000_000) - 2_000_000
    for reader_id, phase in enumerate(phases[1:], start=1):
        events.insert(
            -1,
            {
                "event": "reader_rtp_segment",
                "reader_id": reader_id,
                "cycle": 0,
                "path": phase["path"],
                "track": "audio",
                "phase": "measurement",
                "first_at_monotonic_ms": measurement_start_relative,
                "last_at_monotonic_ms": measurement_end_relative - 1,
                "received_packets": 500,
                "sequence_expected_packets": 500,
                "sequence_gaps": 0,
            },
        )
    events_path = tmp_path / "opus-stall.jsonl"
    write_events(events_path, events)

    summary = summarize_reader_events(profile, events_path)

    assert summary.readers_with_audio_progress == 3
    assert summary.per_reader_packet_rate_slo_pass is False
    assert "per_reader_track_packet_rate_below_minimum" in summary.invalid_reasons


def test_reader_summary_rejects_measurement_rtp_sequence_gap(tmp_path: Path) -> None:
    events_path = tmp_path / "readers.jsonl"
    events = successful_events()
    events[-1]["measurement_rtp_sequence_gaps"] = 1
    next(event for event in events if event["event"] == "reader_rtp_phase")[
        "measurement_video_rtp_sequence_gaps"
    ] = 1
    first_segment = next(event for event in events if event["event"] == "reader_rtp_segment")
    first_segment["sequence_expected_packets"] = 501
    first_segment["sequence_gaps"] = 1
    write_events(events_path, events)

    summary = summarize_reader_events(reader_profile(), events_path)

    assert summary.measurement_expected_rtp_packets == summary.observed_rtp_packets + 1
    assert summary.packet_loss_slo_pass is False
    assert "rtp_sequence_or_sent_received_mismatch" in summary.invalid_reasons


def test_reader_summary_attributes_error_to_failure_phase_timestamp(tmp_path: Path) -> None:
    profile = reader_profile()
    events = successful_events()
    measurement_start = measurement_start_unix_ms(profile, 2_000_000)
    path = next(
        str(event["path"])
        for event in events
        if event["event"] == "reader_started" and event["reader_id"] == 2
    )
    events.insert(
        -1,
        {
            "event": "reader_error",
            "reader_id": 2,
            "cycle": 0,
            "path": path,
            "at_monotonic_ms": measurement_start - 2_000_000 + 1,
            "reason": "gstreamer_error",
        },
    )
    events[-1]["failed_attempts"] = 1
    events_path = tmp_path / "measurement-error.jsonl"
    write_events(events_path, events)

    summary = summarize_reader_events(profile, events_path)

    assert summary.measurement_failed_establishments == 1
    assert summary.soak_failed_establishments == 0


def test_reader_summary_gates_soak_rtp_rate_separately(tmp_path: Path) -> None:
    raw = valid_profile()
    workload = raw["workload"]
    duration = raw["duration"]
    assert isinstance(workload, dict)
    assert isinstance(duration, dict)
    workload.update(total_readers=4, active_sources=2)
    duration["soak_seconds"] = 5
    profile = LoadProfile.model_validate(raw)
    events = successful_events()
    completion = events[-1]
    completion.update(
        profile_sha256=canonical_profile_bytes(profile)[1],
        scheduled_workload_end_unix_ms=workload_end_unix_ms(profile, 2_000_000),
        workload_end_unix_ms=workload_end_unix_ms(profile, 2_000_000),
        process_end_unix_ms=workload_end_unix_ms(profile, 2_000_000) + 100,
        rtp_packets=2500,
        measurement_rtp_packets=2000,
        soak_rtp_packets=500,
        measurement_rtp_sequence_gaps=0,
        soak_rtp_sequence_gaps=0,
    )
    for event in events:
        if event["event"] == "reader_rtp_phase":
            event["soak_video_rtp_packets"] = 125
            events.insert(
                -1,
                {
                    "event": "reader_rtp_segment",
                    "reader_id": event["reader_id"],
                    "cycle": 0,
                    "path": event["path"],
                    "track": "video",
                    "phase": "soak",
                    "first_at_monotonic_ms": measurement_end_unix_ms(profile, 2_000_000)
                    - 2_000_000,
                    "last_at_monotonic_ms": workload_end_unix_ms(profile, 2_000_000)
                    - 2_000_000
                    - 1,
                    "received_packets": 125,
                    "sequence_expected_packets": 125,
                    "sequence_gaps": 0,
                },
            )
    events_path = tmp_path / "soak-rate.jsonl"
    write_events(events_path, events)

    summary = summarize_reader_events(profile, events_path)

    assert summary.soak_observed_rtp_packets_per_second == 100
    assert summary.soak_packet_rate_slo_pass is True


def test_reader_summary_rejects_steady_disconnect_rate_deviation(tmp_path: Path) -> None:
    raw = valid_profile()
    workload = raw["workload"]
    lifecycle = raw["reader_lifecycle"]
    assert isinstance(workload, dict)
    assert isinstance(lifecycle, dict)
    workload.update(total_readers=4, connect_rate_per_second=10)
    workload["active_sources"] = 2
    lifecycle.update(
        mode="steady",
        disconnect_rate_per_second=10,
        reconnect_attempts=1,
        backoff_max_ms=1000,
    )
    duration = raw["duration"]
    assert isinstance(duration, dict)
    duration["warmup_seconds"] = 7
    profile = LoadProfile.model_validate(raw)
    events = successful_events()
    completion = events[-1]
    assert completion["event"] == "run_completed"
    lifecycle_epoch = lifecycle_start_unix_ms(profile, 2_000_000)
    completion.update(
        profile_sha256=canonical_profile_bytes(profile)[1],
        lifecycle_start_unix_ms=lifecycle_epoch,
        measurement_start_unix_ms=measurement_start_unix_ms(profile, 2_000_000),
        measurement_end_unix_ms=measurement_end_unix_ms(profile, 2_000_000),
        scheduled_workload_end_unix_ms=workload_end_unix_ms(profile, 2_000_000),
        workload_end_unix_ms=workload_end_unix_ms(profile, 2_000_000),
        process_end_unix_ms=workload_end_unix_ms(profile, 2_000_000) + 100,
        lifecycle_scheduled_slots=98,
        injected_disconnects=98,
    )
    paths = {
        event["reader_id"]: event["path"] for event in events if event["event"] == "reader_started"
    }
    events[-1:-1] = [
        {
            "event": "reader_disconnected",
            "reader_id": index % 4,
            "cycle": index + 1,
            "path": paths[index % 4],
            "at_monotonic_ms": 8000 + index * 100,
            "at_unix_ms": lifecycle_epoch + index * 100 + (400 if index == 1 else 0),
            "injected": True,
            "lifecycle_slot": index,
        }
        for index in range(98)
    ]
    events_path = tmp_path / "steady-rate.jsonl"
    write_events(events_path, events)

    summary = summarize_reader_events(profile, events_path)

    assert "steady_lifecycle_rate_deviation" in summary.invalid_reasons


def test_reader_summary_binds_completion_counts_to_each_shard(tmp_path: Path) -> None:
    raw = valid_profile()
    raw["generator_hosts"] = [
        {
            "name": "generator-a",
            "architecture": "arm64",
            "rtsp_host": "generator-a.load.internal",
            "rtsp_port": 8554,
            "source_start": 0,
            "source_count": 1,
        },
        {
            "name": "generator-b",
            "architecture": "amd64",
            "rtsp_host": "generator-b.load.internal",
            "rtsp_port": 8554,
            "source_start": 1,
            "source_count": 3,
        },
    ]
    profile = LoadProfile.model_validate(raw)
    plans = [build_proxy_reader_plan(profile, host.name) for host in profile.generator_hosts]
    targets = [target for plan in plans for target in plan.targets]
    paths = {
        reader_id: target.path
        for target in targets
        for reader_id in range(target.reader_id_start, target.reader_id_start + target.reader_count)
    }
    scheduled_start = 2_000_000
    events: list[dict[str, object]] = []
    for reader_id in range(profile.workload.total_readers):
        events.extend(
            [
                {
                    "event": "reader_started",
                    "reader_id": reader_id,
                    "cycle": 0,
                    "path": paths[reader_id],
                    "at_monotonic_ms": reader_id * 100,
                    "at_unix_ms": scheduled_start + reader_id * 100,
                },
                {
                    "event": "play_sent",
                    "reader_id": reader_id,
                    "cycle": 0,
                    "path": paths[reader_id],
                    "at_monotonic_ms": reader_id * 100 + 10,
                    "describe_to_play_ms": 10,
                },
                {
                    "event": "first_decodable_frame",
                    "reader_id": reader_id,
                    "cycle": 0,
                    "path": paths[reader_id],
                    "at_monotonic_ms": reader_id * 100 + 20,
                    "describe_to_first_decodable_ms": 20,
                    "play_to_first_decodable_ms": 10,
                    "access_unit": True,
                },
            ]
        )
    for index, (host, plan, reported_count) in enumerate(
        zip(profile.generator_hosts, plans, (6, 2), strict=True)
    ):
        plan_body = "".join(
            f"{target.path}\t{target.reader_count}\t{target.reader_id_start}\t"
            f"{target.warm_anchor_count}\t{target.measured_schedule_start}\n"
            for target in plan.targets
        ).encode("ascii")
        events.append(
            {
                "event": "run_completed",
                "at_monotonic_ms": 2000,
                "started_readers": reported_count,
                "ready_readers": reported_count,
                "failed_attempts": 0,
                "normal_completion": True,
                "interrupted": False,
                "lifecycle_complete": True,
                "exit_code": 0,
                "schedule_shard_index": index,
                "schedule_shards": 2,
                "generator_host": host.name,
                "profile_sha256": canonical_profile_bytes(profile)[1],
                "reader_plan_sha256": hashlib.sha256(plan_body).hexdigest(),
                "anchor_start_unix_ms": warm_anchor_start_unix_ms(profile, scheduled_start),
                "scheduled_start_unix_ms": scheduled_start,
                "ramp_end_unix_ms": ramp_end_unix_ms(profile, scheduled_start),
                "lifecycle_start_unix_ms": lifecycle_start_unix_ms(profile, scheduled_start),
                "measurement_start_unix_ms": measurement_start_unix_ms(profile, scheduled_start),
                "measurement_end_unix_ms": measurement_end_unix_ms(profile, scheduled_start),
                "scheduled_workload_end_unix_ms": workload_end_unix_ms(profile, scheduled_start),
                "process_start_unix_ms": warm_anchor_start_unix_ms(profile, scheduled_start) - 100,
                "workload_end_unix_ms": workload_end_unix_ms(profile, scheduled_start),
                "process_end_unix_ms": workload_end_unix_ms(profile, scheduled_start) + 100,
                "clock_synchronized": True,
                "clock_max_error_ms": 1,
                "lifecycle_scheduled_slots": 0,
                "injected_disconnects": 0,
                "rtp_packets": 1000,
                "measurement_rtp_packets": 1000,
                "soak_rtp_packets": 0,
                "measurement_rtp_sequence_gaps": 0,
                "soak_rtp_sequence_gaps": 0,
            }
        )
    path = tmp_path / "swapped-shard-counts.jsonl"
    write_events(path, events)

    summary = summarize_reader_events(profile, path)

    assert "reader_process_completion_missing_or_invalid" in summary.invalid_reasons


def test_outage_summary_binds_exact_cohort_to_common_epoch(tmp_path: Path) -> None:
    raw = valid_profile()
    workload = raw["workload"]
    lifecycle = raw["reader_lifecycle"]
    assert isinstance(workload, dict)
    assert isinstance(lifecycle, dict)
    workload["total_readers"] = 4
    workload["active_sources"] = 2
    lifecycle.update(
        mode="outage",
        reconnect_attempts=1,
        backoff_max_ms=1000,
        outage_percent=25,
    )
    duration = raw["duration"]
    assert isinstance(duration, dict)
    duration["warmup_seconds"] = 7
    profile = LoadProfile.model_validate(raw)
    lifecycle_epoch = lifecycle_start_unix_ms(profile, 2_000_000)

    def outage_events(*, lateness_ms: int) -> list[dict[str, object]]:
        events = successful_events()
        completion = events[-1]
        completion.update(
            profile_sha256=canonical_profile_bytes(profile)[1],
            lifecycle_start_unix_ms=lifecycle_epoch,
            measurement_start_unix_ms=measurement_start_unix_ms(profile, 2_000_000),
            measurement_end_unix_ms=measurement_end_unix_ms(profile, 2_000_000),
            scheduled_workload_end_unix_ms=workload_end_unix_ms(profile, 2_000_000),
            workload_end_unix_ms=workload_end_unix_ms(profile, 2_000_000),
            process_end_unix_ms=workload_end_unix_ms(profile, 2_000_000) + 100,
            lifecycle_scheduled_slots=1,
            injected_disconnects=1,
        )
        expected_reader_id = profile.seed % profile.workload.total_readers
        expected_reader = next(
            event
            for event in events
            if event["event"] == "reader_started" and event["reader_id"] == expected_reader_id
        )
        path = expected_reader["path"]
        reconnect_backoff_ms = injected_reconnect_backoff_ms(
            profile,
            expected_reader_id,
            0,
        )
        reconnect_at = lifecycle_epoch + reconnect_backoff_ms
        reconnect_monotonic_ms = reconnect_at - 2_000_000
        for segment in events:
            if segment["event"] == "reader_rtp_segment":
                segment["first_at_monotonic_ms"] = lifecycle_epoch - 2_000_000
                segment["last_at_monotonic_ms"] = (
                    measurement_end_unix_ms(profile, 2_000_000) - 2_000_001
                )
            elif segment["event"] == "reader_rtp_phase":
                segment["at_monotonic_ms"] = workload_end_unix_ms(profile, 2_000_000) - 2_000_000
        replacement_segment = next(
            event
            for event in events
            if event["event"] == "reader_rtp_segment" and event["reader_id"] == expected_reader_id
        )
        replacement_segment.update(
            cycle=1,
            first_at_monotonic_ms=reconnect_monotonic_ms + 200,
        )
        events[-1:-1] = [
            {
                "event": "reader_disconnected",
                "reader_id": expected_reader_id,
                "cycle": 0,
                "path": path,
                "at_monotonic_ms": lifecycle_epoch - 2_000_000,
                "at_unix_ms": lifecycle_epoch + lateness_ms,
                "injected": True,
                "lifecycle_slot": 0,
            },
            {
                "event": "reconnect_scheduled",
                "reader_id": expected_reader_id,
                "cycle": 0,
                "path": path,
                "at_monotonic_ms": lifecycle_epoch - 2_000_000,
                "backoff_ms": reconnect_backoff_ms,
            },
            {
                "event": "reader_started",
                "reader_id": expected_reader_id,
                "cycle": 1,
                "path": path,
                "at_monotonic_ms": reconnect_monotonic_ms,
                "at_unix_ms": reconnect_at,
            },
            {
                "event": "play_sent",
                "reader_id": expected_reader_id,
                "cycle": 1,
                "path": path,
                "at_monotonic_ms": reconnect_monotonic_ms + 100,
                "describe_to_play_ms": 100,
            },
            {
                "event": "first_decodable_frame",
                "reader_id": expected_reader_id,
                "cycle": 1,
                "path": path,
                "at_monotonic_ms": reconnect_monotonic_ms + 200,
                "describe_to_first_decodable_ms": 200,
                "play_to_first_decodable_ms": 100,
                "access_unit": True,
            },
        ]
        return events

    valid_path = tmp_path / "outage-valid.jsonl"
    late_path = tmp_path / "outage-late.jsonl"
    write_events(valid_path, outage_events(lateness_ms=0))
    write_events(late_path, outage_events(lateness_ms=251))

    assert summarize_reader_events(profile, valid_path).valid is True
    assert (
        "outage_lifecycle_epoch_deviation"
        in summarize_reader_events(profile, late_path).invalid_reasons
    )

    wrong_backoff = outage_events(lateness_ms=0)
    reconnect = next(event for event in wrong_backoff if event["event"] == "reconnect_scheduled")
    reported_backoff = reconnect["backoff_ms"]
    assert isinstance(reported_backoff, int)
    reconnect["backoff_ms"] = reported_backoff + 1
    wrong_backoff_path = tmp_path / "outage-wrong-backoff.jsonl"
    write_events(wrong_backoff_path, wrong_backoff)
    assert (
        "reader_reconnect_chain_invalid"
        in summarize_reader_events(profile, wrong_backoff_path).invalid_reasons
    )

    missing_play = outage_events(lateness_ms=0)
    missing_play.remove(
        next(
            event for event in missing_play if event["event"] == "play_sent" and event["cycle"] == 1
        )
    )
    missing_play_path = tmp_path / "outage-missing-play.jsonl"
    write_events(missing_play_path, missing_play)
    assert (
        "reader_reconnect_chain_invalid"
        in summarize_reader_events(profile, missing_play_path).invalid_reasons
    )

    incomplete = outage_events(lateness_ms=0)
    incomplete[-1].update(lifecycle_scheduled_slots=0, injected_disconnects=0)
    incomplete_path = tmp_path / "outage-incomplete.jsonl"
    write_events(incomplete_path, incomplete)
    assert (
        "outage_lifecycle_cohort_incomplete"
        in summarize_reader_events(profile, incomplete_path).invalid_reasons
    )

    wrong_cohort = outage_events(lateness_ms=0)
    disconnect = next(event for event in wrong_cohort if event["event"] == "reader_disconnected")
    original_reader_id = disconnect["reader_id"]
    assert isinstance(original_reader_id, int)
    disconnect["reader_id"] = (original_reader_id + 1) % 4
    disconnect["path"] = next(
        event["path"]
        for event in wrong_cohort
        if event["event"] == "reader_started" and event["reader_id"] == disconnect["reader_id"]
    )
    wrong_cohort_path = tmp_path / "outage-wrong-cohort.jsonl"
    write_events(wrong_cohort_path, wrong_cohort)
    assert (
        "outage_lifecycle_cohort_incomplete"
        in summarize_reader_events(profile, wrong_cohort_path).invalid_reasons
    )

    late_ready = outage_events(lateness_ms=0)
    last_initial_frame = next(
        event
        for event in late_ready
        if event["event"] == "first_decodable_frame" and event["reader_id"] == 3
    )
    last_initial_frame["at_monotonic_ms"] = lifecycle_epoch - 2_000_000 + 1
    late_ready_path = tmp_path / "outage-late-ready.jsonl"
    write_events(late_ready_path, late_ready)
    assert (
        "lifecycle_readiness_deadline_missed"
        in summarize_reader_events(profile, late_ready_path).invalid_reasons
    )

    unexpected = successful_events()
    unexpected[-1].update(lifecycle_scheduled_slots=1, injected_disconnects=1)
    unexpected[-1:-1] = [
        {
            "event": "reader_disconnected",
            "reader_id": 0,
            "cycle": 0,
            "path": unexpected[0]["path"],
            "at_monotonic_ms": 8000,
            "at_unix_ms": lifecycle_epoch,
            "injected": True,
            "lifecycle_slot": 0,
        }
    ]
    unexpected_path = tmp_path / "single-unexpected-lifecycle.jsonl"
    write_events(unexpected_path, unexpected)
    assert (
        "unexpected_lifecycle_disconnects"
        in summarize_reader_events(reader_profile(), unexpected_path).invalid_reasons
    )


def test_reader_summary_rejects_reader_id_path_mismatch(tmp_path: Path) -> None:
    events_path = tmp_path / "readers.jsonl"
    events = successful_events()
    wrong_path = next(
        event["path"]
        for event in events
        if event.get("reader_id") == 0 and event.get("event") == "reader_started"
    )
    for event in events:
        if event.get("reader_id") == 3:
            event["path"] = wrong_path
    write_events(events_path, events)

    summary = summarize_reader_events(reader_profile(), events_path)

    assert summary.valid is False
    assert "reader_path_plan_mismatch" in summary.invalid_reasons


def test_reader_errors_and_missing_decodable_frame_invalidate_run(tmp_path: Path) -> None:
    events_path = tmp_path / "readers.jsonl"
    events = [
        event
        for event in successful_events()
        if event["event"] != "run_completed" and event.get("reader_id") != 3
    ]
    expected_path = next(
        event["path"]
        for event in successful_events()
        if event.get("reader_id") == 3 and event.get("event") == "reader_started"
    )
    failed_completion = dict(successful_events()[-1])
    failed_completion.update(
        ready_readers=3,
        failed_attempts=1,
        exit_code=6,
        rtp_packets=1600,
        measurement_rtp_packets=1600,
        soak_rtp_packets=0,
        measurement_rtp_sequence_gaps=0,
        soak_rtp_sequence_gaps=0,
    )
    events.extend(
        [
            {
                "event": "reader_started",
                "reader_id": 3,
                "cycle": 0,
                "path": expected_path,
                "at_monotonic_ms": 300,
                "at_unix_ms": 2_000_300,
            },
            failed_completion,
            {
                "event": "reader_error",
                "reader_id": 3,
                "cycle": 0,
                "path": expected_path,
                "at_monotonic_ms": 350,
                "reason": "gstreamer_error",
            },
        ]
    )
    write_events(events_path, events)

    summary = summarize_reader_events(reader_profile(), events_path)

    assert summary.valid is False
    assert summary.decodable_establishments == 3
    assert summary.failed_establishments == 1
    assert summary.establishment_success_percent == 75
    assert {
        "session_establishment_below_99_9_percent",
        "reader_errors_observed",
        "reader_process_completion_missing_or_invalid",
        "reader_rtp_phase_set_incomplete",
    }.issubset(summary.invalid_reasons)


def test_cold_latency_requires_compatible_direct_control_decomposition(
    tmp_path: Path,
) -> None:
    proxy_events = tmp_path / "proxy.jsonl"
    direct_events = tmp_path / "direct.jsonl"
    write_events(
        proxy_events,
        successful_events(temperature="cold", handshake_offset_ms=200, decodable_offset_ms=900),
    )
    write_events(
        direct_events,
        successful_events(endpoint_mode="direct-control", temperature="cold"),
    )
    proxy_profile = reader_profile(temperature="cold")
    direct_profile = reader_profile(temperature="cold", endpoint_mode="direct-control")

    standalone = summarize_reader_events(proxy_profile, proxy_events)
    comparison = summarize_cold_comparison(
        proxy_profile,
        proxy_events,
        direct_profile,
        direct_events,
        direct_final_manifest_sha256="a" * 64,
    )

    assert standalone.latency_slo_pass is None
    assert standalone.latency_gate == "requires_direct_control_decomposition"
    assert comparison.compared_establishments == 4
    assert comparison.proxy_overhead_p99_ms == 200
    assert comparison.proxy_wait_for_decodable_p99_ms == 1400
    assert comparison.direct_wait_for_decodable_p99_ms == 500
    assert comparison.proxy_overhead_slo_pass is True
    assert comparison.valid is True


def test_cold_comparison_rejects_incompatible_profiles(tmp_path: Path) -> None:
    proxy_events = tmp_path / "proxy.jsonl"
    direct_events = tmp_path / "direct.jsonl"
    write_events(proxy_events, successful_events(temperature="cold"))
    write_events(
        direct_events,
        successful_events(endpoint_mode="direct-control", temperature="cold"),
    )
    proxy_profile = reader_profile(temperature="cold")
    incompatible_raw = valid_profile()
    workload = incompatible_raw["workload"]
    fixture = incompatible_raw["fixture"]
    assert isinstance(workload, dict)
    assert isinstance(fixture, dict)
    workload.update(
        total_readers=4,
        session_temperature="cold",
        endpoint_mode="direct-control",
    )
    fixture["gop_frames"] = 100
    incompatible = LoadProfile.model_validate(incompatible_raw)

    with pytest.raises(ValueError, match="comparison_profiles_differ"):
        summarize_cold_comparison(
            proxy_profile,
            proxy_events,
            incompatible,
            direct_events,
            direct_final_manifest_sha256="a" * 64,
        )


def test_reader_summary_cli_writes_exclusive_machine_readable_result(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    profile = reader_profile()
    run_directory = tmp_path / "run"
    initialize_run_directory(profile, run_directory)
    first_events = run_directory / "readers-a.jsonl"
    second_events = run_directory / "readers-b.jsonl"
    all_events = successful_events()
    write_events(
        first_events,
        [
            event
            for event in all_events
            if event["event"] == "run_completed" or event.get("reader_id") in {0, 2}
        ],
    )
    write_events(
        second_events,
        [
            event
            for event in all_events
            if event["event"] != "run_completed" and event.get("reader_id") in {1, 3}
        ],
    )
    events_path = run_directory / "readers.jsonl"
    assert (
        load_cli_main(
            [
                "merge-readers",
                str(run_directory),
                str(events_path),
                str(first_events),
                str(second_events),
            ]
        )
        == 0
    )
    merge_output = capsys.readouterr()
    assert merge_output.out.startswith("MERGED_READERS events=21")
    output_path = run_directory / "summary.json"

    assert (
        load_cli_main(
            [
                "summarize-readers",
                str(run_directory),
                str(events_path),
                str(output_path),
            ]
        )
        == 0
    )
    output = capsys.readouterr()
    assert output.err == ""
    assert output.out.startswith("SUMMARIZED_READERS")
    assert json.loads(output_path.read_text(encoding="utf-8"))["latency_slo_pass"] is True
