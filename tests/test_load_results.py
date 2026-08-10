from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from rtsp_proxy.load_catalog import build_direct_reader_plan, build_proxy_reader_plan
from rtsp_proxy.load_cli import main as load_cli_main
from rtsp_proxy.load_profile import LoadProfile, canonical_profile_bytes, initialize_run_directory
from rtsp_proxy.load_results import (
    ReaderEvent,
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
    plan_body = "".join(
        f"{target.path}\t{target.reader_count}\t{target.reader_id_start}\n"
        for target in plan.targets
    ).encode("ascii")
    for reader_id, base_handshake_ms in enumerate((100, 200, 300, 400)):
        handshake_ms = base_handshake_ms + handshake_offset_ms
        path = expected_paths[reader_id]
        events.extend(
            [
                {
                    "event": "reader_started",
                    "reader_id": reader_id,
                    "cycle": 0,
                    "path": path,
                    "at_monotonic_ms": reader_id * 100,
                    "at_unix_ms": schedule_start_unix_ms + reader_id * 100,
                },
                {
                    "event": "play_sent",
                    "reader_id": reader_id,
                    "cycle": 0,
                    "path": path,
                    "at_monotonic_ms": reader_id * 100 + handshake_ms,
                    "describe_to_play_ms": handshake_ms,
                },
                {
                    "event": "first_decodable_frame",
                    "reader_id": reader_id,
                    "cycle": 0,
                    "path": path,
                    "at_monotonic_ms": reader_id * 100 + handshake_ms + 500,
                    "describe_to_first_decodable_ms": handshake_ms + 500 + decodable_offset_ms,
                    "play_to_first_decodable_ms": 500 + decodable_offset_ms,
                },
            ]
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
            "scheduled_start_unix_ms": schedule_start_unix_ms,
            "process_start_unix_ms": schedule_start_unix_ms - 100,
            "process_end_unix_ms": schedule_start_unix_ms + 1000,
            "clock_synchronized": True,
            "clock_max_error_ms": 1,
            "rtp_packets": 1000,
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
        rtp_packets=750,
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
    assert summary.invalid_reasons == (
        "session_establishment_below_99_9_percent",
        "reader_errors_observed",
        "reader_process_completion_missing_or_invalid",
    )


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
    assert merge_output.out.startswith("MERGED_READERS events=13")
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
