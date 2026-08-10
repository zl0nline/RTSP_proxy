from __future__ import annotations

import json
from pathlib import Path

import pytest

from rtsp_proxy.load_cli import main as load_cli_main
from rtsp_proxy.load_profile import LoadProfile, initialize_run_directory
from rtsp_proxy.load_results import summarize_cold_comparison, summarize_reader_events
from tests.test_load_profile import valid_profile


def reader_profile(
    *, temperature: str = "warm", endpoint_mode: str = "proxy"
) -> LoadProfile:
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


def successful_events(*, decodable_offset_ms: float = 0) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    for reader_id, handshake_ms in enumerate((100, 200, 300, 400)):
        path = "a" * 25
        events.extend(
            [
                {
                    "event": "reader_started",
                    "reader_id": reader_id,
                    "cycle": 0,
                    "path": path,
                    "at_monotonic_ms": reader_id * 100,
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
                    "describe_to_first_decodable_ms": handshake_ms
                    + 500
                    + decodable_offset_ms,
                    "play_to_first_decodable_ms": 500 + decodable_offset_ms,
                },
            ]
        )
    return events


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


def test_reader_errors_and_missing_decodable_frame_invalidate_run(tmp_path: Path) -> None:
    events_path = tmp_path / "readers.jsonl"
    events = successful_events()[:-3]
    events.extend(
        [
            {
                "event": "reader_started",
                "reader_id": 3,
                "cycle": 0,
                "path": "a" * 25,
                "at_monotonic_ms": 300,
            },
            {
                "event": "reader_error",
                "reader_id": 3,
                "cycle": 0,
                "path": "a" * 25,
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
    )


def test_cold_latency_requires_compatible_direct_control_decomposition(
    tmp_path: Path,
) -> None:
    proxy_events = tmp_path / "proxy.jsonl"
    direct_events = tmp_path / "direct.jsonl"
    write_events(proxy_events, successful_events(decodable_offset_ms=200))
    write_events(direct_events, successful_events())
    proxy_profile = reader_profile(temperature="cold")
    direct_profile = reader_profile(
        temperature="cold", endpoint_mode="direct-control"
    )

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
    assert comparison.proxy_overhead_slo_pass is True
    assert comparison.valid is True


def test_cold_comparison_rejects_incompatible_profiles(tmp_path: Path) -> None:
    proxy_events = tmp_path / "proxy.jsonl"
    direct_events = tmp_path / "direct.jsonl"
    write_events(proxy_events, successful_events())
    write_events(direct_events, successful_events())
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
    events_path = run_directory / "readers.jsonl"
    write_events(events_path, successful_events())
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
