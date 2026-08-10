from __future__ import annotations

import json
from pathlib import Path

import pytest

from rtsp_proxy.load_cli import main as load_cli_main
from rtsp_proxy.load_profile import LoadProfile
from rtsp_proxy.load_results import summarize_reader_events
from tests.test_load_profile import valid_profile


def reader_profile(*, temperature: str = "warm") -> LoadProfile:
    raw = valid_profile()
    workload = raw["workload"]
    assert isinstance(workload, dict)
    workload["total_readers"] = 4
    workload["session_temperature"] = temperature
    return LoadProfile.model_validate(raw)


def write_events(path: Path, events: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )


def successful_events() -> list[dict[str, object]]:
    return [
        {
            "event": "first_packet",
            "reader_id": reader_id,
            "path": "a" * 25,
            "latency_ms": latency_ms,
        }
        for reader_id, latency_ms in enumerate((100, 200, 300, 400))
    ]


def test_warm_reader_summary_applies_p99_and_success_gates(tmp_path: Path) -> None:
    events_path = tmp_path / "readers.jsonl"
    write_events(events_path, successful_events())

    summary = summarize_reader_events(reader_profile(), events_path)

    assert summary.valid is True
    assert summary.invalid_reasons == ()
    assert summary.expected_readers == 4
    assert summary.first_packet_readers == 4
    assert summary.establishment_success_percent == 100
    assert summary.latency_p50_ms == 200
    assert summary.latency_p95_ms == 400
    assert summary.latency_p99_ms == 400
    assert summary.latency_slo_ms == 500
    assert summary.latency_slo_pass is True


def test_reader_errors_and_missing_first_packet_invalidate_run(tmp_path: Path) -> None:
    events_path = tmp_path / "readers.jsonl"
    events = successful_events()[:3]
    events.append(
        {
            "event": "reader_error",
            "reader_id": 3,
            "path": "a" * 25,
            "reason": "gstreamer_error",
        }
    )
    write_events(events_path, events)

    summary = summarize_reader_events(reader_profile(), events_path)

    assert summary.valid is False
    assert summary.first_packet_readers == 3
    assert summary.failed_readers == 1
    assert summary.establishment_success_percent == 75
    assert summary.invalid_reasons == (
        "session_establishment_below_99_9_percent",
        "reader_errors_observed",
    )


def test_cold_latency_is_not_claimed_without_direct_control_decomposition(
    tmp_path: Path,
) -> None:
    events_path = tmp_path / "readers.jsonl"
    write_events(events_path, successful_events())

    summary = summarize_reader_events(
        reader_profile(temperature="cold"), events_path
    )

    assert summary.valid is True
    assert summary.latency_slo_ms is None
    assert summary.latency_slo_pass is None
    assert summary.latency_gate == "requires_direct_control_decomposition"


def test_reader_summary_cli_emits_machine_readable_result(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    raw_profile = valid_profile()
    workload = raw_profile["workload"]
    assert isinstance(workload, dict)
    workload["total_readers"] = 4
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(json.dumps(raw_profile), encoding="utf-8")
    events_path = tmp_path / "readers.jsonl"
    write_events(events_path, successful_events())

    assert (
        load_cli_main(["summarize-readers", str(profile_path), str(events_path)])
        == 0
    )
    output = capsys.readouterr()
    assert output.err == ""
    assert json.loads(output.out)["latency_slo_pass"] is True
