from __future__ import annotations

import hashlib
from pathlib import Path
from uuid import UUID

import pytest

from rtsp_proxy.load_control import (
    ControlWorkloadEvent,
    load_control_events,
    summarize_control_events,
)
from rtsp_proxy.load_profile import EvidenceSampling, LoadProfile, WorkloadAxes

START = 4_102_444_800_000


def _profile(*, probe_rate: float = 0.2, crud_rate: float = 0.1) -> LoadProfile:
    workload = WorkloadAxes(
        endpoint_mode="proxy",
        session_temperature="cold",
        registered_paths=1,
        active_sources=1,
        total_readers=1,
        connect_rate_per_second=1,
        minimum_rtp_packets_per_second=1,
        probe_rate_per_second=probe_rate,
        crud_rate_per_second=crud_rate,
    )
    sampling = EvidenceSampling(
        interval_seconds=1,
        maximum_gap_factor=1.5,
        maximum_clock_error_ms=10,
        maximum_start_lateness_ms=250,
    )
    return LoadProfile.model_construct(workload=workload, evidence_sampling=sampling)


def _event(
    sequence: int,
    *,
    operation: str,
    scheduled_at: int,
    outcome: str = "success",
    status_code: int = 200,
) -> ControlWorkloadEvent:
    return ControlWorkloadEvent.model_validate(
        {
            "schema_version": 1,
            "request_id": UUID(f"00000000-0000-4000-8000-{sequence:012d}"),
            "operation": operation,
            "target_sha256": hashlib.sha256(f"target-{sequence}".encode()).hexdigest(),
            "scheduled_at_unix_ms": scheduled_at,
            "started_at_unix_ms": scheduled_at + 10,
            "completed_at_unix_ms": scheduled_at + 50,
            "outcome": outcome,
            "status_code": status_code,
            "reason_code": None if outcome == "success" else "request_failed",
        }
    )


def test_nonzero_control_axes_have_reproducible_rate_and_latency_evidence() -> None:
    events = (
        _event(1, operation="probe", scheduled_at=START + 1_000),
        _event(2, operation="crud", scheduled_at=START + 2_000),
        _event(3, operation="probe", scheduled_at=START + 6_000),
    )
    summary = summarize_control_events(
        _profile(),
        events,
        events_sha256="a" * 64,
        measurement_start_unix_ms=START,
        workload_end_unix_ms=START + 10_000,
    )

    assert summary.valid is True
    assert summary.invalid_reasons == ()
    assert summary.probe.observed_count == 2
    assert summary.probe.observed_rate_per_second == 0.2
    assert summary.crud.observed_count == 1
    assert summary.crud.p99_completion_ms == 40


def test_control_summary_keeps_failures_and_rate_misses_in_the_verdict() -> None:
    events = (
        _event(
            1,
            operation="probe",
            scheduled_at=START + 1_000,
            outcome="failed",
            status_code=503,
        ),
        _event(2, operation="crud", scheduled_at=START + 2_000),
    )
    summary = summarize_control_events(
        _profile(),
        events,
        events_sha256="b" * 64,
        measurement_start_unix_ms=START,
        workload_end_unix_ms=START + 10_000,
    )

    assert summary.valid is False
    assert summary.probe.failed_count == 1
    assert summary.probe.success_percent == 0
    assert summary.invalid_reasons == (
        "control_probe_rate_outside_profile",
        "control_probe_success_below_99_9_percent",
    )


def test_control_event_loader_rejects_duplicate_ids_and_window_escape(
    tmp_path: Path,
) -> None:
    event = _event(1, operation="probe", scheduled_at=START + 1_000)
    events_path = tmp_path / "control.jsonl"
    line = event.model_dump_json() + "\n"
    events_path.write_text(line + line, encoding="utf-8")
    with pytest.raises(ValueError, match="control_event_request_id_duplicate"):
        load_control_events(events_path)

    with pytest.raises(ValueError, match="control_event_outside_workload_window"):
        summarize_control_events(
            _profile(probe_rate=0.1, crud_rate=0),
            (event.model_copy(update={"scheduled_at_unix_ms": START - 1}),),
            events_sha256="c" * 64,
            measurement_start_unix_ms=START,
            workload_end_unix_ms=START + 10_000,
        )


def test_control_event_rejects_secret_shaped_or_inconsistent_result_fields() -> None:
    payload = _event(
        1,
        operation="crud",
        scheduled_at=START + 1_000,
    ).model_dump(mode="json")
    payload["reason_code"] = "rtsp://user:password@example.invalid/private"
    with pytest.raises(ValueError):
        ControlWorkloadEvent.model_validate(payload)

    payload["reason_code"] = "request_failed"
    with pytest.raises(ValueError, match="control_event_success_reason_present"):
        ControlWorkloadEvent.model_validate(payload)
