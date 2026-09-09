from __future__ import annotations

import hashlib
from pathlib import Path
from uuid import UUID, uuid1

import pytest

from rtsp_proxy.load_control import (
    ControlOperationSummary,
    ControlWorkloadEvent,
    ControlWorkloadSummary,
    load_control_events,
    sha256_file,
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


@pytest.mark.parametrize(
    ("update", "reason"),
    [
        ({"request_id": uuid1()}, "control_event_request_id_not_uuid4"),
        ({"started_at_unix_ms": START - 1}, "control_event_timing_invalid"),
        ({"outcome": "failed", "status_code": 200, "reason_code": "failed"},
         "control_event_status_outcome_mismatch"),
        ({"outcome": "failed", "status_code": 503, "reason_code": None},
         "control_event_failure_reason_missing"),
    ],
)
def test_control_event_rejects_identity_timing_and_result_contradictions(
    update: dict[str, object],
    reason: str,
) -> None:
    payload = _event(1, operation="probe", scheduled_at=START).model_dump(mode="json")
    payload.update(update)
    with pytest.raises(ValueError, match=reason):
        ControlWorkloadEvent.model_validate(payload)


def test_control_loader_and_summary_reject_empty_or_unreproducible_evidence(
    tmp_path: Path,
) -> None:
    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="control_events_empty"):
        load_control_events(empty)

    invalid = tmp_path / "invalid.jsonl"
    invalid.write_text("not-json\n", encoding="utf-8")
    with pytest.raises(ValueError, match="control_event_invalid"):
        load_control_events(invalid)
    with pytest.raises(ValueError, match="control_events_file_invalid"):
        load_control_events(tmp_path)

    event = _event(1, operation="probe", scheduled_at=START + 1_000)
    with pytest.raises(ValueError, match="control_summary_input_invalid"):
        summarize_control_events(
            _profile(),
            (event,),
            events_sha256="not-a-digest",
            measurement_start_unix_ms=START,
            workload_end_unix_ms=START + 10_000,
        )
    assert sha256_file(empty) == hashlib.sha256(b"").hexdigest()


def test_control_summary_gates_probe_lateness_and_crud_completion() -> None:
    probe = _event(1, operation="probe", scheduled_at=START + 1_000).model_copy(
        update={
            "started_at_unix_ms": START + 1_400,
            "completed_at_unix_ms": START + 1_450,
        }
    )
    crud = _event(2, operation="crud", scheduled_at=START + 2_000).model_copy(
        update={"completed_at_unix_ms": START + 3_100}
    )
    summary = summarize_control_events(
        _profile(probe_rate=0.1, crud_rate=0.1),
        (probe, crud),
        events_sha256="d" * 64,
        measurement_start_unix_ms=START,
        workload_end_unix_ms=START + 10_000,
    )
    assert summary.valid is False
    assert summary.invalid_reasons == (
        "control_crud_p99_above_one_second",
        "control_probe_start_lateness_above_profile",
    )


def test_control_summary_models_reject_inconsistent_derived_values() -> None:
    operation: dict[str, object] = {
        "expected_rate_per_second": 0,
        "expected_minimum_count": 0,
        "expected_maximum_count": 0,
        "observed_count": 1,
        "success_count": 0,
        "rejected_count": 0,
        "failed_count": 0,
        "observed_rate_per_second": 0,
        "success_percent": 0,
        "p99_start_lateness_ms": 0,
        "p99_completion_ms": 0,
    }
    with pytest.raises(ValueError, match="control_summary_counts_invalid"):
        ControlOperationSummary.model_validate(operation)

    valid_operation = dict(operation)
    valid_operation.update({"observed_count": 0, "p99_start_lateness_ms": None,
                            "p99_completion_ms": None})
    with pytest.raises(ValueError, match="control_summary_invalid"):
        ControlWorkloadSummary.model_validate(
            {
                "schema_version": 1,
                "events_sha256": "e" * 64,
                "measurement_start_unix_ms": START,
                "workload_end_unix_ms": START + 1_000,
                "probe": valid_operation,
                "crud": valid_operation,
                "valid": True,
                "invalid_reasons": ("failure",),
            }
        )
