from __future__ import annotations

import hashlib
import math
import stat
from pathlib import Path
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from rtsp_proxy.load_profile import LoadProfile

Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
ReasonCode = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,63}$"),
]

_MAX_CONTROL_EVENTS = 2_000_000


class ControlWorkloadEvent(BaseModel):
    """One secret-free externally observed control-plane workload operation."""

    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    schema_version: Literal[1]
    request_id: UUID
    operation: Literal["probe", "crud"]
    target_sha256: Sha256
    scheduled_at_unix_ms: Annotated[int, Field(gt=0)]
    started_at_unix_ms: Annotated[int, Field(gt=0)]
    completed_at_unix_ms: Annotated[int, Field(gt=0)]
    outcome: Literal["success", "rejected", "failed"]
    status_code: Annotated[int, Field(ge=100, le=599)]
    reason_code: ReasonCode | None = None

    @model_validator(mode="after")
    def validate_operation_result(self) -> Self:
        if self.request_id.version != 4:
            raise ValueError("control_event_request_id_not_uuid4")
        if (
            self.started_at_unix_ms < self.scheduled_at_unix_ms
            or self.completed_at_unix_ms < self.started_at_unix_ms
            or self.completed_at_unix_ms - self.scheduled_at_unix_ms > 60_000
        ):
            raise ValueError("control_event_timing_invalid")
        success_status = 200 <= self.status_code < 300
        if (self.outcome == "success") != success_status:
            raise ValueError("control_event_status_outcome_mismatch")
        if self.outcome != "success" and self.reason_code is None:
            raise ValueError("control_event_failure_reason_missing")
        if self.outcome == "success" and self.reason_code is not None:
            raise ValueError("control_event_success_reason_present")
        return self


class ControlOperationSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    expected_rate_per_second: Annotated[float, Field(ge=0, le=10)]
    expected_minimum_count: Annotated[int, Field(ge=0)]
    expected_maximum_count: Annotated[int, Field(ge=0)]
    observed_count: Annotated[int, Field(ge=0)]
    success_count: Annotated[int, Field(ge=0)]
    rejected_count: Annotated[int, Field(ge=0)]
    failed_count: Annotated[int, Field(ge=0)]
    observed_rate_per_second: Annotated[float, Field(ge=0)]
    success_percent: Annotated[float, Field(ge=0, le=100)]
    p99_start_lateness_ms: Annotated[float, Field(ge=0)] | None
    p99_completion_ms: Annotated[float, Field(ge=0)] | None

    @model_validator(mode="after")
    def validate_counts(self) -> Self:
        if (
            self.expected_maximum_count < self.expected_minimum_count
            or self.success_count + self.rejected_count + self.failed_count != self.observed_count
            or (self.observed_count == 0)
            != (self.p99_start_lateness_ms is None or self.p99_completion_ms is None)
        ):
            raise ValueError("control_summary_counts_invalid")
        return self


class ControlWorkloadSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    schema_version: Literal[1]
    events_sha256: Sha256
    measurement_start_unix_ms: Annotated[int, Field(gt=0)]
    workload_end_unix_ms: Annotated[int, Field(gt=0)]
    probe: ControlOperationSummary
    crud: ControlOperationSummary
    valid: bool
    invalid_reasons: tuple[ReasonCode, ...]

    @model_validator(mode="after")
    def validate_window_and_verdict(self) -> Self:
        if (
            self.workload_end_unix_ms <= self.measurement_start_unix_ms
            or tuple(sorted(set(self.invalid_reasons))) != self.invalid_reasons
            or self.valid == bool(self.invalid_reasons)
        ):
            raise ValueError("control_summary_invalid")
        return self


def load_control_events(path: Path) -> tuple[ControlWorkloadEvent, ...]:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 256 * 1024 * 1024:
        raise ValueError("control_events_file_invalid")
    events: list[ControlWorkloadEvent] = []
    seen: set[UUID] = set()
    with path.open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if line_number > _MAX_CONTROL_EVENTS:
                raise ValueError("control_event_count_exceeds_limit")
            try:
                event = ControlWorkloadEvent.model_validate_json(line)
            except ValueError:
                raise ValueError("control_event_invalid") from None
            if event.request_id in seen:
                raise ValueError("control_event_request_id_duplicate")
            seen.add(event.request_id)
            events.append(event)
    if not events:
        raise ValueError("control_events_empty")
    return tuple(events)


def summarize_control_events(
    profile: LoadProfile,
    events: tuple[ControlWorkloadEvent, ...],
    *,
    events_sha256: str,
    measurement_start_unix_ms: int,
    workload_end_unix_ms: int,
) -> ControlWorkloadSummary:
    if (
        len(events_sha256) != 64
        or any(character not in "0123456789abcdef" for character in events_sha256)
        or workload_end_unix_ms <= measurement_start_unix_ms
        or len({event.request_id for event in events}) != len(events)
    ):
        raise ValueError("control_summary_input_invalid")
    if any(
        event.scheduled_at_unix_ms < measurement_start_unix_ms
        or event.completed_at_unix_ms > workload_end_unix_ms
        for event in events
    ):
        raise ValueError("control_event_outside_workload_window")

    duration_seconds = (workload_end_unix_ms - measurement_start_unix_ms) / 1000
    summaries: dict[str, ControlOperationSummary] = {}
    invalid: list[str] = []
    for operation, expected_rate in (
        ("probe", profile.workload.probe_rate_per_second),
        ("crud", profile.workload.crud_rate_per_second),
    ):
        selected = tuple(event for event in events if event.operation == operation)
        expected = expected_rate * duration_seconds
        minimum = 0 if expected_rate == 0 else max(1, math.ceil(expected * 0.99))
        maximum = 0 if expected_rate == 0 else max(1, math.floor(expected * 1.01) + 1)
        outcome_counts = {
            outcome: sum(event.outcome == outcome for event in selected)
            for outcome in ("success", "rejected", "failed")
        }
        success_percent = (
            100.0
            if not selected and expected_rate == 0
            else outcome_counts["success"] / len(selected) * 100
            if selected
            else 0.0
        )
        start_lateness = tuple(
            event.started_at_unix_ms - event.scheduled_at_unix_ms for event in selected
        )
        completion = tuple(
            event.completed_at_unix_ms - event.started_at_unix_ms for event in selected
        )
        summary = ControlOperationSummary(
            expected_rate_per_second=expected_rate,
            expected_minimum_count=minimum,
            expected_maximum_count=maximum,
            observed_count=len(selected),
            success_count=outcome_counts["success"],
            rejected_count=outcome_counts["rejected"],
            failed_count=outcome_counts["failed"],
            observed_rate_per_second=len(selected) / duration_seconds,
            success_percent=success_percent,
            p99_start_lateness_ms=_nearest_rank_p99(start_lateness),
            p99_completion_ms=_nearest_rank_p99(completion),
        )
        summaries[operation] = summary
        if not minimum <= len(selected) <= maximum:
            invalid.append(f"control_{operation}_rate_outside_profile")
        if success_percent < 99.9:
            invalid.append(f"control_{operation}_success_below_99_9_percent")
        if (
            operation == "crud"
            and summary.p99_completion_ms is not None
            and summary.p99_completion_ms > 1000
        ):
            invalid.append("control_crud_p99_above_one_second")
        if (
            operation == "probe"
            and summary.p99_start_lateness_ms is not None
            and summary.p99_start_lateness_ms > profile.evidence_sampling.maximum_start_lateness_ms
        ):
            invalid.append("control_probe_start_lateness_above_profile")

    reasons = tuple(sorted(invalid))
    return ControlWorkloadSummary(
        schema_version=1,
        events_sha256=events_sha256,
        measurement_start_unix_ms=measurement_start_unix_ms,
        workload_end_unix_ms=workload_end_unix_ms,
        probe=summaries["probe"],
        crud=summaries["crud"],
        valid=not reasons,
        invalid_reasons=reasons,
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _nearest_rank_p99(values: tuple[int, ...]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return float(ordered[max(0, math.ceil(len(ordered) * 0.99) - 1)])
