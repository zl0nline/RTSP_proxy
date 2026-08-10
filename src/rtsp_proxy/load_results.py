from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from rtsp_proxy.load_profile import LoadProfile

LatencyGate = Literal[
    "warm_proxy_p99",
    "requires_direct_control_decomposition",
    "direct_control_reference",
]


class ReaderEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    event: Literal["first_packet", "reader_error"]
    reader_id: Annotated[int, Field(ge=0, lt=100000)]
    path: Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9_.:-]{1,128}$")]
    latency_ms: Annotated[float, Field(ge=0)] | None = None
    reason: Literal[
        "gstreamer_error", "unexpected_eos", "state_change_failure"
    ] | None = None

    @model_validator(mode="after")
    def validate_event_shape(self) -> Self:
        if self.event == "first_packet" and (
            self.latency_ms is None or self.reason is not None
        ):
            raise ValueError("invalid_first_packet_event")
        if self.event == "reader_error" and (
            self.reason is None or self.latency_ms is not None
        ):
            raise ValueError("invalid_reader_error_event")
        return self


class ReaderRunSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    expected_readers: int
    first_packet_readers: int
    failed_readers: int
    establishment_success_percent: float
    latency_p50_ms: float | None
    latency_p95_ms: float | None
    latency_p99_ms: float | None
    latency_slo_ms: float | None
    latency_slo_pass: bool | None
    latency_gate: LatencyGate
    valid: bool
    invalid_reasons: tuple[str, ...]


def _nearest_rank(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[math.ceil(percentile * len(ordered)) - 1]


def _load_reader_events(path: Path) -> tuple[ReaderEvent, ...]:
    events: list[ReaderEvent] = []
    with path.open(encoding="utf-8") as source:
        for line in source:
            if not line.strip():
                raise ValueError("blank_reader_event_line")
            events.append(ReaderEvent.model_validate(json.loads(line)))
    if not events:
        raise ValueError("reader_events_empty")
    return tuple(events)


def summarize_reader_events(profile: LoadProfile, path: Path) -> ReaderRunSummary:
    events = _load_reader_events(path)
    expected_readers = profile.workload.total_readers
    first_packets: dict[int, float] = {}
    failed_readers: set[int] = set()
    for event in events:
        if event.reader_id >= expected_readers:
            raise ValueError("reader_event_id_out_of_range")
        if event.event == "first_packet":
            if event.reader_id in first_packets:
                raise ValueError("duplicate_first_packet_event")
            assert event.latency_ms is not None
            first_packets[event.reader_id] = event.latency_ms
        else:
            if event.reader_id in failed_readers:
                raise ValueError("duplicate_reader_error_event")
            failed_readers.add(event.reader_id)

    latencies = list(first_packets.values())
    p50 = _nearest_rank(latencies, 0.50)
    p95 = _nearest_rank(latencies, 0.95)
    p99 = _nearest_rank(latencies, 0.99)
    success_percent = len(first_packets) / expected_readers * 100
    reasons: list[str] = []
    if success_percent < 99.9:
        reasons.append("session_establishment_below_99_9_percent")
    if failed_readers:
        reasons.append("reader_errors_observed")

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
        expected_readers=expected_readers,
        first_packet_readers=len(first_packets),
        failed_readers=len(failed_readers),
        establishment_success_percent=success_percent,
        latency_p50_ms=p50,
        latency_p95_ms=p95,
        latency_p99_ms=p99,
        latency_slo_ms=latency_slo_ms,
        latency_slo_pass=latency_slo_pass,
        latency_gate=latency_gate,
        valid=not reasons,
        invalid_reasons=tuple(reasons),
    )
