from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from rtsp_proxy.identifiers import PublicId
from rtsp_proxy.load_evidence import KernelClockProof, prove_linux_clock
from rtsp_proxy.load_profile import (
    MAX_COLD_PREFLIGHT_PATHS,
    GeneratorHost,
    LoadProfile,
    canonical_profile_bytes,
)
from rtsp_proxy.media import MediaMtxClient, MediaPathConfig

COLD_PREFLIGHT_MAX_LEAD_MS = 30_000
WARM_PREFLIGHT_MAX_LEAD_MS = 30_000
WARM_PREFLIGHT_MAX_END_LATENESS_MS = 2_000
WARM_PREFLIGHT_MAX_SWEEP_MS = 2_000
WARM_PREFLIGHT_MAX_GAP_MS = 1_000


def _unix_time_ms() -> int:
    return time.time_ns() // 1_000_000


def _path_set_sha256(paths: tuple[str, ...]) -> str:
    return hashlib.sha256(("\n".join(paths) + "\n").encode("ascii")).hexdigest()


def _reader_counts_sha256(counts: dict[str, int]) -> str:
    return hashlib.sha256(
        json.dumps(counts, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


class LoadPath(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    index: Annotated[int, Field(ge=0, lt=10000)]
    public_id: Annotated[str, StringConstraints(pattern=r"^[a-z2-7]{25}[aeimquy4]$")]
    source_url: str


class LoadCatalog(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1]
    source_mode: Literal["rtsp-pull"]
    paths: tuple[LoadPath, ...]


class ReaderTarget(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9_.:-]{1,128}$")]
    reader_count: Annotated[int, Field(gt=0, le=100000)]
    reader_id_start: Annotated[int, Field(ge=0, lt=100000)]
    warm_anchor_count: Literal[0, 1]
    measured_schedule_start: Annotated[int, Field(ge=0, lt=100000)]


class ReaderPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1]
    endpoint_mode: Literal["proxy", "direct-control"]
    generator_host: str | None
    targets: tuple[ReaderTarget, ...]

    @model_validator(mode="after")
    def validate_plan_ids_and_host(self) -> Self:
        if self.endpoint_mode == "direct-control" and self.generator_host is None:
            raise ValueError("reader_plan_host_mode_mismatch")
        ids: set[int] = set()
        paths: set[str] = set()
        for target in self.targets:
            if target.path in paths:
                raise ValueError("reader_plan_duplicate_path")
            paths.add(target.path)
            if target.warm_anchor_count > target.reader_count:
                raise ValueError("reader_plan_anchor_count_exceeds_target")
            for reader_id in range(
                target.reader_id_start,
                target.reader_id_start + target.reader_count,
            ):
                if reader_id >= 100000 or reader_id in ids:
                    raise ValueError("reader_plan_duplicate_or_out_of_range_id")
                ids.add(reader_id)
        return self


@dataclass(frozen=True, slots=True)
class LoadCatalogApplyResult:
    applied_paths: int
    verified_paths: int


class LoadCatalogApplyError(RuntimeError):
    """The load catalog did not converge to the expected isolated lab state."""


def load_public_id(*, seed: int, index: int) -> PublicId:
    if seed < 0 or not 0 <= index < 10000:
        raise ValueError("load_public_id_input_out_of_range")
    digest = hashlib.sha256(f"rtsp-proxy-load:{seed}:{index}".encode()).digest()
    encoded = base64.b32encode(digest[:16]).decode("ascii").lower().rstrip("=")
    return PublicId.parse(encoded)


def build_load_catalog(profile: LoadProfile) -> LoadCatalog:
    paths: list[LoadPath] = []
    for host in sorted(profile.generator_hosts, key=lambda item: item.source_start):
        url_host = f"[{host.rtsp_host}]" if ":" in host.rtsp_host else host.rtsp_host
        for index in range(host.source_start, host.source_start + host.source_count):
            paths.append(
                LoadPath(
                    index=index,
                    public_id=str(load_public_id(seed=profile.seed, index=index)),
                    source_url=f"rtsp://{url_host}:{host.rtsp_port}/source-{index:05d}",
                )
            )
    return LoadCatalog(schema_version=1, source_mode="rtsp-pull", paths=tuple(paths))


def _active_indices(profile: LoadProfile) -> tuple[int, ...]:
    hosts = sorted(profile.generator_hosts, key=lambda item: item.source_start)
    selected: list[int] = []
    offset = 0
    while len(selected) < profile.workload.active_sources:
        made_progress = False
        for host in hosts:
            if offset < host.source_count:
                selected.append(host.source_start + offset)
                made_progress = True
                if len(selected) == profile.workload.active_sources:
                    return tuple(selected)
        if not made_progress:
            break
        offset += 1
    return tuple(selected)


def _target_specs(profile: LoadProfile) -> tuple[tuple[int, int, int, int], ...]:
    indices = _active_indices(profile)
    if not indices:
        return ()
    base, remainder = divmod(profile.workload.total_readers, len(indices))
    reader_id_start = 0
    measured_schedule_start = 0
    targets: list[tuple[int, int, int, int]] = []
    anchors_per_target = 1 if profile.workload.session_temperature == "warm" else 0
    for position, index in enumerate(indices):
        count = base + (1 if position < remainder else 0)
        targets.append((index, count, reader_id_start, measured_schedule_start))
        reader_id_start += count
        measured_schedule_start += count - anchors_per_target
    return tuple(targets)


def build_proxy_reader_plan(profile: LoadProfile, generator_host: str | None = None) -> ReaderPlan:
    catalog_by_index = {path.index: path for path in build_load_catalog(profile).paths}
    selected_host = None
    if generator_host is not None:
        selected_host = next(
            (item for item in profile.generator_hosts if item.name == generator_host),
            None,
        )
        if selected_host is None:
            raise ValueError("unknown_generator_host")

    def belongs_to_selected_host(index: int) -> bool:
        if selected_host is None:
            return True
        return (
            selected_host.source_start
            <= index
            < (selected_host.source_start + selected_host.source_count)
        )

    targets = tuple(
        ReaderTarget(
            path=catalog_by_index[index].public_id,
            reader_count=count,
            reader_id_start=start,
            warm_anchor_count=1 if profile.workload.session_temperature == "warm" else 0,
            measured_schedule_start=measured_start,
        )
        for index, count, start, measured_start in _target_specs(profile)
        if belongs_to_selected_host(index)
    )
    return ReaderPlan(
        schema_version=1,
        endpoint_mode="proxy",
        generator_host=generator_host,
        targets=targets,
    )


def build_direct_reader_plan(profile: LoadProfile, generator_host: str) -> ReaderPlan:
    reader_host = next(
        (item for item in profile.generator_hosts if item.name == generator_host),
        None,
    )
    if reader_host is None:
        raise ValueError("unknown_generator_host")
    source_host = direct_source_host(profile, generator_host)
    end = source_host.source_start + source_host.source_count
    targets = tuple(
        ReaderTarget(
            path=f"source-{index:05d}",
            reader_count=count,
            reader_id_start=start,
            warm_anchor_count=1 if profile.workload.session_temperature == "warm" else 0,
            measured_schedule_start=measured_start,
        )
        for index, count, start, measured_start in _target_specs(profile)
        if source_host.source_start <= index < end
    )
    return ReaderPlan(
        schema_version=1,
        endpoint_mode="direct-control",
        generator_host=reader_host.name,
        targets=targets,
    )


def direct_source_host(profile: LoadProfile, reader_host: str) -> GeneratorHost:
    """Select the source host for a direct-control reader shard.

    LAN smoke preserves the one-host local control. Impaired profiles rotate
    shards so the camera stream crosses a receiver ingress and cannot bypass
    the netem contract used by the proxy run.
    """
    hosts = tuple(profile.generator_hosts)
    reader_index = next(
        (index for index, item in enumerate(hosts) if item.name == reader_host),
        None,
    )
    if reader_index is None:
        raise ValueError("unknown_generator_host")
    if profile.network.profile == "lan":
        return hosts[reader_index]
    return hosts[(reader_index - 1) % len(hosts)]


def _cold_proxy_paths(profile: LoadProfile) -> tuple[str, ...]:
    return tuple(target.path for target in build_proxy_reader_plan(profile).targets)


def validate_cold_preflight_payload(
    profile: LoadProfile,
    payload: dict[str, object],
    *,
    scheduled_start_unix_ms: int,
) -> None:
    observed_start = payload.get("observed_start_unix_ms")
    observed_end = payload.get("observed_end_unix_ms")
    try:
        clock_start = KernelClockProof.model_validate(payload.get("clock_proof_start"))
        clock_end = KernelClockProof.model_validate(payload.get("clock_proof_end"))
    except ValueError as error:
        raise ValueError("cold_preflight_evidence_invalid") from error
    if (
        profile.workload.endpoint_mode != "proxy"
        or profile.workload.session_temperature != "cold"
        or set(payload)
        != {
            "schema_version",
            "profile_sha256",
            "scheduled_start_unix_ms",
            "observed_start_unix_ms",
            "observed_end_unix_ms",
            "clock_proof_start",
            "clock_proof_end",
            "reset_paths",
            "unavailable_paths",
        }
        or payload.get("schema_version") != 1
        or payload.get("profile_sha256") != canonical_profile_bytes(profile)[1]
        or payload.get("scheduled_start_unix_ms") != scheduled_start_unix_ms
        or not isinstance(observed_start, int)
        or isinstance(observed_start, bool)
        or not isinstance(observed_end, int)
        or isinstance(observed_end, bool)
        or not scheduled_start_unix_ms - COLD_PREFLIGHT_MAX_LEAD_MS
        <= observed_start
        <= observed_end
        <= scheduled_start_unix_ms
        or payload.get("reset_paths") != list(_cold_proxy_paths(profile))
        or payload.get("unavailable_paths") != list(_cold_proxy_paths(profile))
        or not clock_start.synchronized
        or not clock_end.synchronized
        or max(clock_start.max_error_ms, clock_end.max_error_ms)
        > profile.evidence_sampling.maximum_clock_error_ms
        or not clock_start.observed_at_unix_ms
        <= observed_start
        <= observed_end
        <= clock_end.observed_at_unix_ms
        <= scheduled_start_unix_ms
    ):
        raise ValueError("cold_preflight_evidence_invalid")


def capture_cold_preflight(
    profile: LoadProfile,
    client: MediaMtxClient,
    *,
    scheduled_start_unix_ms: int,
    clock_ms: Callable[[], int] | None = None,
    clock_proof: Callable[[float], KernelClockProof] | None = None,
) -> dict[str, object]:
    if profile.workload.endpoint_mode != "proxy" or profile.workload.session_temperature != "cold":
        raise ValueError("cold_preflight_profile_invalid")
    if clock_ms is None:
        clock_ms = _unix_time_ms
    if clock_proof is None:
        clock_proof = prove_linux_clock
    target_paths = _cold_proxy_paths(profile)
    if not target_paths:
        raise ValueError("cold_preflight_requires_target_paths")
    if len(target_paths) > MAX_COLD_PREFLIGHT_PATHS:
        raise ValueError("cold_preflight_path_count_exceeds_safety_cap")
    catalog = {path.public_id: path for path in build_load_catalog(profile).paths}
    clock_proof_start = clock_proof(profile.evidence_sampling.maximum_clock_error_ms)
    observed_start_unix_ms = clock_ms()

    def reset_and_verify(path: str) -> None:
        name = PublicId.parse(path)
        expected = MediaPathConfig(name=name, source_url=catalog[path].source_url)
        client.delete_path(name)
        client.put_path(expected)
        if client.get_path(name) != expected:
            raise ValueError("cold_preflight_mapping_mismatch_after_reset")

    with ThreadPoolExecutor(max_workers=min(32, len(target_paths))) as executor:
        tuple(executor.map(reset_and_verify, target_paths))
    statuses = client.runtime_path_statuses(tuple(PublicId.parse(path) for path in target_paths))
    if any(status is not None and status[0] for status in statuses.values()):
        raise ValueError("cold_preflight_path_available_after_reset")
    observed_end_unix_ms = clock_ms()
    clock_proof_end = clock_proof(profile.evidence_sampling.maximum_clock_error_ms)
    payload: dict[str, object] = {
        "schema_version": 1,
        "profile_sha256": canonical_profile_bytes(profile)[1],
        "scheduled_start_unix_ms": scheduled_start_unix_ms,
        "observed_start_unix_ms": observed_start_unix_ms,
        "observed_end_unix_ms": observed_end_unix_ms,
        "clock_proof_start": clock_proof_start.model_dump(mode="json"),
        "clock_proof_end": clock_proof_end.model_dump(mode="json"),
        "reset_paths": list(target_paths),
        "unavailable_paths": list(target_paths),
    }
    validate_cold_preflight_payload(
        profile, payload, scheduled_start_unix_ms=scheduled_start_unix_ms
    )
    return payload


def validate_warm_preflight_payload(
    profile: LoadProfile,
    payload: dict[str, object],
    *,
    scheduled_start_unix_ms: int,
) -> None:
    target_paths = _cold_proxy_paths(profile)
    observed_start = payload.get("observed_start_unix_ms")
    observed_end = payload.get("observed_end_unix_ms")
    sample_count = payload.get("sample_count")
    minimum_counts = payload.get("minimum_reader_count_by_path")
    sweeps = payload.get("sweeps")
    try:
        clock_start = KernelClockProof.model_validate(payload.get("clock_proof_start"))
        clock_end = KernelClockProof.model_validate(payload.get("clock_proof_end"))
    except ValueError as error:
        raise ValueError("warm_preflight_evidence_invalid") from error
    expected_path_digest = _path_set_sha256(target_paths)
    if (
        profile.workload.endpoint_mode != "proxy"
        or profile.workload.session_temperature != "warm"
        or set(payload)
        != {
            "schema_version",
            "profile_sha256",
            "scheduled_start_unix_ms",
            "observed_start_unix_ms",
            "observed_end_unix_ms",
            "sample_count",
            "ready_paths",
            "minimum_reader_count_by_path",
            "sweeps",
            "clock_proof_start",
            "clock_proof_end",
        }
        or payload.get("schema_version") != 1
        or payload.get("profile_sha256") != canonical_profile_bytes(profile)[1]
        or payload.get("scheduled_start_unix_ms") != scheduled_start_unix_ms
        or not isinstance(observed_start, int)
        or isinstance(observed_start, bool)
        or not isinstance(observed_end, int)
        or isinstance(observed_end, bool)
        or not 0 <= scheduled_start_unix_ms - observed_start <= WARM_PREFLIGHT_MAX_LEAD_MS
        or not scheduled_start_unix_ms
        <= observed_end
        <= scheduled_start_unix_ms + WARM_PREFLIGHT_MAX_END_LATENESS_MS
        or not isinstance(sample_count, int)
        or isinstance(sample_count, bool)
        or sample_count < 2
        or payload.get("ready_paths") != list(target_paths)
        or not isinstance(minimum_counts, dict)
        or set(minimum_counts) != set(target_paths)
        or any(
            not isinstance(count, int) or isinstance(count, bool) or count < 1
            for count in minimum_counts.values()
        )
        or not isinstance(sweeps, list)
        or len(sweeps) != sample_count
        or not clock_start.synchronized
        or not clock_end.synchronized
        or max(clock_start.max_error_ms, clock_end.max_error_ms)
        > profile.evidence_sampling.maximum_clock_error_ms
        or not clock_start.observed_at_unix_ms
        <= observed_start
        <= observed_end
        <= clock_end.observed_at_unix_ms
    ):
        raise ValueError("warm_preflight_evidence_invalid")
    previous_end: int | None = None
    for index, sweep in enumerate(sweeps):
        if not isinstance(sweep, dict) or set(sweep) != {
            "observed_start_unix_ms",
            "observed_end_unix_ms",
            "ready_path_count",
            "ready_paths_sha256",
            "minimum_reader_count",
            "reader_counts_sha256",
        }:
            raise ValueError("warm_preflight_evidence_invalid")
        sweep_start = sweep.get("observed_start_unix_ms")
        sweep_end = sweep.get("observed_end_unix_ms")
        count_digest = sweep.get("reader_counts_sha256")
        if (
            not isinstance(sweep_start, int)
            or isinstance(sweep_start, bool)
            or not isinstance(sweep_end, int)
            or isinstance(sweep_end, bool)
            or not sweep_start <= sweep_end <= sweep_start + WARM_PREFLIGHT_MAX_SWEEP_MS
            or sweep.get("ready_path_count") != len(target_paths)
            or sweep.get("ready_paths_sha256") != expected_path_digest
            or not isinstance(sweep.get("minimum_reader_count"), int)
            or isinstance(sweep.get("minimum_reader_count"), bool)
            or sweep.get("minimum_reader_count", 0) < 1
            or not isinstance(count_digest, str)
            or len(count_digest) != 64
            or any(character not in "0123456789abcdef" for character in count_digest)
            or (
                previous_end is not None
                and not 0 <= sweep_start - previous_end <= WARM_PREFLIGHT_MAX_GAP_MS
            )
        ):
            raise ValueError("warm_preflight_evidence_invalid")
        if index == 0 and sweep_start != observed_start:
            raise ValueError("warm_preflight_evidence_invalid")
        previous_end = sweep_end
    last_sweep = sweeps[-1]
    if (
        last_sweep["observed_end_unix_ms"] != observed_end
        or not last_sweep["observed_start_unix_ms"]
        <= scheduled_start_unix_ms
        <= last_sweep["observed_end_unix_ms"]
    ):
        raise ValueError("warm_preflight_evidence_invalid")


def capture_warm_preflight(
    profile: LoadProfile,
    client: MediaMtxClient,
    *,
    scheduled_start_unix_ms: int,
    clock_ms: Callable[[], int] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    poll_interval_seconds: float = 0.25,
    clock_proof: Callable[[float], KernelClockProof] | None = None,
) -> dict[str, object]:
    if profile.workload.endpoint_mode != "proxy" or profile.workload.session_temperature != "warm":
        raise ValueError("warm_preflight_profile_invalid")
    if poll_interval_seconds <= 0 or poll_interval_seconds > 1:
        raise ValueError("warm_preflight_poll_interval_invalid")
    if clock_ms is None:
        clock_ms = _unix_time_ms
    if clock_proof is None:
        clock_proof = prove_linux_clock
    target_paths = _cold_proxy_paths(profile)
    clock_proof_start = clock_proof(profile.evidence_sampling.maximum_clock_error_ms)
    first_observed_at = clock_ms()
    if not 0 <= scheduled_start_unix_ms - first_observed_at <= WARM_PREFLIGHT_MAX_LEAD_MS:
        raise ValueError("warm_preflight_start_outside_window")
    minimum_counts = {path: 100_001 for path in target_paths}
    sample_count = 0
    sweeps: list[dict[str, object]] = []
    while True:
        sweep_start = first_observed_at if sample_count == 0 else clock_ms()
        statuses = client.runtime_path_statuses(
            tuple(PublicId.parse(path) for path in target_paths)
        )
        counts: dict[str, int] = {}
        for path, name in zip(target_paths, statuses, strict=True):
            status = statuses[name]
            if status is None or not status[0] or status[1] < 1:
                raise ValueError("warm_preflight_anchor_missing")
            counts[path] = status[1]
            minimum_counts[path] = min(minimum_counts[path], status[1])
        sample_count += 1
        observed_end = clock_ms()
        sweeps.append(
            {
                "observed_start_unix_ms": sweep_start,
                "observed_end_unix_ms": observed_end,
                "ready_path_count": len(target_paths),
                "ready_paths_sha256": _path_set_sha256(target_paths),
                "minimum_reader_count": min(counts.values()),
                "reader_counts_sha256": _reader_counts_sha256(counts),
            }
        )
        if observed_end >= scheduled_start_unix_ms:
            break
        sleep(
            min(
                poll_interval_seconds,
                (scheduled_start_unix_ms - observed_end) / 1000,
            )
        )
    clock_proof_end = clock_proof(profile.evidence_sampling.maximum_clock_error_ms)
    payload: dict[str, object] = {
        "schema_version": 1,
        "profile_sha256": canonical_profile_bytes(profile)[1],
        "scheduled_start_unix_ms": scheduled_start_unix_ms,
        "observed_start_unix_ms": first_observed_at,
        "observed_end_unix_ms": observed_end,
        "sample_count": sample_count,
        "ready_paths": list(target_paths),
        "minimum_reader_count_by_path": minimum_counts,
        "sweeps": sweeps,
        "clock_proof_start": clock_proof_start.model_dump(mode="json"),
        "clock_proof_end": clock_proof_end.model_dump(mode="json"),
    }
    validate_warm_preflight_payload(
        profile, payload, scheduled_start_unix_ms=scheduled_start_unix_ms
    )
    return payload


def _write_bytes(destination: Path, body: bytes) -> str:
    with destination.open("xb") as output:
        output.write(body)
        output.flush()
        os.fsync(output.fileno())
    destination.chmod(0o640)
    return hashlib.sha256(body).hexdigest()


def write_load_catalog(profile: LoadProfile, destination: Path) -> str:
    catalog = build_load_catalog(profile)
    body = (
        json.dumps(catalog.model_dump(mode="json"), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    ).encode("utf-8")
    return _write_bytes(destination, body)


def apply_load_catalog(catalog: LoadCatalog, client: MediaMtxClient) -> LoadCatalogApplyResult:
    for path in catalog.paths:
        client.put_path(
            MediaPathConfig(
                name=PublicId.parse(path.public_id),
                source_url=path.source_url,
            )
        )

    expected_ids = {PublicId.parse(path.public_id) for path in catalog.paths}
    inventory = client.inventory_paths()
    if set(inventory.camera_ids) != expected_ids:
        raise LoadCatalogApplyError("load_catalog_inventory_mismatch")

    sample_offsets = {0, len(catalog.paths) // 2, len(catalog.paths) - 1}
    for offset in sample_offsets:
        expected = catalog.paths[offset]
        observed = client.get_path(PublicId.parse(expected.public_id))
        if observed is None or observed.source_url != expected.source_url:
            raise LoadCatalogApplyError("load_catalog_mapping_mismatch")
    return LoadCatalogApplyResult(
        applied_paths=len(catalog.paths),
        verified_paths=len(sample_offsets),
    )


def write_reader_paths(plan: ReaderPlan, destination: Path) -> str:
    body = (
        "".join(
            f"{target.path}\t{target.reader_count}\t{target.reader_id_start}\t"
            f"{target.warm_anchor_count}\t{target.measured_schedule_start}\n"
            for target in plan.targets
        )
    ).encode("ascii")
    return _write_bytes(destination, body)


def write_direct_reader_paths(profile: LoadProfile, generator_host: str, destination: Path) -> str:
    return write_reader_paths(build_direct_reader_plan(profile, generator_host), destination)
