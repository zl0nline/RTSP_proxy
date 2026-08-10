from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from rtsp_proxy.identifiers import PublicId
from rtsp_proxy.load_profile import LoadProfile
from rtsp_proxy.media import MediaMtxClient, MediaPathConfig

_BASE36_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"


class LoadPath(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    index: Annotated[int, Field(ge=0, lt=10000)]
    public_id: Annotated[str, StringConstraints(pattern=r"^[a-z0-9]{25}$")]
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


def _base36(value: int) -> str:
    encoded = ""
    while value:
        value, remainder = divmod(value, 36)
        encoded = _BASE36_ALPHABET[remainder] + encoded
    return encoded or "0"


def load_public_id(*, seed: int, index: int) -> PublicId:
    if seed < 0 or not 0 <= index < 10000:
        raise ValueError("load_public_id_input_out_of_range")
    digest = hashlib.sha256(f"rtsp-proxy-load:{seed}:{index}".encode()).digest()
    encoded = _base36(int.from_bytes(digest[:16], "big")).rjust(25, "0")
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


def _target_specs(profile: LoadProfile) -> tuple[tuple[int, int, int], ...]:
    indices = _active_indices(profile)
    if not indices:
        return ()
    base, remainder = divmod(profile.workload.total_readers, len(indices))
    reader_id_start = 0
    targets: list[tuple[int, int, int]] = []
    for position, index in enumerate(indices):
        count = base + (1 if position < remainder else 0)
        targets.append((index, count, reader_id_start))
        reader_id_start += count
    return tuple(targets)


def build_proxy_reader_plan(
    profile: LoadProfile, generator_host: str | None = None
) -> ReaderPlan:
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
        return selected_host.source_start <= index < (
            selected_host.source_start + selected_host.source_count
        )

    targets = tuple(
        ReaderTarget(
            path=catalog_by_index[index].public_id,
            reader_count=count,
            reader_id_start=start,
        )
        for index, count, start in _target_specs(profile)
        if belongs_to_selected_host(index)
    )
    return ReaderPlan(
        schema_version=1,
        endpoint_mode="proxy",
        generator_host=generator_host,
        targets=targets,
    )


def build_direct_reader_plan(profile: LoadProfile, generator_host: str) -> ReaderPlan:
    host = next(
        (item for item in profile.generator_hosts if item.name == generator_host),
        None,
    )
    if host is None:
        raise ValueError("unknown_generator_host")
    end = host.source_start + host.source_count
    targets = tuple(
        ReaderTarget(
            path=f"source-{index:05d}",
            reader_count=count,
            reader_id_start=start,
        )
        for index, count, start in _target_specs(profile)
        if host.source_start <= index < end
    )
    return ReaderPlan(
        schema_version=1,
        endpoint_mode="direct-control",
        generator_host=host.name,
        targets=targets,
    )


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
        json.dumps(
            catalog.model_dump(mode="json"), ensure_ascii=False, indent=2, sort_keys=True
        )
        + "\n"
    ).encode("utf-8")
    return _write_bytes(destination, body)


def apply_load_catalog(
    catalog: LoadCatalog, client: MediaMtxClient
) -> LoadCatalogApplyResult:
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
            f"{target.path}\t{target.reader_count}\t{target.reader_id_start}\n"
            for target in plan.targets
        )
    ).encode("ascii")
    return _write_bytes(destination, body)


def write_direct_reader_paths(
    profile: LoadProfile, generator_host: str, destination: Path
) -> str:
    return write_reader_paths(build_direct_reader_plan(profile, generator_host), destination)
