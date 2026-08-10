from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

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
                    source_url=(
                        f"rtsp://{url_host}:{host.rtsp_port}/source-{index:05d}"
                    ),
                )
            )
    return LoadCatalog(schema_version=1, source_mode="rtsp-pull", paths=tuple(paths))


def write_load_catalog(profile: LoadProfile, destination: Path) -> str:
    catalog = build_load_catalog(profile)
    body = (
        json.dumps(catalog.model_dump(mode="json"), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    ).encode("utf-8")
    with destination.open("xb") as output:
        output.write(body)
        output.flush()
        os.fsync(output.fileno())
    destination.chmod(0o640)
    return hashlib.sha256(body).hexdigest()


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


def write_reader_paths(catalog: LoadCatalog, destination: Path) -> str:
    body = ("\n".join(path.public_id for path in catalog.paths) + "\n").encode("ascii")
    with destination.open("xb") as output:
        output.write(body)
        output.flush()
        os.fsync(output.fileno())
    destination.chmod(0o640)
    return hashlib.sha256(body).hexdigest()
