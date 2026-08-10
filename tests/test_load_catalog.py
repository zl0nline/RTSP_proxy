from __future__ import annotations

import json
from pathlib import Path

from rtsp_proxy.identifiers import PublicId
from rtsp_proxy.load_catalog import build_load_catalog, load_public_id, write_load_catalog
from rtsp_proxy.load_profile import LoadProfile
from tests.test_load_profile import valid_profile


def test_load_public_ids_are_deterministic_canonical_and_index_specific() -> None:
    first = load_public_id(seed=1234, index=0)
    repeated = load_public_id(seed=1234, index=0)
    second = load_public_id(seed=1234, index=1)

    assert isinstance(first, PublicId)
    assert len(str(first)) == 25
    assert first == repeated
    assert first != second


def test_catalog_maps_every_registered_path_to_its_generator_range() -> None:
    profile = LoadProfile.model_validate(valid_profile(tier="capacity"))

    catalog = build_load_catalog(profile)

    assert catalog.schema_version == 1
    assert catalog.source_mode == "rtsp-pull"
    assert len(catalog.paths) == 4
    assert catalog.paths[0].source_url == (
        "rtsp://generator-a.load.internal:8554/source-00000"
    )
    assert catalog.paths[1].source_url.endswith("/source-00001")
    assert catalog.paths[2].source_url == (
        "rtsp://generator-b.load.internal:8554/source-00002"
    )
    assert len({path.public_id for path in catalog.paths}) == 4


def test_catalog_write_is_exclusive_and_contains_no_userinfo(tmp_path: Path) -> None:
    profile = LoadProfile.model_validate(valid_profile())
    destination = tmp_path / "path-catalog.json"

    catalog_sha256 = write_load_catalog(profile, destination)

    payload = destination.read_text(encoding="utf-8")
    stored = json.loads(payload)
    assert len(catalog_sha256) == 64
    assert stored["source_mode"] == "rtsp-pull"
    assert "@" not in payload
    assert destination.stat().st_mode & 0o777 == 0o640

    try:
        write_load_catalog(profile, destination)
    except FileExistsError:
        pass
    else:
        raise AssertionError("load catalog was overwritten")
