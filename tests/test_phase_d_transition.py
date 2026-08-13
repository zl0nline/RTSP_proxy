from __future__ import annotations

import hashlib
import json
import platform
from collections.abc import Callable
from pathlib import Path
from typing import cast
from uuid import UUID

import pytest

from rtsp_proxy.config import NodeRegistrationPolicy
from rtsp_proxy.phase_d_transition import PhaseDTransitionError, main, restore_transition
from rtsp_proxy.release import trusted_mediamtx_identity

NODE_A = "00000000-0000-0000-0000-000000000001"
CAMERA_A = "10000000-0000-0000-0000-000000000001"


def transition_manifest() -> dict[str, object]:
    return {
        "schema_version": 1,
        "source_schema": "0008_node_administration",
        "nodes": [
            {
                "id": NODE_A,
                "name": "media-a",
                "external_port": 12000,
                "api_port": 13000,
                "metrics_port": 14000,
                "creation_mode": "operator",
                "state": "stopped",
                "maintenance": False,
                "desired_revision": 1,
            }
        ],
        "cameras": [
            {
                "id": CAMERA_A,
                "name": "entrance",
                "source_url": "rtsp://camera.local/main",
                "public_id": "a" * 26,
                "node_id": NODE_A,
                "placement_mode": "manual",
                "placement_generation": 1,
                "state": "enabled",
            }
        ],
    }


def write_manifest(path: Path, manifest: dict[str, object]) -> tuple[Path, str]:
    payload = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    path.write_bytes(payload)
    path.chmod(0o600)
    return path, hashlib.sha256(payload).hexdigest()


def test_node_registration_policy_rejects_invalid_host_bounds() -> None:
    with pytest.raises(ValueError, match="max_nodes_invalid"):
        NodeRegistrationPolicy(
            max_nodes=101,
            external_ports=range(12000, 12100),
            api_ports=range(13000, 13100),
            metrics_ports=range(14000, 14100),
            reserved_ports=frozenset(),
        )
    with pytest.raises(ValueError, match="node_port_range_invalid"):
        NodeRegistrationPolicy(
            max_nodes=50,
            external_ports=range(0),
            api_ports=range(13000, 13100),
            metrics_ports=range(14000, 14100),
            reserved_ports=frozenset(),
        )


def restore_invalid_manifest(path: Path, digest: str) -> None:
    _version, trusted_digest = trusted_mediamtx_identity(platform.machine(), "0.1.0")
    restore_transition(
        "postgresql+psycopg://must-not-connect.invalid/rtsp_proxy",
        path,
        manifest_sha256=digest,
        release_id="0.1.0",
        mediamtx_binary_sha256=trusted_digest.root,
        node_policy=NodeRegistrationPolicy(
            max_nodes=50,
            external_ports=range(12000, 12100),
            api_ports=range(13000, 13100),
            metrics_ports=range(14000, 14100),
            reserved_ports=frozenset(),
        ),
        port_is_bindable=lambda _port: True,
    )


@pytest.mark.parametrize(
    ("mutate", "reason"),
    (
        (
            lambda value: value["nodes"].append(dict(value["nodes"][0])),
            "transition_node_duplicate",
        ),
        (
            lambda value: value["nodes"][0].__setitem__("api_port", 12000),
            "transition_node_port_duplicate",
        ),
        (
            lambda value: value["nodes"][0].__setitem__("state", "starting"),
            "transition_node_state_invalid",
        ),
        (
            lambda value: value["nodes"][0].update(
                {"state": "running", "maintenance": True}
            ),
            "transition_node_maintenance_invalid",
        ),
        (
            lambda value: value["cameras"].append(dict(value["cameras"][0])),
            "transition_camera_duplicate",
        ),
        (
            lambda value: value["cameras"][0].__setitem__("node_id", str(UUID(int=2))),
            "transition_camera_node_missing",
        ),
        (
            lambda value: value["cameras"][0].__setitem__("public_id", "invalid"),
            "transition_manifest_invalid",
        ),
        (
            lambda value: value["cameras"][0].__setitem__("source_url", "rtsps://camera/main"),
            "transition_manifest_invalid",
        ),
        (
            lambda value: value["cameras"][0].__setitem__("state", "deleted"),
            "transition_camera_state_invalid",
        ),
    ),
)
def test_restore_rejects_invalid_transition_contract_before_database_access(
    tmp_path: Path,
    mutate: Callable[[dict[str, object]], None],
    reason: str,
) -> None:
    manifest = transition_manifest()
    mutate(manifest)
    path, digest = write_manifest(tmp_path / "phase-d.json", manifest)

    with pytest.raises(PhaseDTransitionError, match=reason):
        restore_invalid_manifest(path, digest)


def test_restore_requires_an_exact_private_checksum_bound_regular_file(tmp_path: Path) -> None:
    path, digest = write_manifest(tmp_path / "phase-d.json", transition_manifest())

    with pytest.raises(PhaseDTransitionError, match="transition_manifest_checksum_mismatch"):
        restore_invalid_manifest(path, "0" * 64)

    path.chmod(0o644)
    with pytest.raises(PhaseDTransitionError, match="transition_manifest_unsafe"):
        restore_invalid_manifest(path, digest)


def test_restore_rejects_missing_database_configuration_before_file_access(
    tmp_path: Path,
) -> None:
    with pytest.raises(PhaseDTransitionError, match="database_url_required"):
        restore_transition(
            "",
            tmp_path / "missing.json",
            manifest_sha256="0" * 64,
            release_id="0.1.0",
            mediamtx_binary_sha256="0" * 64,
            node_policy=NodeRegistrationPolicy(
                max_nodes=50,
                external_ports=range(12000, 12100),
                api_ports=range(13000, 13100),
                metrics_ports=range(14000, 14100),
                reserved_ports=frozenset(),
            ),
            port_is_bindable=lambda _port: True,
        )


def test_restore_requires_an_absolute_manifest_path(tmp_path: Path) -> None:
    path, digest = write_manifest(tmp_path / "phase-d.json", transition_manifest())

    with pytest.raises(PhaseDTransitionError, match="transition_manifest_unsafe"):
        restore_invalid_manifest(Path(path.name), digest)

    path.unlink()
    target, _target_digest = write_manifest(tmp_path / "target.json", transition_manifest())
    path.symlink_to(target)
    with pytest.raises(PhaseDTransitionError, match="transition_manifest_unsafe"):
        restore_invalid_manifest(path, digest)


def test_restore_rejects_a_release_digest_outside_the_versioned_trust_catalog(
    tmp_path: Path,
) -> None:
    path, digest = write_manifest(tmp_path / "phase-d.json", transition_manifest())

    with pytest.raises(PhaseDTransitionError, match="transition_release_identity_untrusted"):
        restore_transition(
            "postgresql+psycopg://must-not-connect.invalid/rtsp_proxy",
            path,
            manifest_sha256=digest,
            release_id="0.1.0",
            mediamtx_binary_sha256="0" * 64,
            node_policy=NodeRegistrationPolicy(
                max_nodes=50,
                external_ports=range(12000, 12100),
                api_ports=range(13000, 13100),
                metrics_ports=range(14000, 14100),
                reserved_ports=frozenset(),
            ),
            port_is_bindable=lambda _port: True,
        )


@pytest.mark.parametrize(
    ("policy", "bindable", "reason"),
    (
        (
            NodeRegistrationPolicy(
                max_nodes=50,
                external_ports=range(12001, 12100),
                api_ports=range(13000, 13100),
                metrics_ports=range(14000, 14100),
                reserved_ports=frozenset(),
            ),
            lambda _port: True,
            "transition_node_port_out_of_policy",
        ),
        (
            NodeRegistrationPolicy(
                max_nodes=50,
                external_ports=range(12000, 12100),
                api_ports=range(13000, 13100),
                metrics_ports=range(14000, 14100),
                reserved_ports=frozenset({12000}),
            ),
            lambda _port: True,
            "transition_node_port_out_of_policy",
        ),
    ),
)
def test_restore_rejects_nodes_that_cannot_start_under_the_current_host_policy(
    tmp_path: Path,
    policy: NodeRegistrationPolicy,
    bindable: Callable[[int], bool],
    reason: str,
) -> None:
    path, digest = write_manifest(tmp_path / "phase-d.json", transition_manifest())
    _version, trusted_digest = trusted_mediamtx_identity(platform.machine(), "0.1.0")

    with pytest.raises(PhaseDTransitionError, match=reason):
        restore_transition(
            "postgresql+psycopg://must-not-connect.invalid/rtsp_proxy",
            path,
            manifest_sha256=digest,
            release_id="0.1.0",
            mediamtx_binary_sha256=trusted_digest.root,
            node_policy=policy,
            port_is_bindable=bindable,
        )


def test_restore_rejects_a_manifest_above_the_current_node_limit(tmp_path: Path) -> None:
    manifest = transition_manifest()
    nodes = cast(list[dict[str, object]], manifest["nodes"])
    second_node = dict(nodes[0])
    second_node.update(
        {
            "id": str(UUID(int=2)),
            "name": "media-b",
            "external_port": 12001,
            "api_port": 13001,
            "metrics_port": 14001,
        }
    )
    nodes.append(second_node)
    path, digest = write_manifest(tmp_path / "phase-d.json", manifest)
    _version, trusted_digest = trusted_mediamtx_identity(platform.machine(), "0.1.0")

    with pytest.raises(PhaseDTransitionError, match="transition_max_nodes_exceeded"):
        restore_transition(
            "postgresql+psycopg://must-not-connect.invalid/rtsp_proxy",
            path,
            manifest_sha256=digest,
            release_id="0.1.0",
            mediamtx_binary_sha256=trusted_digest.root,
            node_policy=NodeRegistrationPolicy(
                max_nodes=1,
                external_ports=range(12000, 12100),
                api_ports=range(13000, 13100),
                metrics_ports=range(14000, 14100),
                reserved_ports=frozenset(),
            ),
            port_is_bindable=lambda _port: True,
        )


def test_transition_cli_reports_a_stable_failure_without_database_configuration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("RTSP_PROXY_DATABASE_URL", raising=False)

    result = main(["export", "--manifest", str((tmp_path / "phase-d.json").resolve())])

    assert result == 1
    assert capsys.readouterr().err == (
        "phase-d transition failed: database_url_required\n"
    )

    result = main(
        [
            "restore",
            "--manifest",
            str((tmp_path / "missing.json").resolve()),
            "--manifest-sha256",
            "0" * 64,
        ]
    )

    assert result == 1
    assert capsys.readouterr().err == (
        "phase-d transition failed: database_url_required\n"
    )


def test_transition_cli_reports_invalid_current_host_policy_without_a_traceback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv(
        "RTSP_PROXY_DATABASE_URL",
        "postgresql+psycopg://must-not-connect.invalid/rtsp_proxy",
    )
    monkeypatch.setenv("RTSP_PROXY_MAX_NODES", "101")

    result = main(
        [
            "restore",
            "--manifest",
            str((tmp_path / "missing.json").resolve()),
            "--manifest-sha256",
            "0" * 64,
        ]
    )

    assert result == 1
    assert capsys.readouterr().err == (
        "phase-d transition failed: transition_settings_invalid\n"
    )
