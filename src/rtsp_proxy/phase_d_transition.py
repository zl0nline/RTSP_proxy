from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import stat
import sys
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import create_engine, func, insert, select, text, update
from sqlalchemy.engine import Connection
from sqlalchemy.exc import SQLAlchemyError

from rtsp_proxy.config import NodeRegistrationPolicy, RuntimeRole, Settings
from rtsp_proxy.database import (
    audit_events,
    camera_access_policies,
    camera_move_sagas,
    camera_placement_history,
    camera_placements,
    cameras,
    media_nodes,
    node_port_change_sagas,
    outbox_messages,
    public_id_tombstones,
)
from rtsp_proxy.identifiers import PublicId
from rtsp_proxy.nodes import (
    CameraState,
    NodeCreationMode,
    NodeState,
    PlacementMode,
    PortBindable,
    tcp_port_is_bindable,
    validate_camera_source_url,
)
from rtsp_proxy.release import (
    APPLICATION_SCHEMA,
    ReleaseVerificationError,
    trusted_mediamtx_identity,
)

_TRANSITION_SCHEMA = 1
_NODE_REGISTRY_LOCK_KEY = 0x52545350524F5859
_CAMERA_PLACEMENT_LOCK_KEY = 0x43414D504C414345
_RESTORABLE_NODE_STATES = frozenset(
    {
        NodeState.RUNNING,
        NodeState.STOPPED,
        NodeState.DRAINING,
        NodeState.MAINTENANCE,
        NodeState.FAILED,
    }
)


class PhaseDTransitionError(RuntimeError):
    """The offline Phase-C to Phase-D transition cannot proceed safely."""


class TransitionNode(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: UUID
    name: str = Field(min_length=1, max_length=128)
    external_port: int = Field(ge=1, le=65535)
    api_port: int = Field(ge=1, le=65535)
    metrics_port: int = Field(ge=1, le=65535)
    creation_mode: NodeCreationMode
    state: NodeState
    maintenance: bool
    desired_revision: int = Field(ge=1)


class TransitionCamera(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: UUID
    name: str = Field(min_length=1, max_length=128)
    source_url: str = Field(min_length=1, max_length=8192)
    public_id: str
    node_id: UUID
    placement_mode: PlacementMode
    placement_generation: int = Field(ge=1)
    state: CameraState


class PhaseDTransitionManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(ge=_TRANSITION_SCHEMA, le=_TRANSITION_SCHEMA)
    source_schema: str = Field(pattern=r"^0008_node_administration$")
    nodes: tuple[TransitionNode, ...]
    cameras: tuple[TransitionCamera, ...]


def export_transition(database_url: str, manifest_path: Path) -> str:
    """Export immutable camera paths before normal drain/delete operations."""

    if not database_url:
        raise PhaseDTransitionError("database_url_required")
    if not manifest_path.is_absolute():
        raise PhaseDTransitionError("transition_manifest_path_must_be_absolute")
    engine = create_engine(database_url, pool_pre_ping=True, hide_parameters=True)
    try:
        with engine.begin() as connection:
            _require_schema(connection, "0008_node_administration")
            connection.execute(
                text("SELECT pg_advisory_xact_lock(:key)"),
                {"key": _NODE_REGISTRY_LOCK_KEY},
            )
            connection.execute(
                text("SELECT pg_advisory_xact_lock(:key)"),
                {"key": _CAMERA_PLACEMENT_LOCK_KEY},
            )
            if connection.scalar(
                select(func.count()).select_from(camera_move_sagas).where(
                    camera_move_sagas.c.state != "complete"
                )
            ):
                raise PhaseDTransitionError("transition_camera_move_in_progress")
            if connection.scalar(
                select(func.count()).select_from(node_port_change_sagas).where(
                    node_port_change_sagas.c.state == "prepared"
                )
            ):
                raise PhaseDTransitionError("transition_port_change_in_progress")
            node_rows = tuple(
                connection.execute(
                    select(
                        media_nodes.c.id,
                        media_nodes.c.name,
                        media_nodes.c.external_port,
                        media_nodes.c.api_port,
                        media_nodes.c.metrics_port,
                        media_nodes.c.creation_mode,
                        media_nodes.c.state,
                        media_nodes.c.maintenance,
                        media_nodes.c.registered_cameras,
                        media_nodes.c.desired_revision,
                    ).order_by(media_nodes.c.id)
                ).mappings()
            )
            camera_rows = tuple(
                connection.execute(
                    select(
                        cameras,
                        camera_placements.c.node_id,
                        camera_placements.c.placement_mode,
                        camera_placements.c.generation.label("placement_generation"),
                    )
                    .join(camera_placements, camera_placements.c.camera_id == cameras.c.id)
                    .where(cameras.c.state.in_(("enabled", "disabled")))
                    .order_by(cameras.c.id)
                ).mappings()
            )
            camera_count = connection.scalar(
                select(func.count()).select_from(cameras).where(cameras.c.state != "deleted")
            )
            if camera_count != len(camera_rows):
                raise PhaseDTransitionError("transition_camera_not_stable")
            counts = Counter(UUID(str(row["node_id"])) for row in camera_rows)
            if any(
                int(row["registered_cameras"]) != counts[UUID(str(row["id"]))]
                for row in node_rows
            ):
                raise PhaseDTransitionError("transition_camera_count_mismatch")
            manifest = PhaseDTransitionManifest(
                schema_version=_TRANSITION_SCHEMA,
                source_schema="0008_node_administration",
                nodes=tuple(
                    TransitionNode(
                        id=row["id"],
                        name=str(row["name"]),
                        external_port=int(row["external_port"]),
                        api_port=int(row["api_port"]),
                        metrics_port=int(row["metrics_port"]),
                        creation_mode=NodeCreationMode(str(row["creation_mode"])),
                        state=NodeState(str(row["state"])),
                        maintenance=bool(row["maintenance"]),
                        desired_revision=int(row["desired_revision"]),
                    )
                    for row in node_rows
                ),
                cameras=tuple(
                    TransitionCamera(
                        id=row["id"],
                        name=str(row["name"]),
                        source_url=str(row["source_url"]),
                        public_id=str(row["public_id"]),
                        node_id=row["node_id"],
                        placement_mode=PlacementMode(str(row["placement_mode"])),
                        placement_generation=int(row["placement_generation"]),
                        state=CameraState(str(row["state"])),
                    )
                    for row in camera_rows
                ),
            )
            _validate_manifest(manifest)
        payload = _canonical_manifest(manifest)
        _write_new_private_file(manifest_path, payload)
        return hashlib.sha256(payload).hexdigest()
    except (
        OSError,
        SQLAlchemyError,
        ValidationError,
        ValueError,
        PhaseDTransitionError,
    ) as error:
        if isinstance(error, PhaseDTransitionError):
            raise
        raise PhaseDTransitionError("transition_export_failed") from error
    finally:
        engine.dispose()


def restore_transition(
    database_url: str,
    manifest_path: Path,
    *,
    manifest_sha256: str,
    release_id: str,
    mediamtx_binary_sha256: str,
    node_policy: NodeRegistrationPolicy,
    port_is_bindable: PortBindable = tcp_port_is_bindable,
    machine: str | None = None,
) -> None:
    """Restore exact UUID/public-id placement after migration and node cleanup."""

    if not database_url:
        raise PhaseDTransitionError("database_url_required")
    payload = _read_private_manifest(manifest_path)
    if hashlib.sha256(payload).hexdigest() != manifest_sha256:
        raise PhaseDTransitionError("transition_manifest_checksum_mismatch")
    try:
        manifest = PhaseDTransitionManifest.model_validate_json(payload)
        _validate_manifest(manifest)
        _validate_host_policy(manifest, node_policy)
        _version, trusted_digest = trusted_mediamtx_identity(
            platform.machine() if machine is None else machine,
            release_id,
        )
        if mediamtx_binary_sha256 != trusted_digest.root:
            raise PhaseDTransitionError("transition_release_identity_untrusted")
    except (
        ValidationError,
        ValueError,
        ReleaseVerificationError,
        PhaseDTransitionError,
    ) as error:
        if isinstance(error, PhaseDTransitionError):
            raise
        raise PhaseDTransitionError("transition_manifest_invalid") from error

    engine = create_engine(database_url, pool_pre_ping=True, hide_parameters=True)
    try:
        with engine.begin() as connection:
            connection.execute(text("SET LOCAL synchronous_commit = on"))
            _require_schema(connection, APPLICATION_SCHEMA)
            connection.execute(
                text("SELECT pg_advisory_xact_lock(:key)"),
                {"key": _NODE_REGISTRY_LOCK_KEY},
            )
            connection.execute(
                text("SELECT pg_advisory_xact_lock(:key)"),
                {"key": _CAMERA_PLACEMENT_LOCK_KEY},
            )
            if connection.scalar(select(func.count()).select_from(media_nodes)):
                if _already_restored(connection, manifest, release_id, mediamtx_binary_sha256):
                    return
                raise PhaseDTransitionError("transition_target_not_empty")
            if connection.scalar(select(func.count()).select_from(camera_placements)):
                raise PhaseDTransitionError("transition_target_not_empty")
            _require_ports_bindable(manifest, port_is_bindable)
            persisted = {
                UUID(str(row["id"])): row
                for row in connection.execute(select(cameras).with_for_update()).mappings()
            }
            for camera in manifest.cameras:
                row = persisted.get(camera.id)
                if row is None or any(
                    (
                        str(row["name"]) != camera.name,
                        str(row["source_url"]) != camera.source_url,
                        str(row["public_id"]) != camera.public_id,
                        str(row["state"]) != CameraState.DELETED.value,
                    )
                ):
                    raise PhaseDTransitionError("transition_camera_identity_mismatch")
                if connection.scalar(
                    select(func.count()).select_from(public_id_tombstones).where(
                        public_id_tombstones.c.public_id == camera.public_id
                    )
                ) != 1:
                    raise PhaseDTransitionError("transition_tombstone_missing")

            counts = Counter(camera.node_id for camera in manifest.cameras)
            for node in manifest.nodes:
                last_revision = connection.scalar(
                    select(func.max(audit_events.c.aggregate_revision)).where(
                        audit_events.c.aggregate_type == "media_node",
                        audit_events.c.aggregate_id == node.id,
                    )
                )
                restored_revision = max(node.desired_revision, int(last_revision or 0)) + 1
                connection.execute(
                    insert(media_nodes).values(
                        id=node.id,
                        name=node.name,
                        external_port=node.external_port,
                        api_port=node.api_port,
                        metrics_port=node.metrics_port,
                        release_id=release_id,
                        mediamtx_binary_sha256=mediamtx_binary_sha256,
                        creation_mode=node.creation_mode.value,
                        state=node.state.value,
                        runtime_state="provisioning",
                        health="unknown",
                        registered_cameras=counts[node.id],
                        camera_capacity=100,
                        active_sources=0,
                        maintenance=node.maintenance,
                        management_fresh=False,
                        config_compatible=False,
                        desired_revision=restored_revision,
                        applied_revision=0,
                    )
                )
                _record_transition_event(
                    connection,
                    aggregate_type="media_node",
                    aggregate_id=node.id,
                    aggregate_revision=restored_revision,
                    event_type="media_node.phase_d_restored",
                    payload={"release_id": release_id},
                )
            for camera in manifest.cameras:
                row = persisted[camera.id]
                restored_revision = int(row["desired_revision"]) + 1
                restored_generation = camera.placement_generation + 1
                connection.execute(
                    update(cameras)
                    .where(cameras.c.id == camera.id, cameras.c.state == "deleted")
                    .values(
                        state=camera.state.value,
                        desired_revision=restored_revision,
                        applied_revision=0,
                    )
                )
                connection.execute(
                    insert(camera_access_policies).values(
                        camera_id=camera.id,
                        internet_cidrs=[],
                        local_cidrs=[],
                        revision=1,
                        updated_at=func.clock_timestamp(),
                    )
                )
                connection.execute(
                    insert(camera_placements).values(
                        camera_id=camera.id,
                        node_id=camera.node_id,
                        placement_mode=camera.placement_mode.value,
                        generation=restored_generation,
                    )
                )
                connection.execute(
                    insert(camera_placement_history).values(
                        camera_id=camera.id,
                        node_id=camera.node_id,
                        placement_mode=camera.placement_mode.value,
                        generation=restored_generation,
                    )
                )
                _record_transition_event(
                    connection,
                    aggregate_type="camera",
                    aggregate_id=camera.id,
                    aggregate_revision=restored_revision,
                    event_type="camera.phase_d_restored",
                    payload={
                        "node_id": str(camera.node_id),
                        "placement_generation": restored_generation,
                        "public_id": camera.public_id,
                    },
                )
                _record_transition_event(
                    connection,
                    aggregate_type="camera_access_policy",
                    aggregate_id=camera.id,
                    aggregate_revision=1,
                    event_type="camera.access_policy_created",
                    payload={
                        "camera_id": str(camera.id),
                        "internet_cidrs": [],
                        "local_cidrs": [],
                        "revision": 1,
                    },
                )
    except (SQLAlchemyError, ValueError, PhaseDTransitionError) as error:
        if isinstance(error, PhaseDTransitionError):
            raise
        raise PhaseDTransitionError("transition_restore_failed") from error
    finally:
        engine.dispose()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rtsp-proxy-phase-d-transition")
    subparsers = parser.add_subparsers(dest="operation", required=True)
    export = subparsers.add_parser("export")
    export.add_argument("--manifest", required=True, type=Path)
    restore = subparsers.add_parser("restore")
    restore.add_argument("--manifest", required=True, type=Path)
    restore.add_argument("--manifest-sha256", required=True)
    arguments = parser.parse_args(argv)
    database_url = os.environ.get("RTSP_PROXY_DATABASE_URL", "")
    try:
        if arguments.operation == "export":
            digest = export_transition(database_url, arguments.manifest)
            print(f"exported phase-d transition manifest sha256={digest}")
        else:
            settings = Settings(role=RuntimeRole.WEB)
            restore_transition(
                database_url,
                arguments.manifest,
                manifest_sha256=arguments.manifest_sha256,
                release_id=settings.node_release_id,
                mediamtx_binary_sha256=settings.node_mediamtx_binary_sha256,
                node_policy=settings.node_registration_policy(),
            )
            print("restored phase-d transition manifest")
    except (PhaseDTransitionError, ValidationError) as error:
        if isinstance(error, ValidationError):
            print("phase-d transition failed: transition_settings_invalid", file=sys.stderr)
            return 1
        print(f"phase-d transition failed: {error}", file=sys.stderr)
        return 1
    return 0


def _canonical_manifest(manifest: PhaseDTransitionManifest) -> bytes:
    return (
        json.dumps(
            manifest.model_dump(mode="json"),
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _write_new_private_file(path: Path, payload: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("transition_manifest_write_incomplete")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _read_private_manifest(path: Path) -> bytes:
    if not path.is_absolute():
        raise PhaseDTransitionError("transition_manifest_unsafe")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise OSError
            if stat.S_IMODE(metadata.st_mode) not in {0o400, 0o600}:
                raise OSError
            chunks: list[bytes] = []
            while chunk := os.read(descriptor, 1024 * 1024):
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise PhaseDTransitionError("transition_manifest_unsafe") from error


def _validate_manifest(manifest: PhaseDTransitionManifest) -> None:
    node_ids = {node.id for node in manifest.nodes}
    if len(node_ids) != len(manifest.nodes):
        raise PhaseDTransitionError("transition_node_duplicate")
    if len(manifest.nodes) > 100:
        raise PhaseDTransitionError("transition_node_limit_exceeded")
    ports = [
        port
        for node in manifest.nodes
        for port in (node.external_port, node.api_port, node.metrics_port)
    ]
    if len(set(ports)) != len(ports):
        raise PhaseDTransitionError("transition_node_port_duplicate")
    for node in manifest.nodes:
        if node.state not in _RESTORABLE_NODE_STATES:
            raise PhaseDTransitionError("transition_node_state_invalid")
        if node.maintenance is not (node.state is NodeState.MAINTENANCE):
            raise PhaseDTransitionError("transition_node_maintenance_invalid")
    camera_ids = {camera.id for camera in manifest.cameras}
    public_ids = {camera.public_id for camera in manifest.cameras}
    if len(camera_ids) != len(manifest.cameras) or len(public_ids) != len(manifest.cameras):
        raise PhaseDTransitionError("transition_camera_duplicate")
    counts = Counter(camera.node_id for camera in manifest.cameras)
    if any(camera.node_id not in node_ids for camera in manifest.cameras):
        raise PhaseDTransitionError("transition_camera_node_missing")
    if any(count > 100 for count in counts.values()):
        raise PhaseDTransitionError("transition_node_capacity_exceeded")
    for camera in manifest.cameras:
        PublicId.parse(camera.public_id)
        validate_camera_source_url(camera.source_url, allow_credentials=True)
        if camera.state not in {CameraState.ENABLED, CameraState.DISABLED}:
            raise PhaseDTransitionError("transition_camera_state_invalid")


def _validate_host_policy(
    manifest: PhaseDTransitionManifest,
    policy: NodeRegistrationPolicy,
) -> None:
    if len(manifest.nodes) > policy.max_nodes:
        raise PhaseDTransitionError("transition_max_nodes_exceeded")
    for node in manifest.nodes:
        if not policy.permits(
            external_port=node.external_port,
            api_port=node.api_port,
            metrics_port=node.metrics_port,
        ):
            raise PhaseDTransitionError("transition_node_port_out_of_policy")


def _require_ports_bindable(
    manifest: PhaseDTransitionManifest,
    port_is_bindable: PortBindable,
) -> None:
    if any(
        not port_is_bindable(port)
        for node in manifest.nodes
        for port in (node.external_port, node.api_port, node.metrics_port)
    ):
        raise PhaseDTransitionError("transition_node_port_in_use")


def _require_schema(connection: Connection, expected: str) -> None:
    revision = connection.scalar(text("SELECT version_num FROM alembic_version"))
    if revision != expected:
        raise PhaseDTransitionError("transition_schema_mismatch")


def _already_restored(
    connection: Connection,
    manifest: PhaseDTransitionManifest,
    release_id: str,
    digest: str,
) -> bool:
    nodes = tuple(connection.execute(select(media_nodes)).mappings())
    restored_node_revisions = {
        UUID(str(row["aggregate_id"])): int(row["restored_revision"])
        for row in connection.execute(
            select(
                audit_events.c.aggregate_id,
                func.max(audit_events.c.aggregate_revision).label("restored_revision"),
            )
            .where(
                audit_events.c.aggregate_type == "media_node",
                audit_events.c.event_type == "media_node.phase_d_restored",
            )
            .group_by(audit_events.c.aggregate_id)
        ).mappings()
    }
    restored_cameras = tuple(
        connection.execute(
            select(
                cameras,
                camera_placements.c.node_id,
                camera_placements.c.placement_mode,
                camera_placements.c.generation,
            )
            .join(camera_placements, camera_placements.c.camera_id == cameras.c.id)
            .where(cameras.c.state != CameraState.DELETED.value)
        ).mappings()
    )
    access_policies = {
        UUID(str(row["camera_id"])): (
            tuple(str(value) for value in row["internet_cidrs"]),
            tuple(str(value) for value in row["local_cidrs"]),
            int(row["revision"]),
        )
        for row in connection.execute(select(camera_access_policies)).mappings()
    }
    counts = Counter(camera.node_id for camera in manifest.cameras)
    expected_nodes = {
        node.id: (
            node.name,
            node.external_port,
            node.api_port,
            node.metrics_port,
            node.creation_mode.value,
            node.state.value,
            node.maintenance,
            counts[node.id],
            restored_node_revisions.get(node.id),
        )
        for node in manifest.nodes
    }
    expected_placements = {
        camera.id: (
            camera.name,
            camera.source_url,
            camera.public_id,
            camera.state.value,
            camera.node_id,
            camera.placement_mode.value,
            camera.placement_generation + 1,
        )
        for camera in manifest.cameras
    }
    return (
        {
            UUID(str(row["id"])): (
                str(row["name"]),
                int(row["external_port"]),
                int(row["api_port"]),
                int(row["metrics_port"]),
                str(row["creation_mode"]),
                str(row["state"]),
                bool(row["maintenance"]),
                int(row["registered_cameras"]),
                int(row["desired_revision"]),
            )
            for row in nodes
        }
        == expected_nodes
        and all(
            str(row["release_id"]) == release_id
            and str(row["mediamtx_binary_sha256"]) == digest
            for row in nodes
        )
        and {
            UUID(str(row["id"])): (
                str(row["name"]),
                str(row["source_url"]),
                str(row["public_id"]),
                str(row["state"]),
                UUID(str(row["node_id"])),
                str(row["placement_mode"]),
                int(row["generation"]),
            )
            for row in restored_cameras
        }
        == expected_placements
        and access_policies
        == {camera.id: ((), (), 1) for camera in manifest.cameras}
    )


def _record_transition_event(
    connection: Connection,
    *,
    aggregate_type: str,
    aggregate_id: UUID,
    aggregate_revision: int,
    event_type: str,
    payload: dict[str, object],
) -> None:
    values = {
        "aggregate_type": aggregate_type,
        "aggregate_id": aggregate_id,
        "event_type": event_type,
        "aggregate_revision": aggregate_revision,
        "payload": payload,
    }
    connection.execute(insert(audit_events).values(id=uuid4(), **values))
    connection.execute(insert(outbox_messages).values(id=uuid4(), **values))
