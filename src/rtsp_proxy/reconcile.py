from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol
from uuid import UUID

from rtsp_proxy.identifiers import PublicId
from rtsp_proxy.media import MediaNodeError, MediaPathConfig, MediaPathInventory
from rtsp_proxy.nodes import (
    CameraLifecycleConflict,
    CameraMove,
    CameraMoveExpired,
    CameraMoveState,
    CameraMoveStore,
    CameraNotFound,
    CameraPlacement,
    CameraRevisionConflict,
    CameraState,
    EligibleNodeMissing,
    MediaNode,
    NodeCameraCapacityReached,
    NodeDisruptionConfirmationContext,
    NodeLifecycleBusy,
    NodeNotFound,
    NodeState,
    ReconcileStore,
    validate_camera_name,
    validate_camera_source_url,
)


class MediaNodeClient(Protocol):
    def put_path(self, path: MediaPathConfig) -> None: ...

    def get_path(self, name: PublicId) -> MediaPathConfig | None: ...

    def inventory_paths(self) -> MediaPathInventory: ...

    def delete_path(self, name: PublicId) -> None: ...

    def path_runtime_status(self, name: PublicId) -> tuple[bool, int] | None: ...


class MediaNodeClientFactory(Protocol):
    def for_node(self, node: MediaNode) -> MediaNodeClient: ...


class CameraMutationStore(CameraMoveStore, Protocol):
    def update_camera(
        self,
        camera_id: UUID,
        *,
        name: str,
        source_url: str,
        expected_revision: int | None = None,
    ) -> CameraPlacement: ...

    def set_camera_enabled(
        self,
        camera_id: UUID,
        *,
        enabled: bool,
        expected_revision: int | None = None,
    ) -> CameraPlacement: ...

    def request_camera_delete(
        self,
        camera_id: UUID,
        *,
        expected_revision: int | None = None,
    ) -> CameraPlacement: ...


@dataclass(frozen=True, slots=True)
class ReconcileReport:
    node_id: UUID
    applied: int
    unchanged: int
    deleted_orphans: int


class ReconcileRetry(RuntimeError):
    """The desired state remains authoritative but was not verified as applied."""


class ReconcileCancelled(RuntimeError):
    """Cooperative shutdown stopped a reconcile cycle at an operation boundary."""


def _continue_or_cancel(cancelled: Callable[[], bool]) -> None:
    if cancelled():
        raise ReconcileCancelled("camera_reconcile_cancelled")


@dataclass(frozen=True, slots=True)
class CameraRuntimeObservation:
    camera_id: UUID
    node_id: UUID
    ready: bool
    reader_count: int
    occupied: bool
    reader_limit_violated: bool


class CameraRuntimeObserver:
    def __init__(
        self,
        *,
        store: ReconcileStore,
        media_nodes: MediaNodeClientFactory,
    ) -> None:
        self._store = store
        self._media_nodes = media_nodes

    def observe(self, camera_id: UUID) -> CameraRuntimeObservation:
        camera = self._store.get_camera(camera_id)
        if camera is None:
            raise CameraNotFound("camera_not_found")
        node = self._store.get_node(camera.node_id)
        if node is None:
            raise ReconcileRetry("camera_runtime_node_missing")
        status = self._media_nodes.for_node(node).path_runtime_status(camera.public_id)
        ready, readers = (False, 0) if status is None else status
        return CameraRuntimeObservation(
            camera_id=camera.id,
            node_id=camera.node_id,
            ready=ready,
            reader_count=readers,
            occupied=readers == 1,
            reader_limit_violated=readers > 1,
        )


class CameraOccupied(RuntimeError):
    """An ordinary camera move cannot interrupt its active reader."""


class CameraReaderInvariantViolation(RuntimeError):
    """Runtime evidence observed more than the supported single reader."""


class MoveConfirmationRequired(RuntimeError):
    """A forced move lacks a valid revision/blast-radius confirmation."""


class CameraDisruptionConfirmationRequired(RuntimeError):
    """A disruptive camera mutation lacks current blast-radius confirmation."""


class CameraMutationOperation(StrEnum):
    UPDATE_SOURCE = "update_source"
    DISABLE = "disable"
    DELETE = "delete"


def _valid_confirmation_digest(value: str) -> bool:
    return len(value) == 64 and not set(value) - set("0123456789abcdef")


def _confirmation_context_payload(
    context: NodeDisruptionConfirmationContext | None,
) -> dict[str, object] | None:
    if context is None:
        return None
    return {
        "account_id": str(context.account_id),
        "session_id": str(context.session_id),
        "authz_version": context.authz_version,
        "mfa_verified_at_unix_ms": context.mfa_verified_at_unix_ms,
    }


@dataclass(frozen=True, slots=True)
class CameraMutationPreview:
    camera_id: UUID
    operation: CameraMutationOperation
    desired_revision: int
    occupied: bool
    disconnect_readers: int
    mutation_sha256: str
    confirmation_token: str | None


@dataclass(frozen=True, slots=True)
class CameraMovePreview:
    camera_id: UUID
    source_node_id: UUID
    target_node_id: UUID
    desired_revision: int
    occupied: bool
    disconnect_readers: int
    confirmation_token: str | None
    source_port: int
    target_port: int
    source_endpoint: str
    target_endpoint: str


@dataclass(frozen=True, slots=True)
class CameraMoveTarget:
    id: UUID
    name: str
    external_port: int
    registered_cameras: int
    camera_capacity: int


class ConfirmationTokenService:
    def __init__(
        self,
        *,
        secret: bytes,
        lifetime_seconds: int,
        wall_time: Callable[[], float] = time.time,
    ) -> None:
        if len(secret) < 32:
            raise ValueError("confirmation_secret_too_short")
        if lifetime_seconds < 1 or lifetime_seconds > 300:
            raise ValueError("confirmation_lifetime_invalid")
        self._secret = secret
        self._lifetime_seconds = lifetime_seconds
        self._wall_time = wall_time

    def issue(
        self,
        *,
        camera_id: UUID,
        source_node_id: UUID,
        target_node_id: UUID,
        desired_revision: int,
        disconnect_readers: int,
    ) -> str:
        payload = self._payload(
            camera_id=camera_id,
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            desired_revision=desired_revision,
            disconnect_readers=disconnect_readers,
            expires_at=int(self._wall_time()) + self._lifetime_seconds,
        )
        return self._sign(payload)

    def verify(
        self,
        token: str,
        *,
        camera_id: UUID,
        source_node_id: UUID,
        target_node_id: UUID,
        desired_revision: int,
        disconnect_readers: int,
    ) -> bool:
        decoded_token = self._decode(token)
        if decoded_token is None:
            return False
        payload, signature, decoded = decoded_token
        expires_at = decoded.get("expires_at")
        if (
            not isinstance(decoded, dict)
            or not isinstance(expires_at, int)
            or isinstance(expires_at, bool)
            or expires_at < int(self._wall_time())
        ):
            return False
        expected = self._payload(
            camera_id=camera_id,
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            desired_revision=desired_revision,
            disconnect_readers=disconnect_readers,
            expires_at=expires_at,
        )
        expected_signature = hmac.new(self._secret, expected, hashlib.sha256).hexdigest()
        return hmac.compare_digest(payload, expected) and hmac.compare_digest(
            signature,
            expected_signature,
        )

    def issue_node_port_change(
        self,
        *,
        node_id: UUID,
        old_port: int,
        new_port: int,
        desired_revision: int,
        registered_cameras: int,
        blast_radius_sha256: str,
        reader_blast_radius_sha256: str = "0" * 64,
        active_readers: int = 0,
        confirmation_context: NodeDisruptionConfirmationContext | None = None,
    ) -> str:
        return self._sign(
            self._node_port_payload(
                node_id=node_id,
                old_port=old_port,
                new_port=new_port,
                desired_revision=desired_revision,
                registered_cameras=registered_cameras,
                blast_radius_sha256=blast_radius_sha256,
                reader_blast_radius_sha256=reader_blast_radius_sha256,
                active_readers=active_readers,
                confirmation_context=confirmation_context,
                expires_at=int(self._wall_time()) + self._lifetime_seconds,
            )
        )

    def verify_node_port_change(
        self,
        token: str,
        *,
        node_id: UUID,
        old_port: int,
        new_port: int,
        desired_revision: int,
        registered_cameras: int,
        blast_radius_sha256: str,
        reader_blast_radius_sha256: str = "0" * 64,
        active_readers: int = 0,
        confirmation_context: NodeDisruptionConfirmationContext | None = None,
    ) -> bool:
        if not _valid_confirmation_digest(blast_radius_sha256) or not (
            _valid_confirmation_digest(reader_blast_radius_sha256)
        ):
            return False
        decoded_token = self._decode(token)
        if decoded_token is None:
            return False
        payload, signature, decoded = decoded_token
        expires_at = decoded.get("expires_at")
        if (
            not isinstance(expires_at, int)
            or isinstance(expires_at, bool)
            or expires_at < int(self._wall_time())
        ):
            return False
        expected = self._node_port_payload(
            node_id=node_id,
            old_port=old_port,
            new_port=new_port,
            desired_revision=desired_revision,
            registered_cameras=registered_cameras,
            blast_radius_sha256=blast_radius_sha256,
            reader_blast_radius_sha256=reader_blast_radius_sha256,
            active_readers=active_readers,
            confirmation_context=confirmation_context,
            expires_at=expires_at,
        )
        expected_signature = hmac.new(self._secret, expected, hashlib.sha256).hexdigest()
        return hmac.compare_digest(payload, expected) and hmac.compare_digest(
            signature,
            expected_signature,
        )

    def issue_node_reconfigure(
        self,
        *,
        node_id: UUID,
        external_port: int,
        desired_revision: int,
        registered_cameras: int,
        blast_radius_sha256: str,
        target_release_id: str,
        target_mediamtx_binary_sha256: str,
        reader_blast_radius_sha256: str = "0" * 64,
        active_readers: int = 0,
        confirmation_context: NodeDisruptionConfirmationContext | None = None,
    ) -> str:
        return self._sign(
            self._node_reconfigure_payload(
                node_id=node_id,
                external_port=external_port,
                desired_revision=desired_revision,
                registered_cameras=registered_cameras,
                blast_radius_sha256=blast_radius_sha256,
                target_release_id=target_release_id,
                target_mediamtx_binary_sha256=target_mediamtx_binary_sha256,
                reader_blast_radius_sha256=reader_blast_radius_sha256,
                active_readers=active_readers,
                confirmation_context=confirmation_context,
                expires_at=int(self._wall_time()) + self._lifetime_seconds,
            )
        )

    def verify_node_reconfigure(
        self,
        token: str,
        *,
        node_id: UUID,
        external_port: int,
        desired_revision: int,
        registered_cameras: int,
        blast_radius_sha256: str,
        target_release_id: str,
        target_mediamtx_binary_sha256: str,
        reader_blast_radius_sha256: str = "0" * 64,
        active_readers: int = 0,
        confirmation_context: NodeDisruptionConfirmationContext | None = None,
    ) -> bool:
        if not _valid_confirmation_digest(blast_radius_sha256) or not (
            _valid_confirmation_digest(reader_blast_radius_sha256)
        ):
            return False
        decoded_token = self._decode(token)
        if decoded_token is None:
            return False
        payload, signature, decoded = decoded_token
        expires_at = decoded.get("expires_at")
        if (
            not isinstance(expires_at, int)
            or isinstance(expires_at, bool)
            or expires_at < int(self._wall_time())
        ):
            return False
        expected = self._node_reconfigure_payload(
            node_id=node_id,
            external_port=external_port,
            desired_revision=desired_revision,
            registered_cameras=registered_cameras,
            blast_radius_sha256=blast_radius_sha256,
            target_release_id=target_release_id,
            target_mediamtx_binary_sha256=target_mediamtx_binary_sha256,
            reader_blast_radius_sha256=reader_blast_radius_sha256,
            active_readers=active_readers,
            confirmation_context=confirmation_context,
            expires_at=expires_at,
        )
        expected_signature = hmac.new(self._secret, expected, hashlib.sha256).hexdigest()
        return hmac.compare_digest(payload, expected) and hmac.compare_digest(
            signature,
            expected_signature,
        )

    def issue_camera_mutation(
        self,
        *,
        camera_id: UUID,
        operation: CameraMutationOperation,
        desired_revision: int,
        disconnect_readers: int,
        mutation_sha256: str,
    ) -> str:
        return self._sign(
            self._camera_mutation_payload(
                camera_id=camera_id,
                operation=operation,
                desired_revision=desired_revision,
                disconnect_readers=disconnect_readers,
                mutation_sha256=mutation_sha256,
                expires_at=int(self._wall_time()) + self._lifetime_seconds,
            )
        )

    def verify_camera_mutation(
        self,
        token: str,
        *,
        camera_id: UUID,
        operation: CameraMutationOperation,
        desired_revision: int,
        disconnect_readers: int,
        mutation_sha256: str,
    ) -> bool:
        decoded_token = self._decode(token)
        if decoded_token is None:
            return False
        payload, signature, decoded = decoded_token
        expires_at = decoded.get("expires_at")
        if (
            not isinstance(expires_at, int)
            or isinstance(expires_at, bool)
            or expires_at < int(self._wall_time())
        ):
            return False
        expected = self._camera_mutation_payload(
            camera_id=camera_id,
            operation=operation,
            desired_revision=desired_revision,
            disconnect_readers=disconnect_readers,
            mutation_sha256=mutation_sha256,
            expires_at=expires_at,
        )
        expected_signature = hmac.new(self._secret, expected, hashlib.sha256).hexdigest()
        return hmac.compare_digest(payload, expected) and hmac.compare_digest(
            signature,
            expected_signature,
        )

    def _sign(self, payload: bytes) -> str:
        encoded = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
        signature = hmac.new(self._secret, payload, hashlib.sha256).hexdigest()
        return f"{encoded}.{signature}"

    @staticmethod
    def _decode(token: str) -> tuple[bytes, str, dict[str, object]] | None:
        if len(token) > 4096:
            return None
        try:
            encoded, signature = token.split(".", 1)
            payload = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
            decoded = json.loads(payload)
        except (TypeError, ValueError, UnicodeError, json.JSONDecodeError):
            return None
        if not isinstance(decoded, dict):
            return None
        return payload, signature, decoded

    @staticmethod
    def _node_port_payload(
        *,
        node_id: UUID,
        old_port: int,
        new_port: int,
        desired_revision: int,
        registered_cameras: int,
        blast_radius_sha256: str,
        reader_blast_radius_sha256: str,
        active_readers: int,
        confirmation_context: NodeDisruptionConfirmationContext | None,
        expires_at: int,
    ) -> bytes:
        return json.dumps(
            {
                "blast_radius_sha256": blast_radius_sha256,
                "reader_blast_radius_sha256": reader_blast_radius_sha256,
                "active_readers": active_readers,
                "confirmation_context": _confirmation_context_payload(confirmation_context),
                "desired_revision": desired_revision,
                "expires_at": expires_at,
                "new_port": new_port,
                "node_id": str(node_id),
                "old_port": old_port,
                "operation": "node_port_change",
                "registered_cameras": registered_cameras,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    @staticmethod
    def _node_reconfigure_payload(
        *,
        node_id: UUID,
        external_port: int,
        desired_revision: int,
        registered_cameras: int,
        blast_radius_sha256: str,
        target_release_id: str,
        target_mediamtx_binary_sha256: str,
        reader_blast_radius_sha256: str,
        active_readers: int,
        confirmation_context: NodeDisruptionConfirmationContext | None,
        expires_at: int,
    ) -> bytes:
        return json.dumps(
            {
                "blast_radius_sha256": blast_radius_sha256,
                "reader_blast_radius_sha256": reader_blast_radius_sha256,
                "active_readers": active_readers,
                "confirmation_context": _confirmation_context_payload(confirmation_context),
                "desired_revision": desired_revision,
                "expires_at": expires_at,
                "external_port": external_port,
                "node_id": str(node_id),
                "operation": "node_reconfigure",
                "registered_cameras": registered_cameras,
                "target_release_id": target_release_id,
                "target_mediamtx_binary_sha256": target_mediamtx_binary_sha256,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    @staticmethod
    def _camera_mutation_payload(
        *,
        camera_id: UUID,
        operation: CameraMutationOperation,
        desired_revision: int,
        disconnect_readers: int,
        mutation_sha256: str,
        expires_at: int,
    ) -> bytes:
        if len(mutation_sha256) != 64:
            raise ValueError("camera_mutation_digest_invalid")
        return json.dumps(
            {
                "camera_id": str(camera_id),
                "desired_revision": desired_revision,
                "disconnect_readers": disconnect_readers,
                "expires_at": expires_at,
                "mutation_sha256": mutation_sha256,
                "operation": operation.value,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    @staticmethod
    def _payload(
        *,
        camera_id: UUID,
        source_node_id: UUID,
        target_node_id: UUID,
        desired_revision: int,
        disconnect_readers: int,
        expires_at: int,
    ) -> bytes:
        return json.dumps(
            {
                "camera_id": str(camera_id),
                "desired_revision": desired_revision,
                "disconnect_readers": disconnect_readers,
                "expires_at": expires_at,
                "operation": "camera_move_force",
                "source_node_id": str(source_node_id),
                "target_node_id": str(target_node_id),
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")


class CameraMoveControl:
    def __init__(
        self,
        *,
        store: CameraMoveStore,
        runtime: CameraRuntimeObserver,
        confirmations: ConfirmationTokenService,
        new_move_id: Callable[[], UUID],
        move_timeout_seconds: int = 300,
        management_freshness_seconds: int = 30,
    ) -> None:
        self._store = store
        self._runtime = runtime
        self._confirmations = confirmations
        self._new_move_id = new_move_id
        if move_timeout_seconds < 1 or move_timeout_seconds > 3600:
            raise ValueError("camera_move_timeout_invalid")
        self._move_timeout_seconds = move_timeout_seconds
        if management_freshness_seconds < 1 or management_freshness_seconds > 300:
            raise ValueError("management_freshness_seconds_invalid")
        self._management_freshness_seconds = management_freshness_seconds

    def targets(
        self,
        camera_id: UUID,
        *,
        expected_revision: int | None = None,
    ) -> tuple[CameraMoveTarget, ...]:
        self._camera(camera_id, expected_revision=expected_revision)
        nodes = self._store.list_camera_move_targets(
            camera_id,
            management_freshness_seconds=self._management_freshness_seconds,
        )
        return tuple(
            CameraMoveTarget(
                id=node.id,
                name=node.name,
                external_port=node.external_port,
                registered_cameras=node.registered_cameras,
                camera_capacity=node.camera_capacity,
            )
            for node in sorted(
                nodes,
                key=lambda node: (
                    node.registered_cameras,
                    node.name,
                    str(node.id),
                ),
            )
        )

    def preview(
        self,
        camera_id: UUID,
        *,
        target_node_id: UUID,
        expected_revision: int | None = None,
    ) -> CameraMovePreview:
        camera = self._camera(camera_id, expected_revision=expected_revision)
        target = next(
            (
                node
                for node in self._store.list_camera_move_targets(
                    camera_id,
                    management_freshness_seconds=self._management_freshness_seconds,
                )
                if node.id == target_node_id
            ),
            None,
        )
        known_target = self._store.get_node(target_node_id)
        if known_target is None:
            raise NodeNotFound("node_not_found")
        if known_target.id == camera.node_id:
            raise CameraLifecycleConflict("camera_already_on_target")
        if known_target.registered_cameras >= known_target.camera_capacity:
            raise NodeCameraCapacityReached("node_camera_capacity_reached")
        if target is None:
            raise EligibleNodeMissing("manual_node_ineligible")
        observation = self._runtime.observe(camera_id)
        if observation.reader_limit_violated:
            raise CameraReaderInvariantViolation("camera_reader_limit_violated")
        disconnect_readers = observation.reader_count if observation.occupied else 0
        token = (
            self._confirmations.issue(
                camera_id=camera.id,
                source_node_id=camera.node_id,
                target_node_id=target_node_id,
                desired_revision=camera.desired_revision,
                disconnect_readers=disconnect_readers,
            )
            if observation.occupied
            else None
        )
        return CameraMovePreview(
            camera_id=camera.id,
            source_node_id=camera.node_id,
            target_node_id=target_node_id,
            desired_revision=camera.desired_revision,
            occupied=observation.occupied,
            disconnect_readers=disconnect_readers,
            confirmation_token=token,
            source_port=camera.node_port,
            target_port=target.external_port,
            source_endpoint=f"rtsp://server:{camera.node_port}/{camera.public_id}",
            target_endpoint=f"rtsp://server:{target.external_port}/{camera.public_id}",
        )

    def request_move(
        self,
        camera_id: UUID,
        *,
        target_node_id: UUID,
        expected_revision: int | None = None,
        force: bool = False,
        confirmation_token: str | None = None,
    ) -> CameraMove:
        preview = self.preview(
            camera_id,
            target_node_id=target_node_id,
            expected_revision=expected_revision,
        )
        if preview.occupied and not force:
            raise CameraOccupied("camera_occupied")
        if confirmation_token is not None and (
            not force
            or not self._confirmations.verify(
                confirmation_token,
                camera_id=preview.camera_id,
                source_node_id=preview.source_node_id,
                target_node_id=preview.target_node_id,
                desired_revision=preview.desired_revision,
                disconnect_readers=preview.disconnect_readers,
            )
        ):
            raise MoveConfirmationRequired("move_confirmation_required")
        if preview.occupied and confirmation_token is None:
            raise MoveConfirmationRequired("move_confirmation_required")
        return self._store.create_camera_move(
            move_id=self._new_move_id(),
            camera_id=camera_id,
            target_node_id=target_node_id,
            expected_revision=preview.desired_revision,
            force=force,
            confirmed_disconnect_readers=preview.disconnect_readers,
            timeout_seconds=self._move_timeout_seconds,
            management_freshness_seconds=self._management_freshness_seconds,
        )

    def get_move(self, move_id: UUID) -> CameraMove | None:
        return self._store.get_camera_move(move_id)

    def _camera(
        self,
        camera_id: UUID,
        *,
        expected_revision: int | None,
    ) -> CameraPlacement:
        camera = self._store.get_camera(camera_id)
        if camera is None:
            raise CameraNotFound("camera_not_found")
        if expected_revision is not None and camera.desired_revision != expected_revision:
            raise CameraRevisionConflict(
                expected_revision=expected_revision,
                current_revision=camera.desired_revision,
            )
        if camera.state is not CameraState.ENABLED:
            raise CameraLifecycleConflict("camera_not_enabled")
        return camera


class CameraMutationControl:
    """Fence reader-disruptive camera mutations at the MediaMTX path boundary."""

    def __init__(
        self,
        *,
        store: CameraMutationStore,
        media_nodes: MediaNodeClientFactory,
        confirmations: ConfirmationTokenService,
    ) -> None:
        self._store = store
        self._media_nodes = media_nodes
        self._confirmations = confirmations

    def preview(
        self,
        camera_id: UUID,
        *,
        operation: CameraMutationOperation,
        expected_revision: int | None = None,
        name: str | None = None,
        source_url: str | None = None,
    ) -> CameraMutationPreview:
        camera = self._camera(camera_id, expected_revision=expected_revision)
        if operation is CameraMutationOperation.UPDATE_SOURCE:
            if name is None or source_url is None:
                raise ValueError("camera_mutation_payload_required")
            validate_camera_name(name)
            validate_camera_source_url(source_url)
        mutation_sha256 = self._mutation_sha256(
            operation=operation,
            name=name,
            source_url=source_url,
        )
        status = self._status(camera)
        readers = 0 if status is None else status[1]
        if readers > 1:
            raise CameraReaderInvariantViolation("camera_reader_limit_violated")
        token = (
            self._confirmations.issue_camera_mutation(
                camera_id=camera.id,
                operation=operation,
                desired_revision=camera.desired_revision,
                disconnect_readers=readers,
                mutation_sha256=mutation_sha256,
            )
            if readers == 1
            else None
        )
        return CameraMutationPreview(
            camera_id=camera.id,
            operation=operation,
            desired_revision=camera.desired_revision,
            occupied=readers == 1,
            disconnect_readers=readers,
            mutation_sha256=mutation_sha256,
            confirmation_token=token,
        )

    def update(
        self,
        camera_id: UUID,
        *,
        name: str,
        source_url: str,
        expected_revision: int | None = None,
        confirmation_token: str | None,
    ) -> CameraPlacement:
        name = validate_camera_name(name)
        camera = self._camera(camera_id, expected_revision=expected_revision)
        if camera.source_url == source_url and confirmation_token is None:
            return self._store.update_camera(
                camera_id,
                name=name,
                source_url=source_url,
                expected_revision=camera.desired_revision,
            )
        with self._fence(
            camera,
            operation=CameraMutationOperation.UPDATE_SOURCE,
            name=name,
            source_url=source_url,
            confirmation_token=confirmation_token,
        ):
            return self._store.update_camera(
                camera_id,
                name=name,
                source_url=source_url,
                expected_revision=camera.desired_revision,
            )

    def disable(
        self,
        camera_id: UUID,
        *,
        expected_revision: int | None = None,
        confirmation_token: str | None,
    ) -> CameraPlacement:
        camera = self._camera(camera_id, expected_revision=expected_revision)
        if camera.state is CameraState.DISABLED:
            return camera
        with self._fence(
            camera,
            operation=CameraMutationOperation.DISABLE,
            name=None,
            source_url=None,
            confirmation_token=confirmation_token,
        ):
            return self._store.set_camera_enabled(
                camera_id,
                enabled=False,
                expected_revision=camera.desired_revision,
            )

    def delete(
        self,
        camera_id: UUID,
        *,
        expected_revision: int | None = None,
        confirmation_token: str | None,
    ) -> CameraPlacement:
        camera = self._camera(camera_id, expected_revision=expected_revision)
        with self._fence(
            camera,
            operation=CameraMutationOperation.DELETE,
            name=None,
            source_url=None,
            confirmation_token=confirmation_token,
        ):
            return self._store.request_camera_delete(
                camera_id,
                expected_revision=camera.desired_revision,
            )

    @contextmanager
    def _fence(
        self,
        camera: CameraPlacement,
        *,
        operation: CameraMutationOperation,
        name: str | None,
        source_url: str | None,
        confirmation_token: str | None,
    ) -> Iterator[None]:
        mutation_sha256 = self._mutation_sha256(
            operation=operation,
            name=name,
            source_url=source_url,
        )
        with self._store.reconcile_guard(camera.node_id):
            current = self._camera(camera.id)
            if current.desired_revision != camera.desired_revision:
                raise CameraRevisionConflict(
                    expected_revision=camera.desired_revision,
                    current_revision=current.desired_revision,
                )
            node = self._store.get_node(current.node_id)
            if node is None:
                raise ReconcileRetry("camera_runtime_node_missing")
            client = self._media_nodes.for_node(node)
            quiesced = MediaPathConfig(
                name=current.public_id,
                source_url=current.source_url,
                max_readers=-1,
            )
            client.put_path(quiesced)
            if client.get_path(current.public_id) != quiesced:
                raise ReconcileRetry("camera_mutation_quiesce_unverified")
            status = client.path_runtime_status(current.public_id)
            readers = 0 if status is None else status[1]
            if readers > 1:
                raise CameraReaderInvariantViolation("camera_reader_limit_violated")
            confirmation_invalid = confirmation_token is not None and not (
                self._confirmations.verify_camera_mutation(
                    confirmation_token,
                    camera_id=current.id,
                    operation=operation,
                    desired_revision=current.desired_revision,
                    disconnect_readers=1,
                    mutation_sha256=mutation_sha256,
                )
            )
            if confirmation_invalid or (readers == 1 and confirmation_token is None):
                client.put_path(
                    MediaPathConfig(name=current.public_id, source_url=current.source_url)
                )
                raise CameraDisruptionConfirmationRequired(
                    "camera_disruption_confirmation_required"
                )
            try:
                yield
            except Exception:
                client.put_path(
                    MediaPathConfig(name=current.public_id, source_url=current.source_url)
                )
                raise

    def _camera(
        self,
        camera_id: UUID,
        *,
        expected_revision: int | None = None,
    ) -> CameraPlacement:
        camera = self._store.get_camera(camera_id)
        if camera is None:
            raise CameraNotFound("camera_not_found")
        if expected_revision is not None and camera.desired_revision != expected_revision:
            raise CameraRevisionConflict(
                expected_revision=expected_revision,
                current_revision=camera.desired_revision,
            )
        return camera

    def _status(self, camera: CameraPlacement) -> tuple[bool, int] | None:
        node = self._store.get_node(camera.node_id)
        if node is None:
            raise ReconcileRetry("camera_runtime_node_missing")
        return self._media_nodes.for_node(node).path_runtime_status(camera.public_id)

    @staticmethod
    def _mutation_sha256(
        *,
        operation: CameraMutationOperation,
        name: str | None,
        source_url: str | None,
    ) -> str:
        payload = json.dumps(
            {"name": name, "operation": operation.value, "source_url": source_url},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()


class CameraMoveReconciler:
    def __init__(
        self,
        *,
        store: CameraMoveStore,
        media_nodes: MediaNodeClientFactory,
    ) -> None:
        self._store = store
        self._media_nodes = media_nodes

    def resume(
        self,
        move_id: UUID,
        *,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> CameraMove:
        _continue_or_cancel(cancelled)
        move = self._store.get_camera_move(move_id)
        if move is None:
            raise CameraNotFound("camera_move_not_found")
        if move.state in {CameraMoveState.COMPLETE, CameraMoveState.ABORTED}:
            return move
        with self._node_guards(move, cancelled):
            move = self._store.get_camera_move(move_id)
            if move is None:
                raise CameraNotFound("camera_move_not_found")
            if move.state is CameraMoveState.PREPARE_TARGET:
                self._prepare_and_verify(move, cancelled)
                try:
                    self._quiesce_and_validate_source(move, cancelled)
                    _continue_or_cancel(cancelled)
                    move = self._store.switch_camera_move(
                        move.id,
                        cancelled=cancelled,
                    )
                except CameraMoveExpired:
                    move = self._store.request_camera_move_abort(
                        move.id,
                        reason="camera_move_expired",
                        cancelled=cancelled,
                    )
                except (
                    CameraOccupied,
                    CameraReaderInvariantViolation,
                    MoveConfirmationRequired,
                ):
                    move = self._store.request_camera_move_abort(
                        move.id,
                        reason="camera_move_occupancy_changed",
                        cancelled=cancelled,
                    )
                except (EligibleNodeMissing, NodeCameraCapacityReached):
                    move = self._store.request_camera_move_abort(
                        move.id,
                        reason="camera_move_target_ineligible",
                        cancelled=cancelled,
                    )
            if move.state is CameraMoveState.CLEANUP_TARGET:
                self._cleanup_target(move, cancelled)
                self._restore_source(move, cancelled)
                _continue_or_cancel(cancelled)
                move = self._store.abort_camera_move(move.id)
            if move.state is CameraMoveState.CLEANUP_SOURCE:
                self._cleanup_source(move, cancelled)
                _continue_or_cancel(cancelled)
                move = self._store.mark_camera_move_source_cleaned(move.id)
            if move.state is CameraMoveState.ACTIVATE_TARGET:
                self._activate_target(move, cancelled)
                _continue_or_cancel(cancelled)
                move = self._store.complete_camera_move(move.id)
        return move

    def _node_guards(
        self,
        move: CameraMove,
        cancelled: Callable[[], bool],
    ) -> ExitStack:
        stack = ExitStack()
        try:
            for node_id in sorted(
                {move.source_node_id, move.target_node_id},
                key=lambda value: value.int,
            ):
                stack.enter_context(self._store.reconcile_guard(node_id, cancelled=cancelled))
        except Exception:
            stack.close()
            raise
        return stack

    def _prepare_and_verify(
        self,
        move: CameraMove,
        cancelled: Callable[[], bool],
    ) -> None:
        _continue_or_cancel(cancelled)
        target = self._store.get_node(move.target_node_id)
        if target is None:
            raise ReconcileRetry("camera_move_target_missing")
        client = self._media_nodes.for_node(target)
        expected = MediaPathConfig(
            name=move.public_id,
            source_url=move.source_url,
            max_readers=-1,
        )
        try:
            if client.get_path(move.public_id) != expected:
                _continue_or_cancel(cancelled)
                client.put_path(expected)
            _continue_or_cancel(cancelled)
            actual = client.get_path(move.public_id)
        except MediaNodeError:
            actual = CameraReconciler._safe_read_back(client, expected, cancelled)
        if actual != expected:
            raise ReconcileRetry("camera_move_target_unverified")

    def _activate_target(
        self,
        move: CameraMove,
        cancelled: Callable[[], bool],
    ) -> None:
        _continue_or_cancel(cancelled)
        target = self._store.get_node(move.target_node_id)
        if target is None:
            raise ReconcileRetry("camera_move_target_missing")
        client = self._media_nodes.for_node(target)
        expected = MediaPathConfig(name=move.public_id, source_url=move.source_url)
        client.put_path(expected)
        _continue_or_cancel(cancelled)
        if client.get_path(move.public_id) != expected:
            raise ReconcileRetry("camera_move_target_activation_unverified")

    def _cleanup_source(
        self,
        move: CameraMove,
        cancelled: Callable[[], bool],
    ) -> None:
        _continue_or_cancel(cancelled)
        source = self._store.get_node(move.source_node_id)
        if source is None:
            raise ReconcileRetry("camera_move_source_missing")
        client = self._media_nodes.for_node(source)
        CameraReconciler._remove_disabled_path(client, move.public_id, cancelled)

    def _cleanup_target(
        self,
        move: CameraMove,
        cancelled: Callable[[], bool],
    ) -> None:
        _continue_or_cancel(cancelled)
        target = self._store.get_node(move.target_node_id)
        if target is None:
            raise ReconcileRetry("camera_move_target_missing")
        CameraReconciler._remove_disabled_path(
            self._media_nodes.for_node(target),
            move.public_id,
            cancelled,
        )

    def _restore_source(
        self,
        move: CameraMove,
        cancelled: Callable[[], bool],
    ) -> None:
        _continue_or_cancel(cancelled)
        source = self._store.get_node(move.source_node_id)
        if source is None:
            raise ReconcileRetry("camera_move_source_missing")
        client = self._media_nodes.for_node(source)
        expected = MediaPathConfig(name=move.public_id, source_url=move.source_url)
        _continue_or_cancel(cancelled)
        client.put_path(expected)
        _continue_or_cancel(cancelled)
        if client.get_path(move.public_id) != expected:
            raise ReconcileRetry("camera_move_source_restore_unverified")

    def _quiesce_and_validate_source(
        self,
        move: CameraMove,
        cancelled: Callable[[], bool],
    ) -> None:
        _continue_or_cancel(cancelled)
        source = self._store.get_node(move.source_node_id)
        if source is None:
            raise ReconcileRetry("camera_move_source_missing")
        client = self._media_nodes.for_node(source)
        quiesced = MediaPathConfig(
            name=move.public_id,
            source_url=move.source_url,
            max_readers=-1,
        )
        client.put_path(quiesced)
        _continue_or_cancel(cancelled)
        if client.get_path(move.public_id) != quiesced:
            raise ReconcileRetry("camera_move_quiesce_unverified")
        _continue_or_cancel(cancelled)
        status = client.path_runtime_status(move.public_id)
        readers = 0 if status is None else status[1]
        if readers > 1:
            raise CameraReaderInvariantViolation("camera_reader_limit_violated")
        if not move.force and readers != 0:
            raise CameraOccupied("camera_occupied")
        if move.force and readers != move.confirmed_disconnect_readers:
            raise MoveConfirmationRequired("move_confirmation_required")


@dataclass(frozen=True, slots=True)
class ReconcileCycleReport:
    completed_moves: int
    reconciled_nodes: int
    retryable_failures: int


class ReconcileCoordinator:
    def __init__(
        self,
        *,
        store: CameraMoveStore,
        cameras: CameraReconciler,
        moves: CameraMoveReconciler,
    ) -> None:
        self._store = store
        self._cameras = cameras
        self._moves = moves

    def run_once(
        self,
        *,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> ReconcileCycleReport:
        completed_moves = 0
        reconciled_nodes = 0
        retryable_failures = 0
        for move in self._store.list_incomplete_camera_moves():
            _continue_or_cancel(cancelled)
            try:
                result = self._moves.resume(move.id, cancelled=cancelled)
                if result.state is CameraMoveState.COMPLETE:
                    completed_moves += 1
            except (
                ReconcileRetry,
                MediaNodeError,
                CameraLifecycleConflict,
                NodeLifecycleBusy,
            ):
                retryable_failures += 1
        for node in self._store.list_nodes():
            _continue_or_cancel(cancelled)
            if node.runtime_state is not NodeState.RUNNING:
                continue
            try:
                self._cameras.reconcile_node(node.id, cancelled=cancelled)
                reconciled_nodes += 1
            except (
                ReconcileRetry,
                MediaNodeError,
                CameraLifecycleConflict,
                NodeLifecycleBusy,
            ):
                retryable_failures += 1
        return ReconcileCycleReport(
            completed_moves=completed_moves,
            reconciled_nodes=reconciled_nodes,
            retryable_failures=retryable_failures,
        )


class CameraReconciler:
    def __init__(
        self,
        *,
        store: ReconcileStore,
        media_nodes: MediaNodeClientFactory,
    ) -> None:
        self._store = store
        self._media_nodes = media_nodes

    def reconcile_node(
        self,
        node_id: UUID,
        *,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> ReconcileReport:
        _continue_or_cancel(cancelled)
        with self._store.reconcile_guard(node_id, cancelled=cancelled):
            node = self._store.get_node(node_id)
            if node is None:
                raise NodeNotFound("node_not_found")
            if node.runtime_state is not NodeState.RUNNING or not node.config_compatible:
                raise ReconcileRetry("camera_reconcile_node_unavailable")
            client = self._media_nodes.for_node(node)
            desired = self._store.list_node_cameras(node_id)
            active_moves = self._store.list_node_active_moves(node_id)
            inventory = client.inventory_paths()
            if not inventory.no_oracle_matcher_present:
                raise ReconcileRetry("camera_reconcile_reserved_path_missing")
            known_ids = {camera.public_id for camera in desired}.union(
                move.public_id for move in active_moves
            )
            move_camera_ids = {move.camera_id for move in active_moves}
            applied = 0
            unchanged = 0

            for camera in desired:
                _continue_or_cancel(cancelled)
                if camera.id in move_camera_ids:
                    unchanged += 1
                    continue
                if camera.state is not CameraState.ENABLED:
                    self._remove_disabled_path(client, camera.public_id, cancelled)
                    if not self._store.mark_camera_applied(
                        camera_id=camera.id,
                        node_id=node_id,
                        placement_generation=camera.placement_generation,
                        desired_revision=camera.desired_revision,
                    ):
                        raise ReconcileRetry("camera_reconcile_fenced")
                    applied += 1
                    continue
                path = MediaPathConfig(
                    name=camera.public_id,
                    source_url=camera.source_url,
                    max_readers=1,
                )
                try:
                    actual = client.get_path(camera.public_id)
                    changed = actual != path
                    if changed:
                        _continue_or_cancel(cancelled)
                        client.put_path(path)
                    _continue_or_cancel(cancelled)
                    verified = client.get_path(camera.public_id)
                except MediaNodeError:
                    verified = self._safe_read_back(client, path, cancelled)
                    changed = True
                if verified != path:
                    raise ReconcileRetry("camera_reconcile_unverified")
                if not self._store.mark_camera_applied(
                    camera_id=camera.id,
                    node_id=node_id,
                    placement_generation=camera.placement_generation,
                    desired_revision=camera.desired_revision,
                ):
                    raise ReconcileRetry("camera_reconcile_fenced")
                if changed:
                    applied += 1
                else:
                    unchanged += 1

            deleted = 0
            for orphan in set(inventory.camera_ids).difference(known_ids):
                _continue_or_cancel(cancelled)
                try:
                    client.delete_path(orphan)
                    _continue_or_cancel(cancelled)
                    remaining = client.get_path(orphan)
                except MediaNodeError:
                    remaining = self._safe_get(client, orphan, cancelled)
                if remaining is not None:
                    raise ReconcileRetry("camera_reconcile_orphan_unverified")
                deleted += 1

            return ReconcileReport(
                node_id=node_id,
                applied=applied,
                unchanged=unchanged,
                deleted_orphans=deleted,
            )

    @staticmethod
    def _remove_disabled_path(
        client: MediaNodeClient,
        name: PublicId,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> None:
        try:
            _continue_or_cancel(cancelled)
            if client.get_path(name) is None:
                return
            _continue_or_cancel(cancelled)
            client.delete_path(name)
            _continue_or_cancel(cancelled)
            remaining = client.get_path(name)
        except MediaNodeError:
            remaining = CameraReconciler._safe_get(client, name, cancelled)
        if remaining is not None:
            raise ReconcileRetry("camera_reconcile_delete_unverified")

    @staticmethod
    def _safe_read_back(
        client: MediaNodeClient,
        expected: MediaPathConfig,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> MediaPathConfig | None:
        try:
            _continue_or_cancel(cancelled)
            return client.get_path(expected.name)
        except MediaNodeError:
            raise ReconcileRetry("camera_reconcile_unverified") from None

    @staticmethod
    def _safe_get(
        client: MediaNodeClient,
        name: PublicId,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> MediaPathConfig | None:
        try:
            _continue_or_cancel(cancelled)
            return client.get_path(name)
        except MediaNodeError:
            raise ReconcileRetry("camera_reconcile_orphan_unverified") from None
