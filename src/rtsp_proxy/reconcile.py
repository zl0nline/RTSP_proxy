from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from rtsp_proxy.identifiers import PublicId
from rtsp_proxy.media import MediaNodeError, MediaPathConfig, MediaPathInventory
from rtsp_proxy.nodes import (
    CameraLifecycleConflict,
    CameraMove,
    CameraMoveState,
    CameraMoveStore,
    CameraNotFound,
    CameraState,
    EligibleNodeMissing,
    MediaNode,
    NodeCameraCapacityReached,
    NodeLifecycleBusy,
    NodeNotFound,
    NodeState,
    ReconcileStore,
    is_node_eligible,
)


class MediaNodeClient(Protocol):
    def put_path(self, path: MediaPathConfig) -> None: ...

    def get_path(self, name: PublicId) -> MediaPathConfig | None: ...

    def inventory_paths(self) -> MediaPathInventory: ...

    def delete_path(self, name: PublicId) -> None: ...

    def path_runtime_status(self, name: PublicId) -> tuple[bool, int] | None: ...


class MediaNodeClientFactory(Protocol):
    def for_node(self, node: MediaNode) -> MediaNodeClient: ...


@dataclass(frozen=True, slots=True)
class ReconcileReport:
    node_id: UUID
    applied: int
    unchanged: int
    deleted_orphans: int


class ReconcileRetry(RuntimeError):
    """The desired state remains authoritative but was not verified as applied."""


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


@dataclass(frozen=True, slots=True)
class CameraMovePreview:
    camera_id: UUID
    source_node_id: UUID
    target_node_id: UUID
    desired_revision: int
    occupied: bool
    disconnect_readers: int
    confirmation_token: str | None


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
        encoded = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
        signature = hmac.new(self._secret, payload, hashlib.sha256).hexdigest()
        return f"{encoded}.{signature}"

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
        try:
            encoded, signature = token.split(".", 1)
            payload = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
            decoded = json.loads(payload)
            expires_at = decoded["expires_at"]
        except (KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError):
            return False
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
    ) -> None:
        self._store = store
        self._runtime = runtime
        self._confirmations = confirmations
        self._new_move_id = new_move_id

    def preview(self, camera_id: UUID, *, target_node_id: UUID) -> CameraMovePreview:
        camera = self._store.get_camera(camera_id)
        if camera is None:
            raise CameraNotFound("camera_not_found")
        target = self._store.get_node(target_node_id)
        if target is None:
            raise NodeNotFound("node_not_found")
        if target.id == camera.node_id:
            raise CameraLifecycleConflict("camera_already_on_target")
        if target.registered_cameras >= target.camera_capacity:
            raise NodeCameraCapacityReached("node_camera_capacity_reached")
        if not is_node_eligible(target):
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
        )

    def request_move(
        self,
        camera_id: UUID,
        *,
        target_node_id: UUID,
        force: bool = False,
        confirmation_token: str | None = None,
    ) -> CameraMove:
        preview = self.preview(camera_id, target_node_id=target_node_id)
        if preview.occupied and not force:
            raise CameraOccupied("camera_occupied")
        if preview.occupied and (
            confirmation_token is None
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
        return self._store.create_camera_move(
            move_id=self._new_move_id(),
            camera_id=camera_id,
            target_node_id=target_node_id,
            expected_revision=preview.desired_revision,
            force=force,
        )

    def get_move(self, move_id: UUID) -> CameraMove | None:
        return self._store.get_camera_move(move_id)


class CameraMoveReconciler:
    def __init__(
        self,
        *,
        store: CameraMoveStore,
        media_nodes: MediaNodeClientFactory,
    ) -> None:
        self._store = store
        self._media_nodes = media_nodes

    def resume(self, move_id: UUID) -> CameraMove:
        move = self._store.get_camera_move(move_id)
        if move is None:
            raise CameraNotFound("camera_move_not_found")
        if move.state is CameraMoveState.COMPLETE:
            return move
        if move.state is CameraMoveState.PREPARE_TARGET:
            self._prepare_and_verify(move)
            move = self._store.switch_camera_move(move.id)
        if move.state is CameraMoveState.CLEANUP_SOURCE:
            self._cleanup_source(move)
            move = self._store.complete_camera_move(move.id)
        return move

    def _prepare_and_verify(self, move: CameraMove) -> None:
        target = self._store.get_node(move.target_node_id)
        if target is None:
            raise ReconcileRetry("camera_move_target_missing")
        client = self._media_nodes.for_node(target)
        expected = MediaPathConfig(name=move.public_id, source_url=move.source_url)
        try:
            if client.get_path(move.public_id) != expected:
                client.put_path(expected)
            actual = client.get_path(move.public_id)
        except MediaNodeError:
            actual = CameraReconciler._safe_read_back(client, expected)
        if actual != expected:
            raise ReconcileRetry("camera_move_target_unverified")

    def _cleanup_source(self, move: CameraMove) -> None:
        source = self._store.get_node(move.source_node_id)
        if source is None:
            raise ReconcileRetry("camera_move_source_missing")
        client = self._media_nodes.for_node(source)
        CameraReconciler._remove_disabled_path(client, move.public_id)


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

    def run_once(self) -> ReconcileCycleReport:
        completed_moves = 0
        reconciled_nodes = 0
        retryable_failures = 0
        for move in self._store.list_incomplete_camera_moves():
            try:
                result = self._moves.resume(move.id)
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
            if node.runtime_state is not NodeState.RUNNING:
                continue
            try:
                self._cameras.reconcile_node(node.id)
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

    def reconcile_node(self, node_id: UUID) -> ReconcileReport:
        with self._store.reconcile_guard(node_id):
            node = self._store.get_node(node_id)
            if node is None:
                raise NodeNotFound("node_not_found")
            if node.runtime_state is not NodeState.RUNNING or not node.config_compatible:
                raise ReconcileRetry("camera_reconcile_node_unavailable")
            client = self._media_nodes.for_node(node)
            desired = self._store.list_node_cameras(node_id)
            active_moves = self._store.list_node_active_moves(node_id)
            inventory = client.inventory_paths()
            known_ids = {camera.public_id for camera in desired}.union(
                move.public_id for move in active_moves
            )
            move_camera_ids = {move.camera_id for move in active_moves}
            applied = 0
            unchanged = 0

            for camera in desired:
                if camera.id in move_camera_ids:
                    unchanged += 1
                    continue
                if camera.state is not CameraState.ENABLED:
                    self._remove_disabled_path(client, camera.public_id)
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
                )
                try:
                    actual = client.get_path(camera.public_id)
                    changed = actual != path
                    if changed:
                        client.put_path(path)
                    verified = client.get_path(camera.public_id)
                except MediaNodeError:
                    verified = self._safe_read_back(client, path)
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
                try:
                    client.delete_path(orphan)
                    remaining = client.get_path(orphan)
                except MediaNodeError:
                    remaining = self._safe_get(client, orphan)
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
    def _remove_disabled_path(client: MediaNodeClient, name: PublicId) -> None:
        try:
            if client.get_path(name) is None:
                return
            client.delete_path(name)
            remaining = client.get_path(name)
        except MediaNodeError:
            remaining = CameraReconciler._safe_get(client, name)
        if remaining is not None:
            raise ReconcileRetry("camera_reconcile_delete_unverified")

    @staticmethod
    def _safe_read_back(
        client: MediaNodeClient,
        expected: MediaPathConfig,
    ) -> MediaPathConfig | None:
        try:
            return client.get_path(expected.name)
        except MediaNodeError:
            raise ReconcileRetry("camera_reconcile_unverified") from None

    @staticmethod
    def _safe_get(client: MediaNodeClient, name: PublicId) -> MediaPathConfig | None:
        try:
            return client.get_path(name)
        except MediaNodeError:
            raise ReconcileRetry("camera_reconcile_orphan_unverified") from None
