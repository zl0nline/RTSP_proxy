from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from rtsp_proxy.identifiers import PublicId
from rtsp_proxy.media import MediaNodeError, MediaPathConfig, MediaPathInventory
from rtsp_proxy.nodes import (
    CameraState,
    MediaNode,
    NodeNotFound,
    NodeState,
    ReconcileStore,
)


class MediaNodeClient(Protocol):
    def put_path(self, path: MediaPathConfig) -> None: ...

    def get_path(self, name: PublicId) -> MediaPathConfig | None: ...

    def inventory_paths(self) -> MediaPathInventory: ...

    def delete_path(self, name: PublicId) -> None: ...


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
            inventory = client.inventory_paths()
            known_ids = {camera.public_id for camera in desired}
            applied = 0
            unchanged = 0

            for camera in desired:
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
