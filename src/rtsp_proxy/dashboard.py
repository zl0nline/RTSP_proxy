from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from functools import lru_cache
from typing import Final

from jinja2 import Environment, PackageLoader, StrictUndefined, select_autoescape

from rtsp_proxy.nodes import (
    CameraCatalogItem,
    CameraCatalogPage,
    CameraCatalogQuery,
    CameraMove,
    CameraState,
)
from rtsp_proxy.observability import FleetSnapshot, NodeSnapshot, SnapshotReader
from rtsp_proxy.operator_access import OperatorPrincipal
from rtsp_proxy.reconcile import (
    CameraMovePreview,
    CameraMoveTarget,
    CameraMutationPreview,
)

DASHBOARD_CSP: Final = (
    "default-src 'none'; style-src 'self'; base-uri 'none'; "
    "form-action 'self'; frame-ancestors 'none'"
)


@dataclass(frozen=True, slots=True)
class DashboardUnavailable:
    title: str
    message: str


class FleetSnapshotFailureReason(StrEnum):
    UNAVAILABLE = "fleet_snapshot_unavailable"
    PENDING = "fleet_snapshot_pending"
    STALE = "fleet_snapshot_stale"


class FleetSnapshotReadFailure(RuntimeError):
    def __init__(self, reason: FleetSnapshotFailureReason) -> None:
        super().__init__(reason.value)
        self.reason = reason


def require_fresh_snapshot(
    reader: SnapshotReader | None,
    *,
    now: datetime,
    max_age_seconds: float,
) -> FleetSnapshot:
    if reader is None:
        raise FleetSnapshotReadFailure(FleetSnapshotFailureReason.UNAVAILABLE)
    try:
        snapshot = reader.current_snapshot()
    except Exception:
        raise FleetSnapshotReadFailure(FleetSnapshotFailureReason.UNAVAILABLE) from None
    if snapshot is None:
        raise FleetSnapshotReadFailure(FleetSnapshotFailureReason.PENDING)
    if snapshot.generated_at < now - timedelta(seconds=max_age_seconds):
        raise FleetSnapshotReadFailure(FleetSnapshotFailureReason.STALE)
    return snapshot


@lru_cache(maxsize=1)
def _environment() -> Environment:
    environment = Environment(
        loader=PackageLoader("rtsp_proxy", "templates"),
        autoescape=select_autoescape(enabled_extensions=("html", "xml"), default=True),
        undefined=StrictUndefined,
        auto_reload=False,
    )
    environment.filters["dashboard_time"] = _format_time
    environment.filters["dashboard_bitrate"] = _format_bitrate
    return environment


def render_overview(*, snapshot: FleetSnapshot, principal: OperatorPrincipal) -> str:
    return _environment().get_template("dashboard/overview.html").render(
        snapshot=snapshot,
        principal=principal,
    )


def render_node_detail(
    *,
    snapshot: FleetSnapshot,
    node: NodeSnapshot,
    principal: OperatorPrincipal,
) -> str:
    return _environment().get_template("dashboard/node.html").render(
        snapshot=snapshot,
        node=node,
        principal=principal,
    )


def render_camera_catalog(
    *,
    page: CameraCatalogPage,
    query: CameraCatalogQuery,
    next_url: str | None,
    principal: OperatorPrincipal,
) -> str:
    return _environment().get_template("dashboard/cameras.html").render(
        page=page,
        query=query,
        next_url=next_url,
        principal=principal,
        states=(CameraState.ENABLED, CameraState.DISABLED, CameraState.DELETING),
    )


def render_camera_detail(
    *,
    camera: CameraCatalogItem,
    principal: OperatorPrincipal,
    csrf_token: str,
    can_mutate: bool,
    can_move: bool,
) -> str:
    return _environment().get_template("dashboard/camera.html").render(
        camera=camera,
        principal=principal,
        csrf_token=csrf_token,
        can_mutate=can_mutate,
        can_move=can_move,
    )


def render_camera_edit(
    *,
    camera: CameraCatalogItem,
    principal: OperatorPrincipal,
    csrf_token: str,
) -> str:
    return _environment().get_template("dashboard/camera_edit.html").render(
        camera=camera,
        principal=principal,
        csrf_token=csrf_token,
    )


def render_camera_mutation_confirmation(
    *,
    camera: CameraCatalogItem,
    preview: CameraMutationPreview,
    principal: OperatorPrincipal,
    csrf_token: str,
    name: str | None,
) -> str:
    return _environment().get_template("dashboard/camera_mutation_confirmation.html").render(
        camera=camera,
        preview=preview,
        principal=principal,
        csrf_token=csrf_token,
        name=name,
    )


def render_camera_move(
    *,
    camera: CameraCatalogItem,
    targets: tuple[CameraMoveTarget, ...],
    principal: OperatorPrincipal,
    csrf_token: str,
) -> str:
    return _environment().get_template("dashboard/camera_move.html").render(
        camera=camera,
        targets=targets,
        principal=principal,
        csrf_token=csrf_token,
    )


def render_camera_move_confirmation(
    *,
    camera: CameraCatalogItem,
    preview: CameraMovePreview,
    principal: OperatorPrincipal,
    csrf_token: str,
) -> str:
    return _environment().get_template(
        "dashboard/camera_move_confirmation.html"
    ).render(
        camera=camera,
        preview=preview,
        principal=principal,
        csrf_token=csrf_token,
    )


def render_camera_move_status(
    *,
    camera: CameraCatalogItem,
    move: CameraMove,
    principal: OperatorPrincipal,
) -> str:
    return _environment().get_template("dashboard/camera_move_status.html").render(
        camera=camera,
        move=move,
        principal=principal,
    )


def render_unavailable(
    unavailable: DashboardUnavailable,
    *,
    principal: OperatorPrincipal | None = None,
) -> str:
    return _environment().get_template("dashboard/unavailable.html").render(
        unavailable=unavailable,
        principal=principal,
    )


def _format_time(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%d.%m.%Y %H:%M:%S UTC")


def _format_bitrate(value: float | None) -> str:
    if value is None:
        return "—"
    if value >= 1_000_000:
        return f"{value / 1_000_000:.2f} Мбит/с"  # noqa: RUF001
    if value >= 1_000:
        return f"{value / 1_000:.1f} Кбит/с"  # noqa: RUF001
    return f"{value:.0f} бит/с"  # noqa: RUF001
