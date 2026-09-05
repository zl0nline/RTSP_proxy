"""Authenticated, revision-fenced monitoring configuration for API and Dashboard."""

from datetime import timedelta
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from rtsp_proxy.dashboard_forms import DashboardForm, DashboardFormInvalid
from rtsp_proxy.node_operator import node_mutation_context
from rtsp_proxy.nodes import CameraLifecycleConflict, CameraNotFound
from rtsp_proxy.operator_access import (
    OperatorPermission,
    OperatorPrincipal,
    OperatorRequestAuditContext,
)
from rtsp_proxy.probe_routine import (
    CameraProbeProfile,
    CameraProbeProfiles,
    CameraProbeProfileUnavailable,
    StoredCameraProbeProfile,
)


class ProbeProfileUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    expected_revision: int = Field(ge=0, le=2**63 - 2)
    enabled: bool
    max_source_sessions: int = Field(ge=1, le=16)
    require_video: bool
    require_audio: bool
    routine_seconds: int = Field(ge=30, le=86400)
    confirmation_seconds: int = Field(ge=1, le=3600)
    timeout_seconds: int = Field(ge=1, le=30)

    def profile(self) -> CameraProbeProfile:
        return CameraProbeProfile(
            enabled=self.enabled, max_source_sessions=self.max_source_sessions,
            require_video=self.require_video, require_audio=self.require_audio,
            routine_interval=timedelta(seconds=self.routine_seconds),
            confirmation_interval=timedelta(seconds=self.confirmation_seconds),
            execution_timeout=timedelta(seconds=self.timeout_seconds),
        )


def camera_probe_profile_router(profiles: CameraProbeProfiles | None) -> APIRouter:
    router = APIRouter()

    def require_profiles() -> CameraProbeProfiles:
        if profiles is None:
            raise HTTPException(503, detail={"code": "camera_probe_profiles_unavailable"})
        return profiles

    def require_principal(request: Request, permission: OperatorPermission) -> OperatorPrincipal:
        principal = getattr(request.state, "operator_principal", None)
        if not isinstance(principal, OperatorPrincipal) or not principal.allows(permission):
            raise HTTPException(403, detail={"code": "operator_authorization_denied"})
        return principal

    def update(camera_id: UUID, payload: ProbeProfileUpdate, request: Request) -> JSONResponse:
        principal = require_principal(request, OperatorPermission.CONTROL_MUTATE)
        audit = getattr(request.state, "operator_audit_context", None)
        if not isinstance(audit, OperatorRequestAuditContext):
            raise HTTPException(503, detail={"code": "operator_audit_context_unavailable"})
        try:
            result = require_profiles().update_camera_probe_profile(
                camera_id, profile=payload.profile(), expected_revision=payload.expected_revision,
                mutation_context=node_mutation_context(principal=principal, audit_context=audit),
            )
        except CameraNotFound:
            raise HTTPException(404, detail={"code": "camera_not_found"}) from None
        except CameraLifecycleConflict:
            raise HTTPException(
                409, detail={"code": "camera_probe_profile_revision_conflict"},
            ) from None
        except ValueError:
            raise HTTPException(422, detail={"code": "camera_probe_profile_invalid"}) from None
        except CameraProbeProfileUnavailable:
            raise HTTPException(503, detail={"code": "camera_probe_profiles_unavailable"}) from None
        return _profile_response(result)

    @router.get("/api/v1/cameras/{camera_id}/probe-profile")
    def get_profile(camera_id: UUID, request: Request) -> JSONResponse:
        require_principal(request, OperatorPermission.CONTROL_READ)
        try:
            return _profile_response(require_profiles().camera_probe_profile(camera_id))
        except CameraNotFound:
            raise HTTPException(404, detail={"code": "camera_not_found"}) from None
        except CameraProbeProfileUnavailable:
            raise HTTPException(503, detail={"code": "camera_probe_profiles_unavailable"}) from None

    @router.put("/api/v1/cameras/{camera_id}/probe-profile")
    def put_profile(camera_id: UUID, payload: ProbeProfileUpdate, request: Request) -> JSONResponse:
        return update(camera_id, payload, request)

    @router.post("/dashboard/cameras/{camera_id}/probe-profile", include_in_schema=False)
    def submit_profile(camera_id: UUID, request: Request) -> RedirectResponse:
        form = getattr(request.state, "dashboard_form", None)
        if not isinstance(form, DashboardForm):
            raise HTTPException(422, detail={"code": "dashboard_form_invalid"})
        fields = frozenset(ProbeProfileUpdate.model_fields)
        try:
            form.require_exact_fields(fields | {"_csrf"})
            values: dict[str, object] = {}
            for name in fields:
                raw = form.required(name, max_length=20)
                if name in {"enabled", "require_video", "require_audio"}:
                    if raw not in {"true", "false"}:
                        raise ValueError("camera_probe_profile_invalid")
                    values[name] = raw == "true"
                else:
                    values[name] = int(raw, 10)
            payload = ProbeProfileUpdate.model_validate(values)
        except (DashboardFormInvalid, ValidationError, ValueError):
            raise HTTPException(422, detail={"code": "camera_probe_profile_invalid"}) from None
        update(camera_id, payload, request)
        return RedirectResponse(
            f"/dashboard/cameras/{camera_id}", status_code=303,
            headers={"Cache-Control": "no-store"},
        )

    return router


def _profile_response(record: StoredCameraProbeProfile) -> JSONResponse:
    profile = record.profile
    return JSONResponse(
        {
            "camera_id": str(record.camera_id), "revision": record.revision,
            "enabled": profile.enabled, "max_source_sessions": profile.max_source_sessions,
            "require_video": profile.require_video, "require_audio": profile.require_audio,
            "routine_seconds": int(profile.routine_interval.total_seconds()),
            "confirmation_seconds": int(profile.confirmation_interval.total_seconds()),
            "timeout_seconds": int(profile.execution_timeout.total_seconds()),
            "mode": "active" if profile.enabled and profile.max_source_sessions > 1 else "passive",
        },
        headers={"Cache-Control": "no-store"},
    )
