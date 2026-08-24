from __future__ import annotations

from datetime import timedelta
from urllib.parse import urlencode
from uuid import UUID, uuid4

from fastapi import APIRouter, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse

from rtsp_proxy.access import (
    AccessGrantControl,
    AccessGrantIdempotencyConflict,
    AccessGrantIssueReplayed,
    AccessGrantSchemaUnavailable,
    AccessPolicyControl,
)
from rtsp_proxy.dashboard import (
    DASHBOARD_CSP,
    DashboardUnavailable,
    render_access_grant_revoke,
    render_access_grant_secret,
    render_camera_access,
    render_camera_catalog,
    render_camera_detail,
    render_camera_edit,
    render_camera_move,
    render_camera_move_confirmation,
    render_camera_move_status,
    render_camera_mutation_confirmation,
    render_unavailable,
)
from rtsp_proxy.dashboard_forms import DashboardForm, DashboardFormInvalid
from rtsp_proxy.media import MediaNodeError
from rtsp_proxy.node_operator import node_mutation_context
from rtsp_proxy.nodes import (
    MAX_CAMERA_NAME_LENGTH,
    CameraCatalogItem,
    CameraCatalogQuery,
    CameraCatalogUnavailable,
    CameraControl,
    CameraLifecycleConflict,
    CameraNotFound,
    CameraRevisionConflict,
    CameraState,
    EligibleNodeMissing,
    InvalidCameraName,
    InvalidCameraSource,
    NodeCameraCapacityReached,
    NodeMutationContext,
    NodeNotFound,
)
from rtsp_proxy.operator_access import (
    OperatorPermission,
    OperatorPrincipal,
    OperatorRequestAuditContext,
    OperatorSessionControl,
    OperatorSessionUnavailable,
)
from rtsp_proxy.reconcile import (
    CameraDisruptionConfirmationRequired,
    CameraMoveControl,
    CameraMutationControl,
    CameraMutationOperation,
    CameraOccupied,
    CameraReaderInvariantViolation,
    MoveConfirmationRequired,
    ReconcileRetry,
)


def camera_dashboard_router(
    *,
    camera_control: CameraControl | None,
    camera_mutation_control: CameraMutationControl | None,
    camera_move_control: CameraMoveControl | None,
    access_policy_control: AccessPolicyControl | None,
    access_grant_control: AccessGrantControl | None,
    operator_sessions: OperatorSessionControl | None,
    recent_mfa_seconds: int,
    secret_reveal_seconds: int,
) -> APIRouter:
    """Build the complete secret-free camera dashboard surface."""

    if not 1 <= secret_reveal_seconds <= 30:
        raise ValueError("access_secret_reveal_seconds_invalid")

    router = APIRouter()

    @router.get(
        "/dashboard/cameras",
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    def camera_catalog(request: Request) -> Response:
        principal = _principal(request)
        if isinstance(principal, Response):
            return principal
        if camera_control is None:
            return _catalog_unavailable(principal)
        try:
            query = _catalog_query(request)
        except ValueError:
            return _unavailable_response(
                DashboardUnavailable(
                    title="Некорректный запрос каталога",
                    message="Проверьте фильтры, курсор и размер страницы.",
                ),
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                principal=principal,
            )
        try:
            page = camera_control.catalog(query)
        except CameraCatalogUnavailable:
            return _catalog_unavailable(principal)
        return _html_response(
            render_camera_catalog(
                page=page,
                query=query,
                next_url=_catalog_next_url(query, page.next_after),
                principal=principal,
            )
        )

    @router.get(
        "/dashboard/cameras/{camera_id}",
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    def camera_detail(request: Request, camera_id: UUID) -> Response:
        principal = _principal(request)
        if isinstance(principal, Response):
            return principal
        camera = _camera_item(camera_control, camera_id, principal)
        if isinstance(camera, Response):
            return camera
        return _html_response(
            render_camera_detail(
                camera=camera,
                principal=principal,
                csrf_token=request.cookies.get("__Host-rtsp_proxy_csrf", ""),
                can_mutate=(
                    principal.allows(OperatorPermission.CONTROL_MUTATE)
                    and _valid_csrf_cookie(request)
                ),
                can_move=(
                    camera_move_control is not None
                    and camera.state is CameraState.ENABLED
                ),
                can_manage_access=(
                    access_policy_control is not None
                    and access_grant_control is not None
                    and principal.allows(OperatorPermission.ACCESS_ADMIN)
                ),
            )
        )

    @router.get(
        "/dashboard/cameras/{camera_id}/access",
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    def camera_access(request: Request, camera_id: UUID) -> Response:
        principal = _principal(request)
        if isinstance(principal, Response):
            return principal
        unavailable = _access_controls_unavailable(
            access_policy_control,
            access_grant_control,
            principal,
        )
        if unavailable is not None:
            return unavailable
        if not _valid_csrf_cookie(request):
            return _fresh_session_required(principal)
        camera = _camera_item(camera_control, camera_id, principal)
        if isinstance(camera, Response):
            return camera
        assert access_policy_control is not None
        assert access_grant_control is not None
        try:
            policy = access_policy_control.get(camera_id)
            grants = access_grant_control.list_for_camera(camera_id, limit=100)
            if operator_sessions is not None:
                audit_context = getattr(request.state, "operator_audit_context", None)
                if not isinstance(audit_context, OperatorRequestAuditContext):
                    raise OperatorSessionUnavailable("operator_session_store_unavailable")
                operator_sessions.record_sensitive_read(
                    principal=principal,
                    audit_context=audit_context,
                )
        except Exception as error:
            expected = _access_error(error, principal)
            if expected is not None:
                return expected
            raise
        return _html_response(
            render_camera_access(
                camera=camera,
                policy=policy,
                grants=grants,
                principal=principal,
                csrf_token=request.cookies.get("__Host-rtsp_proxy_csrf", ""),
                issue_idempotency_key=uuid4(),
                rotation_idempotency_keys={grant.id: uuid4() for grant in grants.items},
            )
        )

    @router.post(
        "/dashboard/cameras/{camera_id}/access-policy",
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    def camera_access_policy(request: Request, camera_id: UUID) -> Response:
        principal = _principal(request)
        if isinstance(principal, Response):
            return principal
        if access_policy_control is None:
            return _access_unavailable(principal)
        expected_revision: int | None = None
        try:
            form = _form(request)
            form.require_exact_fields(
                frozenset(
                    {"_csrf", "expected_revision", "internet_cidrs", "local_cidrs"}
                )
            )
            expected_revision = _positive_revision(form)
            access_policy_control.update(
                camera_id,
                internet_cidrs=_cidr_lines(form, "internet_cidrs"),
                local_cidrs=_cidr_lines(form, "local_cidrs"),
                expected_revision=expected_revision,
                mutation_context=_access_mutation_context(request, principal),
            )
        except DashboardFormInvalid:
            return _form_invalid(principal)
        except Exception as error:
            if isinstance(error, (CameraNotFound, CameraLifecycleConflict)) and (
                expected_revision is not None
            ):
                error = _record_dashboard_access_rejection(
                    operator_sessions,
                    request=request,
                    principal=principal,
                    error=error,
                    target_grant_id=None,
                    expected_revision=expected_revision,
                    idempotency_key=None,
                )
            expected = _access_error(error, principal)
            if expected is not None:
                return expected
            raise
        return _access_redirect(camera_id)

    @router.post(
        "/dashboard/cameras/{camera_id}/access-grants",
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    def issue_access_grant(request: Request, camera_id: UUID) -> Response:
        principal = _principal(request)
        if isinstance(principal, Response):
            return principal
        if access_grant_control is None:
            return _access_unavailable(principal)
        recent_mfa = _require_recent_mfa(principal, recent_mfa_seconds)
        if recent_mfa is not None:
            return recent_mfa
        idempotency_key: UUID | None = None
        try:
            form = _form(request)
            form.require_exact_fields(
                frozenset(
                    {"_csrf", "kind", "lifetime_seconds", "idempotency_key"}
                )
            )
            kind = form.required("kind", max_length=16)
            if kind not in {"temporary", "service"}:
                raise DashboardFormInvalid("dashboard_form_invalid")
            lifetime = timedelta(
                seconds=_bounded_integer(
                    form,
                    "lifetime_seconds",
                    minimum=1,
                    maximum=366 * 24 * 60 * 60,
                )
            )
            idempotency_key = _idempotency_key(form)
            camera = _camera_item(camera_control, camera_id, principal)
            if isinstance(camera, Response):
                if camera.status_code == status.HTTP_404_NOT_FOUND:
                    audit_error = _record_dashboard_access_rejection(
                        operator_sessions,
                        request=request,
                        principal=principal,
                        error=CameraNotFound("camera_not_found"),
                        target_grant_id=None,
                        expected_revision=None,
                        idempotency_key=idempotency_key,
                    )
                    if isinstance(audit_error, OperatorSessionUnavailable):
                        expected = _access_error(audit_error, principal)
                        assert expected is not None
                        return expected
                return camera
            issued = access_grant_control.create(
                camera_id=camera_id,
                lifetime=lifetime,
                kind=kind,
                created_by=f"operator:{principal.account_id}",
                idempotency_key=idempotency_key,
                mutation_context=_access_mutation_context(
                    request,
                    principal,
                    idempotency_key=idempotency_key,
                ),
            )
        except DashboardFormInvalid:
            return _form_invalid(principal)
        except Exception as error:
            if isinstance(
                error,
                (
                    CameraNotFound,
                    AccessGrantIssueReplayed,
                    AccessGrantIdempotencyConflict,
                ),
            ) and idempotency_key is not None:
                error = _record_dashboard_access_rejection(
                    operator_sessions,
                    request=request,
                    principal=principal,
                    error=error,
                    target_grant_id=None,
                    expected_revision=None,
                    idempotency_key=idempotency_key,
                )
            expected = _access_error(error, principal)
            if expected is not None:
                return expected
            raise
        response = _html_response(
            render_access_grant_secret(
                camera=camera,
                issued=issued,
                principal=principal,
            ),
            status_code=status.HTTP_201_CREATED,
        )
        response.headers["Refresh"] = (
            f"{secret_reveal_seconds}; url=/dashboard/cameras/{camera_id}/access"
        )
        return response

    @router.post(
        "/dashboard/cameras/{camera_id}/access-grants/{grant_id}/rotate",
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    def rotate_access_grant(
        request: Request,
        camera_id: UUID,
        grant_id: UUID,
    ) -> Response:
        principal = _principal(request)
        if isinstance(principal, Response):
            return principal
        if access_grant_control is None:
            return _access_unavailable(principal)
        recent_mfa = _require_recent_mfa(principal, recent_mfa_seconds)
        if recent_mfa is not None:
            return recent_mfa
        expected_revision: int | None = None
        idempotency_key: UUID | None = None
        try:
            form = _form(request)
            form.require_exact_fields(
                frozenset(
                    {
                        "_csrf",
                        "expected_revision",
                        "overlap_seconds",
                        "lifetime_seconds",
                        "idempotency_key",
                    }
                )
            )
            camera = _camera_item(camera_control, camera_id, principal)
            if isinstance(camera, Response):
                return camera
            expected_revision = _positive_revision(form)
            idempotency_key = _idempotency_key(form)
            issued = access_grant_control.rotate(
                grant_id,
                camera_id=camera_id,
                overlap=timedelta(
                    seconds=_bounded_integer(
                        form,
                        "overlap_seconds",
                        minimum=0,
                        maximum=24 * 60 * 60,
                    )
                ),
                lifetime=timedelta(
                    seconds=_bounded_integer(
                        form,
                        "lifetime_seconds",
                        minimum=1,
                        maximum=366 * 24 * 60 * 60,
                    )
                ),
                expected_revision=expected_revision,
                created_by=f"operator:{principal.account_id}",
                idempotency_key=idempotency_key,
                mutation_context=_access_mutation_context(
                    request,
                    principal,
                    idempotency_key=idempotency_key,
                ),
            )
        except DashboardFormInvalid:
            return _form_invalid(principal)
        except Exception as error:
            if (
                isinstance(
                    error,
                    (
                        LookupError,
                        CameraLifecycleConflict,
                        AccessGrantIssueReplayed,
                        AccessGrantIdempotencyConflict,
                    ),
                )
                and expected_revision is not None
                and idempotency_key is not None
            ):
                error = _record_dashboard_access_rejection(
                    operator_sessions,
                    request=request,
                    principal=principal,
                    error=error,
                    target_grant_id=grant_id,
                    expected_revision=expected_revision,
                    idempotency_key=idempotency_key,
                )
            expected = _access_error(error, principal)
            if expected is not None:
                return expected
            raise
        response = _html_response(
            render_access_grant_secret(
                camera=camera,
                issued=issued,
                principal=principal,
            ),
            status_code=status.HTTP_201_CREATED,
        )
        response.headers["Refresh"] = (
            f"{secret_reveal_seconds}; url=/dashboard/cameras/{camera_id}/access"
        )
        return response

    @router.get(
        "/dashboard/cameras/{camera_id}/access-grants/{grant_id}/revoke",
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    def access_grant_revoke_confirmation(
        request: Request,
        camera_id: UUID,
        grant_id: UUID,
    ) -> Response:
        principal = _principal(request)
        if isinstance(principal, Response):
            return principal
        if access_grant_control is None:
            return _access_unavailable(principal)
        if not _valid_csrf_cookie(request):
            return _fresh_session_required(principal)
        camera = _camera_item(camera_control, camera_id, principal)
        if isinstance(camera, Response):
            return camera
        try:
            grant = access_grant_control.get(grant_id, camera_id=camera_id)
        except Exception as error:
            expected = _access_error(error, principal)
            if expected is not None:
                return expected
            raise
        return _html_response(
            render_access_grant_revoke(
                camera=camera,
                grant=grant,
                principal=principal,
                csrf_token=request.cookies.get("__Host-rtsp_proxy_csrf", ""),
            )
        )

    @router.post(
        "/dashboard/cameras/{camera_id}/access-grants/{grant_id}/revoke",
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    def revoke_access_grant(
        request: Request,
        camera_id: UUID,
        grant_id: UUID,
    ) -> Response:
        principal = _principal(request)
        if isinstance(principal, Response):
            return principal
        if access_grant_control is None:
            return _access_unavailable(principal)
        recent_mfa = _require_recent_mfa(principal, recent_mfa_seconds)
        if recent_mfa is not None:
            return recent_mfa
        expected_revision: int | None = None
        try:
            form = _form(request)
            form.require_exact_fields(frozenset({"_csrf", "expected_revision"}))
            expected_revision = _positive_revision(form)
            access_grant_control.revoke(
                grant_id,
                camera_id=camera_id,
                expected_revision=expected_revision,
                mutation_context=_access_mutation_context(request, principal),
            )
        except DashboardFormInvalid:
            return _form_invalid(principal)
        except Exception as error:
            if isinstance(error, (LookupError, CameraLifecycleConflict)) and (
                expected_revision is not None
            ):
                error = _record_dashboard_access_rejection(
                    operator_sessions,
                    request=request,
                    principal=principal,
                    error=error,
                    target_grant_id=grant_id,
                    expected_revision=expected_revision,
                    idempotency_key=None,
                )
            expected = _access_error(error, principal)
            if expected is not None:
                return expected
            raise
        return _access_redirect(camera_id)

    @router.get(
        "/dashboard/cameras/{camera_id}/edit",
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    def camera_edit(request: Request, camera_id: UUID) -> Response:
        principal = _principal(request)
        if isinstance(principal, Response):
            return principal
        camera = _camera_item(camera_control, camera_id, principal)
        if isinstance(camera, Response):
            return camera
        csrf_token = request.cookies.get("__Host-rtsp_proxy_csrf", "")
        if not _valid_csrf_cookie(request):
            return _unavailable_response(
                DashboardUnavailable(
                    title="Требуется новая сессия",
                    message="CSRF cookie отсутствует или повреждён. Выполните вход повторно.",
                ),
                status_code=status.HTTP_401_UNAUTHORIZED,
                principal=principal,
            )
        return _html_response(
            render_camera_edit(
                camera=camera,
                principal=principal,
                csrf_token=csrf_token,
            )
        )

    @router.get(
        "/dashboard/cameras/{camera_id}/move",
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    def camera_move(request: Request, camera_id: UUID) -> Response:
        principal = _principal(request)
        if isinstance(principal, Response):
            return principal
        if camera_move_control is None:
            return _move_unavailable(principal)
        camera = _camera_item(camera_control, camera_id, principal)
        if isinstance(camera, Response):
            return camera
        if not _valid_csrf_cookie(request):
            return _unavailable_response(
                DashboardUnavailable(
                    title="Требуется новая сессия",
                    message="CSRF cookie отсутствует или повреждён. Выполните вход повторно.",
                ),
                status_code=status.HTTP_401_UNAUTHORIZED,
                principal=principal,
            )
        try:
            targets = camera_move_control.targets(
                camera_id,
                expected_revision=camera.desired_revision,
            )
        except Exception as error:
            expected = _move_error(error, principal)
            if expected is not None:
                return expected
            raise
        if not targets:
            return _unavailable_response(
                DashboardUnavailable(
                    title="Нет доступной целевой ноды",
                    message="Освободите место или восстановите подходящую ноду и повторите.",
                ),
                status_code=status.HTTP_409_CONFLICT,
                principal=principal,
            )
        return _html_response(
            render_camera_move(
                camera=camera,
                targets=targets,
                principal=principal,
                csrf_token=request.cookies.get("__Host-rtsp_proxy_csrf", ""),
            )
        )

    @router.post(
        "/dashboard/cameras/{camera_id}/moves/preview",
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    def camera_move_preview(request: Request, camera_id: UUID) -> Response:
        principal = _principal(request)
        if isinstance(principal, Response):
            return principal
        if camera_move_control is None:
            return _move_unavailable(principal)
        try:
            form = _form(request)
            target_node_id, expected_revision, _confirmation_token = _move_fields(form)
        except DashboardFormInvalid:
            return _form_invalid(principal)
        camera = _camera_item(camera_control, camera_id, principal)
        if isinstance(camera, Response):
            return camera
        try:
            preview = camera_move_control.preview(
                camera_id,
                target_node_id=target_node_id,
                expected_revision=expected_revision,
            )
            if not preview.occupied:
                move = camera_move_control.request_move(
                    camera_id,
                    target_node_id=target_node_id,
                    expected_revision=expected_revision,
                )
                return _move_redirect(camera_id, move.id)
        except Exception as error:
            expected = _move_error(error, principal)
            if expected is not None:
                return expected
            raise
        return _html_response(
            render_camera_move_confirmation(
                camera=camera,
                preview=preview,
                principal=principal,
                csrf_token=form.csrf_token,
            )
        )

    @router.post(
        "/dashboard/cameras/{camera_id}/moves/apply",
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    def camera_move_apply(request: Request, camera_id: UUID) -> Response:
        principal = _principal(request)
        if isinstance(principal, Response):
            return principal
        if camera_move_control is None:
            return _move_unavailable(principal)
        try:
            form = _form(request)
            target_node_id, expected_revision, confirmation_token = _move_fields(
                form,
                confirmation=True,
            )
            move = camera_move_control.request_move(
                camera_id,
                target_node_id=target_node_id,
                expected_revision=expected_revision,
                force=True,
                confirmation_token=confirmation_token,
            )
        except DashboardFormInvalid:
            return _form_invalid(principal)
        except Exception as error:
            expected = _move_error(error, principal)
            if expected is not None:
                return expected
            raise
        return _move_redirect(camera_id, move.id)

    @router.get(
        "/dashboard/cameras/{camera_id}/moves/{move_id}",
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    def camera_move_status(
        request: Request,
        camera_id: UUID,
        move_id: UUID,
    ) -> Response:
        principal = _principal(request)
        if isinstance(principal, Response):
            return principal
        if camera_move_control is None:
            return _move_unavailable(principal)
        move = camera_move_control.get_move(move_id)
        if move is None or move.camera_id != camera_id:
            return _move_not_found(principal)
        camera = _camera_item(camera_control, camera_id, principal)
        if isinstance(camera, Response):
            return camera
        return _html_response(
            render_camera_move_status(
                camera=camera,
                move=move,
                principal=principal,
            )
        )

    @router.post(
        "/dashboard/cameras/{camera_id}/mutations/preview",
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    def mutation_preview(request: Request, camera_id: UUID) -> Response:
        principal = _principal(request)
        if isinstance(principal, Response):
            return principal
        if camera_mutation_control is None:
            return _mutation_unavailable(principal)
        try:
            form = _form(request)
            operation, expected_revision, name, source_url = _mutation_fields(form)
        except DashboardFormInvalid:
            return _form_invalid(principal)
        camera = _camera_item(camera_control, camera_id, principal)
        if isinstance(camera, Response):
            return camera
        try:
            preview = camera_mutation_control.preview(
                camera_id,
                operation=operation,
                expected_revision=expected_revision,
                name=name,
                source_url=source_url,
            )
            if not preview.occupied:
                _apply_mutation(
                    camera_mutation_control,
                    camera_id=camera_id,
                    operation=operation,
                    expected_revision=preview.desired_revision,
                    name=name,
                    source_url=source_url,
                    confirmation_token=None,
                )
                return _redirect(camera_id)
        except Exception as error:
            expected = _mutation_error(error, principal)
            if expected is not None:
                return expected
            raise
        return _html_response(
            render_camera_mutation_confirmation(
                camera=camera,
                preview=preview,
                principal=principal,
                csrf_token=form.csrf_token,
                name=name,
            )
        )

    @router.post(
        "/dashboard/cameras/{camera_id}/mutations/apply",
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    def mutation_apply(request: Request, camera_id: UUID) -> Response:
        principal = _principal(request)
        if isinstance(principal, Response):
            return principal
        if camera_mutation_control is None:
            return _mutation_unavailable(principal)
        try:
            form = _form(request)
            operation, expected_revision, name, source_url = _mutation_fields(
                form,
                confirmation=True,
            )
            confirmation_token = form.required("confirmation_token", max_length=4096)
            _apply_mutation(
                camera_mutation_control,
                camera_id=camera_id,
                operation=operation,
                expected_revision=expected_revision,
                name=name,
                source_url=source_url,
                confirmation_token=confirmation_token,
            )
        except DashboardFormInvalid:
            return _form_invalid(principal)
        except Exception as error:
            expected = _mutation_error(error, principal)
            if expected is not None:
                return expected
            raise
        return _redirect(camera_id)

    @router.post(
        "/dashboard/cameras/{camera_id}/enable",
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    def camera_enable(request: Request, camera_id: UUID) -> Response:
        principal = _principal(request)
        if isinstance(principal, Response):
            return principal
        if camera_control is None:
            return _catalog_unavailable(principal)
        try:
            form = _form(request)
            form.require_exact_fields(frozenset({"_csrf", "expected_revision"}))
            expected_revision = _positive_revision(form)
            camera_control.set_camera_enabled(
                camera_id,
                enabled=True,
                expected_revision=expected_revision,
            )
        except DashboardFormInvalid:
            return _form_invalid(principal)
        except Exception as error:
            expected = _mutation_error(error, principal)
            if expected is not None:
                return expected
            raise
        return _redirect(camera_id)

    return router


def _principal(request: Request) -> OperatorPrincipal | Response:
    principal = getattr(request.state, "operator_principal", None)
    if isinstance(principal, OperatorPrincipal):
        return principal
    return _unavailable_response(
        DashboardUnavailable(
            title="Сессии операторов не настроены",
            message="Дашборд закрыт до подключения авторизации операторов.",
        ),
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
    )


def _form(request: Request) -> DashboardForm:
    form = getattr(request.state, "dashboard_form", None)
    if not isinstance(form, DashboardForm):
        raise DashboardFormInvalid("dashboard_form_invalid")
    return form


def _valid_csrf_cookie(request: Request) -> bool:
    token = request.cookies.get("__Host-rtsp_proxy_csrf", "")
    return 43 <= len(token) <= 1024


def _positive_revision(form: DashboardForm) -> int:
    try:
        value = int(form.required("expected_revision", max_length=20), 10)
    except ValueError:
        raise DashboardFormInvalid("dashboard_form_invalid") from None
    if value < 1:
        raise DashboardFormInvalid("dashboard_form_invalid")
    return value


def _bounded_integer(
    form: DashboardForm,
    name: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    try:
        value = int(form.required(name, max_length=20), 10)
    except ValueError:
        raise DashboardFormInvalid("dashboard_form_invalid") from None
    if not minimum <= value <= maximum:
        raise DashboardFormInvalid("dashboard_form_invalid")
    return value


def _cidr_lines(form: DashboardForm, name: str) -> tuple[str, ...]:
    raw = form.optional(name, max_length=16_384)
    if raw is None or not raw.strip():
        return ()
    values = tuple(line.strip() for line in raw.splitlines() if line.strip())
    if len(values) > 128:
        raise DashboardFormInvalid("dashboard_form_invalid")
    return values


def _access_mutation_context(
    request: Request,
    principal: OperatorPrincipal,
    *,
    idempotency_key: UUID | None = None,
) -> NodeMutationContext:
    audit_context = getattr(request.state, "operator_audit_context", None)
    if not isinstance(audit_context, OperatorRequestAuditContext):
        raise DashboardFormInvalid("dashboard_form_invalid")
    return node_mutation_context(
        principal=principal,
        audit_context=audit_context,
        idempotency_key=idempotency_key,
    )


def _idempotency_key(form: DashboardForm) -> UUID:
    try:
        key = UUID(form.required("idempotency_key", max_length=36))
    except ValueError:
        raise DashboardFormInvalid("dashboard_form_invalid") from None
    if key.version != 4:
        raise DashboardFormInvalid("dashboard_form_invalid")
    return key


def _mutation_fields(
    form: DashboardForm,
    *,
    confirmation: bool = False,
) -> tuple[CameraMutationOperation, int, str | None, str | None]:
    try:
        operation = CameraMutationOperation(form.required("operation", max_length=32))
    except ValueError:
        raise DashboardFormInvalid("dashboard_form_invalid") from None
    expected_revision = _positive_revision(form)
    base_fields = {"_csrf", "operation", "expected_revision"}
    if confirmation:
        base_fields.add("confirmation_token")
    if operation is CameraMutationOperation.UPDATE_SOURCE:
        form.require_exact_fields(frozenset({*base_fields, "name", "source_url"}))
        return (
            operation,
            expected_revision,
            form.required("name", max_length=MAX_CAMERA_NAME_LENGTH),
            form.required("source_url", max_length=8192),
        )
    form.require_exact_fields(frozenset(base_fields))
    return operation, expected_revision, None, None


def _move_fields(
    form: DashboardForm,
    *,
    confirmation: bool = False,
) -> tuple[UUID, int, str | None]:
    fields = {"_csrf", "target_node_id", "expected_revision"}
    if confirmation:
        fields.add("confirmation_token")
    form.require_exact_fields(frozenset(fields))
    try:
        target_node_id = UUID(form.required("target_node_id", max_length=36))
    except ValueError:
        raise DashboardFormInvalid("dashboard_form_invalid") from None
    confirmation_token = (
        form.required("confirmation_token", max_length=4096)
        if confirmation
        else None
    )
    return target_node_id, _positive_revision(form), confirmation_token


def _apply_mutation(
    control: CameraMutationControl,
    *,
    camera_id: UUID,
    operation: CameraMutationOperation,
    expected_revision: int,
    name: str | None,
    source_url: str | None,
    confirmation_token: str | None,
) -> None:
    if operation is CameraMutationOperation.UPDATE_SOURCE:
        if name is None or source_url is None:
            raise DashboardFormInvalid("dashboard_form_invalid")
        control.update(
            camera_id,
            name=name,
            source_url=source_url,
            expected_revision=expected_revision,
            confirmation_token=confirmation_token,
        )
        return
    if operation is CameraMutationOperation.DISABLE:
        control.disable(
            camera_id,
            expected_revision=expected_revision,
            confirmation_token=confirmation_token,
        )
        return
    control.delete(
        camera_id,
        expected_revision=expected_revision,
        confirmation_token=confirmation_token,
    )


def _camera_item(
    camera_control: CameraControl | None,
    camera_id: UUID,
    principal: OperatorPrincipal,
) -> CameraCatalogItem | Response:
    if camera_control is None:
        return _catalog_unavailable(principal)
    try:
        camera = camera_control.detail(camera_id)
    except CameraCatalogUnavailable:
        return _catalog_unavailable(principal)
    if camera is not None:
        return camera
    return _unavailable_response(
        DashboardUnavailable(
            title="Камера не найдена",
            message=(
                "Камеры с таким идентификатором нет в текущем каталоге."  # noqa: RUF001
            ),
        ),
        status_code=status.HTTP_404_NOT_FOUND,
        principal=principal,
    )


def _mutation_error(
    error: Exception,
    principal: OperatorPrincipal,
) -> HTMLResponse | None:
    if isinstance(error, CameraNotFound):
        return _unavailable_response(
            DashboardUnavailable(
                title="Камера не найдена",
                message="Камера больше не существует в текущем каталоге.",
            ),
            status_code=status.HTTP_404_NOT_FOUND,
            principal=principal,
        )
    if isinstance(error, InvalidCameraName):
        return _unavailable_response(
            DashboardUnavailable(
                title="Некорректное имя камеры",
                message="Имя должно содержать от 1 до 128 символов без управляющих знаков.",
            ),
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            principal=principal,
        )
    if isinstance(error, InvalidCameraSource):
        return _unavailable_response(
            DashboardUnavailable(
                title="Некорректный source URL",
                message="Проверьте RTSP URL и повторите preview.",
            ),
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            principal=principal,
        )
    if isinstance(error, CameraRevisionConflict):
        return _unavailable_response(
            DashboardUnavailable(
                title="Конфигурация камеры изменилась",
                message=(
                    f"Ожидалась revision {error.expected_revision}, текущая revision "
                    f"{error.current_revision}. Source URL не показан. Обновите страницу."
                ),
            ),
            status_code=status.HTTP_409_CONFLICT,
            principal=principal,
        )
    if isinstance(
        error,
        (
            CameraDisruptionConfirmationRequired,
            CameraLifecycleConflict,
            CameraReaderInvariantViolation,
        ),
    ):
        return _unavailable_response(
            DashboardUnavailable(
                title="Действие не подтверждено",
                message=(
                    "Состояние камеры или число читателей изменилось. "
                    "Вернитесь к камере и сформируйте новое подтверждение."
                ),
            ),
            status_code=status.HTTP_409_CONFLICT,
            principal=principal,
        )
    if isinstance(error, (MediaNodeError, ReconcileRetry)):
        return _mutation_unavailable(principal)
    return None


def _move_error(
    error: Exception,
    principal: OperatorPrincipal,
) -> HTMLResponse | None:
    mutation_error = _mutation_error(error, principal)
    if mutation_error is not None:
        return mutation_error
    if isinstance(error, NodeNotFound):
        return _unavailable_response(
            DashboardUnavailable(
                title="Целевая нода не найдена",
                message="Обновите список доступных нод и повторите.",
            ),
            status_code=status.HTTP_404_NOT_FOUND,
            principal=principal,
        )
    if isinstance(
        error,
        (
            CameraOccupied,
            MoveConfirmationRequired,
            EligibleNodeMissing,
            NodeCameraCapacityReached,
        ),
    ):
        return _unavailable_response(
            DashboardUnavailable(
                title="Перемещение не подтверждено",
                message=(
                    "Состояние камеры или число читателей изменилось. "
                    "Вернитесь к камере и сформируйте новое подтверждение."
                ),
            ),
            status_code=status.HTTP_409_CONFLICT,
            principal=principal,
        )
    return None


def _catalog_query(request: Request) -> CameraCatalogQuery:
    allowed = {"after", "limit", "q", "node_id", "state"}
    values: dict[str, str] = {}
    for key, value in request.query_params.multi_items():
        if key not in allowed or key in values:
            raise ValueError("camera_catalog_query_invalid")
        values[key] = value
    after_value = values.get("after")
    node_id_value = values.get("node_id")
    state_raw = values.get("state")
    try:
        limit = int(values.get("limit", "50"))
        after = UUID(after_value) if after_value else None
        node_id = UUID(node_id_value) if node_id_value else None
        state_value = CameraState(state_raw) if state_raw else None
    except (TypeError, ValueError):
        raise ValueError("camera_catalog_query_invalid") from None
    if state_value is CameraState.DELETED:
        raise ValueError("camera_catalog_query_invalid")
    return CameraCatalogQuery(
        after=after,
        limit=limit,
        search=values.get("q") or None,
        node_id=node_id,
        state=state_value,
    )


def _catalog_next_url(
    query: CameraCatalogQuery,
    next_after: UUID | None,
) -> str | None:
    if next_after is None:
        return None
    parameters: list[tuple[str, str]] = [("limit", str(query.limit))]
    if query.search is not None:
        parameters.append(("q", query.search))
    if query.node_id is not None:
        parameters.append(("node_id", str(query.node_id)))
    if query.state is not None:
        parameters.append(("state", query.state.value))
    parameters.append(("after", str(next_after)))
    return f"/dashboard/cameras?{urlencode(parameters)}"


def _redirect(camera_id: UUID) -> RedirectResponse:
    return RedirectResponse(
        f"/dashboard/cameras/{camera_id}",
        status_code=status.HTTP_303_SEE_OTHER,
        headers={"Cache-Control": "no-store"},
    )


def _access_redirect(camera_id: UUID) -> RedirectResponse:
    return RedirectResponse(
        f"/dashboard/cameras/{camera_id}/access",
        status_code=status.HTTP_303_SEE_OTHER,
        headers={"Cache-Control": "no-store"},
    )


def _move_redirect(camera_id: UUID, move_id: UUID) -> RedirectResponse:
    return RedirectResponse(
        f"/dashboard/cameras/{camera_id}/moves/{move_id}",
        status_code=status.HTTP_303_SEE_OTHER,
        headers={"Cache-Control": "no-store"},
    )


def _form_invalid(principal: OperatorPrincipal) -> HTMLResponse:
    return _unavailable_response(
        DashboardUnavailable(
            title="Некорректная форма",
            message="Поля действия повреждены или превышают допустимый размер.",
        ),
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        principal=principal,
    )


def _mutation_unavailable(principal: OperatorPrincipal) -> HTMLResponse:
    return _unavailable_response(
        DashboardUnavailable(
            title="Управление камерой недоступно",
            message="Безопасно выполнить это действие сейчас невозможно.",
        ),
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        principal=principal,
    )


def _move_unavailable(principal: OperatorPrincipal) -> HTMLResponse:
    return _unavailable_response(
        DashboardUnavailable(
            title="Перемещение камеры недоступно",
            message="Безопасно выполнить перемещение сейчас невозможно.",
        ),
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        principal=principal,
    )


def _move_not_found(principal: OperatorPrincipal) -> HTMLResponse:
    return _unavailable_response(
        DashboardUnavailable(
            title="Перемещение не найдено",
            message=(
                "Запроса с таким идентификатором нет для этой камеры."  # noqa: RUF001
            ),
        ),
        status_code=status.HTTP_404_NOT_FOUND,
        principal=principal,
    )


def _catalog_unavailable(principal: OperatorPrincipal) -> HTMLResponse:
    return _unavailable_response(
        DashboardUnavailable(
            title="Каталог камер недоступен",
            message="Безопасно прочитать список камер сейчас невозможно.",
        ),
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        principal=principal,
    )


def _access_controls_unavailable(
    policy_control: AccessPolicyControl | None,
    grant_control: AccessGrantControl | None,
    principal: OperatorPrincipal,
) -> HTMLResponse | None:
    if policy_control is None or grant_control is None:
        return _access_unavailable(principal)
    return None


def _access_unavailable(principal: OperatorPrincipal) -> HTMLResponse:
    return _unavailable_response(
        DashboardUnavailable(
            title="Управление доступом недоступно",
            message="Безопасно прочитать или изменить правила доступа сейчас невозможно.",
        ),
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        principal=principal,
    )


def _fresh_session_required(principal: OperatorPrincipal) -> HTMLResponse:
    return _unavailable_response(
        DashboardUnavailable(
            title="Требуется новая сессия",
            message="CSRF cookie отсутствует или повреждён. Выполните вход повторно.",
        ),
        status_code=status.HTTP_401_UNAUTHORIZED,
        principal=principal,
    )


def _require_recent_mfa(
    principal: OperatorPrincipal,
    maximum_age_seconds: int,
) -> HTMLResponse | None:
    if principal.has_recent_mfa(max_age_seconds=maximum_age_seconds):
        return None
    return _unavailable_response(
        DashboardUnavailable(
            title="Требуется недавняя MFA",
            message="Повторно подтвердите второй фактор и затем повторите действие.",
        ),
        status_code=status.HTTP_401_UNAUTHORIZED,
        principal=principal,
    )


def _access_error(
    error: Exception,
    principal: OperatorPrincipal,
) -> HTMLResponse | None:
    if isinstance(error, AccessGrantIssueReplayed):
        return _unavailable_response(
            DashboardUnavailable(
                title="Запрос уже выполнен",
                message=(
                    "Grant уже создан, но секрет повторно не показывается. "
                    "Вернитесь к списку и при необходимости выполните ротацию."
                ),
            ),
            status_code=status.HTTP_409_CONFLICT,
            principal=principal,
        )
    if isinstance(error, AccessGrantIdempotencyConflict):
        return _unavailable_response(
            DashboardUnavailable(
                title="Idempotency key уже использован",
                message="Обновите страницу и повторите действие, используя новый ключ.",
            ),
            status_code=status.HTTP_409_CONFLICT,
            principal=principal,
        )
    if isinstance(error, AccessGrantSchemaUnavailable):
        return _unavailable_response(
            DashboardUnavailable(
                title="Обновление схемы не завершено",
                message="Выдача и ротация grant временно приостановлены. Повторите позже.",
            ),
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            principal=principal,
        )
    if isinstance(error, OperatorSessionUnavailable):
        return _unavailable_response(
            DashboardUnavailable(
                title="Журнал безопасности недоступен",
                message="Чувствительное чтение или изменение заблокировано. Повторите позже.",
            ),
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            principal=principal,
        )
    if isinstance(error, (LookupError, CameraNotFound)):
        return _unavailable_response(
            DashboardUnavailable(
                title="Grant или камера не найдены",
                message="Для этой камеры запрошенной записи нет.",
            ),
            status_code=status.HTTP_404_NOT_FOUND,
            principal=principal,
        )
    if isinstance(error, CameraLifecycleConflict):
        return _unavailable_response(
            DashboardUnavailable(
                title="Правила доступа изменились",
                message="Revision устарела. Обновите страницу и повторите действие.",
            ),
            status_code=status.HTTP_409_CONFLICT,
            principal=principal,
        )
    if isinstance(error, ValueError):
        return _unavailable_response(
            DashboardUnavailable(
                title="Некорректные правила доступа",
                message="Проверьте CIDR, срок и параметры grant.",
            ),
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            principal=principal,
        )
    return None


def _record_dashboard_access_rejection(
    operator_sessions: OperatorSessionControl | None,
    *,
    request: Request,
    principal: OperatorPrincipal,
    error: Exception,
    target_grant_id: UUID | None,
    expected_revision: int | None,
    idempotency_key: UUID | None,
) -> Exception:
    if operator_sessions is None:
        return error
    audit_context = getattr(request.state, "operator_audit_context", None)
    if not isinstance(audit_context, OperatorRequestAuditContext):
        return OperatorSessionUnavailable("operator_session_store_unavailable")
    if isinstance(error, AccessGrantIssueReplayed):
        reason_code = "access_grant_issue_replayed"
    elif isinstance(error, AccessGrantIdempotencyConflict):
        reason_code = "access_grant_idempotency_conflict"
    elif isinstance(error, CameraNotFound):
        reason_code = "camera_not_found"
    elif isinstance(error, CameraLifecycleConflict):
        reason_code = (
            "access_policy_revision_conflict"
            if audit_context.action == "camera.access_policy_update"
            else "access_grant_revision_conflict"
        )
    elif isinstance(error, LookupError):
        reason_code = "access_grant_not_found"
    else:
        return error
    try:
        operator_sessions.record_mutation_rejection(
            principal=principal,
            reason_code=reason_code,
            audit_context=audit_context,
            target_grant_id=target_grant_id,
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
        )
    except OperatorSessionUnavailable as audit_error:
        return audit_error
    return error


def _html_response(
    content: str,
    *,
    status_code: int = status.HTTP_200_OK,
    retry_after: str | None = None,
) -> HTMLResponse:
    headers = {
        "Cache-Control": "no-store",
        "Content-Security-Policy": DASHBOARD_CSP,
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
    }
    if retry_after is not None:
        headers["Retry-After"] = retry_after
    return HTMLResponse(content, status_code=status_code, headers=headers)


def _unavailable_response(
    unavailable: DashboardUnavailable,
    *,
    status_code: int,
    principal: OperatorPrincipal | None = None,
) -> HTMLResponse:
    return _html_response(
        render_unavailable(unavailable, principal=principal),
        status_code=status_code,
        retry_after="5" if status_code == status.HTTP_503_SERVICE_UNAVAILABLE else None,
    )
