from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from threading import BoundedSemaphore, Lock
from time import monotonic
from typing import Literal
from uuid import UUID, uuid4

import anyio
from fastapi import FastAPI, Header, HTTPException, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from pydantic import BaseModel, Field
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from rtsp_proxy.access import (
    AccessAuthorizer,
    AccessDecisionReason,
    AccessDecisionTelemetry,
    AccessGrant,
    AccessGrantControl,
    AccessGrantIdempotencyConflict,
    AccessGrantIssueReplayed,
    AccessGrantSchemaUnavailable,
    AccessGrantSummary,
    AccessPolicy,
    AccessPolicyControl,
    AuthorizeRequest,
    IssuedAccessGrant,
    PepperVerifier,
)
from rtsp_proxy.camera_dashboard import camera_dashboard_router
from rtsp_proxy.config import Settings
from rtsp_proxy.dashboard import (
    DASHBOARD_CSP,
    DashboardUnavailable,
    FleetSnapshotFailureReason,
    FleetSnapshotReadFailure,
    render_logout,
    render_node_detail,
    render_overview,
    render_unavailable,
    require_fresh_snapshot,
)
from rtsp_proxy.dashboard_forms import DashboardFormInvalid, read_dashboard_form
from rtsp_proxy.health import (
    MissingReadinessProvider,
    ReadinessProvider,
    normalize_readiness_results,
)
from rtsp_proxy.identifiers import PublicId
from rtsp_proxy.media import MediaNodeError
from rtsp_proxy.node_dashboard import node_dashboard_router
from rtsp_proxy.node_operator import (
    OperatorNodeCommand,
    OperatorRecentMfaRequired,
    node_disruption_confirmation_context,
    node_mutation_context,
    operator_node_command,
)
from rtsp_proxy.nodes import (
    CameraControl,
    CameraLifecycleConflict,
    CameraMove,
    CameraNotFound,
    CameraRevisionConflict,
    EligibleNodeMissing,
    InvalidCameraName,
    InvalidCameraSource,
    MaximumNodesReached,
    NodeCameraCapacityReached,
    NodeControl,
    NodeDisruptionConfirmationContext,
    NodeDisruptionConfirmationRequired,
    NodeLifecycleBusy,
    NodeLifecycleConflict,
    NodeManagementPortRangeExhausted,
    NodeMutationContext,
    NodeNotEmpty,
    NodeNotFound,
    NodePortInUse,
    NodePortOutOfRange,
    NodePortRangeExhausted,
    NodeReleaseConflict,
    NodeRuntimeFailed,
    NodeRuntimeUnavailable,
    NodeState,
)
from rtsp_proxy.observability import FleetSnapshot, SnapshotReader
from rtsp_proxy.operator_access import (
    IssuedOperatorSession,
    OperatorActionBucket,
    OperatorActionRateLimited,
    OperatorAuthenticationRequired,
    OperatorAuthorizationDenied,
    OperatorPermission,
    OperatorPrincipal,
    OperatorRequestAuditContext,
    OperatorSessionControl,
    OperatorSessionUnavailable,
)
from rtsp_proxy.operator_identity import (
    BreakGlassControl,
    OidcLoginControl,
    OidcLoginInvalid,
    OidcLoginRateLimited,
    OidcLoginUnavailable,
)
from rtsp_proxy.reconcile import (
    CameraDisruptionConfirmationRequired,
    CameraMoveControl,
    CameraMutationControl,
    CameraMutationOperation,
    CameraOccupied,
    CameraReaderInvariantViolation,
    CameraRuntimeObserver,
    MoveConfirmationRequired,
    ReconcileRetry,
)

IDEMPOTENCY_KEY_HEADER = Header(default=None, alias="Idempotency-Key")
NODE_REVISION_HEADER = Header(default=None, alias="X-Node-Revision")
NODE_STATE_HEADER = Header(default=None, alias="X-Node-State")


def _lifecycle_busy() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail={"code": "node_lifecycle_busy"},
        headers={"Retry-After": "1"},
    )


def _camera_revision_conflict(error: CameraRevisionConflict) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail={
            "code": "camera_revision_conflict",
            "expected_revision": error.expected_revision,
            "current_revision": error.current_revision,
        },
    )


class LiveStatus(BaseModel):
    status: str
    role: str


class DependencyStatus(BaseModel):
    name: str
    status: str
    reason: str | None = None


class ReadyStatus(BaseModel):
    status: str
    role: str
    checks: list[DependencyStatus]


class NodeCreateRequest(BaseModel):
    name: str
    external_port: int | None = Field(default=None, ge=1, le=65535)


class NodeResponse(BaseModel):
    id: str
    name: str
    external_port: int
    state: str
    runtime_state: str
    health: str
    registered_cameras: int
    camera_capacity: int
    desired_revision: int
    applied_revision: int


class NodeReleaseRequest(BaseModel):
    release_id: str = Field(min_length=1, max_length=128)
    mediamtx_binary_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class NodePortChangeRequest(BaseModel):
    new_port: int = Field(ge=1, le=65535)
    confirmation_token: str | None = Field(default=None, max_length=4096)


class NodePortChangePreviewResponse(BaseModel):
    node_id: str
    old_port: int
    new_port: int
    desired_revision: int
    registered_cameras: int
    blast_radius_sha256: str
    affected_public_ids: list[str]
    active_reader_public_ids: list[str]
    reader_blast_radius_sha256: str
    reader_observed_at: datetime
    confirmation_token: str


class NodeReconfigureRequest(BaseModel):
    confirmation_token: str | None = Field(default=None, max_length=4096)


class NodeReconfigurePreviewResponse(BaseModel):
    node_id: str
    external_port: int
    desired_revision: int
    registered_cameras: int
    blast_radius_sha256: str
    affected_public_ids: list[str]
    active_reader_public_ids: list[str]
    reader_blast_radius_sha256: str
    reader_observed_at: datetime
    target_release_id: str
    target_mediamtx_binary_sha256: str
    confirmation_token: str


class NodeListResponse(BaseModel):
    items: list[NodeResponse]
    count: int
    max_nodes: int


class NodeMetricResponse(BaseModel):
    active_sources: int
    occupied_streams: int
    received_bytes_total: int
    sent_bytes_total: int


class FleetNodeResponse(BaseModel):
    node_id: str
    name: str
    external_port: int
    desired_state: str
    runtime_state: str
    health: str
    registered_cameras: int
    camera_capacity: int
    desired_revision: int
    applied_revision: int
    scrape_status: str
    scrape_reason: str | None
    metrics: NodeMetricResponse | None
    metric_observed_at: datetime | None
    received_bitrate_bps: float | None
    sent_bitrate_bps: float | None
    counters_reset: bool


class FleetSnapshotResponse(BaseModel):
    generated_at: datetime
    configured_nodes: int
    max_nodes: int
    registered_cameras: int
    external_ports_used: int
    external_ports_free: int
    nodes: list[FleetNodeResponse]


class OperatorSessionResponse(BaseModel):
    account_id: str
    subject: str
    display_name: str
    roles: list[str]
    scopes: list[str]
    authz_version: int
    mfa_verified_at: datetime | None


class BreakGlassLoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=256)
    password: str = Field(min_length=1, max_length=1024)
    totp: str = Field(pattern=r"^[0-9]{6}$")


class CameraCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    source_url: str
    node_id: UUID | None = None


class CameraUpdateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    source_url: str
    expected_revision: int | None = Field(default=None, ge=1)
    confirmation_token: str | None = Field(default=None, max_length=4096)


class CameraDisruptionRequest(BaseModel):
    expected_revision: int | None = Field(default=None, ge=1)
    confirmation_token: str | None = Field(default=None, max_length=4096)


class CameraMutationPreviewRequest(BaseModel):
    operation: CameraMutationOperation
    expected_revision: int | None = Field(default=None, ge=1)
    name: str | None = Field(default=None, min_length=1, max_length=128)
    source_url: str | None = None


class CameraMutationPreviewResponse(BaseModel):
    camera_id: str
    operation: CameraMutationOperation
    desired_revision: int
    occupied: bool
    disconnect_readers: int
    mutation_sha256: str
    confirmation_token: str | None


class CameraResponse(BaseModel):
    id: str
    name: str
    public_id: str
    node_id: str
    node_port: int
    placement_mode: str
    state: str
    registered: bool
    desired_revision: int
    applied_revision: int


class CameraListResponse(BaseModel):
    items: list[CameraResponse]
    count: int


class CameraMoveRequest(BaseModel):
    target_node_id: UUID
    force: bool = False
    confirmation_token: str | None = None


class CameraMovePreviewRequest(BaseModel):
    target_node_id: UUID


class CameraMovePreviewResponse(BaseModel):
    camera_id: str
    source_node_id: str
    target_node_id: str
    desired_revision: int
    occupied: bool
    disconnect_readers: int
    confirmation_token: str | None
    source_port: int
    target_port: int
    source_endpoint: str
    target_endpoint: str


class CameraMoveResponse(BaseModel):
    id: str
    camera_id: str
    source_node_id: str
    target_node_id: str
    source_generation: int
    target_generation: int
    desired_revision: int
    force: bool
    confirmed_disconnect_readers: int
    source_port: int | None
    target_port: int | None
    source_endpoint: str | None
    target_endpoint: str | None
    expires_at: datetime
    abort_reason: str | None
    state: str


class CameraRuntimeResponse(BaseModel):
    camera_id: str
    node_id: str
    ready: bool
    reader_count: int
    occupied: bool
    reader_limit_violated: bool


class AccessPolicyUpdateRequest(BaseModel):
    internet_cidrs: list[str] = Field(default_factory=list, max_length=128)
    local_cidrs: list[str] = Field(default_factory=list, max_length=128)
    expected_revision: int = Field(ge=1)


class AccessPolicyResponse(BaseModel):
    camera_id: str
    internet_cidrs: list[str]
    local_cidrs: list[str]
    revision: int


class AccessGrantCreateRequest(BaseModel):
    kind: Literal["temporary", "service"]
    lifetime_seconds: int = Field(ge=1, le=366 * 24 * 60 * 60)


class AccessGrantRotateRequest(BaseModel):
    overlap_seconds: int = Field(default=30, ge=0, le=24 * 60 * 60)
    lifetime_seconds: int = Field(ge=1, le=366 * 24 * 60 * 60)
    expected_revision: int = Field(ge=1)


class AccessGrantSecretResponse(BaseModel):
    id: str
    camera_id: str
    username: str
    password: str
    not_before: datetime
    expires_at: datetime
    revision: int
    kind: str
    created_by: str
    last_used_at: datetime | None


class AccessGrantResponse(BaseModel):
    id: str
    camera_id: str
    username: str
    not_before: datetime
    expires_at: datetime
    revoked_at: datetime | None
    revision: int
    kind: str
    created_by: str
    last_used_at: datetime | None


class AccessGrantListResponse(BaseModel):
    items: list[AccessGrantResponse]
    count: int
    truncated: bool


class MediaAuthRequest(BaseModel):
    user: str = Field(max_length=64)
    password: str = Field(max_length=256)
    action: str = Field(max_length=16)
    path: str = Field(max_length=256)
    protocol: str = Field(max_length=16)
    ip: str = Field(max_length=64)


class _MediaAuthAdmissionGate:
    def __init__(self, *, max_inflight: int, rate_per_second: int, burst: int) -> None:
        if min(max_inflight, rate_per_second, burst) < 1 or burst < rate_per_second:
            raise ValueError("media_auth_admission_gate_invalid")
        self._inflight = BoundedSemaphore(max_inflight)
        self._lock = Lock()
        self._rate_per_second = float(rate_per_second)
        self._burst = float(burst)
        self._tokens = float(burst)
        self._updated = monotonic()

    def enter(self) -> bool:
        if not self._inflight.acquire(blocking=False):
            return False
        now = monotonic()
        with self._lock:
            elapsed = max(0.0, now - self._updated)
            self._updated = now
            self._tokens = min(
                self._burst,
                self._tokens + elapsed * self._rate_per_second,
            )
            if self._tokens < 1.0:
                self._inflight.release()
                return False
            self._tokens -= 1.0
        return True

    def leave(self) -> None:
        self._inflight.release()


class _MediaAuthAdmissionMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        callback_verifier: PepperVerifier | None,
        body_timeout_seconds: float,
        admission: _MediaAuthAdmissionGate,
    ) -> None:
        self._app = app
        self._callback_verifier = callback_verifier
        self._body_timeout_seconds = body_timeout_seconds
        self._admission = admission

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path") in {
            "/health/live",
            "/health/ready",
            "/internal/v1/metrics",
        }:
            await self._app(scope, receive, send)
            return
        path = str(scope.get("path", ""))
        prefix = "/internal/v1/media-auth/"
        try:
            node_id = UUID(path.removeprefix(prefix))
        except ValueError:
            await _media_auth_denied()(scope, receive, send)
            return
        headers: dict[bytes, bytes] = {}
        for name, value in scope.get("headers", []):
            lowered = name.lower()
            if lowered in {b"authorization", b"content-length"} and lowered in headers:
                await _media_auth_denied()(scope, receive, send)
                return
            headers[lowered] = value
        try:
            body_length = int(headers[b"content-length"])
            authorization = headers.get(b"authorization", b"").decode("ascii")
        except (KeyError, UnicodeError, ValueError):
            await _media_auth_denied()(scope, receive, send)
            return
        if (
            scope.get("method") != "POST"
            or not path.startswith(prefix)
            or body_length < 0
            or body_length > 2048
            or self._callback_verifier is None
            or not self._callback_verifier.verify_callback_authorization(
                node_id,
                authorization,
            )
            or not self._admission.enter()
        ):
            await _media_auth_denied()(scope, receive, send)
            return
        try:
            try:
                body = await self._read_body(receive, expected_length=body_length)
            except (TimeoutError, RuntimeError):
                await _media_auth_denied()(scope, receive, send)
                return
            delivered = False

            async def replay() -> Message:
                nonlocal delivered
                if delivered:
                    return {"type": "http.disconnect"}
                delivered = True
                return {"type": "http.request", "body": body, "more_body": False}

            buffered: list[Message] = []

            async def buffer(message: Message) -> None:
                buffered.append(message)

            try:
                await self._app(scope, replay, buffer)
            except Exception:
                await _media_auth_denied()(scope, replay, send)
                return
            for message in buffered:
                await send(message)
        finally:
            self._admission.leave()

    async def _read_body(self, receive: Receive, *, expected_length: int) -> bytes:
        chunks: list[bytes] = []
        received = 0
        more_body = True
        with anyio.fail_after(self._body_timeout_seconds):
            while more_body:
                message = await receive()
                if message.get("type") != "http.request":
                    raise RuntimeError("media_auth_body_incomplete")
                chunk = message.get("body", b"")
                if not isinstance(chunk, bytes):
                    raise RuntimeError("media_auth_body_invalid")
                received += len(chunk)
                if received > expected_length:
                    raise RuntimeError("media_auth_body_invalid")
                chunks.append(chunk)
                more_body = bool(message.get("more_body", False))
        if received != expected_length:
            raise RuntimeError("media_auth_body_incomplete")
        return b"".join(chunks)


def _media_auth_denied() -> Response:
    return Response(
        status_code=status.HTTP_401_UNAUTHORIZED,
        headers={"Cache-Control": "no-store"},
    )


def create_app(
    settings: Settings,
    readiness: ReadinessProvider | None = None,
    node_control: NodeControl | None = None,
    camera_control: CameraControl | None = None,
    camera_mutation_control: CameraMutationControl | None = None,
    camera_move_control: CameraMoveControl | None = None,
    camera_runtime_observer: CameraRuntimeObserver | None = None,
    access_policy_control: AccessPolicyControl | None = None,
    access_grant_control: AccessGrantControl | None = None,
    fleet_snapshots: SnapshotReader | None = None,
    operator_sessions: OperatorSessionControl | None = None,
    operator_login: OidcLoginControl | None = None,
    break_glass: BreakGlassControl | None = None,
    fleet_snapshot_max_age_seconds: float = 30,
    access_secret_reveal_seconds: int = 30,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    startup: Callable[[], None] | None = None,
    shutdown: Callable[[], None] | None = None,
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        try:
            if startup is not None:
                startup()
            yield
        finally:
            if shutdown is not None:
                shutdown()

    app = FastAPI(title="RTSP Proxy Control Plane", lifespan=lifespan)
    readiness_provider = readiness or MissingReadinessProvider()

    if operator_login is not None:

        @app.get("/auth/oidc/login", include_in_schema=False)
        def oidc_login(request: Request) -> Response:
            try:
                redirect = operator_login.begin(source_ip=_request_source_ip(request))
            except OidcLoginRateLimited as error:
                return _operator_rate_limited(error.retry_after_seconds)
            except OidcLoginUnavailable:
                return _operator_login_unavailable()
            response = RedirectResponse(
                redirect.location,
                status_code=status.HTTP_303_SEE_OTHER,
                headers={"Cache-Control": "no-store"},
            )
            response.set_cookie(
                "__Secure-rtsp_proxy_oidc_flow",
                redirect.browser_token,
                secure=True,
                httponly=True,
                samesite="lax",
                path="/auth/oidc/callback",
                max_age=600,
            )
            return response

        @app.get("/auth/oidc/callback", include_in_schema=False)
        def oidc_callback(
            request: Request,
            state: str = "",
            code: str = "",
        ) -> Response:
            try:
                completed = operator_login.complete(
                    state=state,
                    code=code,
                    browser_token=request.cookies.get(
                        "__Secure-rtsp_proxy_oidc_flow",
                        "",
                    ),
                    audit_context=_operator_login_request_audit_context(request),
                )
            except OidcLoginInvalid:
                try:
                    operator_login.record_rejection(source_ip=_request_source_ip(request))
                except OidcLoginRateLimited as error:
                    response = _operator_rate_limited(error.retry_after_seconds)
                    _clear_oidc_flow_cookie(response)
                    return response
                except OidcLoginUnavailable:
                    response = _operator_login_unavailable()
                    _clear_oidc_flow_cookie(response)
                    return response
                response = JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"detail": {"code": "operator_login_failed"}},
                    headers={"Cache-Control": "no-store"},
                )
                _clear_oidc_flow_cookie(response)
                return response
            except OidcLoginRateLimited as error:
                try:
                    operator_login.record_rejection(source_ip=_request_source_ip(request))
                except OidcLoginRateLimited:
                    pass
                except OidcLoginUnavailable:
                    response = _operator_login_unavailable()
                    _clear_oidc_flow_cookie(response)
                    return response
                response = _operator_rate_limited(error.retry_after_seconds)
                _clear_oidc_flow_cookie(response)
                return response
            except OidcLoginUnavailable:
                response = _operator_login_unavailable()
                _clear_oidc_flow_cookie(response)
                return response
            completed_response = RedirectResponse(
                completed.return_to,
                status_code=status.HTTP_303_SEE_OTHER,
                headers={"Cache-Control": "no-store"},
            )
            _set_operator_session_cookies(completed_response, completed.session)
            _clear_oidc_flow_cookie(completed_response)
            return completed_response

    if break_glass is not None:

        @app.post("/auth/break-glass/login", include_in_schema=False)
        def break_glass_login(
            request: Request,
            payload: BreakGlassLoginRequest,
        ) -> Response:
            try:
                issued = break_glass.login(
                    username=payload.username,
                    password=payload.password,
                    totp=payload.totp,
                    source_ip=_request_source_ip(request),
                    audit_context=_operator_login_request_audit_context(request),
                )
            except OidcLoginRateLimited as error:
                return _operator_rate_limited(error.retry_after_seconds)
            except OidcLoginInvalid:
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"detail": {"code": "operator_login_failed"}},
                    headers={"Cache-Control": "no-store"},
                )
            except OidcLoginUnavailable:
                return _operator_login_unavailable()
            response = RedirectResponse(
                "/",
                status_code=status.HTTP_303_SEE_OTHER,
                headers={"Cache-Control": "no-store"},
            )
            _set_operator_session_cookies(response, issued)
            return response

    if operator_sessions is not None:

        @app.middleware("http")
        async def operator_access_boundary(
            request: Request,
            call_next: Callable[[Request], Awaitable[Response]],
        ) -> Response:
            if not _operator_protected_path(request.url.path):
                result = await call_next(request)
                assert isinstance(result, Response)
                return result
            session_token = request.cookies.get("__Host-rtsp_proxy_session", "")
            require_csrf = request.method not in {"GET", "HEAD", "OPTIONS"}
            permission = _operator_permission_for_request(request)
            required_scope = _operator_scope_for_request(request)
            audit_context = _operator_request_audit_context(
                request,
                required_scope=required_scope,
            )
            request.state.operator_audit_context = audit_context

            def audited_response(response: Response) -> Response:
                response.headers["X-Request-ID"] = str(audit_context.request_id)
                return response

            try:
                csrf_token = request.headers.get("X-CSRF-Token")
                if require_csrf and request.url.path.startswith("/dashboard/"):
                    dashboard_form = await read_dashboard_form(request)
                    request.state.dashboard_form = dashboard_form
                    csrf_token = dashboard_form.csrf_token
                principal = await anyio.to_thread.run_sync(
                    lambda: operator_sessions.authenticate(
                        session_token=session_token,
                        permission=permission,
                        csrf_token=csrf_token,
                        require_csrf=require_csrf,
                        required_scope=required_scope,
                        audit_context=audit_context,
                    ),
                    abandon_on_cancel=True,
                )
            except DashboardFormInvalid:
                try:
                    await anyio.to_thread.run_sync(
                        lambda: operator_sessions.record_denied_request(
                            session_token=session_token,
                            reason_code="operator_csrf_invalid",
                            audit_context=audit_context,
                        ),
                        abandon_on_cancel=True,
                    )
                except OperatorSessionUnavailable:
                    return audited_response(_operator_session_unavailable_response(request))
                return audited_response(
                    _operator_authentication_required_response(
                        request,
                        oidc_enabled=operator_login is not None,
                    )
                )
            except OperatorAuthenticationRequired:
                return audited_response(
                    _operator_authentication_required_response(
                        request,
                        oidc_enabled=operator_login is not None,
                    )
                )
            except OperatorAuthorizationDenied:
                if request.url.path.startswith("/dashboard"):
                    return audited_response(
                        _dashboard_unavailable_response(
                            DashboardUnavailable(
                                title="Недостаточно прав",
                                message=(
                                    "У этой операторской сессии нет доступа к дашборду."  # noqa: RUF001
                                ),
                            ),
                            status_code=status.HTTP_403_FORBIDDEN,
                        )
                    )
                return audited_response(
                    _operator_error_response(
                        status.HTTP_403_FORBIDDEN,
                        "operator_permission_denied",
                    )
                )
            except OperatorSessionUnavailable:
                return audited_response(_operator_session_unavailable_response(request))
            action_bucket = _operator_action_bucket(audit_context.action)
            if action_bucket is not None:
                try:
                    await anyio.to_thread.run_sync(
                        lambda: operator_sessions.admit_action(
                            principal=principal,
                            bucket=action_bucket,
                        ),
                        abandon_on_cancel=True,
                    )
                except OperatorActionRateLimited as error:
                    try:
                        await anyio.to_thread.run_sync(
                            lambda: operator_sessions.record_denied_request(
                                session_token=session_token,
                                reason_code="operator_rate_limited",
                                audit_context=audit_context,
                            ),
                            abandon_on_cancel=True,
                        )
                    except OperatorSessionUnavailable:
                        return audited_response(
                            _operator_session_unavailable_response(request)
                        )
                    return audited_response(
                        _operator_action_rate_limited(error.retry_after_seconds)
                    )
                except OperatorSessionUnavailable:
                    return audited_response(_operator_session_unavailable_response(request))
            request.state.operator_principal = principal
            result = await call_next(request)
            assert isinstance(result, Response)
            result.headers["Cache-Control"] = "no-store"
            return audited_response(result)

    @app.get("/", include_in_schema=False)
    def application_root() -> Response:
        return RedirectResponse("/dashboard", status_code=status.HTTP_303_SEE_OTHER)

    @app.get("/assets/dashboard.css", include_in_schema=False)
    def dashboard_stylesheet() -> Response:
        from importlib.resources import files

        stylesheet = (
            files("rtsp_proxy").joinpath("assets/dashboard.css").read_text(encoding="utf-8")
        )
        return PlainTextResponse(
            stylesheet,
            media_type="text/css",
            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
        )

    @app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
    def dashboard_page(request: Request) -> Response:
        principal = _dashboard_principal(request, operator_sessions)
        if isinstance(principal, Response):
            return principal
        snapshot_response = _dashboard_snapshot_or_response(
            fleet_snapshots=fleet_snapshots,
            max_age_seconds=fleet_snapshot_max_age_seconds,
            now=clock(),
            principal=principal,
        )
        if isinstance(snapshot_response, Response):
            return snapshot_response
        return _dashboard_html_response(
            render_overview(
                snapshot=snapshot_response,
                principal=principal,
                can_manage_nodes=(
                    node_control is not None
                    and principal.allows(OperatorPermission.CONTROL_MUTATE)
                    and 43 <= len(request.cookies.get("__Host-rtsp_proxy_csrf", "")) <= 1024
                ),
            )
        )

    @app.get("/dashboard/logout", response_class=HTMLResponse, include_in_schema=False)
    def dashboard_logout_page(request: Request) -> Response:
        principal = _dashboard_principal(request, operator_sessions)
        if isinstance(principal, Response):
            return principal
        return _dashboard_html_response(
            render_logout(
                principal=principal,
                csrf_token=request.cookies.get("__Host-rtsp_proxy_csrf", ""),
            )
        )

    @app.post("/dashboard/logout", include_in_schema=False)
    def dashboard_logout(request: Request) -> Response:
        assert operator_sessions is not None
        operator_sessions.revoke(
            request.cookies.get("__Host-rtsp_proxy_session", ""),
            audit_context=request.state.operator_audit_context,
        )
        response = RedirectResponse(
            "/dashboard",
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Cache-Control": "no-store"},
        )
        _clear_operator_session_cookies(response)
        return response

    app.include_router(
        camera_dashboard_router(
            camera_control=camera_control,
            camera_mutation_control=camera_mutation_control,
            camera_move_control=camera_move_control,
            access_policy_control=access_policy_control,
            access_grant_control=access_grant_control,
            operator_sessions=operator_sessions,
            recent_mfa_seconds=settings.operator_recent_mfa_seconds,
            secret_reveal_seconds=access_secret_reveal_seconds,
        )
    )
    app.include_router(node_dashboard_router(node_control=node_control, settings=settings))

    @app.get(
        "/dashboard/nodes/{node_id}",
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    def dashboard_node_page(request: Request, node_id: UUID) -> Response:
        principal = _dashboard_principal(request, operator_sessions)
        if isinstance(principal, Response):
            return principal
        snapshot_response = _dashboard_snapshot_or_response(
            fleet_snapshots=fleet_snapshots,
            max_age_seconds=fleet_snapshot_max_age_seconds,
            now=clock(),
            principal=principal,
        )
        if isinstance(snapshot_response, Response):
            return snapshot_response
        node = next((item for item in snapshot_response.nodes if item.node_id == node_id), None)
        if node is None:
            return _dashboard_unavailable_response(
                DashboardUnavailable(
                    title="Нода не найдена",
                    message=(
                        "В текущем снимке сервера нет ноды с таким идентификатором."  # noqa: RUF001
                    ),
                ),
                status_code=status.HTTP_404_NOT_FOUND,
                principal=principal,
            )
        return _dashboard_html_response(
            render_node_detail(
                snapshot=snapshot_response,
                node=node,
                principal=principal,
                csrf_token=request.cookies.get("__Host-rtsp_proxy_csrf", ""),
                can_manage_nodes=(
                    node_control is not None
                    and principal.allows(OperatorPermission.CONTROL_MUTATE)
                    and 43 <= len(request.cookies.get("__Host-rtsp_proxy_csrf", "")) <= 1024
                ),
                port_range_start=settings.node_port_range_start,
                port_range_end=settings.node_port_range_end,
                target_release_id=settings.node_release_id,
            )
        )

    @app.exception_handler(NodeLifecycleBusy)
    async def node_lifecycle_busy_handler(
        _request: Request,
        _error: NodeLifecycleBusy,
    ) -> JSONResponse:
        return _retryable_service_response("node_lifecycle_busy")

    @app.exception_handler(OperatorSessionUnavailable)
    async def operator_session_unavailable_handler(
        _request: Request,
        _error: OperatorSessionUnavailable,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"detail": {"code": "operator_session_unavailable"}},
            headers={"Cache-Control": "no-store", "Retry-After": "1"},
        )

    @app.exception_handler(ReconcileRetry)
    async def reconcile_retry_handler(
        _request: Request,
        _error: ReconcileRetry,
    ) -> JSONResponse:
        return _retryable_service_response("camera_runtime_retry")

    @app.exception_handler(MediaNodeError)
    async def media_node_error_handler(
        _request: Request,
        _error: MediaNodeError,
    ) -> JSONResponse:
        return _retryable_service_response("camera_runtime_retry")

    @app.get("/health/live", response_model=LiveStatus)
    async def live() -> LiveStatus:
        return LiveStatus(status="ok", role=settings.role.value)

    @app.get("/health/ready", response_model=ReadyStatus)
    async def ready(response: Response) -> ReadyStatus:
        results = normalize_readiness_results(
            settings.role,
            await readiness_provider.check(settings.role),
        )
        is_ready = all(result.ready for result in results)
        if not is_ready:
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

        return ReadyStatus(
            status="ready" if is_ready else "not_ready",
            role=settings.role.value,
            checks=[
                DependencyStatus(
                    name=result.name,
                    status="pass" if result.ready else "fail",
                    reason=result.reason,
                )
                for result in results
            ],
        )

    @app.get("/api/v1/dashboard/snapshot", response_model=FleetSnapshotResponse)
    def dashboard_snapshot() -> FleetSnapshotResponse:
        try:
            snapshot = require_fresh_snapshot(
                fleet_snapshots,
                now=clock(),
                max_age_seconds=fleet_snapshot_max_age_seconds,
            )
        except FleetSnapshotReadFailure as error:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": error.reason.value},
            ) from None
        return FleetSnapshotResponse(
            generated_at=snapshot.generated_at,
            configured_nodes=snapshot.configured_nodes,
            max_nodes=snapshot.max_nodes,
            registered_cameras=snapshot.registered_cameras,
            external_ports_used=snapshot.external_ports_used,
            external_ports_free=snapshot.external_ports_free,
            nodes=[
                FleetNodeResponse(
                    node_id=str(node.node_id),
                    name=node.name,
                    external_port=node.external_port,
                    desired_state=node.desired_state.value,
                    runtime_state=node.runtime_state.value,
                    health=node.health.value,
                    registered_cameras=node.registered_cameras,
                    camera_capacity=node.camera_capacity,
                    desired_revision=node.desired_revision,
                    applied_revision=node.applied_revision,
                    scrape_status=node.scrape_status.value,
                    scrape_reason=node.scrape_reason,
                    metrics=(
                        None
                        if node.metrics is None
                        else NodeMetricResponse(
                            active_sources=node.metrics.active_sources,
                            occupied_streams=node.metrics.occupied_streams,
                            received_bytes_total=node.metrics.received_bytes_total,
                            sent_bytes_total=node.metrics.sent_bytes_total,
                        )
                    ),
                    metric_observed_at=node.metric_observed_at,
                    received_bitrate_bps=node.received_bitrate_bps,
                    sent_bitrate_bps=node.sent_bitrate_bps,
                    counters_reset=node.counters_reset,
                )
                for node in snapshot.nodes
            ],
        )

    @app.get("/api/v1/operator/session", response_model=OperatorSessionResponse)
    def operator_session(request: Request) -> OperatorSessionResponse:
        principal = _operator_principal(request)
        return OperatorSessionResponse(
            account_id=str(principal.account_id),
            subject=principal.subject,
            display_name=principal.display_name,
            roles=sorted(role.value for role in principal.roles),
            scopes=sorted(principal.scopes),
            authz_version=principal.authz_version,
            mfa_verified_at=principal.mfa_verified_at,
        )

    @app.delete("/api/v1/operator/session", status_code=status.HTTP_204_NO_CONTENT)
    def operator_logout(request: Request, response: Response) -> None:
        assert operator_sessions is not None
        token = request.cookies.get("__Host-rtsp_proxy_session", "")
        operator_sessions.revoke(
            token,
            audit_context=request.state.operator_audit_context,
        )
        _clear_operator_session_cookies(response)

    @app.post("/api/v1/nodes", response_model=NodeResponse, status_code=201)
    def create_node(
        request: Request,
        payload: NodeCreateRequest,
        response: Response,
        idempotency_key: UUID | None = IDEMPOTENCY_KEY_HEADER,
    ) -> NodeResponse:
        if node_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "node_control_unavailable"},
            )
        try:
            node = node_control.register_node(
                name=payload.name,
                port_range_start=settings.node_port_range_start,
                port_range_end=settings.node_port_range_end,
                max_nodes=settings.max_nodes,
                external_port=payload.external_port,
                reserved_ports=settings.node_port_reserved,
                api_ports=range(
                    settings.node_api_port_range_start,
                    settings.node_api_port_range_end + 1,
                ),
                metrics_ports=range(
                    settings.node_metrics_port_range_start,
                    settings.node_metrics_port_range_end + 1,
                ),
                release_id=settings.node_release_id,
                mediamtx_binary_sha256=settings.node_mediamtx_binary_sha256,
                mutation_context=_external_node_mutation_context(
                    request,
                    idempotency_key=idempotency_key,
                ),
            )
        except NodePortRangeExhausted:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "code": "node_ports_exhausted",
                    "message": "нет свободных портов для регистрации новой ноды",
                },
            ) from None
        except MaximumNodesReached:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "code": "max_nodes_reached",
                    "message": "достигнуто максимальное количество нод",
                },
            ) from None
        except NodeManagementPortRangeExhausted:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "code": "node_management_ports_exhausted",
                    "message": "нет свободной пары loopback API/metrics портов",
                },
            ) from None
        except NodePortOutOfRange:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={
                    "code": "node_port_out_of_range",
                    "message": "порт ноды находится вне разрешенного диапазона",
                },
            ) from None
        except NodePortInUse:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "code": "node_port_in_use",
                    "message": "порт уже используется другой нодой",
                },
            ) from None
        except NodeLifecycleConflict as error:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": str(error)},
            ) from None
        except NodeRuntimeUnavailable:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "node_registration_schema_unavailable"},
            ) from None
        except NodeRuntimeFailed as error:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "code": error.code,
                    "node_id": str(error.node_id),
                },
            ) from None
        response.headers["Location"] = f"/api/v1/nodes/{node.id}"
        return NodeResponse(
            id=str(node.id),
            name=node.name,
            external_port=node.external_port,
            state=node.state.value,
            runtime_state=node.runtime_state.value,
            health=node.health.value,
            registered_cameras=node.registered_cameras,
            camera_capacity=node.camera_capacity,
            desired_revision=node.desired_revision,
            applied_revision=node.applied_revision,
        )

    @app.get("/api/v1/nodes", response_model=NodeListResponse)
    def list_nodes() -> NodeListResponse:
        if node_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "node_control_unavailable"},
            )
        items = [
            NodeResponse(
                id=str(node.id),
                name=node.name,
                external_port=node.external_port,
                state=node.state.value,
                runtime_state=node.runtime_state.value,
                health=node.health.value,
                registered_cameras=node.registered_cameras,
                camera_capacity=node.camera_capacity,
                desired_revision=node.desired_revision,
                applied_revision=node.applied_revision,
            )
            for node in node_control.list_nodes()
        ]
        return NodeListResponse(items=items, count=len(items), max_nodes=settings.max_nodes)

    @app.post("/api/v1/nodes/{node_id}/start", response_model=NodeResponse)
    def start_node(
        request: Request,
        node_id: UUID,
        expected_revision: int | None = NODE_REVISION_HEADER,
        expected_state: NodeState | None = NODE_STATE_HEADER,
    ) -> NodeResponse:
        if node_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "node_control_unavailable"},
            )
        try:
            command = _external_node_command(
                request,
                expected_revision=expected_revision,
                expected_state=expected_state,
                allowed_states=frozenset({NodeState.STOPPED, NodeState.FAILED}),
            )
            node = node_control.start_node(
                node_id,
                fence=None if command is None else command.fence,
                mutation_context=(None if command is None else command.mutation_context),
            )
        except NodeNotFound:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "node_not_found"},
            ) from None
        except NodeLifecycleBusy:
            raise _lifecycle_busy() from None
        except NodeLifecycleConflict as error:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": str(error)},
            ) from None
        except NodeRuntimeUnavailable:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "node_runtime_unavailable"},
            ) from None
        except NodeRuntimeFailed as error:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": error.code, "node_id": str(error.node_id)},
            ) from None
        return NodeResponse(
            id=str(node.id),
            name=node.name,
            external_port=node.external_port,
            state=node.state.value,
            runtime_state=node.runtime_state.value,
            health=node.health.value,
            registered_cameras=node.registered_cameras,
            camera_capacity=node.camera_capacity,
            desired_revision=node.desired_revision,
            applied_revision=node.applied_revision,
        )

    @app.post("/api/v1/nodes/{node_id}/stop", response_model=NodeResponse)
    def stop_node(
        request: Request,
        node_id: UUID,
        expected_revision: int | None = NODE_REVISION_HEADER,
        expected_state: NodeState | None = NODE_STATE_HEADER,
    ) -> NodeResponse:
        if node_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "node_control_unavailable"},
            )
        try:
            command = _external_node_command(
                request,
                expected_revision=expected_revision,
                expected_state=expected_state,
                allowed_states=frozenset(
                    {NodeState.RUNNING, NodeState.DRAINING, NodeState.MAINTENANCE}
                ),
            )
            node = node_control.stop_node(
                node_id,
                fence=None if command is None else command.fence,
                mutation_context=(None if command is None else command.mutation_context),
            )
        except NodeNotFound:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "node_not_found"},
            ) from None
        except NodeLifecycleBusy:
            raise _lifecycle_busy() from None
        except NodeNotEmpty:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "node_not_empty"},
            ) from None
        except NodeLifecycleConflict as error:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": str(error)},
            ) from None
        except NodeRuntimeUnavailable:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "node_runtime_unavailable"},
            ) from None
        except NodeRuntimeFailed as error:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": error.code, "node_id": str(error.node_id)},
            ) from None
        return _node_response(node)

    @app.post("/api/v1/nodes/{node_id}/restart", response_model=NodeResponse)
    def restart_node(
        request: Request,
        node_id: UUID,
        expected_revision: int | None = NODE_REVISION_HEADER,
        expected_state: NodeState | None = NODE_STATE_HEADER,
    ) -> NodeResponse:
        if node_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "node_control_unavailable"},
            )
        try:
            command = _external_node_command(
                request,
                expected_revision=expected_revision,
                expected_state=expected_state,
                allowed_states=frozenset({NodeState.RUNNING}),
            )
            node = node_control.restart_node(
                node_id,
                fence=None if command is None else command.fence,
                mutation_context=(None if command is None else command.mutation_context),
            )
        except NodeNotFound:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "node_not_found"},
            ) from None
        except NodeLifecycleBusy:
            raise _lifecycle_busy() from None
        except NodeLifecycleConflict as error:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": str(error)},
            ) from None
        except NodeNotEmpty:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "node_not_empty"},
            ) from None
        except NodeRuntimeUnavailable:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "node_runtime_unavailable"},
            ) from None
        except NodeRuntimeFailed as error:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": error.code, "node_id": str(error.node_id)},
            ) from None
        return _node_response(node)

    @app.post(
        "/api/v1/nodes/{node_id}/reconfigure/preview",
        response_model=NodeReconfigurePreviewResponse,
    )
    def preview_node_reconfigure(
        request: Request,
        node_id: UUID,
    ) -> NodeReconfigurePreviewResponse:
        if node_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "node_control_unavailable"},
            )
        try:
            preview = node_control.preview_reconfigure(
                node_id,
                confirmation_context=_external_disruption_context(request, settings),
            )
        except NodeNotFound:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "node_not_found"},
            ) from None
        except NodeLifecycleBusy:
            raise _lifecycle_busy() from None
        except NodeLifecycleConflict as error:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": str(error)},
            ) from None
        except NodeRuntimeUnavailable:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "node_confirmation_unavailable"},
            ) from None
        return NodeReconfigurePreviewResponse(
            node_id=str(preview.node_id),
            external_port=preview.external_port,
            desired_revision=preview.desired_revision,
            registered_cameras=preview.registered_cameras,
            blast_radius_sha256=preview.blast_radius_sha256,
            affected_public_ids=[str(value) for value in preview.affected_public_ids],
            active_reader_public_ids=[str(value) for value in preview.active_reader_public_ids],
            reader_blast_radius_sha256=preview.reader_blast_radius_sha256,
            reader_observed_at=preview.reader_observed_at,
            target_release_id=preview.target_release_id,
            target_mediamtx_binary_sha256=(preview.target_mediamtx_binary_sha256),
            confirmation_token=preview.confirmation_token,
        )

    @app.post("/api/v1/nodes/{node_id}/reconfigure", response_model=NodeResponse)
    def reconfigure_node(
        http_request: Request,
        node_id: UUID,
        request: NodeReconfigureRequest,
        expected_revision: int | None = NODE_REVISION_HEADER,
        expected_state: NodeState | None = NODE_STATE_HEADER,
    ) -> NodeResponse:
        if node_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "node_control_unavailable"},
            )
        try:
            command = _external_node_command(
                http_request,
                expected_revision=expected_revision,
                expected_state=expected_state,
                allowed_states=frozenset({NodeState.DRAINING}),
            )
            node = node_control.reconfigure_node(
                node_id,
                confirmation_token=request.confirmation_token,
                confirmation_context=_external_disruption_context(
                    http_request,
                    settings,
                ),
                fence=None if command is None else command.fence,
                mutation_context=(None if command is None else command.mutation_context),
            )
        except NodeNotFound:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "node_not_found"},
            ) from None
        except NodeLifecycleBusy:
            raise _lifecycle_busy() from None
        except NodeDisruptionConfirmationRequired:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "node_disruption_confirmation_required"},
            ) from None
        except NodeLifecycleConflict as error:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": str(error)},
            ) from None
        except NodeRuntimeUnavailable:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "node_runtime_unavailable"},
            ) from None
        except NodeRuntimeFailed as error:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": error.code, "node_id": str(error.node_id)},
            ) from None
        return _node_response(node)

    @app.post("/api/v1/nodes/{node_id}/observe", response_model=NodeResponse)
    def observe_node(node_id: UUID) -> NodeResponse:
        if node_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "node_control_unavailable"},
            )
        try:
            node = node_control.observe_node(node_id)
        except NodeNotFound:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "node_not_found"},
            ) from None
        except NodeLifecycleBusy:
            raise _lifecycle_busy() from None
        except NodeRuntimeUnavailable:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "node_runtime_unavailable"},
            ) from None
        except NodeRuntimeFailed as error:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": error.code, "node_id": str(error.node_id)},
            ) from None
        return _node_response(node)

    @app.put("/api/v1/nodes/{node_id}/release", response_model=NodeResponse)
    def update_node_release(
        http_request: Request,
        node_id: UUID,
        request: NodeReleaseRequest,
        expected_revision: int | None = NODE_REVISION_HEADER,
        expected_state: NodeState | None = NODE_STATE_HEADER,
    ) -> NodeResponse:
        if node_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "node_control_unavailable"},
            )
        if (
            request.release_id != settings.node_release_id
            or request.mediamtx_binary_sha256 != settings.node_mediamtx_binary_sha256
        ):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={"code": "node_release_not_configured"},
            )
        try:
            command = _external_node_command(
                http_request,
                expected_revision=expected_revision,
                expected_state=expected_state,
                allowed_states=frozenset({NodeState.STOPPED}),
            )
            node = node_control.update_node_release(
                node_id,
                release_id=request.release_id,
                mediamtx_binary_sha256=request.mediamtx_binary_sha256,
                fence=None if command is None else command.fence,
                mutation_context=(None if command is None else command.mutation_context),
            )
        except NodeNotFound:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "node_not_found"},
            ) from None
        except NodeLifecycleBusy:
            raise _lifecycle_busy() from None
        except NodeReleaseConflict:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "node_release_transition_requires_stopped_empty"},
            ) from None
        except NodeLifecycleConflict as error:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": str(error)},
            ) from None
        return _node_response(node)

    def set_node_administrative_state(
        request: Request,
        node_id: UUID,
        state: NodeState,
        *,
        expected_revision: int | None,
        expected_state: NodeState | None,
    ) -> NodeResponse:
        if node_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "node_control_unavailable"},
            )
        try:
            allowed_states = {
                NodeState.DRAINING: frozenset({NodeState.RUNNING}),
                NodeState.MAINTENANCE: frozenset({NodeState.DRAINING}),
                NodeState.RUNNING: frozenset({NodeState.DRAINING, NodeState.MAINTENANCE}),
            }
            command = _external_node_command(
                request,
                expected_revision=expected_revision,
                expected_state=expected_state,
                allowed_states=allowed_states[state],
            )
            return _node_response(
                node_control.set_administrative_state(
                    node_id,
                    state,
                    fence=None if command is None else command.fence,
                    mutation_context=(None if command is None else command.mutation_context),
                )
            )
        except NodeNotFound:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "node_not_found"},
            ) from None
        except NodeLifecycleBusy:
            raise _lifecycle_busy() from None
        except NodeLifecycleConflict as error:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": str(error)},
            ) from None

    @app.post("/api/v1/nodes/{node_id}/drain", response_model=NodeResponse)
    def drain_node(
        request: Request,
        node_id: UUID,
        expected_revision: int | None = NODE_REVISION_HEADER,
        expected_state: NodeState | None = NODE_STATE_HEADER,
    ) -> NodeResponse:
        return set_node_administrative_state(
            request,
            node_id,
            NodeState.DRAINING,
            expected_revision=expected_revision,
            expected_state=expected_state,
        )

    @app.post("/api/v1/nodes/{node_id}/maintenance", response_model=NodeResponse)
    def maintain_node(
        request: Request,
        node_id: UUID,
        expected_revision: int | None = NODE_REVISION_HEADER,
        expected_state: NodeState | None = NODE_STATE_HEADER,
    ) -> NodeResponse:
        return set_node_administrative_state(
            request,
            node_id,
            NodeState.MAINTENANCE,
            expected_revision=expected_revision,
            expected_state=expected_state,
        )

    @app.post("/api/v1/nodes/{node_id}/resume", response_model=NodeResponse)
    def resume_node(
        request: Request,
        node_id: UUID,
        expected_revision: int | None = NODE_REVISION_HEADER,
        expected_state: NodeState | None = NODE_STATE_HEADER,
    ) -> NodeResponse:
        return set_node_administrative_state(
            request,
            node_id,
            NodeState.RUNNING,
            expected_revision=expected_revision,
            expected_state=expected_state,
        )

    @app.post(
        "/api/v1/nodes/{node_id}/port-change/preview",
        response_model=NodePortChangePreviewResponse,
    )
    def preview_node_port_change(
        http_request: Request,
        node_id: UUID,
        request: NodePortChangeRequest,
    ) -> NodePortChangePreviewResponse:
        if node_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "node_control_unavailable"},
            )
        try:
            preview = node_control.preview_port_change(
                node_id,
                new_port=request.new_port,
                allowed_ports=(settings.node_registration_policy().allowed_external_ports()),
                confirmation_context=_external_disruption_context(
                    http_request,
                    settings,
                ),
            )
        except NodeNotFound:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "node_not_found"},
            ) from None
        except NodePortOutOfRange:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={"code": "node_port_out_of_range"},
            ) from None
        except NodeLifecycleConflict as error:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": str(error)},
            ) from None
        except NodeRuntimeUnavailable:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "node_confirmation_unavailable"},
            ) from None
        return NodePortChangePreviewResponse(
            node_id=str(preview.node_id),
            old_port=preview.old_port,
            new_port=preview.new_port,
            desired_revision=preview.desired_revision,
            registered_cameras=preview.registered_cameras,
            blast_radius_sha256=preview.blast_radius_sha256,
            affected_public_ids=[str(value) for value in preview.affected_public_ids],
            active_reader_public_ids=[str(value) for value in preview.active_reader_public_ids],
            reader_blast_radius_sha256=preview.reader_blast_radius_sha256,
            reader_observed_at=preview.reader_observed_at,
            confirmation_token=preview.confirmation_token,
        )

    @app.post(
        "/api/v1/nodes/{node_id}/port-change",
        response_model=NodeResponse,
    )
    def change_node_port(
        http_request: Request,
        node_id: UUID,
        request: NodePortChangeRequest,
        expected_revision: int | None = NODE_REVISION_HEADER,
        expected_state: NodeState | None = NODE_STATE_HEADER,
    ) -> NodeResponse:
        if node_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "node_control_unavailable"},
            )
        try:
            command = _external_node_command(
                http_request,
                expected_revision=expected_revision,
                expected_state=expected_state,
                allowed_states=frozenset({NodeState.RUNNING}),
            )
            return _node_response(
                node_control.change_port(
                    node_id,
                    new_port=request.new_port,
                    allowed_ports=(settings.node_registration_policy().allowed_external_ports()),
                    confirmation_token=request.confirmation_token,
                    confirmation_context=_external_disruption_context(
                        http_request,
                        settings,
                    ),
                    fence=None if command is None else command.fence,
                    mutation_context=(None if command is None else command.mutation_context),
                )
            )
        except NodeNotFound:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "node_not_found"},
            ) from None
        except NodeLifecycleBusy:
            raise _lifecycle_busy() from None
        except NodePortOutOfRange:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={"code": "node_port_out_of_range"},
            ) from None
        except NodePortInUse:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "node_port_in_use"},
            ) from None
        except NodeDisruptionConfirmationRequired:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "node_disruption_confirmation_required"},
            ) from None
        except NodeLifecycleConflict as error:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": str(error)},
            ) from None
        except NodeRuntimeUnavailable:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "node_runtime_unavailable"},
            ) from None
        except NodeRuntimeFailed as error:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": error.code, "node_id": str(error.node_id)},
            ) from None

    @app.delete(
        "/api/v1/nodes/{node_id}",
        status_code=status.HTTP_204_NO_CONTENT,
    )
    def delete_node(
        request: Request,
        node_id: UUID,
        expected_revision: int | None = NODE_REVISION_HEADER,
        expected_state: NodeState | None = NODE_STATE_HEADER,
    ) -> Response:
        if node_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "node_control_unavailable"},
            )
        try:
            command = _external_node_command(
                request,
                expected_revision=expected_revision,
                expected_state=expected_state,
                allowed_states=frozenset({NodeState.STOPPED, NodeState.FAILED}),
            )
            node_control.delete_node(
                node_id,
                fence=None if command is None else command.fence,
                mutation_context=(None if command is None else command.mutation_context),
            )
        except NodeNotFound:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "node_not_found"},
            ) from None
        except NodeLifecycleBusy:
            raise _lifecycle_busy() from None
        except NodeNotEmpty:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "node_not_empty"},
            ) from None
        except NodeLifecycleConflict as error:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": str(error)},
            ) from None
        except NodeRuntimeUnavailable:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "node_runtime_unavailable"},
            ) from None
        except NodeRuntimeFailed as error:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": error.code, "node_id": str(error.node_id)},
            ) from None
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.post("/api/v1/cameras", response_model=CameraResponse, status_code=201)
    def create_camera(request: CameraCreateRequest) -> CameraResponse:
        if camera_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "camera_control_unavailable"},
            )
        try:
            camera = camera_control.create_camera(
                name=request.name,
                source_url=request.source_url,
                node_id=request.node_id,
            )
        except NodeCameraCapacityReached:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "code": "node_camera_capacity_reached",
                    "message": "нода уже содержит 100 зарегистрированных камер",
                },
            ) from None
        except NodeNotFound:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "node_not_found"},
            ) from None
        except EligibleNodeMissing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "code": "eligible_node_missing",
                    "message": "нет доступной ноды для размещения камеры",
                },
            ) from None
        except MaximumNodesReached:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "code": "max_nodes_reached",
                    "message": "достигнуто максимальное количество нод",
                },
            ) from None
        except NodePortRangeExhausted:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "code": "node_ports_exhausted",
                    "message": "нет свободных портов для регистрации новой ноды",
                },
            ) from None
        except NodeManagementPortRangeExhausted:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "code": "node_management_ports_exhausted",
                    "message": "нет свободной пары loopback API/metrics портов",
                },
            ) from None
        except NodeRuntimeUnavailable:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "node_runtime_unavailable"},
            ) from None
        except NodeRuntimeFailed as error:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": error.code, "node_id": str(error.node_id)},
            ) from None
        except NodeLifecycleBusy:
            raise _lifecycle_busy() from None
        except (InvalidCameraName, InvalidCameraSource) as error:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={"code": str(error)},
            ) from None
        except CameraLifecycleConflict as error:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": str(error)},
            ) from None
        return _camera_response(camera)

    @app.put("/api/v1/cameras/{camera_id}", response_model=CameraResponse)
    def update_camera(camera_id: UUID, request: CameraUpdateRequest) -> CameraResponse:
        _require_camera_control(camera_control)
        if camera_mutation_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "camera_mutation_confirmation_unavailable"},
            )
        try:
            camera = camera_mutation_control.update(
                camera_id,
                name=request.name,
                source_url=request.source_url,
                expected_revision=request.expected_revision,
                confirmation_token=request.confirmation_token,
            )
        except CameraNotFound:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "camera_not_found"},
            ) from None
        except CameraRevisionConflict as error:
            raise _camera_revision_conflict(error) from None
        except CameraLifecycleConflict as error:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": str(error)},
            ) from None
        except (InvalidCameraName, InvalidCameraSource) as error:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={"code": str(error)},
            ) from None
        except CameraDisruptionConfirmationRequired:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "camera_disruption_confirmation_required"},
            ) from None
        return _camera_response(camera)

    def set_camera_enabled(
        camera_id: UUID,
        *,
        enabled: bool,
        expected_revision: int | None = None,
        confirmation_token: str | None = None,
    ) -> CameraResponse:
        control = _require_camera_control(camera_control)
        if not enabled and camera_mutation_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "camera_mutation_confirmation_unavailable"},
            )
        try:
            if enabled:
                camera = control.set_camera_enabled(
                    camera_id,
                    enabled=True,
                    expected_revision=expected_revision,
                )
            else:
                assert camera_mutation_control is not None
                camera = camera_mutation_control.disable(
                    camera_id,
                    expected_revision=expected_revision,
                    confirmation_token=confirmation_token,
                )
        except CameraNotFound:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "camera_not_found"},
            ) from None
        except CameraRevisionConflict as error:
            raise _camera_revision_conflict(error) from None
        except CameraLifecycleConflict as error:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": str(error)},
            ) from None
        except CameraDisruptionConfirmationRequired:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "camera_disruption_confirmation_required"},
            ) from None
        return _camera_response(camera)

    @app.post("/api/v1/cameras/{camera_id}/enable", response_model=CameraResponse)
    def enable_camera(
        camera_id: UUID,
        request: CameraDisruptionRequest | None = None,
    ) -> CameraResponse:
        return set_camera_enabled(
            camera_id,
            enabled=True,
            expected_revision=(None if request is None else request.expected_revision),
        )

    @app.post("/api/v1/cameras/{camera_id}/disable", response_model=CameraResponse)
    def disable_camera(
        camera_id: UUID,
        request: CameraDisruptionRequest | None = None,
    ) -> CameraResponse:
        return set_camera_enabled(
            camera_id,
            enabled=False,
            expected_revision=(None if request is None else request.expected_revision),
            confirmation_token=(None if request is None else request.confirmation_token),
        )

    @app.delete(
        "/api/v1/cameras/{camera_id}",
        response_model=CameraResponse,
        status_code=status.HTTP_202_ACCEPTED,
    )
    def delete_camera(
        camera_id: UUID,
        request: CameraDisruptionRequest | None = None,
    ) -> CameraResponse:
        _require_camera_control(camera_control)
        if camera_mutation_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "camera_mutation_confirmation_unavailable"},
            )
        try:
            return _camera_response(
                camera_mutation_control.delete(
                    camera_id,
                    expected_revision=(None if request is None else request.expected_revision),
                    confirmation_token=(None if request is None else request.confirmation_token),
                )
            )
        except CameraNotFound:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "camera_not_found"},
            ) from None
        except CameraRevisionConflict as error:
            raise _camera_revision_conflict(error) from None
        except CameraLifecycleConflict as error:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": str(error)},
            ) from None
        except CameraDisruptionConfirmationRequired:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "camera_disruption_confirmation_required"},
            ) from None

    @app.post(
        "/api/v1/cameras/{camera_id}/mutations/preview",
        response_model=CameraMutationPreviewResponse,
    )
    def preview_camera_mutation(
        camera_id: UUID,
        request: CameraMutationPreviewRequest,
    ) -> CameraMutationPreviewResponse:
        if camera_mutation_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "camera_mutation_confirmation_unavailable"},
            )
        if request.operation is CameraMutationOperation.UPDATE_SOURCE and (
            request.name is None or request.source_url is None
        ):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={"code": "camera_mutation_payload_required"},
            )
        try:
            preview = camera_mutation_control.preview(
                camera_id,
                operation=request.operation,
                expected_revision=request.expected_revision,
                name=request.name,
                source_url=request.source_url,
            )
        except CameraNotFound:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "camera_not_found"},
            ) from None
        except CameraReaderInvariantViolation:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "camera_reader_limit_violated"},
            ) from None
        except CameraRevisionConflict as error:
            raise _camera_revision_conflict(error) from None
        except (InvalidCameraName, InvalidCameraSource) as error:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={"code": str(error)},
            ) from None
        return CameraMutationPreviewResponse(
            camera_id=str(preview.camera_id),
            operation=preview.operation,
            desired_revision=preview.desired_revision,
            occupied=preview.occupied,
            disconnect_readers=preview.disconnect_readers,
            mutation_sha256=preview.mutation_sha256,
            confirmation_token=preview.confirmation_token,
        )

    @app.get(
        "/api/v1/cameras/{camera_id}/runtime",
        response_model=CameraRuntimeResponse,
    )
    def camera_runtime(camera_id: UUID) -> CameraRuntimeResponse:
        if camera_runtime_observer is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "camera_runtime_unavailable"},
            )
        try:
            observation = camera_runtime_observer.observe(camera_id)
        except CameraNotFound:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "camera_not_found"},
            ) from None
        return CameraRuntimeResponse(
            camera_id=str(observation.camera_id),
            node_id=str(observation.node_id),
            ready=observation.ready,
            reader_count=observation.reader_count,
            occupied=observation.occupied,
            reader_limit_violated=observation.reader_limit_violated,
        )

    @app.post(
        "/api/v1/cameras/{camera_id}/moves/preview",
        response_model=CameraMovePreviewResponse,
    )
    def preview_camera_move(
        camera_id: UUID,
        request: CameraMovePreviewRequest,
    ) -> CameraMovePreviewResponse:
        if camera_move_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "camera_move_unavailable"},
            )
        try:
            preview = camera_move_control.preview(
                camera_id,
                target_node_id=request.target_node_id,
            )
        except CameraNotFound:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "camera_not_found"},
            ) from None
        except NodeNotFound:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "node_not_found"},
            ) from None
        except (
            CameraLifecycleConflict,
            EligibleNodeMissing,
            NodeCameraCapacityReached,
        ) as error:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": str(error)},
            ) from None
        except CameraReaderInvariantViolation:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "camera_reader_limit_violated"},
            ) from None
        return CameraMovePreviewResponse(
            camera_id=str(preview.camera_id),
            source_node_id=str(preview.source_node_id),
            target_node_id=str(preview.target_node_id),
            desired_revision=preview.desired_revision,
            occupied=preview.occupied,
            disconnect_readers=preview.disconnect_readers,
            confirmation_token=preview.confirmation_token,
            source_port=preview.source_port,
            target_port=preview.target_port,
            source_endpoint=preview.source_endpoint,
            target_endpoint=preview.target_endpoint,
        )

    @app.post(
        "/api/v1/cameras/{camera_id}/moves",
        response_model=CameraMoveResponse,
        status_code=status.HTTP_202_ACCEPTED,
    )
    def request_camera_move(
        camera_id: UUID,
        request: CameraMoveRequest,
    ) -> CameraMoveResponse:
        if camera_move_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "camera_move_unavailable"},
            )
        try:
            move = camera_move_control.request_move(
                camera_id,
                target_node_id=request.target_node_id,
                force=request.force,
                confirmation_token=request.confirmation_token,
            )
        except CameraNotFound:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "camera_not_found"},
            ) from None
        except NodeNotFound:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "node_not_found"},
            ) from None
        except CameraOccupied:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "camera_occupied"},
            ) from None
        except CameraReaderInvariantViolation:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "camera_reader_limit_violated"},
            ) from None
        except MoveConfirmationRequired:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "move_confirmation_required"},
            ) from None
        except (CameraLifecycleConflict, EligibleNodeMissing, NodeCameraCapacityReached) as error:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": str(error)},
            ) from None
        return _camera_move_response(move)

    @app.get(
        "/api/v1/camera-moves/{move_id}",
        response_model=CameraMoveResponse,
    )
    def get_camera_move(move_id: UUID) -> CameraMoveResponse:
        if camera_move_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "camera_move_unavailable"},
            )
        move = camera_move_control.get_move(move_id)
        if move is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "camera_move_not_found"},
            )
        return _camera_move_response(move)

    @app.get("/api/v1/cameras", response_model=CameraListResponse)
    def list_cameras() -> CameraListResponse:
        if camera_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "camera_control_unavailable"},
            )
        items = [_camera_response(camera) for camera in camera_control.list_cameras()]
        return CameraListResponse(items=items, count=len(items))

    @app.get(
        "/api/v1/cameras/{camera_id}/access-policy",
        response_model=AccessPolicyResponse,
    )
    def get_access_policy(camera_id: UUID) -> AccessPolicyResponse:
        if access_policy_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "access_control_unavailable"},
            )
        try:
            return _access_policy_response(access_policy_control.get(camera_id))
        except LookupError:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "camera_not_found"},
            ) from None

    @app.put(
        "/api/v1/cameras/{camera_id}/access-policy",
        response_model=AccessPolicyResponse,
    )
    def update_access_policy(
        camera_id: UUID,
        payload: AccessPolicyUpdateRequest,
        request: Request,
    ) -> AccessPolicyResponse:
        if access_policy_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "access_control_unavailable"},
            )
        try:
            policy = access_policy_control.update(
                camera_id,
                internet_cidrs=payload.internet_cidrs,
                local_cidrs=payload.local_cidrs,
                expected_revision=payload.expected_revision,
                mutation_context=_access_operator_mutation_context(request),
            )
        except LookupError:
            _record_access_mutation_rejection_or_503(
                request,
                operator_sessions=operator_sessions,
                reason_code="camera_not_found",
                target_grant_id=None,
                expected_revision=payload.expected_revision,
                idempotency_key=None,
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "camera_not_found"},
            ) from None
        except CameraLifecycleConflict:
            _record_access_mutation_rejection_or_503(
                request,
                operator_sessions=operator_sessions,
                reason_code="access_policy_revision_conflict",
                target_grant_id=None,
                expected_revision=payload.expected_revision,
                idempotency_key=None,
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "access_policy_revision_conflict"},
            ) from None
        except ValueError as error:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={"code": str(error)},
            ) from None
        return _access_policy_response(policy)

    @app.get(
        "/api/v1/cameras/{camera_id}/access-grants",
        response_model=AccessGrantListResponse,
    )
    def list_access_grants(camera_id: UUID, request: Request) -> AccessGrantListResponse:
        if access_grant_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "access_control_unavailable"},
            )
        page = access_grant_control.list_for_camera(camera_id, limit=100)
        if operator_sessions is not None:
            principal = getattr(request.state, "operator_principal", None)
            audit_context = getattr(request.state, "operator_audit_context", None)
            if not isinstance(principal, OperatorPrincipal) or not isinstance(
                audit_context,
                OperatorRequestAuditContext,
            ):
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail={"code": "operator_session_unavailable"},
                    headers={"Retry-After": "1"},
                )
            try:
                operator_sessions.record_sensitive_read(
                    principal=principal,
                    audit_context=audit_context,
                )
            except OperatorSessionUnavailable:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail={"code": "operator_session_unavailable"},
                    headers={"Retry-After": "1"},
                ) from None
        items = [_access_grant_response(grant) for grant in page.items]
        return AccessGrantListResponse(
            items=items,
            count=len(items),
            truncated=page.truncated,
        )

    @app.post(
        "/api/v1/cameras/{camera_id}/access-grants",
        response_model=AccessGrantSecretResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def create_access_grant(
        camera_id: UUID,
        payload: AccessGrantCreateRequest,
        request: Request,
        response: Response,
        idempotency_key: UUID | None = IDEMPOTENCY_KEY_HEADER,
    ) -> AccessGrantSecretResponse:
        if access_grant_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "access_control_unavailable"},
            )
        try:
            mutation_context = _access_operator_mutation_context(
                request,
                require_recent_mfa=True,
                recent_mfa_seconds=settings.operator_recent_mfa_seconds,
                idempotency_key=idempotency_key,
                require_idempotency=True,
            )
            principal = getattr(request.state, "operator_principal", None)
            issued = access_grant_control.create(
                camera_id=camera_id,
                lifetime=timedelta(seconds=payload.lifetime_seconds),
                kind=payload.kind,
                created_by=(
                    f"operator:{principal.account_id}"
                    if isinstance(principal, OperatorPrincipal)
                    else "bootstrap-control-plane"
                ),
                mutation_context=mutation_context,
                idempotency_key=idempotency_key,
            )
        except CameraNotFound:
            _record_access_mutation_rejection_or_503(
                request,
                operator_sessions=operator_sessions,
                reason_code="camera_not_found",
                target_grant_id=None,
                expected_revision=None,
                idempotency_key=idempotency_key,
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "camera_not_found"},
            ) from None
        except AccessGrantIssueReplayed:
            _record_access_mutation_rejection_or_503(
                request,
                operator_sessions=operator_sessions,
                reason_code="access_grant_issue_replayed",
                target_grant_id=None,
                expected_revision=None,
                idempotency_key=idempotency_key,
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "access_grant_issue_replayed"},
            ) from None
        except AccessGrantIdempotencyConflict:
            _record_access_mutation_rejection_or_503(
                request,
                operator_sessions=operator_sessions,
                reason_code="access_grant_idempotency_conflict",
                target_grant_id=None,
                expected_revision=None,
                idempotency_key=idempotency_key,
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "access_grant_idempotency_conflict"},
            ) from None
        except AccessGrantSchemaUnavailable:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "access_grant_schema_unavailable"},
                headers={"Retry-After": "1"},
            ) from None
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["Location"] = (
            f"/api/v1/cameras/{camera_id}/access-grants/{issued.grant.id}"
        )
        return _issued_access_grant_response(issued)

    @app.post(
        "/api/v1/cameras/{camera_id}/access-grants/{grant_id}/rotate",
        response_model=AccessGrantSecretResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def rotate_access_grant(
        camera_id: UUID,
        grant_id: UUID,
        payload: AccessGrantRotateRequest,
        request: Request,
        response: Response,
        idempotency_key: UUID | None = IDEMPOTENCY_KEY_HEADER,
    ) -> AccessGrantSecretResponse:
        if access_grant_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "access_control_unavailable"},
            )
        try:
            mutation_context = _access_operator_mutation_context(
                request,
                require_recent_mfa=True,
                recent_mfa_seconds=settings.operator_recent_mfa_seconds,
                idempotency_key=idempotency_key,
                require_idempotency=True,
            )
            principal = getattr(request.state, "operator_principal", None)
            issued = access_grant_control.rotate(
                grant_id,
                camera_id=camera_id,
                overlap=timedelta(seconds=payload.overlap_seconds),
                lifetime=timedelta(seconds=payload.lifetime_seconds),
                expected_revision=payload.expected_revision,
                created_by=(
                    f"operator:{principal.account_id}"
                    if isinstance(principal, OperatorPrincipal)
                    else None
                ),
                mutation_context=mutation_context,
                idempotency_key=idempotency_key,
            )
        except LookupError:
            _record_access_mutation_rejection_or_503(
                request,
                operator_sessions=operator_sessions,
                reason_code="access_grant_not_found",
                target_grant_id=grant_id,
                expected_revision=payload.expected_revision,
                idempotency_key=idempotency_key,
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "access_grant_not_found"},
            ) from None
        except CameraLifecycleConflict:
            _record_access_mutation_rejection_or_503(
                request,
                operator_sessions=operator_sessions,
                reason_code="access_grant_revision_conflict",
                target_grant_id=grant_id,
                expected_revision=payload.expected_revision,
                idempotency_key=idempotency_key,
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "access_grant_revision_conflict"},
            ) from None
        except AccessGrantIssueReplayed:
            _record_access_mutation_rejection_or_503(
                request,
                operator_sessions=operator_sessions,
                reason_code="access_grant_issue_replayed",
                target_grant_id=grant_id,
                expected_revision=payload.expected_revision,
                idempotency_key=idempotency_key,
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "access_grant_issue_replayed"},
            ) from None
        except AccessGrantIdempotencyConflict:
            _record_access_mutation_rejection_or_503(
                request,
                operator_sessions=operator_sessions,
                reason_code="access_grant_idempotency_conflict",
                target_grant_id=grant_id,
                expected_revision=payload.expected_revision,
                idempotency_key=idempotency_key,
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "access_grant_idempotency_conflict"},
            ) from None
        except AccessGrantSchemaUnavailable:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "access_grant_schema_unavailable"},
                headers={"Retry-After": "1"},
            ) from None
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["Location"] = (
            f"/api/v1/cameras/{camera_id}/access-grants/{issued.grant.id}"
        )
        return _issued_access_grant_response(issued)

    @app.delete(
        "/api/v1/cameras/{camera_id}/access-grants/{grant_id}",
        response_model=AccessGrantResponse,
    )
    def revoke_access_grant(
        camera_id: UUID,
        grant_id: UUID,
        request: Request,
        expected_revision: int,
    ) -> AccessGrantResponse:
        if access_grant_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "access_control_unavailable"},
            )
        try:
            grant = access_grant_control.revoke(
                grant_id,
                camera_id=camera_id,
                expected_revision=expected_revision,
                mutation_context=_access_operator_mutation_context(
                    request,
                    require_recent_mfa=True,
                    recent_mfa_seconds=settings.operator_recent_mfa_seconds,
                ),
            )
        except LookupError:
            _record_access_mutation_rejection_or_503(
                request,
                operator_sessions=operator_sessions,
                reason_code="access_grant_not_found",
                target_grant_id=grant_id,
                expected_revision=expected_revision,
                idempotency_key=None,
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "access_grant_not_found"},
            ) from None
        except CameraLifecycleConflict:
            _record_access_mutation_rejection_or_503(
                request,
                operator_sessions=operator_sessions,
                reason_code="access_grant_revision_conflict",
                target_grant_id=grant_id,
                expected_revision=expected_revision,
                idempotency_key=None,
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "access_grant_revision_conflict"},
            ) from None
        return _access_grant_response(grant)

    return app


def create_media_auth_app(
    *,
    authorizer: AccessAuthorizer,
    readiness: Callable[[], None] | None = None,
    shutdown: Callable[[], None] | None = None,
    callback_verifier: PepperVerifier | None = None,
    telemetry: AccessDecisionTelemetry | None = None,
    body_timeout_seconds: float = 1,
    max_inflight: int = 128,
    rate_per_second: int = 1000,
    burst: int = 2000,
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            if shutdown is not None:
                shutdown()

    app = FastAPI(
        title="RTSP Proxy Media Authorization",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    if body_timeout_seconds <= 0 or body_timeout_seconds > 5:
        raise ValueError("media_auth_body_timeout_invalid")
    admission = _MediaAuthAdmissionGate(
        max_inflight=max_inflight,
        rate_per_second=rate_per_second,
        burst=burst,
    )

    app.add_middleware(
        _MediaAuthAdmissionMiddleware,
        callback_verifier=callback_verifier,
        body_timeout_seconds=body_timeout_seconds,
        admission=admission,
    )

    @app.exception_handler(RequestValidationError)
    async def media_auth_validation_denied(
        _request: Request,
        _error: RequestValidationError,
    ) -> Response:
        return _media_auth_denied()

    @app.get("/health/live", include_in_schema=False)
    def live() -> dict[str, str]:
        return {"status": "ok", "role": "auth"}

    @app.get("/health/ready", include_in_schema=False)
    def ready(response: Response) -> dict[str, object]:
        try:
            if readiness is None:
                raise RuntimeError("auth_readiness_provider_missing")
            readiness()
        except Exception:
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            return {
                "status": "not_ready",
                "role": "auth",
                "checks": [
                    {"name": "database_schema", "status": "fail"},
                    {"name": "pepper", "status": "pass"},
                ],
            }
        return {
            "status": "ready",
            "role": "auth",
            "checks": [
                {"name": "database_schema", "status": "pass"},
                {"name": "pepper", "status": "pass"},
            ],
        }

    @app.get("/internal/v1/metrics", include_in_schema=False)
    def internal_metrics() -> PlainTextResponse:
        if telemetry is None:
            return PlainTextResponse(
                "rtsp_proxy_access_telemetry_available 0\n",
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        snapshot = telemetry.snapshot()
        lines = ["rtsp_proxy_access_telemetry_available 1"]
        for (reason, allowed, action, protocol, peer_family), count in sorted(
            snapshot.counters.items()
        ):
            labels = (
                f'reason="{reason}",allowed="{str(allowed).lower()}",'
                f'action="{action}",protocol="{protocol}",'
                f'peer_family="{peer_family}"'
            )
            lines.append(f"rtsp_proxy_access_decisions_total{{{labels}}} {count}")
        lines.extend(
            (
                f"rtsp_proxy_access_audit_events_dropped_total {snapshot.dropped_audit}",
                "rtsp_proxy_access_last_use_persistence_failures_total "
                f"{snapshot.last_use_persistence_failures}",
            )
        )
        return PlainTextResponse("\n".join(lines) + "\n")

    @app.post(
        "/internal/v1/media-auth/{node_id}",
        status_code=status.HTTP_204_NO_CONTENT,
        include_in_schema=False,
    )
    def authorize_media(
        node_id: UUID,
        request: MediaAuthRequest,
        http_request: Request,
    ) -> Response:
        if callback_verifier is None or not callback_verifier.verify_callback_authorization(
            node_id,
            http_request.headers.get("authorization"),
        ):
            return _media_auth_denied()
        try:
            public_id = PublicId.parse(request.path)
            decision = authorizer.authorize(
                AuthorizeRequest(
                    node_id=node_id,
                    public_id=public_id,
                    peer_ip=request.ip,
                    username=request.user,
                    password=request.password,
                    action=request.action,
                    protocol=request.protocol,
                )
            )
        except ValueError:
            return _media_auth_denied()
        if not decision.allowed:
            assert decision.reason is not AccessDecisionReason.ALLOWED
            return _media_auth_denied()
        return Response(
            status_code=status.HTTP_204_NO_CONTENT,
            headers={"Cache-Control": "no-store"},
        )

    return app


def _node_response(node: object) -> NodeResponse:
    from rtsp_proxy.nodes import MediaNode

    if not isinstance(node, MediaNode):
        raise TypeError("media_node_required")
    return NodeResponse(
        id=str(node.id),
        name=node.name,
        external_port=node.external_port,
        state=node.state.value,
        runtime_state=node.runtime_state.value,
        health=node.health.value,
        registered_cameras=node.registered_cameras,
        camera_capacity=node.camera_capacity,
        desired_revision=node.desired_revision,
        applied_revision=node.applied_revision,
    )


def _retryable_service_response(code: str) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"detail": {"code": code}},
        headers={"Retry-After": "1"},
    )


def _operator_permission_for_request(request: Request) -> OperatorPermission:
    path = request.url.path
    if path == "/dashboard/cameras" or path.startswith("/dashboard/cameras/"):
        if "/access-grants" in path:
            if path.endswith("/revoke"):
                return OperatorPermission.ACCESS_ADMIN
            return (
                OperatorPermission.ACCESS_ADMIN
                if request.method in {"GET", "HEAD", "OPTIONS"}
                else OperatorPermission.SECRET_ISSUE
            )
        if path.endswith("/access-policy") or path.endswith("/access"):
            return OperatorPermission.ACCESS_ADMIN
        if path.endswith(("/edit", "/move")):
            return OperatorPermission.CONTROL_MUTATE
        return (
            OperatorPermission.CONTROL_READ
            if request.method in {"GET", "HEAD", "OPTIONS"}
            else OperatorPermission.CONTROL_MUTATE
        )
    if path == "/dashboard/nodes/new":
        return OperatorPermission.CONTROL_MUTATE
    if path == "/dashboard/nodes" or path.startswith("/dashboard/nodes/"):
        return (
            OperatorPermission.DASHBOARD_READ
            if request.method in {"GET", "HEAD", "OPTIONS"}
            else OperatorPermission.CONTROL_MUTATE
        )
    if path.startswith("/dashboard") or path in {
        "/api/v1/operator/session",
        "/api/v1/dashboard/snapshot",
    }:
        return OperatorPermission.DASHBOARD_READ
    if path.endswith("/access-policy"):
        return (
            OperatorPermission.CONTROL_READ
            if request.method in {"GET", "HEAD", "OPTIONS"}
            else OperatorPermission.ACCESS_ADMIN
        )
    if "/access-grants" in path:
        return (
            OperatorPermission.SECRET_ISSUE
            if request.method == "POST"
            else OperatorPermission.ACCESS_ADMIN
        )
    if path.startswith("/api/v1/operators"):
        return OperatorPermission.OPERATOR_ADMIN
    if path.startswith("/api/v1/audit"):
        return OperatorPermission.AUDIT_READ
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return OperatorPermission.CONTROL_READ
    return OperatorPermission.CONTROL_MUTATE


def _operator_request_audit_context(
    request: Request,
    *,
    required_scope: str | None,
) -> OperatorRequestAuditContext:
    action, resource_type, resource_id = _operator_audit_target(request)
    return OperatorRequestAuditContext.capture(
        request_id=uuid4(),
        action=action,
        http_method=_operator_audit_http_method(request.method),
        resource_scope="session:self" if required_scope is None else required_scope,
        source_ip=_request_source_ip(request),
        user_agent=_request_user_agent(request),
        resource_type=resource_type,
        resource_id=resource_id,
    )


def _operator_login_request_audit_context(request: Request) -> OperatorRequestAuditContext:
    return OperatorRequestAuditContext.capture(
        request_id=uuid4(),
        action="operator.login",
        http_method=_operator_audit_http_method(request.method),
        resource_scope="server:*",
        source_ip=_request_source_ip(request),
        user_agent=_request_user_agent(request),
        resource_type="session",
        resource_id="self",
    )


def _operator_scope_for_request(request: Request) -> str | None:
    if request.url.path in {
        "/api/v1/operator/session",
        "/dashboard/logout",
    }:
        return None
    for camera_resource_prefix in ("/dashboard/cameras/", "/api/v1/cameras/"):
        if request.url.path.startswith(camera_resource_prefix):
            resource = request.url.path.removeprefix(camera_resource_prefix)
            camera_resource = resource.partition("/")[0]
            if camera_resource:
                try:
                    camera_id = UUID(camera_resource)
                except ValueError:
                    pass
                else:
                    return f"camera:{camera_id}"
    return "server:*"


def _operator_action_bucket(action: str) -> OperatorActionBucket | None:
    if action in {"camera.grant_issue", "camera.grant_rotate"}:
        return OperatorActionBucket.SECRET_ISSUE
    if action in {"camera.access_policy_update", "camera.grant_revoke"}:
        return OperatorActionBucket.ACCESS_MUTATION
    return None


def _operator_audit_http_method(method: str) -> str:
    normalized = method.upper()
    if normalized in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}:
        return normalized
    return "OTHER"


def _operator_audit_target(request: Request) -> tuple[str, str, str]:
    path = request.url.path
    method = _operator_audit_http_method(request.method)
    if method == "OTHER":
        return "request.unsupported", "server", "server"
    if path in {"/api/v1/operator/session", "/dashboard/logout"}:
        action = (
            "operator.session_logout" if method in {"POST", "DELETE"} else "operator.session_read"
        )
        return action, "session", "self"
    if path in {"/dashboard", "/api/v1/dashboard/snapshot"}:
        return "dashboard.read", "dashboard", "server"
    if path == "/dashboard/nodes/new" or path == "/dashboard/nodes":
        return "node.create", "node", "collection"
    if path.startswith("/dashboard/nodes/"):
        node_id = _bounded_path_identifier(path, 2)
        suffix = "/".join(path.strip("/").split("/")[3:])
        action = {
            "": "node.read",
            "registered": "node.read",
            "start": "node.start",
            "stop": "node.stop",
            "restart": "node.restart",
            "drain": "node.drain",
            "maintenance": "node.maintenance",
            "resume": "node.resume",
            "delete": "node.delete",
            "reconfigure/preview": "node.reconfigure_preview",
            "reconfigure": "node.reconfigure",
            "release": "node.release_update",
            "port-change/preview": "node.port_change_preview",
            "port-change": "node.port_change",
        }.get(suffix, "request.unsupported")
        return action, "node", node_id
    if path == "/api/v1/nodes":
        return (
            ("node.create" if method == "POST" else "node.list"),
            "node",
            "collection",
        )
    if path.startswith("/api/v1/nodes/"):
        node_id = _bounded_path_identifier(path, 3)
        suffix = "/".join(path.strip("/").split("/")[4:])
        action = {
            "start": "node.start",
            "stop": "node.stop",
            "restart": "node.restart",
            "reconfigure/preview": "node.reconfigure_preview",
            "reconfigure": "node.reconfigure",
            "observe": "node.observe",
            "release": "node.release_update",
            "drain": "node.drain",
            "maintenance": "node.maintenance",
            "resume": "node.resume",
            "port-change/preview": "node.port_change_preview",
            "port-change": "node.port_change",
            "": "node.delete" if method == "DELETE" else "node.read",
        }.get(suffix, "request.unsupported")
        return action, "node", node_id
    if path == "/api/v1/cameras" or path == "/dashboard/cameras":
        return (
            ("camera.create" if method == "POST" else "camera.list"),
            "camera",
            "collection",
        )
    if path.startswith("/api/v1/camera-moves/"):
        return "camera.move_read", "camera_move", _bounded_path_identifier(path, 3)
    camera_prefix = next(
        (
            prefix
            for prefix in ("/api/v1/cameras/", "/dashboard/cameras/")
            if path.startswith(prefix)
        ),
        None,
    )
    if camera_prefix is not None:
        remainder = path.removeprefix(camera_prefix)
        camera_id, _, suffix = remainder.partition("/")
        resource_id = _canonical_audit_identifier(camera_id)
        if camera_prefix.startswith("/dashboard"):
            if suffix.startswith("moves/") and suffix not in {
                "moves/preview",
                "moves/apply",
            }:
                return (
                    "camera.move_read",
                    "camera_move",
                    _canonical_audit_identifier(suffix.removeprefix("moves/")),
                )
            action = {
                "": "camera.read",
                "edit": "camera.update",
                "move": "camera.move",
                "moves/preview": "camera.move_preview",
                "moves/apply": "camera.move",
                "mutations/preview": "camera.mutation_preview",
                "mutations/apply": "camera.update",
                "enable": "camera.enable",
                "disable": "camera.disable",
                "access": "camera.access_read",
                "access-policy": "camera.access_policy_update",
            }.get(suffix, "request.unsupported")
            if suffix == "access-grants":
                action = "camera.grant_list" if method == "GET" else "camera.grant_issue"
            elif suffix.startswith("access-grants/"):
                action = (
                    "camera.grant_revoke"
                    if suffix.endswith("/revoke")
                    else "camera.grant_rotate"
                )
        else:
            action = {
                "": "camera.delete" if method == "DELETE" else "camera.update",
                "enable": "camera.enable",
                "disable": "camera.disable",
                "mutations/preview": "camera.mutation_preview",
                "runtime": "camera.runtime_read",
                "moves/preview": "camera.move_preview",
                "moves": "camera.move",
                "access-policy": (
                    "camera.access_policy_update"
                    if method == "PUT"
                    else "camera.access_policy_read"
                ),
                "access-grants": "camera.grant_issue",
            }.get(suffix, "request.unsupported")
            if suffix == "access-grants" and method == "GET":
                action = "camera.grant_list"
            elif suffix.startswith("access-grants/"):
                action = (
                    "camera.grant_rotate"
                    if suffix.endswith("/rotate")
                    else "camera.grant_revoke"
                )
        return action, "camera", resource_id
    if path.startswith("/api/v1/operators"):
        return "operator.admin", "operator_account", _bounded_path_identifier(path, 3)
    if path.startswith("/api/v1/audit"):
        return "audit.read", "audit", "collection"
    return "request.unsupported", "server", "server"


def _bounded_path_identifier(path: str, index: int) -> str:
    parts = path.strip("/").split("/")
    if index >= len(parts):
        return "invalid"
    return _canonical_audit_identifier(parts[index])


def _canonical_audit_identifier(value: str) -> str:
    try:
        return str(UUID(value))
    except ValueError:
        return "invalid"


def _operator_protected_path(path: str) -> bool:
    return path.startswith("/api/v1/") or path == "/dashboard" or path.startswith("/dashboard/")


def _dashboard_principal(
    request: Request,
    operator_sessions: OperatorSessionControl | None,
) -> OperatorPrincipal | Response:
    if operator_sessions is None:
        return _dashboard_unavailable_response(
            DashboardUnavailable(
                title="Сессии операторов не настроены",
                message="Дашборд закрыт до подключения авторизации операторов.",
            ),
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return _operator_principal(request)


def _dashboard_snapshot_or_response(
    *,
    fleet_snapshots: SnapshotReader | None,
    max_age_seconds: float,
    now: datetime,
    principal: OperatorPrincipal,
) -> FleetSnapshot | Response:
    try:
        return require_fresh_snapshot(
            fleet_snapshots,
            now=now,
            max_age_seconds=max_age_seconds,
        )
    except FleetSnapshotReadFailure as error:
        unavailable = _dashboard_snapshot_failure(error.reason)
        return _dashboard_unavailable_response(
            unavailable,
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            principal=principal,
        )


def _dashboard_snapshot_failure(reason: FleetSnapshotFailureReason) -> DashboardUnavailable:
    if reason is FleetSnapshotFailureReason.PENDING:
        return DashboardUnavailable(
            title="Снимок состояния ещё не сформирован",
            message=(
                "Коллектор ещё не завершил первый цикл. Повторите попытку через несколько секунд."
            ),
        )
    if reason is FleetSnapshotFailureReason.STALE:
        return DashboardUnavailable(
            title="Снимок состояния устарел",
            message="Данные не показаны, потому что их свежесть нельзя подтвердить.",
        )
    return DashboardUnavailable(
        title="Наблюдение недоступно",
        message="Хранилище снимков состояния сейчас недоступно.",
    )


def _dashboard_html_response(
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


def _dashboard_unavailable_response(
    unavailable: DashboardUnavailable,
    *,
    status_code: int,
    principal: OperatorPrincipal | None = None,
) -> HTMLResponse:
    return _dashboard_html_response(
        render_unavailable(unavailable, principal=principal),
        status_code=status_code,
        retry_after="5" if status_code == status.HTTP_503_SERVICE_UNAVAILABLE else None,
    )


def _operator_error_response(status_code: int, code: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"detail": {"code": code}},
        headers={"Cache-Control": "no-store"},
    )


def _operator_authentication_required_response(
    request: Request,
    *,
    oidc_enabled: bool,
) -> Response:
    if request.url.path.startswith("/dashboard"):
        return _dashboard_unavailable_response(
            DashboardUnavailable(
                title="Требуется вход оператора",
                message="Откройте защищённую сессию, чтобы увидеть состояние сервера.",
                login_href="/auth/oidc/login" if oidc_enabled else None,
            ),
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
    return _operator_error_response(
        status.HTTP_401_UNAUTHORIZED,
        "operator_authentication_required",
    )


def _operator_session_unavailable_response(request: Request) -> Response:
    if request.url.path.startswith("/dashboard"):
        return _dashboard_unavailable_response(
            DashboardUnavailable(
                title="Сессия временно недоступна",
                message="Проверить операторскую сессию сейчас невозможно.",
            ),
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"detail": {"code": "operator_session_unavailable"}},
        headers={"Cache-Control": "no-store", "Retry-After": "1"},
    )


def _operator_login_unavailable() -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"detail": {"code": "operator_login_unavailable"}},
        headers={"Cache-Control": "no-store", "Retry-After": "1"},
    )


def _operator_rate_limited(retry_after_seconds: int) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={"detail": {"code": "operator_login_rate_limited"}},
        headers={
            "Cache-Control": "no-store",
            "Retry-After": str(retry_after_seconds),
        },
    )


def _operator_action_rate_limited(retry_after_seconds: int) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={"detail": {"code": "operator_action_rate_limited"}},
        headers={
            "Cache-Control": "no-store",
            "Retry-After": str(retry_after_seconds),
        },
    )


def _request_source_ip(request: Request) -> str:
    return "unknown" if request.client is None else request.client.host


def _request_user_agent(request: Request) -> str:
    value = request.headers.get("user-agent", "")
    return value if len(value) <= 4096 else "<oversized>"


def _set_operator_session_cookies(
    response: Response,
    issued: IssuedOperatorSession,
) -> None:
    response.set_cookie(
        "__Host-rtsp_proxy_session",
        issued.session_token,
        secure=True,
        httponly=True,
        samesite="strict",
        path="/",
    )
    response.set_cookie(
        "__Host-rtsp_proxy_csrf",
        issued.csrf_token,
        secure=True,
        httponly=False,
        samesite="strict",
        path="/",
    )


def _clear_operator_session_cookies(response: Response) -> None:
    response.delete_cookie(
        "__Host-rtsp_proxy_session",
        path="/",
        secure=True,
        httponly=True,
        samesite="strict",
    )
    response.delete_cookie(
        "__Host-rtsp_proxy_csrf",
        path="/",
        secure=True,
        httponly=False,
        samesite="strict",
    )


def _clear_oidc_flow_cookie(response: Response) -> None:
    response.delete_cookie(
        "__Secure-rtsp_proxy_oidc_flow",
        secure=True,
        httponly=True,
        samesite="lax",
        path="/auth/oidc/callback",
    )


def _operator_principal(request: Request) -> OperatorPrincipal:
    principal = getattr(request.state, "operator_principal", None)
    if not isinstance(principal, OperatorPrincipal):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "operator_authentication_required"},
        )
    return principal


def _external_node_mutation_context(
    request: Request,
    *,
    idempotency_key: UUID | None,
) -> NodeMutationContext | None:
    principal = getattr(request.state, "operator_principal", None)
    if not isinstance(principal, OperatorPrincipal):
        return None
    audit_context = getattr(request.state, "operator_audit_context", None)
    if not isinstance(audit_context, OperatorRequestAuditContext):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "operator_audit_context_unavailable"},
        )
    if idempotency_key is None or idempotency_key.version != 4:
        raise HTTPException(
            status_code=status.HTTP_428_PRECONDITION_REQUIRED,
            detail={"code": "node_idempotency_key_required"},
        )
    return node_mutation_context(
        principal=principal,
        audit_context=audit_context,
        idempotency_key=idempotency_key,
    )


def _access_operator_mutation_context(
    request: Request,
    *,
    require_recent_mfa: bool = False,
    recent_mfa_seconds: int = 300,
    idempotency_key: UUID | None = None,
    require_idempotency: bool = False,
) -> NodeMutationContext | None:
    principal = getattr(request.state, "operator_principal", None)
    if not isinstance(principal, OperatorPrincipal):
        return None
    if require_recent_mfa and not principal.has_recent_mfa(
        max_age_seconds=recent_mfa_seconds
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "operator_recent_mfa_required"},
        )
    if require_idempotency and (
        idempotency_key is None or idempotency_key.version != 4
    ):
        raise HTTPException(
            status_code=status.HTTP_428_PRECONDITION_REQUIRED,
            detail={"code": "access_grant_idempotency_key_required"},
        )
    audit_context = getattr(request.state, "operator_audit_context", None)
    if not isinstance(audit_context, OperatorRequestAuditContext):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "operator_audit_context_unavailable"},
        )
    return node_mutation_context(
        principal=principal,
        audit_context=audit_context,
        idempotency_key=idempotency_key,
    )


def _record_access_mutation_rejection_or_503(
    request: Request,
    *,
    operator_sessions: OperatorSessionControl | None,
    reason_code: str,
    target_grant_id: UUID | None,
    expected_revision: int | None,
    idempotency_key: UUID | None,
) -> None:
    if operator_sessions is None:
        return
    principal = getattr(request.state, "operator_principal", None)
    audit_context = getattr(request.state, "operator_audit_context", None)
    if not isinstance(principal, OperatorPrincipal) or not isinstance(
        audit_context,
        OperatorRequestAuditContext,
    ):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "operator_session_unavailable"},
            headers={"Retry-After": "1"},
        )
    try:
        operator_sessions.record_mutation_rejection(
            principal=principal,
            reason_code=reason_code,
            audit_context=audit_context,
            target_grant_id=target_grant_id,
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
        )
    except OperatorSessionUnavailable:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "operator_session_unavailable"},
            headers={"Retry-After": "1"},
        ) from None


def _external_node_command(
    request: Request,
    *,
    expected_revision: int | None,
    expected_state: NodeState | None,
    allowed_states: frozenset[NodeState],
) -> OperatorNodeCommand | None:
    principal = getattr(request.state, "operator_principal", None)
    if not isinstance(principal, OperatorPrincipal):
        return None
    audit_context = getattr(request.state, "operator_audit_context", None)
    if not isinstance(audit_context, OperatorRequestAuditContext):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "operator_audit_context_unavailable"},
        )
    if expected_revision is None or expected_state is None:
        raise HTTPException(
            status_code=status.HTTP_428_PRECONDITION_REQUIRED,
            detail={"code": "node_command_precondition_required"},
        )
    try:
        return operator_node_command(
            principal=principal,
            audit_context=audit_context,
            expected_revision=expected_revision,
            expected_state=expected_state,
            allowed_states=allowed_states,
        )
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "node_command_source_state_invalid"},
        ) from None


def _external_disruption_context(
    request: Request,
    settings: Settings,
) -> NodeDisruptionConfirmationContext | None:
    principal = getattr(request.state, "operator_principal", None)
    if not isinstance(principal, OperatorPrincipal):
        return None
    try:
        return node_disruption_confirmation_context(
            principal=principal,
            max_age_seconds=settings.operator_recent_mfa_seconds,
        )
    except OperatorRecentMfaRequired:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "operator_recent_mfa_required"},
        ) from None


def _camera_response(camera: object) -> CameraResponse:
    from rtsp_proxy.nodes import CameraPlacement, CameraState

    if not isinstance(camera, CameraPlacement):
        raise TypeError("camera_placement_required")
    return CameraResponse(
        id=str(camera.id),
        name=camera.name,
        public_id=str(camera.public_id),
        node_id=str(camera.node_id),
        node_port=camera.node_port,
        placement_mode=camera.placement_mode.value,
        state=camera.state.value,
        registered=camera.state is not CameraState.DELETED,
        desired_revision=camera.desired_revision,
        applied_revision=camera.applied_revision,
    )


def _require_camera_control(camera_control: CameraControl | None) -> CameraControl:
    if camera_control is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "camera_control_unavailable"},
        )
    return camera_control


def _camera_move_response(move: CameraMove) -> CameraMoveResponse:
    return CameraMoveResponse(
        id=str(move.id),
        camera_id=str(move.camera_id),
        source_node_id=str(move.source_node_id),
        target_node_id=str(move.target_node_id),
        source_generation=move.source_generation,
        target_generation=move.target_generation,
        desired_revision=move.desired_revision,
        force=move.force,
        confirmed_disconnect_readers=move.confirmed_disconnect_readers,
        source_port=move.source_port,
        target_port=move.target_port,
        source_endpoint=move.source_endpoint,
        target_endpoint=move.target_endpoint,
        expires_at=move.expires_at,
        abort_reason=move.abort_reason,
        state=move.state.value,
    )


def _access_policy_response(policy: AccessPolicy) -> AccessPolicyResponse:
    return AccessPolicyResponse(
        camera_id=str(policy.camera_id),
        internet_cidrs=list(policy.internet_cidrs),
        local_cidrs=list(policy.local_cidrs),
        revision=policy.revision,
    )


def _issued_access_grant_response(issued: IssuedAccessGrant) -> AccessGrantSecretResponse:
    return AccessGrantSecretResponse(
        id=str(issued.grant.id),
        camera_id=str(issued.grant.camera_id),
        username=issued.grant.username,
        password=issued.secret,
        not_before=issued.grant.not_before,
        expires_at=issued.grant.expires_at,
        revision=issued.grant.revision,
        kind=issued.grant.kind,
        created_by=issued.grant.created_by,
        last_used_at=issued.grant.last_used_at,
    )


def _access_grant_response(
    grant: AccessGrant | AccessGrantSummary,
) -> AccessGrantResponse:
    return AccessGrantResponse(
        id=str(grant.id),
        camera_id=str(grant.camera_id),
        username=grant.username,
        not_before=grant.not_before,
        expires_at=grant.expires_at,
        revoked_at=grant.revoked_at,
        revision=grant.revision,
        kind=grant.kind,
        created_by=grant.created_by,
        last_used_at=grant.last_used_at,
    )
