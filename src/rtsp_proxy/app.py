from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from threading import BoundedSemaphore, Lock
from time import monotonic
from typing import Literal
from uuid import UUID

import anyio
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from rtsp_proxy.access import (
    AccessAuthorizer,
    AccessDecisionReason,
    AccessDecisionTelemetry,
    AccessGrantControl,
    AccessPolicy,
    AccessPolicyControl,
    AuthorizeRequest,
    IssuedAccessGrant,
    PepperVerifier,
)
from rtsp_proxy.config import Settings
from rtsp_proxy.health import (
    MissingReadinessProvider,
    ReadinessProvider,
    normalize_readiness_results,
)
from rtsp_proxy.identifiers import PublicId
from rtsp_proxy.media import MediaNodeError
from rtsp_proxy.nodes import (
    CameraControl,
    CameraLifecycleConflict,
    CameraMove,
    CameraNotFound,
    EligibleNodeMissing,
    InvalidCameraSource,
    MaximumNodesReached,
    NodeCameraCapacityReached,
    NodeControl,
    NodeDisruptionConfirmationRequired,
    NodeLifecycleBusy,
    NodeLifecycleConflict,
    NodeManagementPortRangeExhausted,
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


def _lifecycle_busy() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail={"code": "node_lifecycle_busy"},
        headers={"Retry-After": "1"},
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
    confirmation_token: str


class NodeReconfigureRequest(BaseModel):
    confirmation_token: str | None = Field(default=None, max_length=4096)


class NodeReconfigurePreviewResponse(BaseModel):
    node_id: str
    external_port: int
    desired_revision: int
    registered_cameras: int
    blast_radius_sha256: str
    target_release_id: str
    target_mediamtx_binary_sha256: str
    confirmation_token: str


class NodeListResponse(BaseModel):
    items: list[NodeResponse]
    count: int
    max_nodes: int


class CameraCreateRequest(BaseModel):
    name: str
    source_url: str
    node_id: UUID | None = None


class CameraUpdateRequest(BaseModel):
    name: str
    source_url: str
    confirmation_token: str | None = Field(default=None, max_length=4096)


class CameraDisruptionRequest(BaseModel):
    confirmation_token: str | None = Field(default=None, max_length=4096)


class CameraMutationPreviewRequest(BaseModel):
    operation: CameraMutationOperation
    name: str | None = None
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

    @app.exception_handler(NodeLifecycleBusy)
    async def node_lifecycle_busy_handler(
        _request: Request,
        _error: NodeLifecycleBusy,
    ) -> JSONResponse:
        return _retryable_service_response("node_lifecycle_busy")

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

    @app.post("/api/v1/nodes", response_model=NodeResponse, status_code=201)
    def create_node(request: NodeCreateRequest, response: Response) -> NodeResponse:
        if node_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "node_control_unavailable"},
            )
        try:
            node = node_control.register_node(
                name=request.name,
                port_range_start=settings.node_port_range_start,
                port_range_end=settings.node_port_range_end,
                max_nodes=settings.max_nodes,
                external_port=request.external_port,
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
    def start_node(node_id: UUID) -> NodeResponse:
        if node_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "node_control_unavailable"},
            )
        try:
            node = node_control.start_node(node_id)
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
    def stop_node(node_id: UUID) -> NodeResponse:
        if node_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "node_control_unavailable"},
            )
        try:
            node = node_control.stop_node(node_id)
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
    def restart_node(node_id: UUID) -> NodeResponse:
        if node_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "node_control_unavailable"},
            )
        try:
            node = node_control.restart_node(node_id)
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
    def preview_node_reconfigure(node_id: UUID) -> NodeReconfigurePreviewResponse:
        if node_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "node_control_unavailable"},
            )
        try:
            preview = node_control.preview_reconfigure(node_id)
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
            target_release_id=preview.target_release_id,
            target_mediamtx_binary_sha256=(
                preview.target_mediamtx_binary_sha256
            ),
            confirmation_token=preview.confirmation_token,
        )

    @app.post("/api/v1/nodes/{node_id}/reconfigure", response_model=NodeResponse)
    def reconfigure_node(
        node_id: UUID,
        request: NodeReconfigureRequest,
    ) -> NodeResponse:
        if node_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "node_control_unavailable"},
            )
        try:
            node = node_control.reconfigure_node(
                node_id,
                confirmation_token=request.confirmation_token,
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
        node_id: UUID,
        request: NodeReleaseRequest,
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
            node = node_control.update_node_release(
                node_id,
                release_id=request.release_id,
                mediamtx_binary_sha256=request.mediamtx_binary_sha256,
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
        node_id: UUID,
        state: NodeState,
    ) -> NodeResponse:
        if node_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "node_control_unavailable"},
            )
        try:
            return _node_response(node_control.set_administrative_state(node_id, state))
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
    def drain_node(node_id: UUID) -> NodeResponse:
        return set_node_administrative_state(node_id, NodeState.DRAINING)

    @app.post("/api/v1/nodes/{node_id}/maintenance", response_model=NodeResponse)
    def maintain_node(node_id: UUID) -> NodeResponse:
        return set_node_administrative_state(node_id, NodeState.MAINTENANCE)

    @app.post("/api/v1/nodes/{node_id}/resume", response_model=NodeResponse)
    def resume_node(node_id: UUID) -> NodeResponse:
        return set_node_administrative_state(node_id, NodeState.RUNNING)

    @app.post(
        "/api/v1/nodes/{node_id}/port-change/preview",
        response_model=NodePortChangePreviewResponse,
    )
    def preview_node_port_change(
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
                allowed_ports=_allowed_node_ports(settings),
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
            confirmation_token=preview.confirmation_token,
        )

    @app.post(
        "/api/v1/nodes/{node_id}/port-change",
        response_model=NodeResponse,
    )
    def change_node_port(
        node_id: UUID,
        request: NodePortChangeRequest,
    ) -> NodeResponse:
        if node_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "node_control_unavailable"},
            )
        try:
            return _node_response(
                node_control.change_port(
                    node_id,
                    new_port=request.new_port,
                    allowed_ports=_allowed_node_ports(settings),
                    confirmation_token=request.confirmation_token,
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
    def delete_node(node_id: UUID) -> Response:
        if node_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "node_control_unavailable"},
            )
        try:
            node_control.delete_node(node_id)
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
        except InvalidCameraSource as error:
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
                confirmation_token=request.confirmation_token,
            )
        except CameraNotFound:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "camera_not_found"},
            ) from None
        except CameraLifecycleConflict as error:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": str(error)},
            ) from None
        except InvalidCameraSource as error:
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
                camera = control.set_camera_enabled(camera_id, enabled=True)
            else:
                assert camera_mutation_control is not None
                camera = camera_mutation_control.disable(
                    camera_id,
                    confirmation_token=confirmation_token,
                )
        except CameraNotFound:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "camera_not_found"},
            ) from None
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
    def enable_camera(camera_id: UUID) -> CameraResponse:
        return set_camera_enabled(camera_id, enabled=True)

    @app.post("/api/v1/cameras/{camera_id}/disable", response_model=CameraResponse)
    def disable_camera(
        camera_id: UUID,
        request: CameraDisruptionRequest | None = None,
    ) -> CameraResponse:
        return set_camera_enabled(
            camera_id,
            enabled=False,
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
                    confirmation_token=(
                        None if request is None else request.confirmation_token
                    ),
                )
            )
        except CameraNotFound:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "camera_not_found"},
            ) from None
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
        request: AccessPolicyUpdateRequest,
    ) -> AccessPolicyResponse:
        if access_policy_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "access_control_unavailable"},
            )
        try:
            policy = access_policy_control.update(
                camera_id,
                internet_cidrs=request.internet_cidrs,
                local_cidrs=request.local_cidrs,
                expected_revision=request.expected_revision,
            )
        except LookupError:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "camera_not_found"},
            ) from None
        except CameraLifecycleConflict:
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

    @app.post(
        "/api/v1/cameras/{camera_id}/access-grants",
        response_model=AccessGrantSecretResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def create_access_grant(
        camera_id: UUID,
        request: AccessGrantCreateRequest,
        response: Response,
    ) -> AccessGrantSecretResponse:
        if access_grant_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "access_control_unavailable"},
            )
        try:
            issued = access_grant_control.create(
                camera_id=camera_id,
                lifetime=timedelta(seconds=request.lifetime_seconds),
                kind=request.kind,
                created_by="bootstrap-control-plane",
            )
        except CameraNotFound:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "camera_not_found"},
            ) from None
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["Location"] = f"/api/v1/access-grants/{issued.grant.id}"
        return _issued_access_grant_response(issued)

    @app.post(
        "/api/v1/access-grants/{grant_id}/rotate",
        response_model=AccessGrantSecretResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def rotate_access_grant(
        grant_id: UUID,
        request: AccessGrantRotateRequest,
        response: Response,
    ) -> AccessGrantSecretResponse:
        if access_grant_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "access_control_unavailable"},
            )
        try:
            issued = access_grant_control.rotate(
                grant_id,
                overlap=timedelta(seconds=request.overlap_seconds),
                lifetime=timedelta(seconds=request.lifetime_seconds),
            )
        except LookupError:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "access_grant_not_found"},
            ) from None
        except CameraLifecycleConflict:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "access_grant_revision_conflict"},
            ) from None
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["Location"] = f"/api/v1/access-grants/{issued.grant.id}"
        return _issued_access_grant_response(issued)

    @app.delete(
        "/api/v1/access-grants/{grant_id}",
        response_model=AccessGrantResponse,
    )
    def revoke_access_grant(grant_id: UUID) -> AccessGrantResponse:
        if access_grant_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "access_control_unavailable"},
            )
        try:
            grant = access_grant_control.revoke(grant_id)
        except LookupError:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "access_grant_not_found"},
            ) from None
        except CameraLifecycleConflict:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "access_grant_revision_conflict"},
            ) from None
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
                "rtsp_proxy_access_audit_events_dropped_total "
                f"{snapshot.dropped_audit}",
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


def _allowed_node_ports(settings: Settings) -> tuple[int, ...]:
    reserved = set(settings.node_port_reserved)
    return tuple(
        port
        for port in range(settings.node_port_range_start, settings.node_port_range_end + 1)
        if port not in reserved
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
