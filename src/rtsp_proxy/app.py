from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from uuid import UUID

from fastapi import FastAPI, HTTPException, Response, status
from pydantic import BaseModel, Field

from rtsp_proxy.config import Settings
from rtsp_proxy.health import (
    MissingReadinessProvider,
    ReadinessProvider,
    normalize_readiness_results,
)
from rtsp_proxy.nodes import (
    CameraControl,
    EligibleNodeMissing,
    InvalidCameraSource,
    MaximumNodesReached,
    NodeCameraCapacityReached,
    NodeControl,
    NodeNotFound,
    NodePortInUse,
    NodePortOutOfRange,
    NodePortRangeExhausted,
    NodeRuntimeUnavailable,
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


class NodeListResponse(BaseModel):
    items: list[NodeResponse]
    count: int
    max_nodes: int


class CameraCreateRequest(BaseModel):
    name: str
    source_url: str
    node_id: UUID | None = None


class CameraResponse(BaseModel):
    id: str
    name: str
    public_id: str
    node_id: str
    node_port: int
    placement_mode: str
    desired_revision: int
    applied_revision: int


class CameraListResponse(BaseModel):
    items: list[CameraResponse]
    count: int


def create_app(
    settings: Settings,
    readiness: ReadinessProvider | None = None,
    node_control: NodeControl | None = None,
    camera_control: CameraControl | None = None,
    shutdown: Callable[[], None] | None = None,
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            if shutdown is not None:
                shutdown()

    app = FastAPI(title="RTSP Proxy Control Plane", lifespan=lifespan)
    readiness_provider = readiness or MissingReadinessProvider()

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
        except NodeRuntimeUnavailable:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "node_runtime_unavailable"},
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
        except InvalidCameraSource:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={"code": "camera_source_secret_reference_required"},
            ) from None
        return CameraResponse(
            id=str(camera.id),
            name=camera.name,
            public_id=str(camera.public_id),
            node_id=str(camera.node_id),
            node_port=camera.node_port,
            placement_mode=camera.placement_mode.value,
            desired_revision=camera.desired_revision,
            applied_revision=camera.applied_revision,
        )

    @app.get("/api/v1/cameras", response_model=CameraListResponse)
    def list_cameras() -> CameraListResponse:
        if camera_control is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "camera_control_unavailable"},
            )
        items = [
            CameraResponse(
                id=str(camera.id),
                name=camera.name,
                public_id=str(camera.public_id),
                node_id=str(camera.node_id),
                node_port=camera.node_port,
                placement_mode=camera.placement_mode.value,
                desired_revision=camera.desired_revision,
                applied_revision=camera.applied_revision,
            )
            for camera in camera_control.list_cameras()
        ]
        return CameraListResponse(items=items, count=len(items))

    return app
