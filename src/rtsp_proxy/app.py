from fastapi import FastAPI, Response, status
from pydantic import BaseModel

from rtsp_proxy.config import Settings
from rtsp_proxy.health import (
    MissingReadinessProvider,
    ReadinessProvider,
    normalize_readiness_results,
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


def create_app(
    settings: Settings,
    readiness: ReadinessProvider | None = None,
) -> FastAPI:
    app = FastAPI(title="RTSP Proxy Control Plane")
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

    return app
