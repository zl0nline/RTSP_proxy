from dataclasses import dataclass
from typing import Protocol

from rtsp_proxy.config import RuntimeRole


@dataclass(frozen=True, slots=True)
class DependencyResult:
    name: str
    ready: bool
    reason: str | None = None


class ReadinessProvider(Protocol):
    async def check(self, role: RuntimeRole) -> tuple[DependencyResult, ...]: ...


class MissingReadinessProvider:
    async def check(self, role: RuntimeRole) -> tuple[DependencyResult, ...]:
        return (
            DependencyResult(
                name="readiness",
                ready=False,
                reason="readiness_provider_missing",
            ),
        )
