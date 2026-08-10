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


ROLE_DEPENDENCIES: dict[RuntimeRole, tuple[str, ...]] = {
    RuntimeRole.WEB: ("database", "schema", "session_store"),
    RuntimeRole.WORKER: ("database", "schema", "outbox"),
    RuntimeRole.RECONCILER: ("database", "schema", "media_adapter"),
    RuntimeRole.PROBE: ("database", "schema", "probe_runtime"),
    RuntimeRole.COLLECTOR: ("database", "schema", "media_metrics"),
}


class MissingReadinessProvider:
    async def check(self, role: RuntimeRole) -> tuple[DependencyResult, ...]:
        return tuple(
            DependencyResult(
                name=dependency,
                ready=False,
                reason=f"{dependency}_provider_missing",
            )
            for dependency in ROLE_DEPENDENCIES[role]
        )
