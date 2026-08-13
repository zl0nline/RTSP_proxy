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
    RuntimeRole.AUTH: ("database", "schema", "pepper"),
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


def normalize_readiness_results(
    role: RuntimeRole,
    results: tuple[DependencyResult, ...],
) -> tuple[DependencyResult, ...]:
    grouped: dict[str, list[DependencyResult]] = {}
    for result in results:
        grouped.setdefault(result.name, []).append(result)

    normalized: list[DependencyResult] = []
    required = ROLE_DEPENDENCIES[role]
    for name in required:
        matches = grouped.get(name, [])
        if not matches:
            normalized.append(
                DependencyResult(
                    name=name,
                    ready=False,
                    reason="readiness_check_missing",
                )
            )
        elif len(matches) > 1:
            normalized.append(
                DependencyResult(
                    name=name,
                    ready=False,
                    reason="readiness_check_duplicate",
                )
            )
        else:
            normalized.append(matches[0])

    for name in sorted(set(grouped).difference(required)):
        normalized.append(
            DependencyResult(
                name=name,
                ready=False,
                reason="readiness_check_unexpected",
            )
        )

    return tuple(normalized)
