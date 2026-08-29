from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol

from anyio import to_thread

from rtsp_proxy.config import RuntimeRole


@dataclass(frozen=True, slots=True)
class DependencyResult:
    name: str
    ready: bool
    reason: str | None = None


class ReadinessProvider(Protocol):
    async def check(self, role: RuntimeRole) -> tuple[DependencyResult, ...]: ...


ROLE_DEPENDENCIES: dict[RuntimeRole, tuple[str, ...]] = {
    RuntimeRole.WEB: ("database", "schema", "session_store", "probe_observations"),
    RuntimeRole.AUTH: ("database", "schema", "pepper"),
    RuntimeRole.WORKER: ("database", "schema", "outbox"),
    RuntimeRole.RECONCILER: ("database", "schema", "media_adapter"),
    RuntimeRole.PROBE: ("database", "schema", "probe_runtime"),
    RuntimeRole.COLLECTOR: ("database", "schema", "media_metrics", "collector_store"),
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


class RoleReadinessProvider:
    """Run bounded role dependency probes without exposing exception details."""

    def __init__(self, checks: Mapping[str, Callable[[], None]]) -> None:
        self._checks = dict(checks)

    async def check(self, role: RuntimeRole) -> tuple[DependencyResult, ...]:
        results: list[DependencyResult] = []
        for name in ROLE_DEPENDENCIES[role]:
            check = self._checks.get(name)
            if check is None:
                results.append(
                    DependencyResult(name=name, ready=False, reason="readiness_check_missing")
                )
                continue
            try:
                await to_thread.run_sync(check)
            except Exception:
                results.append(
                    DependencyResult(name=name, ready=False, reason=f"{name}_unavailable")
                )
            else:
                results.append(DependencyResult(name=name, ready=True))
        return tuple(results)


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
