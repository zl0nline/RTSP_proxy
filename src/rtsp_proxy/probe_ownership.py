from __future__ import annotations

from typing import Protocol


class OwnershipLedger[Owned](Protocol):
    """Exact caller-owned slot used for interruption-safe lease handoff."""

    def publish(self, value: Owned) -> None:
        """Take ownership, or raise while ``owns(value)`` reports the result."""

    def owns(self, value: Owned) -> bool:
        """Return whether this exact capability is currently caller-owned."""

    def release(self, value: Owned) -> None:
        """Relinquish this exact capability after definitive cleanup."""
