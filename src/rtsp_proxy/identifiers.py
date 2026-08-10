from __future__ import annotations

import re
from dataclasses import dataclass

_PUBLIC_ID_PATTERN = re.compile(r"[a-z0-9]{25}\Z")


class InvalidPublicId(ValueError):
    """A public ID is outside the canonical, non-secret identifier space."""


@dataclass(frozen=True, slots=True)
class PublicId:
    """Canonical external path identifier with more than 128 bits of space."""

    value: str

    def __post_init__(self) -> None:
        if _PUBLIC_ID_PATTERN.fullmatch(self.value) is None:
            raise InvalidPublicId("invalid_public_id")

    @classmethod
    def parse(cls, value: str) -> PublicId:
        return cls(value=value)

    def __str__(self) -> str:
        return self.value
