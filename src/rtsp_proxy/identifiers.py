from __future__ import annotations

import base64
import re
import secrets
from dataclasses import dataclass

_PUBLIC_ID_PATTERN = re.compile(r"[a-z2-7]{25}[aeimquy4]\Z")


class InvalidPublicId(ValueError):
    """A public ID is outside the canonical, non-secret identifier space."""


@dataclass(frozen=True, slots=True)
class PublicId:
    """Canonical lowercase base32 encoding of a 128-bit external path ID."""

    value: str

    def __post_init__(self) -> None:
        if _PUBLIC_ID_PATTERN.fullmatch(self.value) is None:
            raise InvalidPublicId("invalid_public_id")

    @classmethod
    def parse(cls, value: str) -> PublicId:
        return cls(value=value)

    def __str__(self) -> str:
        return self.value


def generate_public_id() -> str:
    return base64.b32encode(secrets.token_bytes(16)).decode("ascii").lower().rstrip("=")
