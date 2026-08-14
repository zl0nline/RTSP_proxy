from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from urllib.parse import parse_qsl

import anyio
from starlette.requests import ClientDisconnect, Request

MAX_DASHBOARD_FORM_BYTES = 32_768
MAX_DASHBOARD_FORM_FIELDS = 8
DASHBOARD_FORM_READ_TIMEOUT_SECONDS = 2.0


class DashboardFormInvalid(ValueError):
    """A server-rendered dashboard form cannot be parsed unambiguously."""


@dataclass(frozen=True, slots=True)
class DashboardForm:
    values: MappingProxyType[str, str]

    @property
    def csrf_token(self) -> str:
        return self.required("_csrf", max_length=1024)

    def required(self, name: str, *, max_length: int) -> str:
        value = self.values.get(name)
        if value is None or not value or len(value) > max_length:
            raise DashboardFormInvalid("dashboard_form_invalid")
        return value

    def optional(self, name: str, *, max_length: int) -> str | None:
        value = self.values.get(name)
        if value is None:
            return None
        if len(value) > max_length:
            raise DashboardFormInvalid("dashboard_form_invalid")
        return value

    def require_exact_fields(self, fields: frozenset[str]) -> None:
        if self.values.keys() != fields:
            raise DashboardFormInvalid("dashboard_form_invalid")


async def read_dashboard_form(
    request: Request,
    *,
    read_timeout_seconds: float = DASHBOARD_FORM_READ_TIMEOUT_SECONDS,
) -> DashboardForm:
    content_type = request.headers.get("content-type", "").partition(";")[0].strip().lower()
    if content_type != "application/x-www-form-urlencoded":
        raise DashboardFormInvalid("dashboard_form_invalid")
    content_length = _content_length(request)
    body = bytearray()
    try:
        with anyio.fail_after(read_timeout_seconds):
            async for chunk in request.stream():
                if len(body) + len(chunk) > content_length:
                    raise DashboardFormInvalid("dashboard_form_invalid")
                body.extend(chunk)
    except (ClientDisconnect, TimeoutError):
        raise DashboardFormInvalid("dashboard_form_invalid") from None
    if len(body) != content_length:
        raise DashboardFormInvalid("dashboard_form_invalid")
    try:
        text = bytes(body).decode("utf-8", errors="strict")
        pairs = parse_qsl(
            text,
            keep_blank_values=True,
            strict_parsing=True,
            max_num_fields=MAX_DASHBOARD_FORM_FIELDS,
            encoding="utf-8",
            errors="strict",
        )
    except (UnicodeDecodeError, ValueError):
        raise DashboardFormInvalid("dashboard_form_invalid") from None
    values: dict[str, str] = {}
    for name, value in pairs:
        if not name or name in values:
            raise DashboardFormInvalid("dashboard_form_invalid")
        values[name] = value
    form = DashboardForm(MappingProxyType(values))
    form.required("_csrf", max_length=1024)
    return form


def _content_length(request: Request) -> int:
    raw_length = request.headers.get("content-length", "")
    try:
        content_length = int(raw_length, 10)
    except ValueError:
        raise DashboardFormInvalid("dashboard_form_invalid") from None
    if content_length < 1 or content_length > MAX_DASHBOARD_FORM_BYTES:
        raise DashboardFormInvalid("dashboard_form_invalid")
    return content_length
