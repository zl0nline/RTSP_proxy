from __future__ import annotations

from collections import deque
from typing import cast

import anyio
import pytest
from starlette.requests import Request
from starlette.types import Message

from rtsp_proxy.dashboard_forms import DashboardFormInvalid, read_dashboard_form


def _request(*chunks: bytes, content_length: int) -> Request:
    messages = deque(
        cast(
            Message,
            {
                "type": "http.request",
                "body": chunk,
                "more_body": index < len(chunks) - 1,
            }
        )
        for index, chunk in enumerate(chunks)
    )

    async def receive() -> Message:
        return messages.popleft()

    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/dashboard/cameras/example/mutations/preview",
            "headers": [
                (b"content-type", b"application/x-www-form-urlencoded"),
                (b"content-length", str(content_length).encode("ascii")),
            ],
        },
        receive,
    )


def test_dashboard_form_parser_preserves_exact_utf8_values_across_chunks() -> None:
    body = "_csrf=ccc&operation=update_source&name=Камера&source_url=rtsp%3A%2F%2Fhost".encode()
    form = anyio.run(
        read_dashboard_form,
        _request(body[:17], body[17:], content_length=len(body)),
    )

    assert dict(form.values) == {
        "_csrf": "ccc",
        "operation": "update_source",
        "name": "Камера",
        "source_url": "rtsp://host",
    }


def test_dashboard_form_parser_stops_when_stream_exceeds_declared_bound() -> None:
    first = b"_csrf=ccc&operation=delete"
    request = _request(first, b"&padding=unexpected", content_length=len(first))

    with pytest.raises(DashboardFormInvalid, match="dashboard_form_invalid"):
        anyio.run(read_dashboard_form, request)


def test_dashboard_form_parser_normalizes_client_disconnect() -> None:
    async def receive() -> Message:
        return cast(Message, {"type": "http.disconnect"})

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/dashboard/cameras/example/mutations/preview",
            "headers": [
                (b"content-type", b"application/x-www-form-urlencoded"),
                (b"content-length", b"10"),
            ],
        },
        receive,
    )

    with pytest.raises(DashboardFormInvalid, match="dashboard_form_invalid"):
        anyio.run(read_dashboard_form, request)


def test_dashboard_form_parser_rejects_short_declared_body() -> None:
    body = b"_csrf=ccc"

    with pytest.raises(DashboardFormInvalid, match="dashboard_form_invalid"):
        anyio.run(
            read_dashboard_form,
            _request(body, content_length=len(body) + 1),
        )


def test_dashboard_form_parser_bounds_stalled_body_read() -> None:
    async def receive() -> Message:
        await anyio.sleep_forever()
        raise AssertionError("unreachable")

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/dashboard/cameras/example/mutations/preview",
            "headers": [
                (b"content-type", b"application/x-www-form-urlencoded"),
                (b"content-length", b"10"),
            ],
        },
        receive,
    )

    async def read() -> None:
        await read_dashboard_form(request, read_timeout_seconds=0.001)

    with pytest.raises(DashboardFormInvalid, match="dashboard_form_invalid"):
        anyio.run(read)
