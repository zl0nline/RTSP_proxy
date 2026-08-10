from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class MediaPathConfig:
    name: str
    source_url: str
    source_on_demand: bool


class MediaNodeError(RuntimeError):
    """A MediaMTX operation failed without exposing request secrets."""


class MediaNodeUnavailable(MediaNodeError):
    """The MediaMTX management listener could not be reached."""


class MediaNodeRejected(MediaNodeError):
    """MediaMTX rejected an otherwise well-formed adapter operation."""


class MediaNodeProtocolError(MediaNodeError):
    """MediaMTX returned a response outside the pinned compatibility contract."""


class MediaMtxClient:
    """Version-specific MediaMTX operations used by the reconciler seam."""

    def __init__(self, *, api_url: str, timeout_seconds: float) -> None:
        self._api_url = api_url.rstrip("/")
        self._timeout_seconds = timeout_seconds

    def put_path(self, path: MediaPathConfig) -> None:
        self._request(
            "POST",
            f"/v3/config/paths/replace/{path.name}",
            payload={
                "source": path.source_url,
                "sourceOnDemand": path.source_on_demand,
                "rtspTransport": "tcp",
            },
        )

    def get_path(self, name: str) -> MediaPathConfig | None:
        response = self._request(
            "GET",
            f"/v3/config/paths/get/{name}",
            not_found_is_none=True,
        )
        if response is None:
            return None
        if not isinstance(response, dict):
            raise MediaNodeProtocolError("mediamtx_invalid_path_response")

        source = response.get("source")
        source_on_demand = response.get("sourceOnDemand")
        response_name = response.get("name")
        if (
            not isinstance(response_name, str)
            or not isinstance(source, str)
            or not isinstance(source_on_demand, bool)
        ):
            raise MediaNodeProtocolError("mediamtx_invalid_path_response")
        return MediaPathConfig(
            name=response_name,
            source_url=source,
            source_on_demand=source_on_demand,
        )

    def list_path_names(self) -> tuple[str, ...]:
        names: list[str] = []
        page = 0
        while True:
            response = self._request(
                "GET",
                f"/v3/config/paths/list?itemsPerPage=1000&page={page}",
            )
            if not isinstance(response, dict):
                raise MediaNodeProtocolError("mediamtx_invalid_path_list")
            page_count = response.get("pageCount")
            items = response.get("items")
            if (
                not isinstance(page_count, int)
                or isinstance(page_count, bool)
                or page_count < 0
                or not isinstance(items, list)
            ):
                raise MediaNodeProtocolError("mediamtx_invalid_path_list")
            for item in items:
                if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                    raise MediaNodeProtocolError("mediamtx_invalid_path_list")
                names.append(item["name"])
            page += 1
            if page >= page_count:
                return tuple(names)

    def delete_path(self, name: str) -> None:
        self._request(
            "DELETE",
            f"/v3/config/paths/delete/{name}",
            not_found_is_none=True,
        )

    def _request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        not_found_is_none: bool = False,
    ) -> Any:
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(
            f"{self._api_url}{path}",
            data=body,
            headers={"Content-Type": "application/json"} if body is not None else {},
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout_seconds) as response:
                content = response.read()
        except urllib.error.HTTPError as error:
            if error.code == 404 and not_found_is_none:
                return None
            raise MediaNodeRejected(f"mediamtx_http_{error.code}") from None
        except (OSError, urllib.error.URLError) as error:
            raise MediaNodeUnavailable("mediamtx_unavailable") from error

        if not content:
            return None
        try:
            return json.loads(content)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise MediaNodeProtocolError("mediamtx_invalid_json") from error
