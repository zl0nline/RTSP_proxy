from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from rtsp_proxy.identifiers import InvalidPublicId, PublicId

NO_ORACLE_PATH_MATCHER = "~^[a-z0-9]{25}$"


@dataclass(frozen=True, slots=True)
class MediaPathConfig:
    name: PublicId
    source_url: str


@dataclass(frozen=True, slots=True)
class MediaPathInventory:
    camera_ids: tuple[PublicId, ...]
    no_oracle_matcher_present: bool


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
        name = _path_segment(path.name)
        self._request(
            "POST",
            f"/v3/config/paths/replace/{name}",
            payload={
                "source": path.source_url,
                "sourceOnDemand": True,
                "rtspTransport": "tcp",
            },
        )

    def get_path(self, name: PublicId) -> MediaPathConfig | None:
        path_segment = _path_segment(name)
        response = self._request(
            "GET",
            f"/v3/config/paths/get/{path_segment}",
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
        if not source_on_demand:
            raise MediaNodeProtocolError("mediamtx_path_not_on_demand")
        try:
            parsed_name = PublicId.parse(response_name)
        except InvalidPublicId:
            raise MediaNodeProtocolError("mediamtx_invalid_path_response") from None
        if parsed_name != name:
            raise MediaNodeProtocolError("mediamtx_path_identity_mismatch")
        return MediaPathConfig(
            name=parsed_name,
            source_url=source,
        )

    def inventory_paths(self) -> MediaPathInventory:
        camera_ids: set[PublicId] = set()
        no_oracle_matcher_present = False
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
                name = item["name"]
                if name == NO_ORACLE_PATH_MATCHER:
                    if no_oracle_matcher_present:
                        raise MediaNodeProtocolError("mediamtx_duplicate_path_name")
                    no_oracle_matcher_present = True
                    continue
                try:
                    public_id = PublicId.parse(name)
                except InvalidPublicId:
                    raise MediaNodeProtocolError("mediamtx_unknown_path_name") from None
                if public_id in camera_ids:
                    raise MediaNodeProtocolError("mediamtx_duplicate_path_name")
                camera_ids.add(public_id)
            page += 1
            if page >= page_count:
                return MediaPathInventory(
                    camera_ids=tuple(sorted(camera_ids, key=str)),
                    no_oracle_matcher_present=no_oracle_matcher_present,
                )

    def delete_path(self, name: PublicId) -> None:
        path_segment = _path_segment(name)
        self._request(
            "DELETE",
            f"/v3/config/paths/delete/{path_segment}",
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


def _path_segment(public_id: PublicId) -> str:
    return quote(str(public_id), safe="")
