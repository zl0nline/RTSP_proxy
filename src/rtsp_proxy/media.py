from __future__ import annotations

import json
import urllib.error
import urllib.request
from base64 import b64encode
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from rtsp_proxy.identifiers import InvalidPublicId, PublicId

NO_ORACLE_PATH_MATCHER = "~^[a-z2-7]{25}[aeimquy4]$"
SOURCE_ON_DEMAND_CLOSE_AFTER = "10s"


@dataclass(frozen=True, slots=True)
class MediaPathConfig:
    name: PublicId
    source_url: str
    max_readers: int = 1

    def __post_init__(self) -> None:
        if self.max_readers not in {-1, 1}:
            raise ValueError("media_path_reader_limit_invalid")


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

    def __init__(
        self,
        *,
        api_url: str,
        metrics_url: str | None = None,
        timeout_seconds: float,
        username: str | None = None,
        password: str | None = None,
    ) -> None:
        if (username is None) != (password is None):
            raise ValueError("mediamtx_management_credentials_incomplete")
        self._api_url = api_url.rstrip("/")
        self._metrics_url = None if metrics_url is None else metrics_url.rstrip("/")
        self._timeout_seconds = timeout_seconds
        self._authorization = (
            None
            if username is None or password is None
            else "Basic " + b64encode(f"{username}:{password}".encode()).decode("ascii")
        )

    def put_path(self, path: MediaPathConfig) -> None:
        name = _path_segment(path.name)
        self._request(
            "POST",
            f"/v3/config/paths/replace/{name}",
            payload={
                "source": path.source_url,
                "sourceOnDemand": True,
                "sourceOnDemandCloseAfter": SOURCE_ON_DEMAND_CLOSE_AFTER,
                "rtspTransport": "tcp",
                "maxReaders": path.max_readers,
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
        source_on_demand_close_after = response.get("sourceOnDemandCloseAfter")
        max_readers = response.get("maxReaders")
        response_name = response.get("name")
        if (
            not isinstance(response_name, str)
            or not isinstance(source, str)
            or not isinstance(source_on_demand, bool)
            or source_on_demand_close_after != SOURCE_ON_DEMAND_CLOSE_AFTER
            or not isinstance(max_readers, int)
            or isinstance(max_readers, bool)
            or max_readers not in {-1, 1}
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
            max_readers=max_readers,
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

    def path_runtime_ready(self, name: PublicId) -> bool:
        status = self.path_runtime_status(name)
        return status is not None and status[0]

    def runtime_path_statuses(
        self, names: tuple[PublicId, ...]
    ) -> dict[PublicId, tuple[bool, int] | None]:
        targets = set(names)
        observed: dict[PublicId, tuple[bool, int]] = {}
        page = 0
        while True:
            response = self._request(
                "GET",
                f"/v3/paths/list?itemsPerPage=1000&page={page}",
            )
            if not isinstance(response, dict):
                raise MediaNodeProtocolError("mediamtx_invalid_runtime_path_list")
            page_count = response.get("pageCount")
            items = response.get("items")
            if (
                not isinstance(page_count, int)
                or isinstance(page_count, bool)
                or page_count < 0
                or not isinstance(items, list)
            ):
                raise MediaNodeProtocolError("mediamtx_invalid_runtime_path_list")
            for item in items:
                if not isinstance(item, dict):
                    raise MediaNodeProtocolError("mediamtx_invalid_runtime_path_list")
                raw_name = item.get("name")
                ready = item.get("ready")
                readers = item.get("readers")
                if (
                    not isinstance(raw_name, str)
                    or not isinstance(ready, bool)
                    or not isinstance(readers, list)
                    or any(not isinstance(reader, dict) for reader in readers)
                ):
                    raise MediaNodeProtocolError("mediamtx_invalid_runtime_path_list")
                try:
                    name = PublicId.parse(raw_name)
                except InvalidPublicId:
                    continue
                if name in targets:
                    if name in observed:
                        raise MediaNodeProtocolError("mediamtx_duplicate_runtime_path")
                    observed[name] = (ready, len(readers))
            page += 1
            if page >= page_count:
                return {name: observed.get(name) for name in names}

    def path_runtime_status(self, name: PublicId) -> tuple[bool, int] | None:
        response = self._request(
            "GET",
            f"/v3/paths/get/{_path_segment(name)}",
            not_found_is_none=True,
        )
        if response is None:
            return None
        if not isinstance(response, dict):
            raise MediaNodeProtocolError("mediamtx_invalid_runtime_path_response")
        response_name = response.get("name")
        ready = response.get("ready")
        readers = response.get("readers")
        if (
            response_name != str(name)
            or not isinstance(ready, bool)
            or not isinstance(readers, list)
            or any(not isinstance(reader, dict) for reader in readers)
        ):
            raise MediaNodeProtocolError("mediamtx_invalid_runtime_path_response")
        return ready, len(readers)

    def delete_path(self, name: PublicId) -> None:
        path_segment = _path_segment(name)
        self._request(
            "DELETE",
            f"/v3/config/paths/delete/{path_segment}",
            not_found_is_none=True,
        )

    def path_metrics(self, *, maximum_bytes: int = 1_048_576) -> bytes:
        if self._metrics_url is None:
            raise MediaNodeProtocolError("mediamtx_metrics_url_missing")
        request = urllib.request.Request(
            f"{self._metrics_url}/metrics?type=paths",
            headers=(
                {}
                if self._authorization is None
                else {"Authorization": self._authorization}
            ),
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout_seconds) as response:
                content = bytes(response.read(maximum_bytes + 1))
        except urllib.error.HTTPError as error:
            raise MediaNodeRejected(f"mediamtx_metrics_http_{error.code}") from None
        except (OSError, urllib.error.URLError) as error:
            raise MediaNodeUnavailable("mediamtx_metrics_unavailable") from error
        if len(content) > maximum_bytes:
            raise MediaNodeProtocolError("mediamtx_metrics_too_large")
        return content

    def _request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        not_found_is_none: bool = False,
    ) -> Any:
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"Content-Type": "application/json"} if body is not None else {}
        if self._authorization is not None:
            headers["Authorization"] = self._authorization
        request = urllib.request.Request(
            f"{self._api_url}{path}",
            data=body,
            headers=headers,
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
