from __future__ import annotations

import json
import socket
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

import pytest

from rtsp_proxy.identifiers import PublicId
from rtsp_proxy.load_catalog import apply_load_catalog, build_load_catalog
from rtsp_proxy.load_cli import main as load_cli_main
from rtsp_proxy.load_profile import LoadProfile
from rtsp_proxy.media import (
    MediaMtxClient,
    MediaNodeProtocolError,
    MediaNodeRejected,
    MediaNodeUnavailable,
    MediaPathConfig,
)
from tests.test_load_profile import valid_profile


class MediaMtxFixtureHandler(BaseHTTPRequestHandler):
    paths: ClassVar[dict[str, dict[str, object]]] = {}

    def do_POST(self) -> None:
        name = self.path.removeprefix("/v3/config/paths/replace/")
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length))
        self.paths[name] = {
            "name": name,
            "source": payload["source"],
            "sourceOnDemand": payload["sourceOnDemand"],
        }
        self._respond(200, b'{"status":"ok"}')

    def do_GET(self) -> None:
        if self.path.startswith("/v3/config/paths/list?"):
            self._respond(
                200,
                json.dumps(
                    {
                        "itemCount": len(self.paths),
                        "pageCount": 1,
                        "items": list(self.paths.values()),
                    }
                ).encode("utf-8"),
            )
            return
        name = self.path.removeprefix("/v3/config/paths/get/")
        if name == "c" * 25:
            self._respond(200, b"not-json")
            return
        if name == "d" * 25:
            self._respond(400, b'{"error":"request contained rtsp://secret@camera"}')
            return
        if name == "e" * 25:
            self._respond(
                200,
                json.dumps(
                    {
                        "name": "f" * 25,
                        "source": "rtsp://camera.invalid/main",
                        "sourceOnDemand": True,
                    }
                ).encode("utf-8"),
            )
            return
        if name == "g" * 25:
            self._respond(
                200,
                json.dumps(
                    {
                        "name": name,
                        "source": "rtsp://camera.invalid/main",
                        "sourceOnDemand": False,
                    }
                ).encode("utf-8"),
            )
            return
        path = self.paths.get(name)
        if path is None:
            self._respond(404, b'{"error":"path configuration not found"}')
            return
        self._respond(200, json.dumps(path).encode("utf-8"))

    def do_DELETE(self) -> None:
        name = self.path.removeprefix("/v3/config/paths/delete/")
        if self.paths.pop(name, None) is None:
            self._respond(404, b'{"error":"path configuration not found"}')
            return
        self._respond(200, b'{"status":"ok"}')

    def log_message(self, format: str, *args: object) -> None:
        return

    def _respond(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def media_api() -> Iterator[str]:
    MediaMtxFixtureHandler.paths = {}
    server = ThreadingHTTPServer(("127.0.0.1", 0), MediaMtxFixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host = server.server_address[0]
        port = server.server_address[1]
        assert isinstance(host, str)
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_media_path_operations_converge_without_exposing_http_routes(media_api: str) -> None:
    client = MediaMtxClient(api_url=media_api, timeout_seconds=1)
    path = MediaPathConfig(
        name=PublicId.parse("a" * 25),
        source_url="rtsp://camera.invalid/main",
    )

    client.put_path(path)
    inventory = client.inventory_paths()
    assert inventory.camera_ids == (path.name,)
    assert inventory.no_oracle_matcher_present is False
    assert client.get_path(path.name) == path

    client.delete_path(path.name)
    client.delete_path(path.name)
    assert client.get_path(path.name) is None


def test_load_catalog_apply_is_on_demand_and_verifies_inventory_and_mapping(
    media_api: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    client = MediaMtxClient(api_url=media_api, timeout_seconds=1)
    profile = LoadProfile.model_validate(valid_profile())
    catalog = build_load_catalog(profile)

    result = apply_load_catalog(catalog, client)

    assert result.applied_paths == 4
    assert result.verified_paths == 3
    assert set(MediaMtxFixtureHandler.paths) == {
        path.public_id for path in catalog.paths
    }
    assert all(
        path["sourceOnDemand"] is True for path in MediaMtxFixtureHandler.paths.values()
    )

    MediaMtxFixtureHandler.paths = {}
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(json.dumps(valid_profile()), encoding="utf-8")
    assert (
        load_cli_main(
            ["apply-paths", str(profile_path), "--api-url", media_api]
        )
        == 0
    )
    output = capsys.readouterr()
    assert output.err == ""
    assert output.out == "APPLIED paths=4 verified=3\n"


def test_media_adapter_rejects_invalid_or_rejected_responses_without_secrets(
    media_api: str,
) -> None:
    client = MediaMtxClient(api_url=media_api, timeout_seconds=1)

    with pytest.raises(MediaNodeProtocolError, match="mediamtx_invalid_json"):
        client.get_path(PublicId.parse("c" * 25))

    with pytest.raises(MediaNodeRejected, match="mediamtx_http_400") as rejected:
        client.get_path(PublicId.parse("d" * 25))
    assert "secret" not in str(rejected.value)

    with pytest.raises(MediaNodeProtocolError, match="mediamtx_path_identity_mismatch"):
        client.get_path(PublicId.parse("e" * 25))

    with pytest.raises(MediaNodeProtocolError, match="mediamtx_path_not_on_demand"):
        client.get_path(PublicId.parse("g" * 25))

    MediaMtxFixtureHandler.paths["~^vendor-detail$"] = {
        "name": "~^vendor-detail$",
        "source": "publisher",
        "sourceOnDemand": False,
    }
    with pytest.raises(MediaNodeProtocolError, match="mediamtx_unknown_path_name"):
        client.inventory_paths()


def test_media_adapter_reports_an_unreachable_node_with_a_stable_reason() -> None:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        host, port = listener.getsockname()

    client = MediaMtxClient(api_url=f"http://{host}:{port}", timeout_seconds=0.1)
    with pytest.raises(MediaNodeUnavailable, match="mediamtx_unavailable"):
        client.get_path(PublicId.parse("a" * 25))
