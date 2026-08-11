from __future__ import annotations

import json
import socket
import threading
import time
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

import pytest

from rtsp_proxy.identifiers import PublicId
from rtsp_proxy.load_catalog import (
    apply_load_catalog,
    build_load_catalog,
    build_proxy_reader_plan,
    capture_cold_preflight,
    capture_warm_preflight,
    validate_cold_preflight_payload,
    validate_warm_preflight_payload,
)
from rtsp_proxy.load_cli import main as load_cli_main
from rtsp_proxy.load_evidence import KernelClockProof
from rtsp_proxy.load_profile import LoadProfile, initialize_run_directory
from rtsp_proxy.media import (
    MediaMtxClient,
    MediaNodeProtocolError,
    MediaNodeRejected,
    MediaNodeUnavailable,
    MediaPathConfig,
)
from tests.test_load_profile import valid_profile


def synchronized_clock_proof(
    observed_at_unix_ms: int,
    end_observed_at_unix_ms: int | None = None,
) -> Callable[[float], KernelClockProof]:
    observations = iter((observed_at_unix_ms, end_observed_at_unix_ms))

    def proof(_: float) -> KernelClockProof:
        observed_at = observed_at_unix_ms if end_observed_at_unix_ms is None else next(observations)
        assert observed_at is not None
        return KernelClockProof(
            observed_at_unix_ms=observed_at,
            synchronized=True,
            state=0,
            status=0,
            max_error_ms=1,
        )

    return proof


def current_clock_proof(_: float) -> KernelClockProof:
    return synchronized_clock_proof(time.time_ns() // 1_000_000)(1)


class MediaMtxFixtureHandler(BaseHTTPRequestHandler):
    paths: ClassVar[dict[str, dict[str, object]]] = {}
    ready_paths: ClassVar[set[str]] = set()
    ready_on_put: ClassVar[set[str]] = set()

    def do_POST(self) -> None:
        name = self.path.removeprefix("/v3/config/paths/replace/")
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length))
        self.paths[name] = {
            "name": name,
            "source": payload["source"],
            "sourceOnDemand": payload["sourceOnDemand"],
            "sourceOnDemandCloseAfter": payload["sourceOnDemandCloseAfter"],
        }
        if name in self.ready_on_put:
            self.ready_paths.add(name)
        self._respond(200, b'{"status":"ok"}')

    def do_GET(self) -> None:
        if self.path.startswith("/v3/paths/list?"):
            items = [
                {"name": name, "ready": True, "readers": [{}]} for name in sorted(self.ready_paths)
            ]
            self._respond(
                200,
                json.dumps(
                    {
                        "itemCount": len(items),
                        "pageCount": 1,
                        "items": items,
                    }
                ).encode("utf-8"),
            )
            return
        if self.path.startswith("/v3/paths/get/"):
            name = self.path.removeprefix("/v3/paths/get/")
            if name not in self.ready_paths:
                self._respond(404, b'{"error":"path not ready"}')
                return
            self._respond(
                200,
                json.dumps({"name": name, "ready": True, "readers": [{}]}).encode(),
            )
            return
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
        if name == "c" * 25 + "a":
            self._respond(200, b"not-json")
            return
        if name == "d" * 25 + "a":
            self._respond(400, b'{"error":"request contained rtsp://secret@camera"}')
            return
        if name == "e" * 25 + "a":
            self._respond(
                200,
                json.dumps(
                    {
                        "name": "f" * 25 + "a",
                        "source": "rtsp://camera.invalid/main",
                        "sourceOnDemand": True,
                        "sourceOnDemandCloseAfter": "10s",
                    }
                ).encode("utf-8"),
            )
            return
        if name == "g" * 25 + "a":
            self._respond(
                200,
                json.dumps(
                    {
                        "name": name,
                        "source": "rtsp://camera.invalid/main",
                        "sourceOnDemand": False,
                        "sourceOnDemandCloseAfter": "10s",
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
        self.ready_paths.discard(name)
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
    MediaMtxFixtureHandler.ready_paths = set()
    MediaMtxFixtureHandler.ready_on_put = set()
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
        name=PublicId.parse("a" * 26),
        source_url="rtsp://camera.invalid/main",
    )

    client.put_path(path)
    inventory = client.inventory_paths()
    assert inventory.camera_ids == (path.name,)
    assert inventory.no_oracle_matcher_present is False
    assert client.get_path(path.name) == path
    assert client.path_runtime_ready(path.name) is False
    MediaMtxFixtureHandler.ready_paths.add(str(path.name))
    assert client.path_runtime_ready(path.name) is True

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
    assert set(MediaMtxFixtureHandler.paths) == {path.public_id for path in catalog.paths}
    assert all(path["sourceOnDemand"] is True for path in MediaMtxFixtureHandler.paths.values())

    MediaMtxFixtureHandler.paths = {}
    run_directory = tmp_path / "run"
    initialize_run_directory(profile, run_directory)
    assert load_cli_main(["apply-paths", str(run_directory), "--api-url", media_api]) == 0
    output = capsys.readouterr()
    assert output.err == ""
    assert output.out == "APPLIED paths=4 verified=3\n"

    assert (
        load_cli_main(
            [
                "apply-paths",
                str(run_directory),
                "--api-url",
                media_api.replace("127.0.0.1", "localhost"),
            ]
        )
        == 2
    )
    rejected = capsys.readouterr()
    assert rejected.err == "load_profile_error: invalid_or_unreadable_profile\n"


def test_cold_preflight_proves_every_proxy_path_inactive(
    media_api: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = valid_profile()
    workload = raw["workload"]
    assert isinstance(workload, dict)
    workload.update(session_temperature="cold", total_readers=4)
    profile = LoadProfile.model_validate(raw)
    client = MediaMtxClient(api_url=media_api, timeout_seconds=1)
    apply_load_catalog(build_load_catalog(profile), client)
    scheduled_start = 2_000_000

    payload = capture_cold_preflight(
        profile,
        client,
        scheduled_start_unix_ms=scheduled_start,
        clock_ms=iter((scheduled_start - 1000, scheduled_start - 900)).__next__,
        clock_proof=synchronized_clock_proof(scheduled_start - 1100, scheduled_start - 800),
    )

    validate_cold_preflight_payload(profile, payload, scheduled_start_unix_ms=scheduled_start)
    inactive_paths = payload["unavailable_paths"]
    assert isinstance(inactive_paths, list)
    assert len(inactive_paths) == 4
    first_path = str(inactive_paths[0])
    assert payload["reset_paths"] == inactive_paths
    MediaMtxFixtureHandler.ready_on_put.add(first_path)
    with pytest.raises(ValueError, match="cold_preflight_path_available_after_reset"):
        capture_cold_preflight(
            profile,
            client,
            scheduled_start_unix_ms=scheduled_start,
            clock_ms=iter((scheduled_start - 1000, scheduled_start - 900)).__next__,
            clock_proof=synchronized_clock_proof(scheduled_start - 1100, scheduled_start - 800),
        )
    MediaMtxFixtureHandler.ready_on_put.clear()
    tampered = {**payload, "observed_start_unix_ms": scheduled_start - 30_001}
    with pytest.raises(ValueError, match="cold_preflight_evidence_invalid"):
        validate_cold_preflight_payload(profile, tampered, scheduled_start_unix_ms=scheduled_start)

    MediaMtxFixtureHandler.ready_paths.clear()
    run_directory = tmp_path / "cold-run"
    initialize_run_directory(profile, run_directory)
    (run_directory / "raw").mkdir()
    future_start = time.time_ns() // 1_000_000 + 10_000
    monkeypatch.setattr(
        "rtsp_proxy.load_catalog.prove_linux_clock",
        current_clock_proof,
    )
    (run_directory / "launch-plan.json").write_text(
        json.dumps({"coordinated_start_unix_ms": future_start}), encoding="utf-8"
    )
    assert load_cli_main(["preflight-cold", str(run_directory), "--api-url", media_api]) == 0
    output = run_directory / "raw" / "cold-preflight.json"
    assert output.exists()
    assert capsys.readouterr().out.startswith("COLD_PREFLIGHT inactive=4 output=")


def test_warm_preflight_proves_anchor_readers_across_ramp_epoch(media_api: str) -> None:
    raw = valid_profile()
    workload = raw["workload"]
    assert isinstance(workload, dict)
    workload.update(active_sources=2, total_readers=4)
    profile = LoadProfile.model_validate(raw)
    client = MediaMtxClient(api_url=media_api, timeout_seconds=1)
    apply_load_catalog(build_load_catalog(profile), client)
    target_paths = [target.path for target in build_proxy_reader_plan(profile).targets]
    MediaMtxFixtureHandler.ready_paths.update(target_paths)
    scheduled_start = 2_000_000
    clock_values = iter(
        (
            scheduled_start - 1000,
            scheduled_start - 900,
            scheduled_start - 500,
            scheduled_start,
        )
    )

    payload = capture_warm_preflight(
        profile,
        client,
        scheduled_start_unix_ms=scheduled_start,
        clock_ms=lambda: next(clock_values),
        sleep=lambda _: None,
        clock_proof=synchronized_clock_proof(scheduled_start - 1100, scheduled_start + 100),
    )

    validate_warm_preflight_payload(profile, payload, scheduled_start_unix_ms=scheduled_start)
    assert payload["sample_count"] == 2
    assert payload["ready_paths"] == target_paths
    assert payload["minimum_reader_count_by_path"] == dict.fromkeys(target_paths, 1)
    sweeps = payload["sweeps"]
    assert isinstance(sweeps, list)
    assert len(sweeps) == 2
    tampered = {**payload, "observed_end_unix_ms": scheduled_start - 1}
    with pytest.raises(ValueError, match="warm_preflight_evidence_invalid"):
        validate_warm_preflight_payload(profile, tampered, scheduled_start_unix_ms=scheduled_start)

    with pytest.raises(ValueError, match="warm_preflight_poll_interval_invalid"):
        capture_warm_preflight(
            profile,
            client,
            scheduled_start_unix_ms=scheduled_start,
            clock_ms=lambda: scheduled_start - 100,
            poll_interval_seconds=0,
            clock_proof=synchronized_clock_proof(scheduled_start),
        )
    MediaMtxFixtureHandler.ready_paths.clear()
    with pytest.raises(ValueError, match="warm_preflight_anchor_missing"):
        capture_warm_preflight(
            profile,
            client,
            scheduled_start_unix_ms=scheduled_start,
            clock_ms=lambda: scheduled_start - 100,
            sleep=lambda _: None,
            clock_proof=synchronized_clock_proof(scheduled_start),
        )
    cold_raw = valid_profile()
    cold_workload = cold_raw["workload"]
    assert isinstance(cold_workload, dict)
    cold_workload.update(session_temperature="cold", total_readers=4)
    with pytest.raises(ValueError, match="warm_preflight_profile_invalid"):
        capture_warm_preflight(
            LoadProfile.model_validate(cold_raw),
            client,
            scheduled_start_unix_ms=scheduled_start,
            clock_ms=lambda: scheduled_start - 100,
            clock_proof=synchronized_clock_proof(scheduled_start),
        )


def test_media_adapter_rejects_invalid_or_rejected_responses_without_secrets(
    media_api: str,
) -> None:
    client = MediaMtxClient(api_url=media_api, timeout_seconds=1)

    with pytest.raises(MediaNodeProtocolError, match="mediamtx_invalid_json"):
        client.get_path(PublicId.parse("c" * 25 + "a"))

    with pytest.raises(MediaNodeRejected, match="mediamtx_http_400") as rejected:
        client.get_path(PublicId.parse("d" * 25 + "a"))
    assert "secret" not in str(rejected.value)

    with pytest.raises(MediaNodeProtocolError, match="mediamtx_path_identity_mismatch"):
        client.get_path(PublicId.parse("e" * 25 + "a"))

    with pytest.raises(MediaNodeProtocolError, match="mediamtx_path_not_on_demand"):
        client.get_path(PublicId.parse("g" * 25 + "a"))

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
        client.get_path(PublicId.parse("a" * 26))
