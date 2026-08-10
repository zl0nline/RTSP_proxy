from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request
from base64 import b64encode
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

import pytest

from rtsp_proxy.media import MediaMtxClient, MediaPathConfig
from rtsp_proxy.probe import FfprobeRunner, ProbeFailed, RtspEndpoint

MEDIA_MTX_BINARY = os.environ.get("MEDIAMTX_BINARY")
FFMPEG_BINARY = os.environ.get("FFMPEG_BINARY")
FFPROBE_BINARY = os.environ.get("FFPROBE_BINARY")
pytestmark = [
    pytest.mark.contract,
    pytest.mark.skipif(
        not all((MEDIA_MTX_BINARY, FFMPEG_BINARY, FFPROBE_BINARY)),
        reason="MediaMTX, FFmpeg and ffprobe binaries are required",
    ),
]


def unused_tcp_ports(count: int) -> tuple[int, ...]:
    ports: set[int] = set()
    while len(ports) < count:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            ports.add(int(listener.getsockname()[1]))
    return tuple(ports)


def start_process(command: list[str]) -> subprocess.Popen[str]:
    return subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def stop_process(process: subprocess.Popen[str]) -> str:
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
    try:
        output, _ = process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate(timeout=5)
        pytest.fail("external contract process did not stop within 10 seconds")
    return output


def wait_for_json(url: str, process: subprocess.Popen[str], *, ready_path: bool = False) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output, _ = process.communicate()
            pytest.fail(f"external contract process exited early:\n{output}")
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                payload = json.load(response)
            if not ready_path or payload.get("ready") is True:
                return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(0.1)
    pytest.fail("external contract endpoint did not become ready within 10 seconds")


def authenticated_describe_response(
    *, host: str, port: int, path: str, username: str, password: str
) -> bytes:
    authorization = b64encode(f"{username}:{password}".encode()).decode()
    request = (
        f"DESCRIBE rtsp://{host}:{port}/{path} RTSP/1.0\r\n"
        "CSeq: 1\r\n"
        f"Authorization: Basic {authorization}\r\n"
        "Accept: application/sdp\r\n"
        "\r\n"
    ).encode()
    with socket.create_connection((host, port), timeout=6) as connection:
        connection.settimeout(6)
        connection.sendall(request)
        response = bytearray()
        while b"\r\n\r\n" not in response:
            chunk = connection.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
    return bytes(response).partition(b"\r\n\r\n")[0]


class AuthCallbackHandler(BaseHTTPRequestHandler):
    accepted_paths: ClassVar[set[str]] = set()
    valid_requests: ClassVar[list[dict[str, object]]] = []
    accept_credentials: ClassVar[bool] = True

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length))
        valid = (
            payload.get("user") == "external"
            and payload.get("password") == "lab-secret"
            and payload.get("action") == "read"
            and payload.get("path") in self.accepted_paths
            and payload.get("protocol") == "rtsp"
            and payload.get("ip") == "127.0.0.1"
        )
        if valid and self.accept_credentials:
            self.valid_requests.append(payload)
            self.send_response(204)
        else:
            self.send_response(401)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return


@pytest.mark.parametrize("auth_method", ["internal", "http"])
def test_external_rtsp_tcp_is_transparent_and_unrelated_hot_update_isolated(
    tmp_path: Path,
    auth_method: str,
) -> None:
    assert MEDIA_MTX_BINARY is not None
    assert FFMPEG_BINARY is not None
    assert FFPROBE_BINARY is not None
    (
        origin_api_port,
        origin_rtsp_port,
        proxy_api_port,
        proxy_metrics_port,
        proxy_rtsp_port,
        auth_port,
    ) = (
        unused_tcp_ports(6)
    )
    public_id = "f" * 25
    other_public_id = "g" * 25
    race_public_id = "h" * 25

    origin_config = tmp_path / "origin.yml"
    origin_config.write_text(
        f"""
logLevel: warn
logDestinations: [stdout]
authMethod: internal
authInternalUsers:
  - user: any
    pass:
    ips: [\"127.0.0.1\", \"::1\"]
    permissions:
      - action: api
      - action: publish
      - action: read
api: true
apiAddress: 127.0.0.1:{origin_api_port}
metrics: false
pprof: false
playback: false
rtsp: true
rtspTransports: [tcp]
rtspEncryption: \"no\"
rtspAddress: 127.0.0.1:{origin_rtsp_port}
rtmp: false
hls: false
webrtc: false
srt: false
moq: false
paths:
  fixture:
    source: publisher
""".lstrip(),
        encoding="utf-8",
    )

    template = Path("deploy/mediamtx.yml.example").read_text(encoding="utf-8")
    if auth_method == "http":
        template = template.replace(
            "authMethod: internal",
            "authMethod: http\n"
            f"authHTTPAddress: http://127.0.0.1:{auth_port}/auth\n"
            "authHTTPExclude:\n"
            "  - action: api\n"
            "  - action: metrics",
        ).replace("paths: {}", 'paths:\n  "~^[a-z0-9]{25}$": {}')
    proxy_config = tmp_path / "proxy.yml"
    proxy_config.write_text(
        template.replace("127.0.0.1:9997", f"127.0.0.1:{proxy_api_port}")
        .replace("127.0.0.1:9998", f"127.0.0.1:{proxy_metrics_port}")
        .replace("rtspAddress: :9999", f"rtspAddress: 127.0.0.1:{proxy_rtsp_port}")
        .replace(
            "      - action: metrics\n",
            "      - action: metrics\n"
            "  - user: external\n"
            "    pass: lab-secret\n"
            "    permissions:\n"
            "      - action: read\n"
            f"        path: ~^({public_id}|{other_public_id}|{race_public_id})$\n",
        ),
        encoding="utf-8",
    )

    origin = start_process([MEDIA_MTX_BINARY, str(origin_config)])
    publisher: subprocess.Popen[str] | None = None
    proxy: subprocess.Popen[str] | None = None
    reader: subprocess.Popen[str] | None = None
    auth_server: ThreadingHTTPServer | None = None
    auth_thread: threading.Thread | None = None
    try:
        if auth_method == "http":
            AuthCallbackHandler.accepted_paths = {
                public_id,
                other_public_id,
                race_public_id,
            }
            AuthCallbackHandler.valid_requests = []
            AuthCallbackHandler.accept_credentials = True
            auth_server = ThreadingHTTPServer(
                ("127.0.0.1", auth_port),
                AuthCallbackHandler,
            )
            auth_thread = threading.Thread(target=auth_server.serve_forever, daemon=True)
            auth_thread.start()

        wait_for_json(
            f"http://127.0.0.1:{origin_api_port}/v3/config/global/get",
            origin,
        )
        publisher = start_process(
            [
                FFMPEG_BINARY,
                "-hide_banner",
                "-loglevel",
                "error",
                "-re",
                "-f",
                "lavfi",
                "-i",
                "testsrc=size=160x120:rate=10",
                "-an",
                "-c:v",
                "libx264",
                "-preset",
                "ultrafast",
                "-tune",
                "zerolatency",
                "-g",
                "10",
                "-f",
                "rtsp",
                "-rtsp_transport",
                "tcp",
                f"rtsp://127.0.0.1:{origin_rtsp_port}/fixture",
            ]
        )
        wait_for_json(
            f"http://127.0.0.1:{origin_api_port}/v3/paths/get/fixture",
            publisher,
            ready_path=True,
        )

        proxy = start_process([MEDIA_MTX_BINARY, str(proxy_config)])
        wait_for_json(
            f"http://127.0.0.1:{proxy_api_port}/v3/config/global/get",
            proxy,
        )
        client = MediaMtxClient(
            api_url=f"http://127.0.0.1:{proxy_api_port}",
            timeout_seconds=2,
        )
        client.put_path(
            MediaPathConfig(
                name=public_id,
                source_url=f"rtsp://127.0.0.1:{origin_rtsp_port}/fixture",
                source_on_demand=True,
            )
        )
        client.put_path(
            MediaPathConfig(
                name=other_public_id,
                source_url=f"rtsp://127.0.0.1:{origin_rtsp_port}/fixture",
                source_on_demand=True,
            )
        )
        client.put_path(
            MediaPathConfig(
                name=race_public_id,
                source_url=f"rtsp://127.0.0.1:{origin_rtsp_port}/fixture",
                source_on_demand=True,
            )
        )

        def inspect_cold_path(_: int) -> str:
            observation = FfprobeRunner(
                binary=Path(FFPROBE_BINARY),
                io_timeout_seconds=5,
                total_timeout_seconds=15,
            ).inspect(
                RtspEndpoint(
                    host="127.0.0.1",
                    port=proxy_rtsp_port,
                    path=race_public_id,
                    username="external",
                    password="lab-secret",
                )
            )
            return observation.streams[0].codec_name

        with ThreadPoolExecutor(max_workers=4) as executor:
            assert list(executor.map(inspect_cold_path, range(4))) == ["h264"] * 4
        with urllib.request.urlopen(
            f"http://127.0.0.1:{origin_api_port}/v3/paths/get/fixture",
            timeout=2,
        ) as origin_path_response:
            origin_path = json.load(origin_path_response)
        assert len(origin_path["readers"]) == 1

        result = subprocess.run(
            [
                FFPROBE_BINARY,
                "-v",
                "error",
                "-rtsp_transport",
                "tcp",
                "-rw_timeout",
                "5000000",
                "-show_entries",
                "stream=codec_name,width,height",
                "-of",
                "json",
                f"rtsp://external:lab-secret@127.0.0.1:{proxy_rtsp_port}/{public_id}",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.returncode == 0, "ffprobe failed against the ordinary RTSP endpoint"
        assert json.loads(result.stdout)["streams"] == [
            {"codec_name": "h264", "width": 160, "height": 120}
        ]

        reader = start_process(
            [
                FFMPEG_BINARY,
                "-hide_banner",
                "-loglevel",
                "error",
                "-rtsp_transport",
                "tcp",
                "-i",
                f"rtsp://external:lab-secret@127.0.0.1:{proxy_rtsp_port}/{other_public_id}",
                "-t",
                "3",
                "-map",
                "0:v:0",
                "-f",
                "null",
                "-",
            ]
        )
        time.sleep(0.5)
        if reader.poll() is not None:
            reader_output, _ = reader.communicate()
            pytest.fail("reader failed before the isolated hot update: " + reader_output)

        expected_path_configs = {
            public_id,
            other_public_id,
            race_public_id,
        }
        if auth_method == "http":
            expected_path_configs.add("~^[a-z0-9]{25}$")
        assert set(client.list_path_names()) == expected_path_configs
        with urllib.request.urlopen(
            f"http://127.0.0.1:{proxy_metrics_port}/metrics",
            timeout=2,
        ) as metrics_response:
            metric_lines = metrics_response.read().decode("utf-8").splitlines()
        assert f'paths{{name="{other_public_id}",state="ready"}} 1' in metric_lines
        assert (
            f'paths_readers{{name="{other_public_id}",readerType="rtspSession",state="ready"}} 1'
            in metric_lines
        )
        assert any(
            line.startswith("rtsp_sessions{")
            and f'path="{other_public_id}"' in line
            and 'state="read"' in line
            for line in metric_lines
        )
        assert not any(line.startswith("rtsps_") for line in metric_lines)

        if auth_server is not None:
            assert {
                (request["action"], request["path"], request["protocol"])
                for request in AuthCallbackHandler.valid_requests
            } >= {
                ("read", public_id, "rtsp"),
                ("read", other_public_id, "rtsp"),
            }

            denied_responses = {
                authenticated_describe_response(
                    host="127.0.0.1",
                    port=proxy_rtsp_port,
                    path=case_path,
                    username=case_username,
                    password=case_password,
                )
                for case_path, case_username, case_password in (
                    (public_id, "external", "wrong-secret"),
                    (public_id, "unknown-user", "lab-secret"),
                    ("z" * 25, "external", "lab-secret"),
                )
            }
            assert len(denied_responses) == 1
            assert next(iter(denied_responses)).startswith(b"RTSP/1.0 401 Unauthorized")

            def expect_new_session_denied() -> None:
                with pytest.raises(ProbeFailed, match="ffprobe_failed") as denied:
                    FfprobeRunner(
                        binary=Path(FFPROBE_BINARY),
                        io_timeout_seconds=2,
                        total_timeout_seconds=5,
                    ).inspect(
                        RtspEndpoint(
                            host="127.0.0.1",
                            port=proxy_rtsp_port,
                            path=public_id,
                            username="external",
                            password="lab-secret",
                        )
                    )
                assert "lab-secret" not in str(denied.value)

            AuthCallbackHandler.accept_credentials = False
            revoke_started_at = time.monotonic()
            expect_new_session_denied()
            assert time.monotonic() - revoke_started_at <= 10
            AuthCallbackHandler.accept_credentials = True

            auth_server.shutdown()
            auth_server.server_close()
            assert auth_thread is not None
            auth_thread.join(timeout=2)
            auth_server = None
            auth_thread = None
            expect_new_session_denied()

        client.put_path(
            MediaPathConfig(
                name=public_id,
                source_url=f"rtsp://127.0.0.1:{origin_rtsp_port}/different",
                source_on_demand=True,
            )
        )

        reader_output, _ = reader.communicate(timeout=10)
        assert reader.returncode == 0, (
            "reader of an unrelated path was interrupted: " + reader_output
        )
        reader = None

        proxy_output = stop_process(proxy)
        proxy = None
        for forbidden_secret in ("lab-secret", "wrong-secret"):
            assert forbidden_secret not in proxy_output
    finally:
        if auth_server is not None:
            auth_server.shutdown()
            auth_server.server_close()
        if auth_thread is not None:
            auth_thread.join(timeout=2)
        for process in (reader, proxy, publisher, origin):
            if process is not None:
                stop_process(process)
