from __future__ import annotations

import json
import os
import re
import signal
import socket
import subprocess
import sys
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

from rtsp_proxy.identifiers import PublicId
from rtsp_proxy.media import MediaMtxClient, MediaPathConfig

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
    with socket.create_connection((host, port), timeout=10) as connection:
        connection.settimeout(10)
        connection.sendall(request)
        response = bytearray()
        while b"\r\n\r\n" not in response:
            chunk = connection.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
        headers, separator, body = bytes(response).partition(b"\r\n\r\n")
        content_length = 0
        for header in headers.split(b"\r\n")[1:]:
            name, delimiter, value = header.partition(b":")
            if delimiter and name.lower() == b"content-length":
                content_length = int(value.strip())
        while len(body) < content_length:
            chunk = connection.recv(min(4096, content_length - len(body)))
            if not chunk:
                break
            body += chunk
    return headers + separator + body[:content_length]


def run_lab_ffprobe(
    *,
    binary: str,
    host: str,
    port: int,
    path: str,
    username: str,
    password: str,
    transport: str = "tcp",
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            binary,
            "-v",
            "error",
            "-rtsp_transport",
            transport,
            "-timeout",
            "5000000",
            "-show_entries",
            "stream=codec_type,codec_name,width,height",
            "-of",
            "json",
            f"rtsp://{username}:{password}@{host}:{port}/{path}",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )


def run_lab_ffmpeg_reader(
    *, binary: str, host: str, port: int, path: str, username: str, password: str
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            binary,
            "-hide_banner",
            "-loglevel",
            "error",
            "-rtsp_transport",
            "tcp",
            "-i",
            f"rtsp://{username}:{password}@{host}:{port}/{path}",
            "-t",
            "3",
            "-map",
            "0:v:0",
            "-f",
            "null",
            "-",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


def metrics_lines(url: str) -> list[str]:
    with urllib.request.urlopen(url, timeout=2) as response:
        payload = response.read()
    assert isinstance(payload, bytes)
    return payload.decode("utf-8").splitlines()


def metric_value(lines: list[str], family: str, *, path_name: str) -> float:
    for line in lines:
        if line.startswith(f"{family}{{") and f'name="{path_name}"' in line:
            return float(line.rsplit(" ", 1)[1])
    pytest.fail(f"metric {family} for the expected path is absent")


def metric_schema(lines: list[str]) -> dict[str, list[str]]:
    schema: dict[str, set[str]] = {}
    for line in lines:
        if not line or line.startswith("#"):
            continue
        metric, _, _value = line.rpartition(" ")
        family, separator, raw_labels = metric.partition("{")
        labels = set(re.findall(r'(\w+)="', raw_labels)) if separator else set()
        schema.setdefault(family, set()).update(labels)
    return {family: sorted(labels) for family, labels in sorted(schema.items())}


def wait_for_reader(metrics_url: str, *, path_name: str) -> None:
    deadline = time.monotonic() + 10
    expected = f'paths_readers{{name="{path_name}",readerType="rtspSession",state="ready"}} 1'
    while time.monotonic() < deadline:
        if expected in metrics_lines(metrics_url):
            return
        time.sleep(0.1)
    pytest.fail("RTSP reader did not become observable within 10 seconds")


def wait_for_cold_race(
    *, origin_api_url: str, proxy_metrics_url: str, path_name: str
) -> None:
    deadline = time.monotonic() + 10
    expected_proxy_readers = (
        f'paths_readers{{name="{path_name}",readerType="rtspSession",state="ready"}} 4'
    )
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(origin_api_url, timeout=1) as response:
                origin_path = json.load(response)
            if (
                len(origin_path["readers"]) == 1
                and expected_proxy_readers in metrics_lines(proxy_metrics_url)
            ):
                return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(0.1)
    pytest.fail("cold-reader race did not converge to one upstream and four readers")


def assert_reader_progress(
    reader: subprocess.Popen[str], metrics_url: str, *, path_name: str
) -> None:
    before = metric_value(metrics_lines(metrics_url), "paths_outbound_bytes", path_name=path_name)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if reader.poll() is not None:
            output, _ = reader.communicate(timeout=1)
            pytest.fail(
                f"established reader exited before progress: "
                f"returncode={reader.returncode}, output={output!r}"
            )
        after = metric_value(
            metrics_lines(metrics_url), "paths_outbound_bytes", path_name=path_name
        )
        if after > before:
            return
        time.sleep(0.1)
    pytest.fail("established reader bytes did not progress within five seconds")


def process_owned_udp_sockets(
    process: subprocess.Popen[str],
) -> frozenset[tuple[str, str, str]]:
    if not sys.platform.startswith("linux"):
        return frozenset()
    socket_inodes = {
        target.removeprefix("socket:[").removesuffix("]")
        for fd in (Path("/proc") / str(process.pid) / "fd").iterdir()
        if (target := os.readlink(fd)).startswith("socket:[")
    }
    sockets: set[tuple[str, str, str]] = set()
    for table_name in ("udp", "udp6"):
        table = Path("/proc") / str(process.pid) / "net" / table_name
        for line in table.read_text(encoding="utf-8").splitlines()[1:]:
            fields = line.split()
            if fields[9] in socket_inodes:
                sockets.add((table_name, fields[1], fields[2]))
    return frozenset(sockets)


def assert_partial_rtsp_header_outlives_media_read_timeout(host: str, port: int) -> None:
    started_at = time.monotonic()
    with socket.create_connection((host, port), timeout=2) as connection:
        connection.settimeout(1.5)
        connection.sendall(f"DESCRIBE rtsp://{host}:{port}/".encode())
        with pytest.raises(TimeoutError):
            connection.recv(4096)
    assert time.monotonic() - started_at >= 1


class AuthCallbackServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128


class AuthCallbackHandler(BaseHTTPRequestHandler):
    accepted_paths: ClassVar[set[str]] = set()
    valid_requests: ClassVar[list[dict[str, object]]] = []
    accept_credentials: ClassVar[bool] = True
    response_delay_seconds: ClassVar[float] = 0
    active_requests: ClassVar[int] = 0
    peak_active_requests: ClassVar[int] = 0
    request_lock: ClassVar[threading.Lock] = threading.Lock()

    def do_POST(self) -> None:
        with self.request_lock:
            type(self).active_requests += 1
            type(self).peak_active_requests = max(
                type(self).peak_active_requests,
                type(self).active_requests,
            )
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length))
            time.sleep(self.response_delay_seconds)
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
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            with self.request_lock:
                type(self).active_requests -= 1

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
        timeout_api_port,
        timeout_rtsp_port,
    ) = (
        unused_tcp_ports(8)
    )
    public_id = "f" * 25
    other_public_id = "g" * 25
    race_public_id = "h" * 25
    failing_source_public_id = "i" * 25
    unknown_public_id = "j" * 25

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
  - user: origin-reader
    pass: origin-secret
    permissions:
      - action: read
        path: fixture
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

    timeout_config = tmp_path / "timeout-proxy.yml"
    timeout_config.write_text(
        f"""
logLevel: warn
logDestinations: [stdout]
readTimeout: 1s
authMethod: internal
authInternalUsers:
  - user: any
    pass:
    ips: ["127.0.0.1", "::1"]
    permissions:
      - action: api
api: true
apiAddress: 127.0.0.1:{timeout_api_port}
metrics: false
pprof: false
playback: false
rtsp: true
rtspTransports: [tcp]
rtspEncryption: "no"
rtspAddress: 127.0.0.1:{timeout_rtsp_port}
rtmp: false
hls: false
webrtc: false
srt: false
moq: false
paths: {{}}
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
            f"        path: ~^({public_id}|{other_public_id}|{race_public_id}|"
            f"{failing_source_public_id})$\n",
        ),
        encoding="utf-8",
    )

    origin = start_process([MEDIA_MTX_BINARY, str(origin_config)])
    publisher: subprocess.Popen[str] | None = None
    proxy: subprocess.Popen[str] | None = None
    reader: subprocess.Popen[str] | None = None
    timeout_proxy: subprocess.Popen[str] | None = None
    auth_server: ThreadingHTTPServer | None = None
    auth_thread: threading.Thread | None = None
    try:
        if auth_method == "http":
            AuthCallbackHandler.accepted_paths = {
                public_id,
                other_public_id,
                race_public_id,
                failing_source_public_id,
            }
            AuthCallbackHandler.valid_requests = []
            AuthCallbackHandler.accept_credentials = True
            AuthCallbackHandler.response_delay_seconds = 0
            AuthCallbackHandler.active_requests = 0
            AuthCallbackHandler.peak_active_requests = 0
            auth_server = AuthCallbackServer(
                ("127.0.0.1", auth_port),
                AuthCallbackHandler,
            )
            auth_thread = threading.Thread(target=auth_server.serve_forever, daemon=True)
            auth_thread.start()

        wait_for_json(
            f"http://127.0.0.1:{origin_api_port}/v3/config/global/get",
            origin,
        )
        timeout_proxy = start_process([MEDIA_MTX_BINARY, str(timeout_config)])
        wait_for_json(
            f"http://127.0.0.1:{timeout_api_port}/v3/config/global/get",
            timeout_proxy,
        )
        assert_partial_rtsp_header_outlives_media_read_timeout(
            "127.0.0.1", timeout_rtsp_port
        )
        stop_process(timeout_proxy)
        timeout_proxy = None
        publisher = start_process(
            [
                FFMPEG_BINARY,
                "-hide_banner",
                "-nostdin",
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
        udp_socket_baseline = process_owned_udp_sockets(proxy)
        assert not udp_socket_baseline
        client = MediaMtxClient(
            api_url=f"http://127.0.0.1:{proxy_api_port}",
            timeout_seconds=2,
        )
        client.put_path(
            MediaPathConfig(
                name=PublicId.parse(public_id),
                source_url=(
                    f"rtsp://origin-reader:origin-secret@127.0.0.1:{origin_rtsp_port}"
                    "/fixture"
                ),
            )
        )
        client.put_path(
            MediaPathConfig(
                name=PublicId.parse(other_public_id),
                source_url=(
                    f"rtsp://origin-reader:origin-secret@127.0.0.1:{origin_rtsp_port}"
                    "/fixture"
                ),
            )
        )
        client.put_path(
            MediaPathConfig(
                name=PublicId.parse(race_public_id),
                source_url=(
                    f"rtsp://origin-reader:origin-secret@127.0.0.1:{origin_rtsp_port}"
                    "/fixture"
                ),
            )
        )
        client.put_path(
            MediaPathConfig(
                name=PublicId.parse(failing_source_public_id),
                source_url=(
                    f"rtsp://origin-reader:wrong-source-secret@127.0.0.1:"
                    f"{origin_rtsp_port}/fixture"
                ),
            )
        )

        failing_source_probe = run_lab_ffprobe(
            binary=FFPROBE_BINARY,
            host="127.0.0.1",
            port=proxy_rtsp_port,
            path=failing_source_public_id,
            username="external",
            password="lab-secret",
        )
        assert failing_source_probe.returncode != 0

        metrics_url = f"http://127.0.0.1:{proxy_metrics_port}/metrics"

        def consume_cold_path() -> subprocess.CompletedProcess[str]:
            return run_lab_ffmpeg_reader(
                binary=FFMPEG_BINARY,
                host="127.0.0.1",
                port=proxy_rtsp_port,
                path=race_public_id,
                username="external",
                password="lab-secret",
            )

        with ThreadPoolExecutor(max_workers=4) as executor:
            cold_readers = [executor.submit(consume_cold_path) for _ in range(4)]
            wait_for_cold_race(
                origin_api_url=(
                    f"http://127.0.0.1:{origin_api_port}/v3/paths/get/fixture"
                ),
                proxy_metrics_url=metrics_url,
                path_name=race_public_id,
            )
            assert all(reader.result().returncode == 0 for reader in cold_readers)

        result = run_lab_ffprobe(
            binary=FFPROBE_BINARY,
            host="127.0.0.1",
            port=proxy_rtsp_port,
            path=public_id,
            username="external",
            password="lab-secret",
        )
        assert result.returncode == 0, "ffprobe failed against the ordinary RTSP endpoint"
        assert json.loads(result.stdout)["streams"] == [
            {"codec_name": "h264", "codec_type": "video", "width": 160, "height": 120}
        ]

        udp_result = run_lab_ffprobe(
            binary=FFPROBE_BINARY,
            host="127.0.0.1",
            port=proxy_rtsp_port,
            path=public_id,
            username="external",
            password="lab-secret",
            transport="udp",
        )
        assert udp_result.returncode != 0, "UDP transport was unexpectedly admitted"
        assert process_owned_udp_sockets(proxy) == udp_socket_baseline

        reader = start_process(
            [
                FFMPEG_BINARY,
                "-hide_banner",
                "-nostdin",
                "-loglevel",
                "error",
                "-rtsp_transport",
                "tcp",
                "-i",
                f"rtsp://external:lab-secret@127.0.0.1:{proxy_rtsp_port}/{other_public_id}",
                "-map",
                "0:v:0",
                "-f",
                "null",
                "-",
            ]
        )
        wait_for_reader(metrics_url, path_name=other_public_id)
        assert reader.poll() is None
        assert process_owned_udp_sockets(proxy) == udp_socket_baseline
        assert_reader_progress(reader, metrics_url, path_name=other_public_id)

        expected_camera_ids = {
            PublicId.parse(public_id),
            PublicId.parse(other_public_id),
            PublicId.parse(race_public_id),
            PublicId.parse(failing_source_public_id),
        }
        inventory = client.inventory_paths()
        assert set(inventory.camera_ids) == expected_camera_ids
        assert inventory.no_oracle_matcher_present is (auth_method == "http")
        observed_metrics = metrics_lines(metrics_url)
        schema_contract = json.loads(
            Path("docs/evidence/mediamtx-v1.20.0-metrics-schema.json").read_text(
                encoding="utf-8"
            )
        )
        assert metric_schema(observed_metrics) == schema_contract["families"]
        assert not any(line.startswith(("# HELP ", "# TYPE ")) for line in observed_metrics)
        assert f'paths{{name="{other_public_id}",state="ready"}} 1' in observed_metrics
        assert (
            f'paths_readers{{name="{other_public_id}",readerType="rtspSession",state="ready"}} 1'
            in observed_metrics
        )
        assert any(
            line.startswith("rtsp_sessions{")
            and f'path="{other_public_id}"' in line
            and 'state="read"' in line
            for line in observed_metrics
        )
        assert not any(line.startswith("rtsps_") for line in observed_metrics)

        if auth_server is not None:
            assert {
                (request["action"], request["path"], request["protocol"])
                for request in AuthCallbackHandler.valid_requests
            } >= {
                ("read", public_id, "rtsp"),
                ("read", other_public_id, "rtsp"),
            }

            def expect_new_session_denied() -> None:
                denied = run_lab_ffprobe(
                    binary=FFPROBE_BINARY,
                    host="127.0.0.1",
                    port=proxy_rtsp_port,
                    path=public_id,
                    username="external",
                    password="lab-secret",
                )
                assert denied.returncode != 0

            AuthCallbackHandler.accept_credentials = False
            revoke_started_at = time.monotonic()
            expect_new_session_denied()
            assert time.monotonic() - revoke_started_at <= 10

            denial_cases = (
                (public_id, "external", "lab-secret"),
                (public_id, "external", "wrong-secret"),
                (public_id, "unknown-user", "lab-secret"),
                (unknown_public_id, "external", "lab-secret"),
            )
            denied_responses = {
                authenticated_describe_response(
                    host="127.0.0.1",
                    port=proxy_rtsp_port,
                    path=case_path,
                    username=case_username,
                    password=case_password,
                )
                for case_path, case_username, case_password in denial_cases
            }

            assert len(denied_responses) == 1
            canonical_denial = next(iter(denied_responses))
            assert canonical_denial.startswith(b"RTSP/1.0 401 Unauthorized")

            assert_reader_progress(reader, metrics_url, path_name=other_public_id)
            AuthCallbackHandler.accept_credentials = True

            AuthCallbackHandler.response_delay_seconds = 2
            AuthCallbackHandler.peak_active_requests = 0
            with ThreadPoolExecutor(max_workers=4) as executor:
                overload_results = list(executor.map(lambda _: run_lab_ffprobe(
                    binary=FFPROBE_BINARY,
                    host="127.0.0.1",
                    port=proxy_rtsp_port,
                    path=public_id,
                    username="external",
                    password="lab-secret",
                ).returncode, range(4)))
            assert all(returncode != 0 for returncode in overload_results)
            assert AuthCallbackHandler.peak_active_requests >= 2
            assert_reader_progress(reader, metrics_url, path_name=other_public_id)
            AuthCallbackHandler.response_delay_seconds = 0

            auth_server.shutdown()
            auth_server.server_close()
            assert auth_thread is not None
            auth_thread.join(timeout=2)
            auth_server = None
            auth_thread = None
            expect_new_session_denied()
            assert_reader_progress(reader, metrics_url, path_name=other_public_id)

        client.put_path(
            MediaPathConfig(
                name=PublicId.parse(public_id),
                source_url=(
                    f"rtsp://origin-reader:origin-secret@127.0.0.1:{origin_rtsp_port}"
                    "/different"
                ),
            )
        )

        assert_reader_progress(reader, metrics_url, path_name=other_public_id)
        assert reader.poll() is None
        stop_process(reader)
        reader = None

        proxy_output = stop_process(proxy)
        proxy = None
        for forbidden_secret in (
            "lab-secret",
            "wrong-secret",
            "origin-reader",
            "origin-secret",
            "wrong-source-secret",
        ):
            assert forbidden_secret not in proxy_output
    finally:
        if auth_server is not None:
            auth_server.shutdown()
            auth_server.server_close()
        if auth_thread is not None:
            auth_thread.join(timeout=2)
        for process in (reader, timeout_proxy, proxy, publisher, origin):
            if process is not None:
                stop_process(process)
