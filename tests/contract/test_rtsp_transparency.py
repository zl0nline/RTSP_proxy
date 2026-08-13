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
import urllib.parse
import urllib.request
from base64 import b64encode
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar
from uuid import UUID

import pytest
import uvicorn

from rtsp_proxy.access import (
    AccessAuthorizer,
    AccessDecisionTelemetry,
    AccessGrant,
    AccessPolicy,
    AccessTarget,
    PepperVerifier,
)
from rtsp_proxy.app import create_media_auth_app
from rtsp_proxy.identifiers import PublicId
from rtsp_proxy.load_evidence import REQUIRED_SUT_METRIC_FAMILIES, read_mediamtx_metrics
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


def authenticated_http_request(url: str) -> urllib.request.Request:
    parts = urllib.parse.urlsplit(url)
    request_url = url
    headers: dict[str, str] = {}
    if parts.username is not None:
        hostname = parts.hostname or ""
        if ":" in hostname:
            hostname = f"[{hostname}]"
        authority = hostname if parts.port is None else f"{hostname}:{parts.port}"
        request_url = urllib.parse.urlunsplit(
            (parts.scheme, authority, parts.path, parts.query, parts.fragment)
        )
        credentials = (
            f"{urllib.parse.unquote(parts.username)}:"
            f"{urllib.parse.unquote(parts.password or '')}"
        )
        headers["Authorization"] = "Basic " + b64encode(credentials.encode()).decode()
    return urllib.request.Request(request_url, headers=headers)


def wait_for_json(url: str, process: subprocess.Popen[str], *, ready_path: bool = False) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output, _ = process.communicate()
            pytest.fail(f"external contract process exited early:\n{output}")
        try:
            with urllib.request.urlopen(authenticated_http_request(url), timeout=1) as response:
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


def put_lab_fanout_path(*, api_url: str, path: str, source_url: str) -> None:
    """Install one historical lab-only fan-out path outside the product adapter."""

    request = urllib.request.Request(
        f"{api_url}/v3/config/paths/replace/{path}",
        data=json.dumps(
            {
                "source": source_url,
                "sourceOnDemand": True,
                "sourceOnDemandCloseAfter": "10s",
                "rtspTransport": "tcp",
                "maxReaders": 4,
            }
        ).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=2) as response:
        assert response.status == 200


def metrics_lines(url: str) -> list[str]:
    with urllib.request.urlopen(authenticated_http_request(url), timeout=2) as response:
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


def wait_for_cold_race(*, origin_api_url: str, proxy_metrics_url: str, path_name: str) -> None:
    deadline = time.monotonic() + 10
    expected_proxy_readers = (
        f'paths_readers{{name="{path_name}",readerType="rtspSession",state="ready"}} 4'
    )
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(origin_api_url, timeout=1) as response:
                origin_path = json.load(response)
            if len(origin_path["readers"]) == 1 and expected_proxy_readers in metrics_lines(
                proxy_metrics_url
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


def assert_partial_rtsp_header_closes_at_media_read_timeout(host: str, port: int) -> None:
    started_at = time.monotonic()
    with socket.create_connection((host, port), timeout=2) as connection:
        connection.settimeout(2)
        connection.sendall(f"DESCRIBE rtsp://{host}:{port}/".encode())
        assert connection.recv(4096) == b""
    assert time.monotonic() - started_at >= 1
    assert time.monotonic() - started_at < 2


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


class NativeAccessStore:
    def __init__(
        self,
        *,
        target: AccessTarget,
        grant: AccessGrant,
    ) -> None:
        self.target = target
        self.grant = grant
        self.calls: list[str] = []
        self._lock = threading.Lock()

    def get_access_target(
        self,
        *,
        node_id: UUID,
        public_id: PublicId,
    ) -> AccessTarget | None:
        with self._lock:
            self.calls.append("target")
            return self.target if (node_id, public_id) == (
                self.target.node_id,
                self.target.public_id,
            ) else None

    def get_access_grant(
        self,
        *,
        camera_id: UUID,
        username: str,
    ) -> AccessGrant | None:
        with self._lock:
            self.calls.append("grant")
            return self.grant if (camera_id, username) == (
                self.grant.camera_id,
                self.grant.username,
            ) else None

    def rehash_access_grant(
        self,
        grant_id: UUID,
        *,
        token_verifier: str,
        pepper_key_id: str,
        expected_revision: int,
    ) -> bool:
        with self._lock:
            if self.grant.id != grant_id or self.grant.revision != expected_revision:
                return False
            self.grant = replace(
                self.grant,
                token_verifier=token_verifier,
                pepper_key_id=pepper_key_id,
                revision=expected_revision + 1,
            )
            return True

    def mark_access_grant_used(self, grant_id: UUID) -> bool:
        with self._lock:
            if self.grant.id == grant_id:
                self.grant = replace(self.grant, last_used_at=datetime.now(UTC))
                return True
            return False


def start_native_auth_server(
    *,
    port: int,
    authorizer: AccessAuthorizer,
    callback_verifier: PepperVerifier,
    telemetry: AccessDecisionTelemetry | None = None,
) -> tuple[uvicorn.Server, threading.Thread]:
    server = uvicorn.Server(
        uvicorn.Config(
            create_media_auth_app(
                authorizer=authorizer,
                callback_verifier=callback_verifier,
                telemetry=telemetry,
            ),
            host="127.0.0.1",
            port=port,
            log_level="warning",
            access_log=False,
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/health/live",
                timeout=1,
            ) as response:
                if response.status == 200:
                    return server, thread
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(0.1)
    server.should_exit = True
    thread.join(timeout=2)
    pytest.fail("native access callback did not become ready")


@pytest.mark.parametrize(
    ("encoder", "codec_name"),
    (("libx264", "h264"), ("libx265", "hevc")),
)
def test_real_access_callback_acl_revoke_drain_and_single_reader_race(
    tmp_path: Path,
    encoder: str,
    codec_name: str,
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
    ) = unused_tcp_ports(6)
    node_id = UUID("20000000-0000-0000-0000-000000000002")
    camera_id = UUID("10000000-0000-0000-0000-000000000001")
    grant_id = UUID("30000000-0000-0000-0000-000000000003")
    public_id = PublicId.parse("m" * 25 + "a")
    secret = "N" * 43
    now = datetime.now(UTC)
    pepper = PepperVerifier(primary_key_id="native", keys={"native": b"p" * 32})
    store = NativeAccessStore(
        target=AccessTarget(
            camera_id=camera_id,
            node_id=node_id,
            public_id=public_id,
            enabled=True,
            policy=AccessPolicy(
                camera_id=camera_id,
                revision=1,
                internet_cidrs=("203.0.113.0/24",),
            ),
        ),
        grant=AccessGrant(
            id=grant_id,
            camera_id=camera_id,
            username=f"grant-{grant_id.hex}",
            token_verifier=pepper.digest(secret),
            pepper_key_id=pepper.primary_key_id,
            not_before=now - timedelta(seconds=1),
            expires_at=now + timedelta(hours=1),
            revoked_at=None,
            revision=1,
        ),
    )
    telemetry = AccessDecisionTelemetry()
    origin_config = tmp_path / f"origin-{codec_name}.yml"
    origin_config.write_text(
        f"""
logLevel: warn
authMethod: internal
authInternalUsers:
  - user: any
    pass:
    ips: ["127.0.0.1", "::1"]
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
rtspEncryption: "no"
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
    proxy_config = tmp_path / f"proxy-{codec_name}.yml"
    callback_user, callback_password = pepper.callback_credentials(node_id)
    proxy_config.write_text(
        f"""
logLevel: warn
authMethod: http
authInternalUsers:
  - user: node-management
    pass: node-management-secret
    ips: ["127.0.0.1", "::1"]
    permissions:
      - action: api
      - action: metrics
authHTTPAddress: http://{callback_user}:{callback_password}@127.0.0.1:{auth_port}/internal/v1/media-auth/{node_id}
authHTTPExclude: []
api: true
apiAddress: 127.0.0.1:{proxy_api_port}
metrics: true
metricsAddress: 127.0.0.1:{proxy_metrics_port}
pprof: false
playback: false
rtsp: true
rtspTransports: [tcp]
rtspEncryption: "no"
rtspAddress: 127.0.0.1:{proxy_rtsp_port}
rtmp: false
hls: false
webrtc: false
srt: false
moq: false
paths:
  "~^[a-z2-7]{{25}}[aeimquy4]$": {{}}
""".lstrip(),
        encoding="utf-8",
    )
    origin = start_process([MEDIA_MTX_BINARY, str(origin_config)])
    publisher: subprocess.Popen[str] | None = None
    proxy: subprocess.Popen[str] | None = None
    established: subprocess.Popen[str] | None = None
    auth_server: uvicorn.Server | None = None
    auth_thread: threading.Thread | None = None
    proxy_output = ""
    try:
        auth_server, auth_thread = start_native_auth_server(
            port=auth_port,
            authorizer=AccessAuthorizer(
                store=store,
                verifier=pepper,
                decision_sink=telemetry,
            ),
            callback_verifier=pepper,
            telemetry=telemetry,
        )
        wait_for_json(f"http://127.0.0.1:{origin_api_port}/v3/config/global/get", origin)
        encoder_options = (
            ["-preset", "ultrafast", "-tune", "zerolatency", "-g", "10"]
            if encoder == "libx264"
            else [
                "-preset",
                "ultrafast",
                "-x265-params",
                "pools=1:frame-threads=1:keyint=10:min-keyint=10:scenecut=0",
            ]
        )
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
                encoder,
                *encoder_options,
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
        management_url = (
            f"http://node-management:node-management-secret@127.0.0.1:{proxy_api_port}"
        )
        wait_for_json(f"{management_url}/v3/config/global/get", proxy)
        with pytest.raises(urllib.error.HTTPError) as unauthenticated:
            urllib.request.urlopen(
                f"http://127.0.0.1:{proxy_api_port}/v3/config/global/get",
                timeout=2,
            )
        assert unauthenticated.value.code == 401
        with pytest.raises(urllib.error.HTTPError) as bad_management:
            request = urllib.request.Request(
                f"http://127.0.0.1:{proxy_api_port}/v3/config/global/get",
                headers={"Authorization": "Basic " + b64encode(b"wrong:wrong").decode()},
            )
            # MediaMTX deliberately delays supplied invalid credentials by a
            # random 0-4 seconds. Keep the native boundary above that bounded
            # anti-bruteforce window while the manager regression proves that
            # this management miss never reaches the external callback.
            urllib.request.urlopen(request, timeout=6)
        assert bad_management.value.code == 401
        media = MediaMtxClient(
            api_url=f"http://127.0.0.1:{proxy_api_port}",
            timeout_seconds=2,
            username="node-management",
            password="node-management-secret",
        )
        media.put_path(
            MediaPathConfig(
                name=public_id,
                source_url=(
                    f"rtsp://origin-reader:origin-secret@127.0.0.1:{origin_rtsp_port}/fixture"
                ),
            )
        )
        denied_acl = authenticated_describe_response(
            host="127.0.0.1",
            port=proxy_rtsp_port,
            path=str(public_id),
            username=store.grant.username,
            password=secret,
        )
        assert denied_acl.startswith(b"RTSP/1.0 401 Unauthorized")
        assert store.calls[-1] == "target"
        store.target = replace(
            store.target,
            policy=AccessPolicy(
                camera_id=camera_id,
                revision=2,
                local_cidrs=("127.0.0.0/8",),
            ),
        )
        valid = run_lab_ffprobe(
            binary=FFPROBE_BINARY,
            host="127.0.0.1",
            port=proxy_rtsp_port,
            path=str(public_id),
            username=store.grant.username,
            password=secret,
        )
        assert valid.returncode == 0, valid.stderr
        assert json.loads(valid.stdout)["streams"][0]["codec_name"] == codec_name
        with urllib.request.urlopen(
            f"http://127.0.0.1:{auth_port}/internal/v1/metrics",
            timeout=2,
        ) as response:
            auth_metrics = response.read().decode("utf-8")
        assert (
            'reason="allowed",allowed="true",action="read",protocol="rtsp",'
            'peer_family="ipv4"'
        ) in auth_metrics

        race_barrier = threading.Barrier(2)

        def race_reader() -> subprocess.CompletedProcess[str]:
            race_barrier.wait(timeout=5)
            return run_lab_ffmpeg_reader(
                binary=FFMPEG_BINARY,
                host="127.0.0.1",
                port=proxy_rtsp_port,
                path=str(public_id),
                username=store.grant.username,
                password=secret,
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            raced = [executor.submit(race_reader) for _ in range(2)]
            results = [future.result() for future in raced]
        assert sorted(result.returncode == 0 for result in results) == [False, True]
        rejected = next(result for result in results if result.returncode != 0)
        assert re.search(r"\b453\s*\(?Not Enough Bandwidth\)?", rejected.stderr)

        established = start_process(
            [
                FFMPEG_BINARY,
                "-hide_banner",
                "-nostdin",
                "-loglevel",
                "error",
                "-rtsp_transport",
                "tcp",
                "-i",
                (
                    f"rtsp://{store.grant.username}:{secret}@127.0.0.1:"
                    f"{proxy_rtsp_port}/{public_id}"
                ),
                "-map",
                "0:v:0",
                "-f",
                "null",
                "-",
            ]
        )
        metrics_url = (
            f"http://node-management:node-management-secret@127.0.0.1:"
            f"{proxy_metrics_port}/metrics"
        )
        wait_for_reader(metrics_url, path_name=str(public_id))
        before = metric_value(
            metrics_lines(metrics_url),
            "paths_outbound_bytes",
            path_name=str(public_id),
        )
        store.grant = replace(store.grant, revoked_at=datetime.now(UTC), revision=2)
        revoked = authenticated_describe_response(
            host="127.0.0.1",
            port=proxy_rtsp_port,
            path=str(public_id),
            username=store.grant.username,
            password=secret,
        )
        assert revoked.startswith(b"RTSP/1.0 401 Unauthorized")
        after_revoke = wait_for_rtp_progress_from_metric(
            established,
            metrics_url,
            str(public_id),
            before,
        )
        store.grant = replace(store.grant, revoked_at=None, revision=3)
        store.target = replace(store.target, enabled=False)
        drained = authenticated_describe_response(
            host="127.0.0.1",
            port=proxy_rtsp_port,
            path=str(public_id),
            username=store.grant.username,
            password=secret,
        )
        assert drained == revoked
        wait_for_rtp_progress_from_metric(
            established,
            metrics_url,
            str(public_id),
            after_revoke,
        )
        auth_server.should_exit = True
        auth_thread.join(timeout=5)
        assert not auth_thread.is_alive()
        auth_server = None
        auth_thread = None
        assert established.poll() is None
        assert process_owned_udp_sockets(proxy) == frozenset()
    finally:
        if auth_server is not None:
            auth_server.should_exit = True
        if auth_thread is not None:
            auth_thread.join(timeout=5)
        if established is not None:
            stop_process(established)
        if proxy is not None:
            proxy_output = stop_process(proxy)
        for process in (publisher, origin):
            if process is not None:
                stop_process(process)
    assert secret not in proxy_output


def wait_for_rtp_progress_from_metric(
    reader: subprocess.Popen[str],
    metrics_url: str,
    path_name: str,
    before: float,
) -> float:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if reader.poll() is not None:
            output, _ = reader.communicate(timeout=1)
            pytest.fail(f"established reader exited unexpectedly: {output}")
        after = metric_value(
            metrics_lines(metrics_url),
            "paths_outbound_bytes",
            path_name=path_name,
        )
        if after > before:
            return after
        time.sleep(0.1)
    pytest.fail("established reader stopped making RTP progress")


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
    ) = unused_tcp_ports(8)
    public_id = "f" * 25 + "a"
    other_public_id = "g" * 25 + "a"
    race_public_id = "h" * 25 + "a"
    failing_source_public_id = "k" * 25 + "a"
    unknown_public_id = "j" * 25 + "a"

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
            "authHTTPExclude: []",
        ).replace("paths: {}", 'paths:\n  "~^[a-z2-7]{25}[aeimquy4]$": {}')
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
        assert_partial_rtsp_header_closes_at_media_read_timeout("127.0.0.1", timeout_rtsp_port)
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
        proxy_management_url = (
            f"http://any@127.0.0.1:{proxy_api_port}/v3/config/global/get"
            if auth_method == "http"
            else f"http://127.0.0.1:{proxy_api_port}/v3/config/global/get"
        )
        wait_for_json(proxy_management_url, proxy)
        udp_socket_baseline = process_owned_udp_sockets(proxy)
        assert not udp_socket_baseline
        client = MediaMtxClient(
            api_url=f"http://127.0.0.1:{proxy_api_port}",
            timeout_seconds=2,
            username="any" if auth_method == "http" else None,
            password="" if auth_method == "http" else None,
        )
        client.put_path(
            MediaPathConfig(
                name=PublicId.parse(public_id),
                source_url=(
                    f"rtsp://origin-reader:origin-secret@127.0.0.1:{origin_rtsp_port}/fixture"
                ),
            )
        )
        client.put_path(
            MediaPathConfig(
                name=PublicId.parse(other_public_id),
                source_url=(
                    f"rtsp://origin-reader:origin-secret@127.0.0.1:{origin_rtsp_port}/fixture"
                ),
            )
        )
        put_lab_fanout_path(
            api_url=f"http://127.0.0.1:{proxy_api_port}",
            path=race_public_id,
            source_url=(
                f"rtsp://origin-reader:origin-secret@127.0.0.1:{origin_rtsp_port}/fixture"
            ),
        )
        client.put_path(
            MediaPathConfig(
                name=PublicId.parse(failing_source_public_id),
                source_url=(
                    f"rtsp://origin-reader:wrong-source-secret@127.0.0.1:{origin_rtsp_port}/fixture"
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
                origin_api_url=(f"http://127.0.0.1:{origin_api_port}/v3/paths/get/fixture"),
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
            Path("docs/evidence/mediamtx-v1.20.0-metrics-schema.json").read_text(encoding="utf-8")
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
        typed_metrics = read_mediamtx_metrics(metrics_url)
        assert typed_metrics.observed_families == REQUIRED_SUT_METRIC_FAMILIES
        assert typed_metrics.total_rtsp_sessions >= 1
        assert typed_metrics.ready_runtime_paths >= 1
        assert typed_metrics.active_sessions
        assert typed_metrics.active_paths
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
                overload_results = list(
                    executor.map(
                        lambda _: (
                            run_lab_ffprobe(
                                binary=FFPROBE_BINARY,
                                host="127.0.0.1",
                                port=proxy_rtsp_port,
                                path=public_id,
                                username="external",
                                password="lab-secret",
                            ).returncode
                        ),
                        range(4),
                    )
                )
            assert all(returncode != 0 for returncode in overload_results)
            assert AuthCallbackHandler.peak_active_requests >= 1
            drain_deadline = time.monotonic() + 15
            zero_since: float | None = None
            while time.monotonic() < drain_deadline:
                with AuthCallbackHandler.request_lock:
                    active_requests = AuthCallbackHandler.active_requests
                if active_requests == 0:
                    zero_since = zero_since or time.monotonic()
                    if time.monotonic() - zero_since >= 0.5:
                        break
                else:
                    zero_since = None
                time.sleep(0.1)
            assert AuthCallbackHandler.active_requests == 0
            assert reader.poll() is None
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
                    f"rtsp://origin-reader:origin-secret@127.0.0.1:{origin_rtsp_port}/different"
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
