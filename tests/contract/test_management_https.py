from __future__ import annotations

import http.client
import os
import shutil
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path

import pytest


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _wait_for_https(
    port: int,
    *,
    ca_file: Path,
    timeout_seconds: float = 10,
) -> tuple[int, bytes, str | None]:
    context = ssl.create_default_context(cafile=str(ca_file))
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            connection = http.client.HTTPSConnection(
                "127.0.0.1",
                port,
                context=context,
                timeout=0.5,
            )
            connection.request("GET", "/health/live")
            response = connection.getresponse()
            payload = response.read()
            strict_transport_security = response.getheader("Strict-Transport-Security")
            connection.close()
            if response.status == 200 and b'"status":"ok"' in payload:
                return response.status, payload, strict_transport_security
        except (OSError, ssl.SSLError, http.client.HTTPException):
            time.sleep(0.05)
    raise AssertionError("management_https_listener_not_ready")


def test_web_entrypoint_serves_https_and_rejects_plaintext(tmp_path: Path) -> None:
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("openssl is required for the native HTTPS contract")
    ca_certificate = tmp_path / "management-test-ca.crt"
    ca_private_key = tmp_path / "management-test-ca.key"
    certificate = tmp_path / "management-tls.crt"
    private_key = tmp_path / "management-tls.key"
    certificate_request = tmp_path / "management-tls.csr"
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=RTSP Proxy HTTPS Contract CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout",
            str(ca_private_key),
            "-out",
            str(ca_certificate),
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            openssl,
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=127.0.0.1",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
            "-addext",
            "keyUsage=critical,digitalSignature,keyEncipherment",
            "-addext",
            "extendedKeyUsage=serverAuth",
            "-keyout",
            str(private_key),
            "-out",
            str(certificate_request),
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            openssl,
            "x509",
            "-req",
            "-in",
            str(certificate_request),
            "-CA",
            str(ca_certificate),
            "-CAkey",
            str(ca_private_key),
            "-CAcreateserial",
            "-days",
            "1",
            "-copy_extensions",
            "copy",
            "-out",
            str(certificate),
        ],
        check=True,
        capture_output=True,
    )
    private_key.chmod(0o600)
    certificate.chmod(0o600)
    port = _free_loopback_port()
    environment = os.environ.copy()
    environment.update(
        {
            "RTSP_PROXY_ROLE": "web",
            "RTSP_PROXY_HTTP_HOST": "127.0.0.1",
            "RTSP_PROXY_HTTP_PORT": str(port),
            "RTSP_PROXY_MANAGEMENT_TLS_CERTIFICATE_FILE": str(certificate),
            "RTSP_PROXY_MANAGEMENT_TLS_PRIVATE_KEY_FILE": str(private_key),
        }
    )
    process = subprocess.Popen(
        [sys.executable, "-c", "from rtsp_proxy.runtime import run_web; run_web()"],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        status, payload, strict_transport_security = _wait_for_https(
            port,
            ca_file=ca_certificate,
        )
        assert status == 200
        assert b'"role":"web"' in payload
        assert strict_transport_security == "max-age=31536000"
        plaintext = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
        with pytest.raises((ConnectionError, http.client.HTTPException)):
            plaintext.request("GET", "/health/live")
            plaintext.getresponse()
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
