from __future__ import annotations

import http.client
import os
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import time
from contextlib import suppress
from pathlib import Path

import pytest

pytestmark = pytest.mark.contract


def _command(*argv: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(argv),
        check=True,
        capture_output=True,
        text=True,
        timeout=20,
    )


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _systemctl(user_manager: bool, *arguments: str) -> list[str]:
    return ["systemctl", "--user", *arguments] if user_manager else ["systemctl", *arguments]


def _process_is_live(pid: int | None) -> bool:
    if pid is None:
        return False
    status_path = Path(f"/proc/{pid}/status")
    try:
        status = status_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return False
    state = next(
        (line for line in status.splitlines() if line.startswith("State:")),
        "",
    )
    fields = state.split()
    return len(fields) < 2 or fields[1] not in {"Z", "X", "x"}


def _port_has_listener(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.settimeout(0.2)
        return client.connect_ex(("127.0.0.1", port)) == 0


def _stop_and_reap(unit: str, *, user_manager: bool, pid: int | None, port: int) -> None:
    try:
        stop = subprocess.run(
            _systemctl(user_manager, "stop", unit),
            check=False,
            capture_output=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        stop = None
    cooperative_deadline = time.monotonic() + 2
    while _process_is_live(pid) and time.monotonic() < cooperative_deadline:
        time.sleep(0.05)
    if stop is None or stop.returncode != 0 or _process_is_live(pid):
        for arguments in (
            ("kill", "--kill-whom=all", "--signal=KILL", unit),
            ("stop", unit),
        ):
            with suppress(subprocess.TimeoutExpired):
                subprocess.run(
                    _systemctl(user_manager, *arguments),
                    check=False,
                    capture_output=True,
                    timeout=5,
                )
    reap_deadline = time.monotonic() + 5
    while time.monotonic() < reap_deadline:
        try:
            active = subprocess.run(
                _systemctl(user_manager, "is-active", "--quiet", unit),
                check=False,
                capture_output=True,
                timeout=2,
            ).returncode == 0
        except subprocess.TimeoutExpired:
            active = True
        if not active and not _process_is_live(pid) and not _port_has_listener(port):
            return
        time.sleep(0.05)
    raise AssertionError("management_https_systemd_cleanup_incomplete")


def _wait_for_main_pid(unit: str, *, user_manager: bool) -> int:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        result = subprocess.run(
            _systemctl(user_manager, "show", "--property=MainPID", "--value", unit),
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
        value = result.stdout.strip()
        if result.returncode == 0 and value.isdigit() and int(value) > 0:
            return int(value)
        time.sleep(0.05)
    raise AssertionError("management_https_systemd_service_not_ready")


def _credential_directory(unit: str, *, user_manager: bool) -> Path:
    if user_manager:
        return Path(f"/run/user/{os.geteuid()}/credentials") / unit
    return Path("/run/credentials") / unit


def _wait_for_https(port: int, *, ca_file: Path) -> tuple[bytes, str | None]:
    context = ssl.create_default_context(cafile=str(ca_file))
    deadline = time.monotonic() + 15
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
            hsts = response.getheader("Strict-Transport-Security")
            connection.close()
            if response.status == 200:
                return payload, hsts
        except (OSError, ssl.SSLError, http.client.HTTPException):
            time.sleep(0.05)
    raise AssertionError("management_https_systemd_listener_not_ready")


def _generate_ca_signed_ip_certificate(root: Path) -> tuple[Path, Path, Path]:
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("openssl is required for the native systemd HTTPS contract")
    ca_certificate = root / "management-test-ca.crt"
    ca_private_key = root / "management-test-ca.key"
    certificate = root / "management-tls.crt"
    private_key = root / "management-tls.key"
    request = root / "management-tls.csr"
    _command(
        openssl,
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "1",
        "-subj",
        "/CN=RTSP Proxy systemd contract CA",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-keyout",
        str(ca_private_key),
        "-out",
        str(ca_certificate),
    )
    _command(
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
        str(request),
    )
    _command(
        openssl,
        "x509",
        "-req",
        "-in",
        str(request),
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
    )
    certificate.chmod(0o600)
    private_key.chmod(0o600)
    return ca_certificate, certificate, private_key


def test_systemd_cleanup_kills_and_reaps_after_stop_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []
    stop_calls = 0

    def run_command(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        nonlocal stop_calls
        calls.append(tuple(argv))
        if "stop" in argv:
            stop_calls += 1
            if stop_calls == 1:
                raise subprocess.TimeoutExpired(argv, 10)
        if "is-active" in argv:
            return subprocess.CompletedProcess(argv, 3, b"", b"")
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(subprocess, "run", run_command)
    monkeypatch.setattr(
        "tests.contract.test_management_https_systemd._process_is_live",
        lambda _pid: False,
    )
    monkeypatch.setattr(
        "tests.contract.test_management_https_systemd._port_has_listener",
        lambda _port: False,
    )

    _stop_and_reap("contract.service", user_manager=False, pid=123, port=8443)

    assert any("kill" in call and "--signal=KILL" in call for call in calls)
    assert stop_calls == 2


@pytest.mark.skipif(
    os.environ.get("RTSP_PROXY_RUN_SYSTEMD_HTTPS_CONTRACT") != "1",
    reason="native systemd HTTPS contract is opt-in",
)
def test_systemd_loadcredential_serves_verified_management_https(tmp_path: Path) -> None:
    if sys.platform != "linux" or shutil.which("systemd-run") is None:
        pytest.skip("Linux systemd is required for the native HTTPS contract")
    ca_certificate, certificate, private_key = _generate_ca_signed_ip_certificate(tmp_path)
    credential_bundle = tmp_path / "management-tls.pem"
    credential_bundle.write_bytes(certificate.read_bytes() + private_key.read_bytes())
    credential_bundle.chmod(0o600)
    assert certificate.stat().st_uid == os.geteuid()
    assert private_key.stat().st_uid == os.geteuid()
    assert credential_bundle.stat().st_uid == os.geteuid()
    assert stat.S_IMODE(certificate.stat().st_mode) == 0o600
    assert stat.S_IMODE(private_key.stat().st_mode) == 0o600
    assert stat.S_IMODE(credential_bundle.stat().st_mode) == 0o600

    user_manager = os.geteuid() != 0
    unit = f"rtsp-proxy-management-https-contract-{os.getpid()}.service"
    port = _free_loopback_port()
    repository = Path.cwd().resolve(strict=True)
    runner = ["systemd-run"]
    if user_manager:
        runner.append("--user")
    runner.extend(
        [
            f"--unit={unit}",
            "--collect",
            "--property=Type=simple",
            f"--property=WorkingDirectory={repository}",
            f"--property=LoadCredential=management-tls.pem:{credential_bundle}",
        ]
    )
    if not user_manager:
        runner.append("--property=DynamicUser=yes")
    runner.extend(
        [
            "/bin/sh",
            "-ec",
            (
                'export PYTHONPATH="$1/src" '
                'RTSP_PROXY_ROLE="web" RTSP_PROXY_HTTP_HOST="127.0.0.1" '
                'RTSP_PROXY_HTTP_PORT="$2" '
                'RTSP_PROXY_MANAGEMENT_TLS_CERTIFICATE_FILE='
                '"/tmp/operator-controlled-certificate" '
                'RTSP_PROXY_MANAGEMENT_TLS_PRIVATE_KEY_FILE='
                '"/tmp/operator-controlled-private-key"; '
                'exec "$3" -c "from rtsp_proxy.runtime import run_web_cli; '
                'run_web_cli()" '
                '"--management-tls-certificate-file='
                '$CREDENTIALS_DIRECTORY/management-tls.pem" '
                '"--management-tls-private-key-file='
                '$CREDENTIALS_DIRECTORY/management-tls.pem"'
            ),
            "rtsp-proxy-management-https-contract",
            str(repository),
            str(port),
            sys.executable,
        ]
    )
    pid: int | None = None
    try:
        subprocess.run(runner, check=True, timeout=20)
        pid = _wait_for_main_pid(unit, user_manager=user_manager)
        status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
        service_uid = int(
            next(line for line in status.splitlines() if line.startswith("Uid:")).split()[1]
        )
        credentials_root = _credential_directory(unit, user_manager=user_manager)
        for name in ("management-tls.pem",):
            credential = credentials_root / name
            metadata = credential.stat()
            assert not credential.is_symlink()
            assert stat.S_ISREG(metadata.st_mode)
            assert stat.S_IMODE(metadata.st_mode) == 0o400
            assert metadata.st_uid == service_uid
            assert metadata.st_nlink == 1

        payload, hsts = _wait_for_https(port, ca_file=ca_certificate)
        assert b'"status":"ok"' in payload
        assert b'"role":"web"' in payload
        assert hsts == "max-age=31536000"
        plaintext = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
        with pytest.raises((ConnectionError, http.client.HTTPException)):
            plaintext.request("GET", "/health/live")
            plaintext.getresponse()
    finally:
        _stop_and_reap(unit, user_manager=user_manager, pid=pid, port=port)
