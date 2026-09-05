from __future__ import annotations

import json
import os
import pwd
import re
import runpy
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from uuid import UUID, uuid4

import pytest

pytestmark = [
    pytest.mark.contract,
    pytest.mark.skipif(
        os.environ.get("RTSP_PROXY_RUN_PROBE_BROKER_CONTRACT") != "1",
        reason="installed root probe broker contract is opt-in",
    ),
    pytest.mark.skipif(sys.platform != "linux", reason="Linux root broker contract"),
]

_BROKER_UNIT = "rtsp-proxy-probe-broker.service"
_BROKER_CLIENT_ENV = "RTSP_PROXY_PROBE_BROKER_CLIENT"
_CONTRACT_RELEASE = Path("/opt/rtsp-proxy/releases/probe-contract")
_CURRENT_RELEASE = Path("/opt/rtsp-proxy/current")
_PIN_ROOT = Path("/sys/fs/bpf/rtsp-proxy-probe-broker")
_OWNERSHIP_ROOT = Path("/run/rtsp-proxy-probe-broker/guard-ownership")
_SECRET_CANARY = "probe-broker-secret-canary"
_HOSTILE_INPUT_CASES = runpy.run_path(
    str(Path("tests/fixtures/probe_broker_client.py"))
)["HOSTILE_INPUT_CASES"]
_SAFE_JOURNAL_FIELDS = ("EXIT_CODE", "EXIT_STATUS", "JOB_RESULT", "UNIT_RESULT")
_SYSTEMD_EXIT = re.compile(
    r"Main process exited, code=([a-z-]+), status=([0-9]{1,3})(?:/[A-Z0-9_-]+)?"
)
_BROKER_FAILURE = re.compile(
    r"probe broker executor failure: (probe_execution_[a-z_]+)"
)
_GUARD_FAILURE = re.compile(
    r"probe guard install failure: (map_create|load|attach4|attach6|map)"
)
_GUARD_BACKEND_FAILURE = re.compile(
    r"probe guard backend failure: (artifact|coordinator|ownership|pins)"
)
_GUARD_MANAGER_FAILURE = re.compile(r"probe guard manager failure: (install|verify)")
_GUARD_VERIFY_FAILURE = re.compile(
    r"probe guard verify failure: "
    r"(artifact|receipt|pins|map_show|program4|program6|map_lookup|"
    r"map_key_decode|map_key_value|map_value_decode|map_value_version|"
    r"map_value_family|map_value_port|map_value_address|map_value_reserved|"
    r"map_value_length|"
    r"attachments|attachment_match)"
)


def _service_property(name: str) -> str:
    observed = subprocess.run(
        ["systemctl", "show", _BROKER_UNIT, f"--property={name}", "--value"],
        check=True,
        capture_output=True,
        text=True,
        timeout=2,
    )
    return observed.stdout.strip()


def _service_snapshot() -> dict[str, str]:
    return {
        name: _service_property(name)
        for name in (
            "ActiveState",
            "SubState",
            "Result",
            "ExecMainCode",
            "ExecMainStatus",
            "NRestarts",
        )
    }


def _unit_exit_snapshot(unit_name: str) -> dict[str, tuple[str, ...]]:
    observed = subprocess.run(
        [
            "journalctl",
            "--unit",
            unit_name,
            "--no-pager",
            "--output=json",
            "--since=-2 minutes",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=3,
    )
    values: dict[str, set[str]] = {field: set() for field in _SAFE_JOURNAL_FIELDS}
    process_exit: set[str] = set()
    for line in observed.stdout.splitlines()[:128]:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(entry, dict):
            continue
        message = entry.get("MESSAGE")
        if isinstance(message, str):
            match = _SYSTEMD_EXIT.search(message)
            if match is not None:
                process_exit.add(f"{match.group(1)}:{match.group(2)}")
        for field in _SAFE_JOURNAL_FIELDS:
            value = entry.get(field)
            if isinstance(value, int) and not isinstance(value, bool):
                value = str(value)
            if (
                isinstance(value, str)
                and 1 <= len(value) <= 64
                and all(character.isalnum() or character in "_.:-" for character in value)
            ):
                values[field].add(value)
    if process_exit:
        values["PROCESS_EXIT"] = process_exit
    return {
        field: tuple(sorted(field_values))
        for field, field_values in values.items()
        if field_values
    }


def _broker_failure_snapshot() -> tuple[str, ...]:
    observed = subprocess.run(
        [
            "journalctl",
            "--unit=rtsp-proxy-probe-broker.service",
            "--boot",
            "--no-pager",
            "--output=cat",
            "--lines=64",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=3,
    )
    return tuple(
        value
        for line in observed.stdout.splitlines()
        if (
            value := next(
                (
                    match.group(1)
                    for pattern in (
                        _BROKER_FAILURE,
                        _GUARD_FAILURE,
                        _GUARD_BACKEND_FAILURE,
                        _GUARD_MANAGER_FAILURE,
                        _GUARD_VERIFY_FAILURE,
                    )
                    if (match := pattern.fullmatch(line)) is not None
                ),
                None,
            )
        )
    )


def _probe_unit_snapshot(unit_name: str) -> dict[str, str]:
    observed = subprocess.run(
        [
            "systemctl",
            "show",
            unit_name,
            "--property=LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,ControlGroup",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=3,
    )
    if observed.returncode != 0:
        return {"LoadState": "not-found"}
    values = dict(
        line.split("=", 1)
        for line in observed.stdout.splitlines()
        if "=" in line
    )
    expected_control_group = f"/rtsp.slice/rtsp-probe.slice/{unit_name}"
    control_group = values.pop("ControlGroup", "")
    values["ControlGroup"] = (
        "expected"
        if control_group == expected_control_group
        else "absent"
        if not control_group
        else "other"
    )
    return values


def _safe_client_outcome(payload: bytes) -> dict[str, str | None] | str:
    try:
        decoded = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "invalid"
    if (
        not isinstance(decoded, dict)
        or set(decoded) != {
            "audio_codec",
            "failure_class",
            "outcome",
            "video_codec",
        }
        or decoded["audio_codec"] not in {None, "opus"}
        or decoded["failure_class"] not in {None, "executor"}
        or decoded["outcome"] not in {"healthy", "inconclusive"}
        or decoded["video_codec"] not in {None, "h264", "hevc"}
    ):
        return "invalid"
    return decoded


def _run_client(
    request_id: UUID,
    endpoint_generation: UUID,
    address: str,
    port: int,
    *,
    drop_privileges: bool = True,
    deadline_after_ms: int = 20_000,
    cancellation_input: bool = False,
    input_case: str | None = None,
) -> subprocess.Popen[bytes]:
    raw_client = os.environ.get(_BROKER_CLIENT_ENV, "")
    client_path = Path(raw_client)
    if (
        not client_path.is_absolute()
        or not client_path.is_file()
        or client_path.stat().st_uid != 0
        or client_path.stat().st_mode & 0o022
    ):
        pytest.fail("exact root-owned broker client fixture is required")
    interpreter = str(_CONTRACT_RELEASE / ".venv/bin/python")
    arguments = [
        interpreter,
        str(client_path),
        str(request_id),
        str(endpoint_generation),
        address,
        str(port),
        str(deadline_after_ms),
    ]
    if input_case is not None:
        arguments.append(input_case)
    if drop_privileges:
        setpriv = shutil.which("setpriv")
        if setpriv is None:
            pytest.fail("setpriv is required for the broker peer contract")
        arguments = [
            setpriv,
            "--reuid=rtsp-proxy",
            "--regid=rtsp-proxy",
            "--clear-groups",
            *arguments,
        ]
    return subprocess.Popen(
        arguments,
        stdin=subprocess.PIPE if cancellation_input else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
    )


def _serve_stalled_source(
    listener: socket.socket,
    *,
    connected: threading.Event,
    release: threading.Event,
    errors: list[BaseException],
) -> None:
    try:
        connection, _address = listener.accept()
        connected.set()
        with connection:
            assert release.wait(timeout=30)
    except BaseException as error:
        errors.append(error)


def _serve_redirect_source(
    listener: socket.socket,
    *,
    redirect_port: int,
    secret_canary: str,
    errors: list[BaseException],
) -> None:
    try:
        connection, _address = listener.accept()
        connection.settimeout(5)
        pending = b""
        with connection:
            while True:
                while b"\r\n\r\n" not in pending:
                    part = connection.recv(4_096)
                    if not part:
                        return
                    pending += part
                request, pending = pending.split(b"\r\n\r\n", 1)
                lines = request.split(b"\r\n")
                method = lines[0].split(b" ", 1)[0]
                cseq = next(
                    line.split(b":", 1)[1].strip()
                    for line in lines
                    if line.lower().startswith(b"cseq:")
                )
                if method == b"OPTIONS":
                    response = (
                        b"RTSP/1.0 200 OK\r\nCSeq: "
                        + cseq
                        + b"\r\nPublic: OPTIONS, DESCRIBE\r\nContent-Length: 0\r\n\r\n"
                    )
                elif method == b"DESCRIBE":
                    response = (
                        b"RTSP/1.0 302 Found\r\nCSeq: "
                        + cseq
                        + b"\r\nLocation: rtsp://127.0.0.1:"
                        + str(redirect_port).encode("ascii")
                        + b"/"
                        + secret_canary.encode("ascii")
                        + b"\r\nContent-Length: 0\r\n\r\n"
                    )
                else:
                    raise AssertionError("redirect source received an unexpected method")
                connection.sendall(response)
                if method == b"DESCRIBE":
                    return
    except BaseException as error:
        errors.append(error)


def _wait_until(predicate: object, *, failure: str, timeout: float = 10) -> None:
    assert callable(predicate)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    pytest.fail(failure)


def _wait_for_source_or_client(
    connected: threading.Event,
    client: subprocess.Popen[bytes],
    *,
    timeout: float = 10,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if connected.is_set() or client.poll() is not None:
            return
        time.sleep(0.02)


def _unit_is_collected(unit_name: str) -> bool:
    observed = subprocess.run(
        ["systemctl", "show", unit_name, "--property=LoadState", "--value"],
        check=False,
        capture_output=True,
        text=True,
        timeout=2,
    )
    return observed.returncode != 0 or observed.stdout.strip() == "not-found"


def _guard_attach_types(bpftool: str, cgroup: Path) -> set[str]:
    observed = subprocess.run(
        [bpftool, "-j", "cgroup", "show", str(cgroup)],
        check=True,
        capture_output=True,
        text=True,
        timeout=2,
    )
    decoded = json.loads(observed.stdout)
    assert isinstance(decoded, list)
    return {
        item["attach_type"]
        for item in decoded
        if isinstance(item, dict) and isinstance(item.get("attach_type"), str)
    }


def _assert_probe_secret_isolated_from_proc(unit_name: str) -> None:
    raw_pid = subprocess.run(
        ["systemctl", "show", unit_name, "--property=MainPID", "--value"],
        check=True,
        capture_output=True,
        text=True,
        timeout=2,
    ).stdout.strip()
    assert raw_pid.isdecimal()
    pid = int(raw_pid)
    assert pid > 1
    visible_metadata = (
        Path(f"/proc/{pid}/cmdline").read_bytes()
        + Path(f"/proc/{pid}/environ").read_bytes()
    )
    assert _SECRET_CANARY.encode() not in visible_metadata
    setpriv = shutil.which("setpriv")
    if setpriv is None:
        pytest.fail("setpriv is required for the probe credential boundary")
    identities = (
        pwd.getpwnam("rtsp-proxy"),
        pwd.getpwnam("nobody"),
    )
    for identity in identities:
        observed = subprocess.run(
            [
                setpriv,
                f"--reuid={identity.pw_uid}",
                f"--regid={identity.pw_gid}",
                "--clear-groups",
                "/usr/bin/head",
                "--bytes=16384",
                f"/proc/{pid}/fd/2",
            ],
            check=False,
            capture_output=True,
            timeout=2,
        )
        assert observed.returncode != 0
        assert observed.stdout == b""


def _activate_test_release(target: str) -> None:
    replacement = _CURRENT_RELEASE.with_name(f".current-{uuid4().hex}")
    replacement.symlink_to(target)
    os.replace(replacement, _CURRENT_RELEASE)


def _run_fault_launcher(
    *,
    release_name: str,
    launcher_source: str,
) -> tuple[UUID, int, bytes, bytes]:
    failure_release = Path("/opt/rtsp-proxy/releases") / release_name
    assert not failure_release.exists()
    launcher = failure_release / ".venv/bin/rtsp-proxy-probe-launcher"
    launcher.parent.mkdir(parents=True, mode=0o755)
    launcher.write_text(launcher_source, encoding="utf-8")
    launcher.chmod(0o755)
    original_target = os.readlink(_CURRENT_RELEASE)
    assert original_target == "releases/probe-contract"
    request_id = uuid4()
    switched = False
    client: subprocess.Popen[bytes] | None = None
    try:
        _activate_test_release(f"releases/{release_name}")
        switched = True
        client = _run_client(
            request_id,
            uuid4(),
            "127.0.0.1",
            9,
            deadline_after_ms=5_000,
        )
        stdout, stderr = client.communicate(timeout=12)
    finally:
        if client is not None and client.poll() is None:
            client.kill()
            client.wait(timeout=2)
        if switched:
            _activate_test_release(original_target)
        if failure_release.exists():
            shutil.rmtree(failure_release)
    assert client is not None
    assert isinstance(client.returncode, int)
    assert _CURRENT_RELEASE.resolve() == _CONTRACT_RELEASE
    assert not failure_release.exists()
    return request_id, client.returncode, stdout, stderr


def _assert_failed_probe_is_collected(request_id: UUID, *, label: str) -> None:
    unit_name = f"rtsp-probe-{request_id.hex}.service"
    scope = _PIN_ROOT / request_id.hex
    receipt = _OWNERSHIP_ROOT / f"{request_id.hex}.json"
    _wait_until(lambda: _unit_is_collected(unit_name), failure=f"{label} probe remained")
    _wait_until(lambda: not scope.exists(), failure=f"{label} BPF scope remained")
    assert not receipt.exists()
    assert _service_property("ActiveState") == "active"


def _serve_probe_media(
    listener: socket.socket,
    *,
    port: int,
    connected: threading.Event,
    allow_responses: threading.Event,
    requests: list[str],
    errors: list[BaseException],
    send_media: bool = True,
    profile: str = "video",
    host: str = "127.0.0.1",
) -> None:
    try:
        assert profile in {"video", "audio", "mixed"}
        ip_version = "IP6" if ":" in host else "IP4"
        authority = f"[{host}]" if ip_version == "IP6" else host
        connection, _address = listener.accept()
        connected.set()
        assert allow_responses.wait(timeout=10)
        connection.settimeout(5)
        pending = b""
        with connection:
            while True:
                while b"\r\n\r\n" not in pending:
                    part = connection.recv(4_096)
                    if not part:
                        return
                    pending += part
                request, pending = pending.split(b"\r\n\r\n", 1)
                lines = request.split(b"\r\n")
                request_line = lines[0]
                requests.append(request_line.decode("ascii"))
                method = request_line.split(b" ", 1)[0]
                cseq = next(
                    line.split(b":", 1)[1].strip()
                    for line in lines
                    if line.lower().startswith(b"cseq:")
                )
                body = b""
                if method == b"OPTIONS":
                    headers = b"Public: OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN\r\n"
                elif method == b"DESCRIBE":
                    session = (
                        "v=0\r\n"
                        f"o=- 0 0 IN {ip_version} {host}\r\n"
                        "s=probe\r\n"
                        "t=0 0\r\n"
                        "a=control:*\r\n"
                    )
                    video = (
                        "m=video 0 RTP/AVP 96\r\n"
                        f"c=IN {ip_version} {host}\r\n"
                        "a=rtpmap:96 H264/90000\r\n"
                        "a=fmtp:96 packetization-mode=1;"
                        "sprop-parameter-sets=Z0LQC4xpyAeEQjU=,aM48gA==\r\n"
                        "a=control:trackID=0\r\n"
                    )
                    audio_payload_type = 97 if profile == "mixed" else 96
                    audio_track = 1 if profile == "mixed" else 0
                    audio = (
                        f"m=audio 0 RTP/AVP {audio_payload_type}\r\n"
                        f"c=IN {ip_version} {host}\r\n"
                        f"a=rtpmap:{audio_payload_type} opus/48000/2\r\n"
                        f"a=control:trackID={audio_track}\r\n"
                    )
                    body = (
                        session
                        + (video if profile in {"video", "mixed"} else "")
                        + (audio if profile in {"audio", "mixed"} else "")
                    ).encode("ascii")
                    headers = (
                        b"Content-Type: application/sdp\r\n"
                        + f"Content-Base: rtsp://{authority}:".encode("ascii")
                        + str(port).encode("ascii")
                        + b"/live/\r\n"
                    )
                elif method == b"SETUP":
                    transport = next(
                        line.split(b":", 1)[1].strip()
                        for line in lines
                        if line.lower().startswith(b"transport:")
                    )
                    headers = (
                        b"Transport: "
                        + transport
                        + b"\r\n"
                        b"Session: test-session;timeout=60\r\n"
                    )
                elif method == b"PLAY":
                    headers = b"Session: test-session\r\nRange: npt=0.000-\r\n"
                else:
                    headers = b"Session: test-session\r\n"
                connection.sendall(
                    b"RTSP/1.0 200 OK\r\nCSeq: "
                    + cseq
                    + b"\r\nServer: rtsp-proxy-test\r\n"
                    + headers
                    + b"Content-Length: "
                    + str(len(body)).encode("ascii")
                    + b"\r\n\r\n"
                    + body
                )
                if method == b"PLAY":
                    if not send_media:
                        time.sleep(0.2)
                        return
                    if profile in {"video", "mixed"}:
                        payloads = (
                            bytes.fromhex("6742d00b8c69c807844235"),
                            bytes.fromhex("68ce3c80"),
                            bytes.fromhex("65b8000409fffff87a28000827fc"),
                        )
                        for sequence, payload in enumerate(payloads, start=1):
                            rtp = struct.pack(
                                "!BBHII",
                                0x80,
                                (0x80 if sequence == len(payloads) else 0) | 96,
                                sequence,
                                3_600,
                                0x12345678,
                            ) + payload
                            connection.sendall(
                                b"$\x00" + struct.pack("!H", len(rtp)) + rtp
                            )
                    if profile in {"audio", "mixed"}:
                        channel = 2 if profile == "mixed" else 0
                        payload_type = 97 if profile == "mixed" else 96
                        for sequence in range(1, 9):
                            rtp = struct.pack(
                                "!BBHII",
                                0x80,
                                0x80 | payload_type,
                                sequence,
                                (sequence - 1) * 960,
                                0x87654321,
                            ) + bytes.fromhex("f8fffe")
                            connection.sendall(
                                b"$"
                                + bytes((channel,))
                                + struct.pack("!H", len(rtp))
                                + rtp
                            )
                            time.sleep(0.02)
                    time.sleep(0.2)
                    return
    except BaseException as error:
        errors.append(error)


def test_installed_broker_attaches_guard_before_ffprobe_and_leaves_no_residue() -> None:
    if os.geteuid() != 0:
        pytest.fail("installed broker contract requires root")
    bpftool = os.environ.get("RTSP_PROXY_BPFTOOL", "")
    if not Path(bpftool).is_absolute() or not Path(bpftool).is_file():
        pytest.fail("exact bpftool path is required")
    assert _CURRENT_RELEASE.is_symlink()
    assert _CURRENT_RELEASE.resolve() == _CONTRACT_RELEASE
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(18)
    port = listener.getsockname()[1]
    request_id = uuid4()
    endpoint_generation = uuid4()
    unit_name = f"rtsp-probe-{request_id.hex}.service"
    cgroup = Path("/sys/fs/cgroup/rtsp.slice/rtsp-probe.slice") / unit_name
    scope = _PIN_ROOT / request_id.hex
    receipt = _OWNERSHIP_ROOT / f"{request_id.hex}.json"
    connected = threading.Event()
    allow_responses = threading.Event()
    requests: list[str] = []
    errors: list[BaseException] = []
    server = threading.Thread(
        target=_serve_probe_media,
        args=(listener,),
        kwargs={
            "port": port,
            "connected": connected,
            "allow_responses": allow_responses,
            "requests": requests,
            "errors": errors,
        },
        daemon=True,
    )
    server.start()
    client = _run_client(request_id, endpoint_generation, "127.0.0.1", port)
    try:
        _wait_for_source_or_client(connected, client, timeout=18)
        if not connected.is_set() and client.poll() is None:
            pytest.fail(
                "broker did not reach source or return a bounded result: "
                f"service={_service_snapshot()}, "
                f"cgroup={cgroup.exists()}, scope={scope.exists()}, "
                    f"receipt={receipt.exists()}, unit={_probe_unit_snapshot(unit_name)}, "
                    f"unit_exit={_unit_exit_snapshot(unit_name)}, "
                    f"broker_failure={_broker_failure_snapshot()}"
            )
        if not connected.is_set():
            stdout, stderr = client.communicate(timeout=2)
            pytest.fail(
                "broker returned before source connection: "
                f"returncode={client.returncode}, "
                f"outcome={_safe_client_outcome(stdout)}, "
                f"stderr_generic={stderr == b'probe_broker_client_failed\n'}, "
                f"service={_service_snapshot()}, "
                f"cgroup={cgroup.exists()}, scope={scope.exists()}, "
                    f"receipt={receipt.exists()}, unit={_probe_unit_snapshot(unit_name)}, "
                    f"unit_exit={_unit_exit_snapshot(unit_name)}, "
                    f"broker_failure={_broker_failure_snapshot()}"
            )
        assert errors == []
        _wait_until(cgroup.is_dir, failure="probe cgroup was not created")
        assert scope.is_dir()
        assert receipt.is_file()
        assert _guard_attach_types(bpftool, cgroup) == {
            "cgroup_device",
            "cgroup_inet4_connect",
            "cgroup_inet6_connect",
            "cgroup_inet_egress",
            "cgroup_inet_ingress",
        }
        _assert_probe_secret_isolated_from_proc(unit_name)
        allow_responses.set()
        stdout, stderr = client.communicate(timeout=15)
    finally:
        allow_responses.set()
        if client.poll() is None:
            client.kill()
            client.wait(timeout=2)
        server.join(timeout=2)
        listener.close()
    assert errors == []
    assert server.is_alive() is False
    assert client.returncode == 0
    assert stderr == b""
    assert json.loads(stdout) == {
        "audio_codec": None,
        "failure_class": None,
        "outcome": "healthy",
        "video_codec": "h264",
    }
    assert _service_property("LimitCORE") == "0"
    assert _service_property("MemoryMax") == str(256 * 1024 * 1024)
    assert _service_property("MemorySwapMax") == "0"
    assert _service_property("TasksMax") == "64"
    assert _service_property("LimitNOFILE") == "256"
    assert _service_property("CPUQuotaPerSecUSec") == "2s"
    assert requests == [
        f"OPTIONS rtsp://127.0.0.1:{port}/live RTSP/1.0",
        f"DESCRIBE rtsp://127.0.0.1:{port}/live RTSP/1.0",
        f"SETUP rtsp://127.0.0.1:{port}/live/trackID=0 RTSP/1.0",
        f"PLAY rtsp://127.0.0.1:{port}/live/ RTSP/1.0",
    ]
    _wait_until(lambda: _unit_is_collected(unit_name), failure="probe unit residue remained")
    _wait_until(lambda: not scope.exists(), failure="probe BPF pin residue remained")
    assert not receipt.exists()
    journal = subprocess.run(
        ["journalctl", "--unit", _BROKER_UNIT, "--no-pager", "--output=cat"],
        check=False,
        capture_output=True,
        text=True,
        timeout=3,
    )
    assert _SECRET_CANARY not in journal.stdout + journal.stderr


def test_installed_broker_executes_exact_ipv6_target_and_cleans_guard() -> None:
    if os.geteuid() != 0:
        pytest.fail("installed broker contract requires root")
    listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    listener.bind(("::1", 0))
    listener.listen(1)
    listener.settimeout(10)
    port = listener.getsockname()[1]
    request_id = uuid4()
    unit_name = f"rtsp-probe-{request_id.hex}.service"
    scope = _PIN_ROOT / request_id.hex
    receipt = _OWNERSHIP_ROOT / f"{request_id.hex}.json"
    connected = threading.Event()
    allow_responses = threading.Event()
    allow_responses.set()
    requests: list[str] = []
    errors: list[BaseException] = []
    server = threading.Thread(
        target=_serve_probe_media,
        args=(listener,),
        kwargs={
            "port": port,
            "connected": connected,
            "allow_responses": allow_responses,
            "requests": requests,
            "errors": errors,
            "host": "::1",
        },
        daemon=True,
    )
    server.start()
    client = _run_client(request_id, uuid4(), "::1", port)
    try:
        stdout, stderr = client.communicate(timeout=15)
    finally:
        if client.poll() is None:
            client.kill()
            client.wait(timeout=2)
        server.join(timeout=2)
        listener.close()

    assert errors == []
    assert server.is_alive() is False
    assert client.returncode == 0
    assert stderr == b""
    assert json.loads(stdout) == {
        "audio_codec": None,
        "failure_class": None,
        "outcome": "healthy",
        "video_codec": "h264",
    }
    assert requests == [
        f"OPTIONS rtsp://[::1]:{port}/live RTSP/1.0",
        f"DESCRIBE rtsp://[::1]:{port}/live RTSP/1.0",
        f"SETUP rtsp://[::1]:{port}/live/trackID=0 RTSP/1.0",
        f"PLAY rtsp://[::1]:{port}/live/ RTSP/1.0",
    ]
    _wait_until(lambda: _unit_is_collected(unit_name), failure="IPv6 probe remained")
    _wait_until(lambda: not scope.exists(), failure="IPv6 BPF scope remained")
    assert not receipt.exists()


def test_installed_broker_refuses_redirect_without_secret_or_residue() -> None:
    if os.geteuid() != 0:
        pytest.fail("installed broker contract requires root")
    source = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    source.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    source.bind(("127.0.0.1", 0))
    source.listen(1)
    source.settimeout(10)
    redirect = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    redirect.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    redirect.bind(("127.0.0.1", 0))
    redirect.listen(1)
    redirect.settimeout(0.5)
    request_id = uuid4()
    secret_canary = f"redirect-secret-{request_id.hex}"
    unit_name = f"rtsp-probe-{request_id.hex}.service"
    scope = _PIN_ROOT / request_id.hex
    receipt = _OWNERSHIP_ROOT / f"{request_id.hex}.json"
    errors: list[BaseException] = []
    server = threading.Thread(
        target=_serve_redirect_source,
        args=(source,),
        kwargs={
            "redirect_port": redirect.getsockname()[1],
            "secret_canary": secret_canary,
            "errors": errors,
        },
        daemon=True,
    )
    server.start()
    client = _run_client(
        request_id,
        uuid4(),
        "127.0.0.1",
        source.getsockname()[1],
    )
    try:
        stdout, stderr = client.communicate(timeout=15)
        with pytest.raises(TimeoutError):
            redirected, _ = redirect.accept()
            redirected.close()
    finally:
        if client.poll() is None:
            client.kill()
            client.wait(timeout=2)
        server.join(timeout=2)
        source.close()
        redirect.close()

    assert errors == []
    assert server.is_alive() is False
    assert client.returncode == 0
    assert stderr == b""
    assert json.loads(stdout) == {
        "audio_codec": None,
        "failure_class": "executor",
        "outcome": "inconclusive",
        "video_codec": None,
    }
    assert secret_canary.encode() not in stdout + stderr
    _wait_until(lambda: _unit_is_collected(unit_name), failure="redirect probe remained")
    _wait_until(lambda: not scope.exists(), failure="redirect BPF scope remained")
    assert not receipt.exists()
    journal = subprocess.run(
        ["journalctl", "--unit", _BROKER_UNIT, "--no-pager", "--output=cat"],
        check=False,
        capture_output=True,
        text=True,
        timeout=3,
    )
    assert secret_canary not in journal.stdout + journal.stderr


@pytest.mark.parametrize(
    ("drop_privileges", "address"),
    [
        (False, "127.0.0.1"), (True, "127.0.0.2"),
        (True, "169.254.169.254"), (True, "fd00:ec2::254"),
        (True, "fd00:ec2::23"), (True, "100.100.100.200"),
        (True, "0.0.0.0"), (True, "::"), (True, "fe80::1"),
        (True, "224.0.0.1"), (True, "ff02::1"),
        (True, "240.0.0.1"), (True, "::2"),
    ],
)
def test_installed_broker_denies_root_peer_and_out_of_policy_target_without_unit(
    drop_privileges: bool, address: str,
) -> None:
    if os.geteuid() != 0:
        pytest.fail("installed broker contract requires root")
    request_id = uuid4()
    client = _run_client(request_id, uuid4(), address, 9, drop_privileges=drop_privileges)
    stdout, stderr = client.communicate(timeout=5)
    assert client.returncode == 0
    assert stderr == b""
    assert json.loads(stdout) == {
        "audio_codec": None, "failure_class": "executor",
        "outcome": "inconclusive", "video_codec": None,
    }
    _assert_no_request_execution(request_id)


def _assert_no_request_execution(request_id: UUID) -> None:
    unit_name = f"rtsp-probe-{request_id.hex}.service"
    assert _unit_is_collected(unit_name)
    assert not (_PIN_ROOT / request_id.hex).exists()
    assert not (_OWNERSHIP_ROOT / f"{request_id.hex}.json").exists()
    journal = subprocess.run(
        ["journalctl", "--unit", unit_name, "--no-pager", "--output=json", "--lines=1"],
        capture_output=True, check=True, timeout=3,
    )
    assert not journal.stdout.strip(), "rejected request created unit journal entries"


@pytest.mark.parametrize("input_case", _HOSTILE_INPUT_CASES)
def test_installed_broker_rejects_untrusted_protocol_input_before_execution(
    input_case: str,
) -> None:
    if os.geteuid() != 0:
        pytest.fail("installed broker contract requires root")
    request_id = uuid4()
    process_id = int(_service_property("MainPID"))
    descriptors_before = len(list(Path(f"/proc/{process_id}/fd").iterdir()))
    client = _run_client(request_id, uuid4(), "127.0.0.1", 8554, input_case=input_case)
    stdout, stderr = client.communicate(timeout=5)
    assert client.returncode == 0
    assert stderr == b""
    assert json.loads(stdout) == {"rejected": True}
    _assert_no_request_execution(request_id)
    assert _service_property("ActiveState") == "active"
    assert int(_service_property("MainPID")) == process_id
    assert len(list(Path(f"/proc/{process_id}/fd").iterdir())) == descriptors_before


@pytest.mark.parametrize(
    ("profile", "expected_video", "expected_audio", "expected_setups"),
    (
        ("audio", None, "opus", 1),
        ("mixed", "h264", "opus", 2),
    ),
)
def test_installed_broker_decodes_audio_and_mixed_profiles(
    profile: str,
    expected_video: str | None,
    expected_audio: str,
    expected_setups: int,
) -> None:
    if os.geteuid() != 0:
        pytest.fail("installed broker contract requires root")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(10)
    port = listener.getsockname()[1]
    request_id = uuid4()
    unit_name = f"rtsp-probe-{request_id.hex}.service"
    scope = _PIN_ROOT / request_id.hex
    receipt = _OWNERSHIP_ROOT / f"{request_id.hex}.json"
    connected = threading.Event()
    allow_responses = threading.Event()
    allow_responses.set()
    requests: list[str] = []
    errors: list[BaseException] = []
    server = threading.Thread(
        target=_serve_probe_media,
        args=(listener,),
        kwargs={
            "port": port,
            "connected": connected,
            "allow_responses": allow_responses,
            "requests": requests,
            "errors": errors,
            "profile": profile,
        },
        daemon=True,
    )
    server.start()
    client = _run_client(request_id, uuid4(), "127.0.0.1", port)
    try:
        stdout, stderr = client.communicate(timeout=15)
    finally:
        if client.poll() is None:
            client.kill()
            client.wait(timeout=2)
        server.join(timeout=2)
        listener.close()

    assert errors == []
    assert server.is_alive() is False
    assert client.returncode == 0
    assert stderr == b""
    assert json.loads(stdout) == {
        "audio_codec": expected_audio,
        "failure_class": None,
        "outcome": "healthy",
        "video_codec": expected_video,
    }
    assert sum(request.startswith("SETUP ") for request in requests) == expected_setups
    assert requests[-1] == f"PLAY rtsp://127.0.0.1:{port}/live/ RTSP/1.0"
    _wait_until(lambda: _unit_is_collected(unit_name), failure="media probe remained")
    _wait_until(lambda: not scope.exists(), failure="media BPF scope remained")
    assert not receipt.exists()


def test_installed_broker_deadline_collects_stalled_probe_and_remains_available() -> None:
    if os.geteuid() != 0:
        pytest.fail("installed broker contract requires root")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(10)
    request_id = uuid4()
    unit_name = f"rtsp-probe-{request_id.hex}.service"
    scope = _PIN_ROOT / request_id.hex
    receipt = _OWNERSHIP_ROOT / f"{request_id.hex}.json"
    connected = threading.Event()
    release = threading.Event()
    errors: list[BaseException] = []
    server = threading.Thread(
        target=_serve_stalled_source,
        args=(listener,),
        kwargs={"connected": connected, "release": release, "errors": errors},
        daemon=True,
    )
    server.start()
    client = _run_client(
        request_id,
        uuid4(),
        "127.0.0.1",
        listener.getsockname()[1],
        deadline_after_ms=1_500,
    )
    try:
        _wait_for_source_or_client(connected, client, timeout=10)
        assert connected.is_set(), _service_snapshot()
        stdout, stderr = client.communicate(timeout=12)
    finally:
        release.set()
        if client.poll() is None:
            client.kill()
            client.wait(timeout=2)
        server.join(timeout=2)
        listener.close()

    assert errors == []
    assert server.is_alive() is False
    assert client.returncode == 0
    assert stderr == b""
    assert json.loads(stdout) == {
        "audio_codec": None,
        "failure_class": "executor",
        "outcome": "inconclusive",
        "video_codec": None,
    }
    _wait_until(lambda: _unit_is_collected(unit_name), failure="timed-out probe remained")
    _wait_until(lambda: not scope.exists(), failure="timed-out BPF scope remained")
    assert not receipt.exists()
    assert _service_property("ActiveState") == "active"
    assert _service_property("SubState") == "running"


@pytest.mark.parametrize("cause", ["caller", "shutdown"])
def test_installed_broker_cancellation_collects_probe_before_deadline(cause: str) -> None:
    if os.geteuid() != 0:
        pytest.fail("installed broker contract requires root")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(10)
    request_id = uuid4()
    unit_name = f"rtsp-probe-{request_id.hex}.service"
    scope = _PIN_ROOT / request_id.hex
    receipt = _OWNERSHIP_ROOT / f"{request_id.hex}.json"
    connected = threading.Event()
    release = threading.Event()
    errors: list[BaseException] = []
    server = threading.Thread(
        target=_serve_stalled_source, args=(listener,),
        kwargs={"connected": connected, "release": release, "errors": errors}, daemon=True,
    )
    server.start()
    client = _run_client(
        request_id, uuid4(), "127.0.0.1", listener.getsockname()[1],
        deadline_after_ms=60_000, cancellation_input=True,
    )
    try:
        _wait_for_source_or_client(connected, client, timeout=10)
        assert connected.is_set(), _service_snapshot()
        assert scope.is_dir()
        assert receipt.is_file()
        if cause == "caller":
            assert client.stdin is not None
            client.stdin.write(b"cancel\n")
            client.stdin.flush()
        else:
            subprocess.run(
                ["systemctl", "stop", _BROKER_UNIT], check=True,
                capture_output=True, timeout=10,
            )
        stdout, stderr = client.communicate(timeout=5)
        assert client.returncode == 0
        assert stderr == b""
        assert json.loads(stdout)["outcome"] == "inconclusive"
        _wait_until(lambda: _unit_is_collected(unit_name), failure="cancelled probe remained",
                    timeout=5)
        _wait_until(lambda: not scope.exists(), failure="cancelled guard remained", timeout=5)
        assert not receipt.exists()
    finally:
        release.set()
        if client.poll() is None:
            client.kill()
            client.wait(timeout=2)
        server.join(timeout=2)
        listener.close()
        if cause == "shutdown":
            subprocess.run(
                ["systemctl", "start", _BROKER_UNIT], check=True,
                capture_output=True, timeout=40,
            )
    assert errors == []
    assert not server.is_alive()
    assert _service_property("ActiveState") == "active"


def test_installed_broker_restart_recovers_inflight_probe_on_startup() -> None:
    if os.geteuid() != 0:
        pytest.fail("installed broker contract requires root")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(10)
    request_id = uuid4()
    unit_name = f"rtsp-probe-{request_id.hex}.service"
    cgroup = Path("/sys/fs/cgroup/rtsp.slice/rtsp-probe.slice") / unit_name
    scope = _PIN_ROOT / request_id.hex
    receipt = _OWNERSHIP_ROOT / f"{request_id.hex}.json"
    connected = threading.Event()
    release = threading.Event()
    errors: list[BaseException] = []
    server = threading.Thread(
        target=_serve_stalled_source,
        args=(listener,),
        kwargs={"connected": connected, "release": release, "errors": errors},
        daemon=True,
    )
    server.start()
    client = _run_client(
        request_id,
        uuid4(),
        "127.0.0.1",
        listener.getsockname()[1],
    )
    try:
        _wait_for_source_or_client(connected, client, timeout=10)
        assert connected.is_set(), _service_snapshot()
        _wait_until(
            cgroup.is_dir,
            failure="probe cgroup was not created before broker restart",
        )
        assert scope.is_dir()
        assert receipt.is_file()
        prior_restarts = int(_service_property("NRestarts"))
        subprocess.run(
            [
                "systemctl",
                "kill",
                "--kill-whom=main",
                "--signal=SIGKILL",
                _BROKER_UNIT,
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=3,
        )
        _wait_until(
            lambda: (
                _service_property("ActiveState") == "active"
                and _service_property("SubState") == "running"
                and int(_service_property("NRestarts")) > prior_restarts
            ),
            failure="broker did not restart after forced interruption",
            timeout=15,
        )
        stdout, stderr = client.communicate(timeout=5)
    finally:
        release.set()
        if client.poll() is None:
            client.kill()
            client.wait(timeout=2)
        server.join(timeout=2)
        listener.close()

    assert errors == []
    assert server.is_alive() is False
    assert client.returncode == 0
    assert stderr == b""
    assert json.loads(stdout) == {
        "audio_codec": None,
        "failure_class": "executor",
        "outcome": "inconclusive",
        "video_codec": None,
    }
    _wait_until(lambda: _unit_is_collected(unit_name), failure="restarted probe remained")
    _wait_until(lambda: not scope.exists(), failure="restarted BPF scope remained")
    assert not receipt.exists()


def test_installed_broker_repeated_no_media_results_are_inconclusive_and_collected() -> None:
    if os.geteuid() != 0:
        pytest.fail("installed broker contract requires root")
    for _attempt in range(3):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(10)
        port = listener.getsockname()[1]
        request_id = uuid4()
        unit_name = f"rtsp-probe-{request_id.hex}.service"
        scope = _PIN_ROOT / request_id.hex
        receipt = _OWNERSHIP_ROOT / f"{request_id.hex}.json"
        connected = threading.Event()
        allow_responses = threading.Event()
        allow_responses.set()
        requests: list[str] = []
        errors: list[BaseException] = []
        server = threading.Thread(
            target=_serve_probe_media,
            args=(listener,),
            kwargs={
                "port": port,
                "connected": connected,
                "allow_responses": allow_responses,
                "requests": requests,
                "errors": errors,
                "send_media": False,
            },
            daemon=True,
        )
        server.start()
        client = _run_client(
            request_id,
            uuid4(),
            "127.0.0.1",
            port,
        )
        try:
            stdout, stderr = client.communicate(timeout=15)
        finally:
            if client.poll() is None:
                client.kill()
                client.wait(timeout=2)
            server.join(timeout=2)
            listener.close()

        assert errors == []
        assert server.is_alive() is False
        assert client.returncode == 0
        assert stderr == b""
        assert json.loads(stdout) == {
            "audio_codec": None,
            "failure_class": "executor",
            "outcome": "inconclusive",
            "video_codec": None,
        }
        assert requests[-1] == (
            f"PLAY rtsp://127.0.0.1:{port}/live/ RTSP/1.0"
        )
        _wait_until(
            lambda unit_name=unit_name: _unit_is_collected(unit_name),
            failure="no-media probe unit remained",
        )
        _wait_until(
            lambda scope=scope: not scope.exists(),
            failure="no-media BPF scope remained",
        )
        assert not receipt.exists()
        assert _service_property("ActiveState") == "active"


def test_installed_broker_stops_output_flood_and_leaves_no_residue() -> None:
    if os.geteuid() != 0:
        pytest.fail("installed broker contract requires root")
    request_id, returncode, stdout, stderr = _run_fault_launcher(
        release_name="probe-output-flood",
        launcher_source=(
            "#!/usr/bin/python3\n"
            "import os\n"
            "if os.read(0, 2) != b'R':\n"
            "    raise SystemExit(70)\n"
            "payload = b'x' * 131072\n"
            "while payload:\n"
            "    payload = payload[os.write(1, payload):]\n"
        ),
    )
    assert returncode == 0
    assert stderr == b""
    assert json.loads(stdout) == {
        "audio_codec": None,
        "failure_class": "executor",
        "outcome": "inconclusive",
        "video_codec": None,
    }
    _assert_failed_probe_is_collected(request_id, label="flooded")


def test_installed_broker_rejects_malformed_result_and_leaves_no_residue() -> None:
    if os.geteuid() != 0:
        pytest.fail("installed broker contract requires root")
    request_id, returncode, stdout, stderr = _run_fault_launcher(
        release_name="probe-malformed-result",
        launcher_source=(
            "#!/usr/bin/python3\n"
            "import os\n"
            "if os.read(0, 2) != b'R':\n"
            "    raise SystemExit(70)\n"
            "os.write(1, b'{')\n"
        ),
    )
    assert returncode == 0
    assert stderr == b""
    assert json.loads(stdout) == {
        "audio_codec": None,
        "failure_class": "executor",
        "outcome": "inconclusive",
        "video_codec": None,
    }
    _assert_failed_probe_is_collected(request_id, label="malformed-result")
