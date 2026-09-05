"""Run the real setup shell with temporary paths and emulated root-only commands.

The harness tests ordering, key preservation and concurrent execution, not Linux
ownership enforcement. Python, key parsing, flock, awk and rename remain real.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux deployment shell")


@pytest.fixture
def setup_command(tmp_path: Path) -> tuple[list[str], dict[str, str], Path]:
    commands = tmp_path / "commands"
    commands.mkdir()
    shim = commands / "shim"
    shim.write_text(
        f"#!{sys.executable}\n" + '''import os, stat, sys, time
from pathlib import Path
name = Path(sys.argv[0]).name
args = sys.argv[1:]
if name == "id":
    print("0")
elif name == "uname":
    print("Linux")
elif name == "chown":
    pass
elif name == "install":
    assert args[:1] == ["-d"]
    Path(args[-1]).mkdir(parents=True, exist_ok=True)
    Path(args[-1]).chmod(0o750)
elif name == "stat":
    info = Path(args[-1]).lstat()
    mode = format(stat.S_IMODE(info.st_mode), "o")
    if args[1] == "%a":
        print(mode)
    else:
        assert args[1] == "%a:%U:%G:%F:%h"
        kind = "regular file" if stat.S_ISREG(info.st_mode) else "other"
        print(f"{mode}:root:rtsp-proxy-access:{kind}:{info.st_nlink}")
elif name == "setup-python":
    if os.environ.get("BOOTSTRAP_TEST_PAUSE") == "1" and "secrets.token_bytes" in args[-1]:
        root = Path(os.environ["BOOTSTRAP_TEST_DIRECTORY"])
        (root / "paused").touch()
        deadline = time.monotonic() + 10
        while not (root / "resume").exists():
            if time.monotonic() >= deadline:
                raise SystemExit("test barrier expired")
            time.sleep(0.01)
    os.execv(sys.executable, [sys.executable, *args])
else:
    raise SystemExit("unexpected shim command")
''', encoding="utf-8",
    )
    shim.chmod(0o755)
    for name in ("id", "uname", "chown", "install", "stat", "setup-python"):
        (commands / name).symlink_to(shim)
    original = Path("tools/configure_camera_sources.sh").read_text(encoding="utf-8")
    lock_line = "setup_lock_directory=/run/rtsp-proxy-camera-source-setup"
    assert original.count(lock_line) == 1
    original = original.replace(
        lock_line,
        "setup_lock_directory=" + shlex.quote(str(tmp_path / "setup-lock")),
    )
    release_line = "release_python=/opt/rtsp-proxy/releases/$release_id/.venv/bin/python"
    assert original.count(release_line) == 1
    script = tmp_path / "configure.sh"
    script.write_text(original.replace(
        release_line, "release_python=" + shlex.quote(str(commands / "setup-python")),
    ), encoding="utf-8")
    web = tmp_path / "web.env"
    reconciler = tmp_path / "reconciler.env"
    for path in (web, reconciler):
        path.write_text("EXISTING=value\n", encoding="utf-8")
        path.chmod(0o640)
    key = tmp_path / "keys" / "camera-source-keys.json"
    environment = {
        **os.environ, "PATH": f"{commands}:{os.environ['PATH']}",
        "BOOTSTRAP_TEST_DIRECTORY": str(tmp_path),
    }
    arguments = [
        "sh", str(script), "--release-id", "test", "--source-cidrs", "192.0.2.0/24",
        "--web-environment", str(web), "--reconciler-environment", str(reconciler),
        "--key-file", str(key),
    ]
    return arguments, environment, key


@pytest.mark.parametrize("payload", [b'{"broken":true}\n', b"{", b"", b"x" * 4097, b"\xff"])
def test_malformed_keyring_fails_before_environment_change(setup_command, payload: bytes) -> None:
    arguments, environment, key = setup_command
    key.parent.mkdir()
    key.write_bytes(payload)
    key.chmod(0o640)
    result = subprocess.run(arguments, env=environment, capture_output=True, timeout=5)
    assert result.returncode != 0, "malformed keyring was accepted"
    assert (key.parent.parent / "web.env").read_text() == "EXISTING=value\n"
    assert (key.parent.parent / "reconciler.env").read_text() == "EXISTING=value\n"
    assert key.read_bytes() == payload


@pytest.mark.parametrize("different_key_path", [False, True])
def test_parallel_setup_cannot_replace_another_callers_key(
    setup_command, different_key_path: bool,
) -> None:
    arguments, environment, key = setup_command
    root = key.parent.parent
    first = subprocess.Popen(
        arguments, env={**environment, "BOOTSTRAP_TEST_PAUSE": "1"},
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 5
        while not (root / "paused").exists():
            assert first.poll() is None, "first setup failed before key creation"
            assert time.monotonic() < deadline, "first setup never reached key creation"
            time.sleep(0.01)
        second_arguments = (
            [*arguments[:-1], str(key.with_name("other-keys.json"))]
            if different_key_path else arguments
        )
        second = subprocess.run(second_arguments, env=environment, capture_output=True, timeout=5)
        second_key = key.read_bytes() if key.exists() else None
    finally:
        (root / "resume").touch()
        try:
            first.communicate(timeout=5)
        finally:
            if first.poll() is None:
                first.kill()
                first.communicate(timeout=3)
    assert first.returncode == 0
    if second_key is not None:
        assert key.read_bytes() == second_key, "a successfully created key was overwritten"
    assert second.returncode != 0, "concurrent setup entered the keyring critical section"
    assert b"already running" in second.stderr
    original_key = key.read_bytes()
    repeat = subprocess.run(arguments, env=environment, capture_output=True, timeout=5)
    assert repeat.returncode == 0
    assert key.read_bytes() == original_key


def test_sequential_setup_preserves_existing_valid_key(setup_command) -> None:
    arguments, environment, key = setup_command
    first = subprocess.run(arguments, env=environment, capture_output=True, timeout=5)
    assert first.returncode == 0
    original_key = key.read_bytes()
    second = subprocess.run(arguments, env=environment, capture_output=True, timeout=5)
    assert second.returncode == 0
    assert key.read_bytes() == original_key


def test_missing_flock_fails_before_creating_key_or_changing_configuration(setup_command) -> None:
    arguments, environment, key = setup_command
    shell = shutil.which("sh")
    assert shell is not None
    environment = {**environment, "PATH": environment["PATH"].split(":", 1)[0]}
    result = subprocess.run(
        [shell, *arguments[1:]], env=environment, capture_output=True, timeout=5,
    )
    assert result.returncode == 1
    assert result.stderr == b"flock is required; install the util-linux package\n"
    assert not key.exists()
    assert (key.parent.parent / "web.env").read_text() == "EXISTING=value\n"
