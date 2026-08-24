from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from contextlib import suppress
from pathlib import Path

import pytest


def _terminate_process_group(
    process: subprocess.Popen[str],
    *,
    terminate_timeout_seconds: float,
    kill_timeout_seconds: float,
) -> tuple[str, str]:
    process_group_id = process.pid
    with suppress(ProcessLookupError):
        os.killpg(process_group_id, signal.SIGTERM)
    if not _wait_for_process_group_exit(
        process,
        process_group_id=process_group_id,
        timeout_seconds=terminate_timeout_seconds,
    ):
        with suppress(ProcessLookupError):
            os.killpg(process_group_id, signal.SIGKILL)
        if not _wait_for_process_group_exit(
            process,
            process_group_id=process_group_id,
            timeout_seconds=kill_timeout_seconds,
        ):
            raise RuntimeError("browser_process_group_shutdown_timeout")
    if process.stdout is not None and process.stdout.closed:
        return "", ""
    return process.communicate(timeout=kill_timeout_seconds)


def _wait_for_process_group_exit(
    process: subprocess.Popen[str],
    *,
    process_group_id: int,
    timeout_seconds: float,
) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while True:
        process.poll()
        try:
            os.killpg(process_group_id, 0)
        except ProcessLookupError:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)


@pytest.mark.browser
def test_dashboard_oidc_confirmation_accessibility_and_logout() -> None:
    if os.environ.get("RTSP_PROXY_RUN_BROWSER_E2E") != "1":
        pytest.skip("set RTSP_PROXY_RUN_BROWSER_E2E=1 for the real-browser contract")
    if shutil.which("agent-browser") is None:
        pytest.fail("agent-browser is required for the real-browser contract")

    process = subprocess.Popen(
        ["bash", "tools/e2e/dashboard_browser.sh"],
        cwd=Path(__file__).parents[2],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=150)
    except subprocess.TimeoutExpired:
        stdout, stderr = _terminate_process_group(
            process,
            terminate_timeout_seconds=5,
            kill_timeout_seconds=5,
        )
        pytest.fail(f"browser E2E timed out\nstdout:\n{stdout}\nstderr:\n{stderr}")
    finally:
        _terminate_process_group(
            process,
            terminate_timeout_seconds=5,
            kill_timeout_seconds=5,
        )

    assert process.returncode == 0, (
        f"browser E2E failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    )


@pytest.mark.skipif(os.name != "posix", reason="POSIX process groups are required")
def test_browser_process_group_escalates_when_sigterm_is_ignored() -> None:
    process = subprocess.Popen(
        [
            "bash",
            "-c",
            "trap '' TERM; printf 'ready\\n'; while :; do sleep 1; done",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    assert process.stdout is not None
    assert process.stdout.readline() == "ready\n"
    started_at = time.monotonic()
    try:
        _terminate_process_group(
            process,
            terminate_timeout_seconds=0.05,
            kill_timeout_seconds=1,
        )
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=1)

    assert process.returncode == -signal.SIGKILL
    assert time.monotonic() - started_at < 2


@pytest.mark.skipif(os.name != "posix", reason="POSIX process groups are required")
def test_browser_cleanup_kills_descendant_after_leader_exits(tmp_path: Path) -> None:
    ready_path = tmp_path / "descendant-ready"
    process = subprocess.Popen(
        [
            "bash",
            "-c",
            "(trap '' TERM; : > \"$1\"; exec >/dev/null 2>&1; "
            "while :; do sleep 1; done) & "
            "child=$!; while [ ! -e \"$1\" ]; do sleep 0.01; done; "
            "printf '%s\\n' \"$child\"",
            "browser-e2e-descendant",
            str(ready_path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    assert process.stdout is not None
    descendant_pid = int(process.stdout.readline())
    assert process.wait(timeout=1) == 0

    _terminate_process_group(
        process,
        terminate_timeout_seconds=0.05,
        kill_timeout_seconds=1,
    )

    with pytest.raises(ProcessLookupError):
        os.kill(descendant_pid, 0)
