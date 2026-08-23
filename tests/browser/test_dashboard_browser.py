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
    if process.poll() is not None:
        return process.communicate()
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return process.communicate()
    try:
        return process.communicate(timeout=terminate_timeout_seconds)
    except subprocess.TimeoutExpired:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        return process.communicate(timeout=kill_timeout_seconds)


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
        stdout, stderr = process.communicate(timeout=90)
    except subprocess.TimeoutExpired:
        stdout, stderr = _terminate_process_group(
            process,
            terminate_timeout_seconds=5,
            kill_timeout_seconds=5,
        )
        pytest.fail(f"browser E2E timed out\nstdout:\n{stdout}\nstderr:\n{stderr}")
    finally:
        if process.poll() is None:
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
