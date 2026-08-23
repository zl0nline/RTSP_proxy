from __future__ import annotations

import os
import shutil
import signal
import subprocess
from pathlib import Path

import pytest


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
        os.killpg(process.pid, signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=10)
        pytest.fail(f"browser E2E timed out\nstdout:\n{stdout}\nstderr:\n{stderr}")

    assert process.returncode == 0, (
        f"browser E2E failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    )
