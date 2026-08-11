from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

from rtsp_proxy.load_evidence import (
    read_linux_generator_counters,
    summarize_generator_headroom,
)
from rtsp_proxy.load_profile import LoadProfile
from rtsp_proxy.load_runtime import capture_generator_runtime, validate_runtime_manifest
from rtsp_proxy.release import normalize_linux_arch

pytestmark = pytest.mark.skipif(
    os.environ.get("RTSP_RUNTIME_NATIVE") != "1",
    reason="RTSP_RUNTIME_NATIVE=1 is required for the privileged native contract",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _command_stdout(argv: list[str]) -> str:
    return subprocess.run(
        argv,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=15,
    ).stdout.strip()


def _wait_for_main_pid(unit: str) -> int:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        raw = _command_stdout(["sudo", "systemctl", "show", "--property=MainPID", "--value", unit])
        if raw.isdigit() and int(raw) > 0:
            pid = int(raw)
            maps = Path(f"/proc/{pid}/maps")
            if maps.is_file() and "libgstreamer-1.0.so" in maps.read_text(encoding="utf-8"):
                return pid
        time.sleep(0.1)
    raise AssertionError("native runtime contract service did not become ready")


def _native_profile(*, interface: str, mtu: int, executable_sha256: str) -> LoadProfile:
    version_output = _command_stdout(["/usr/bin/gst-launch-1.0", "--version"])
    version_match = re.search(r"^GStreamer\s+(\d+\.\d+\.\d+)\s*$", version_output, re.MULTILINE)
    assert version_match is not None
    build_id = _command_stdout(
        ["dpkg-query", "--show", "--showformat=${Version}", "libgstreamer1.0-0"]
    )
    architecture = normalize_linux_arch(platform.machine()).value
    return LoadProfile.model_validate(
        {
            "schema_version": 1,
            "tier": "smoke",
            "seed": 1,
            "comparison_id": "native-runtime-contract",
            "sut_architecture": architecture,
            "sut_rtsp_host": "127.0.0.1",
            "sut_rtsp_port": 8554,
            "reader_credentials_file": None,
            "artifacts": {
                "git_commit": "1" * 40,
                "mediamtx_version": "v1.20.0",
                "mediamtx_sha256": "1" * 64,
                "ffmpeg_version": "native-contract",
                "ffmpeg_sha256": "2" * 64,
                "ffprobe_sha256": "3" * 64,
                "gstreamer_version": version_match.group(1),
                "gstreamer_build_id": build_id,
                "pull_server_sha256": executable_sha256,
                "load_reader_sha256": "4" * 64,
            },
            "fixture": {
                "source_mode": "rtsp-pull",
                "path": "/tmp/native-runtime-contract.h264",
                "sha256": "5" * 64,
                "codec": "h264",
                "bitrate_bps": 2_000_000,
                "fps": 25,
                "gop_frames": 50,
                "rtp_mtu_bytes": 1200,
                "audio": "none",
            },
            "generator_hosts": [
                {
                    "name": "generator-native",
                    "architecture": architecture,
                    "rtsp_host": "127.0.0.1",
                    "rtsp_port": 8555,
                    "source_start": 0,
                    "source_count": 1,
                }
            ],
            "network": {
                "profile": "lan",
                "interface": interface,
                "mtu_bytes": mtu,
                "rtt_ms": 0,
                "jitter_ms": 0,
                "loss_percent": 0,
            },
            "workload": {
                "endpoint_mode": "direct-control",
                "session_temperature": "warm",
                "registered_paths": 1,
                "active_sources": 0,
                "total_readers": 0,
                "connect_rate_per_second": 0,
                "minimum_rtp_packets_per_second": 0,
                "probe_rate_per_second": 0,
                "crud_rate_per_second": 0,
            },
            "reader_lifecycle": {
                "mode": "single",
                "disconnect_rate_per_second": 0,
                "outage_percent": 0,
                "reconnect_attempts": 0,
                "backoff_base_ms": 250,
                "backoff_max_ms": 30_000,
            },
            "evidence_sampling": {
                "interval_seconds": 1,
                "maximum_gap_factor": 3,
                "maximum_clock_error_ms": 1000,
                "maximum_start_lateness_ms": 250,
            },
            "duration": {
                "warmup_seconds": 0,
                "measurement_seconds": 2,
                "soak_seconds": 0,
            },
        }
    )


def test_native_runtime_capture_binds_real_proc_cgroup_dpkg_and_maps() -> None:
    assert platform.system() == "Linux"
    route = json.loads(_command_stdout(["ip", "-json", "route", "show", "default"]))
    assert isinstance(route, list) and route and isinstance(route[0].get("dev"), str)
    interface = route[0]["dev"]
    mtu = int(Path(f"/sys/class/net/{interface}/mtu").read_text(encoding="utf-8"))
    unit = f"rtsp-runtime-contract-{os.getpid()}.service"
    try:
        subprocess.run(
            [
                "sudo",
                "systemd-run",
                f"--unit={unit}",
                f"--uid={os.getuid()}",
                "--property=CPUQuota=200%",
                "--property=MemoryMax=1G",
                "--property=TasksMax=128",
                "--collect",
                "/usr/bin/gst-launch-1.0",
                "videotestsrc",
                "is-live=true",
                "!",
                "fakesink",
                "sync=false",
            ],
            check=True,
            timeout=15,
        )
        pid = _wait_for_main_pid(unit)
        process_status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
        uid_match = re.search(r"^Uid:\s+(\d+)\s+", process_status, re.MULTILINE)
        assert uid_match is not None and int(uid_match.group(1)) == os.getuid()
        executable = Path(f"/proc/{pid}/exe").resolve(strict=True)
        executable_sha256 = _sha256(executable)
        membership = Path(f"/proc/{pid}/cgroup").read_text(encoding="utf-8").strip()
        prefix, separator, cgroup = membership.partition("0::/")
        assert prefix == "" and separator and cgroup
        profile = _native_profile(
            interface=interface,
            mtu=mtu,
            executable_sha256=executable_sha256,
        )
        manifest = capture_generator_runtime(
            profile,
            host="generator-native",
            pids=(pid,),
            cgroup=cgroup,
            expected_executables={pid: executable_sha256},
            gst_launch_binary=Path("/usr/bin/gst-launch-1.0"),
        )

        observations = []
        previous = read_linux_generator_counters(
            Path("/"),
            interface=interface,
            pids=(pid,),
            cgroup=cgroup,
            expected_executables={pid: executable_sha256},
            expected_mtu_bytes=mtu,
        )
        previous_at = time.monotonic()
        for _ in range(2):
            time.sleep(1)
            current = read_linux_generator_counters(
                Path("/"),
                interface=interface,
                pids=(pid,),
                cgroup=cgroup,
                expected_executables={pid: executable_sha256},
                expected_mtu_bytes=mtu,
            )
            current_at = time.monotonic()
            observations.append(
                current.observation_since(
                    previous,
                    generator_host="generator-native",
                    elapsed_seconds=current_at - previous_at,
                    timestamp=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                )
            )
            previous = current
            previous_at = current_at
        summary = summarize_generator_headroom(
            observations,
            expected_generator_host="generator-native",
            minimum_duration_seconds=2,
            expected_interval_seconds=1,
            maximum_gap_factor=3,
            observations_sha256="a" * 64,
        )
        validate_runtime_manifest(
            profile,
            manifest,
            role="generator",
            host="generator-native",
            expected_architecture=profile.generator_hosts[0].architecture,
            coordinated_anchor_start_unix_ms=manifest.capture_started_clock.observed_at_unix_ms,
            coordinated_measurement_start_unix_ms=(
                manifest.capture_completed_clock.observed_at_unix_ms + 60_000
            ),
            resource_summary=summary,
        )
    finally:
        subprocess.run(
            ["sudo", "systemctl", "stop", unit],
            check=False,
            timeout=15,
        )
