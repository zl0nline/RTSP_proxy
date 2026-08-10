from __future__ import annotations

import argparse
import platform
import sys
from collections.abc import Sequence
from pathlib import Path

from rtsp_proxy.release import ReleaseVerificationError, normalize_linux_arch, verify_release


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="rtsp-proxy-verify-release",
        description="Verify immutable RTSP Proxy release artifacts before activation.",
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--python-version", required=True)
    parser.add_argument(
        "--arch",
        choices=("amd64", "arm64"),
        help="release architecture; defaults to the native Linux machine architecture",
    )
    arguments = parser.parse_args(argv)

    try:
        architecture = arguments.arch or normalize_linux_arch(platform.machine())
        release = verify_release(
            arguments.manifest,
            expected_python=arguments.python_version,
            expected_arch=architecture,
        )
    except ReleaseVerificationError as error:
        print(f"release verification failed: {error}", file=sys.stderr)
        return 1

    print(f"verified release {release.release_id}")
    return 0
