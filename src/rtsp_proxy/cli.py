from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from rtsp_proxy.release import ReleaseVerificationError, verify_release


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="rtsp-proxy-verify-release",
        description="Verify immutable RTSP Proxy release artifacts before activation.",
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--python-version", required=True)
    parser.add_argument("--arch", required=True, choices=("amd64", "arm64"))
    arguments = parser.parse_args(argv)

    try:
        release = verify_release(
            arguments.manifest,
            expected_python=arguments.python_version,
            expected_arch=arguments.arch,
        )
    except ReleaseVerificationError as error:
        print(f"release verification failed: {error}", file=sys.stderr)
        return 1

    print(f"verified release {release.release_id}")
    return 0
