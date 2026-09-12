from __future__ import annotations

import sys
from pathlib import Path

EXPECTED_TEXT_FILES = (
    "01-anonymous.snapshot.txt",
    "01-login.snapshot.txt",
    "02-dashboard.snapshot.txt",
    "03-confirmation.snapshot.txt",
    "04-logged-out.snapshot.txt",
)
EXPECTED_PNG_FILES = (
    "01-login.png",
    "02-dashboard.png",
    "02-overview-1440-light.png",
    "02-overview-1440-dark.png",
    "02-overview-390-dark.png",
    "02-camera-create.png",
    "02-camera-status.png",
    "02-catalog-1024.png",
    "02-camera-768.png",
    "02-camera-390.png",
    "02-node.png",
    "02-camera-monitoring.png",
    "02-camera-access.png",
    "02-camera-management.png",
    "03-confirmation.png",
    "04-logged-out.png",
)
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
SOURCE_SECRET_CANARIES = (
    b"browser-source-password-canary-0123456789abcdef",
    b"browser-new-source-password-canary-0123456789abcdef",
)
MAX_TEXT_BYTES = 1_048_576
MAX_PNG_BYTES = 16_777_216


def _fail(reason: str) -> int:
    print(reason, file=sys.stderr)
    return 1


def verify_artifacts(root: Path) -> int:
    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        return _fail("browser_evidence_directory_invalid")

    expected_names = set(EXPECTED_TEXT_FILES + EXPECTED_PNG_FILES)
    actual_names = {entry.name for entry in root.iterdir()}
    if actual_names != expected_names:
        return _fail("browser_evidence_file_set_invalid")

    for name in EXPECTED_TEXT_FILES:
        path = root / name
        if path.is_symlink() or not path.is_file():
            return _fail("browser_evidence_text_invalid")
        size = path.stat().st_size
        if size < 1 or size > MAX_TEXT_BYTES:
            return _fail("browser_evidence_text_invalid")
        content = path.read_bytes()
        if any(canary in content for canary in SOURCE_SECRET_CANARIES):
            return _fail("browser_evidence_secret_canary_present")

    for name in EXPECTED_PNG_FILES:
        path = root / name
        if path.is_symlink() or not path.is_file():
            return _fail("browser_evidence_png_invalid")
        size = path.stat().st_size
        if size <= len(PNG_SIGNATURE) or size > MAX_PNG_BYTES:
            return _fail("browser_evidence_png_invalid")
        content = path.read_bytes()
        if not content.startswith(PNG_SIGNATURE):
            return _fail("browser_evidence_png_invalid")
        if any(canary in content for canary in SOURCE_SECRET_CANARIES):
            return _fail("browser_evidence_secret_canary_present")

    return 0


def main() -> int:
    if len(sys.argv) != 2:
        return _fail("usage: verify_dashboard_browser_artifacts.py ARTIFACT_DIR")
    return verify_artifacts(Path(sys.argv[1]))


if __name__ == "__main__":
    raise SystemExit(main())
