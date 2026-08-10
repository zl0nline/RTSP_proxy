import hashlib
import json
from pathlib import Path

import pytest

from rtsp_proxy.cli import main
from rtsp_proxy.release import (
    ReleaseManifest,
    ReleaseVerificationError,
    normalize_linux_arch,
    verify_release,
)


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def write_release(tmp_path: Path, *, wheel_payload: bytes = b"wheel") -> Path:
    artifacts = {
        "uv.lock": b"lock",
        "dist/rtsp_proxy-0.1.0-py3-none-any.whl": wheel_payload,
        "bin/mediamtx": b"mediamtx",
    }
    for relative_path, payload in artifacts.items():
        path = tmp_path / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)

    manifest = {
        "schema_version": 1,
        "release_id": "0.1.0",
        "git_commit": "a" * 40,
        "python": {
            "version": "3.12",
            "lock": "uv.lock",
            "lock_sha256": sha256(artifacts["uv.lock"]),
            "wheel": "dist/rtsp_proxy-0.1.0-py3-none-any.whl",
            "wheel_sha256": sha256(wheel_payload),
        },
        "mediamtx": {
            "version": "v0.0.0-test",
            "linux_arch": "amd64",
            "binary": "bin/mediamtx",
            "binary_sha256": sha256(artifacts["bin/mediamtx"]),
        },
        "ffmpeg": {"version": "test"},
        "schema_compatibility": {"minimum": "base", "maximum": "base"},
        "config_schema_version": 1,
    }
    manifest_path = tmp_path / "release-manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return manifest_path


def test_verified_release_exposes_only_validated_artifact_paths(tmp_path: Path) -> None:
    manifest_path = write_release(tmp_path)

    release = verify_release(manifest_path, expected_python="3.12", expected_arch="amd64")

    assert release.release_id == "0.1.0"
    assert release.wheel == tmp_path / "dist/rtsp_proxy-0.1.0-py3-none-any.whl"
    assert release.mediamtx_binary == tmp_path / "bin/mediamtx"


def test_tampered_artifact_is_rejected_with_a_stable_reason(tmp_path: Path) -> None:
    manifest_path = write_release(tmp_path)
    (tmp_path / "dist/rtsp_proxy-0.1.0-py3-none-any.whl").write_bytes(b"tampered")

    with pytest.raises(ReleaseVerificationError, match=r"checksum_mismatch:python\.wheel"):
        verify_release(manifest_path, expected_python="3.12", expected_arch="amd64")


def test_artifact_cannot_escape_the_release_directory(tmp_path: Path) -> None:
    manifest_path = write_release(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["mediamtx"]["binary"] = "../mediamtx"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ReleaseVerificationError, match=r"unsafe_path:mediamtx\.binary"):
        verify_release(manifest_path, expected_python="3.12", expected_arch="amd64")


def test_incompatible_python_runtime_is_rejected(tmp_path: Path) -> None:
    manifest_path = write_release(tmp_path)

    with pytest.raises(ReleaseVerificationError, match="python_version_mismatch"):
        verify_release(manifest_path, expected_python="3.13", expected_arch="amd64")


def test_release_for_a_different_linux_architecture_is_rejected(tmp_path: Path) -> None:
    manifest_path = write_release(tmp_path)

    with pytest.raises(ReleaseVerificationError, match="linux_arch_mismatch"):
        verify_release(manifest_path, expected_python="3.12", expected_arch="arm64")


def test_release_verifier_cli_is_usable_by_linux_installation_automation(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    manifest_path = write_release(tmp_path)

    exit_code = main(
        [
            "--manifest",
            str(manifest_path),
            "--python-version",
            "3.12",
            "--arch",
            "amd64",
        ]
    )

    assert exit_code == 0
    assert capsys.readouterr().out == "verified release 0.1.0\n"


def test_release_verifier_cli_fails_closed_on_tampering(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    manifest_path = write_release(tmp_path)
    (tmp_path / "bin/mediamtx").write_bytes(b"tampered")

    exit_code = main(
        [
            "--manifest",
            str(manifest_path),
            "--python-version",
            "3.12",
            "--arch",
            "amd64",
        ]
    )

    assert exit_code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "release verification failed: checksum_mismatch:mediamtx.binary\n"


def test_non_utf8_manifest_is_rejected(tmp_path: Path) -> None:
    manifest_path = tmp_path / "release-manifest.json"
    manifest_path.write_bytes(b"\xff")

    with pytest.raises(ReleaseVerificationError, match="invalid_manifest"):
        verify_release(manifest_path, expected_python="3.12", expected_arch="amd64")


@pytest.mark.parametrize(
    ("machine", "expected"),
    [
        ("x86_64", "amd64"),
        ("AMD64", "amd64"),
        ("aarch64", "arm64"),
        ("ARM64", "arm64"),
    ],
)
def test_linux_machine_architecture_has_one_canonical_release_name(
    machine: str,
    expected: str,
) -> None:
    assert normalize_linux_arch(machine) == expected


def test_unknown_linux_machine_architecture_fails_closed() -> None:
    with pytest.raises(ReleaseVerificationError, match="unsupported_linux_arch:riscv64"):
        normalize_linux_arch("riscv64")


def test_cli_detects_the_native_linux_architecture_when_not_overridden(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest_path = write_release(tmp_path)
    monkeypatch.setattr("rtsp_proxy.cli.platform.machine", lambda: "x86_64")

    exit_code = main(
        [
            "--manifest",
            str(manifest_path),
            "--python-version",
            "3.12",
        ]
    )

    assert exit_code == 0
    assert capsys.readouterr().out == "verified release 0.1.0\n"


def test_example_manifests_cover_both_supported_linux_architectures() -> None:
    manifests = [
        ReleaseManifest.model_validate_json(path.read_text(encoding="utf-8"))
        for path in sorted(Path("deploy").glob("release-manifest.*.example.json"))
    ]

    assert {manifest.mediamtx.linux_arch for manifest in manifests} == {"amd64", "arm64"}
    assert len({manifest.release_id for manifest in manifests}) == 2
