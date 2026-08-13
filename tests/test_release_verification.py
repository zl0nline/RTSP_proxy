import hashlib
import json
from importlib.resources import files
from pathlib import Path

import pytest

from rtsp_proxy.cli import main
from rtsp_proxy.release import (
    ReleaseManifest,
    ReleaseVerificationError,
    Sha256,
    normalize_linux_arch,
    trusted_mediamtx_activation_identity,
    verify_release,
)


def test_database_migrations_are_packaged_with_the_application() -> None:
    package_root = files("rtsp_proxy")

    assert package_root.joinpath("migrations", "env.py").is_file()
    assert package_root.joinpath(
        "migrations",
        "versions",
        "0004_management_freshness.py",
    ).is_file()
    assert package_root.joinpath(
        "migrations",
        "versions",
        "0005_node_runtime.py",
    ).is_file()
    assert package_root.joinpath(
        "migrations",
        "versions",
        "0006_camera_reconcile.py",
    ).is_file()
    assert package_root.joinpath(
        "migrations",
        "versions",
        "0007_camera_move_saga.py",
    ).is_file()
    assert package_root.joinpath(
        "migrations",
        "versions",
        "0008_node_administration.py",
    ).is_file()
    assert package_root.joinpath(
        "migrations",
        "versions",
        "0010_camera_access.py",
    ).is_file()


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


@pytest.fixture(autouse=True)
def trust_test_mediamtx(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = b"#!/bin/sh\nprintf 'v1.20.0-rtsp-proxy.2\\n'\n"
    monkeypatch.setattr(
        "rtsp_proxy.release._trusted_mediamtx_identity",
        lambda _architecture, _release_id: (
            "v1.20.0-rtsp-proxy.2",
            Sha256.model_validate(sha256(payload)),
        ),
    )


def write_release(tmp_path: Path, *, wheel_payload: bytes = b"wheel") -> Path:
    mediamtx_payload = b"#!/bin/sh\nprintf 'v1.20.0-rtsp-proxy.2\\n'\n"
    ffmpeg_payload = b"#!/bin/sh\nprintf 'ffmpeg version test build\\n'\n"
    ffprobe_payload = b"#!/bin/sh\nprintf 'ffprobe version test build\\n'\n"
    artifacts = {
        "uv.lock": b"lock",
        "dist/rtsp_proxy-0.1.0-py3-none-any.whl": wheel_payload,
        "bin/mediamtx": mediamtx_payload,
        "bin/ffmpeg": ffmpeg_payload,
        "bin/ffprobe": ffprobe_payload,
    }
    for relative_path, payload in artifacts.items():
        path = tmp_path / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        if relative_path.startswith("bin/"):
            path.chmod(0o750)

    manifest = {
        "schema_version": 1,
        "release_id": "0.2.0",
        "git_commit": "a" * 40,
        "python": {
            "version": "3.12",
            "lock": "uv.lock",
            "lock_sha256": sha256(artifacts["uv.lock"]),
            "wheel": "dist/rtsp_proxy-0.1.0-py3-none-any.whl",
            "wheel_sha256": sha256(wheel_payload),
        },
        "mediamtx": {
            "version": "v1.20.0-rtsp-proxy.2",
            "linux_arch": "amd64",
            "binary": "bin/mediamtx",
            "binary_sha256": sha256(mediamtx_payload),
        },
        "ffmpeg": {
            "version": "test",
            "binary": "bin/ffmpeg",
            "binary_sha256": sha256(ffmpeg_payload),
            "ffprobe_binary": "bin/ffprobe",
            "ffprobe_sha256": sha256(ffprobe_payload),
        },
        "schema_compatibility": {
            "minimum": "0010_camera_access",
            "maximum": "0011_observability",
        },
        "config_schema_version": 1,
    }
    manifest_path = tmp_path / "release-manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return manifest_path


def test_verified_release_exposes_only_validated_artifact_paths(tmp_path: Path) -> None:
    manifest_path = write_release(tmp_path)

    release = verify_release(manifest_path, expected_python="3.12", expected_arch="amd64")

    assert release.release_id == "0.2.0"
    assert release.wheel == tmp_path / "dist/rtsp_proxy-0.1.0-py3-none-any.whl"
    assert release.mediamtx_binary == tmp_path / "bin/mediamtx"
    assert release.ffmpeg_binary == tmp_path / "bin/ffmpeg"
    assert release.ffprobe_binary == tmp_path / "bin/ffprobe"


def test_stock_or_self_declared_mediamtx_is_rejected_before_execution(tmp_path: Path) -> None:
    manifest_path = write_release(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["mediamtx"] |= {
        "version": "v1.20.0",
        "binary_sha256": sha256((tmp_path / "bin/mediamtx").read_bytes()),
    }
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ReleaseVerificationError, match="untrusted_mediamtx_artifact"):
        verify_release(manifest_path, expected_python="3.12", expected_arch="amd64")


def test_historical_release_is_trusted_for_provenance_but_not_activation() -> None:
    with pytest.raises(
        ReleaseVerificationError,
        match="mediamtx_release_activation_incompatible",
    ):
        trusted_mediamtx_activation_identity("amd64", "0.1.0")

    version, _digest = trusted_mediamtx_activation_identity("amd64", "0.2.0")
    assert version == "v1.20.0-rtsp-proxy.2"


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
    native_linux_amd64: None,
) -> None:
    manifest_path = write_release(tmp_path)

    exit_code = main(["--manifest", str(manifest_path)])

    assert exit_code == 0
    assert capsys.readouterr().out == "verified release 0.2.0\n"


def test_release_verifier_cli_fails_closed_on_tampering(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    native_linux_amd64: None,
) -> None:
    manifest_path = write_release(tmp_path)
    (tmp_path / "bin/mediamtx").write_bytes(b"tampered")

    exit_code = main(["--manifest", str(manifest_path)])

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


@pytest.fixture
def native_linux_amd64(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("rtsp_proxy.cli.platform.system", lambda: "Linux")
    monkeypatch.setattr("rtsp_proxy.cli.platform.machine", lambda: "x86_64")


def test_cli_detects_the_native_linux_runtime(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    native_linux_amd64: None,
) -> None:
    manifest_path = write_release(tmp_path)

    exit_code = main(["--manifest", str(manifest_path)])

    assert exit_code == 0
    assert capsys.readouterr().out == "verified release 0.2.0\n"


def test_cli_rejects_a_non_linux_activation_host(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest_path = write_release(tmp_path)
    monkeypatch.setattr("rtsp_proxy.cli.platform.system", lambda: "Darwin")

    exit_code = main(["--manifest", str(manifest_path)])

    assert exit_code == 1
    assert capsys.readouterr().err == "release verification failed: unsupported_platform:darwin\n"


def test_declared_binary_version_must_match_the_verified_executable(tmp_path: Path) -> None:
    manifest_path = write_release(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["ffmpeg"]["version"] = "different"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ReleaseVerificationError, match=r"version_mismatch:ffmpeg\.binary"):
        verify_release(manifest_path, expected_python="3.12", expected_arch="amd64")


def test_incompatible_config_schema_is_rejected(tmp_path: Path) -> None:
    manifest_path = write_release(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["config_schema_version"] = 2
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ReleaseVerificationError, match="config_schema_mismatch"):
        verify_release(manifest_path, expected_python="3.12", expected_arch="amd64")


def test_incompatible_database_schema_range_is_rejected(tmp_path: Path) -> None:
    manifest_path = write_release(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["schema_compatibility"] = {"minimum": "future", "maximum": "future"}
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ReleaseVerificationError, match="database_schema_mismatch"):
        verify_release(manifest_path, expected_python="3.12", expected_arch="amd64")


def test_example_manifests_cover_both_supported_linux_architectures() -> None:
    manifests = [
        ReleaseManifest.model_validate_json(path.read_text(encoding="utf-8"))
        for path in sorted(Path("deploy").glob("release-manifest.*.example.json"))
    ]

    assert {manifest.mediamtx.linux_arch for manifest in manifests} == {"amd64", "arm64"}
    assert {manifest.release_id for manifest in manifests} == {"0.2.0"}


def test_example_manifests_are_derived_from_the_artifact_catalog() -> None:
    catalog = json.loads(Path("deploy/artifact-catalog.json").read_text(encoding="utf-8"))

    for path in sorted(Path("deploy").glob("release-manifest.*.example.json")):
        manifest = ReleaseManifest.model_validate_json(path.read_text(encoding="utf-8"))
        architecture = manifest.mediamtx.linux_arch.value
        mediamtx_pin = catalog["mediamtx"]["architectures"][architecture]
        ffmpeg_pin = catalog["ffmpeg"]["architectures"][architecture]

        assert manifest.mediamtx.version == catalog["mediamtx"]["version"]
        assert manifest.mediamtx.binary_sha256.root == mediamtx_pin["binary_sha256"]
        assert manifest.ffmpeg.version == catalog["ffmpeg"]["version"]
        assert manifest.ffmpeg.binary_sha256.root == ffmpeg_pin["ffmpeg_sha256"]
        assert manifest.ffmpeg.ffprobe_sha256.root == ffmpeg_pin["ffprobe_sha256"]
