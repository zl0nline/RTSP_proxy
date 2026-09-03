import hashlib
import json
from importlib.resources import files
from pathlib import Path

import pytest

from rtsp_proxy.cli import main
from rtsp_proxy.release import (
    APPLICATION_SCHEMA,
    ReleaseManifest,
    ReleaseVerificationError,
    Sha256,
    normalize_linux_arch,
    trusted_mediamtx_activation_identity,
    trusted_probe_connect_guard_identity,
    trusted_probe_ffprobe_identity,
    verify_release,
)


def test_database_migrations_are_packaged_with_the_application() -> None:
    package_root = files("rtsp_proxy")

    assert package_root.joinpath("artifacts", "probe_ffprobe.json").is_file()
    assert package_root.joinpath("artifacts", "probe_connect_guard.json").is_file()
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
    assert package_root.joinpath(
        "migrations",
        "versions",
        "0011_observability.py",
    ).is_file()
    assert package_root.joinpath(
        "migrations",
        "versions",
        "0012_operator_sessions.py",
    ).is_file()
    assert package_root.joinpath(
        "migrations",
        "versions",
        "0013_operator_login.py",
    ).is_file()
    assert package_root.joinpath(
        "migrations",
        "versions",
        "0014_camera_catalog_projection.py",
    ).is_file()
    assert package_root.joinpath(
        "migrations",
        "versions",
        "0015_camera_name_contract.py",
    ).is_file()
    assert package_root.joinpath(
        "migrations",
        "versions",
        "0016_node_registration_idempotency.py",
    ).is_file()
    assert package_root.joinpath(
        "migrations",
        "versions",
        "0017_access_grant_idempotency.py",
    ).is_file()
    assert package_root.joinpath(
        "migrations",
        "versions",
        "0018_camera_registration_idempotency.py",
    ).is_file()
    assert package_root.joinpath(
        "migrations",
        "versions",
        "0019_dashboard_rate_limits.py",
    ).is_file()
    assert package_root.joinpath(
        "migrations",
        "versions",
        "0020_probe_observations.py",
    ).is_file()
    assert package_root.joinpath(
        "migrations",
        "versions",
        "0021_local_operator_login.py",
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


@pytest.fixture(autouse=True)
def trust_test_probe_ffprobe(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = b"#!/bin/sh\nprintf 'ffprobe version probe-test\\n'\n"
    monkeypatch.setattr(
        "rtsp_proxy.release._trusted_probe_ffprobe_identity",
        lambda _architecture: (
            "probe-test",
            Sha256.model_validate(sha256(payload)),
        ),
    )


@pytest.fixture(autouse=True)
def trust_test_probe_connect_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = b"test probe connect guard object"
    monkeypatch.setattr(
        "rtsp_proxy.release._trusted_probe_connect_guard_identity",
        lambda _architecture: (
            "0.1.0",
            Sha256.model_validate(sha256(payload)),
        ),
    )


def write_release(tmp_path: Path, *, wheel_payload: bytes = b"wheel") -> Path:
    mediamtx_payload = b"#!/bin/sh\nprintf 'v1.20.0-rtsp-proxy.2\\n'\n"
    ffmpeg_payload = b"#!/bin/sh\nprintf 'ffmpeg version test build\\n'\n"
    ffprobe_payload = b"#!/bin/sh\nprintf 'ffprobe version test build\\n'\n"
    probe_ffprobe_payload = b"#!/bin/sh\nprintf 'ffprobe version probe-test\\n'\n"
    probe_guard_payload = b"test probe connect guard object"
    artifacts = {
        "uv.lock": b"lock",
        "dist/rtsp_proxy-0.1.0-py3-none-any.whl": wheel_payload,
        "bin/mediamtx": mediamtx_payload,
        "bin/ffmpeg": ffmpeg_payload,
        "bin/ffprobe": ffprobe_payload,
        "libexec/rtsp-proxy-probe/ffprobe": probe_ffprobe_payload,
        "libexec/rtsp-proxy-probe/rtsp_probe_connect_guard.bpf.o": probe_guard_payload,
    }
    for relative_path, payload in artifacts.items():
        path = tmp_path / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        if relative_path.startswith(("bin/", "libexec/")):
            path.chmod(0o750)

    manifest = {
        "schema_version": 4,
        "release_id": "0.5.0",
        "git_commit": "a" * 40,
        "python": {
            "version": "3.12",
            "lock": "uv.lock",
            "lock_sha256": sha256(artifacts["uv.lock"]),
            "wheel": "dist/rtsp_proxy-0.1.0-py3-none-any.whl",
            "wheel_sha256": sha256(wheel_payload),
        },
        "mediamtx": {
            "release_id": "0.2.0",
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
        "probe_ffprobe": {
            "version": "probe-test",
            "linux_arch": "amd64",
            "binary": "libexec/rtsp-proxy-probe/ffprobe",
            "binary_sha256": sha256(probe_ffprobe_payload),
        },
        "probe_connect_guard": {
            "release_id": "0.1.0",
            "linux_arch": "amd64",
            "object": "libexec/rtsp-proxy-probe/rtsp_probe_connect_guard.bpf.o",
            "object_sha256": sha256(probe_guard_payload),
        },
        "schema_compatibility": {
            "minimum": "0012_operator_sessions",
            "maximum": APPLICATION_SCHEMA,
        },
        "config_schema_version": 1,
    }
    manifest_path = tmp_path / "release-manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return manifest_path


def test_verified_release_exposes_only_validated_artifact_paths(tmp_path: Path) -> None:
    manifest_path = write_release(tmp_path)

    release = verify_release(manifest_path, expected_python="3.12", expected_arch="amd64")

    assert release.release_id == "0.5.0"
    assert release.wheel == tmp_path / "dist/rtsp_proxy-0.1.0-py3-none-any.whl"
    assert release.mediamtx_binary == tmp_path / "bin/mediamtx"
    assert release.ffmpeg_binary == tmp_path / "bin/ffmpeg"
    assert release.ffprobe_binary == tmp_path / "bin/ffprobe"
    assert release.probe_ffprobe_binary == tmp_path / "libexec/rtsp-proxy-probe/ffprobe"
    assert release.probe_connect_guard_object == (
        tmp_path / "libexec/rtsp-proxy-probe/rtsp_probe_connect_guard.bpf.o"
    )


def test_controlled_probe_ffprobe_is_bound_to_packaged_trust(tmp_path: Path) -> None:
    manifest_path = write_release(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["probe_ffprobe"]["binary_sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(
        ReleaseVerificationError,
        match="untrusted_probe_ffprobe_artifact",
    ):
        verify_release(manifest_path, expected_python="3.12", expected_arch="amd64")


def test_packaged_probe_ffprobe_catalog_covers_both_linux_architectures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.undo()
    amd64_version, amd64_digest = trusted_probe_ffprobe_identity("amd64")
    arm64_version, arm64_digest = trusted_probe_ffprobe_identity("arm64")

    assert amd64_version == arm64_version == "9b6c896-rtsp-proxy.1"
    assert amd64_digest != arm64_digest


def test_packaged_probe_connect_guard_catalog_covers_both_linux_architectures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.undo()
    amd64_release, amd64_digest = trusted_probe_connect_guard_identity("amd64")
    arm64_release, arm64_digest = trusted_probe_connect_guard_identity("arm64")

    assert amd64_release == arm64_release == "0.1.0"
    assert amd64_digest == arm64_digest


def test_connect_guard_object_is_bound_to_packaged_trust(tmp_path: Path) -> None:
    manifest_path = write_release(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["probe_connect_guard"]["object_sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(
        ReleaseVerificationError,
        match="untrusted_probe_connect_guard_artifact",
    ):
        verify_release(manifest_path, expected_python="3.12", expected_arch="amd64")


class _FakePackagedResource:
    def __init__(self, payload: str) -> None:
        self._payload = payload

    def joinpath(self, *_parts: str) -> "_FakePackagedResource":
        return self

    def read_text(self, *, encoding: str) -> str:
        assert encoding == "utf-8"
        return self._payload


@pytest.mark.parametrize(
    "payload",
    [
        "[]",
        '{"schema_version":2}',
        '{"schema_version":1,"version":"candidate","architectures":{}}',
        (
            '{"schema_version":1,"version":7,'
            '"architectures":{"amd64":{"binary_sha256":"'
            + "0" * 64
            + '"}}}'
        ),
        (
            '{"schema_version":1,"version":"candidate",'
            '"architectures":{"amd64":{"binary_sha256":"not-a-digest"}}}'
        ),
    ],
)
def test_malformed_packaged_probe_ffprobe_catalog_fails_closed(
    payload: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.undo()
    monkeypatch.setattr(
        "rtsp_proxy.release.files",
        lambda _package: _FakePackagedResource(payload),
    )

    with pytest.raises(
        ReleaseVerificationError,
        match="trusted_artifact_catalog_invalid",
    ):
        trusted_probe_ffprobe_identity("amd64")


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


def test_probe_ffprobe_for_a_different_architecture_is_rejected(tmp_path: Path) -> None:
    manifest_path = write_release(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["probe_ffprobe"]["linux_arch"] = "arm64"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ReleaseVerificationError, match="probe_ffprobe_arch_mismatch"):
        verify_release(manifest_path, expected_python="3.12", expected_arch="amd64")


def test_probe_connect_guard_for_a_different_architecture_is_rejected(
    tmp_path: Path,
) -> None:
    manifest_path = write_release(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["probe_connect_guard"]["linux_arch"] = "arm64"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ReleaseVerificationError, match="probe_connect_guard_arch_mismatch"):
        verify_release(manifest_path, expected_python="3.12", expected_arch="amd64")


def test_release_verifier_cli_is_usable_by_linux_installation_automation(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    native_linux_amd64: None,
) -> None:
    manifest_path = write_release(tmp_path)

    exit_code = main(["--manifest", str(manifest_path)])

    assert exit_code == 0
    assert capsys.readouterr().out == "verified release 0.5.0\n"


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
    assert capsys.readouterr().out == "verified release 0.5.0\n"


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
    assert {manifest.probe_connect_guard.linux_arch for manifest in manifests} == {
        "amd64",
        "arm64",
    }
    assert {manifest.release_id for manifest in manifests} == {"0.13.8"}
    assert {manifest.mediamtx.release_id for manifest in manifests} == {"0.2.1"}
    assert {manifest.probe_connect_guard.release_id for manifest in manifests} == {
        "0.1.0"
    }


def test_previous_application_manifest_is_not_claimed_as_rollback_after_0015(
    tmp_path: Path,
) -> None:
    manifest_path = write_release(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["schema_compatibility"]["maximum"] = "0014_camera_catalog_projection"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ReleaseVerificationError, match="database_schema_mismatch"):
        verify_release(manifest_path, expected_python="3.12", expected_arch="amd64")


def test_example_manifests_are_derived_from_the_artifact_catalog() -> None:
    catalog = json.loads(Path("deploy/artifact-catalog.json").read_text(encoding="utf-8"))

    for path in sorted(Path("deploy").glob("release-manifest.*.example.json")):
        manifest = ReleaseManifest.model_validate_json(path.read_text(encoding="utf-8"))
        architecture = manifest.mediamtx.linux_arch.value
        mediamtx_pin = catalog["mediamtx"]["architectures"][architecture]
        ffmpeg_pin = catalog["ffmpeg"]["architectures"][architecture]
        probe_ffprobe_pin = catalog["probe_ffprobe"]["architectures"][architecture]
        probe_guard_pin = catalog["probe_connect_guard"]["architectures"][architecture]

        assert manifest.mediamtx.version == catalog["mediamtx"]["version"]
        assert manifest.mediamtx.binary_sha256.root == mediamtx_pin["binary_sha256"]
        assert manifest.ffmpeg.version == catalog["ffmpeg"]["version"]
        assert manifest.ffmpeg.binary_sha256.root == ffmpeg_pin["ffmpeg_sha256"]
        assert manifest.ffmpeg.ffprobe_sha256.root == ffmpeg_pin["ffprobe_sha256"]
        assert manifest.probe_ffprobe.version == catalog["probe_ffprobe"]["version"]
        assert (
            manifest.probe_ffprobe.binary_sha256.root
            == probe_ffprobe_pin["binary_sha256"]
        )
        assert (
            manifest.probe_connect_guard.release_id
            == catalog["probe_connect_guard"]["release_id"]
        )
        assert (
            manifest.probe_connect_guard.object_sha256.root
            == probe_guard_pin["object_sha256"]
        )
