from __future__ import annotations

import hashlib
import io
import json
import stat
import subprocess
import sys
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from rtsp_proxy.host_platform import (
    HostFacts,
    PackagePlan,
    _command_output,
    _ensure_pinned_uv,
    _glibc_version,
    _install_packages,
    _mounted_filesystem,
    _read_text,
    _require_safe_install_directory,
    _require_trusted_uv,
    _systemd_version,
    collect_host_facts,
    evaluate_host,
    main,
    package_plan,
    parse_os_release,
)


def _facts(**overrides: object) -> HostFacts:
    values: dict[str, object] = {
        "os_id": "ubuntu",
        "os_id_like": ("debian",),
        "os_version": "26.04",
        "architecture": "aarch64",
        "kernel_version": "6.18.37-ophub",
        "systemd_version": 259,
        "python_version": (3, 14, 4),
        "glibc_version": (2, 43),
        "pid1": "systemd",
        "cgroup2": True,
        "bpffs": True,
        "btf": True,
        "commands": frozenset(
            {
                "curl",
                "git",
                "jq",
                "nft",
                "openssl",
                "psql",
                "systemctl",
                "systemd-run",
            }
        ),
    }
    values.update(overrides)
    return HostFacts(**values)  # type: ignore[arg-type]


def test_capability_report_accepts_modern_arm_systemd_linux_without_distro_allowlist() -> None:
    report = evaluate_host(_facts(os_id="armbian", os_id_like=("ubuntu", "debian")))

    assert report.supported is True
    assert report.architecture == "arm64"
    assert report.blockers == ()
    assert report.profile == "modern-systemd-linux-v1"
    assert json.loads(report.as_json())["supported"] is True


@pytest.mark.parametrize(
    ("overrides", "blocker"),
    [
        ({"python_version": (3, 11, 9)}, "python_too_old"),
        ({"glibc_version": (2, 38)}, "glibc_too_old"),
        ({"systemd_version": 254}, "systemd_too_old"),
        ({"kernel_version": "6.7.12"}, "kernel_too_old"),
        ({"cgroup2": False}, "cgroup_v2_unavailable"),
        ({"bpffs": False}, "bpffs_unavailable"),
        ({"btf": False}, "kernel_btf_unavailable"),
        ({"pid1": "openrc-init"}, "systemd_not_pid1"),
        ({"kernel_name": "Darwin"}, "linux_required"),
        ({"systemd_state": "degraded"}, "systemd_not_operational:degraded"),
        (
            {"cgroup_controllers": frozenset({"cpu", "pids"})},
            "cgroup_resource_controllers_unavailable",
        ),
        ({"executable_paths": frozenset()}, "missing_executable:/usr/bin/env"),
    ],
)
def test_capability_report_fails_closed_with_stable_blocker_codes(
    overrides: dict[str, object], blocker: str
) -> None:
    report = evaluate_host(_facts(**overrides))

    assert report.supported is False
    assert blocker in report.blockers


def test_missing_runtime_commands_are_reported_together() -> None:
    report = evaluate_host(_facts(commands=frozenset({"systemctl", "systemd-run"})))

    assert report.blockers == (
        "missing_command:curl",
        "missing_command:git",
        "missing_command:jq",
        "missing_command:nft",
        "missing_command:openssl",
        "missing_command:psql",
    )


@pytest.mark.parametrize(
    ("manager", "expected_package"),
    [
        ("apt-get", "postgresql-client"),
        ("dnf", "postgresql"),
        ("zypper", "postgresql"),
        ("pacman", "postgresql-libs"),
    ],
)
def test_package_adapters_cover_major_modern_systemd_families(
    manager: str, expected_package: str
) -> None:
    plan = package_plan(frozenset({manager}))

    assert plan.manager == manager
    assert expected_package in plan.packages
    assert "nftables" in plan.packages
    assert {"bpftool", "bpf"} & set(plan.packages)


def test_os_release_parser_handles_quotes_comments_and_id_like() -> None:
    parsed = parse_os_release(
        '# generated\nID="armbian"\nID_LIKE="ubuntu debian"\nVERSION_ID=26.04\n'
    )

    assert parsed == {
        "ID": "armbian",
        "ID_LIKE": "ubuntu debian",
        "VERSION_ID": "26.04",
    }


def test_os_release_parser_ignores_malformed_entries() -> None:
    assert parse_os_release('lower=value\nBROKEN="unterminated\nEMPTY=\n') == {
        "EMPTY": ""
    }


def test_package_plan_rejects_an_unknown_manager() -> None:
    with pytest.raises(ValueError, match="supported_package_manager_unavailable"):
        package_plan(frozenset({"apk"}))


def test_host_collection_and_low_level_probes_are_total(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert collect_host_facts().python_version[:2] == (3, 12)
    missing = tmp_path / "missing"
    assert _read_text(missing) == ""
    monkeypatch.setattr(
        "rtsp_proxy.host_platform._read_text",
        lambda _path: (
            "malformed\n"
            "31 24 0:27 / /sys/fs/bpf rw,nosuid - bpf bpf rw\n"
        ),
    )
    assert _mounted_filesystem("/sys/fs/bpf", "bpf") is True
    assert _mounted_filesystem("/sys/fs/cgroup", "cgroup2") is False


def test_version_probes_handle_success_and_execution_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "rtsp_proxy.host_platform.subprocess.run",
        lambda *_arguments, **_keywords: SimpleNamespace(
            returncode=0,
            stdout="systemd 259 (259.5)\nfeatures\n",
        ),
    )
    assert _systemd_version() == 259
    assert _command_output(("systemctl", "is-system-running")) == (
        "systemd 259 (259.5)\nfeatures"
    )
    monkeypatch.setattr(
        "rtsp_proxy.host_platform.subprocess.run",
        lambda *_arguments, **_keywords: (_ for _ in ()).throw(OSError("missing")),
    )
    assert _systemd_version() == 0
    assert _command_output(("missing",)) == "unavailable"


def test_glibc_probe_handles_valid_and_unavailable_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("rtsp_proxy.host_platform.os.confstr", lambda _name: "glibc 2.43")
    assert _glibc_version() == (2, 43)
    monkeypatch.setattr(
        "rtsp_proxy.host_platform.os.confstr",
        lambda _name: (_ for _ in ()).throw(ValueError("unsupported")),
    )
    assert _glibc_version() == (0, 0)


def test_package_installer_uses_a_bounded_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[tuple[str, ...], dict[str, str]]] = []
    monkeypatch.setattr("rtsp_proxy.host_platform.os.geteuid", lambda: 0)
    monkeypatch.setattr(
        "rtsp_proxy.host_platform.subprocess.run",
        lambda command, check, env: calls.append((command, env)),
    )
    plan = PackagePlan(
        manager="apt-get",
        packages=("nftables",),
        commands=(("apt-get", "install", "--yes", "nftables"),),
    )

    _install_packages(plan)

    assert calls[0][0] == plan.commands[0]
    assert calls[0][1]["DEBIAN_FRONTEND"] == "noninteractive"
    monkeypatch.setattr("rtsp_proxy.host_platform.os.geteuid", lambda: 1000)
    with pytest.raises(PermissionError, match="package_install_requires_root"):
        _install_packages(plan)


def test_uv_checks_reject_unsafe_paths_without_network(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="uv_install_directory_untrusted"):
        _require_safe_install_directory(tmp_path)
    candidate = tmp_path / "uv"
    candidate.write_text("not trusted", encoding="utf-8")
    candidate.chmod(0o777)
    with pytest.raises(ValueError, match="uv_executable_untrusted"):
        _require_trusted_uv(candidate)


def test_missing_pinned_uv_fails_without_downloading(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="uv_executable_missing"):
        _ensure_pinned_uv(
            tmp_path / "missing-uv",
            catalog_path=Path("deploy/bootstrap-artifacts.json"),
            architecture="arm64",
            install_missing=False,
        )


def test_uv_version_check_accepts_official_metadata_and_rejects_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = tmp_path / "uv"
    candidate.write_text("#!/bin/sh\nprintf 'uv 0.12.3 (arm64-build)\\n'\n", encoding="utf-8")
    candidate.chmod(0o755)
    original_stat = Path.stat

    def trusted_stat(path: Path, *, follow_symlinks: bool = True) -> object:
        observed = original_stat(path, follow_symlinks=follow_symlinks)
        if path == candidate:
            return SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o755)
        return observed

    monkeypatch.setattr(Path, "stat", trusted_stat)

    _require_trusted_uv(candidate, expected_version="0.12.3")
    candidate.write_text("#!/bin/sh\nprintf 'uv 9.9.9\\n'\n", encoding="utf-8")
    with pytest.raises(ValueError, match="uv_version_mismatch"):
        _require_trusted_uv(candidate, expected_version="0.12.3")


def test_uv_catalog_and_path_validation_fail_before_download(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="uv_destination_must_be_absolute"):
        _ensure_pinned_uv(
            Path("relative/uv"),
            catalog_path=Path("deploy/bootstrap-artifacts.json"),
            architecture="arm64",
        )
    invalid_catalog = tmp_path / "invalid.json"
    invalid_catalog.write_text('{"schema_version":2}', encoding="utf-8")
    with pytest.raises(ValueError, match="bootstrap_artifact_catalog_invalid"):
        _ensure_pinned_uv(
            tmp_path / "uv",
            catalog_path=invalid_catalog,
            architecture="arm64",
        )


def test_host_doctor_install_flow_uses_one_report_interface(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    facts = _facts(commands=_facts().commands | {"apt-get"})
    installed: list[str] = []
    verified: list[str] = []
    monkeypatch.setattr("rtsp_proxy.host_platform.collect_host_facts", lambda: facts)
    monkeypatch.setattr(
        "rtsp_proxy.host_platform._install_packages",
        lambda plan: installed.append(plan.manager),
    )
    monkeypatch.setattr(
        "rtsp_proxy.host_platform._ensure_pinned_uv",
        lambda *_arguments, **_keywords: verified.append("uv"),
    )

    result = main(
        [
            "--install",
            "--json",
            "--uv",
            str(tmp_path / "uv"),
            "--bootstrap-catalog",
            "deploy/bootstrap-artifacts.json",
        ]
    )

    assert result == 0
    assert installed == ["apt-get"]
    assert verified == ["uv"]
    assert json.loads(capsys.readouterr().out)["supported"] is True


def test_host_doctor_refuses_platform_mutation_before_package_install(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        "rtsp_proxy.host_platform.collect_host_facts",
        lambda: _facts(systemd_version=200, commands=_facts().commands | {"apt-get"}),
    )

    assert main(["--install", "--json"]) == 1
    assert json.loads(capsys.readouterr().out) == {
        "error": "host_capability_check_failed_before_package_install"
    }


def test_host_doctor_human_report_lists_all_blockers(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        "rtsp_proxy.host_platform.collect_host_facts",
        lambda: _facts(commands=frozenset(), architecture="mips64"),
    )

    assert main([]) == 1
    output = capsys.readouterr().out
    assert "architecture: unsupported" in output
    assert "BLOCKER: unsupported_architecture:mips64" in output
    assert "BLOCKER: missing_command:nft" in output


def test_host_doctor_json_uses_the_public_report_shape() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "rtsp_proxy.host_platform", "--json"],
        check=False,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert result.returncode in {0, 1}
    assert set(payload) == {
        "architecture",
        "blockers",
        "capabilities",
        "distribution",
        "package_adapter",
        "profile",
        "supported",
        "versions",
    }
    assert payload["profile"] == "modern-systemd-linux-v1"


def test_bootstrap_delegates_to_capability_module_without_distribution_allowlist() -> None:
    script = Path("tools/bootstrap_rtsp_proxy_host.sh").read_text(encoding="utf-8")

    assert "host_platform.py" in script
    assert "unsupported distribution" not in script
    assert "unsupported Ubuntu release" not in script
    assert "apt-get" not in script


def test_pinned_uv_installer_verifies_archive_and_publishes_atomically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = b"#!/bin/sh\nprintf 'uv 0.12.3\\n'\n"
    archive_stream = io.BytesIO()
    with tarfile.open(fileobj=archive_stream, mode="w:gz") as archive:
        member = tarfile.TarInfo("uv-aarch64-unknown-linux-gnu/uv")
        member.size = len(executable)
        member.mode = 0o755
        archive.addfile(member, io.BytesIO(executable))
    payload = archive_stream.getvalue()
    catalog = {
        "schema_version": 1,
        "uv": {
            "version": "0.12.3",
            "architectures": {
                "arm64": {
                    "archive_url": (
                        "https://github.com/astral-sh/uv/releases/download/0.12.3/"
                        "uv-aarch64-unknown-linux-gnu.tar.gz"
                    ),
                    "archive_sha256": hashlib.sha256(payload).hexdigest(),
                    "member": "uv-aarch64-unknown-linux-gnu/uv",
                }
            },
        },
    }
    catalog_path = tmp_path / "catalog.json"
    catalog_path.write_text(json.dumps(catalog), encoding="utf-8")

    class _Response(io.BytesIO):
        def __enter__(self) -> _Response:
            return self

        def __exit__(self, *_arguments: object) -> None:
            self.close()

    monkeypatch.setattr(
        "rtsp_proxy.host_platform.request.urlopen",
        lambda _url, timeout: _Response(payload),
    )
    monkeypatch.setattr("rtsp_proxy.host_platform.os.chown", lambda *_arguments: None)
    monkeypatch.setattr(
        "rtsp_proxy.host_platform._require_safe_install_directory",
        lambda _path: None,
    )
    validated: list[tuple[Path, str | None]] = []
    monkeypatch.setattr(
        "rtsp_proxy.host_platform._require_trusted_uv",
        lambda path, expected_version=None: validated.append((path, expected_version)),
    )
    destination = tmp_path / "bin/uv"
    destination.parent.mkdir()

    _ensure_pinned_uv(destination, catalog_path=catalog_path, architecture="arm64")

    assert destination.read_bytes() == executable
    assert destination.stat().st_mode & 0o777 == 0o755
    assert validated == [(destination, "0.12.3")]


def test_pinned_uv_installer_rejects_checksum_mismatch_before_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    catalog = {
        "schema_version": 1,
        "uv": {
            "version": "0.12.3",
            "architectures": {
                "arm64": {
                    "archive_url": (
                        "https://github.com/astral-sh/uv/releases/download/0.12.3/"
                        "uv-aarch64-unknown-linux-gnu.tar.gz"
                    ),
                    "archive_sha256": "0" * 64,
                    "member": "uv-aarch64-unknown-linux-gnu/uv",
                }
            },
        },
    }
    catalog_path = tmp_path / "catalog.json"
    catalog_path.write_text(json.dumps(catalog), encoding="utf-8")

    class _Response(io.BytesIO):
        def __enter__(self) -> _Response:
            return self

        def __exit__(self, *_arguments: object) -> None:
            self.close()

    monkeypatch.setattr(
        "rtsp_proxy.host_platform.request.urlopen",
        lambda _url, timeout: _Response(b"not the admitted archive"),
    )
    destination = tmp_path / "bin/uv"

    with pytest.raises(ValueError, match="uv_archive_checksum_mismatch"):
        _ensure_pinned_uv(destination, catalog_path=catalog_path, architecture="arm64")

    assert not destination.exists()


def test_bootstrap_artifact_catalog_pins_official_uv_archives() -> None:
    catalog = json.loads(
        Path("deploy/bootstrap-artifacts.json").read_text(encoding="utf-8")
    )

    assert catalog["schema_version"] == 1
    assert catalog["uv"]["version"] == "0.12.3"
    assert set(catalog["uv"]["architectures"]) == {"amd64", "arm64"}
    for artifact in catalog["uv"]["architectures"].values():
        assert artifact["archive_url"].startswith(
            "https://github.com/astral-sh/uv/releases/download/0.12.3/"
        )
        assert len(artifact["archive_sha256"]) == 64


def test_ci_qualifies_real_package_adapters_before_publishing_native_bundles() -> None:
    workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")

    for profile in (
        "debian-13",
        "fedora-42",
        "rocky-10",
        "opensuse-tumbleweed",
        "arch",
    ):
        assert f"- {profile}" in workflow
    assert "needs: [host-package-adapter, test, probe-ffprobe-contract]" in workflow
    assert 'tools/ci/test_host_package_adapter.sh "${{ matrix.profile }}"' in workflow
