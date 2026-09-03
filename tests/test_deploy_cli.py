from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
from sqlalchemy.exc import OperationalError

import rtsp_proxy.deploy as deploy_module
import rtsp_proxy.schema_cli as schema_cli
from rtsp_proxy.deploy import (
    DeploymentError,
    DeploymentPaths,
    LinuxDeploymentHost,
    main,
)


class FakeHost:
    def __init__(self, *, schema: str = "0020_probe_observations") -> None:
        self.schema = schema
        self.active: set[str] = {"rtsp-proxy-web.service"}
        self.restarted: list[tuple[str, ...]] = []
        self.health_ok = True
        self.assets_installed = 0

    def require_root_linux(self) -> None:  # pragma: no cover - contract no-op
        pass

    def stage(self, bundle: Path, target: Path, source_root: Path) -> str:
        manifest = json.loads((bundle / "release-manifest.json").read_text())
        assert isinstance(manifest["release_id"], str)
        target.mkdir(parents=True)
        (target / "release-manifest.json").write_text(json.dumps(manifest))
        return manifest["release_id"]

    def verify(self, release: Path) -> None:
        assert (release / "release-manifest.json").is_file()

    def install_assets(self, source_root: Path, release: Path) -> None:
        self.assets_installed += 1

    def database_revision(self, release: Path, environment_file: Path) -> str:
        return self.schema

    def active_units(self) -> tuple[str, ...]:
        return tuple(sorted(self.active))

    def restart_units(self, units: tuple[str, ...]) -> None:
        self.restarted.append(units)

    def health(self, url: str, ca_file: Path | None) -> bool:
        return self.health_ok


def _bundle(root: Path, release_id: str, minimum: str, maximum: str) -> Path:
    bundle = root / f"bundle-{release_id}"
    bundle.mkdir()
    (bundle / "release-manifest.json").write_text(
        json.dumps(
            {
                "release_id": release_id,
                "schema_compatibility": {"minimum": minimum, "maximum": maximum},
            }
        )
    )
    return bundle


def test_update_switches_atomically_and_records_rollback_target(tmp_path: Path) -> None:
    paths = DeploymentPaths.under(tmp_path / "host")
    old = paths.releases / "0.11.0"
    old.mkdir(parents=True)
    (old / "release-manifest.json").write_text(
        json.dumps(
            {
                "release_id": "0.11.0",
                "schema_compatibility": {
                    "minimum": "0012_operator_sessions",
                    "maximum": "0020_probe_observations",
                },
            }
        )
    )
    paths.opt_root.mkdir(parents=True, exist_ok=True)
    paths.current.symlink_to(Path("releases/0.11.0"))
    bundle = _bundle(
        tmp_path,
        "0.12.0",
        "0012_operator_sessions",
        "0020_probe_observations",
    )
    host = FakeHost()

    result = main(
        [
            "update",
            "--bundle",
            str(bundle),
            "--environment-file",
            "/etc/rtsp-proxy/control-plane/rtsp-proxy.env",
            "--health-url",
            "https://management.example/health/ready",
        ],
        host=host,
        paths=paths,
        source_root=tmp_path,
    )

    assert result == 0
    assert paths.current.readlink() == Path("releases/0.12.0")
    receipt = json.loads(paths.receipt.read_text())
    assert receipt["current_release_id"] == "0.12.0"
    assert receipt["previous_release_id"] == "0.11.0"
    assert host.restarted == [("rtsp-proxy-web.service",)]


def test_fresh_install_stages_assets_without_activating_or_starting(tmp_path: Path) -> None:
    paths = DeploymentPaths.under(tmp_path / "host")
    bundle = _bundle(tmp_path, "0.12.0", "0012_operator_sessions", "0020_probe_observations")
    host = FakeHost()

    result = main(
        ["install", "--bundle", str(bundle)],
        host=host,
        paths=paths,
        source_root=tmp_path,
    )

    assert result == 0
    assert (paths.releases / "0.12.0/release-manifest.json").is_file()
    assert not paths.current.exists()
    assert host.assets_installed == 1
    assert host.restarted == []


def test_failed_update_health_restores_previous_release(tmp_path: Path) -> None:
    paths = DeploymentPaths.under(tmp_path / "host")
    old = paths.releases / "0.11.0"
    old.mkdir(parents=True)
    (old / "release-manifest.json").write_text(
        json.dumps(
            {
                "release_id": "0.11.0",
                "schema_compatibility": {
                    "minimum": "0012_operator_sessions",
                    "maximum": "0020_probe_observations",
                },
            }
        )
    )
    paths.opt_root.mkdir(parents=True, exist_ok=True)
    paths.current.symlink_to(Path("releases/0.11.0"))
    bundle = _bundle(tmp_path, "0.12.0", "0012_operator_sessions", "0020_probe_observations")
    host = FakeHost()
    host.health_ok = False

    try:
        main(
            [
                "update",
                "--bundle",
                str(bundle),
                "--environment-file",
                "/etc/rtsp-proxy/control-plane/rtsp-proxy.env",
                "--health-url",
                "https://management.example/health/ready",
            ],
            host=host,
            paths=paths,
            source_root=tmp_path,
        )
    except DeploymentError as error:
        assert str(error) == "activation_health_check_failed_rolled_back"
    else:  # pragma: no cover - assertion branch
        raise AssertionError("update unexpectedly succeeded")

    assert paths.current.readlink() == Path("releases/0.11.0")
    assert len(host.restarted) == 2


def test_rollback_rejects_database_newer_than_target_manifest(tmp_path: Path) -> None:
    paths = DeploymentPaths.under(tmp_path / "host")
    target = paths.releases / "0.11.0"
    target.mkdir(parents=True)
    (target / "release-manifest.json").write_text(
        json.dumps(
            {
                "release_id": "0.11.0",
                "schema_compatibility": {
                    "minimum": "0012_operator_sessions",
                    "maximum": "0019_dashboard_rate_limits",
                },
            }
        )
    )
    host = FakeHost(schema="0020_probe_observations")

    try:
        main(
            [
                "rollback",
                "--release-id",
                "0.11.0",
                "--environment-file",
                "/etc/rtsp-proxy/control-plane/rtsp-proxy.env",
                "--health-url",
                "https://management.example/health/ready",
            ],
            host=host,
            paths=paths,
            source_root=tmp_path,
        )
    except DeploymentError as error:
        assert str(error) == "database_schema_incompatible_with_release"
    else:  # pragma: no cover - assertion branch
        raise AssertionError("rollback unexpectedly succeeded")


def test_linux_host_stages_exact_clean_checkout_into_immutable_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "uv.lock").write_bytes(b"lock")
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    subprocess.run(
        ["git", "-C", str(source), "config", "user.email", "test@example.invalid"],
        check=True,
    )
    subprocess.run(["git", "-C", str(source), "config", "user.name", "Test"], check=True)
    subprocess.run(["git", "-C", str(source), "add", "uv.lock"], check=True)
    subprocess.run(["git", "-C", str(source), "commit", "-qm", "fixture"], check=True)
    commit = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    bundle = tmp_path / "bundle"
    (bundle / "dist").mkdir(parents=True)
    (bundle / "uv.lock").write_bytes(b"lock")
    (bundle / "dist/app.whl").write_bytes(b"wheel")
    (bundle / "release-manifest.json").write_text(
        json.dumps(
            {
                "release_id": "0.12.0",
                "git_commit": commit,
                "python": {
                    "lock": "uv.lock",
                    "lock_sha256": __import__("hashlib").sha256(b"lock").hexdigest(),
                    "wheel": "dist/app.whl",
                },
            }
        )
    )
    fake_uv = tmp_path / "uv"
    fake_uv.write_text(
        """#!/bin/sh
set -eu
case "$1" in
  export) for out do :; done; : >"$out" ;;
  venv)
    [ "$2" = --relocatable ] || exit 42
    for target do :; done
    mkdir -p "$target/bin"
    : >"$target/bin/python"
    ;;
  pip)
    if [ "$2" = install ]; then
      while [ "$1" != --python ]; do shift; done
      python=$2
      printf '%s\n' '#!/bin/sh' 'exit 0' >"$(dirname "$python")/rtsp-proxy-verify-release"
      chmod 755 "$(dirname "$python")/rtsp-proxy-verify-release"
    fi
    ;;
esac
"""
    )
    fake_uv.chmod(0o755)
    paths = DeploymentPaths.under(tmp_path / "host")
    host = LinuxDeploymentHost(paths, uv=fake_uv)
    monkeypatch.setattr(host, "_require_tool", lambda path, label: None)

    previous_umask = os.umask(0o077)
    try:
        release_id = host.stage(bundle, paths.releases / "0.12.0", source)
    finally:
        os.umask(previous_umask)

    release = paths.releases / "0.12.0"
    assert release_id == "0.12.0"
    assert (release / ".venv/bin/rtsp-proxy-verify-release").is_file()
    assert paths.opt_root.stat().st_mode & 0o777 == 0o755
    assert paths.releases.stat().st_mode & 0o777 == 0o755
    assert release.stat().st_mode & 0o777 == 0o755
    assert (release / ".venv").stat().st_mode & 0o777 == 0o755
    assert (release / ".venv/bin").stat().st_mode & 0o777 == 0o755
    assert (release / "runtime-requirements.txt").stat().st_mode & 0o777 == 0o644
    assert not any(path.name.startswith(".0.12.0.staging-") for path in paths.releases.iterdir())


def test_linux_host_rejects_unexpected_bundle_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = DeploymentPaths.under(tmp_path / "host")
    host = LinuxDeploymentHost(paths)
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "secret.txt").write_text("no")
    staging = tmp_path / "staging"
    staging.mkdir()

    with pytest.raises(DeploymentError, match="release_bundle_contains_unexpected_entry"):
        host._copy_bundle(bundle, staging)


def test_linux_host_preserves_bundle_executable_mode(tmp_path: Path) -> None:
    host = LinuxDeploymentHost(DeploymentPaths.under(tmp_path / "host"))
    bundle = tmp_path / "bundle"
    binary = bundle / "bin/mediamtx"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"fixture")
    binary.chmod(0o755)
    staging = tmp_path / "staging"
    staging.mkdir()

    host._copy_bundle(bundle, staging)

    assert (staging / "bin/mediamtx").stat().st_mode & 0o777 == 0o755


def test_linux_host_immutability_does_not_follow_venv_symlinks(tmp_path: Path) -> None:
    release = tmp_path / "release"
    binary_directory = release / ".venv/bin"
    binary_directory.mkdir(parents=True)
    shared_python = tmp_path / "shared-python"
    shared_python.write_bytes(b"fixture")
    shared_python.chmod(0o777)
    (binary_directory / "python3.12").symlink_to(shared_python)
    host = LinuxDeploymentHost(DeploymentPaths.under(tmp_path / "host"))

    host._make_immutable(release)

    assert shared_python.stat().st_mode & 0o777 == 0o777
    assert (binary_directory.stat().st_mode & 0o022) == 0


def test_linux_host_reports_command_exit_and_captured_stderr(tmp_path: Path) -> None:
    host = LinuxDeploymentHost(DeploymentPaths.under(tmp_path / "host"))

    with pytest.raises(DeploymentError) as captured:
        host._run(
            Path("/bin/sh"),
            "-c",
            "printf 'fatal: fixture detail\\n' >&2; exit 23",
            capture=True,
        )

    assert str(captured.value) == (
        "host_command_failed command=sh exit_code=23 stderr=fatal: fixture detail"
    )


def test_command_diagnostic_is_bounded_and_redacts_common_credentials() -> None:
    detail = deploy_module._safe_command_detail(
        "https://operator:camera-password@example.invalid/path "
        "token=private-value\n" + "x" * 2048
    )

    assert "camera-password" not in detail
    assert "private-value" not in detail
    assert "https://<redacted>@example.invalid/path" in detail
    assert "token=<redacted>" in detail
    assert len(detail) == 1024


def test_linux_host_captures_release_verifier_diagnostic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host = LinuxDeploymentHost(DeploymentPaths.under(tmp_path / "host"))
    release = tmp_path / "release"
    calls: list[tuple[tuple[Path | str, ...], bool]] = []

    def record(
        *command: Path | str,
        capture: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        calls.append((command, capture))
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(host, "_run", record)

    host.verify(release)

    assert calls == [
        (
            (
                release / ".venv/bin/rtsp-proxy-verify-release",
                "--manifest",
                str(release / "release-manifest.json"),
            ),
            True,
        )
    ]


def test_source_checkout_uses_scoped_git_safe_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "operator-owned-source"
    source.mkdir()
    lock = source / "uv.lock"
    lock.write_bytes(b"lock")
    commit = "a" * 40
    manifest: dict[str, object] = {
        "git_commit": commit,
        "python": {
            "lock": "uv.lock",
            "lock_sha256": __import__("hashlib").sha256(b"lock").hexdigest(),
        },
    }

    def git_with_different_owner(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        expected_option = f"safe.directory={source}"
        if command[1:3] != ["-c", expected_option]:
            raise subprocess.CalledProcessError(
                128,
                command,
                stderr="fatal: detected dubious ownership in repository",
            )
        stdout = f"{commit}\n" if "rev-parse" in command else ""
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(subprocess, "run", git_with_different_owner)
    host = LinuxDeploymentHost(DeploymentPaths.under(tmp_path / "host"))

    host._require_source_checkout(source, manifest)


def test_linux_host_reads_schema_and_manages_only_active_units(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = DeploymentPaths.under(tmp_path / "host")
    host = LinuxDeploymentHost(paths)
    release = tmp_path / "release"
    (release / ".venv/bin").mkdir(parents=True)
    environment = tmp_path / "rtsp-proxy.env"
    environment.write_text("RTSP_PROXY_DATABASE_URL=secret\n")
    environment.chmod(0o600)
    restarted: list[tuple[str, ...]] = []

    def fake_run(*command: Path | str, capture: bool = False) -> subprocess.CompletedProcess[str]:
        values = tuple(str(item) for item in command)
        if values[0] == "/usr/bin/systemd-run":
            return subprocess.CompletedProcess(values, 0, stdout="0020_probe_observations\n")
        if values[0] == "/usr/bin/systemctl" and values[1] == "restart":
            restarted.append(values[2:])
        return subprocess.CompletedProcess(values, 0, stdout="")

    active = {"rtsp-proxy-web.service", "rtsp-proxy-probe-broker.socket"}

    def fake_subprocess(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0 if command[-1] in active else 3)

    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(deploy_module, "_require_root_owned_file", lambda *args, **kwargs: None)
    monkeypatch.setattr(host, "_run", fake_run)
    monkeypatch.setattr(subprocess, "run", fake_subprocess)

    assert host.database_revision(release, environment) == "0020_probe_observations"
    units = host.active_units()
    host.restart_units(units)

    assert units == ("rtsp-proxy-probe-broker.socket", "rtsp-proxy-web.service")
    assert restarted == [units]


def test_status_rejects_a_symlinked_deployment_lock(tmp_path: Path) -> None:
    paths = DeploymentPaths.under(tmp_path / "host")
    paths.lock.parent.mkdir(parents=True)
    victim = tmp_path / "victim"
    victim.write_text("unchanged")
    paths.lock.symlink_to(victim)

    with pytest.raises(DeploymentError, match="deployment_lock_unavailable"):
        main(["status"], host=FakeHost(), paths=paths, source_root=tmp_path)
    assert victim.read_text() == "unchanged"


def test_linux_host_installs_only_static_assets_and_examples(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    for relative in (
        "deploy/systemd/rtsp-proxy-web.service",
        "deploy/systemd/rtsp-proxy-probe-broker.socket",
        "deploy/systemd/mediamtx.service",
        "deploy/sysusers.d/rtsp-proxy.conf",
        "deploy/tmpfiles.d/rtsp-proxy.conf",
        "deploy/tmpfiles.d/rtsp-proxy-probe-broker.conf",
        "deploy/rtsp-proxy.env.example",
        "deploy/systemd/rtsp-proxy-web-auth.conf.example",
        "deploy/systemd/rtsp-proxy-web-local-auth.conf.example",
        "deploy/nftables/rtsp-proxy.nft",
    ):
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(relative)
    paths = DeploymentPaths.under(tmp_path / "host")
    host = LinuxDeploymentHost(paths)
    commands: list[tuple[str, ...]] = []
    monkeypatch.setattr(host, "verify", lambda release: None)
    monkeypatch.setattr(host, "_require_source_checkout", lambda root, manifest: None)
    def record_command(
        *command: Path | str,
        **kwargs: object,
    ) -> subprocess.CompletedProcess[object]:
        commands.append(tuple(map(str, command)))
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(host, "_run", record_command)
    release = tmp_path / "release"
    release.mkdir()
    (release / "release-manifest.json").write_text("{}")

    host.install_assets(source, release)

    assert (paths.root / "etc/systemd/system/rtsp-proxy-web.service").is_file()
    assert (paths.root / "etc/systemd/system/rtsp-proxy-probe-broker.socket").is_file()
    assert not (paths.root / "etc/systemd/system/mediamtx.service").exists()
    assert (paths.root / "etc/rtsp-proxy/examples/rtsp-proxy.env.example").is_file()
    assert (paths.root / "etc/rtsp-proxy/examples/rtsp-proxy.nft.example").is_file()
    assert (
        paths.root / "etc/rtsp-proxy/examples/rtsp-proxy-web-auth.conf.example"
    ).is_file()
    assert (
        paths.root / "etc/rtsp-proxy/examples/rtsp-proxy-web-local-auth.conf.example"
    ).is_file()
    assert commands[-1] == ("/usr/bin/systemctl", "daemon-reload")


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("http://management.example/health/ready", "invalid_health_url"),
        ("https://user@management.example/health/ready", "invalid_health_url"),
        ("https://management.example/health/ready?secret=x", "invalid_health_url"),
    ],
)
def test_linux_host_rejects_unsafe_health_urls(tmp_path: Path, url: str, reason: str) -> None:
    host = LinuxDeploymentHost(DeploymentPaths.under(tmp_path / "host"))
    with pytest.raises(DeploymentError, match=reason):
        host.health(url, None)


def test_linux_host_health_accepts_only_http_200(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host = LinuxDeploymentHost(DeploymentPaths.under(tmp_path / "host"))

    class Response:
        status = 200

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *args: object) -> None:
            pass

    monkeypatch.setattr(
        "rtsp_proxy.deploy.request.urlopen",
        lambda *args, **kwargs: Response(),
    )
    assert host.health("https://management.example/health/ready", None)


@pytest.mark.parametrize(
    "revision",
    ["", "head", "20_probe", "0020-UPPER", "0020"],
)
def test_activate_rejects_noncanonical_database_revision(tmp_path: Path, revision: str) -> None:
    paths = DeploymentPaths.under(tmp_path / "host")
    release = paths.releases / "0.12.0"
    release.mkdir(parents=True)
    (release / "release-manifest.json").write_text(
        json.dumps(
            {
                "release_id": "0.12.0",
                "schema_compatibility": {
                    "minimum": "0012_operator_sessions",
                    "maximum": "0020_probe_observations",
                },
            }
        )
    )
    host = FakeHost(schema=revision)
    with pytest.raises(DeploymentError, match="invalid_database_revision"):
        main(
            [
                "activate",
                "--release-id",
                "0.12.0",
                "--environment-file",
                "/etc/rtsp-proxy/control-plane/rtsp-proxy.env",
                "--health-url",
                "https://management.example/health/ready",
            ],
            host=host,
            paths=paths,
            source_root=tmp_path,
        )


def test_schema_revision_cli_prints_one_authoritative_revision(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class Connection:
        def execute(self, statement: object) -> None:
            pass

        def scalars(self, statement: object) -> tuple[str, ...]:
            return ("0020_probe_observations",)

    class Context:
        def __enter__(self) -> Connection:
            return Connection()

        def __exit__(self, *args: object) -> None:
            pass

    class Engine:
        def connect(self) -> Context:
            return Context()

        def dispose(self) -> None:
            pass

    monkeypatch.setenv("RTSP_PROXY_DATABASE_URL", "postgresql+psycopg://fixture")
    monkeypatch.setattr(schema_cli, "create_engine", lambda *args, **kwargs: Engine())

    schema_cli.main()

    assert capsys.readouterr().out == "0020_probe_observations\n"


def test_schema_revision_cli_rejects_missing_database_url(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("RTSP_PROXY_DATABASE_URL", raising=False)
    with pytest.raises(SystemExit, match="1"):
        schema_cli.main()
    assert "database_url_required" in capsys.readouterr().err


def test_public_status_stage_and_asset_commands(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    paths = DeploymentPaths.under(tmp_path / "host")
    bundle = _bundle(tmp_path, "0.12.0", "0012_operator_sessions", "0020_probe_observations")
    host = FakeHost()

    assert main(["status"], host=host, paths=paths, source_root=tmp_path) == 0
    assert json.loads(capsys.readouterr().out)["current_release_id"] is None
    assert (
        main(
            ["stage", "--bundle", str(bundle)],
            host=host,
            paths=paths,
            source_root=tmp_path,
        )
        == 0
    )
    capsys.readouterr()
    assert (
        main(
            ["install-assets", "--release-id", "0.12.0"],
            host=host,
            paths=paths,
            source_root=tmp_path,
        )
        == 0
    )
    assert host.assets_installed == 1


def test_status_reports_invalid_receipt_and_rejects_unsafe_current_link(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    paths = DeploymentPaths.under(tmp_path / "host")
    paths.receipt.parent.mkdir(parents=True)
    paths.receipt.write_text("not-json")
    assert main(["status"], host=FakeHost(), paths=paths, source_root=tmp_path) == 0
    assert json.loads(capsys.readouterr().out)["receipt"] == "invalid"
    paths.opt_root.mkdir(parents=True, exist_ok=True)
    paths.current.symlink_to("../foreign")
    with pytest.raises(DeploymentError, match="unsafe_current_release_link"):
        main(["status"], host=FakeHost(), paths=paths, source_root=tmp_path)


def test_linux_host_platform_and_root_preflight_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host = LinuxDeploymentHost(DeploymentPaths.under(tmp_path / "host"))
    monkeypatch.setattr("rtsp_proxy.deploy.platform.system", lambda: "Darwin")
    with pytest.raises(DeploymentError, match="linux_host_required"):
        host.require_root_linux()
    monkeypatch.setattr("rtsp_proxy.deploy.platform.system", lambda: "Linux")
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    with pytest.raises(DeploymentError, match="root_required"):
        host.require_root_linux()


def test_existing_release_is_idempotent_only_for_same_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = DeploymentPaths.under(tmp_path / "host")
    host = LinuxDeploymentHost(paths)
    target = paths.releases / "0.12.0"
    target.mkdir(parents=True)
    bundle = _bundle(tmp_path, "0.12.0", "0012_operator_sessions", "0020_probe_observations")
    (target / "release-manifest.json").write_bytes((bundle / "release-manifest.json").read_bytes())
    monkeypatch.setattr(host, "verify", lambda release: None)
    assert host.stage(bundle, target, tmp_path) == "0.12.0"
    (bundle / "release-manifest.json").write_text('{"release_id":"0.12.0"}')
    with pytest.raises(
        DeploymentError,
        match="release_id_already_installed_with_different_manifest",
    ):
        host.stage(bundle, target, tmp_path)


def test_linux_host_health_maps_transport_failure_to_false(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host = LinuxDeploymentHost(DeploymentPaths.under(tmp_path / "host"))

    def fail(*args: object, **kwargs: object) -> None:
        raise OSError("offline")

    monkeypatch.setattr("rtsp_proxy.deploy.request.urlopen", fail)
    assert not host.health("https://management.example/health/ready", None)


@pytest.mark.parametrize(
    "revisions",
    [(), ("0019_dashboard_rate_limits", "0020_probe_observations")],
)
def test_schema_revision_cli_rejects_non_singleton_head(
    monkeypatch: pytest.MonkeyPatch,
    revisions: tuple[str, ...],
) -> None:
    class Connection:
        def execute(self, statement: object) -> None:
            pass

        def scalars(self, statement: object) -> tuple[str, ...]:
            return revisions

    class Context:
        def __enter__(self) -> Connection:
            return Connection()

        def __exit__(self, *args: object) -> None:
            pass

    class Engine:
        def connect(self) -> Context:
            return Context()

        def dispose(self) -> None:
            pass

    monkeypatch.setenv("RTSP_PROXY_DATABASE_URL", "postgresql+psycopg://fixture")
    monkeypatch.setattr(schema_cli, "create_engine", lambda *args, **kwargs: Engine())
    with pytest.raises(SystemExit, match="1"):
        schema_cli.main()


def test_schema_revision_cli_sanitizes_database_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    class Engine:
        def connect(self) -> None:
            raise OperationalError("select", {}, Exception("secret"))

        def dispose(self) -> None:
            pass

    monkeypatch.setenv("RTSP_PROXY_DATABASE_URL", "postgresql+psycopg://secret")
    monkeypatch.setattr(schema_cli, "create_engine", lambda *args, **kwargs: Engine())
    with pytest.raises(SystemExit, match="1"):
        schema_cli.main()


def test_host_file_boundary_rejects_relative_symlink_missing_and_wrong_mode(
    tmp_path: Path,
) -> None:
    relative = Path("relative.env")
    with pytest.raises(DeploymentError, match="unsafe_host_file"):
        deploy_module._require_root_owned_file(relative, allowed_modes={0o600})
    missing = tmp_path / "missing"
    with pytest.raises(DeploymentError, match="host_file_unavailable"):
        deploy_module._require_root_owned_file(missing, allowed_modes={0o600})
    target = tmp_path / "target"
    target.write_text("x")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(DeploymentError, match="unsafe_host_file"):
        deploy_module._require_root_owned_file(link, allowed_modes={0o600})
    target.chmod(0o644)
    with pytest.raises(DeploymentError, match="unsafe_host_file"):
        deploy_module._require_root_owned_file(target, allowed_modes={0o600})
