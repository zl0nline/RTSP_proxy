from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib import parse, request

_RELEASE_ID = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]{0,127}$")
_REVISION = re.compile(r"^(\d{4})_[0-9a-z_]+$")
_MANAGED_UNITS = (
    "rtsp-proxy-nftables.service",
    "rtsp-proxy-auth.service",
    "rtsp-proxy-node-runtime.socket",
    "rtsp-proxy-node-metrics.socket",
    "rtsp-proxy-probe-broker.socket",
    "rtsp-proxy-web.service",
    "rtsp-proxy@reconciler.service",
    "rtsp-proxy@probe.service",
    "rtsp-proxy-collector.service",
    "rtsp-proxy-notifier.service",
)


class DeploymentError(RuntimeError):
    """A deployment transaction failed closed."""


@dataclass(frozen=True, slots=True)
class DeploymentPaths:
    root: Path
    opt_root: Path
    releases: Path
    current: Path
    receipt: Path
    lock: Path

    @classmethod
    def under(cls, root: Path) -> DeploymentPaths:
        canonical = root.resolve()
        opt_root = canonical / "opt/rtsp-proxy"
        return cls(
            root=canonical,
            opt_root=opt_root,
            releases=opt_root / "releases",
            current=opt_root / "current",
            receipt=canonical / "var/lib/rtsp-proxy/deployment.json",
            lock=canonical / "run/lock/rtsp-proxy-deploy.lock",
        )


class DeploymentHost(Protocol):
    def require_root_linux(self) -> None: ...

    def stage(self, bundle: Path, target: Path, source_root: Path) -> str: ...

    def verify(self, release: Path) -> None: ...

    def install_assets(self, source_root: Path, release: Path) -> None: ...

    def database_revision(self, release: Path, environment_file: Path) -> str: ...

    def active_units(self) -> tuple[str, ...]: ...

    def restart_units(self, units: tuple[str, ...]) -> None: ...

    def health(self, url: str, ca_file: Path | None) -> bool: ...


class LinuxDeploymentHost:
    def __init__(self, paths: DeploymentPaths, *, uv: Path = Path("/usr/local/bin/uv")) -> None:
        self._paths = paths
        self._uv = uv

    def require_root_linux(self) -> None:
        if platform.system() != "Linux":
            raise DeploymentError("linux_host_required")
        if os.geteuid() != 0:
            raise DeploymentError("root_required")

    def stage(self, bundle: Path, target: Path, source_root: Path) -> str:
        manifest = _manifest(bundle)
        release_id = _release_id(manifest)
        if target.name != release_id or target.parent != self._paths.releases:
            raise DeploymentError("unsafe_release_target")
        if target.exists() or target.is_symlink():
            if target.is_symlink() or not target.is_dir():
                raise DeploymentError("unsafe_installed_release")
            self.verify(target)
            if _manifest_digest(target) != _manifest_digest(bundle):
                raise DeploymentError("release_id_already_installed_with_different_manifest")
            return release_id

        self._require_source_checkout(source_root, manifest)
        self._require_tool(self._uv, "uv")
        self._paths.releases.mkdir(parents=True, exist_ok=True, mode=0o755)
        staging = Path(tempfile.mkdtemp(prefix=f".{release_id}.staging-", dir=target.parent))
        try:
            self._copy_bundle(bundle, staging)
            requirements = staging / "runtime-requirements.txt"
            self._run(
                self._uv,
                "export",
                "--locked",
                "--no-dev",
                "--no-emit-project",
                "--format",
                "requirements.txt",
                "--project",
                str(source_root),
                "--output-file",
                str(requirements),
            )
            self._run(
                self._uv,
                "venv",
                "--relocatable",
                "--python",
                "3.12",
                str(staging / ".venv"),
            )
            python = staging / ".venv/bin/python"
            self._run(self._uv, "pip", "sync", "--python", str(python), str(requirements))
            wheel = _artifact_path(staging, manifest, "python", "wheel")
            self._run(
                self._uv,
                "pip",
                "install",
                "--python",
                str(python),
                "--no-deps",
                str(wheel),
            )
            self.verify(staging)
            staging.chmod(0o755)
            self._make_immutable(staging)
            os.replace(staging, target)
            _fsync_directory(target.parent)
        except BaseException:
            shutil.rmtree(staging, ignore_errors=True)
            raise
        return release_id

    def verify(self, release: Path) -> None:
        verifier = release / ".venv/bin/rtsp-proxy-verify-release"
        self._run(
            verifier,
            "--manifest",
            str(release / "release-manifest.json"),
            capture=True,
        )

    def install_assets(self, source_root: Path, release: Path) -> None:
        self.verify(release)
        self._require_source_checkout(source_root, _manifest(release))
        assets: tuple[tuple[Path, Path, int], ...] = tuple(
            (path, Path("etc/systemd/system") / path.name, 0o644)
            for path in sorted((source_root / "deploy/systemd").glob("*.service"))
            if path.name != "mediamtx.service"
        ) + tuple(
            (path, Path("etc/systemd/system") / path.name, 0o644)
            for path in sorted((source_root / "deploy/systemd").glob("*.socket"))
        ) + (
            (
                source_root / "deploy/sysusers.d/rtsp-proxy.conf",
                Path("usr/lib/sysusers.d/rtsp-proxy.conf"),
                0o644,
            ),
            (
                source_root / "deploy/tmpfiles.d/rtsp-proxy.conf",
                Path("usr/lib/tmpfiles.d/rtsp-proxy.conf"),
                0o644,
            ),
            (
                source_root / "deploy/tmpfiles.d/rtsp-proxy-probe-broker.conf",
                Path("usr/lib/tmpfiles.d/rtsp-proxy-probe-broker.conf"),
                0o644,
            ),
        )
        for source, relative, mode in assets:
            _install_file(source, self._paths.root / relative, mode)
        examples = self._paths.root / "etc/rtsp-proxy/examples"
        examples.mkdir(parents=True, exist_ok=True, mode=0o750)
        for source in sorted((source_root / "deploy").glob("*.env.example")):
            _install_file(source, examples / source.name, 0o640)
        for source, name in (
            (
                source_root / "deploy/systemd/rtsp-proxy-web-auth.conf.example",
                "rtsp-proxy-web-auth.conf.example",
            ),
            (
                source_root / "deploy/systemd/rtsp-proxy-web-local-auth.conf.example",
                "rtsp-proxy-web-local-auth.conf.example",
            ),
            (source_root / "deploy/nftables/rtsp-proxy.nft", "rtsp-proxy.nft.example"),
        ):
            _install_file(source, examples / name, 0o640)
        self._run(
            Path("/usr/bin/systemd-sysusers"),
            str(self._paths.root / "usr/lib/sysusers.d/rtsp-proxy.conf"),
        )
        self._run(
            Path("/usr/bin/systemd-tmpfiles"),
            "--create",
            str(self._paths.root / "usr/lib/tmpfiles.d/rtsp-proxy.conf"),
        )
        self._run(Path("/usr/bin/systemctl"), "daemon-reload")

    def database_revision(self, release: Path, environment_file: Path) -> str:
        _require_root_owned_file(environment_file, allowed_modes={0o600, 0o640})
        command = release / ".venv/bin/rtsp-proxy-schema-revision"
        result = self._run(
            Path("/usr/bin/systemd-run"),
            "--quiet",
            "--wait",
            "--pipe",
            "--collect",
            "--uid=rtsp-proxy",
            "--gid=rtsp-proxy",
            f"--property=EnvironmentFile={environment_file}",
            str(command),
            capture=True,
        )
        revision = result.stdout.strip()
        _revision_number(revision)
        return revision

    def active_units(self) -> tuple[str, ...]:
        active: list[str] = []
        for unit in _MANAGED_UNITS:
            result = subprocess.run(
                ["/usr/bin/systemctl", "is-active", "--quiet", unit], check=False
            )
            if result.returncode == 0:
                active.append(unit)
        return tuple(active)

    def restart_units(self, units: tuple[str, ...]) -> None:
        if units:
            self._run(Path("/usr/bin/systemctl"), "restart", *units)

    def health(self, url: str, ca_file: Path | None) -> bool:
        parsed = parse.urlsplit(url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise DeploymentError("invalid_health_url")
        context = None
        if ca_file is not None:
            _require_root_owned_file(ca_file, allowed_modes={0o600, 0o640, 0o644})
            import ssl

            context = ssl.create_default_context(cafile=str(ca_file))
        try:
            with request.urlopen(url, timeout=10, context=context) as response:
                return int(response.status) == 200
        except (OSError, ValueError):
            return False

    def _require_source_checkout(self, root: Path, manifest: dict[str, object]) -> None:
        expected = manifest.get("git_commit")
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{40}", expected):
            raise DeploymentError("invalid_manifest_git_commit")
        safe_directory = f"safe.directory={root}"
        head = self._run(
            Path("/usr/bin/git"),
            "-c",
            safe_directory,
            "-C",
            str(root),
            "rev-parse",
            "HEAD",
            capture=True,
        )
        status = self._run(
            Path("/usr/bin/git"),
            "-c",
            safe_directory,
            "-C",
            str(root),
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            capture=True,
        )
        if head.stdout.strip() != expected or status.stdout:
            raise DeploymentError("source_checkout_not_exact_release_commit")
        lock = _artifact_path(root, manifest, "python", "lock")
        if _sha256(lock) != _nested_string(manifest, "python", "lock_sha256"):
            raise DeploymentError("source_lock_mismatch")

    @staticmethod
    def _copy_bundle(bundle: Path, staging: Path) -> None:
        allowed = {"bin", "dist", "libexec", "release-manifest.json", "uv.lock"}
        for source in bundle.rglob("*"):
            relative = source.relative_to(bundle)
            if relative.parts[0] not in allowed:
                raise DeploymentError("release_bundle_contains_unexpected_entry")
            if source.is_symlink() or not (source.is_dir() or source.is_file()):
                raise DeploymentError("release_bundle_contains_unsafe_entry")
            destination = staging / relative
            if source.is_dir():
                destination.mkdir(exist_ok=True)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                source_mode = stat.S_IMODE(source.stat(follow_symlinks=False).st_mode)
                shutil.copyfile(source, destination)
                destination.chmod(source_mode & 0o777)

    @staticmethod
    def _make_immutable(root: Path) -> None:
        for path in [root, *root.rglob("*")]:
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                continue
            path.chmod(stat.S_IMODE(mode) & ~(stat.S_IWGRP | stat.S_IWOTH))

    @staticmethod
    def _require_tool(path: Path, label: str) -> None:
        try:
            status_value = path.stat()
        except OSError as error:
            raise DeploymentError(f"{label}_unavailable") from error
        if not stat.S_ISREG(status_value.st_mode) or not os.access(path, os.X_OK):
            raise DeploymentError(f"{label}_unavailable")
        if status_value.st_uid != 0 or status_value.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise DeploymentError(f"{label}_untrusted")

    @staticmethod
    def _run(*command: Path | str, capture: bool = False) -> subprocess.CompletedProcess[str]:
        command_label = Path(str(command[0])).name if command else "unknown"
        try:
            return subprocess.run(
                [str(value) for value in command],
                check=True,
                text=True,
                stdout=subprocess.PIPE if capture else None,
                stderr=subprocess.PIPE if capture else None,
                timeout=180,
                env={
                    "LC_ALL": "C",
                    "PATH": os.defpath,
                    "UV_PYTHON_INSTALL_DIR": "/opt/rtsp-proxy/python",
                },
            )
        except subprocess.CalledProcessError as error:
            message = (
                f"host_command_failed command={command_label} exit_code={error.returncode}"
            )
            detail = _safe_command_detail(error.stderr)
            if detail:
                message = f"{message} stderr={detail}"
            raise DeploymentError(message) from error
        except subprocess.TimeoutExpired as error:
            raise DeploymentError(
                f"host_command_failed command={command_label} timeout_seconds=180"
            ) from error
        except OSError as error:
            suffix = f" errno={error.errno}" if error.errno is not None else ""
            raise DeploymentError(
                f"host_command_failed command={command_label}{suffix}"
            ) from error


def main(
    argv: Sequence[str] | None = None,
    *,
    host: DeploymentHost | None = None,
    paths: DeploymentPaths | None = None,
    source_root: Path | None = None,
) -> int:
    parser = _parser()
    arguments = parser.parse_args(argv)
    selected_paths = paths or DeploymentPaths.under(Path("/"))
    selected_host = host or LinuxDeploymentHost(selected_paths, uv=arguments.uv)
    selected_source = (
        source_root or arguments.source_root or Path(__file__).resolve().parents[2]
    ).resolve()
    selected_host.require_root_linux()
    with _deployment_lock(selected_paths.lock):
        if arguments.command == "status":
            print(json.dumps(_status(selected_paths), sort_keys=True))
            return 0
        if arguments.command == "install-assets":
            release = selected_paths.releases / arguments.release_id
            selected_host.install_assets(selected_source, release)
            print("deployment assets installed; services remain disabled")
            return 0
        if arguments.command == "stage":
            release_id = _stage(selected_host, selected_paths, arguments.bundle, selected_source)
            print(f"staged release {release_id}")
            return 0
        if arguments.command == "install":
            release_id = _stage(selected_host, selected_paths, arguments.bundle, selected_source)
            selected_host.install_assets(selected_source, selected_paths.releases / release_id)
            print(
                f"installed release {release_id} without activation; configure the host, "
                "migrate PostgreSQL, then run activate"
            )
            return 0
        if arguments.command == "update":
            release_id = _stage(selected_host, selected_paths, arguments.bundle, selected_source)
            selected_host.install_assets(selected_source, selected_paths.releases / release_id)
            _activate(
                selected_host,
                selected_paths,
                release_id,
                arguments.environment_file,
                arguments.health_url,
                arguments.ca_file,
            )
            print(f"activated release {release_id}")
            return 0
        if arguments.command in {"activate", "rollback"}:
            _activate(
                selected_host,
                selected_paths,
                arguments.release_id,
                arguments.environment_file,
                arguments.health_url,
                arguments.ca_file,
            )
            print(f"activated release {arguments.release_id}")
            return 0
    raise DeploymentError("unsupported_deployment_command")


def cli() -> None:
    try:
        raise SystemExit(main())
    except (DeploymentError, BlockingIOError) as error:
        print(f"deployment failed: {error}", file=sys.stderr)
        raise SystemExit(1) from None


def _stage(host: DeploymentHost, paths: DeploymentPaths, bundle: Path, source: Path) -> str:
    release_id = _release_id(_manifest(bundle))
    return host.stage(bundle.resolve(), paths.releases / release_id, source)


def _activate(
    host: DeploymentHost,
    paths: DeploymentPaths,
    release_id: str,
    environment_file: Path,
    health_url: str,
    ca_file: Path | None,
) -> None:
    if not _RELEASE_ID.fullmatch(release_id):
        raise DeploymentError("invalid_release_id")
    release = paths.releases / release_id
    host.verify(release)
    revision = host.database_revision(release, environment_file)
    if not _schema_compatible(_manifest(release), revision):
        raise DeploymentError("database_schema_incompatible_with_release")
    previous = _current_release(paths)
    units = host.active_units()
    _switch(paths, release_id)
    try:
        host.restart_units(units)
        if units and not host.health(health_url, ca_file):
            raise DeploymentError("activation_health_check_failed")
    except BaseException as error:
        if previous is not None:
            previous_release = paths.releases / previous
            if _schema_compatible(_manifest(previous_release), revision):
                _switch(paths, previous)
                host.restart_units(units)
                raise DeploymentError("activation_health_check_failed_rolled_back") from error
        raise
    _write_receipt(paths, release_id, previous, revision)


def _switch(paths: DeploymentPaths, release_id: str) -> None:
    paths.opt_root.mkdir(parents=True, exist_ok=True)
    temporary = paths.opt_root / f".current.next.{os.getpid()}"
    if temporary.exists() or temporary.is_symlink():
        temporary.unlink()
    temporary.symlink_to(Path("releases") / release_id)
    os.replace(temporary, paths.current)
    _fsync_directory(paths.opt_root)


def _write_receipt(paths: DeploymentPaths, current: str, previous: str | None, schema: str) -> None:
    paths.receipt.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    payload = {
        "schema_version": 1,
        "current_release_id": current,
        "previous_release_id": previous,
        "database_revision": schema,
    }
    temporary = paths.receipt.with_name(f".{paths.receipt.name}.next.{os.getpid()}")
    temporary.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    os.replace(temporary, paths.receipt)
    _fsync_directory(paths.receipt.parent)


def _status(paths: DeploymentPaths) -> dict[str, object]:
    current = _current_release(paths)
    receipt: object = None
    if paths.receipt.is_file():
        try:
            receipt = json.loads(paths.receipt.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            receipt = "invalid"
    installed = (
        sorted(path.name for path in paths.releases.iterdir() if path.is_dir())
        if paths.releases.is_dir()
        else []
    )
    return {"current_release_id": current, "installed_release_ids": installed, "receipt": receipt}


def _current_release(paths: DeploymentPaths) -> str | None:
    if not paths.current.is_symlink():
        return None
    target = paths.current.readlink()
    if (
        len(target.parts) != 2
        or target.parts[0] != "releases"
        or not _RELEASE_ID.fullmatch(target.parts[1])
    ):
        raise DeploymentError("unsafe_current_release_link")
    return target.parts[1]


def _schema_compatible(manifest: dict[str, object], revision: str) -> bool:
    current = _revision_number(revision)
    minimum = _revision_number(_nested_string(manifest, "schema_compatibility", "minimum"))
    maximum = _revision_number(_nested_string(manifest, "schema_compatibility", "maximum"))
    return minimum <= current <= maximum


def _revision_number(value: str) -> int:
    match = _REVISION.fullmatch(value)
    if match is None:
        raise DeploymentError("invalid_database_revision")
    return int(match.group(1))


def _manifest(root: Path) -> dict[str, object]:
    try:
        payload = json.loads((root / "release-manifest.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise DeploymentError("invalid_release_manifest") from error
    if not isinstance(payload, dict):
        raise DeploymentError("invalid_release_manifest")
    return payload


def _release_id(manifest: dict[str, object]) -> str:
    value = manifest.get("release_id")
    if not isinstance(value, str) or _RELEASE_ID.fullmatch(value) is None:
        raise DeploymentError("invalid_release_id")
    return value


def _nested_string(manifest: dict[str, object], section: str, field: str) -> str:
    nested = manifest.get(section)
    value = nested.get(field) if isinstance(nested, dict) else None
    if not isinstance(value, str):
        raise DeploymentError("invalid_release_manifest")
    return value


def _artifact_path(root: Path, manifest: dict[str, object], section: str, field: str) -> Path:
    relative = Path(_nested_string(manifest, section, field))
    if relative.is_absolute() or ".." in relative.parts:
        raise DeploymentError("unsafe_release_artifact_path")
    return root / relative


def _manifest_digest(root: Path) -> str:
    return _sha256(root / "release-manifest.json")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_command_detail(value: str | bytes | None) -> str:
    if value is None:
        return ""
    text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value
    printable = "".join(character if character.isprintable() else " " for character in text)
    collapsed = " ".join(printable.split())
    collapsed = re.sub(
        r"([A-Za-z][A-Za-z0-9+.-]*://)[^/@\s]+@",
        r"\1<redacted>@",
        collapsed,
    )
    collapsed = re.sub(
        r"(?i)\b(password|token|secret|authorization)=\S+",
        r"\1=<redacted>",
        collapsed,
    )
    return collapsed[:1024]


def _install_file(source: Path, target: Path, mode: int) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.next.{os.getpid()}")
    shutil.copyfile(source, temporary)
    temporary.chmod(mode)
    os.replace(temporary, target)
    _fsync_directory(target.parent)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@contextmanager
def _deployment_lock(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise DeploymentError("deployment_lock_unavailable") from error
    try:
        status_value = os.fstat(descriptor)
        if (
            not stat.S_ISREG(status_value.st_mode)
            or status_value.st_uid != os.geteuid()
            or stat.S_IMODE(status_value.st_mode) != 0o600
            or status_value.st_nlink != 1
        ):
            raise DeploymentError("deployment_lock_untrusted")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)


def _require_root_owned_file(path: Path, *, allowed_modes: set[int]) -> None:
    if not path.is_absolute() or path.is_symlink():
        raise DeploymentError("unsafe_host_file")
    try:
        status_value = path.stat()
    except OSError as error:
        raise DeploymentError("host_file_unavailable") from error
    if (
        not stat.S_ISREG(status_value.st_mode)
        or status_value.st_uid != 0
        or stat.S_IMODE(status_value.st_mode) not in allowed_modes
        or status_value.st_nlink != 1
    ):
        raise DeploymentError("unsafe_host_file")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rtsp-proxy-deploy")
    parser.add_argument("--uv", type=Path, default=Path("/usr/local/bin/uv"))
    parser.add_argument("--source-root", type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    install_assets = commands.add_parser("install-assets")
    install_assets.add_argument("--release-id", required=True)
    stage = commands.add_parser("stage")
    stage.add_argument("--bundle", type=Path, required=True)
    install = commands.add_parser("install")
    install.add_argument("--bundle", type=Path, required=True)
    update = commands.add_parser("update")
    update.add_argument("--bundle", type=Path, required=True)
    _activation_arguments(update)
    for name in ("activate", "rollback"):
        command = commands.add_parser(name)
        command.add_argument("--release-id", required=True)
        _activation_arguments(command)
    return parser


def _activation_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--environment-file", type=Path, required=True)
    parser.add_argument("--health-url", required=True)
    parser.add_argument("--ca-file", type=Path)


if __name__ == "__main__":  # pragma: no cover - console entrypoint
    cli()
