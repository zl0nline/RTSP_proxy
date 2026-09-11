from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import platform
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Final
from urllib import request

PROFILE: Final = "modern-systemd-linux-v1"
SYSTEM_COMMAND_PATH: Final = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
MINIMUM_KERNEL: Final = (6, 8)
MINIMUM_SYSTEMD: Final = 255
MINIMUM_PYTHON: Final = (3, 12)
MINIMUM_GLIBC: Final = (2, 39)
REQUIRED_COMMANDS: Final = frozenset(
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
)
REQUIRED_PATHS: Final = frozenset(
    {
        "/usr/bin/env",
        "/usr/bin/getent",
        "/usr/bin/git",
        "/usr/bin/install",
        "/usr/bin/sh",
        "/usr/bin/systemctl",
        "/usr/bin/systemd-run",
        "/usr/bin/systemd-sysusers",
        "/usr/bin/systemd-tmpfiles",
        "/usr/sbin/nft",
    }
)


@dataclass(frozen=True, slots=True)
class HostFacts:
    os_id: str
    os_id_like: tuple[str, ...]
    os_version: str
    architecture: str
    kernel_version: str
    systemd_version: int
    python_version: tuple[int, int, int]
    glibc_version: tuple[int, int]
    pid1: str
    cgroup2: bool
    bpffs: bool
    btf: bool
    commands: frozenset[str]
    ipv6: bool = True
    executable_paths: frozenset[str] = REQUIRED_PATHS
    kernel_name: str = "Linux"
    systemd_state: str = "running"
    cgroup_controllers: frozenset[str] = frozenset({"cpu", "memory", "pids"})


@dataclass(frozen=True, slots=True)
class PackagePlan:
    manager: str
    packages: tuple[str, ...]
    commands: tuple[tuple[str, ...], ...]


@dataclass(frozen=True, slots=True)
class HostReport:
    profile: str
    supported: bool
    architecture: str
    distribution: dict[str, object]
    versions: dict[str, object]
    capabilities: dict[str, bool]
    package_adapter: str | None
    blockers: tuple[str, ...]
    limitations: tuple[str, ...]

    def as_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))


_PACKAGE_SETS: Final[dict[str, tuple[str, ...]]] = {
    "apt-get": (
        "bpftool",
        "ca-certificates",
        "curl",
        "git",
        "iproute2",
        "jq",
        "nftables",
        "openssl",
        "postgresql-client",
        "systemd",
        "util-linux",
    ),
    "dnf": (
        "bpftool",
        "ca-certificates",
        "curl",
        "git",
        "iproute",
        "jq",
        "nftables",
        "openssl",
        "postgresql",
        "systemd",
        "util-linux",
    ),
    "zypper": (
        "bpftool",
        "ca-certificates",
        "curl",
        "git",
        "iproute2",
        "jq",
        "nftables",
        "openssl",
        "postgresql",
        "systemd",
        "util-linux",
    ),
    "pacman": (
        "bpf",
        "ca-certificates",
        "curl",
        "git",
        "iproute2",
        "jq",
        "nftables",
        "openssl",
        "postgresql-libs",
        "systemd",
        "util-linux",
    ),
}


def parse_os_release(content: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            continue
        try:
            values = shlex.split(raw_value, comments=True, posix=True)
        except ValueError:
            continue
        if len(values) == 1:
            result[key] = values[0]
        elif raw_value == "":
            result[key] = ""
    return result


def package_plan(available_commands: frozenset[str]) -> PackagePlan:
    manager = next(
        (
            candidate
            for candidate in ("apt-get", "dnf", "zypper", "pacman")
            if candidate in available_commands
        ),
        None,
    )
    if manager is None:
        raise ValueError("supported_package_manager_unavailable")
    packages = _PACKAGE_SETS[manager]
    commands: tuple[tuple[str, ...], ...]
    if manager == "apt-get":
        commands = (
            ("apt-get", "-o", "Acquire::Retries=10", "-o", "Acquire::https::Timeout=30", "update"),
            (
                "apt-get",
                "-o",
                "Acquire::Retries=10",
                "-o",
                "Acquire::https::Timeout=30",
                "install",
                "--yes",
                *packages,
            ),
        )
    elif manager == "dnf":
        commands = (("dnf", "install", "--assumeyes", *packages),)
    elif manager == "zypper":
        commands = (
            ("zypper", "--non-interactive", "refresh"),
            ("zypper", "--non-interactive", "install", "--no-recommends", *packages),
        )
    else:
        commands = (
            (
                "pacman",
                "--sync",
                "--refresh",
                "--sysupgrade",
                "--needed",
                "--noconfirm",
                *packages,
            ),
        )
    return PackagePlan(manager=manager, packages=packages, commands=commands)


def evaluate_host(facts: HostFacts) -> HostReport:
    architecture = _normalize_architecture(facts.architecture)
    capabilities = {
        "bpffs": facts.bpffs,
        "cgroup_v2": facts.cgroup2,
        "cgroup_resource_controllers": {
            "cpu",
            "memory",
            "pids",
        }.issubset(facts.cgroup_controllers),
        "kernel_btf": facts.btf,
        "linux": facts.kernel_name == "Linux",
        "ipv6": facts.ipv6,
        "systemd_operational": facts.systemd_state == "running",
        "systemd_pid1": facts.pid1 == "systemd",
    }
    blockers: list[str] = []
    if not capabilities["linux"]:
        blockers.append("linux_required")
    if architecture == "unsupported":
        blockers.append(f"unsupported_architecture:{facts.architecture or 'unknown'}")
    if _version_prefix(facts.kernel_version) < MINIMUM_KERNEL:
        blockers.append("kernel_too_old")
    if facts.systemd_version < MINIMUM_SYSTEMD:
        blockers.append("systemd_too_old")
    if facts.python_version[:2] < MINIMUM_PYTHON:
        blockers.append("python_too_old")
    if facts.glibc_version < MINIMUM_GLIBC:
        blockers.append("glibc_too_old")
    if not capabilities["systemd_pid1"]:
        blockers.append("systemd_not_pid1")
    if not capabilities["cgroup_v2"]:
        blockers.append("cgroup_v2_unavailable")
    if not capabilities["cgroup_resource_controllers"]:
        blockers.append("cgroup_resource_controllers_unavailable")
    if not capabilities["bpffs"]:
        blockers.append("bpffs_unavailable")
    if not capabilities["kernel_btf"]:
        blockers.append("kernel_btf_unavailable")
    if not capabilities["systemd_operational"]:
        blockers.append(f"systemd_not_operational:{facts.systemd_state or 'unknown'}")
    blockers.extend(
        f"missing_command:{command}" for command in sorted(REQUIRED_COMMANDS - facts.commands)
    )
    blockers.extend(
        f"missing_executable:{path}"
        for path in sorted(REQUIRED_PATHS - facts.executable_paths)
    )
    available_managers = facts.commands & _PACKAGE_SETS.keys()
    adapter = next(
        (
            candidate
            for candidate in ("apt-get", "dnf", "zypper", "pacman")
            if candidate in available_managers
        ),
        None,
    )
    return HostReport(
        profile=PROFILE,
        supported=not blockers,
        architecture=architecture,
        distribution={
            "id": facts.os_id,
            "id_like": list(facts.os_id_like),
            "version": facts.os_version,
        },
        versions={
            "glibc": ".".join(map(str, facts.glibc_version)),
            "kernel": facts.kernel_version,
            "python": ".".join(map(str, facts.python_version)),
            "systemd": facts.systemd_version,
        },
        capabilities=capabilities,
        package_adapter=adapter,
        blockers=tuple(blockers),
        limitations=() if facts.ipv6 else ("ipv6_unavailable",),
    )


def collect_host_facts() -> HostFacts:
    os_release = parse_os_release(_read_text(Path("/etc/os-release")))
    commands = frozenset(
        command
        for command in REQUIRED_COMMANDS | _PACKAGE_SETS.keys()
        if shutil.which(command) is not None
    )
    return HostFacts(
        os_id=os_release.get("ID", "unknown"),
        os_id_like=tuple(os_release.get("ID_LIKE", "").split()),
        os_version=os_release.get("VERSION_ID", "unknown"),
        architecture=platform.machine(),
        kernel_version=platform.release(),
        systemd_version=_systemd_version(),
        python_version=(sys.version_info.major, sys.version_info.minor, sys.version_info.micro),
        glibc_version=_glibc_version(),
        pid1=_read_text(Path("/proc/1/comm")).strip(),
        cgroup2=_mounted_filesystem("/sys/fs/cgroup", "cgroup2"),
        bpffs=_mounted_filesystem("/sys/fs/bpf", "bpf"),
        btf=os.access("/sys/kernel/btf/vmlinux", os.R_OK),
        ipv6=_loopback_family_available(socket.AF_INET6, "::1"),
        commands=commands,
        executable_paths=frozenset(
            path for path in REQUIRED_PATHS if os.access(path, os.X_OK)
        ),
        kernel_name=platform.system(),
        systemd_state=_command_output(("systemctl", "is-system-running")),
        cgroup_controllers=frozenset(
            _read_text(Path("/sys/fs/cgroup/cgroup.controllers")).split()
        ),
    )


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return ""


def _mounted_filesystem(target: str, filesystem: str) -> bool:
    for line in _read_text(Path("/proc/self/mountinfo")).splitlines():
        left, separator, right = line.partition(" - ")
        if not separator:
            continue
        left_fields = left.split()
        right_fields = right.split()
        if len(left_fields) >= 5 and right_fields and left_fields[4] == target:
            return right_fields[0] == filesystem
    return False


def _loopback_family_available(family: socket.AddressFamily, address: str) -> bool:
    try:
        with socket.socket(family, socket.SOCK_STREAM) as listener:
            listener.bind((address, 0))
    except OSError:
        return False
    return True


def _systemd_version() -> int:
    try:
        result = subprocess.run(
            ("systemctl", "--version"),
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
            env={"LC_ALL": "C", "PATH": SYSTEM_COMMAND_PATH},
        )
    except (OSError, subprocess.TimeoutExpired):
        return 0
    match = re.search(r"^systemd\s+(\d+)", result.stdout, re.MULTILINE)
    return int(match.group(1)) if match else 0


def _command_output(command: tuple[str, ...]) -> str:
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
            env={"LC_ALL": "C", "PATH": SYSTEM_COMMAND_PATH},
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable"
    return result.stdout.strip() or "unavailable"


def _glibc_version() -> tuple[int, int]:
    try:
        value = os.confstr("CS_GNU_LIBC_VERSION") or ""
    except (OSError, ValueError):
        value = ""
    match = re.fullmatch(r"glibc\s+(\d+)\.(\d+)(?:\.\d+)?", value)
    return (int(match.group(1)), int(match.group(2))) if match else (0, 0)


def _version_prefix(value: str) -> tuple[int, int]:
    match = re.match(r"^(\d+)\.(\d+)", value)
    return (int(match.group(1)), int(match.group(2))) if match else (0, 0)


def _normalize_architecture(value: str) -> str:
    return {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(
        value.strip().lower(), "unsupported"
    )


def _install_packages(plan: PackagePlan) -> None:
    if os.geteuid() != 0:
        raise PermissionError("package_install_requires_root")
    environment = {"LC_ALL": "C", "PATH": SYSTEM_COMMAND_PATH}
    if plan.manager == "apt-get":
        environment["DEBIAN_FRONTEND"] = "noninteractive"
    for command in plan.commands:
        subprocess.run(command, check=True, env=environment)


def _ensure_pinned_uv(
    destination: Path,
    *,
    catalog_path: Path,
    architecture: str,
    install_missing: bool = True,
) -> None:
    if not destination.is_absolute():
        raise ValueError("uv_destination_must_be_absolute")
    try:
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        if catalog.get("schema_version") != 1:
            raise ValueError
        uv = catalog["uv"]
        version = uv["version"]
        artifact = uv["architectures"][architecture]
        url = artifact["archive_url"]
        expected_digest = artifact["archive_sha256"]
        member_name = artifact["member"]
        if (
            not isinstance(version, str)
            or not re.fullmatch(r"\d+\.\d+\.\d+", version)
            or not isinstance(url, str)
            or not url.startswith(
                f"https://github.com/astral-sh/uv/releases/download/{version}/"
            )
            or not isinstance(expected_digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected_digest)
            or not isinstance(member_name, str)
            or not re.fullmatch(r"uv-[A-Za-z0-9_-]+/uv", member_name)
        ):
            raise ValueError
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        raise ValueError("bootstrap_artifact_catalog_invalid") from None
    if destination.exists() or destination.is_symlink():
        _require_trusted_uv(destination, expected_version=version)
        return
    if not install_missing:
        raise ValueError("uv_executable_missing")

    with request.urlopen(url, timeout=60) as response:
        archive = response.read(64 * 1024 * 1024 + 1)
    if len(archive) > 64 * 1024 * 1024:
        raise ValueError("uv_archive_too_large")
    if hashlib.sha256(archive).hexdigest() != expected_digest:
        raise ValueError("uv_archive_checksum_mismatch")
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
            selected = [member for member in bundle.getmembers() if member.name == member_name]
            if len(selected) != 1 or not selected[0].isfile():
                raise ValueError
            source = bundle.extractfile(selected[0])
            if source is None:
                raise ValueError
            executable = source.read(64 * 1024 * 1024 + 1)
            if not executable or len(executable) > 64 * 1024 * 1024:
                raise ValueError
    except (tarfile.TarError, KeyError, ValueError):
        raise ValueError("uv_archive_layout_invalid") from None

    _require_safe_install_directory(destination.parent)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.next-", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(executable)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(0o755)
        os.chown(temporary, 0, 0)
        os.replace(temporary, destination)
        directory = os.open(
            destination.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()
    _require_trusted_uv(destination, expected_version=version)


def _require_safe_install_directory(path: Path) -> None:
    status_value = path.stat(follow_symlinks=False)
    if (
        not path.is_dir()
        or path.is_symlink()
        or status_value.st_uid != 0
        or status_value.st_mode & 0o022
    ):
        raise ValueError("uv_install_directory_untrusted")


def _require_trusted_uv(path: Path, *, expected_version: str | None = None) -> None:
    status_value = path.stat(follow_symlinks=False)
    if (
        not path.is_file()
        or path.is_symlink()
        or status_value.st_uid != 0
        or status_value.st_mode & 0o022
        or status_value.st_mode & 0o111 == 0
    ):
        raise ValueError("uv_executable_untrusted")
    if expected_version is None:
        return
    result = subprocess.run(
        (path, "--version"),
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
        env={"LC_ALL": "C", "PATH": SYSTEM_COMMAND_PATH},
    )
    if result.returncode != 0 or re.fullmatch(
        rf"uv {re.escape(expected_version)}(?: \([^\r\n]+\))?",
        result.stdout.strip(),
    ) is None:
        raise ValueError("uv_version_mismatch")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="RTSP Proxy systemd Linux host doctor")
    parser.add_argument("--install", action="store_true", help="install host packages first")
    parser.add_argument(
        "--verify-uv",
        action="store_true",
        help="also verify the pinned root-owned uv bootstrap executable",
    )
    parser.add_argument("--json", action="store_true", help="emit a stable machine-readable report")
    parser.add_argument("--uv", type=Path, default=Path("/usr/local/bin/uv"))
    parser.add_argument(
        "--bootstrap-catalog",
        type=Path,
        default=Path("deploy/bootstrap-artifacts.json"),
    )
    arguments = parser.parse_args(argv)
    try:
        facts = collect_host_facts()
        if arguments.install:
            initial = evaluate_host(facts)
            platform_blockers = tuple(
                blocker
                for blocker in initial.blockers
                if not blocker.startswith(("missing_command:", "missing_executable:"))
            )
            if platform_blockers:
                raise ValueError("host_capability_check_failed_before_package_install")
            _install_packages(package_plan(facts.commands))
            facts = collect_host_facts()
            preliminary = evaluate_host(facts)
            if preliminary.blockers:
                raise ValueError("host_capability_check_failed")
            _ensure_pinned_uv(
                arguments.uv,
                catalog_path=arguments.bootstrap_catalog,
                architecture=preliminary.architecture,
            )
        report = evaluate_host(facts)
        if arguments.verify_uv and not arguments.install and not report.blockers:
            _ensure_pinned_uv(
                arguments.uv,
                catalog_path=arguments.bootstrap_catalog,
                architecture=report.architecture,
                install_missing=False,
            )
    except (
        OSError,
        UnicodeError,
        ValueError,
        PermissionError,
        subprocess.CalledProcessError,
    ) as error:
        if arguments.json:
            print(json.dumps({"error": str(error)}, sort_keys=True, separators=(",", ":")))
        else:
            print(f"host doctor failed: {error}", file=sys.stderr)
        return 1
    if arguments.json:
        print(report.as_json())
    else:
        print(f"profile: {report.profile}")
        print(f"distribution: {facts.os_id} {facts.os_version}")
        print(f"architecture: {report.architecture}")
        print(f"package adapter: {report.package_adapter or 'manual'}")
        if report.blockers:
            for blocker in report.blockers:
                print(f"BLOCKER: {blocker}")
        else:
            print("host capability check passed")
        for limitation in report.limitations:
            print(f"LIMITATION: {limitation}")
    return 0 if report.supported else 1


if __name__ == "__main__":
    raise SystemExit(main())
