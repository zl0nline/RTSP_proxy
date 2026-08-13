from __future__ import annotations

import hashlib
import json
import os
import subprocess
from dataclasses import dataclass
from enum import StrEnum
from importlib.resources import files
from pathlib import Path, PurePosixPath

from pydantic import BaseModel, ConfigDict, Field, RootModel, ValidationError

APPLICATION_SCHEMA = "0011_observability"
MINIMUM_APPLICATION_SCHEMA = "0010_camera_access"
CONFIG_SCHEMA_VERSION = 1


class Sha256(RootModel[str]):
    model_config = ConfigDict(frozen=True)

    root: str = Field(pattern=r"^[0-9a-f]{64}$")


class LinuxArch(StrEnum):
    AMD64 = "amd64"
    ARM64 = "arm64"


class PythonArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str = Field(min_length=1)
    lock: str = Field(min_length=1)
    lock_sha256: Sha256
    wheel: str = Field(min_length=1)
    wheel_sha256: Sha256


class MediaMtxArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    release_id: str = Field(pattern=r"^[0-9A-Za-z][0-9A-Za-z._-]{0,127}$")
    version: str = Field(min_length=1)
    linux_arch: LinuxArch
    binary: str = Field(min_length=1)
    binary_sha256: Sha256


class FfmpegArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str = Field(min_length=1)
    binary: str = Field(min_length=1)
    binary_sha256: Sha256
    ffprobe_binary: str = Field(min_length=1)
    ffprobe_sha256: Sha256


class SchemaCompatibility(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    minimum: str = Field(min_length=1)
    maximum: str = Field(min_length=1)


class ReleaseManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(ge=2, le=2)
    release_id: str = Field(pattern=r"^[0-9A-Za-z][0-9A-Za-z._-]{0,127}$")
    git_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    python: PythonArtifact
    mediamtx: MediaMtxArtifact
    ffmpeg: FfmpegArtifact
    schema_compatibility: SchemaCompatibility
    config_schema_version: int = Field(ge=1)


@dataclass(frozen=True, slots=True)
class VerifiedRelease:
    release_id: str
    git_commit: str
    wheel: Path
    mediamtx_binary: Path
    ffmpeg_binary: Path
    ffprobe_binary: Path


class ReleaseVerificationError(ValueError):
    """A release cannot be trusted or is incompatible with this runtime."""


def _trusted_mediamtx_identity(
    architecture: LinuxArch,
    release_id: str,
) -> tuple[str, Sha256]:
    try:
        resource = files("rtsp_proxy").joinpath("artifacts", "mediamtx.json")
        payload = json.loads(resource.read_text(encoding="utf-8"))
        if payload.get("schema_version") != 2:
            raise ValueError
        release = payload["releases"][release_id]
        version = release["version"]
        digest = release["architectures"][architecture.value]["binary_sha256"]
        if not isinstance(version, str):
            raise ValueError
        return version, Sha256.model_validate(digest)
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        KeyError,
        TypeError,
        ValueError,
        AttributeError,
        ValidationError,
    ):
        raise ReleaseVerificationError("trusted_artifact_catalog_invalid") from None


def trusted_mediamtx_activation_identity(
    machine: str,
    release_id: str = "0.2.0",
) -> tuple[str, Sha256]:
    """Return an identity only when the packaged catalog permits activation."""

    architecture = normalize_linux_arch(machine)
    try:
        resource = files("rtsp_proxy").joinpath("artifacts", "mediamtx.json")
        payload = json.loads(resource.read_text(encoding="utf-8"))
        release = payload["releases"][release_id]
        if release.get("activation_compatible") is not True:
            raise ReleaseVerificationError("mediamtx_release_activation_incompatible")
    except ReleaseVerificationError:
        raise
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        KeyError,
        TypeError,
        ValueError,
        AttributeError,
    ):
        raise ReleaseVerificationError("trusted_artifact_catalog_invalid") from None
    return _trusted_mediamtx_identity(architecture, release_id)


def trusted_mediamtx_identity(
    machine: str,
    release_id: str = "0.2.0",
) -> tuple[str, Sha256]:
    """Return one release's packaged MediaMTX identity for a Linux architecture."""

    return _trusted_mediamtx_identity(normalize_linux_arch(machine), release_id)


def normalize_linux_arch(machine: str) -> LinuxArch:
    canonical = machine.strip().lower()
    aliases = {
        "x86_64": LinuxArch.AMD64,
        "amd64": LinuxArch.AMD64,
        "aarch64": LinuxArch.ARM64,
        "arm64": LinuxArch.ARM64,
    }
    try:
        return aliases[canonical]
    except KeyError as error:
        value = canonical or "unknown"
        raise ReleaseVerificationError(f"unsupported_linux_arch:{value}") from error


def verify_release(
    manifest_path: Path,
    *,
    expected_python: str,
    expected_arch: str,
) -> VerifiedRelease:
    root = manifest_path.parent.resolve()
    manifest = _read_manifest(manifest_path)

    if manifest.python.version != expected_python:
        raise ReleaseVerificationError("python_version_mismatch")
    if manifest.mediamtx.linux_arch != expected_arch:
        raise ReleaseVerificationError("linux_arch_mismatch")
    trusted_version, trusted_digest = _trusted_mediamtx_identity(
        manifest.mediamtx.linux_arch,
        manifest.mediamtx.release_id,
    )
    try:
        trusted_mediamtx_activation_identity(
            manifest.mediamtx.linux_arch.value,
            manifest.mediamtx.release_id,
        )
    except ReleaseVerificationError as error:
        raise ReleaseVerificationError("untrusted_mediamtx_artifact") from error
    if (
        manifest.mediamtx.version != trusted_version
        or manifest.mediamtx.binary_sha256 != trusted_digest
    ):
        raise ReleaseVerificationError("untrusted_mediamtx_artifact")
    if manifest.config_schema_version != CONFIG_SCHEMA_VERSION:
        raise ReleaseVerificationError("config_schema_mismatch")
    if (
        manifest.schema_compatibility.minimum != MINIMUM_APPLICATION_SCHEMA
        or manifest.schema_compatibility.maximum != APPLICATION_SCHEMA
    ):
        raise ReleaseVerificationError("database_schema_mismatch")

    lock = _artifact_path(root, manifest.python.lock, "python.lock")
    wheel = _artifact_path(root, manifest.python.wheel, "python.wheel")
    mediamtx = _artifact_path(root, manifest.mediamtx.binary, "mediamtx.binary")
    ffmpeg = _artifact_path(root, manifest.ffmpeg.binary, "ffmpeg.binary")
    ffprobe = _artifact_path(root, manifest.ffmpeg.ffprobe_binary, "ffmpeg.ffprobe")

    _verify_checksum(lock, manifest.python.lock_sha256, "python.lock")
    _verify_checksum(wheel, manifest.python.wheel_sha256, "python.wheel")
    _verify_checksum(mediamtx, manifest.mediamtx.binary_sha256, "mediamtx.binary")
    _verify_checksum(ffmpeg, manifest.ffmpeg.binary_sha256, "ffmpeg.binary")
    _verify_checksum(ffprobe, manifest.ffmpeg.ffprobe_sha256, "ffmpeg.ffprobe")

    _verify_version(mediamtx, ("--version",), manifest.mediamtx.version, "mediamtx.binary")
    _verify_version(ffmpeg, ("-version",), manifest.ffmpeg.version, "ffmpeg.binary")
    _verify_version(ffprobe, ("-version",), manifest.ffmpeg.version, "ffmpeg.ffprobe")

    return VerifiedRelease(
        release_id=manifest.release_id,
        git_commit=manifest.git_commit,
        wheel=wheel,
        mediamtx_binary=mediamtx,
        ffmpeg_binary=ffmpeg,
        ffprobe_binary=ffprobe,
    )


def _read_manifest(path: Path) -> ReleaseManifest:
    try:
        content = path.read_text(encoding="utf-8")
        return ReleaseManifest.model_validate(json.loads(content))
    except (OSError, UnicodeError, json.JSONDecodeError, ValidationError) as error:
        raise ReleaseVerificationError("invalid_manifest") from error


def _artifact_path(root: Path, relative: str, label: str) -> Path:
    path = PurePosixPath(relative)
    if path.is_absolute() or ".." in path.parts or "\\" in relative:
        raise ReleaseVerificationError(f"unsafe_path:{label}")

    try:
        candidate = (root / Path(*path.parts)).resolve(strict=True)
    except OSError as error:
        raise ReleaseVerificationError(f"artifact_missing:{label}") from error

    if not candidate.is_relative_to(root):
        raise ReleaseVerificationError(f"unsafe_path:{label}")
    if not candidate.is_file():
        raise ReleaseVerificationError(f"artifact_missing:{label}")
    return candidate


def _verify_checksum(path: Path, expected: Sha256, label: str) -> None:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as artifact:
            for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise ReleaseVerificationError(f"artifact_unreadable:{label}") from error

    if digest.hexdigest() != expected.root:
        raise ReleaseVerificationError(f"checksum_mismatch:{label}")


def _verify_version(path: Path, arguments: tuple[str, ...], expected: str, label: str) -> None:
    try:
        result = subprocess.run(
            [path, *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            env={"LC_ALL": "C", "PATH": os.defpath},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ReleaseVerificationError(f"version_probe_failed:{label}") from error

    first_line = result.stdout.splitlines()[0].strip() if result.stdout else ""
    if label == "mediamtx.binary":
        version_matches = first_line == expected
    else:
        tokens = first_line.split()
        version_matches = len(tokens) >= 3 and tokens[:3] == [path.name, "version", expected]
    if result.returncode != 0 or not version_matches:
        raise ReleaseVerificationError(f"version_mismatch:{label}")
