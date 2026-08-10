from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from pydantic import BaseModel, ConfigDict, Field, ValidationError

Sha256 = str


class PythonArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str = Field(min_length=1)
    lock: str = Field(min_length=1)
    lock_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    wheel: str = Field(min_length=1)
    wheel_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")


class MediaMtxArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str = Field(min_length=1)
    linux_arch: str = Field(min_length=1)
    binary: str = Field(min_length=1)
    binary_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")


class FfmpegArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str = Field(min_length=1)


class SchemaCompatibility(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    minimum: str = Field(min_length=1)
    maximum: str = Field(min_length=1)


class ReleaseManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(ge=1, le=1)
    release_id: str = Field(min_length=1)
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


class ReleaseVerificationError(ValueError):
    """A release cannot be trusted or is incompatible with this runtime."""


def normalize_linux_arch(machine: str) -> str:
    canonical = machine.strip().lower()
    aliases = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
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

    lock = _artifact_path(root, manifest.python.lock, "python.lock")
    wheel = _artifact_path(root, manifest.python.wheel, "python.wheel")
    mediamtx = _artifact_path(root, manifest.mediamtx.binary, "mediamtx.binary")

    _verify_checksum(lock, manifest.python.lock_sha256, "python.lock")
    _verify_checksum(wheel, manifest.python.wheel_sha256, "python.wheel")
    _verify_checksum(mediamtx, manifest.mediamtx.binary_sha256, "mediamtx.binary")

    return VerifiedRelease(
        release_id=manifest.release_id,
        git_commit=manifest.git_commit,
        wheel=wheel,
        mediamtx_binary=mediamtx,
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

    if digest.hexdigest() != expected:
        raise ReleaseVerificationError(f"checksum_mismatch:{label}")
