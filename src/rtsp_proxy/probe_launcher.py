from __future__ import annotations

import hashlib
import json
import os
import platform
import stat
import sys
from builtins import open as open_file
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path

from rtsp_proxy.probe_executor import validate_sealed_probe_input
from rtsp_proxy.probes import ProbeExecutionResult, ProbeOutcome
from rtsp_proxy.release import Sha256, trusted_probe_ffprobe_identity

PROBE_FFPROBE_BINARY = Path(
    "/opt/rtsp-proxy/current/libexec/rtsp-proxy-probe/ffprobe"
)
PROBE_FFPROBE_ARGV = (
    "ffprobe",
    "-v",
    "quiet",
    "-f",
    "concat",
    "-safe",
    "0",
    "-protocol_whitelist",
    "file,pipe,rtsp,rtp,tcp",
    "-read_intervals",
    "%+#64",
    "-i",
    "pipe:2",
    "-show_frames",
    "-show_entries",
    "stream=codec_name,codec_type:frame=media_type",
    "-of",
    "json",
)
_PROBE_FFPROBE_ENV = {"LANG": "C", "LC_ALL": "C"}
_MAX_PROBE_BINARY_BYTES = 64 * 1024 * 1024
_MAX_PROBE_RESULT_BYTES = 65_536
_LAUNCH_FAILURE_EXIT_CODE = 70


class ProbeLauncherError(RuntimeError):
    """The quiet probe launcher rejected its fixed local execution contract."""


class LinuxProbeFfprobeLauncher:
    """Release one sealed probe to the hash-bound controlled ffprobe inode."""

    def __init__(
        self,
        *,
        binary_path: Path = PROBE_FFPROBE_BINARY,
        trusted_owner_uid: int = 0,
        gate_reader: Callable[[int, int], bytes] = os.read,
        input_validator: Callable[[int], int] = validate_sealed_probe_input,
        identity_provider: Callable[[str], tuple[str, Sha256]] = (
            trusted_probe_ffprobe_identity
        ),
        machine: Callable[[], str] = platform.machine,
        execve: Callable[[int, tuple[str, ...], Mapping[str, str]], object] = os.execve,
    ) -> None:
        if (
            not isinstance(binary_path, Path)
            or not binary_path.is_absolute()
            or isinstance(trusted_owner_uid, bool)
            or not isinstance(trusted_owner_uid, int)
            or trusted_owner_uid < 0
        ):
            raise ProbeLauncherError("probe_launcher_policy_invalid")
        self._binary_path = binary_path
        self._trusted_owner_uid = trusted_owner_uid
        self._gate_reader = gate_reader
        self._input_validator = input_validator
        self._identity_provider = identity_provider
        self._machine = machine
        self._execve = execve

    def launch(self) -> None:
        self._consume_gate()
        try:
            self._input_validator(2)
        except Exception:
            raise ProbeLauncherError("probe_launcher_input_invalid") from None
        try:
            _version, expected_digest = self._identity_provider(self._machine())
        except Exception:
            raise ProbeLauncherError("probe_launcher_binary_invalid") from None
        if not isinstance(expected_digest, Sha256):
            raise ProbeLauncherError("probe_launcher_binary_invalid")
        self._exec_verified_binary(expected_digest.root)

    def _consume_gate(self) -> None:
        try:
            released = self._gate_reader(0, 2)
            trailing = self._gate_reader(0, 1) if released == b"R" else b""
        except Exception:
            raise ProbeLauncherError("probe_launcher_gate_invalid") from None
        if released != b"R" or trailing != b"":
            raise ProbeLauncherError("probe_launcher_gate_invalid")

    def _exec_verified_binary(self, expected_digest: str) -> None:
        no_follow = getattr(os, "O_NOFOLLOW", None)
        close_on_exec = getattr(os, "O_CLOEXEC", None)
        if not isinstance(no_follow, int) or not isinstance(close_on_exec, int):
            raise ProbeLauncherError("probe_launcher_binary_invalid")

        def opener(path: str, flags: int) -> int:
            return os.open(path, flags | no_follow | close_on_exec)

        try:
            with open_file(
                self._binary_path,
                "rb",
                buffering=0,
                opener=opener,
            ) as binary:
                descriptor = binary.fileno()
                metadata = os.fstat(descriptor)
                if not self._binary_metadata_valid(metadata):
                    raise ProbeLauncherError("probe_launcher_binary_invalid")
                if self._descriptor_sha256(descriptor, metadata.st_size) != expected_digest:
                    raise ProbeLauncherError("probe_launcher_binary_invalid")
                self._execve(
                    descriptor,
                    PROBE_FFPROBE_ARGV,
                    dict(_PROBE_FFPROBE_ENV),
                )
                raise ProbeLauncherError("probe_launcher_exec_failed")
        except ProbeLauncherError:
            raise
        except Exception:
            raise ProbeLauncherError("probe_launcher_binary_invalid") from None

    def _binary_metadata_valid(self, metadata: os.stat_result) -> bool:
        return (
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_uid == self._trusted_owner_uid
            and metadata.st_nlink == 1
            and metadata.st_mode & 0o022 == 0
            and metadata.st_mode & 0o111 != 0
            and 1 <= metadata.st_size <= _MAX_PROBE_BINARY_BYTES
        )

    @staticmethod
    def _descriptor_sha256(descriptor: int, size: int) -> str:
        digest = hashlib.sha256()
        offset = 0
        while offset < size:
            try:
                chunk = os.pread(descriptor, min(1024 * 1024, size - offset), offset)
            except OSError:
                raise ProbeLauncherError("probe_launcher_binary_invalid") from None
            if not chunk:
                raise ProbeLauncherError("probe_launcher_binary_invalid")
            digest.update(chunk)
            offset += len(chunk)
        try:
            if os.pread(descriptor, 1, size):
                raise ProbeLauncherError("probe_launcher_binary_invalid")
        except OSError:
            raise ProbeLauncherError("probe_launcher_binary_invalid") from None
        return digest.hexdigest()


class ProbeFfprobeResultDecoder:
    """Decode only the bounded codec projection emitted by controlled ffprobe."""

    def __init__(self, *, clock: Callable[[], datetime]) -> None:
        self._clock = clock

    def decode(self, payload: bytes) -> ProbeExecutionResult:
        try:
            root = _decode_unique_json(payload)
            if not isinstance(root, dict) or set(root) != {
                "frames",
                "programs",
                "stream_groups",
                "streams",
            }:
                raise ValueError
            if root["programs"] != [] or root["stream_groups"] != []:
                raise ValueError
            streams = root["streams"]
            if not isinstance(streams, list) or not 1 <= len(streams) <= 2:
                raise ValueError
            codecs: dict[str, str] = {}
            for stream in streams:
                if not isinstance(stream, dict) or set(stream) != {
                    "codec_name",
                    "codec_type",
                }:
                    raise ValueError
                codec_name = stream["codec_name"]
                codec_type = stream["codec_type"]
                if not isinstance(codec_name, str) or not isinstance(codec_type, str):
                    raise ValueError
                allowed = {
                    "video": frozenset({"h264", "hevc"}),
                    "audio": frozenset({"opus"}),
                }
                if codec_type in codecs or codec_name not in allowed.get(codec_type, ()):
                    raise ValueError
                codecs[codec_type] = codec_name
            frames = root["frames"]
            if not isinstance(frames, list) or not 1 <= len(frames) <= 128:
                raise ValueError
            decoded_types: set[str] = set()
            for frame in frames:
                if not isinstance(frame, dict) or set(frame) != {"media_type"}:
                    raise ValueError
                media_type = frame["media_type"]
                if not isinstance(media_type, str) or media_type not in codecs:
                    raise ValueError
                decoded_types.add(media_type)
            if decoded_types != set(codecs):
                raise ValueError
            completed_at = self._clock()
            if (
                not isinstance(completed_at, datetime)
                or completed_at.tzinfo is None
                or completed_at.utcoffset() is None
            ):
                raise ValueError
            return ProbeExecutionResult(
                outcome=ProbeOutcome.HEALTHY,
                completed_at=completed_at,
                video_codec=codecs.get("video"),
                audio_codec=codecs.get("audio"),
            )
        except Exception:
            raise ValueError("probe_ffprobe_result_invalid") from None


def _decode_unique_json(payload: bytes) -> object:
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= _MAX_PROBE_RESULT_BYTES:
        raise ValueError

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if not isinstance(key, str) or key in result:
                raise ValueError
            result[key] = value
        return result

    def reject_constant(_value: str) -> object:
        raise ValueError

    try:
        text = payload.decode("utf-8")
        return json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise ValueError from None


def main() -> int:
    """Run without arguments or diagnostics as the fixed DynamicUser launcher."""

    try:
        if sys.platform != "linux" or os.execve not in os.supports_fd:
            return _LAUNCH_FAILURE_EXIT_CODE
        LinuxProbeFfprobeLauncher().launch()
    except BaseException:
        return _LAUNCH_FAILURE_EXIT_CODE
    return _LAUNCH_FAILURE_EXIT_CODE
