from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote


@dataclass(frozen=True, slots=True)
class RtspEndpoint:
    host: str
    port: int
    path: str
    username: str
    password: str


@dataclass(frozen=True, slots=True)
class ProbeStream:
    codec_name: str
    width: int
    height: int


@dataclass(frozen=True, slots=True)
class ProbeObservation:
    streams: tuple[ProbeStream, ...]


class ProbeFailed(RuntimeError):
    """A probe failed with a stable, credential-free reason."""


class FfprobeRunner:
    """Run pinned ffprobe over TCP without returning raw command or stderr."""

    def __init__(
        self,
        *,
        binary: Path,
        io_timeout_seconds: int,
        total_timeout_seconds: int,
    ) -> None:
        self._binary = binary
        self._io_timeout_microseconds = io_timeout_seconds * 1_000_000
        self._total_timeout_seconds = total_timeout_seconds

    def inspect(self, endpoint: RtspEndpoint) -> ProbeObservation:
        url = _endpoint_url(endpoint)
        try:
            result = subprocess.run(
                [
                    self._binary,
                    "-v",
                    "error",
                    "-rtsp_transport",
                    "tcp",
                    "-timeout",
                    str(self._io_timeout_microseconds),
                    "-show_entries",
                    "stream=codec_name,width,height",
                    "-of",
                    "json",
                    url,
                ],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self._total_timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            raise ProbeFailed("ffprobe_deadline_exceeded") from None
        except OSError:
            raise ProbeFailed("ffprobe_start_failed") from None

        if result.returncode != 0:
            raise ProbeFailed("ffprobe_failed")

        try:
            payload = json.loads(result.stdout)
            raw_streams = payload["streams"]
            if not isinstance(raw_streams, list) or not raw_streams:
                raise ValueError
            streams = tuple(_parse_stream(stream) for stream in raw_streams)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            raise ProbeFailed("ffprobe_invalid_output") from None
        return ProbeObservation(streams=streams)


def _endpoint_url(endpoint: RtspEndpoint) -> str:
    username = quote(endpoint.username, safe="")
    password = quote(endpoint.password, safe="")
    host = f"[{endpoint.host}]" if ":" in endpoint.host else endpoint.host
    path = quote(endpoint.path.lstrip("/"), safe="/")
    return f"rtsp://{username}:{password}@{host}:{endpoint.port}/{path}"


def _parse_stream(raw: object) -> ProbeStream:
    if not isinstance(raw, dict):
        raise ValueError
    codec_name = raw.get("codec_name")
    width = raw.get("width")
    height = raw.get("height")
    if (
        not isinstance(codec_name, str)
        or not isinstance(width, int)
        or isinstance(width, bool)
        or not isinstance(height, int)
        or isinstance(height, bool)
    ):
        raise ValueError
    return ProbeStream(codec_name=codec_name, width=width, height=height)
