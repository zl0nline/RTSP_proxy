from __future__ import annotations

import hashlib
import os
import shutil
import sys
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from rtsp_proxy.probe_executor import create_sealed_probe_input, serialize_probe_input
from rtsp_proxy.probe_launcher import (
    PROBE_FFPROBE_ARGV,
    LinuxProbeFfprobeLauncher,
    ProbeFfprobeResultDecoder,
    ProbeLauncherError,
    main,
)
from rtsp_proxy.probes import ProbeExecutionResult, ProbeOutcome
from rtsp_proxy.release import Sha256

NOW = datetime(2026, 8, 30, 18, 0, tzinfo=UTC)


class _GateReader:
    def __init__(self, *chunks: bytes) -> None:
        self._chunks = iter(chunks)
        self.calls: list[tuple[int, int]] = []

    def __call__(self, descriptor: int, maximum: int) -> bytes:
        self.calls.append((descriptor, maximum))
        return next(self._chunks)


def _launcher(
    binary: Path,
    *,
    gate_reader: Callable[[int, int], bytes] | None = None,
    expected_digest: str | None = None,
    input_validator: Callable[[int], int] | None = None,
    execve: Callable[[int, tuple[str, ...], Mapping[str, str]], object] | None = None,
    identity_provider: Callable[[str], tuple[str, Sha256]] | None = None,
) -> LinuxProbeFfprobeLauncher:
    payload = binary.read_bytes()
    digest = expected_digest or hashlib.sha256(payload).hexdigest()
    return LinuxProbeFfprobeLauncher(
        binary_path=binary,
        trusted_owner_uid=os.getuid(),
        gate_reader=gate_reader or _GateReader(b"R", b""),
        input_validator=input_validator or (lambda descriptor: descriptor),
        identity_provider=identity_provider
        or (lambda _machine: ("probe-test", Sha256(root=digest))),
        machine=lambda: "x86_64",
        execve=execve or (lambda _fd, _argv, _env: None),
    )


def _binary(tmp_path: Path) -> Path:
    binary = tmp_path / "ffprobe"
    binary.write_bytes(b"\x7fELF-controlled-probe")
    binary.chmod(0o555)
    return binary


def test_launcher_releases_only_the_fixed_fd_bound_command(tmp_path: Path) -> None:
    binary = _binary(tmp_path)
    gate = _GateReader(b"R", b"")
    events: list[object] = []

    def validate_input(descriptor: int) -> int:
        events.append(("input", descriptor))
        return 512

    def execve(
        descriptor: int,
        argv: tuple[str, ...],
        environment: Mapping[str, str],
    ) -> object:
        events.append(
            (
                "exec",
                os.pread(descriptor, binary.stat().st_size, 0),
                argv,
                environment,
            )
        )
        raise SystemExit(0)

    launcher = _launcher(
        binary,
        gate_reader=gate,
        input_validator=validate_input,
        execve=execve,
    )

    with pytest.raises(SystemExit) as raised:
        launcher.launch()

    assert raised.value.code == 0
    assert gate.calls == [(0, 2), (0, 1)]
    assert events == [
        ("input", 2),
        (
            "exec",
            binary.read_bytes(),
            PROBE_FFPROBE_ARGV,
            {"LANG": "C", "LC_ALL": "C"},
        ),
    ]


@pytest.mark.parametrize(
    ("binary_path", "trusted_owner_uid"),
    [(Path("relative/ffprobe"), 0), (Path("/absolute/ffprobe"), True)],
)
def test_launcher_rejects_an_invalid_local_policy(
    binary_path: Path,
    trusted_owner_uid: int,
) -> None:
    with pytest.raises(ProbeLauncherError, match=r"^probe_launcher_policy_invalid$"):
        LinuxProbeFfprobeLauncher(
            binary_path=binary_path,
            trusted_owner_uid=trusted_owner_uid,
        )


@pytest.mark.parametrize(
    "chunks",
    [
        (b"", b""),
        (b"X", b""),
        (b"RR", b""),
        (b"R", b"X"),
    ],
)
def test_launcher_rejects_any_noncanonical_gate_before_reading_input(
    tmp_path: Path,
    chunks: tuple[bytes, bytes],
) -> None:
    binary = _binary(tmp_path)
    input_reads: list[int] = []

    def validate_input(descriptor: int) -> int:
        input_reads.append(descriptor)
        return 1

    launcher = _launcher(
        binary,
        gate_reader=_GateReader(*chunks),
        input_validator=validate_input,
    )

    with pytest.raises(ProbeLauncherError, match=r"^probe_launcher_gate_invalid$"):
        launcher.launch()

    assert input_reads == []


def test_launcher_sanitizes_a_gate_read_failure(tmp_path: Path) -> None:
    binary = _binary(tmp_path)

    def failing_gate(_descriptor: int, _maximum: int) -> bytes:
        raise OSError("injected gate failure")

    with pytest.raises(ProbeLauncherError, match=r"^probe_launcher_gate_invalid$"):
        _launcher(binary, gate_reader=failing_gate).launch()


def test_launcher_rejects_an_untrusted_binary_without_executing_it(
    tmp_path: Path,
) -> None:
    binary = _binary(tmp_path)
    executed: list[int] = []
    launcher = _launcher(
        binary,
        expected_digest="0" * 64,
        execve=lambda descriptor, _argv, _env: executed.append(descriptor),
    )

    with pytest.raises(ProbeLauncherError, match=r"^probe_launcher_binary_invalid$"):
        launcher.launch()

    assert executed == []


@pytest.mark.parametrize("invalid_identity", [RuntimeError("secret"), object()])
def test_launcher_rejects_an_invalid_packaged_identity_without_disclosure(
    tmp_path: Path,
    invalid_identity: object,
) -> None:
    binary = _binary(tmp_path)

    def identity_provider(_machine: str) -> tuple[str, Sha256]:
        if isinstance(invalid_identity, BaseException):
            raise invalid_identity
        return "probe-test", invalid_identity  # type: ignore[return-value]

    launcher = _launcher(binary, identity_provider=identity_provider)

    with pytest.raises(ProbeLauncherError) as raised:
        launcher.launch()

    assert str(raised.value) == "probe_launcher_binary_invalid"
    assert "secret" not in repr(raised.value)


def test_launcher_rejects_missing_no_follow_support(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = _binary(tmp_path)
    monkeypatch.delattr("rtsp_proxy.probe_launcher.os.O_NOFOLLOW")

    with pytest.raises(ProbeLauncherError, match=r"^probe_launcher_binary_invalid$"):
        _launcher(binary).launch()


@pytest.mark.parametrize("failure", ["error", "short", "growth"])
def test_launcher_rejects_ambiguous_binary_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    binary = _binary(tmp_path)
    real_pread = os.pread
    size = binary.stat().st_size

    def failing_pread(descriptor: int, count: int, offset: int) -> bytes:
        if failure == "error":
            raise OSError("injected read failure")
        if failure == "short":
            return b""
        if offset == size:
            return b"x"
        return real_pread(descriptor, count, offset)

    monkeypatch.setattr("rtsp_proxy.probe_launcher.os.pread", failing_pread)

    with pytest.raises(ProbeLauncherError, match=r"^probe_launcher_binary_invalid$"):
        _launcher(binary).launch()


def test_launcher_closes_the_binary_if_exec_unexpectedly_returns(
    tmp_path: Path,
) -> None:
    binary = _binary(tmp_path)
    executed: list[int] = []
    launcher = _launcher(
        binary,
        execve=lambda descriptor, _argv, _env: executed.append(descriptor),
    )

    with pytest.raises(ProbeLauncherError, match=r"^probe_launcher_exec_failed$"):
        launcher.launch()

    assert len(executed) == 1
    with pytest.raises(OSError):
        os.fstat(executed[0])


def test_launcher_rejects_a_writable_or_symlinked_binary(tmp_path: Path) -> None:
    binary = _binary(tmp_path)
    binary.chmod(0o775)

    with pytest.raises(ProbeLauncherError, match=r"^probe_launcher_binary_invalid$"):
        _launcher(binary).launch()

    binary.chmod(0o555)
    link = tmp_path / "ffprobe-link"
    link.symlink_to(binary)
    with pytest.raises(ProbeLauncherError, match=r"^probe_launcher_binary_invalid$"):
        _launcher(link).launch()


def test_launcher_sanitizes_input_validation_failures(tmp_path: Path) -> None:
    binary = _binary(tmp_path)

    def reject_input(_descriptor: int) -> int:
        raise ValueError("rtsp://camera:secret@192.0.2.10/live")

    launcher = _launcher(binary, input_validator=reject_input)

    with pytest.raises(ProbeLauncherError) as raised:
        launcher.launch()

    assert str(raised.value) == "probe_launcher_input_invalid"
    assert "secret" not in repr(raised.value)


def test_launcher_main_fails_quietly_off_linux(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr("rtsp_proxy.probe_launcher.sys.platform", "unsupported")

    assert main() == 70
    assert capsys.readouterr() == ("", "")


def test_launcher_main_fails_quietly_on_linux_gate_eof(
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    original_stdin = os.dup(0)
    gate_read, gate_write = os.pipe()
    os.close(gate_write)
    try:
        os.dup2(gate_read, 0)
        os.close(gate_read)
        monkeypatch.setattr("rtsp_proxy.probe_launcher.sys.platform", "linux")
        monkeypatch.setattr(
            "rtsp_proxy.probe_launcher.os.supports_fd",
            {os.execve},
        )

        assert main() == 70
    finally:
        os.dup2(original_stdin, 0)
        os.close(original_stdin)

    assert capfd.readouterr() == ("", "")


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux fd exec and memfd")
def test_linux_launcher_executes_the_verified_inode_after_the_gate(
    tmp_path: Path,
) -> None:
    binary = tmp_path / "ffprobe"
    shutil.copyfile("/bin/true", binary)
    binary.chmod(0o555)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    sealed_input = create_sealed_probe_input(
        serialize_probe_input(
            address=IPv4Address("192.0.2.10"),
            port=8554,
            path_and_query="/live",
            username="camera",
            password="secret-canary",
            io_timeout_microseconds=1_000_000,
        )
    )
    gate_read, gate_write = os.pipe()
    process_id = os.fork()
    if process_id == 0:
        try:
            os.close(gate_write)
            os.dup2(gate_read, 0, inheritable=True)
            os.dup2(sealed_input, 2, inheritable=True)
            os.close(gate_read)
            os.close(sealed_input)
            LinuxProbeFfprobeLauncher(
                binary_path=binary,
                trusted_owner_uid=os.getuid(),
                identity_provider=lambda _machine: (
                    "probe-test",
                    Sha256(root=digest),
                ),
            ).launch()
        except BaseException:
            os._exit(111)
        os._exit(112)

    os.close(gate_read)
    os.close(sealed_input)
    try:
        assert os.write(gate_write, b"R") == 1
    finally:
        os.close(gate_write)
    waited, status = os.waitpid(process_id, 0)

    assert waited == process_id
    assert os.waitstatus_to_exitcode(status) == 0


def test_result_decoder_accepts_only_allowlisted_streams() -> None:
    decoder = ProbeFfprobeResultDecoder(clock=lambda: NOW)

    assert decoder.decode(
        b'{"frames":[{"media_type":"video"},{"media_type":"audio"}],'
        b'"programs":[],"stream_groups":[],"streams":['
        b'{"codec_name":"hevc","codec_type":"video"},'
        b'{"codec_name":"opus","codec_type":"audio"}]}'
    ) == ProbeExecutionResult(
        outcome=ProbeOutcome.HEALTHY,
        completed_at=NOW,
        video_codec="hevc",
        audio_codec="opus",
    )


@pytest.mark.parametrize(
    "payload",
    [
        b"{}",
        b'{"frames":[],"programs":[],"stream_groups":[],"streams":[]}',
        b'{"frames":[],"programs":[{}],"stream_groups":[],"streams":['
        b'{"codec_name":"h264","codec_type":"video"}]}',
        b'{"frames":[],"programs":[],"stream_groups":[{}],"streams":['
        b'{"codec_name":"h264","codec_type":"video"}]}',
        b'{"frames":[],"programs":[],"stream_groups":[],"streams":['
        b'{"codec_name":"aac","codec_type":"audio"}]}',
        b'{"frames":[],"programs":[],"stream_groups":[],"streams":['
        b'{"codec_name":"h264","codec_type":"video"},'
        b'{"codec_name":"hevc","codec_type":"video"}]}',
        b'{"frames":[],"programs":[],"stream_groups":[],"streams":['
        b'{"codec_name":"h264","codec_type":"video","url":"secret"}]}',
        b'{"frames":[],"programs":[],"programs":[],"stream_groups":[],'
        b'"streams":['
        b'{"codec_name":"h264","codec_type":"video"}]}',
        b'{"frames":[],"programs":[],"stream_groups":[],"streams":['
        b'{"codec_name":"h264","codec_name":"hevc","codec_type":"video"}]}',
        b'{"frames":[],"programs":[],"stream_groups":[],"streams":['
        b'{"codec_name":"h264","codec_type":"video"}]}',
        b'{"frames":[{"media_type":"audio"}],"programs":[],'
        b'"stream_groups":[],"streams":['
        b'{"codec_name":"h264","codec_type":"video"}]}',
        b'{"frames":[{"media_type":"video","url":"secret"}],'
        b'"programs":[],"stream_groups":[],"streams":['
        b'{"codec_name":"h264","codec_type":"video"}]}',
        b'{"frames":[{"media_type":"video"}],"programs":[],'
        b'"stream_groups":[],"streams":['
        b'{"codec_name":"h264","codec_type":1}]}',
        b'{"frames":[{"media_type":"video"}],"programs":[],'
        b'"stream_groups":[],"streams":['
        b'{"codec_name":"h264","codec_type":"video"},'
        b'{"codec_name":"opus","codec_type":"audio"}]}',
        b'{"frames":NaN,"programs":[],"stream_groups":[],"streams":['
        b'{"codec_name":"h264","codec_type":"video"}]}',
        b"not-json-secret-canary",
    ],
)
def test_result_decoder_rejects_non_allowlisted_or_ambiguous_output(
    payload: bytes,
) -> None:
    decoder = ProbeFfprobeResultDecoder(clock=lambda: NOW)

    with pytest.raises(ValueError) as raised:
        decoder.decode(payload)

    assert str(raised.value) == "probe_ffprobe_result_invalid"
    assert "secret" not in repr(raised.value)


def test_result_decoder_rejects_an_invalid_completion_clock() -> None:
    decoder = ProbeFfprobeResultDecoder(clock=lambda: datetime(2026, 8, 30))

    with pytest.raises(ValueError, match=r"^probe_ffprobe_result_invalid$"):
        decoder.decode(
            b'{"frames":[{"media_type":"video"}],"programs":[],'
            b'"stream_groups":[],"streams":['
            b'{"codec_name":"h264","codec_type":"video"}]}'
        )
