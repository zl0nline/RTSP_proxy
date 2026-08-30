# Phase G controlled ffprobe artifact and launcher contract

- Date: 2026-08-30
- Status: artifact/release amd64+arm64 CI green; launcher implementation and
  direct-Linux amd64 mechanism green; independent review and integrated native
  executor evidence pending
- Launcher commit: `b85c4587bcde2e68a35a9827abb6db3d5dfb95f5`
- Artifact CI: [run 33323810984](https://github.com/zl0nline/RTSP_proxy/actions/runs/33323810984)
  — all nine jobs passed
- Deployment: direct Linux/system manager, no Docker
- Production decision: NO-GO

## Retained artifact boundary

The source-probe binary is not the general `bin/ffprobe`. It is built from the
exact FFmpeg source commit `9b6c8969e05b4f0b29f0f85cd501be6b3e582e6b`
with the SHA-bound opt-in `rtsp_flags=no_redirect` patch and a pinned Ubuntu
snapshot/toolchain. The build normalizes source paths, rebuilds twice and
requires byte-identical output. Architecture-specific SHA-256 digests are
bound in both `deploy/artifact-catalog.json` and the packaged trust catalog.

Release schema v3 stages the artifact only at
`libexec/rtsp-proxy-probe/ffprobe`. The installed candidate wheel's own
verifier checks architecture, version, packaged digest, release-manifest
digest, on-disk checksum and version output. CI run 33323810984 rebuilt and
exercised the controlled binary on amd64 and arm64, then installed the wheel in
an isolated release venv and verified the same staged architecture artifact.
The behavioral contract proves ordinary H264 OPTIONS/DESCRIBE/SETUP/PLAY over
interleaved RTSP/TCP and opt-in redirect refusal without emitting the redirect
secret canary; the unpatched/default behavior remains unchanged.

## Fixed launcher and result boundary

`rtsp-proxy-probe-launcher` accepts no command, URL or environment policy from
the caller. It waits for the exact one-byte run gate and EOF before reading fd
2, validates the canonical immutable sealed input, and opens only the fixed
release path with `O_NOFOLLOW` and `O_CLOEXEC`. The production policy requires
a regular, single-link, root-owned executable that is not group/other writable
and is at most 64 MiB. SHA-256 is calculated through that descriptor and the
same inode is executed with fd-based `execve`; only `LANG=C` and `LC_ALL=C`
survive. Argv is fixed to quiet concat input on `pipe:2`, TCP-only nested
protocols and the `codec_name`/`codec_type` JSON projection.

The decoder accepts at most 64 KiB of unique-key UTF-8 JSON. Root keys are
exactly `programs`, `stream_groups` and `streams`; the first two must be empty.
One or two streams are accepted, with no duplicate media type: video is H264 or
HEVC and audio is Opus. URL, metadata, programs, raw errors, unknown codecs,
duplicate keys and malformed output fail with one secret-free error class.

The focused local set passed 183 tests. A temporary isolated checkout on
`grob` passed 61 Linux tests, including real sealed-memfd validation and
`execve(fd)` after the run gate; the temporary directory was removed. These are
mechanism results, not integrated production evidence.

## Deliberately excluded

The root-owned authenticated broker service is still absent and the launcher
is not reachable from production scheduling. The complete transaction still
needs to prove, on native amd64 and arm64, that the exact cgroup connect guard
is attached and read back before gate release, the real staged controlled
binary returns an allowlisted result, deadlines/cancellation collect the unit,
and repeated failure/restart leaves no descriptor, unit, cgroup or BPF residue.
Independent Spec and Standards review of the launcher slice is also pending.
ADR 0004 remains Proposed, Phase G remains IN PROGRESS and Production remains
NO-GO.
