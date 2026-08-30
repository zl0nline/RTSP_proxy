# Phase G controlled ffprobe artifact and launcher contract

- Date: 2026-08-30
- Status: artifact/release and launcher/result amd64+arm64 CI green;
  independent Spec/Standards review green; integrated native executor evidence
  pending
- Launcher/result commit: `92cec7405f5789f1cb305807f641e7fa247c096d`
- CI: [run 33325835101](https://github.com/zl0nline/RTSP_proxy/actions/runs/33325835101)
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

Release schema v4 stages the controlled binary at
`libexec/rtsp-proxy-probe/ffprobe` and the separately verified connect-guard
object at `libexec/rtsp-proxy-probe/rtsp_probe_connect_guard.bpf.o`. The
installed candidate wheel's own
verifier checks architecture, version, packaged digest, release-manifest
digest, on-disk checksum and version output. CI run 33325835101 rebuilt and
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

The invocation also caps input work at 64 packets and requests decoded-frame
`media_type`. `-show_frames` precedes `-show_entries`; this order is part of the
fixed contract because the reverse order makes ffprobe emit non-allowlisted
frame metadata. SDP stream declarations without a decoded frame are not a
healthy result.

The decoder accepts at most 64 KiB of unique-key UTF-8 JSON. Root keys are
exactly `frames`, `programs`, `stream_groups` and `streams`; the middle two must
be empty. One or two streams are accepted, with no duplicate media type: video
is H264 or HEVC and audio is Opus. Every declared media type must have at least
one decoded frame and at most 128 bounded frame rows are accepted. URL,
metadata, programs, raw errors, unknown codecs, duplicate keys, SDP-only output
and malformed output fail with one secret-free error class.

The initial focused local set passed 183 tests. An isolated checkout on `grob`
passed 61 Linux launcher/descriptor tests, including real sealed-memfd
validation and `execve(fd)` after the run gate. A follow-up exact-candidate run
passed 40 controlled-artifact/launcher tests: zero RTP and corrupt H264 were
rejected, while generated SPS/PPS/IDR produced the required decoded video
frame. These are mechanism results, not integrated production evidence.

CI run 33325835101 repeated that exact controlled-artifact contract on amd64
and arm64: each architecture passed all five redirect/ordinary-media/
zero-RTP/corrupt-media cases. Both application jobs passed 1,445 tests, the
independent 90% gate at 90.08%, the installed clean-wheel launcher EOF contract
and the privileged transient policy. Both release jobs verified the staged
architecture-specific artifact. Independent Spec and Standards review found no
remaining High/Medium issue in this slice.

## Deliberately excluded

The root-owned authenticated socket-activated broker and executor are now an
implemented integrated candidate, but they are not reachable from production
scheduling and have not yet passed the mandatory native amd64/arm64 transaction
gate. That gate must prove that the exact cgroup connect guard is attached and
read back before release, the staged controlled binary returns an allowlisted
result, deadlines/cancellation collect the unit, and repeated failure/restart
leaves no descriptor, unit, cgroup or BPF residue. ADR 0004 remains Proposed,
Phase G remains IN PROGRESS and Production remains NO-GO.
