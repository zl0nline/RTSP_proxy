# Phase G integrated probe-broker contract

- Date: 2026-09-01
- Status: installed production-client success/failure matrix, exact IPv6 target
  and redirect refusal native amd64/arm64 CI green; explicit caller/shutdown
  cancellation and remaining policy matrix pending
- Commit: `e5d12e071c64ce70633f067e8b84c864d101058d`
- CI: [run 33439334327](https://github.com/zl0nline/RTSP_proxy/actions/runs/33439334327)
  — all nine jobs passed
- Deployment: direct Linux/system manager, no Docker
- Production decision: NO-GO

## Installed boundary proved

Both architecture-specific `media-binaries-contract` jobs installed the clean
wheel and schema-v4 release under `/opt/rtsp-proxy/releases/probe-contract`,
activated the documented `current` symlink, and started the shipped
socket-activated root broker with its bounded systemd policy. The installed
fixture invoked the wheel's production `UnixProbeBrokerClient` as the fixed
`rtsp-proxy` identity. The broker verified that peer's UID/GID and the client
verified the root broker with `SO_PEERCRED`; a root peer and an admitted-identity
request outside the configured CIDR were rejected without creating a transient
unit, BPF scope or ownership receipt.

For the accepted request, the broker received exactly one sealed credential fd,
created the transient unit in the real nested
`rtsp.slice/rtsp-probe.slice/<unit>` cgroup, and populated a separately created
BTF-free one-entry target map. The two project connect programs were loaded
against that exact map and attached alongside systemd's device, ingress and
egress programs. Direct `BPF_PROG_QUERY` readback proved the exact project
program IDs without adding broad `CAP_SYS_ADMIN`; the run gate remained closed
until map ABI, program/map identity and both attachments matched.

After release, the controlled no-redirect ffprobe completed ordinary
OPTIONS/DESCRIBE/SETUP/PLAY over interleaved RTSP/TCP and decoded the generated
H264 SPS/PPS/IDR. Audio-only Opus and mixed H264+Opus interleaved fixtures also
returned exact decoded-frame `HEALTHY` results. The test then proved the
transient unit, nested cgroup, BPF scope and ownership
receipt were collected, the root broker stayed active, and the credential
canary was absent from its journal. While the child was live, root inspection
proved it absent from `cmdline` and `environ`; both the control-plane UID and an
unrelated service UID were unable to open sealed fd 2 through `/proc`. Effective
broker CPU, memory, swap, task, fd and core-dump limits were also read back.

An exact IPv6 `::1` contract independently completed the same decoded H264
transaction with a bracketed RTSP authority and exact `connect6` tuple, then
proved zero unit, pin and receipt residue. Loopback is used only by the isolated
native fixture; ordinary camera admission continues to reject special ranges.
A redirect response containing a unique secret canary was rejected by the
controlled ffprobe before any connection to the redirected listener. The
canary was absent from client output, stderr and the broker journal, and cleanup
again left no unit, BPF scope or receipt.

The installed failure matrix additionally proved:

- a stalled RTSP source exhausts the absolute request deadline, cancels the
  transient unit and leaves the broker available with zero residue;
- forced `SIGKILL` of the broker during an active probe is recovered on the new
  process's startup, including the previous unit, guard pins and receipt;
- three consecutive SDP/PLAY-without-media executions return only normalized
  `INCONCLUSIVE` results and leave no residue;
- a root-only isolated fault release that writes 128 KiB to stdout triggers the
  64 KiB cap, cancellation and cleanup without modifying the admitted release;
- a separate fault release that writes literal malformed JSON is rejected by
  the strict result decoder and collected identically.

Each architecture's installed broker contract passed all eleven cases. Both
application jobs passed 1,545 tests with 47 expected skips and the
independent coverage gate at 90.03%. The adjacent release, controlled-ffprobe,
direct systemd, exact connect-guard, load/pull and browser jobs also passed.

## Deliberately excluded

This evidence does not yet define or prove explicit caller/shutdown cancellation
independently of the absolute request deadline. The remaining integrated
special-range and alternate-protocol policy cases also stay open. The periodic
risk-based producer, encrypted source-secret reference, authoritative camera
probe profile and durable health-state orchestration are not wired to this
broker. ADR 0004 therefore remains Proposed, Phase G remains IN PROGRESS and
Production remains NO-GO.
