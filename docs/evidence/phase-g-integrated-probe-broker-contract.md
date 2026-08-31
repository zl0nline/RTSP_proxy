# Phase G integrated probe-broker success contract

- Date: 2026-08-31
- Status: installed success/denial transaction native amd64/arm64 CI green;
  integrated failure matrix pending
- Commit: `905eb0236e7df6a0ea0e3b3b7f28726f90df3b57`
- CI: [run 33426435190](https://github.com/zl0nline/RTSP_proxy/actions/runs/33426435190)
  — all nine jobs passed
- Deployment: direct Linux/system manager, no Docker
- Production decision: NO-GO

## Installed boundary proved

Both architecture-specific `media-binaries-contract` jobs installed the clean
wheel and schema-v4 release under `/opt/rtsp-proxy/releases/probe-contract`,
activated the documented `current` symlink, and started the shipped
socket-activated root broker with its bounded systemd policy. The test client
ran as the fixed `rtsp-proxy` identity; a root peer and an admitted-identity
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
H264 SPS/PPS/IDR. The broker returned only the normalized `HEALTHY` result. The
test then proved the transient unit, nested cgroup, BPF scope and ownership
receipt were collected, the root broker stayed active, and the credential
canary was absent from its journal. Effective broker CPU, memory, swap, task,
fd and core-dump limits were also read back.

Both application jobs passed 1,529 tests with 38 expected skips and the
independent coverage gate at 90.02%. The adjacent release, controlled-ffprobe,
direct systemd, exact connect-guard, load/pull and browser jobs also passed.

## Deliberately excluded

This evidence proves the installed happy path, peer/target denial and
successful-path zero residue. It does not yet prove the integrated timeout,
cancellation, output-flood, malformed-result, broker-restart or repeated-failure
matrix required by ADR 0004. The periodic risk-based producer and durable
health-state orchestration are also not wired to this broker. ADR 0004 remains
Proposed, Phase G remains IN PROGRESS and Production remains NO-GO.
