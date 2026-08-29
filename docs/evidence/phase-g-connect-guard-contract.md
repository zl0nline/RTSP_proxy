# Phase G exact connect-guard contract

- Date: 2026-08-30
- Status: parameterized implementation, direct-Linux amd64 contract and
  independent Spec/Standards review green; native amd64/arm64 CI pending
- Production decision: NO-GO

## Scope

This slice turns the validated throwaway mechanism into a production-oriented,
but not yet enabled, cgroup BPF primitive:

- `ProbeConnectGuardTarget` serializes one literal address family, IP and port
  into an explicit 32-byte, version-1, little-endian map ABI;
- `rtsp_probe_connect_guard.bpf.c` has separate `connect4` and `connect6`
  hooks. Missing map state, ABI drift, a malformed reserved field, the wrong
  family, any other address and any other port all return deny;
- the build script produces one eBPF ELF on Linux amd64 or arm64 without
  runtime clang use; and
- the privileged contract creates a fresh cgroup, loads and pins the map and
programs, attaches both hooks before releasing a blocked child, checks IPv4
and IPv6 separately, then detaches and proves the pin and cgroup are gone. Its
explicit ownership ledger also runs every cleanup action after partial command
failure or process interruption without removing a colliding foreign path.

The direct-Linux run on `grob` used Linux 7.0, systemd 259, cgroup v2, bpftool
7.7/libbpf 1.7 and clang 21. It passed both target families and left no scoped
kernel or filesystem residue. The predecessor mechanism prototype is retained
on branch `prototype/phase-g-connect-guard` at commit `f984814` as required by
the prototype workflow.

## Deliberately excluded

There is still no production probe executor. This slice does not grant the
control plane BPF or system-bus authority and does not handle a camera secret.
The narrow authenticated root broker, `StartTransientUnit` property allowlist,
attach/readback/canary transaction, credential transport, controlled
no-redirect ffprobe, bounded result parser, cancellation and repeated failure
cleanup remain mandatory. ADR 0004 therefore remains Proposed and Phase G
remains IN PROGRESS / Production NO-GO.
