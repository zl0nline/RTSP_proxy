# Phase G exact connect-guard contract

- Date: 2026-08-30
- Status: parameterized implementation, direct-Linux amd64 contract,
  independent Spec/Standards review and privileged native amd64/arm64 CI green
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
the prototype workflow. The packaged build and privileged contract then passed
in the amd64 and arm64 `test` jobs, while all seven jobs completed successfully in
[CI run 33280195424](https://github.com/zl0nline/RTSP_proxy/actions/runs/33280195424)
at commit `bb3790b`.

The command boundary was subsequently hardened against interruption during
descriptor allocation/transfer, signal-mask mutation and `posix_spawn` PID
publication. The parent now owns anonymous channels and a pre-opened
`/proc/thread-self/children` inventory before spawn, keeps the child behind a
gate with termination signals blocked, executes the wrapper through the
current `/proc/self/exe` inode, and gives inventory recovery a separate bounded
budget before PID-report fallback. Direct Linux regressions include delayed
and zombie wrappers plus transient inventory-read failure and prove exact reap
and descriptor parity. Independent Spec and Standards re-review passed; all
seven jobs, including the privileged amd64 and arm64 connect-guard steps,
completed successfully in
[CI run 33314959484](https://github.com/zl0nline/RTSP_proxy/actions/runs/33314959484)
at commit `ab705c1`.

## Deliberately excluded

There is still no production probe executor. This slice does not grant the
control plane BPF or system-bus authority and does not handle a camera secret.
The narrow authenticated root broker, `StartTransientUnit` property allowlist,
attach/readback/canary transaction, credential transport, controlled
no-redirect ffprobe, bounded result parser, cancellation and repeated failure
cleanup remain mandatory. ADR 0004 therefore remains Proposed and Phase G
remains IN PROGRESS / Production NO-GO.
