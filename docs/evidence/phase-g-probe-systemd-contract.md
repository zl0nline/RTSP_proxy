# Phase G direct systemd probe contract

- Date: 2026-08-30
- Status: implementation, direct-Linux amd64 contract, independent Spec/
  Standards review and privileged native amd64/arm64 CI green
- Commit: `e1481f3d97a9d687db769ff7d3b80025ae556d56`
- CI: [run 33293333254](https://github.com/zl0nline/RTSP_proxy/actions/runs/33293333254)
  — all seven jobs passed
- Deployment: direct Linux/system manager, no Docker
- Production decision: NO-GO

## Scope

This slice implements the direct system-manager primitive that a future narrow
root broker can invoke. It does not deploy that broker or execute production
ffprobe.

- The caller supplies only one typed probe request and four owned descriptors.
  The manager constructs the entire `StartTransientUnit` request from a fixed
  property allowlist; caller-provided unit names, executables and properties do
  not cross the boundary. `mode=fail` gives each request UUID one atomic unit
  name.
- The transient service runs in `rtsp-probe.slice` as a `DynamicUser` with no
  capabilities, `NoNewPrivileges`, strict filesystem/kernel/cgroup protection,
  a narrow address-family set, no socket bind and address-level network deny.
  `LimitCORE=0` is applied before the launcher can read fd 2. Exact destination
  enforcement remains the separate cgroup connect guard.
- stdin is a broker-held release gate, fd 2 is immutable sealed input and stdout
  is a bounded result pipe. The quiet launcher never writes diagnostics to fd 2.
  This fixed ABI uses transient properties available in systemd 255 while also
  passing on systemd 259.
- A successful start returns an identity-bound opaque lease. Read or cancel
  validates the exact lease and output-pipe inode before taking ownership.
  Output has one absolute deadline and a 64 KiB cap.
- Start, read, cancel and recovery serialize per unit. Definitive D-Bus
  rejection never cleans another owner's unit; ambiguous completion always
  performs stop/reset/collection. Interruptions retain the primary failure,
  cleanup failures become retryable `cleanup_pending`, and retry uses a
  nonblocking lock, one seven-second operation budget, a bounded two-second
  D-Bus disconnect reserve and an eight-unit batch.

## Native evidence

The direct root contract on `grob` (systemd 259) passed three cases: policy and
sealed-input gate flow, output overflow, and cancellation. Each case proved the
transient unit was collected afterward.

[CI run 33293333254](https://github.com/zl0nline/RTSP_proxy/actions/runs/33293333254)
completed successfully at the exact commit above. Both `test (amd64)` and
`test (arm64)` ran and passed `Verify direct transient probe policy` on Ubuntu
24.04/systemd 255, as well as the adjacent exact cgroup connect-guard contract.
The application coverage, lint, type, packaging, migration, release,
pull/load and external-browser jobs all passed; there were seven successful
jobs in total.

The follow-up launcher/result hardening in
[CI run 33325835101](https://github.com/zl0nline/RTSP_proxy/actions/runs/33325835101)
passed all nine jobs at commit `92cec7405f5789f1cb305807f641e7fa247c096d`.
Both privileged application jobs proved effective soft/hard core limits `[0,0]`
before the fixture read its source-secret canary, then aborted and left the
canary absent from the unit journal. The same jobs exercised the installed
clean-wheel launcher and passed the independent 90% coverage gate at 90.08%.

## Deliberately excluded

An installed root-owned socket/service and production-shaped executor now exist
as an unpromoted integrated candidate. The controlled no-redirect artifact,
fixed quiet launcher and strict decoded-frame result contract remain separately
proven; native amd64/arm64 CI must still prove that the broker authenticates its
AF_UNIX peer, revalidates site/CIDR policy, attaches and reads back both cgroup
BPF hooks before releasing the gate, and performs end-to-end cancellation,
restart and residue cleanup. ADR 0004 therefore remains Proposed, Phase G stays
IN PROGRESS and Production remains NO-GO.
