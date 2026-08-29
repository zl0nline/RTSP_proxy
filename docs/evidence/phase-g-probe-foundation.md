# Phase G probe foundation

- Date: 2026-08-29
- Status: implemented; independent Spec/Standards review PASS; native CI green
- Commit: `446b6a325d13fd60569214296e3862c7f45ee836`
- CI: [run 33273481381](https://github.com/zl0nline/RTSP_proxy/actions/runs/33273481381)
  — all seven jobs passed, including application,
  MediaMTX/release and pull/load contracts on amd64 and arm64 plus external
  Chromium E2E
- Deployment: direct Linux/systemd, no Docker
- Server architectures: foundation contract green on amd64 and arm64; native
  privileged executor evidence pending
- Production decision: NO-GO

## Evidence boundary

This slice implements the non-privileged scheduler, observation, persistence,
endpoint-admission and dashboard projection foundations from issue #6. It does
not ship or enable a production source-probe executor and does not accept ADR
0004. No code in this slice grants WEB, scheduler or reconciler system-manager,
root, BPF or arbitrary subprocess authority.

The companion research note
[`2026-08-29-phase-g-linux-probe-execution-boundary.md`](../research/2026-08-29-phase-g-linux-probe-execution-boundary.md)
records the primary-source and direct-Linux findings that keep production
closed.

## Implemented foundation

- `BoundedProbeScheduler` owns one bounded queue and one single-flight request
  per camera. It enforces global, per-node, per-site and separately reported
  SOURCE/PATH active limits, bounded
  leases/retries, controlled borrowing from the initial 4/3/3 class-reservation
  hypothesis and near-deadline aging. A manual join promotes queued routine
  work instead of starting a second process; manual work cannot bypass the same
  hard limits. Class reservations are applied before deadline aging, so urgent
  manual traffic cannot consume the confirmation/routine guarantees.
- Admission rejects disabled/maintenance cameras, occupied path probes,
  path probes while a source pull is already active, non-running path targets
  and source probes that would exceed the camera
  source-session budget. A current-target batch repeats those checks when a
  lease is claimed; missing authority leaves work queued rather than executing
  from stale state. PATH work also requires exact node applied revision and
  PID/start/boot/release identity. The result stores repeat those invariants.
- SOURCE health, PATH health and freshness are separate typed dimensions. Two
  time-separated deep failures are required for `UNHEALTHY`; recovery uses
  `RECOVERING` before the second time-separated success. Missing/late work makes
  freshness stale or overdue, not camera health unhealthy. Executor/output
  failures are persisted as `INCONCLUSIVE` and do not advance either health
  state.
- Migration `0020_probe_observations` adds an immutable endpoint-generation
  registry plus one latest result per camera/method. Camera create/source-update
  resolves and validates exactly once before the synchronous camera transaction,
  then atomically stores the approved literal address, port, URL digest and new
  opaque generation. Old 0019 rows remain unadmitted and therefore cannot be
  probed until an explicit source update/re-registration validates them.
  A synchronous transaction writes only when camera ID/Public ID, desired
  revision, placement generation, node, node state and maintenance still match;
  PATH also matches the exact runtime generation, while both methods match the
  current endpoint generation and current site-policy digest. Non-source camera
  revisions invalidate old observations without invalidating the admitted
  endpoint. Same-observation replay is immutable and remains
  idempotent outside the new-write clock window; a different observation must
  be newer, and PostgreSQL time bounds incoming completion timestamps to prevent
  future-date poisoning. Exact readiness validates both tables, columns,
  constraints, index and required privileges rather than trusting Alembic head.
  Database
  constraints repeat duration, eligibility and normalized-result rules. The
  observation schema has no source URL, hostname, literal address, port,
  username, password or secret column. The separate admission table deliberately
  stores the approved literal IP:port plus site/policy digest, but never the
  source URL, hostname, path/query or credentials.
- The live-update component reads result and fleet stores independently. A
  result-store failure cannot poison ordinary camera state. A matching newer
  observation emits a bounded, normalized `probe_completed` event containing
  only method/outcome/failure class/codecs/timing/attempt and an opaque
  observation ID. Authoritative absence after generation invalidation emits
  `probe_cleared` and purges the stale event from replay. Initial replay remains
  bounded and `current()` remains a state snapshot rather than accidentally
  returning a probe event.
- Endpoint admission accepts only `rtsp://`, canonicalizes IDNA, resolves once
  through a four-slot Linux NSS subprocess boundary with a two-second hard
  deadline and bounded output,
  during camera create/source update,
  normalizes IPv4-mapped IPv6, validates every answer against forbidden ranges
  and an explicitly configured site/CIDR policy, then persists one UUID-bound
  literal target. Empty CIDRs are an intentional deny-all policy; changing the
  policy digest invalidates prior admissions until explicit re-registration.
  The existing camera update operation performs that recovery even when the
  source URL is unchanged: missing/mismatched admission state forces a new
  generation and camera revision rather than returning the normal no-op.
  Probe scheduling carries only that immutable generation; it never accepts a
  hostname or performs DNS. The ffconcat builder
  fixes `rtsp_transport=tcp` and `rw_timeout` in microseconds. Credentials and
  path/query token material are excluded from object representations.

## Deliberately open gates

The `grob` spike proved that `systemd-run --user` can accept
`IPAddressDeny=any` while enforcing nothing, and upstream systemd documents
address-only rather than port-aware filtering. The pinned stock RTSP demuxer
also follows 3xx redirects, while non-quiet concat errors can log the full
credential-bearing nested URL.

Before any source executor is enabled, the project still requires:

1. a narrow root-owned authenticated broker that constructs a fixed
   system-manager transient service rather than exposing `manage-units`;
2. a root-attached cgroup `connect4`/`connect6` guard proving the exact admitted
   IP and port before credentials/run release;
3. a controlled, provenance-retained ffprobe build that refuses RTSP redirects,
   forces quiet output and returns only a size-bounded allowlisted result;
4. pipe or sealed-memfd secret transport plus `/proc`, journal, cancellation,
   cleanup and resource-exhaustion tests; and
5. the complete privileged native matrix on amd64 and arm64, followed by the
   100-camera-per-node, multi-node, WAN/fault and 24-hour capacity evidence.

The periodic risk-based producer, durable health-state orchestration, operator
manual-trigger workflow and capacity-calibrated intervals/weights are also
outside this foundation. Until every gate passes, Phase G remains IN PROGRESS
and Production remains NO-GO.
