# Phase 0B load harness evidence

- Last reviewed: 2026-08-12
- Status: functional harness reviewed; no capacity decision
- Deployment: direct Linux, no Docker/container runtime
- Architectures: native `amd64` and `arm64`

> The harness was originally built for one generic SUT and larger reader
> ladders. Bounded-node profile validation, one-reader/RTSP-453 admission and
> multi-SUT orchestration are **pending Phase C/G work**. Planned product
> qualification will use it first for one node at no more than 100 registered
> cameras/readers, then for multiple independent nodes on one server. Generic
> fan-out/burst support is harness capability, not the product contract.

## Implemented contract

- prepared H.264/H.265 fixtures require a typed pinned-FFmpeg/ffprobe manifest
  proving codec/FPS/bitrate/internal keyframe intervals and the final
  keyframe-to-loop-restart interval before GStreamer serves them;
- every remote source process verifies the pinned fixture SHA-256 before
  announcing readiness;
- each RTSP media instance reparses video to complete H.264/H.265 access units,
  passes the first unit immediately for preroll and schedules subsequent units
  at profile FPS using rational absolute monotonic deadlines; when a buffer
  arrives more than one frame interval after its deadline, the schedule rebases
  and waits one interval instead of producing a catch-up burst, otherwise it
  preserves the absolute deadlines. Opus uses 960-sample/20ms raw buffers on an
  independent 50 Hz schedule before encoding and RTP payloading;
- MediaMTX is expected to pull those endpoints on demand; push publication into
  MediaMTX is not a supported primary load path;
- source and reader processes force RTSP-over-TCP and the native contract scans
  every process-owned UDP/UDP6 socket;
- many GStreamer readers run in one process and record the reader ID/path,
  `DESCRIBE→PLAY`, first AU-aligned IDR/IRAP random-access unit (header-only,
  delta, decode-only, corrupted and gap buffers are rejected),
  RTP packet count and
  stable error reason as raw JSONL;
- video and configured Opus RTP pads are sequence-checked independently per
  reader/reconnect generation; every cycle/track/phase segment publishes
  successfully parsed received packets and the sender sequence-number span,
  then reconciles both with phase and shard totals. Video must sustain at least
  80% of pinned fixture FPS (Opus: 40 packets/s) in every typed connected
  interval, with successful first/last packets within one second of its
  boundaries, so both an internal sequence gap and a gap-free trailing stall fail;
- Basic Auth credentials are optional synthetic lab inputs read from a
  two-line file and never placed in argv or event output;
- strict profiles pin artifacts, fixture SHA/codec/bitrate/FPS/GOP/audio,
  topology, workload axes, durations and generator ranges;
- registered paths, active sources and total readers remain independent fields;
- deterministic lab-only public IDs map every registered path to one generator
  endpoint, apply as `sourceOnDemand=true`, and are inventory/read-back checked;
- profile, path catalog, reader path list and run directory use exclusive
  creation; existing evidence is not overwritten;
- all shards share warm-anchor/ramp/measurement epochs and one absolute
  soak/workload end; they record kernel clock-sync proof throughout the workload,
  exact per-shard counts, lifecycle slots and profile/reader-plan/host bindings.
  Every injected disconnect binds its deterministic backoff to the same-cycle
  schedule and ordered next-cycle start→PLAY→first-decodable chain; orphan or
  skipped cycles fail;
- Phase 0B profiles fail closed on IPv6 literals until the native source and
  evidence paths are fully dual-stack;
- a derived post-workload grace keeps every reader PID observable until a final
  generator sample covers the actual workload end, without extending media load;
- generator PID sets must exactly equal the finite cgroup process set and bind
  to pinned executable digests/start times; CPU/RAM/FD/NIC byte/packet/MTU raw
  samples plus effective ephemeral-port capacity after reserved ports and
  in-use TCP sockets cover the
  complete workload window; capacity CPU is `<=65%`, NIC bytes/packets `<=60%`,
  and RAM/FD/socket/cgroup-pids remain `<70%`. Cgroup v2 accounting walks every
  limiting ancestor and includes shared-slice usage; hard denominators and the
  canonical constraint chain must remain unchanged across samples;
- every finalized run requires typed runtime/hardware evidence from every
  generator host; proxy and capacity runs also require the SUT manifest. The
  capture is bracketed by synchronized Linux clock proofs and binds profile to native architecture,
  machine/boot, CPU/RAM/NIC/kernel/OS, fixed sysctls, effective cgroup/RLIMIT and
  exact PID/start/executable identity. Generator evidence also binds the exact
  `libgstreamer1.0-0` dpkg build, installed package ledger and
  SHA-256/device/inode identities of mapped GStreamer libraries for every
  workload process. Cold A/B copies finalized direct runtime manifests and rejects
  stable environment drift;
- reader summary retains failed attempts, enforces `>=99.9%` establishment and
  warm proxy ramp p99 `<=500ms`; one anchor inside `total_readers` keeps every
  active path warm across ramp start, typed API polling proves the anchors, and
  generic burst profiles can retain at least 1000 measured readers after
  anchors are reserved;
  cold runs cannot claim proxy overhead without a
  paired direct-control handshake decomposition; GOP waits remain separate;
- finalization semantically regenerates prepared plans and recomputes typed
  summaries from raw evidence, so a fabricated `valid: true` cannot pass.
- cold proxy profiles use one reader per active path, `single` lifecycle, no
  more than the conservative 512-path/32-worker implementation safety cap, and a
  typed reset/recreate + unavailable-path preflight captured no more than 30
  seconds before the coordinated start; missing/stale/post-reset-ready evidence
  fails finalization.
- ramp, warm-up, measurement and soak are bound as distinct epochs; session
  health, RTP rates and resource ceilings are recomputed separately for measurement and
  soak, and steady/outage injection starts only after the readiness warm-up.
- every proxy and every capacity finalization requires an independent SUT series bound to the exact
  MediaMTX PID/cgroup/NIC and pinned metrics families. Each sample and each
  loopback cold/warm preflight carries fail-closed kernel clock proof;
  per-session/per-path counters remain cumulative across churn and are gated
  from a pre-measurement baseline. Exact empty-family zero sentinels fail closed.
  Session history identity remains stable on `id+remoteAddr` across legal
  idle/read path transitions, while every sample requires matching
  `id/path/remoteAddr/state` labels across selected families. State-specific
  RTP/RTCP error fields and aggregate reconciliation fail closed; an observed
  path ready/notReady transition starts a new counter generation, while a
  decrease in a continuously observed state is invalid. It gates SUT
  headroom, maximum rolling 6h RSS slope including
  cross-phase windows, FD drain, all RTSP sessions plus ready runtime paths
  after the pinned on-demand close/drain interval, and zero RTP/RTCP/path error
  delta. Capacity additionally applies the long-window leak/soak conclusions;
- named WAN profiles are exact (`50 ms` added RTT at camera-side ingress,
  `10 ms` jitter, `0.5%` random loss); exact camera-source IPv4/TCP flows are
  redirected by `clsact/flower` to a dedicated, MTU-matched IFB with no
  routable address, a pinned bounded delay/jitter root and a maximum-capacity
  random-loss child netem qdisc. Installation refuses
  dirty/ambiguous ingress, egress, chain or IFB state and rollback removes only
  exact owned state;
- every impaired run requires typed raw observations and a recomputed summary
  for every receiver site. Evidence binds canonical plans, interface
  indexes/MTU, `tc`/`ip` canonical path/SHA/version, exact per-flow action
  counters, both qdisc levels, queue boundaries and synchronized time. The
  cumulative parent-minus-child drop delta proves queue overflow independently
  from child random loss, which must fit a two-sided envelope. Positive action
  drops/overlimits, counter drift/reset, missing scoped traffic, any queue
  overflow, loss outside the envelope, packet-accounting mismatch or
  non-quiescent drain fails closed. Cold proxy A/B copies and revalidates the
  direct netem raw/summary/runtime/launch evidence and seals the aggregate
  proxy-minus-direct loss delta;
- the final manifest is the sealing completion marker; verification checks
  exact `0440`/`0550` modes and an interrupted final chmod is recoverable only
  by rerunning the full semantic finalizer. The marker is published with an
  fsynced temporary inode, atomic link and parent-directory fsync.

## Functional CI boundary

Hardened native amd64/arm64
[run 31529502107](https://github.com/zl0nline/RTSP_proxy/actions/runs/31529502107)
is green for all six application, release/media and pull-load-generator jobs at
commit
[`1ea5137b4b51bba3736827ed3b5fa13f45912be9`](https://github.com/zl0nline/RTSP_proxy/commit/1ea5137b4b51bba3736827ed3b5fa13f45912be9).
This records CI outcome, not a final Phase 0B exit-review PASS.

The native jobs compile both C binaries with distro GStreamer development
libraries, print exact package versions and binary SHA-256 values, prepare
pinned-FFmpeg fixtures, then prove two H.264 and two H.265 pull endpoints with
fan-out readers and rejected UDP transport. The updated workflow also starts a
finite systemd service and runs the public runtime capture/binding contract
against real `/proc`, cgroup v2, dpkg and mapped GStreamer libraries. Isolated
Linux network namespaces also prove that matching camera-source traffic is
impaired, an adjacent control flow is not, counters reconcile, drift is rejected
and exact state is removed. All contracts run on both amd64 and arm64 before the
H.264/H.265 RTSP/TCP checks.

This proves functional compatibility only. It does not satisfy production
per-node or per-server capacity qualification. None of the following evidence
has been published: production-equivalent
hardware capture, two-host generator convergence, production-equivalent LAN/WAN baseline,
1/10/50/80/100 per-node ladder, 1/5/10/25/50 node server ladder, knee,
churn/fault matrix or 24-hour soak.

Non-zero probe/CRUD axes currently fail profile validation until their typed
drivers and verification evidence are implemented. This is an explicit Phase
0B code gap, not a silently ignored workload axis. The green namespace netem
contract is functional compatibility evidence, not a real WAN capacity result.
