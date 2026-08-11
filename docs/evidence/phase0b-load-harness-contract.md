# Phase 0B load harness evidence

- Date: 2026-08-10
- Status: functional harness in progress; no capacity decision
- Deployment: direct Linux, no Docker/container runtime
- Architectures: native `amd64` and `arm64`

## Implemented contract

- prepared H.264/H.265 fixtures require a typed pinned-FFmpeg/ffprobe manifest
  proving codec/FPS/bitrate/internal keyframe intervals and the final
  keyframe-to-loop-restart interval before GStreamer serves them;
- every remote source process verifies the pinned fixture SHA-256 before
  announcing readiness;
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
  and RAM/FD/socket/cgroup-pids remain `<70%`;
- reader summary retains failed attempts, enforces `>=99.9%` establishment and
  warm proxy ramp p99 `<=500ms`; one anchor inside `total_readers` keeps every
  active path warm across ramp start, typed API polling proves the anchors, and
  burst retains at least 1000 measured readers after anchors are reserved;
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
- capacity finalization additionally requires a SUT series bound to the exact
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
  delta.
- the final manifest is the sealing completion marker; verification checks
  exact `0440`/`0550` modes and an interrupted final chmod is recoverable only
  by rerunning the full semantic finalizer. The marker is published with an
  fsynced temporary inode, atomic link and parent-directory fsync.

## Functional CI boundary

Previous native amd64/arm64 run `31417242196` is green for application,
release/media and pull-load-generator jobs. The current hardened slice requires
a fresh native run before its repeat exit review can pass.

The native jobs compile both C binaries with distro GStreamer development
libraries, print exact package versions and binary SHA-256 values, prepare
pinned-FFmpeg fixtures, then prove two H.264 and two H.265 pull endpoints with
fan-out readers and rejected UDP transport.

This proves functional compatibility only. It does not satisfy the Spike #0
exit: no production-equivalent hardware manifest, two-host generator
convergence, LAN/WAN baseline, 100/500/1000 ladder, knee, churn/fault matrix or
24-hour soak has been published yet.

WAN/netem and non-zero probe/CRUD axes currently fail profile validation until
their typed drivers and verification evidence are implemented. This is an
explicit Phase 0B code gap, not a silently ignored workload axis.
