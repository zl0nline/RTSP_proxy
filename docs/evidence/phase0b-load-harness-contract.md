# Phase 0B load harness evidence

- Date: 2026-08-10
- Status: functional harness in progress; no capacity decision
- Deployment: direct Linux, no Docker/container runtime
- Architectures: native `amd64` and `arm64`

## Implemented contract

- prepared H.264/H.265 fixtures are served by GStreamer RTSP server endpoints;
- MediaMTX is expected to pull those endpoints on demand; push publication into
  MediaMTX is not a supported primary load path;
- source and reader processes force RTSP-over-TCP and the native contract scans
  every process-owned UDP/UDP6 socket;
- many GStreamer readers run in one process and record reader ID, path,
  first-packet latency and stable error reason as raw JSONL;
- Basic Auth credentials are optional synthetic lab inputs read from a
  two-line file and never placed in argv or event output;
- strict profiles pin artifacts, fixture SHA/codec/bitrate/FPS/GOP/audio,
  topology, workload axes, durations and generator ranges;
- registered paths, active sources and total readers remain independent fields;
- deterministic lab-only public IDs map every registered path to one generator
  endpoint, apply as `sourceOnDemand=true`, and are inventory/read-back checked;
- profile, path catalog, reader path list and run directory use exclusive
  creation; existing evidence is not overwritten;
- generator CPU/RAM/global-FD/NIC raw samples cover the complete run and fail
  validation at `>=70%` utilization;
- reader summary retains failed attempts, enforces `>=99.9%` establishment and
  warm proxy p99 `<=500ms`; cold runs cannot claim proxy overhead without a
  paired direct-control decomposition.

## Functional CI boundary

The native jobs compile both C binaries with distro GStreamer development
libraries, print exact package versions and binary SHA-256 values, prepare
pinned-FFmpeg fixtures, then prove two H.264 and two H.265 pull endpoints with
fan-out readers and rejected UDP transport.

This proves functional compatibility only. It does not satisfy the Spike #0
exit: no production-equivalent hardware manifest, two-host generator
convergence, LAN/WAN baseline, 100/500/1000 ladder, knee, churn/fault matrix or
24-hour soak has been published yet.
