# RTSP Proxy engineering context

## Domain language

- **Camera** — catalog object representing one configured RTSP source path.
- **Source** — private camera endpoint pulled by MediaMTX on demand.
- **Public ID** — immutable external path name, never an access credential.
- **Access grant** — proxy-owned external username/password and read scope.
- **Desired state** — PostgreSQL configuration accepted by the control plane.
- **Applied state** — configuration verified on a concrete media target.
- **Media node** — one directly installed MediaMTX runtime.
- **Consumer** — external FFmpeg process using ordinary `rtsp://`.
- **Reconciler** — process converging desired and applied media-node state.
- **Probe** — bounded observation of a source or external path.

## Confirmed test seams

Tests observe behavior only through these interfaces:

1. HTTP application interface: health, catalog and camera commands.
2. Media-node interface: one adapter hides MediaMTX HTTP/version details.
3. External RTSP interface: real FFmpeg against ordinary RTSP-over-TCP.
4. PostgreSQL behavior through application commands, not private repository
   methods.
5. Linux deployment interface: environment/config consumed by systemd-managed
   processes and immutable release artifacts.

External dependencies may use test adapters at these seams. Tests do not mock
our own internal modules or assert private call order.

## Deployment contract

- Direct Linux deployment on amd64 and arm64; both architectures have identical
  release, compatibility and production gates. No Docker or container runtime.
- Python 3.12 environment built from `uv.lock` and a verified wheel.
- Immutable root-owned releases under `/opt/rtsp-proxy/releases/<version>`.
- Atomic `/opt/rtsp-proxy/current` symlink for activation and rollback.
- Dedicated non-login Linux users and hardened systemd units.
- `deploy/artifact-catalog.json` is the single machine-readable candidate source
  for architecture-specific MediaMTX, FFmpeg and ffprobe versions, URLs and
  SHA-256 values. Release manifests copy those pins and are verified natively.

## Current implementation boundary

The repository is in Phase 0. The reviewed foundation provides fail-closed role
readiness, native release verification and direct-Linux service artifacts. The
Phase 0A compatibility layer passed Standards/Spec exit review and native
amd64/arm64 CI. It provides a typed MediaMTX path adapter; executable lab
contracts cover ordinary RTSP-over-TCP, on-demand pull, restart/cold restore,
auth behavior and pinned metrics on real binaries. There is no production
ffprobe runner until ADR 0004's process/egress boundary is accepted.

Phase 0B is in progress. `tools/load` contains native GStreamer pull-source and
multi-reader binaries plus a digest-bound per-host run orchestrator. Latency is
split into RTSP handshake and first-decodable measurements; cold results require
a finalized direct-control pair and subtract only handshake latency, not
unsynchronized GOP waits. A warm proxy run reserves one reader per active path
inside `total_readers` as an anchor, starts those anchors 60 seconds before the
measured ramp and proves them through the ramp boundary with typed API polling.
Shards share future UTC anchor/ramp/measurement/soak epochs and remain observable
through a derived post-workload sampling grace. Completion binds exact per-host
counts and lifecycle slots to
host/profile/reader-plan/clock evidence, including an end-of-workload clock
proof and bounded early/late schedule deviation. Generator evidence binds the exact
cgroup PID set to executable digests/start times and captures NIC packets/MTU
plus effective ephemeral TCP capacity after reserved ports. An obligatory
per-host runtime manifest brackets the full capture with synchronized clock proofs and binds profile, architecture,
machine/boot, CPU/RAM/NIC/kernel/sysctl, effective cgroup/RLIMIT values and exact
process identity; generator manifests also bind the dpkg GStreamer build and
the SHA/device/inode of libraries mapped by every workload process. Measurement and
soak headroom/session-health gates are recomputed separately;
finalization regenerates plans and summaries from raw data before sealing the
bundle. Every proxy bundle, and every capacity bundle, also requires an independent
typed MediaMTX PID/cgroup/NIC series; capacity gates additionally include
maximum rolling 6h RSS slope, FD/all-session/runtime-path drain, per-sample SUT
clock proof, cumulative MediaMTX loss deltas and phase-bound reader RTP sequence
reconciliation. A fixture
manifest binds the pinned FFmpeg/ffprobe tools to probed codec/FPS/bitrate/GOP.
Hardened native amd64/arm64 CI `31499414349` and its full rerun cover the
pre-runtime-manifest harness. The runtime collector now has a privileged public
capture/binding contract on both native runners but requires a newly published CI
result and repeat review. WAN/netem and non-zero probe/CRUD axes
deliberately fail closed
until typed drivers exist; native CI is functional evidence only and is not a
measured single-node capacity envelope.

The runtime/hardware manifest code is implemented, but no production-equivalent
hardware manifest or capacity run has been published. A finalized functional
bundle remains compatibility evidence, not a production capacity claim.

Role processes do not yet run catalog, grant, reconciler, scheduler or
observability loops. PostgreSQL durability, artifact provenance, capacity and
production readiness have not been proven. Proposed ADRs and successful lab
contracts must not be presented as production approval.
