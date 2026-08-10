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
multi-reader binaries; strict profiles/catalogs and JSONL headroom/latency
summaries are in the Python package. Native CI is functional evidence only and
must not be described as a measured single-node capacity envelope.

Role processes do not yet run catalog, grant, reconciler, scheduler or
observability loops. PostgreSQL durability, artifact provenance, capacity and
production readiness have not been proven. Proposed ADRs and successful lab
contracts must not be presented as production approval.
