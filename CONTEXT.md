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
- MediaMTX is an official architecture-specific binary pinned by version and
  SHA-256.

## Current implementation boundary

The repository is in Phase 0/foundation. Implemented behavior must not imply
that MediaMTX compatibility, PostgreSQL durability, capacity or production
readiness have already been proven.
