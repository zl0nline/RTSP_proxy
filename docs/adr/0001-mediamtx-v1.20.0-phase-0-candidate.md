# ADR 0001: MediaMTX v1.20.0 as the Phase 0 candidate

- Status: Proposed
- Date: 2026-08-10
- Decision owners: technical owner, security owner, operations owner

## Context

Direct Linux deployment needs one reproducible MediaMTX binary before the
executable API/auth/hot-update/metrics/RTSP contract can be measured. On 10
August 2026, `v1.20.0` was the latest upstream release returned by `gh`.

The upstream release and checksums are published at
<https://github.com/bluenviron/mediamtx/releases/tag/v1.20.0>.

## Decision

Use `v1.20.0` as the Phase 0 test candidate on Linux amd64 and arm64. This is a
candidate pin, not production approval. Only the official upstream archives are
admitted. Their GitHub artifact attestations and archive checksums were verified
with `gh`; the extracted binary hashes were then measured locally. The exact
URLs and hashes are normative only in
[`deploy/artifact-catalog.json`](../../deploy/artifact-catalog.json), which CI
uses directly and release manifests must match.

The selected architecture and extracted binary checksum must appear in every
immutable release manifest and pass `rtsp-proxy-verify-release` before systemd
activation.

## Acceptance before status can become Accepted

- ordinary external FFmpeg `rtsp://` DESCRIBE/SETUP/PLAY/TEARDOWN over TCP;
- on-demand source pull and restart persistence;
- single-path API create/update/delete without unrelated session impact;
- authentication model, revoke-new behavior and auth-outage behavior;
- API/metrics schema inventory and management listener isolation;
- disabled UDP, HLS, WebRTC, playback, recording and unused listeners;
- startup/readiness version and effective-config checks;
- Linux amd64 and arm64 smoke evidence for each supported architecture.

Any failed mandatory contract keeps this ADR Proposed and triggers comparison
with another pinned release or an explicit design change.

## Consequences

Implementation may build the adapter and contract harness against this exact
candidate. It may not claim MediaMTX compatibility or production readiness
until the acceptance evidence is attached and this ADR is accepted.
