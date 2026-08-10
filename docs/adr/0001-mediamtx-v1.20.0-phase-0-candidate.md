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
with `gh`; the extracted binary hashes were then measured locally.

| Architecture | Upstream archive SHA-256 | Extracted `mediamtx` SHA-256 |
|---|---|---|
| linux/amd64 | `952d5f7d31d1b448ab4da4509550594c511d42636db9d7bb175d377f4ede81df` | `25947caac403f37ec881c9be213af2cad67e344a6c7098905b0d31c17f40e336` |
| linux/arm64 | `6aa3c03da7b6477f1e110c8e18e819cf9ef121e8981b52b8f8219982dae35f2f` | `2da379972ba86627632aa7e3f779c680ba04a5ee26ef2a20dc61cefcc24f73b8` |

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
