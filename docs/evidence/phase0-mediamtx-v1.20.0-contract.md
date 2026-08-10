# Phase 0 MediaMTX v1.20.0 compatibility evidence

- Candidate: MediaMTX `v1.20.0`
- Date: 2026-08-10
- Status: in progress; this is not production approval
- Normative artifact pins: `deploy/artifact-catalog.json`

## Confirmed contracts

- external listener is ordinary `rtsp://`, RTSP-over-TCP interleaved only;
- API and metrics remain on loopback; unused listeners are disabled;
- path replace is convergent for create/update, read-back returns effective path
  configuration, and repeated delete is safe through the adapter;
- update of path A does not interrupt an active FFmpeg reader of path B;
- a separate RTSP origin is pulled on demand; publishing directly into the
  proxy is not used as a substitute for the source path;
- an external FFmpeg/ffprobe consumer receives H.264 through a standard Basic
  Auth RTSP URL and does not require a proxy-specific scheme or handshake;
- runtime paths written through the management API disappear after MediaMTX
  restart and can be restored with a repeated convergent apply.

## Architecture consequence

Runtime MediaMTX configuration is applied state, not desired state. PostgreSQL
must remain authoritative. A restarted media node is not ready until inventory
and bounded cold restore complete. The startup restore rate and traffic policy
remain open until the load spike.

## Reproduction

```sh
MEDIAMTX_BINARY=/path/to/mediamtx \
FFMPEG_BINARY=/path/to/ffmpeg \
FFPROBE_BINARY=/path/to/ffprobe \
uv run pytest -m contract tests/contract
```

CI executes this suite natively on Linux amd64 and arm64. The CI run URL and
architecture-specific result are attached to issues #2, #5 and #14 after the
corresponding commit is green.

## Still open in Phase 0A

- external callback versus runtime/static auth decision, revoke-new and auth
  outage behavior;
- metrics schema inventory and signal mapping;
- explicit on-demand race and secret-leak negative tests;
- two-version FFmpeg/supervisor timeout and reconnect matrix;
- security-owner decision for FFmpeg build provenance.
