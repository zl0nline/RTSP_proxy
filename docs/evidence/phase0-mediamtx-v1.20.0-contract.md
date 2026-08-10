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
- four simultaneous first readers of one cold on-demand path all succeed while
  the origin observes exactly one upstream proxy reader;
- both internal and HTTP callback auth modes pass the ordinary RTSP contract;
  callback input contains the expected user/password/action/path/protocol;
- callback denial revokes new sessions within 10 seconds; callback outage
  fails new sessions closed while an established reader continues;
- wrong password, unknown user and unknown path return the same RTSP response
  through the HTTP callback, without a path or credential enumeration oracle;
- registered configs, runtime path/source state, readers and RTSP sessions have
  distinct pinned API/metrics signals; no `rtsps_*` family is emitted;
- the platform ffprobe interface uses the pinned `-timeout` microsecond option,
  TCP transport and credential-free errors even when raw ffprobe stderr contains
  the rejected userinfo URL;
- MediaMTX output collected across successful auth, denied auth and callback
  outage does not contain the exercised external passwords;
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

- two-version FFmpeg/supervisor timeout and reconnect matrix;
- process-argument isolation for source credentials and remaining source-error
  MediaMTX log scenarios;
- callback overload/rate-limit tests and statistical timing-oracle analysis;
- cross-host callback/L4/VPN source-IP boundary;
- security-owner decision for FFmpeg build provenance.
