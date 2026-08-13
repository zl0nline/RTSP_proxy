# Phase 0 MediaMTX v1.20.0 compatibility evidence

- Candidate: MediaMTX `v1.20.0`
- Date: 2026-08-10
- Status: in progress; this is not production approval
- Normative artifact pins: `deploy/artifact-catalog.json`

> The 2026-08-12 bounded-node decision changes the product admission contract
> to one downstream reader per camera. The four-reader checks below remain
> historical MediaMTX fan-out/on-demand compatibility evidence; they are not a
> production behavior claim. A new native contract must prove one winner and
> RTSP 453 for concurrent additional readers.

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
  the origin observes exactly one upstream proxy reader; this historical path
  is installed directly by the compatibility test with lab-only
  `maxReaders=4`, outside the product adapter whose invariant remains exactly
  one downstream reader;
- both internal and HTTP callback auth modes pass the ordinary RTSP contract;
  callback input contains the expected user/password/action/path/protocol;
- callback denial revokes new sessions within 10 seconds; callback outage
  fails new sessions closed while an established reader remains live and its
  outbound-byte counter continues increasing after both events;
- a revoked grant, wrong password, unknown user and unknown path return the same
  byte-for-byte RTSP response through the HTTP callback; the short runtime
  contract does not claim statistical timing equivalence;
- four concurrent callbacks delayed past the one-second MediaMTX read deadline
  fail new sessions closed while the established reader continues progressing;
- an incomplete RTSP header remains open past that one-second setting, proving
  that `readTimeout` is not a sufficient slowloris/handshake control;
- registered configs, runtime path/source state, readers and RTSP sessions have
  distinct pinned API/metrics signals; the full emitted family/label schema is
  versioned and no `rtsps_*` family is emitted;
- an active UDP ffprobe is rejected and the native Linux process owns no UDP
  socket on the external RTSP port;
- the lab ffprobe command uses the pinned `-timeout` microsecond option and TCP
  transport. It uses synthetic credentials and is not shipped as production
  code; the rejected production execution boundary is recorded in ADR 0004;
- MediaMTX output collected across successful auth, denied auth and callback
  outage does not contain the exercised external passwords; successful and
  rejected credentialed source pulls likewise do not expose source userinfo;
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

CI executes this suite natively on Linux amd64 and arm64. Remediation commit
`653f93b` passed both architecture-specific unit/release jobs and both
real-binary media contract jobs in
[CI run 31406619869](https://github.com/zl0nline/RTSP_proxy/actions/runs/31406619869).

## Follow-up gates after the Phase 0A exit

- two-version FFmpeg/supervisor timeout and reconnect matrix;
- isolated production probe execution (ADR 0004; health/security slices);
- auth-layer/edge rate limiting and slow-client resource controls;
- statistically powered timing no-oracle evidence for revoked, wrong-password,
  unknown-user and unknown-path denials;
- native VPN source-IP preservation; L4/NAT and cross-host callback remain
  explicitly prohibited for direct node exposure until that evidence;
- security-owner decision for FFmpeg build provenance.
- per-node HTTP admission contract for ACL-before-password, drain and exact
  one-reader/RTSP 453 behavior (ADR 0003).
