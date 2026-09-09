# Camera profile admission contract

Create one versioned profile for every vendor/model/firmware/media combination.
A camera is not production-admitted until its profile passes or a named owner
accepts each unknown. Never put source credentials or private URLs in this file.

## Identity and ownership

| Field | Required value |
|---|---|
| Profile ID / revision | Stable identifier and monotonically updated revision |
| Vendor / exact model | TBD |
| Firmware version/range | TBD |
| Evidence date / admission ID | TBD |
| Site and profile owner | TBD |

## Media and source contract

| Field | Required value |
|---|---|
| Main/sub path shapes | Credential-free redacted patterns; no guessed discovery |
| Codec / resolution / audio | H264/H265 and exact audio layout |
| Typical and peak bitrate/packet rate | Measured |
| Typical and maximum GOP/keyframe interval | Measured |
| RTSP transport | Interleaved TCP passes |
| Keepalive/timeouts/redirects | Observed; redirects are unsupported |
| Maximum simultaneous upstream sessions | Measured at representative load |
| Monitoring policy | Passive-only, or SOURCE enabled only when upstream capacity ≥2 |
| Required media types / probe interval | Explicit profile settings |
| Downstream readers | Exactly one; second receives `453` |

Unknown or one-session upstream capacity is always passive-only, including
while `sourceOnDemand` is idle. Deep observation may not create a competing
source session. Normal idle, recent-demand connecting/start failure and deep
probe health are independent dashboard signals.

## Required evidence

- ordinary FFmpeg `rtsp://` DESCRIBE/SETUP/PLAY/TEARDOWN with advancing bytes;
- main/sub path validation and exact unsupported-media behavior;
- cold start at typical and maximum GOP;
- source outage, authentication rejection and recovery;
- one existing source session plus the claimed additional-session capacity;
- winner stream continuity and exact `453` for a second downstream reader;
- source credentials containing `$`, `%`, `@` and `:` through separate
  raw fields, with no secret in logs/API/audit;
- camera update/move/grant revoke isolation with an unrelated witness stream;
- contribution to the final 24-hour capacity soak.

The catalog stores a credential-free `rtsp://host/path` plus separate raw
username/password fields. Operators must not percent-encode those fields; the
server encodes reserved characters exactly once and stores a camera-bound
AES-256-GCM envelope. API, dashboard and audit never return the secret.

`RTSP_PROXY_PROBE_SOURCE_CIDRS` is an exact site allowlist for source
registration; empty means deny-all. Source admission resolves once, persists a
literal IP/port plus policy/source digest and is invalidated by policy change.
This is separate from downstream `internet`/`local` CIDRs, where both empty
means allow-all at the direct-peer IP stage.

## Decision

| Item | Value |
|---|---|
| Highest measured cameras/node for this profile | TBD |
| Maximum admitted operational cameras/node | TBD |
| Residual risks accepted by | TBD |
| Decision (`PASS`, `HOLD`, `REJECT`) | TBD |

The operational cap cannot exceed either the measured profile envelope or the
server envelope. The owner-deferred 100-camera test remains visible when a
lower cap is used.
