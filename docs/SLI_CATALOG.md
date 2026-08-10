# Initial SLI catalog

This catalog defines measurement intent. Exact signal names and queries are
filled from the pinned MediaMTX and application inventory during Phase 0.

| SLI | Measurement point | Initial target | Error attribution |
|---|---|---:|---|
| Warm RTSP start | external FFmpeg, DESCRIBE to first playable packet | p99 ≤ 500 ms | platform/network vs camera |
| Cold proxy overhead | external FFmpeg minus measured keyframe wait | p99 ≤ 1 s | platform only |
| Cold end-to-end | external FFmpeg | informative ≤ 1 s + profile GOP max | platform + camera GOP |
| Catalog read | HTTP ingress to response | p99 ≤ 200 ms | control plane |
| CRUD mutation | HTTP ingress to desired accepted | p99 ≤ 1 s | control plane |
| Deep observation freshness | scheduler projection by site/subnet | ≥ 95% within 2 × interval | scheduler vs camera |
| Manual confirmation start | accepted command to probe start | ≥ 99% within queue-delay SLO | scheduler |
| Control-plane availability | external management probe | ≥ 99.5% / month | platform |
| Established media availability | external consumer | ≥ 99.0% / month | platform vs camera |

Rules:

- p50 and p95 remain diagnostics; normative latency pass/fail uses p99.
- Failed attempts stay in the success-rate SLI and are not discarded from
  reports.
- Scheduler overload changes observation freshness, never camera health.
- SLO weakening requires an ADR with baseline and evidence.

## Pinned MediaMTX v1.20.0 signal mapping

| Meaning | Source | Pinned signal |
|---|---|---|
| Registered path configs | management API | paginated `/v3/config/paths/list` `itemCount` |
| Runtime path/source state | metrics | `paths{name,state}` |
| Readers per runtime path | metrics | `paths_readers{name,state,readerType}` |
| Path traffic/errors | metrics | `paths_inbound_bytes`, `paths_outbound_bytes`, `paths_inbound_frames_in_error` |
| RTSP sessions | metrics | `rtsp_sessions{id,path,remoteAddr,state}` |
| RTSP transport traffic/loss | metrics | non-deprecated `rtsp_sessions_*` counters |

The runtime `paths` metric is not catalog cardinality: an on-demand configured
path can be registered while absent from runtime metrics. Dashboard and capacity
reports therefore keep registered configs, ready sources and readers separate.
The platform-owned canonical-ID fallback matcher used for no-oracle auth is
excluded from camera counts and protected from reconciler deletion.
Session `id` and `remoteAddr` are high-cardinality labels; the future collector
must aggregate/drop them before long-retention storage while preserving bounded
per-path signals. Deprecated `*_bytes_received/sent` metrics are not used for
new queries. An enabled `rtsps_*` family is a startup-contract violation.
