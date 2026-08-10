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
