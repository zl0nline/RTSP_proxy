# SLI catalog

These definitions are normative for one admitted direct-Linux server. Every
report includes failures, sample count, window, release/commit, hardware,
camera profile and workload axes. Averages never replace p99, success rate or
resource peaks.

## User and media SLIs

| SLI | Measurement | Target | Attribution |
|---|---|---:|---|
| Warm RTSP handshake | external client, DESCRIBE sent through successful PLAY | p99 ≤500 ms; success ≥99.9% | proxy/network versus camera |
| Cold proxy overhead | external cold start minus measured source keyframe wait | p99 ≤1 s | platform |
| Cold end-to-end | external cold start | informational: ≤1 s plus profile GOP maximum | platform plus camera |
| Established media availability | external reader with monotonic received bytes | ≥99.0% monthly; no unexplained resets in soak | platform versus camera/network |
| Second-reader admission | concurrent external clients | winner continues; loser receives RTSP `453` | media admission |
| Camera CRUD isolation | unrelated established readers | 0 interruptions | selected path/node |
| Node lifecycle isolation | established reader on another node | 0 interruptions | selected node/server |

## Control and operational SLIs

| SLI | Measurement | Target | Attribution |
|---|---|---:|---|
| Catalog read | HTTPS ingress to complete response | p99 ≤200 ms; ≥99.9% | control plane |
| Desired-state mutation | HTTPS ingress to committed accepted state | p99 ≤1 s; ≥99.9% | control plane |
| Management readiness | external HTTPS `/health/ready` | ≥99.5% monthly | control plane/database |
| Runtime observation freshness | latest generation-bound node sample | ≥95% within 2× configured interval; 100% before placement decision | collector/node |
| Probe scheduling start | accepted manual confirmation to broker start | ≥99% within configured queue-delay SLO | worker/broker |
| Incident notification | durable incident to terminal relay outcome | one failure and one recovery; within configured deadline | notifier/SMTP |
| Backup freshness | last verified database plus control-assets backup | recovery point ≤5 min at admission | data/operations |
| Restore time | declared incident to ready control plane | ≤30 min | data/operations |

## Resource gates

During the final 24-hour production-equivalent soak, each hard resource stays
below 70% of its effective limit (at least 30% headroom): CPU, RAM, NIC
throughput/packet rate, file descriptors, processes/tasks, node/API ports,
PostgreSQL connections/storage and generator capacity. No positive unbounded
RSS/FD/connection slope is allowed. Any saturation, dropped sample or generator
headroom violation invalidates the interval rather than lowering the workload.

## State interpretation

- Registered camera count is capacity admission; it is not source or reader
  activity.
- `idle` is normal for `sourceOnDemand` with no reader.
- Recent authorized demand without received media is `connecting`, then
  `unavailable` after the bounded start window; it does not mark the node
  unhealthy.
- Deep `SOURCE`/`PATH` observations and their freshness are separate from
  live ingest. Scheduler overload changes freshness, never camera health.
- Failed attempts remain in every success-rate denominator.
- Weakening a target requires an ADR and new baseline evidence.

## Pinned MediaMTX v1.20.0 mapping

| Meaning | Source | Pinned signal |
|---|---|---|
| Registered path configs | management API | paginated `/v3/config/paths/list` `itemCount` |
| Runtime path/source state | metrics | `paths{name,state}` |
| Readers | metrics | `paths_readers{name,state,readerType}` |
| Traffic/errors | metrics | `paths_inbound_bytes`, `paths_outbound_bytes`, `paths_inbound_frames_in_error` |
| RTSP sessions | metrics | `rtsp_sessions{id,path,remoteAddr,state}` |
| RTSP transport | metrics | non-deprecated `rtsp_sessions_*` counters |

The exact family/label contract is
[`evidence/mediamtx-v1.20.0-metrics-schema.json`](evidence/mediamtx-v1.20.0-metrics-schema.json).
MediaMTX does not emit Prometheus `HELP`/`TYPE`; consumers use the pinned
semantics. An on-demand registered path may be absent from runtime metrics.
High-cardinality session labels are aggregated before retention, while all
series retain stable node ID and process generation so port/PID reuse cannot
merge observations.
