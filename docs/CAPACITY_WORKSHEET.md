# Capacity and soak worksheet

Create one copy per hardware/workload envelope. Blank means unknown, never zero.
A configured 100 cameras/node or 50 nodes/server is an admission ceiling, not a
capacity result.

## Immutable manifest

| Field | Value |
|---|---|
| Admission ID / UTC window | TBD |
| Release ID / 40-character commit / manifest SHA-256 | TBD |
| Schema / MediaMTX identity and SHA-256 | TBD |
| Architecture / distribution / kernel | TBD |
| CPU model/count / RAM / NIC / storage | TBD |
| sysctl / ulimit / systemd limits | TBD |
| PostgreSQL version/config/storage | TBD |
| Generator A and B hardware/headroom | TBD |
| Camera-side WAN/LAN topology and netem | TBD |
| Camera profile evidence links | TBD |
| `max_nodes`, node/API/RTSP port ranges | TBD |

## Independent workload axes

| Axis | Value |
|---|---:|
| Node count and per-node process map | TBD |
| Registered/enabled paths per node | TBD |
| Concurrent source pulls per node | TBD |
| Occupied downstream readers per node | TBD |
| Occupancy distribution, including uneven nodes | TBD |
| Codec/audio/GOP | TBD |
| Typical/peak bitrate and packet rate | TBD |
| Reader connect/disconnect rate | TBD |
| Camera CRUD rate and operation mix | TBD |
| SOURCE/PATH probe rate | TBD |
| Metrics/dashboard poll rate | TBD |
| Injected latency/loss/faults | TBD |

Both generator hosts must be distinct from the system under test and each stay
below 70% of CPU, RAM, NIC, FD and process limits. Any zero probe/CRUD rate must
be explicitly justified; it cannot qualify the full production envelope.

## Ladder

Run node occupancy and server process count as independent dimensions. Standard
node checkpoints are 1, 10, 50 and 80 registered cameras plus the owner-deferred
100-camera checkpoint. Server checkpoints are 1, 5, 10, 25 and 50 nodes when
hardware permits. Stop at the first failing checkpoint and publish the previous
passing envelope; never extrapolate.

| Run | Nodes | Registered/node | Sources/node | Readers/node | Churn | CRUD | Probe | Duration | Result |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| baseline | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD |
| ladder | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD |
| final soak | TBD | TBD | TBD | TBD | TBD | TBD | TBD | 24h | TBD |

## Results

| Resource or SLI | p50 | p95 | p99 / peak | Gate | Pass |
|---|---:|---:|---:|---:|---|
| Warm DESCRIBE→PLAY | TBD | TBD | TBD | ≤500 ms p99 | TBD |
| Cold proxy overhead | TBD | TBD | TBD | ≤1 s p99 | TBD |
| Handshake success | TBD | TBD | TBD | ≥99.9% | TBD |
| Established stream resets/loss | TBD | TBD | TBD | no unexplained reset | TBD |
| Catalog read / mutation | TBD | TBD | TBD | ≤200 ms / ≤1 s p99 | TBD |
| Observation freshness | TBD | TBD | TBD | ≥95% within 2× interval | TBD |
| CPU | TBD | TBD | TBD | <70% | TBD |
| RAM / RSS slope | TBD | TBD | TBD | <70%; no positive leak | TBD |
| NIC throughput / packet rate | TBD | TBD | TBD | <70% | TBD |
| File descriptors / tasks | TBD | TBD | TBD | <70%; no positive leak | TBD |
| PostgreSQL connections/storage | TBD | TBD | TBD | <70%; no positive leak | TBD |
| Generator A/B headroom | TBD | TBD | TBD | both <70% | TBD |

Attach raw timestamped series, event/failure rows, run manifest, verifier report
and SHA-256 inventory. Report the highest passing node occupancy and server node
count separately. If the 100-camera run is deferred, state that limitation in
the decision and enforce a lower operational cap.
