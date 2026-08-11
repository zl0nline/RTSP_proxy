# Capacity worksheet

Every run records independent workload axes. Blank cells mean unknown, not zero.

## Manifest

| Field | Value |
|---|---|
| Release ID / git commit | TBD |
| MediaMTX version / binary SHA-256 | TBD |
| Architecture (`amd64` or `arm64`) | TBD |
| Linux distribution / kernel | TBD |
| CPU / RAM / NIC / storage | TBD |
| sysctl / ulimit / systemd limits | TBD |
| Generator hosts and headroom | TBD |
| Network topology / netem | TBD |
| Node count / node process map | TBD |
| Configured max_nodes / port range | TBD |

## Workload

| Axis | Value |
|---|---:|
| Registered/enabled paths per node | TBD |
| Active sources per node | TBD |
| Occupied readers per node | TBD |
| Node occupancy distribution | TBD |
| Bitrate / packet rate | TBD |
| Codec / audio / GOP | TBD |
| Connect/disconnect churn | TBD |
| CRUD / probes / metrics load | TBD |

## Results

| Resource or SLI | p50 | p95 | p99 / peak | Gate | Pass |
|---|---:|---:|---:|---:|---|
| Warm DESCRIBE→PLAY | TBD | TBD | TBD | ≤500ms p99 | TBD |
| Cold proxy overhead | TBD | TBD | TBD | ≤1s p99 | TBD |
| CPU | TBD | TBD | TBD | <70% | TBD |
| RAM | TBD | TBD | TBD | <70% | TBD |
| NIC / packet rate | TBD | TBD | TBD | <70% | TBD |
| File descriptors | TBD | TBD | TBD | <70% limit | TBD |
| Handshake success | TBD | TBD | TBD | ≥99.9% | TBD |

Publish raw series, failures and slopes with this summary. An average aggregate
cannot hide saturation of one workload axis.

Qualification is two-level: first one node at 1/10/50/80/100 registered
cameras, then one server at 1/5/10/25/50 nodes. Optional 100-node runs require
an explicit config/port-range change. The worksheet must report both aggregate
server usage and per-node process attribution. A configured node limit is not a
capacity result.
