# Capacity worksheet

Every run records independent workload axes. Blank cells mean unknown, not zero.

## Manifest

| Field | Value |
|---|---|
| Release ID / git commit | TBD |
| MediaMTX version / binary SHA-256 | TBD |
| Linux distribution / kernel | TBD |
| CPU / RAM / NIC / storage | TBD |
| sysctl / ulimit / systemd limits | TBD |
| Generator hosts and headroom | TBD |
| Network topology / netem | TBD |

## Workload

| Axis | Value |
|---|---:|
| Registered/enabled paths | TBD |
| Active sources | TBD |
| Total readers | TBD |
| Readers/source and skew | TBD |
| Bitrate / packet rate | TBD |
| Codec / audio / GOP | TBD |
| Connect/disconnect churn | TBD |
| CRUD / probes / metrics load | TBD |

## Results

| Resource or SLI | p50 | p95 | p99 / peak | Gate | Pass |
|---|---:|---:|---:|---:|---|
| Warm DESCRIBE→PLAY | TBD | TBD | TBD | ≤500ms p99 | TBD |
| Cold proxy overhead | TBD | TBD | TBD | ≤1s p99 | TBD |
| CPU | TBD | TBD | TBD | ≤65% Spike #0 | TBD |
| RAM | TBD | TBD | TBD | <70% | TBD |
| NIC / packet rate | TBD | TBD | TBD | ≤60% Spike #0 | TBD |
| File descriptors | TBD | TBD | TBD | <70% limit | TBD |
| Handshake success | TBD | TBD | TBD | ≥99.9% | TBD |

Publish raw series, failures and slopes with this summary. An average aggregate
cannot hide saturation of one workload axis.
