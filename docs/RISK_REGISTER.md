# Risk register

| ID | Risk | Current status | Gate / mitigation | Owner |
|---|---|---|---|---|
| R1 | Per-node 100-camera capacity is unproven | Open | per-node matrix and 24h soak | technical |
| R2 | Sustainable media-node count per server is unknown | Open | 1/5/10/25/50 node ladder; optional 100 | technical |
| R3 | MediaMTX API/auth/restart semantics are unproven | Closed for pinned v1.20.0-rtsp-proxy.3 | [Phase 0 contract](evidence/phase0-mediamtx-v1.20.0-contract.md), [node administration contract](evidence/phase-d-node-administration-contract.md), and [0.13.10 native startup evidence](evidence/release-0.13.10-node-startup-contract.md); reopen on MediaMTX upgrade | media/security |
| R4 | Camera move/port change changes consumer URL | Open | blast-radius confirmation and managed client config channel | migration |
| R5 | Production network/kernel/camera drift changes capacity | Open | production-like manifest and soak | operations |
| R6 | ACL-before-password, direct peer IP and exact RTSP 453 are unproven | Open | per-node auth/admission native tests | security |
| R7 | Camera GOP/session limits are unknown | Open per profile | measured camera profile before admission | site owner |
| R8 | Port/max_nodes races can over-allocate or strand listeners | Open | transactional allocator + crash/rollback tests | control/operations |
| R9 | One physical server remains a shared failure domain | Accepted limitation | remote monitoring, backup and manual recovery; no failover claim | owner |

Closing a risk requires linked evidence or an accepted ADR. Rewording a risk is
not closure.
