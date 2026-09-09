# Risk register

Last reviewed: 2026-09-10. `Closed` means linked repeatable evidence exists;
site-specific risks remain open until the admission record contains that site's
result.

| ID | Risk | Status | Gate / mitigation | Owner |
|---|---|---|---|---|
| R1 | Throughput at 100 registered cameras on one node is unproven | Deferred/open | Owner explicitly deferred the physical test; enforce a lower measured operational cap | product/technical |
| R2 | Sustainable node count differs by server and workload | Site required | Independent server ladder and 24h soak; publish highest passing count | technical/operations |
| R3 | MediaMTX API/auth/restart/one-reader semantics drift | Closed for `v1.20.0-rtsp-proxy.3` | Native contracts and pinned digests; reopen on runtime/patch upgrade | media/security |
| R4 | Move or node-port change alters consumer endpoint | Accepted/design | Preview exact reader blast radius; distribute returned URL through the site client-config process | site owner |
| R5 | Kernel, NIC, camera, GOP or network drift invalidates capacity | Site required | Exact manifests/profiles and requalification after a material change | operations |
| R6 | ACL-before-password, direct peer IP and exact `453` regress | Closed for current runtime | Native auth/admission suites; reopen on MediaMTX or firewall change | security |
| R7 | A camera model's GOP/session capacity is unknown | Open per profile | Complete [`CAMERA_PROFILE.md`](CAMERA_PROFILE.md); unknown upstream capacity stays passive-only | site owner |
| R8 | Concurrent allocation strands ports or exceeds limits | Closed in software | Transactional advisory-lock allocator, lifecycle fences, crash/rollback and PostgreSQL race tests | control |
| R9 | One physical server is a shared failure domain | Accepted limitation | Remote monitoring, verified off-host backup and manual recovery; no failover claim | owner |
| R10 | Database backup exists but cannot be restored | Site required | Schema/release-bound custom archive plus isolated restore comparison each admission | data/operations |
| R11 | Local keyring/TLS/config loss makes recovery impossible | Site required | Root-owned control-assets archive, checksum and encrypted off-host copy with access drill | security/operations |
| R12 | SMTP relay rejects, delays or ambiguously accepts incidents | Site required | Real accepted/rejected/recovery drill; monitor durable terminal outcome and age | operations |
| R13 | Active source probing steals a single allowed camera session | Closed by policy | Missing/one-session profile is passive-only; SOURCE probe requires explicit capacity ≥2 | media/site owner |
| R14 | Production GO is inferred from CI or configured limits | Open governance | Admission uses [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md); named sign-off and evidence links | owner |

Closing or accepting a risk requires a linked immutable result, scope, owner and
date. Rewording, passing mocks, or lowering load is not closure.
