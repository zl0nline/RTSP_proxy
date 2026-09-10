# Production readiness

Last reviewed: 2026-09-11.

This is the single current admission record for the product. Historical CI and
pilot reports remain under [`evidence/`](evidence/); they do not override this
matrix. `PASS` means the repository contract is implemented and has repeatable
evidence. `SITE REQUIRED` means an operator must produce evidence on the exact
server, network, camera profile or relay being admitted. `DEFERRED` is an
explicit owner decision, not an implicit pass.

## Current candidate

| Item | Value |
|---|---|
| Application candidate | `0.17.6` |
| Git commit | `36c317ff4f1efbf8c360d4088fae13ffa0398231` |
| Database head | `0024_camera_probe_profiles` |
| Media runtime | `v1.20.0-rtsp-proxy.3` |
| Host compatibility contract | [`modern-systemd-linux-v1`](HOST_COMPATIBILITY.md), native amd64 or arm64 |
| Compatibility evidence | [0.17.6 CI and ARM hardware record](evidence/host-compatibility-0.17.6-arm64-2026-09-11.md) |
| Production pilot | [0.17.4 admission record](evidence/production-admission-2026-09-10.md); it is historical site evidence, not the current release |
| Product status | **Portable release-functional candidate; Production HOLD pending exact-site evidence** |

The candidate values above are updated only after a fully successful release CI
and immutable bundle verification. A later manifest is authoritative when this
file is being prepared as part of that same release change.

## Gate matrix

| Gate | Status | Required evidence / reason |
|---|---|---|
| Capability-based Linux detection, bootstrap and package adapters | PASS (contract and compatibility hardware); SITE REQUIRED admitted host | Native Ubuntu 24.04 amd64/arm64 CI, real package installs on five distro families and the [0.17.6 ARM hardware smoke](evidence/host-compatibility-0.17.6-arm64-2026-09-11.md); doctor plus native contracts must pass again on the exact production host |
| Node registry, placement, lifecycle and 100-camera hard admission limit | PASS | Unit, PostgreSQL race and native lifecycle suites; the hard limit is a safety constraint, not a throughput claim |
| Per-node process/config/port isolation | PASS | Native amd64/arm64 media, namespace and load/isolation CI |
| Ordinary RTSP/TCP, one-reader admission and exact `453` | PASS (contract); SITE REQUIRED per profile | Pinned MediaMTX native contracts; ordinary-reader smoke for every admitted camera profile |
| Camera CRUD, move, drain, forced operations and delete guards | PASS (contract and pilot); SITE REQUIRED admitted host | Automated transactional tests and the [0.17.4 pilot game day](evidence/production-admission-2026-09-10.md); repeat on the supported admitted host |
| ACL, downstream grants, local login, TOTP, RBAC and audit | PASS (contract and pilot) | Native/unit security suites plus audited pilot login, MFA step-up, grant use and final revocation |
| HTTPS management boundary and secret handling | PASS (contract); SITE REQUIRED certificate | Release verifier and deployment tests; CA-issued site certificate/SAN and secret inventory are local evidence |
| Placement and move targets with stale runtime state | PASS | Both paths observe and persist plausible candidate runtime state through the guarded write-side helper before applying freshness filters |
| Source credentials with reserved characters | PASS | Raw separate-field contract and exact encode-once regression; percent-looking operator input triggers an explicit raw-value warning and confirmation |
| On-demand ingest diagnosis | PASS | Idle, connecting, unavailable and ready are derived without opening an unsafe second upstream session; active probe reason remains independent |
| Isolated source probe worker/broker | PASS | Native amd64/arm64 broker, BPF, cancellation, policy and worker suites |
| Collector and node metrics | PASS | Read-only collector plus least-privilege process identity observation |
| Incident outbox/notifier semantics | PASS (contract); SITE REQUIRED relay | Deterministic accepted/rejected/ambiguous/recovery tests; a real configured SMTP relay drill is mandatory |
| Immutable install/update/health rollback | PASS (contract and historical pilot continuity); SITE REQUIRED admitted host | Exact `0.17.6` both-architecture release CI plus exact arm64 bundle verification; historical `0.17.4` pilot updates preserved every media PID and the established reader, but 0.17.6 has not replaced that pilot |
| PostgreSQL backup and isolated restore verification | PASS (tooling and pilot); SITE REQUIRED admitted host | Exact `0.17.4` archive restored all 32 tables and five invariants in 1.80 s; the site must retain its own checksum-bound report |
| Control assets/keyring backup and off-host copy | SITE REQUIRED | Root-owned archive, checksum, encrypted off-host copy and restore-access proof cannot be supplied by source CI |
| RPO/RTO recovery drill | SITE REQUIRED | Restore database and control assets within RPO ≤5 min / control RTO ≤30 min on site hardware |
| Control restart while media is established | PASS (pilot); SITE REQUIRED admitted host | Pilot web/auth/reconciler/collector restart preserved the media PID and reader; repeat on admitted hardware |
| Failure-domain/game-day matrix | SITE REQUIRED (partial pilot evidence) | Database, collector, probe, media, limits, port rollback, move and control-restart rows have pilot evidence; real relay, network/power and supported-host rows remain open |
| 24-hour production-equivalent soak | SITE REQUIRED | Exact hardware, network, camera profile, non-zero churn/probe/CRUD axes and ≥30% hard-resource headroom |
| Sustainable node count per server | SITE REQUIRED | Publish the highest passing independent server ladder; configured `max_nodes` is not evidence |
| 100 registered cameras on one node | **DEFERRED by owner** | Physical test explicitly excluded from this work; no production capacity claim may say it passed |
| Owner/security/operations sign-off | SITE REQUIRED | Named approval after all non-deferred rows pass and deferred scope is accepted |

## Honest admission decision

The software is packaged and installed as an exact, pilot-verified production
candidate, but the repository cannot grant Production GO to an arbitrary site.
Current decision is **HOLD** until that site's supported-host certificate,
backup/off-host recovery, real SMTP, remaining game-day rows, camera-profile
matrix, 24-hour soak and measured server envelope are attached to an admission
record. The explicitly deferred 100-camera test remains a disclosed capacity
restriction even after those rows pass.

A site may approve a narrower deployment only by recording all of the following:

1. the measured per-node camera/bitrate/GOP envelope below 100;
2. the measured sustainable node count for that exact server;
3. an operational cap at or below both measurements;
4. explicit acceptance that the product-wide 100-camera capacity claim remains
   unqualified;
5. named owner, security and operations signatures.

## Evidence procedure

Use [`../deploy/PRODUCTION_RUNBOOK.md`](../deploy/PRODUCTION_RUNBOOK.md) for the
ordered procedure. Copy this matrix into the private site admission directory,
replace every `SITE REQUIRED` row with a link to immutable evidence, and record
`PASS`, `HOLD` or `ROLLBACK`. Never place credentials, private source URLs,
TOTP secrets, database DSNs or SMTP passwords in repository evidence.

The reusable measurement schemas are:

- [`CAPACITY_WORKSHEET.md`](CAPACITY_WORKSHEET.md) for workload and hardware;
- [`CAMERA_PROFILE.md`](CAMERA_PROFILE.md) for each model/firmware combination;
- [`SLI_CATALOG.md`](SLI_CATALOG.md) for normative signals and targets;
- [`FAILURE_DOMAIN_MATRIX.md`](FAILURE_DOMAIN_MATRIX.md) for game days;
- [`RISK_REGISTER.md`](RISK_REGISTER.md) for residual acceptance.
