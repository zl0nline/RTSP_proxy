# Production readiness

Last reviewed: 2026-09-16.

This is the single current admission record for the product. Historical CI and
pilot reports remain under [`evidence/`](evidence/); they do not override this
matrix. `PASS` means the repository contract is implemented and has repeatable
evidence. `SITE REQUIRED` means an operator must produce evidence on the exact
server, network, camera profile or relay being admitted. `DEFERRED` is an
explicit owner decision, not an implicit pass.

## Current candidate

| Item | Value |
|---|---|
| Application candidate | `0.18.0` |
| Git commit | `20f79cdeceac8bec37b0196b121c15d88bd462d8` |
| Database head | `0026_probe_source_networks` |
| Media runtime | `v1.20.0-rtsp-proxy.4` |
| Host compatibility contract | [`modern-systemd-linux-v1`](HOST_COMPATIBILITY.md), native amd64 or arm64 |
| Release CI | [0.18.0 exact-commit run: all 14 jobs passed](https://github.com/zl0nline/RTSP_proxy/actions/runs/35067011035) |
| Compatibility evidence | [0.17.6 ARM hardware record](evidence/host-compatibility-0.17.6-arm64-2026-09-11.md); retained as historical hardware evidence |
| Production pilot | [0.18.0 update record](evidence/pilot-update-0.18.0-2026-09-16.md); bridge/migration, explicit MediaMTX transition and operator-workflow evidence on an unadmitted host |
| Product status | **Portable release-functional candidate; Production HOLD pending exact-site evidence** |

The candidate values above are updated only after a fully successful release CI
and immutable bundle verification. A later manifest is authoritative when this
file is being prepared as part of that same release change.

## Gate matrix

| Gate | Status | Required evidence / reason |
|---|---|---|
| Capability-based Linux detection, bootstrap and package adapters | PASS (contract and compatibility hardware); SITE REQUIRED admitted host | Exact 0.18.0 native Ubuntu 24.04 amd64/arm64 CI, real package installs on five distro families over HTTPS (including a full supported Arch sync-upgrade) and the [0.17.6 ARM hardware smoke](evidence/host-compatibility-0.17.6-arm64-2026-09-11.md); doctor plus native contracts must pass again on the exact production host |
| Node registry, placement, lifecycle and 100-camera hard admission limit | PASS | Unit, PostgreSQL race and native lifecycle suites; the hard limit is a safety constraint, not a throughput claim |
| Per-node process/config/port isolation | PASS | Native amd64/arm64 media, namespace and load/isolation CI |
| Ordinary RTSP/TCP, one-reader admission, exact `453` and upstream-unavailable `503` | PASS (contract); SITE REQUIRED per profile/failure path | Pinned MediaMTX native contracts on both architectures; the pilot passed ordinary DESCRIBE for both currently operational cameras, but did not reproduce an unavailable source |
| Camera CRUD, move, drain, forced operations and delete guards | PASS (contract and pilot); SITE REQUIRED admitted host | Automated transactional tests and the [0.17.4 pilot game day](evidence/production-admission-2026-09-10.md); repeat on the supported admitted host |
| ACL, downstream grants, local login, TOTP, RBAC and audit | PASS (contract and pilot) | Native/unit security suites plus audited pilot login, 30-minute recent-MFA projection, grant use/revocation and purge; 0.18.0 preserves replay-safe inline local TOTP refresh, keeps temporary secrets time-bounded and emits one audit event per purged inactive grant |
| Albedo dashboard shell, responsive forms and camera tabs | PASS (contract and pilot) | Exact-commit browser E2E plus authenticated pilot smoke; live node/readers projection, source-auth/network controls and recent-MFA status were exercised after the 0.18.0 update |
| HTTPS management boundary and secret handling | PASS (contract); SITE REQUIRED certificate | Release verifier and deployment tests; CA-issued site certificate/SAN and secret inventory are local evidence |
| Placement and move targets with stale runtime state | PASS | Both paths observe and persist plausible candidate runtime state through the guarded write-side helper before applying freshness filters |
| Source credentials with reserved characters | PASS | Raw separate-field contract and exact encode-once regression; detail view exposes only sanitized host/port/path and a credential-presence flag, while username, password, query and fragment remain secret |
| On-demand ingest diagnosis | PASS | Idle, connecting, unavailable and ready are derived without opening an unsafe second upstream session; active probe reason remains independent |
| Isolated source probe worker/broker | PASS | Native amd64/arm64 broker, BPF, cancellation, audited dynamic `/32`/`/24` policy, static-envelope and worker suites |
| Collector and node metrics | PASS (contract and pilot) | Read-only collector plus least-privilege process identity observation; node detail now consumes the bounded live snapshot and the pilot projected health, runtime, bitrate and downstream readers through the MediaMTX transition |
| Incident outbox/notifier semantics | PASS (contract); SITE REQUIRED relay | Deterministic accepted/rejected/ambiguous/recovery tests; a real configured SMTP relay drill is mandatory |
| Immutable install/update/health rollback | PASS (contract and pilot continuity); SITE REQUIRED admitted host | Exact `0.18.0` both-architecture release CI and the [0.18.0 pilot update](evidence/pilot-update-0.18.0-2026-09-16.md) prove that control-plane activation preserves media, while a separate zero-reader drain/preview/confirmation moves only the selected node from verified `0.2.1` to `0.2.2` |
| PostgreSQL backup and isolated restore verification | PASS (tooling and pilot); SITE REQUIRED admitted host | The 0.18.0 pre-0026 archive passed checksum and restore-list verification; the exact historical `0.17.4` archive restored all 32 tables and five invariants in 1.80 s; the site must retain its own checksum-bound report |
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
