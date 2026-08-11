# Production-план RTSP Proxy

> Актуализировано 10 августа 2026 года по текущим телам и обсуждениям
> [issues #1–#14](https://github.com/zl0nline/RTSP_proxy/issues).
>
> **PLANNING CONSENSUS: COMPLETE · SPEC CORRECTIONS: COMPLETE · PHASE 0:
> IN PROGRESS · FOUNDATION: IN PROGRESS · PRODUCTION: NO-GO · 10K: NOT CLAIMED**

Этот документ — единая исполнимая спецификация проекта. Он описывает, что
следует построить, в каком порядке принимать решения и какими артефактами
доказывается готовность каждого этапа. Он не утверждает, что система уже
реализована, готова к production или выдерживает 10 000 одновременно активных
потоков.

Consensus означает, что согласованы инварианты, порядок экспериментов и
acceptance criteria. Владелец разрешил Phase 0 и foundation implementation 10
августа 2026. Product behavior, зависящий от неподтверждённых fork decisions,
pilot и каждая следующая migration wave требуют прохождения своих gates и
отдельного решения владельца проекта.

## 1. Иерархия решений

Приоритет источников:

1. Принятый ADR с приложенными evidence-артефактами.
2. Этот production-план.
3. Актуальные тела issues #1–#14.
4. Исторические consensus/review comments.

Если эксперимент опровергает planning-гипотезу, реализация не подгоняет
результат под план. Создаётся versioned ADR, обновляются SLO/capacity
assumptions, затронутые issues, этот документ и README. Молчаливое ослабление
threshold или смена topology запрещены.

Численные значения разделяются на:

- **SLO** — пользовательский или эксплуатационный контракт;
- **evidence gate** — порог допуска результата;
- **spike budget** — критерий сравнения вариантов, не production-обещание;
- **capacity envelope** — измеренная комбинация workload и инфраструктуры.

## 2. Цель продукта

Система заменяет отдельные внешние RTSP-порты камер одним настраиваемым
endpoint, по умолчанию `:9999`.

Внешний адрес:

```text
rtsp://<external-user>:<external-password>@<host>:9999/<public_id>
```

Это стандартный RTSP URL. Consumer выполняет обычный DESCRIBE/SETUP/PLAY и не
получает proxy-specific scheme, redirect, header или setup step. External grant
скрывает source credentials камеры. Для недоверенной сети confidentiality
обеспечивается внешним VPN/private L3 transport, который не меняет `rtsp://`
URL или handshake.

Целевой результат:

- внешний FFmpeg consumer не получает IP и source credentials камеры;
- оператор управляет каталогом, группами, grants и диагностикой через HTTPS
  dashboard без ручной правки БД или MediaMTX config;
- изменение одной камеры не перезапускает media node и не влияет на другие
  paths;
- PostgreSQL хранит desired state, MediaMTX обслуживает медиапоток;
- capacity, security, availability, restore и rollback доказываются тестами;
- миграция со старых port-forward URL идёт волнами с явным go/no-go.

`10k` всегда раскладывается на независимые workload axes:

- registered и enabled paths;
- одновременно active sources;
- readers per source и fan-out skew;
- bitrate, codec, audio, GOP и packet rate;
- session duration, connect/disconnect churn и reconnect storms;
- CRUD, reconcile, probes, TSDB и dashboard load.

`10k registered` не означает `10k active`. Поддерживаемой считается только
комбинация осей, опубликованная вместе с hardware/network manifest и raw
результатами испытаний.

## 3. Scope и non-goals

В scope:

- Python 3.12, FastAPI, Jinja2/HTMX и PostgreSQL для control plane;
- pinned MediaMTX version и binary SHA-256 для media plane;
- on-demand pull источников;
- RTSP-over-TCP interleaved снаружи и до камеры;
- FFmpeg + supervisor как эталонный внешний consumer;
- каталог, camera profiles, groups, RBAC, grants, audit и probes;
- observability, load/chaos, deployment, restore, drain и rollback;
- single-node baseline и доказуемый путь к scale-out;
- controlled migration со старой системы.
- direct Linux deployment на amd64 и arm64 с одинаковыми SLO/security/release
  gates и нативными tests для каждой архитектуры.

Не входят:

- NVR, запись и архив видео;
- transcoding и изменение media profile;
- HLS, WebRTC, playback или publish как внешний production contract;
- UDP/multicast RTP;
- публичный интеграционный API;
- собственный RTSP router до провала готовых вариантов;
- сохранение живого TCP-сеанса при потере media node;
- автоматическое добавление инфраструктуры без измеренной причины.

## 4. Статусы и decision rights

| Уровень | Статус | Условие перехода |
|---|---|---|
| Planning consensus | COMPLETE | Issues согласованы, corrections внесены |
| Phase 0 | IN PROGRESS | Owner authorization получено 2026-08-10 |
| Phase 0A compatibility | COMPLETE | Standards/Spec PASS; native amd64/arm64 contract CI |
| Phase 0B harness / Spike #0 | IN PROGRESS | Functional harness review/CI passed; dedicated hardware evidence absent |
| Scale-out topology | EVIDENCE BLOCKED | Провален single-node gate и пройден topology spike #10 |
| Foundation implementation | REVIEWED | Health/release/package/Linux artifacts прошли exit review |
| Product behavior | EVIDENCE GATED | Зелёные обязательные Phase 0 fork decisions |
| Production pilot | NO-GO | Зелёные artifacts #1–#12 и owner sign-off |
| Scale after pilot 100 | NO-GO | 7-day exit gate #13 и опубликованный envelope |
| 10k claim | NOT CLAIMED | Production-like evidence конкретного workload |

Права решения:

- project owner разрешает phase, pilot и следующую wave;
- technical owner останавливает rollout при SLO/integrity/capacity breach;
- security owner останавливает при auth, secret, audit или network-boundary breach;
- operations owner принимает restore, drain, rollback и runbook evidence;
- on-call вправе объявить `STOP`; возобновление требует нового owner `GO`.

## 5. Архитектурные инварианты

1. Один внешний configurable RTSP endpoint, default port `9999`.
2. **RTSP-over-TCP interleaved — единственный поддерживаемый transport** снаружи
   и до источника. UDP/multicast выключены. `sockets_per_session = 1`. Изменение
   транспорта требует отдельного ADR и пересчёта capacity. Внешняя схема всегда
   обычная `rtsp://`; consumer не должен отличать proxy endpoint от прямой
   RTSP-камеры.
3. Python не находится в media datapath и не proxy/remux/transcode video.
4. MediaMTX запускается только из release artifact с pinned version/SHA-256 и
   compatibility manifest.
5. PostgreSQL — единственный source of truth desired state. JSON/CSV используются
   только для import/export.
6. API подтверждает `desired accepted`, а не ложно обещает `applied`.
7. Desired revision, outbox и нормативный audit фиксируются одной synchronous
   quorum transaction. Async commit разрешён только probes и ненормативной
   derived telemetry, не `audit_events`.
8. Reconciler идемпотентно сводит desired и actual state; exactly-once не
   обещается.
9. Штатный CRUD одной камеры не вызывает restart/reload MediaMTX и не меняет
   TCP/bytes/PTS других paths.
10. Established media sessions не требуют synchronous request-time доступа к
    DB/control plane. New sessions при auth outage следуют явной fail-closed/cache
    policy.
11. `public_id` не credential. Это 25 равномерных lowercase base36 characters,
    regex `^[a-z0-9]{25}$`, пространство ≈129.25 bit; имя не переиспользуется.
12. L4 frontend не path-aware. Схема `L4 → assigned origin shard` отвергнута.
13. Single-node first: scale-out появляется только после измеренного провала или
    capacity forecast и отдельного spike.
14. Security, audit, observability, restore, rollback и capacity — release
    gates, а не post-launch work.
15. Неизвестные возможности MediaMTX подтверждаются executable tests конкретных
    version и binary SHA-256.
16. Cold start = `proxy_overhead + wait_for_keyframe(GOP)`. SLO предъявляется к
    нашей части; GOP фиксируется в camera profile.
17. Linux amd64 и arm64 — равноправные production targets. Release manifest,
    native binary checksum, compatibility suite, clean-host smoke, load envelope
    и rollback evidence формируются отдельно для каждой архитектуры; evidence
    одной архитектуры не переносится на другую.

## 6. Логическая архитектура

### 6.1 Single-node baseline

```text
Operator browser
      |
      v
HTTPS Dashboard/API -----------------------> PostgreSQL
      |                                      desired state
      |                                      audit/outbox/jobs
      v                                             |
web / worker / reconciler / probe scheduler <-------+
      |                         |
      |                         +--> sandboxed ffprobe --> cameras
      v
MediaMTX management boundary
      ^
      |
External FFmpeg + supervisor --> RTSP/TCP :9999 --> MediaMTX --> cameras
                                                        |
                                                        +--> metrics/events
                                                               |
                                                               v
                                                        collector / TSDB
```

Runtime roles:

- `web` — dashboard/API, browser sessions и authorization;
- `worker` — outbox/jobs и фоновые commands;
- `reconciler` — desired/actual convergence;
- `probe` — bounded source/path checks;
- `collector` — media/host signals и TSDB ingestion.

### 6.2 Conditional multi-node candidate

Topology не выбрана заранее. Первый candidate после провала single-node:

```text
External FFmpeg
      |
      v
L4 TCP frontend :9999
      |
      +------> any replicated gateway -------+
      |                                      |
      +------> any replicated gateway        v
                                         assigned origin shard --> camera
```

Здесь два независимых уровня:

- **external routing:** L4 выбирает любой healthy gateway и не читает RTSP path;
- **origin ownership:** БД определяет origin, владеющий source pull.

Gateway имеет proxy path для любого внешнего `public_id`; camera credentials не
покидают origin. Если gateway tier не проходит SLO/security/capacity, проверяется
готовый RTSP-aware L7. Самописный router — последний резерв.

## 7. Camera contract

Параметры источника — отдельный versioned артефакт `docs/CAMERA_PROFILE.md` и
таблица профилей в БД. Шаблон создаётся в Phase 0; реальные profiles обязательны
для pilot и полностью заполнены до pilot 100.

| Поле | Назначение |
|---|---|
| model / firmware | воспроизводимость и support matrix |
| main/sub normalized paths | uniqueness и probe templates |
| codec/audio | compatibility matrix |
| bitrate / packet rate | per-hop capacity |
| GOP / keyframe interval | cold-start decomposition и load profile |
| `max_concurrent_rtsp_sessions` | probes, overlap и migration cutover |
| RTSP-over-TCP support | production admission |
| timeout/keepalive limits | end-to-end timeout budget |

Preflight проверяет профиль на текущей camera load. Неизвестный GOP или session
limit не заменяется удобной synthetic constant: camera/cohort блокируется либо
получает явно принятый risk.

## 8. SLI, SLO и numerical gates

### 8.1 Normative initial SLO

| SLI | Initial SLO |
|---|---:|
| Warm `DESCRIBE → PLAY`, p99 | `≤ 500 ms` |
| Cold on-demand `proxy_overhead`, p99 | `≤ 1 s` |
| Cold end-to-end, informative | `≤ 1 s + GOP_max` profile |
| Catalog read, p99 | `≤ 200 ms` |
| CRUD mutation, p99 | `≤ 1 s` |
| `deep_observation_freshness` | `≥95%` routine-enabled не старше `2 × configured_interval` |
| `manual_confirmation_start` | `≥99%` внутри queue-delay SLO |
| Control-plane availability | `≥99.5% / month`, planned maintenance excluded |
| Established media-session availability | `≥99.0% / month` |

Безусловный `cold ≤3s` отменён: он зависит от GOP. Performance suite отдельно
публикует `proxy_overhead`, wait-for-keyframe и end-to-end latency минимум для
typical и worst-known GOP.

Measurement rules:

- warm/cold и p50/p95/p99 публикуются раздельно, pass/fail использует p99;
- latency измеряет внешний FFmpeg consumer на production-like network;
- failures входят в success-rate SLI и не исчезают из latency report;
- platform/network failure отделяется от camera-origin failure;
- health freshness считается отдельно по site/subnet;
- scheduler overload меняет `observation_state`, а не camera health.

### 8.2 Operational gates

| Contract | Gate |
|---|---:|
| Dashboard authz downgrade/revoke | `≤2s`, fail closed |
| Dashboard authz upgrade | `≤30s` |
| Media-grant revoke for new sessions | candidate `≤10s`; positive cache `≤5s` |
| FFmpeg supervisor recovery | p95 `≤10s`, max `≤35s` |
| Steady successful handshakes | `≥99.9%` outside injected failures |
| Control/data impact on media | throughput `≤5%`, latency `≤10%`, errors `≤0.1pp` |
| PostgreSQL backup/PITR | RPO `≤5m`, control-plane RTO `≤30m` |
| Critical desired+audit HA failover | RPO `0` only with proven synchronous quorum |
| Global resource envelope | each hard resource `<70%`, headroom `≥30%` |
| Restore drill / critical game day | monthly / quarterly |

Spike #0 additionally uses stricter ceilings where applicable: CPU `≤65%`,
NIC/packet-rate `≤60%`, FD `<70%`, RAM `<70%`. Ослабление — только ADR с
evidence.

## 9. Foundation и immutable deployment

### 9.1 Linux release и supply chain

- Docker/containers не используются; target — direct Linux deployment;
- target architectures — amd64 и arm64; CI запускает application и pinned
  MediaMTX contract нативно на обеих архитектурах без эмуляции;
- release manifest фиксирует application wheel/lock hash, MediaMTX binary
  version/SHA-256, FFmpeg/ffprobe versions, schema/config compatibility;
- CI проверяет checksums, provenance/signature где доступна, SBOM, dependencies,
  wheel/sdist, lockfile и clean Linux install;
- production release размещается root-owned в
  `/opt/rtsp-proxy/releases/<version>` и не изменяется service users;
- `/opt/rtsp-proxy/current` переключается atomic symlink; предыдущий release
  сохраняется для rollback;
- runtime host не требует compiler/dev tools/hot reload;
- startup smoke выполняется против реально запущенных binaries.

### 9.2 MediaMTX contract levels

1. **Build/deploy:** binary/wheel checksums и release manifest immutable.
2. **Startup:** executable API/auth/metrics/RTSP compatibility probe.
3. **Runtime:** readiness читает minimal effective contract конкретного node.

Readiness проверяет effective config через API:

- TCP-only transport;
- API/metrics не слушают внешний interface;
- HLS/WebRTC/playback/record и ненужные listeners выключены;
- reported version и SHA-256 установленного binary соответствуют manifest.

### 9.3 Linux process layout

- `uv sync --locked` используется в development; production устанавливает
  проверенный wheel/venv из lockfile в versioned release directory;
- web, worker, reconciler, probe, collector и MediaMTX — отдельные `systemd`
  services под dedicated non-login users;
- units фиксируют config/environment files, working directory, restart policy,
  timeouts, `LimitNOFILE`, memory/CPU limits и dependencies;
- hardening baseline: `NoNewPrivileges=yes`, `ProtectSystem=strict`,
  `ProtectHome=yes`, `PrivateTmp=yes`, `RestrictSUIDSGID=yes`, empty capability
  set by default и allowlisted `ReadWritePaths`;
- config/secrets root-managed; service получает только минимальный read access;
- startup/readiness и journal logging не зависят от container runtime.

### 9.4 Config classes

| Класс | Примеры | Изменение |
|---|---|---|
| `runtime` | paths, credentials, per-camera settings | API/hot-update без разрыва unrelated sessions |
| `restart-node` | RTSP listen address/port, transports | drain, maintenance, restart, smoke |
| `restart-control-plane` | pool size, tracing, sessions | rolling control-plane update |

Смена `RTSP_PORT` — не CRUD. Она обрывает sessions узла и выполняется только по
runbook #12.

### 9.5 PostgreSQL connection budget

```text
sum(replicas_by_role * (pool_size + max_overflow))
    <= 0.70 * PostgreSQL max_connections
```

Не менее 30% остаётся migrations/ops/failover/emergency. Initial upper bounds:
web `10+10`, worker `5+5`, reconciler `2+2`, collector `2+2`. Advisory-lock
reconciler использует отдельный direct/session-pooled DSN; statement pooling
запрещён.

Обязательны bounded pool timeout, recycle/pre-ping, idle transaction timeout,
role-specific statement timeout и pool metrics.

### 9.6 Health и migrations

- `/health/live` проверяет process/event loop; dependency failure не создаёт
  restart loop;
- `/health/ready` role-specific, со stable reason code без secrets;
- schema ahead/behind делает incompatible binary not ready;
- Alembic revisions immutable, single head;
- migration — отдельный singleton job с advisory lock;
- `expand → bounded backfill → switch → contract`, N/N-1 compatibility;
- production rollback не использует destructive down migration: compatible
  image, pause/resume backfill или forward-fix.

## 10. PostgreSQL data contract

### 10.1 Identifiers и endpoint

- `camera_id`: UUID v7/v4, internal PK;
- `public_id`: exactly 25 uniform lowercase base36 characters, CSPRNG rejection
  sampling without modulo bias, regex `^[a-z0-9]{25}$`, ≥128-bit space;
- `grant_id`: separate non-secret grant identifier;
- canonical endpoint fingerprint используется для duplicate warning;
- partial unique `(host, port, normalized_path)` только для non-deleted rows;
- collision с soft-deleted camera предлагает restore;
- `camera_public_ids` — единое namespace active/alias/revoked/tombstoned names.

Rotation:

```text
create new id -> reconcile/auth ready -> atomic switch
              -> revoke old -> drain/terminate -> permanent tombstone
```

Unknown, revoked и unauthorized existing paths проходят no-oracle parity по
status, headers, body и timing.

### 10.2 Lifecycle

- lifecycle: `PROVISIONING | ACTIVE | DELETE_PENDING | DELETED | PURGED`;
- admin mode: `ENABLED | MAINTENANCE | DISABLED`;
- soft delete в одной transaction ставит `DELETE_PENDING/DISABLED`, отзывает
  grants и создаёт audit/outbox;
- restore до purge создаёт новую desired revision и не реактивирует secrets или
  grants неявно.

### 10.3 Entities

`cameras`, `camera_sources`, `camera_public_ids`, `camera_secret_versions`,
`camera_groups`, `camera_group_memberships`, `access_grants`, `media_nodes`,
`camera_placements`, `reconcile_outbox`, `camera_health_current`,
`probe_results`, `audit_events` и versioned camera profiles.

Raw source URL с userinfo не хранится. Source secrets, access verifiers и
ordinary metadata физически разделены.

### 10.4 Transactions и durability

- optimistic revision/row lock исключает lost update;
- desired revision, required `audit_event` и outbox atomic and synchronous;
- destructive/security/sensitive read operation fail-closed без durable audit;
- `synchronous_commit=off` разрешён только `probe_results` и отдельной
  non-normative telemetry;
- applied revision хранится по `camera × target/placement_generation`;
- API ack при HA policy следует только после quorum acknowledgement;
- backup/PITR RPO≤5m не подменяет HA-failover RPO0.

### 10.5 Ordering, queries и churn

- probe ordering: `(camera_id, source_revision, probe_generation)`;
- timestamps — observability, не ordering key;
- `camera_health_current` принимает только newer generation;
- list/search use keyset/cursor pagination;
- query shapes утверждаются до indexes и проверяются `EXPLAIN (ANALYZE,
  BUFFERS)` на production-like data;
- outbox/health current получают measured fillfactor и aggressive per-table
  autovacuum;
- bloat и p99 enqueue/dequeue проверяются 24h soak;
- partitioning вводится по rows/day, bytes/day, WAL, autovacuum и restore time.

### 10.6 Retention

| Data | Retention |
|---|---:|
| Audit hot searchable | 12 months |
| Audit WORM/archive | 3 years; legal hold overrides |
| Probe raw | 30 days |
| Probe aggregates | 12 months |
| Metrics high-resolution | 30 days |
| Metrics downsampled | 13 months |

## 11. Dashboard, RBAC и browser boundary

Dashboard показывает catalog, groups, desired/applied state, health freshness,
readers/bitrate, errors и audit, но не декодирует media.

### 11.1 Authorization

- roles admin/operator, least privilege;
- monotonic `authz_version` per user/session;
- downgrade/revoke `≤2s` fail-closed, upgrade `≤30s`;
- one no-oracle policy for list/count/search/direct/export/SSE;
- SSE uses authz/resource epochs and pre-delivery checks;
- break-glass requires MFA, alert, runbook and drill;
- changed IdP claims do not auto-upgrade active session.

### 11.2 CRUD, conflicts и bulk

UI различает:

1. desired changed by another actor — conflict/merge;
2. own desired accepted, applied behind — wait for reconcile;
3. apply failed — diagnostic error and retry.

Merge semantics фиксируются ADR/executable matrix. Placement, credentials,
`public_id` rotation, lifecycle/admin mode не auto-merge.

Bulk разрешён только closed enum. Каждая operation определяет required role,
atomic/best-effort semantics, per-object result и terminal-subset retry. Всё вне
allowlist deny by default.

### 11.3 Secrets и audit

- URL по default копируется без userinfo;
- secret reveal — standalone privileged single-use `no-store` surface, auto-clear
  30s, no Service Worker, `Referrer-Policy: no-referrer`;
- clipboard является secret-storage boundary: long-lived secret запрещён;
- reveal/export/sensitive read audited;
- application role has INSERT-only access to append-only audit;
- critical events replicated to WORM sink;
- destructive action fail-closed if required audit cannot commit.

Hostile browser extension или compromised client host остаётся за documented
trust boundary.

## 12. Reconciler и MediaMTX hot-update

### 12.1 Delivery

```text
API transaction:
optimistic lock -> desired revision -> audit -> outbox -> synchronous commit

Reconciler:
claim -> lock/fence -> read actual -> minimal diff -> apply -> verify
      -> commit applied
```

- claim через `FOR UPDATE SKIP LOCKED`, lease, per-camera serialization;
- до proven MediaMTX CAS — one writer per node via PostgreSQL session advisory
  lock;
- lost DB connection cancels in-flight apply;
- new writer acquires lock and reads inventory first;
- exactly-once not promised; bounded inconsistency + forward repair.

### 12.2 Apply loop

1. Validate pinned API contract before write.
2. Read configured state and compute minimal diff.
3. Apply convergent/idempotent single-path operation.
4. Synchronously verify **configured state** — determines job success.
5. Asynchronously verify **runtime state**; no active source is normal for
   on-demand path.
6. Commit applied revision only if desired/fencing still current.
7. Resolve timeout/unknown outcome through read-back and forward reconcile.

Fast revisions coalesce only within one placement generation. Placement change:

```text
PREPARE_NEW -> SWITCH -> DRAIN_OLD -> DELETE_OLD -> COMPLETE
```

If switch cannot be proven, migration is disruptive and requires maintenance.

### 12.3 Delete и restart recovery

- `IMMEDIATE`: stop new sessions, revoke, delete; active may break;
- `GRACEFUL(deadline)`: stop new, wait readers/deadline, then delete or
  disabled+blocked;
- actual RTSP codes/session fate come from pinned spike.

Path persistence after MediaMTX restart is a required contract test. If API
changes are not persistent, node cannot become ready before minimum inventory is
restored, or exposes only explicitly defined degraded admission. Blind 10k
rewrite and thundering herd are prohibited.

## 13. Health plane

Signals:

- Level 1 — MediaMTX API/metrics: cheap operational state;
- Level 2 — bounded ffprobe: deep verification.

| Probe | Target | Constraint |
|---|---|---|
| `source_probe` | camera directly | CIDR/egress allowlist and camera session budget |
| `path_probe` | external proxy path | sampling only; starts on-demand pull |

`path_probe` never runs across all 10k and respects source-on-demand close timer.
`source_probe` cannot consume the final session slot of an active camera.

Independent states:

- health: `UNKNOWN | HEALTHY | SUSPECT | UNHEALTHY | RECOVERING`;
- observation: `FRESH | STALE | OVERDUE`;
- admin: `ENABLED | MAINTENANCE | DISABLED`.

Every enabled camera gets a max deep-observation interval. Risk sampling adds
frequency for new/recovered/suspect and random control group, not replaces the
guarantee. Scheduler uses bounded concurrency, single-flight, jitter, reserved
capacity, deadline aging, per-site/subnet limits and adaptive backoff.

ffprobe:

- pinned version, subprocess without shell;
- exact timeout option and microsecond unit covered by unit test;
- network timeout and hard process kill tested separately;
- CPU/RAM/process/time/stderr limits and process-group cleanup;
- canonical parse, IDNA, all A/AAAA and IPv4-mapped IPv6 validation;
- approved literal `IP:port` + immutable endpoint generation;
- redirects/re-resolve prohibited;
- egress only to approved target;
- no credentials in logs/errors/artifacts.

## 14. FFmpeg + supervisor contract

Compatibility matrix includes production-pinned FFmpeg and previous supported
line, exact build flags and recommended command.

Coverage: H264/H265, audio/no-audio, OMNY fixtures, DNS/IPv4/bracketed IPv6,
non-default port, RTSP handshake/TEARDOWN, multiple readers, abort/timeouts,
source recovery, path update/delete, credential rotation/revoke and on-demand
races.

Supervisor:

- EOF/timeout/transport failure starts a new full handshake;
- exponential full-jitter backoff `1s → 30s`, reset after `60s` stable;
- max one active and one terminating process per stream;
- permanent auth/path failures never tight-loop;
- recovery p95 `≤10s`, max `≤35s` from source/server ready to first packet.

Keepalive, FFmpeg connect/read timeouts, L4/NAT idle timeout and `SETUP→PLAY`
deadline form one versioned budget. Server does not promise old TCP resume.

URL uses structured encoder. Since some builds expose URL in argv, compatibility
test reads cmdline/environ. Production compensation: separate service account/PID
namespace, least-scope grants, redaction and rotation.

TCP-only is active-tested: UDP `SETUP` denied; media process opens no RTP/RTCP
UDP sockets during TCP session.

## 15. Security contract

### 15.1 Access grants и auth fork

Source credentials and external grants are separate. Grant token is CSPRNG,
URL-safe and ≥128 bit. Default scope is read one `public_id`; group scope opt-in.
Publish/management deny by default.

Phase 0 spike selects one proven pinned MediaMTX model:

- external auth callback; or
- static/runtime user configuration.

Before the spike there is no promise of selective terminate, external-auth
availability or exact rotation behavior.

Revoke-new candidate `≤10s`; positive cache TTL `≤5s`. Push invalidation is an
optimization; bounded TTL provides correctness. During auth outage new sessions
fail closed. Established continue only if pinned contract proves setup-only auth.
Callback model requires at least two auth instances, internal LB and mTLS.

### 15.2 Secrets и keys

- source secrets: per-record DEK, KEK in KMS/Vault outside PostgreSQL;
- access token stored as verifier + `pepper_key_id`, raw shown once;
- pepper rotation: active + verify-only previous key;
- KEK/DEK rotation: resumable bounded batches with progress metric;
- old key removed only after 100% re-encryption and backup recovery window;
- crypto-erasure restore marks `UNRECOVERABLE/REISSUE_REQUIRED`.

### 15.3 Transparent RTSP, network boundary и abuse protection

- management API/metrics never public;
- camera egress limited to approved CIDR/destination;
- edge/pre-auth/auth/post-auth/media limits are separate;
- unknown path/user/wrong password have no-oracle parity;
- Slowloris controls accept, headers, auth and `SETUP→PLAY` deadlines;
- external media contract is ordinary `rtsp://` over TCP interleaved; consumer
  must not receive proxy-specific protocol behavior;
- RTSPS/TLS listener is outside scope;
- untrusted WAN/Internet path requires WireGuard/IPsec/managed VPN or private L3
  transport outside RTSP; without it deployment is NO-GO or needs explicit owner
  risk acceptance;
- L4/VPN boundary preserves source IP directly or through proven PROXY protocol;
  otherwise rate-limit/audit impact is an explicit blocker/trade-off.

MediaMTX logs are inside secret-scan perimeter.

## 16. Observability contract

### 16.1 Signal inventory и budgets

Versioned catalog defines `signal → source → exact schema → labels/cardinality →
interval → reset/staleness → recording rule → consumer`.

| Budget | Initial value |
|---|---:|
| Active series at 10k registered | `≤100k` |
| Series per enabled camera | `≤6` |
| Overview queries/refresh | `≤20` |
| Camera view | `≤10` + one bounded SSE |
| Interactive query p95 | `≤2s` |
| Recording rule evaluation | `<50%` interval |

Credential, URL, IP, raw error and trace ID are forbidden metric labels.

Conditional signals:

| Signal | When required | Semantics |
|---|---|---|
| `active_gateway_copies_per_path` | gateway topology | active gateway→origin pulls by internal camera key |
| `origin_egress_amplification` | gateway topology | `origin_gateway_egress / camera_ingress`; zero denominator = unknown |
| `legacy_active_sessions` | compatibility migration | bounded per cohort; stale/collector loss ≠ zero |

Conditional series remain inside global cardinality budget. Gateway threshold
comes from Spike #1. Legacy metric retained for 30-day window + 7 days and has a
migration owner.

### 16.2 Bitrate and series state

```text
bitrate_bps = 8 * max(0, delta(bytes_total)) / delta(monotonic_seconds)
```

Counter reset, stale gap and series absent are distinct. On-demand series absent
with no readers means `idle`, not `offline`. Aggregates use fresh samples only
and publish coverage ratio.

### 16.3 UI, traces and alerts

- overview/group: aggregate polling default 10s, configurable 5–30s;
- camera view: one bounded SSE, heartbeat 15s, coalescing, slow-consumer
  disconnect, bounded resume and `resync_required`;
- trace context flows API → outbox → worker/reconciler/probe → adapter;
- initial normal head sample 5%; exporter failure does not block requests;
- alerts have owner, source, SLI, threshold/duration, severity, runbook,
  dashboard, grouping and recovery condition;
- critical → paging, warning → ops chat, info → dashboard;
- node-down inhibits child alerts; single camera not page by default;
- dead-man switch detects loss of telemetry itself.

## 17. Capacity model and topology decision

### 17.1 Formulas

```text
sessions = active_sources + total_readers + gateway_internal_pulls
sockets_per_session = 1

required_RAM = mediamtx_baseline
             + heap_per_source * active_sources
             + heap_per_reader * total_readers
             + buffer_bytes_per_session * sessions
             + control_plane_RAM

required_FD = baseline_FD
            + FD_per_source * active_sources
            + FD_per_reader * total_readers
            + control_DB_and_internal_connections

camera_ingress        = sum(source_bitrate)
origin_gateway_egress = sum(source_bitrate * active_gateway_copies_per_path)
external_egress       = sum(source_bitrate * readers_per_path)
```

Each hop includes protocol/retransmit factor, packet rate, kernel sockets, NIC
queues and CPU. Spike publishes baseline/slope, p95/p99 buffers, FD/sockets and
churn; aggregate average cannot hide one-axis saturation.

### 17.2 Spike #0: single-node

Minimum matrix:

- registered paths to 10k;
- active sources 100/500/1000/2000 and onward to first knee;
- readers/source 1/2/5 plus hot-path skew;
- bitrate 1/2/4/8 Mbit/s;
- H264/H265, audio variants, typical/worst GOP;
- steady/ramp/burst reconnect;
- representative probes/CRUD/observability load.

Pass requires 24h soak, faults/churn, all SLO and resource headroom. If target
fits, production baseline remains single-node. This does not prove HA: node loss
is still full media failure domain and needs separate design.

### 17.3 Spike #1: gateway → origin

Runs only after single-node insufficiency. It proves:

- one FFmpeg host reads paths from different origins through one endpoint;
- every healthy gateway can serve every external path;
- duplicate pulls and per-hop bandwidth bounded and observable;
- H264/H265/audio cascade decodable, A/V skew `≤40ms`, added packet loss
  `<0.01%` vs baseline;
- warm overhead `≤+50ms`, cold `≤+500ms` vs direct-origin as spike budgets;
- gateway/origin loss, storms, keepalive, TEARDOWN, PAUSE, backpressure and
  timeouts pass;
- two-level reconcile cannot delete healthy origin due to gateway failure;
- camera credentials remain on origin;
- gateway identities are unique, rotated/revoked, mTLS/allowlist/audit work.

If it fails, Spike #2 evaluates ready-made RTSP-aware L7. Custom router only
after documented ready-made failure.

## 18. Performance and chaos

### 18.1 Generator

Main load uses N independent RTSP **servers** pulled on demand by MediaMTX. Push
publication into MediaMTX cannot substitute this path.

GStreamer fixtures control codec, audio, bitrate, packet rate and GOP. Load hosts
are outside SUT and maintain ≥30% headroom; otherwise run invalid. At least two
generator hosts confirm the generator knee is not mistaken for SUT capacity.
The native source reparses video to complete access units, passes the first unit
without clock wait for RTSP preroll and then uses per-media rational absolute
monotonic deadlines. A buffer arriving more than one frame interval after its
deadline rebases the schedule and waits one interval instead of producing a
catch-up burst; otherwise absolute deadlines are preserved. Opus uses a
separate 960-sample/20ms raw-buffer schedule before encoding and RTP payloading.
Relative per-buffer sleeps and pipeline-clock pacing are not accepted because
they respectively drift over a soak or can deadlock while gst-rtsp-server
prepares blocked payloader pads.

Every run saves commit and release-artifact SHA-256 values, versions, hardware,
kernel/sysctl/ulimit/systemd resource limits, network, topology, workload axes,
seed, synchronized time, raw series/events and summary.

### 18.2 Test ladder

- untuned baseline 100/500/1000;
- registered 100 → 500 → 1k → 5k → 10k;
- active sources and readers grow independently;
- one warm anchor per active path is included in total reader load; measured
  ramp, 15m warm-up, 30m measurement and candidate 24h soak are immutable,
  separately evidenced epochs;
- LAN and WAN/netem 50ms RTT, 0.5% loss, 10ms jitter;
- extended DNS/half-open/150ms+2% loss/bandwidth/DB/auth/node/L4 chaos;
- churn 10/s and 100/s, ramp 100/s, burst 1000/s;
- outage cohorts 10/25/100%.

Pass/fail uses p99 SLO from §8. Additional gates:

- zero unexpected healthy-cohort disconnects;
- maximum rolling RSS slope `≤1%/h` over every covered 6h window;
- leaked FD/sessions `≤0.1%` or `≤10`;
- added packet loss in healthy topology = 0;
- A/B probes/CRUD/dashboard/observability within `5% / 10% / 0.1pp`.

Cadence:

- PR: 100 registered/active/readers, 10m;
- nightly: 1k, 1h, LAN + bounded WAN/churn;
- pre-release or MediaMTX upgrade: full ladder, chaos, 24h soak.

## 19. Operations contract

### 19.1 Drain and update

```text
SERVING -> STOP_NEW -> DRAINING -> FORCE_BATCH -> UPDATING -> SMOKE -> SERVING
                                                     \-> ROLLBACK | QUARANTINED
```

- preflight: N-1 capacity, config/API compatibility, backup and previous release
  artifacts/checksums;
- `STOP_NEW` proven by connection test, not only LB removal;
- initial drain deadline 15m;
- force batch max one node and 5% fleet readers;
- smoke: API/auth, H264/H265, multiple readers, reconnect, TCP-only;
- observation window 5m;
- failed smoke → rollback/quarantine, never automatic return.

Same procedure is mandatory for RTSP listen address/port and transport changes.
The media listener remains ordinary `rtsp://`; TLS/RTSPS is not introduced.
Single-node maintenance honestly means media interruption without proven
redundancy.

### 19.2 Backup/PITR and post-restore safety

- continuous WAL/PITR: RPO `≤5m`, control RTO `≤30m`;
- DB backup and versioned encryption keys stored separately;
- restore first isolated, checking schema, rows, integrity, sample decrypt and
  audit chain;
- monthly restore drill, quarterly game day and before major release.

After PITR reconciler starts only in `report-only`:

```text
restored desired <-> actual paths
        |
        +--> to_create / to_update / to_delete
```

Create/update and delete require separate approvals. If `to_delete` exceeds
safety threshold, apply blocks for admin approval. Drill includes cameras created
after restore point and proves their paths are not auto-deleted.

### 19.3 Logs and runbooks

Structured logs have bounded buffers, runtime rotation/retention, disk budget,
backpressure and redaction tests. Debug is allowlisted by component/correlation,
max 15m, audited and auto-disabled.

Every production alert links a versioned runbook with symptoms, blast radius,
safe diagnostics/actions, rollback, escalation and verification. Runbook is
ready only after another operator executes it. Required: DB/PITR, media/auth/
queue, drift, probe backlog, saturation, credentials/certs, reconnect, migration,
update, telemetry loss, listener change and post-restore reconcile.

## 20. Release and migration

### 20.1 Prerequisites and state model

No production wave before green #1–#12, immutable release manifest, rollback
evidence and overlap capacity.

```text
EXPECTED -> PREFLIGHT_OK -> IMPORTED -> APPLIED -> AUTH_OK -> READABLE
         -> CUTOVER -> SOAK_OK
```

Batch report includes expected/skipped/imported/applied/readable/cut-over/failed/
rolled-back/orphans. Camera never vanishes from report; retryable and terminal
outcomes differ; repeat import/reconcile is idempotent.

### 20.2 Camera and wave preflight

Each camera: reachability, DNS, profile/firmware, codec/audio/GOP, source auth,
`public_id`, owner, bitrate, resource budget and managed client rollback.

Session limit checked under current load:

```text
existing_sessions + required_migration_pull <= camera_session_limit
```

If no slot, order changes: managed client cutover first, new proxy pull second.
Camera-origin rejection is an abort signal, not mislabeled proxy failure.

Wave preflight checks ≥30% headroom after old/new overlap, fresh backup/PITR,
rollback artifacts, alerts/runbooks, on-call/change owner and freeze scope.

### 20.3 Waves

1. Lab: synthetic + representative OMNY.
2. Pilot 10: one canary, then rest.
3. Pilot 100: canary 5% (minimum 5), batches ≤25.
4. 500/1k+: canary 5% (minimum 10, maximum 50) within envelope.
5. Multi-node only after #10 evidence and repeated #11/#12 gates.

Soak: canary 24h; pilot 100 — 7d; 500+ — at least 48h.

Wave success:

- 100% canary and ≥99% batch readable;
- zero system-caused unplanned healthy-stream disconnects;
- FFmpeg recovery and health freshness within SLO;
- auth/path error growth `≤0.1pp`;
- hard resources <70%, headroom ≥30%;
- no open critical/high integrity/security/cross-camera issue;
- operator sign-off without blocking manual workaround.

Automatic `STOP`: security/data incident, cross-camera impact, rollback loss,
observability loss, capacity breach, unexpected healthy disconnect or failed
restore/readiness.

### 20.4 Legacy coexistence and rollback

- before cutover old system is authoritative; new runs shadow validation without
  second upstream pull;
- ownership switches atomically per camera/cohort;
- legacy window lasts minimum 30 days after last cohort cutover;
- legacy path disables only after 7 consecutive full days of fresh
  `legacy_active_sessions = 0` immediately before change;
- any legacy session resets the counter; stale/unknown metric blocks shutdown;
- migration owner, date and explicit sign-off required;
- uncontrolled dual pull prohibited;
- client rollback requires managed supervisor config, service discovery, DNS or
  cohort mapping;
- hardcoded FFmpeg URLs without managed channel block cohort.

Before client cutover rollback is full. After cutover it means restoring legacy
path and reversing client config; this asymmetry is a go/no-go input.

## 21. Implementation roadmap

Phase 0 and foundation implementation began after explicit owner authorization
on 2026-08-10. The evidence gates below still control dependent product
behavior, pilot and rollout.

### Pre-Phase 0 — specification bootstrap

- add ADR template/registry;
- add SLI catalog and measurement points;
- add `docs/CAMERA_PROFILE.md` template and owner;
- create immutable release/compatibility manifest schema;
- create capacity worksheet, failure-domain and risk register templates.

**Exit:** artifacts versioned, owners assigned, gates automatable.

### Phase 0 — evidence foundation

#### 0A. MediaMTX/FFmpeg/ffprobe compatibility lab — COMPLETE

- pin versions and release-artifact checksums;
- API create/update/delete/isolation/idempotency/read-back tests;
- path persistence after node restart;
- external callback vs static/runtime auth;
- cache/revoke/established-session behavior;
- transparent ordinary-RTSP contract and L4/VPN source-IP boundary;
- metrics inventory;
- TCP-only, FFmpeg, on-demand race and secret-leak tests.

**Exit:** critical forks have Proposed/Accepted ADR backed by evidence.

Exit review: Standards/Spec `PASS`; native Linux amd64/arm64 CI run
`31406619869`. Proposed ADR constraints remain production gates.

#### 0B. Reproducible load harness and Spike #0 — IN PROGRESS

- RTSP pull-server generator and fixtures;
- manifest/raw artifacts;
- untuned baselines and resource slopes;
- single-node knee, 24h soak, fault/churn matrix;
- safe envelope and hardware/network profile.

**Exit:** `SINGLE_NODE BASELINE` decision or authorization for Spike #1.

Implementation status: native GStreamer pull sources/readers and a digest-bound
orchestrator are present. A stored profile generates exact per-host source and
reader plans; active paths and reader counts remain independent. Reader events
separate outgoing `DESCRIBE→PLAY` from the first parser-aligned
IDR/IRAP random-access unit; header-only, delta, decode-only, corrupted and gap
buffers are rejected. Cold pass/fail is accepted only from a compatible
finalized direct-control pair; only handshake deltas are compared, while both GOP waits are published
separately. Seeded steady/ramp/burst/outage primitives, interruption
fail-closed and owner-only credentials are implemented. Warm proxy profiles
reserve one reader from `total_readers` per active path as an anchor, start the
anchors 60 seconds before measured ramp and require typed MediaMTX runtime
polling through the ramp boundary. Anchors remain normal downstream sessions in
the same reader processes/cgroups and therefore cannot hide generator or SUT
load. Shards share future UTC anchor/ramp/measurement/soak epochs; completion records exact
per-host reader counts/lifecycle slots, host/profile/reader-plan digests and
kernel clock proof through workload end. A derived post-workload grace keeps
PIDs observable for the final sampler interval without extending media load.
Every injected disconnect binds the deterministic backoff to its same-cycle
schedule and ordered next-cycle start→PLAY→first-decodable chain; orphan or
skipped cycles fail finalization.
Cold profiles use one reader per active path and require a typed reset/recreate
plus unavailable-path preflight within 30 seconds of start. Until a bulk
MediaMTX reset/snapshot path is proven, cold evidence uses a conservative
implementation safety cap of 512 paths and 32 concurrent API workers; larger
profiles fail validation. Generator evidence
requires exact PID/cgroup membership, pinned executable digests/start times,
NIC packet/MTU measurements, effective ephemeral-port capacity after reserved
ports and finite CPU/memory/pids limits. Capacity policy enforces CPU `<=65%`,
NIC byte/packet rate `<=60%`, and RAM/FD/socket/cgroup-pids `<70%`; measurement
and soak are recomputed and gated separately. Finalization regenerates catalog/plans and exact typed
summaries from raw evidence before sealing a hash-complete read-only bundle,
which is then moved to root-owned immutable/WORM storage.

Fixture bytes alone are insufficient evidence: `prepare` requires a typed
manifest produced with the pinned FFmpeg/ffprobe binaries and matching probed
codec, FPS, bitrate, every internal GOP interval and the cyclic loop boundary.
The Phase 0B harness is IPv4-only and rejects IPv6 literals until its native
source/evidence path is fully dual-stack. Every proxy and capacity bundle requires
a typed SUT series bound to the single MediaMTX PID/systemd cgroup and relevant
NIC. Each SUT sample and loopback preflight carries Linux kernel clock proof;
session/path counters remain cumulative across churn and use a pre-measurement
baseline. Exact empty-family zero sentinels and active identities are bound;
session history stays stable on `id+remoteAddr` across idle/read path changes,
while every sample requires equal `id/path/remoteAddr/state` labels across
selected families. State-specific RTP/RTCP/path-error fields and recomputed
cumulative totals are bound; an observed path ready/notReady transition starts
a counter generation, while a decrease within one continuously observed state
fails closed. Reader
completions independently reconcile per-reader/per-track video and configured
Opus phase RTP with shard totals, compare successfully parsed receives with the
sender RTP sequence-number span per cycle/track/phase, require video progress
of at least 80% of pinned fixture FPS (Opus: 40 packets/s) during typed
connected intervals, require first/last successful packets within one second
of the interval boundaries and reject every gap, including one spanning
measurement into soak.
Recomputed gates enforce SUT headroom, maximum rolling RSS slope `<=1%/h` for
every covered 6h window, including cross-phase windows,
bounded FD delta, zero RTSP sessions and ready runtime paths after the pinned
on-demand close/drain interval, and zero inbound/outbound RTP, RTCP and path
loss/error delta. Every proxy bundle requires the same independent SUT
identity/resource/session/loss series with the functional `<70%` headroom policy;
capacity adds the 6h/24h leak/soak conclusions. Missing SUT or fixture evidence
fails finalization rather than downgrading the claim.

Every finalized run requires a typed manifest from each generator host; proxy
and capacity runs also require the SUT manifest. It binds the canonical profile
and brackets the complete capture with synchronized start/completion clock proofs.
Native architecture, machine/boot, CPU/RAM/NIC, kernel/OS, the fixed sysctl set,
full cgroup v2 constraint-chain digest, effective cgroup/RLIMIT values and the exact
PID/start/executable identities already present in the resource series.
Generator manifests additionally require the profile-pinned GStreamer version,
the exact `libgstreamer1.0-0` dpkg build, a canonical installed-package ledger,
and SHA-256/device/inode proof for GStreamer libraries mapped by every workload
process. Capture rechecks process/cgroup/denominator identity before the completion
proof and is bounded to the five minutes before the anchor through measurement
start. Resource sampling gates usage of every limiting cgroup ancestor, including
shared systemd slices, and binds unchanged RAM/NIC/cgroup/RLIMIT denominators back
to this manifest. The typed `ip_local_port_range` and canonical reserved-port set
must recompute the exact socket denominator and digest in the resource series.
Cold proxy/direct bundles copy, hash and compare stable generator
runtime environments; machine/boot/kernel/sysctl/cgroup/RLIMIT or GStreamer drift
invalidates the A/B pair. Missing, stale, cross-machine or architecture-mismatched
evidence fails finalization. This collector targets the documented Ubuntu 24.04
native host shape equally on amd64 and arm64.

Hardened native amd64/arm64 CI run `31511231574` covers the complete functional
harness. On both native runners it executes the runtime collector against real
procfs, non-root cgroup v2 constraints, dpkg and mapped GStreamer libraries,
then executes the H.264/H.265 RTSP/TCP contract. Repeat Standards/Spec review
passed.
Per-host hardware/architecture and dynamically linked GStreamer package/build
evidence is now mandatory in the finalizer, but no production-equivalent host
manifest or capacity result has been published. WAN/netem and non-zero probe/CRUD
profiles currently fail closed until typed drivers and their evidence verifiers
are implemented. CI is not capacity evidence; dedicated LAN/WAN hardware,
untuned baselines, saturation knee, complete fault matrix and 24h soak remain
mandatory before the Phase 0B exit decision.

#### 0C. Conditional topology spike

- gateway→origin matrix;
- on failure, ready-made RTSP-aware L7 evaluation;
- topology ADR with failure/security/rollout/rollback evidence.

**Exit:** selected topology never relies on L4 path awareness.

### Phase 1 — control/data/media vertical slices

1. **#2 Foundation:** package, roles, typed config, CI, immutable Linux release
   artifacts, systemd units, health, Alembic and DB pools.
2. **#3 Data:** IDs, profiles, lifecycle, groups, grants, sync audit/outbox,
   ordering, retention and migrations.
3. **#4 Dashboard/RBAC:** sessions, authz epochs, no-oracle, CRUD, conflicts,
   bulk, reveal and WORM audit.
4. **#5 Reconciler:** fencing, minimal path diff, read-back, delete, restart
   recovery and drift metrics.
5. **#6 Health:** scheduler, source/path probes, state machine, SSRF sandbox and
   dashboard projection.

Each slice ends with contract/integration tests, migration compatibility,
redaction/audit assertions and rollback evidence.

### Phase 2 — cross-cutting production contracts

1. **#7 Observability:** signal catalog, TSDB budgets, bitrate, traces, bounded
   polling/SSE, alerts/dead-man.
2. **#8 FFmpeg:** two-version matrix, supervisor, timeout/reconnect, TCP-only and
   process-secret tests.
3. **#9 Security:** auth/network-boundary decision, grants, keys, limits,
   hardening and drills.
4. **#11 Performance:** full A/B, load, chaos and 24h soak; publish envelope.

**Exit:** release candidate has evidenced SLO/security/resource limits and no
unaccepted blocker/high finding.

### Phase 3 — operations and release

1. **#12 Operations:** deploy automation, N/N-1 migration, drain/quarantine,
   PITR/keys, post-restore report-only and game days.
2. **#13 Release:** lab → pilot 10 → pilot 100 → measured 500/1k waves.
3. Every gate ends in owner `GO | HOLD | ROLLBACK`.

Parallel work is allowed only where it cannot hide a dependency/evidence gate.
Multi-node and rollout never precede compatibility and Spike #0.

## 22. Global go/no-go gates

### Start Phase 0

**SATISFIED 2026-08-10:** explicit owner message authorized plan execution and
foundation code. Permitted infrastructure is direct Linux/systemd deployment;
Docker/containers are excluded. Production and evidence-dependent feature gates
remain `NO-GO` until their own conditions pass.

### Start feature implementation

Pinned compatibility results, accepted critical fork decisions, reproducible
load harness and no architecture blocker in the topology being implemented.

### Start production pilot

- green artifacts #1–#12;
- no blocker/high without accepted risk;
- proven client rollback;
- restore/security/drain/alert drills;
- overlap capacity;
- formal owner sign-off.

### Exit pilot 100

1. 7d soak and zero system-caused healthy disconnects.
2. All SLO/error/capacity/probe thresholds green.
3. No orphan paths/credentials; reconciliation converged.
4. Restore, credential rotation, alert and rollback drills passed.
5. Critical/high closed; medium owned or accepted.
6. Operator review has no blocking workflow/manual workaround.
7. Owner signed next-wave decision.

## 23. Open evidence risks

| Risk | Why consensus cannot close it | Evidence |
|---|---|---|
| R1 single-node capacity | 10k is multidimensional | Spike #0 and published envelope |
| R2 multi-node topology | L4 not path-aware; gateway is hypothesis | Spike #1/#2 and ADR |
| R3 MediaMTX semantics | API/auth/delete/persistence/transparent RTSP depend on binary version | pinned binary contract suite |
| R4 client rollback | hardcoded external URL unmanaged | supervisor/service discovery/DNS/cohort mapping |
| R5 environment drift | OMNY/WAN/NAT/kernel/NIC/overlap alter knee | preflight and production-like soak |
| R6 auth/network fork | callback/static and VPN/L4 source-IP boundary unknown | Phase 0 security spike |
| R7 restore deletes newer runtime paths | restored desired older than actual | report-only diff and delete approval |

These are evidence gates, not internal specification contradictions. They block
the corresponding feature, claim or rollout until proved.

## 24. Evidence registry

| Issue | Area |
|---|---|
| [#1](https://github.com/zl0nline/RTSP_proxy/issues/1) | ADR, SLO, capacity, camera assumptions, failures |
| [#2](https://github.com/zl0nline/RTSP_proxy/issues/2) | Foundation, config classes, MediaMTX, migrations |
| [#3](https://github.com/zl0nline/RTSP_proxy/issues/3) | Data, identifiers, secrets, retention |
| [#4](https://github.com/zl0nline/RTSP_proxy/issues/4) | Dashboard, RBAC, conflicts, browser, audit |
| [#5](https://github.com/zl0nline/RTSP_proxy/issues/5) | Outbox/reconciler, hot-update, placement, recovery |
| [#6](https://github.com/zl0nline/RTSP_proxy/issues/6) | Health, probes, SSRF, profiles |
| [#7](https://github.com/zl0nline/RTSP_proxy/issues/7) | Metrics, TSDB, UI, tracing, alerts |
| [#8](https://github.com/zl0nline/RTSP_proxy/issues/8) | FFmpeg/supervisor and TCP-only regression |
| [#9](https://github.com/zl0nline/RTSP_proxy/issues/9) | Threat model, auth, keys, network boundary, hardening |
| [#10](https://github.com/zl0nline/RTSP_proxy/issues/10) | Single-node-first and topology spikes |
| [#11](https://github.com/zl0nline/RTSP_proxy/issues/11) | Load generator, performance, chaos |
| [#12](https://github.com/zl0nline/RTSP_proxy/issues/12) | Deploy, drain, migrations, PITR, runbooks |
| [#13](https://github.com/zl0nline/RTSP_proxy/issues/13) | Pilot, coexistence, rollback, rollout |
| [#14](https://github.com/zl0nline/RTSP_proxy/issues/14) | EPIC, dependencies, planning DoD |

## 25. Product Definition of Done

Product/release is ready only when:

- operator performs normal CRUD/diagnostics without DB/MediaMTX CLI;
- one path change does not break unrelated streams;
- FFmpeg + supervisor passes pinned matrix;
- authz/no-oracle/revoke, secrets, audit/WORM and browser gates are green;
- camera profiles filled and preflight uses GOP/session limits;
- published capacity envelope has load/chaos evidence;
- restore cannot delete newer runtime paths without explicit decision;
- drain, update, rollback and runbooks passed drills;
- pilot exits green and owner gives `GO`;
- every 10k claim is bounded by the actually measured workload envelope.

Phase 0 is authorized and in progress. The next valid action is to finish the
remaining typed Phase 0B drivers, execute Spike #0 on production-equivalent
amd64/arm64 stands, and then decide `SINGLE_NODE BASELINE` or authorize the
conditional topology spike. Until those artifacts exist, dependent product
behavior and production rollout remain `NO-GO`.
