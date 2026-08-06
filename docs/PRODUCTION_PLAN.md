# Production-план RTSP Proxy

> Версия документа: planning baseline после внешнего критического ревью issues
> [#1–#13](https://github.com/zl0nline/RTSP_proxy/issues/14).
>
> **PLANNING: READY · IMPLEMENTATION: NOT AUTHORIZED · PRODUCTION: NOT READY · 10K: NOT CLAIMED**

Этот документ описывает согласованный production-контракт. Он не утверждает, что система уже реализована, готова к эксплуатации или выдерживает 10 000 одновременно активных потоков. Любая реализация начинается только после отдельного решения владельца проекта. Consensus в issue означает согласованный проверяемый контракт, а не выполненную работу.

## 1. Цель, область и ограничения

Система должна заменить множество внешних RTSP-портов единым настраиваемым endpoint, по умолчанию `:9999`, и обеспечить безопасное управление каталогом до 10 000 зарегистрированных камер.

Раздельно измеряются:

- зарегистрированные пути;
- одновременно активные источники;
- readers на источник;
- средний и пиковый bitrate, codec/GOP/audio profile;
- длительность сессий, churn и reconnect rate;
- нагрузка control plane, probes и observability.

`10k registered` не означает `10k active`. Допустимая комбинация этих осей публикуется только как измеренный capacity envelope.

Поддерживаемый внешний клиент — FFmpeg вместе с supervisor. Внешний media transport — RTSP over TCP interleaved. UDP и транскодирование не входят в контракт.

Не входят в текущую область: NVR/архив видео, собственная реализация RTSP, публичный интеграционный API, автоматическое добавление инфраструктуры без измеренной потребности и гарантии бесшовности при потере живого TCP-сеанса.

## 2. Статусы и права принятия решений

| Уровень | Текущий статус | Условие перехода |
|---|---|---|
| Planning | READY | Consensus и внешнее ревью #1–#13 завершены |
| Implementation | NOT AUTHORIZED | Явное решение владельца с scope, например `START PHASE 0` |
| Production pilot | NO-GO | Зелёные evidence artifacts #1–#12, отсутствие непринятых blocker/high risks, owner sign-off |
| Scale after pilot 100 | NO-GO | 7-дневный exit gate, опубликованный envelope, operator review и `GO/HOLD/ROLLBACK` |
| 10k | NOT CLAIMED | Только результаты production-like load/chaos испытаний |

Decision rights:

- владелец проекта разрешает старт phase, pilot и следующую волну;
- технический owner останавливает rollout при нарушении gate;
- security owner может остановить rollout при auth, secret, audit или TLS breach;
- operations owner принимает restore/drain/rollback evidence;
- ослабление численных целей допускается только versioned ADR с baseline, evidence и явным одобрением.

## 3. Архитектурные инварианты

1. Один внешний configurable RTSP endpoint, default `9999`.
2. Python не находится в медиапути. Media plane строится на pinned MediaMTX digest.
3. PostgreSQL — единственный source of truth для desired state; JSON допустим только для import/export.
4. Established media sessions не зависят от синхронного request-time PostgreSQL/control-plane fan-out.
5. CRUD одной камеры не должен обрывать TCP/bytes/PTS других путей; штатный CRUD не вызывает restart/reload MediaMTX.
6. Desired state доставляется через transactional outbox и идемпотентный reconciler; API сообщает `desired accepted`, а не ложно обещает `applied`.
7. L4 load balancer не считается path-aware. Схема `L4 -> assigned shard` запрещена.
8. Single-node first: multi-node появляется только после измеренного провала/прогноза single-node gate и отдельного topology spike.
9. Security, audit, observability, rollback, restore и capacity — обязательные release gates.
10. Неизвестные возможности MediaMTX подтверждаются executable contract tests конкретного digest, а не документацией абстрактной версии.

## 4. Логическая архитектура

```text
Operator
   |
   v
HTTPS Dashboard/API -----> PostgreSQL
   |                         | desired state, authz, audit, outbox
   |                         v
   +--------------------> Workers / Reconciler / Probe scheduler
                              |             |
                              |             +--> bounded ffprobe --> cameras
                              v
External FFmpeg --> RTSP/TCP endpoint --> MediaMTX node --> cameras
                                           |
                                           +--> metrics/events --> collector/TSDB
```

### 4.1 Control plane

- Python 3.12, FastAPI, Jinja2/HTMX и PostgreSQL.
- Отдельные runtime roles: web, worker, reconciler и collector.
- DB-backed queue/outbox на старте. Redis/NATS вводятся только отдельным ADR после измеренной необходимости.
- Management API внутренний; публичным интеграционным API он становится только через новый scope.
- OpenTelemetry настраиваемый; недоступность collector не ломает request path.

### 4.2 Media plane

- Pinned MediaMTX image digest, immutable release manifest, SBOM/signature policy.
- Источники по умолчанию on-demand и RTSP-over-TCP.
- Python не proxy/remux/transcode media.
- Management API и metrics доступны только management boundary.
- Runtime readiness проверяет фактический минимальный API contract узла, а не «угадывает» digest соседнего контейнера.

### 4.3 Failure domains

- MediaMTX node, PostgreSQL, FastAPI/workers и gateway — разные failure domains.
- Потеря control plane или PostgreSQL останавливает/ограничивает CRUD, authz changes и reconcile, но не должна обрывать established sessions на живом media node.
- Новые sessions при outage разрешаются только по доказанной cached auth policy с bounded revoke window; иначе fail closed.
- Потеря gateway обрывает только его TCP sessions; reconnect может попасть на живой gateway, но бесшовность TCP не обещается.
- Потеря origin shard затрагивает его sources, пока failover ownership не доказан отдельно.
- Каждый ADR содержит: `failure -> effect -> blast radius -> detection -> recovery -> SLI impact`.

## 5. Foundation и supply-chain contract

### 5.1 Immutable deployment

Production manifest использует `image@sha256:...`; mutable tags запрещены. CI проверяет allowlisted digest, SBOM/signature и compatibility manifest. На startup выполняется API/auth/metrics/RTSP smoke против реально запущенного image.

Dev и production images разделены. Production image: multi-stage slim, locked dependencies, non-root, read-only root filesystem где возможно, без compiler/dev tools и hot reload.

### 5.2 PostgreSQL connections

```text
sum(replicas_by_role * (pool_size + max_overflow)) <= 0.70 * max_connections
```

Не менее 30% остаётся для migrations, operations, failover и emergency access. Начальные верхние границы до load test: web `10+10`, worker `5+5`, reconciler `2+2`, collector `2+2`. Для advisory-lock reconciler применяется отдельный direct/session-pooled DSN; statement pooling запрещён.

Обязательны bounded `pool_timeout`, recycle/pre-ping, idle transaction timeout, role-specific statement timeouts и метрики wait/checked-out/overflow/timeouts.

### 5.3 Health endpoints

- `/health/live`: процесс/event loop жив; потеря dependency не провоцирует restart loop.
- `/health/ready`: role-specific возможность выполнять работу.
- web требует совместимую schema, DB и session store;
- worker — DB и queue/outbox contract;
- reconciler — DB/schema и MediaMTX adapter contract;
- collector остаётся ready при потере одного target, но показывает degraded status.

Schema ahead/behind делает соответствующий binary not ready. Reason codes стабильны и не содержат DSN/secrets.

### 5.4 Migrations

Alembic revisions immutable и имеют single head. Приложение не запускает migration автоматически. Отдельный migration job берёт advisory lock. Стратегия — expand → bounded backfill → switch → contract с N/N-1 совместимостью.

Production rollback не опирается на destructive downgrade. Необратимая migration требует backup/PITR и forward-fix plan. CI проверяет empty DB, N-1 upgrade, drift, locking и production-volume fixture.

## 6. PostgreSQL data contract

### 6.1 Идентификаторы и lifecycle

- `camera_id`: UUID v7/v4, внутренний PK, не credential.
- `public_id`: immutable CSPRNG URL-safe identifier с энтропией не менее 128 бит; не является авторизацией.
- `grant_id`: отдельный несекретный identifier access grant.
- `public_id` никогда не переиспользуется; после purge остаётся tombstone.
- Rotation public ID идёт через alias registry: create → reconcile/auth readiness → atomic switch → revoke old → drain/terminate → permanent tombstone.

Lifecycle и административный режим разделены:

- lifecycle: `PROVISIONING | ACTIVE | DELETE_PENDING | DELETED | PURGED`;
- admin mode: `ENABLED | MAINTENANCE | DISABLED`.

Soft delete одной транзакцией переводит объект в `DELETE_PENDING/DISABLED`, отзывает grants, создаёт audit и outbox event. Restore не реактивирует credentials/grants неявно.

### 6.2 Основные сущности

- `cameras`, `camera_sources`;
- `camera_public_ids`;
- `camera_secret_versions`;
- `camera_groups`, `camera_group_memberships`;
- `access_grants`;
- `media_nodes`, `camera_placements`, target/reconcile state;
- `reconcile_outbox`, jobs/DLQ;
- `camera_health_current`, `probe_results`;
- append-only `audit_events`.

Raw source URL с userinfo не хранится. Secrets и access verifiers физически отделены от metadata.

### 6.3 Concurrency и ordering

- Mutations используют optimistic revision/row lock; desired revision, audit и outbox фиксируются атомарно.
- Applied revision хранится по target/placement generation, а не в `cameras`.
- Probe ordering: `(camera_id, source_revision, probe_generation)`; timestamps не являются ordering key.
- Conditional UPSERT в `camera_health_current` принимает только более новую generation.
- List views используют keyset/cursor pagination, не deep OFFSET.

### 6.4 Retention, partitioning и HA

Partitioning вводится по измеренным rows/day, bytes/day, WAL, autovacuum и restore time, а не из-за самого числа камер. Кандидаты — `probe_results` и `audit_events`; partitions создаются заранее, default partition аварийная и алертится.

Production target для критического desired state/audit при failover — RPO, заданный release policy. RPO=0 требует synchronous quorum/remote-apply policy; `synchronous_commit=on` само по себе недостаточно. Async replica означает явно принятый ненулевой RPO.

## 7. Reconciler и hot-update

### 7.1 Delivery semantics

Одна API transaction: optimistic lock → desired revision → outbox → audit. Reconcilers claim jobs через `FOR UPDATE SKIP LOCKED`, lease и per-camera serialization.

До доказанного MediaMTX CAS один active writer на node обеспечивается PostgreSQL session advisory lock. Потеря DB connection отменяет in-flight apply; новый writer сначала получает lock и делает read-back inventory.

Exactly-once не обещается. Контракт — bounded inconsistency и automatic forward repair.

### 7.2 Apply loop

1. Проверить pinned API contract до write.
2. Сделать read-back и вычислить минимальный diff.
3. Применить convergent/idempotent operation.
4. Выполнить read-back verification.
5. Commit applied revision только если desired ещё актуальна и fencing token совпадает.
6. При timeout классифицировать неизвестный результат через read-back и forward reconcile.

Revision N не откатывает принятую N+1. Last-known-good restoration допустима только как fenced compensating action.

Быстрые revisions в одной placement generation можно coalesce до latest. Placement change — отдельная saga:

```text
PREPARE_NEW -> SWITCH -> DRAIN_OLD -> DELETE_OLD -> COMPLETE
```

Если topology не даёт доказуемого switch, migration объявляется disruptive и выполняется в maintenance window.

### 7.3 Delete semantics

- `IMMEDIATE`: запрет новых sessions, revoke, delete path; активные могут оборваться.
- `GRACEFUL(deadline)`: запрет новых, ожидание readers до нуля/deadline, затем delete или disabled+blocked.

Фактические RTSP codes и поведение active sessions фиксирует pinned contract spike.

Startup reconciliation использует inventory diff, cursor/checkpoint, fairness и adaptive concurrency; безусловный write всех 10k запрещён.

## 8. Dashboard, RBAC и browser boundary

Dashboard показывает каталог, группы, desired/applied state, health freshness, readers/bitrate, историю ошибок и audit, но не декодирует видео и не участвует в медиапути.

### 8.1 Authorization

- Монотонный `authz_version` для пользователя/session.
- Downgrade/revoke enforcement `<=2s`, fail closed; upgrade `<=30s`.
- Version fencing в authoritative store, не надежда на cache flush.
- List/count/search/direct/export/SSE соблюдают единую no-oracle policy.
- SSE использует authz/resource epochs и batch pre-delivery checks; событие после scope loss запрещено.
- Break-glass обязателен: MFA, alert, runbook и drill.
- Изменившиеся IdP claims не повышают права активной session автоматически.

### 8.2 Concurrency UX

Bulk jobs возвращают per-object outcomes, поддерживают retry terminal subset, admission control и честный partial success. Merge semantics закрепляются ADR и executable matrix. Placement, credentials, public ID rotation и lifecycle/admin-mode никогда не auto-merge.

Dashboard различает `desired accepted`, `applied`, `STALE` и `OVERDUE`, показывает timestamps и dependency degradation banners.

### 8.3 Secrets и audit

Secret reveal — отдельная `no-store` surface с auto-clear через 30 секунд, `Referrer-Policy: no-referrer`, без Service Worker. Secret exposure в hostile browser extension/compromised endpoint не считается решённой задачей; trust boundary документируется честно.

Sensitive read/reveal/export аудируются. Application roles имеют только INSERT для audit; critical events уходят в immutable/WORM sink. Destructive operation fail closed при невозможности принять обязательный audit event.

## 9. Health plane

Два уровня сигналов:

- MediaMTX API/metrics — дешёвый operational signal;
- bounded ffprobe — глубокая end-to-end verification.

Состояния разделены:

- health: `UNKNOWN | HEALTHY | SUSPECT | UNHEALTHY | RECOVERING`;
- observation: `FRESH | STALE | OVERDUE`;
- admin overlay: `ENABLED | MAINTENANCE | DISABLED`.

Scheduler overload не делает камеру `UNHEALTHY`; он влияет на freshness. Начальные transitions: add/change → UNKNOWN; один negative → SUSPECT; второй независимый failure после backoff → UNHEALTHY; первый success → RECOVERING; два последовательных success → HEALTHY. Новая source generation инвалидирует старые observations.

Scheduler использует bounded concurrency, single-flight, jitter, reserved capacity, deadline aging, per-site/subnet limits и risk-based sampling. Manual jobs не монополизируют pool. Для enabled cameras существует гарантированный max interval.

ffprobe запускается без shell, pinned version, с CPU/RAM/process/time/stderr limits. Endpoint проходит canonical parse, IDNA normalization, проверку всех A/AAAA и IPv4-mapped IPv6. Job получает approved literal IP:port и immutable endpoint generation; redirects/re-resolve запрещены. Egress policy разрешает только approved destination.

Freshness: не менее 95% routine-enabled камер имеют deep observation не старше `2 * configured_interval`; add/change confirmations измеряют отдельный queue-delay SLO.

## 10. FFmpeg + supervisor contract

Release compatibility matrix содержит production-pinned FFmpeg и предыдущую поддерживаемую major/minor line, точные build/configuration и рекомендуемые команды.

Матрица покрывает H264/H265, audio/no-audio, OMNY fixtures, DNS/IPv4/bracketed IPv6, non-default port, DESCRIBE/SETUP/PLAY/TEARDOWN, multiple readers, client abort, timeout, source outage/recovery, path update/delete и credential rotation/revoke.

Supervisor:

- при EOF/timeout/transport failure завершает текущий FFmpeg и запускает новый полный handshake;
- exponential backoff с full jitter: `1s -> 30s`, reset после `60s` стабильного чтения;
- не более одного активного и одного завершающегося process на stream;
- permanent auth/path failures не попадают в tight loop;
- recovery target: p95 `<=10s`, maximum `<=35s` от server/source ready до первого packet/frame.

RTSP keepalive, FFmpeg read/connect timeouts и L4/NAT idle timeout образуют единый budget. Сервер не обещает resume внутри прежнего TCP-сеанса.

URL создаётся structured encoder. Special/Unicode credentials, percent-encoding и bracketed IPv6 тестируются. Полное отсутствие URL secret в argv нельзя обещать для всех builds, поэтому production boundary включает отдельный service account/container PID namespace, запрет cross-tenant process inspection, redaction и rotation.

## 11. Security contract

Source credentials и external access grants разделены.

- grant username/id непрозрачен, но не считается секретом;
- password/token генерируется CSPRNG, URL-safe, энтропия не менее 128 бит;
- default scope — read конкретного public ID; group grants opt-in из-за blast radius;
- publish, management API и другие paths deny by default;
- temporary и service grants имеют явные TTL/expiry, rotation overlap и revoke;
- public ID не является credential.

Media-grant `revoke-new` имеет отдельный initial SLO `<=10s`; positive cache TTL `<=5s` и всегда короче revoke SLA. Это не то же самое, что dashboard/session authz downgrade из #4 (`<=2s`). Push invalidation ускоряет отзыв, но correctness обеспечивается bounded TTL. `Revoke-new` и принудительное завершение established session — разные операции; selective kill не обещается до pinned spike.

Source secrets используют envelope encryption: per-record DEK, KEK вне PostgreSQL. В DB хранятся ciphertext/version/key id; access tokens — только verifier + pepper key id после одноразового показа raw value. Backup ciphertext, verifiers и key lifecycle входят в threat model.

Наружу открыт RTSP/RTSPS endpoint; dashboard находится в HTTPS management VPN/allowlist. MediaMTX API/metrics не публикуются. Camera endpoints ограничены approved CIDR/egress policy.

Auth mechanism выбирается pinned spike между внешним auth callback и static/runtime config. Spike доказывает no-oracle parity unknown/revoked/existing path, revoke latency, rotation overlap, auth outage behavior и fate established sessions.

Brute-force, connection flood и slow-client limits должны защищать новые connections, не разрушая established streams. TLS strategy включает CA/SAN/expiry/wrong-CA/cipher matrix, hot certificate reload и при необходимости PROXY protocol source-IP preservation.

Logs/audit содержат grant id, public id, decision reason class, actor/source metadata по privacy policy и correlation id, но никогда password, Authorization header или URL userinfo.

## 12. Observability contract

### 12.1 Signal catalog и budgets

Versioned catalog описывает source, exact name/schema, labels/cardinality, interval, reset/staleness, recording rule и consumer. Отсутствующий signal помечается unsupported/not-ready; log parsing не заменяет production contract.

Initial budgets:

- до `100k` active series при 10k registered cameras;
- до `6` series на enabled camera;
- overview: до `20` TSDB queries на refresh, без request-time fan-out;
- camera view: до `10` TSDB queries + один bounded SSE;
- interactive query p95 `<=2s`;
- recording-rule evaluation менее 50% interval.

Credentials, URL, IP, raw error и trace id запрещены как metric labels.

### 12.2 Bitrate semantics

```text
bitrate_bps = 8 * max(0, delta(bytes_total)) / delta(monotonic_seconds)
```

Counter decrease создаёт reset marker. Gap больше `2 * scrape_interval` даёт stale/unknown без интерполяции. No source/readers — отдельное state, не автоматический `0 bps`. Aggregates используют только fresh samples и публикуют coverage ratio.

### 12.3 Tracing, UI и alerts

Trace context проходит API → outbox → worker/reconciler/probe → adapter. Initial normal-traffic head sample — 5%; health/metrics не sampled. SQL params, RTSP URLs и credentials исключены. Exporter failure не блокирует request path.

Overview/group используют polling aggregated snapshots каждые 10s, configurable 5–30s с server minimum. Single-camera view — один SSE stream; heartbeat 15s, bounded queue, coalescing, slow-consumer disconnect, bounded `Last-Event-ID` resume и `resync_required` при gap.

Alerts имеют owner, SLI, threshold/duration, severity, runbook, dashboard, dedup/group labels и recovery condition. Critical идут в paging, warning — operations chat, info — dashboard. Node-down подавляет дочерние alerts; individual camera outage по умолчанию не page.

## 13. Capacity и scale-out

### 13.1 Capacity formulas

```text
sessions = active_sources + total_readers + gateway_internal_pulls

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

Protocol/retransmit factor, packet rate, kernel sockets, NIC queues and CPU измеряются по каждому hop. Spike снимает baseline и slope, p95/p99 buffers, FD/sockets и churn; среднее не скрывает saturation одной оси.

### 13.2 Single-node gate

Scale-out planning запускается при прогнозе или representative p95 `>=70%` любого hard limit: CPU, RAM, FD/socket, ingress/egress bandwidth или packet rate.

Single-node проходит gate только после 24h soak с faults/churn, выполненными SLO/error rates и `>=30%` headroom по каждому hard limit.

Для topology spike #10 дополнительно проверяются более консервативные candidate ceilings: CPU `<=65%`, NIC/packet-rate `<=60%`, FD `<=70%`, RAM `<=75%`. Они не заменяют общий gate `<70%` там, где он строже; Phase 0 capacity ADR принимает наиболее строгий применимый предел либо документирует изменение evidence.

### 13.3 Multi-node decision tree

1. Spike 0: определить single-node safe envelope.
2. Если его недостаточно — spike replicated MediaMTX gateway tier, где любой gateway знает external paths и on-demand тянет assigned origin.
3. Если gateway tier не проходит latency, bandwidth, duplicate-pull, failure isolation, auth или security gates — spike готового RTSP-aware L7 router.
4. Собственный RTSP router — последний резерв.

L4 перед gateway допустим только потому, что любой gateway способен обслужить path; L4 сам path не читает. Gateway spike обязан доказать один FFmpeg host, читающий paths разных origins через единый endpoint, reconnect/node failure, keepalive, TEARDOWN, backpressure, timeouts, duplicate-pull control и per-hop bandwidth.

## 14. Numerical contract

Значения ниже — initial budgets, а не уже доказанные характеристики.

| Область | Gate |
|---|---|
| Warm RTSP connect | p95 и p99 `<=500ms` |
| Cold on-demand connect | p95 и p99 `<=3s` |
| Catalog read | p95 и p99 `<=200ms` |
| CRUD mutation | p95 и p99 `<=1s` |
| Probe freshness | `>=95%` внутри заданного interval/контракта freshness |
| Availability | control plane `>=99.5%`; established media/platform `>=99.5%` как более строгий consolidated gate |
| Authz downgrade/revoke | `<=2s`, fail closed |
| FFmpeg recovery | p95 `<=10s`, max `<=35s` |
| Steady handshakes | `>=99.9%` successful |
| Probe overhead | throughput loss `<=5%`, latency regression `<=10%`, errors `<=0.1pp` |
| Safe resource envelope | utilization `<70%`, headroom `>=30%`, soak `24h` |
| PostgreSQL catalog/config | RPO `<=5m` |
| Control plane recovery | RTO `<=30m` |
| Restore/game day | monthly / quarterly |
| Retention | audit hot 12m, WORM 3y; probe raw 30d/aggregate 12m; metrics high-res 30d/downsampled 13m |
| Release | canary 5%; soak 24h/7d/48h; old-link compatibility 30d |
| Pilot exit | readable `>=99%`; zero system-caused disconnects of healthy streams in exit window |

Issue #1 формулирует p99/availability SLO, а итоговый EPIC #14 дополнительно приводит consolidated p95/release budgets. До принятия SLI ADR система обязана измерять оба percentile и применять более строгий availability target; молчаливое ослабление запрещено.

## 15. Load, regression и chaos protocol

Основной synthetic generator — GStreamer с pinned fixtures. Load hosts отделены от system under test. Профили включают localhost smoke, LAN и WAN/netem с latency/jitter/loss/reordering/bandwidth constraints.

До tuning снимаются untuned baselines на 100/500/1000. Оси registered, active sources и readers меняются независимо. Проверяются churn 10/s и 100/s, burst до 1000/s, source outage/recovery, node loss, DB/control outage, auth outage, reconnect storm, slow readers и observability pressure.

Сравнение A/B:

- media-only baseline;
- media + probes;
- media + CRUD/reconcile;
- media + observability;
- combined representative workload.

PR suite остаётся bounded; nightly расширяет regressions; pre-release выполняет полную production-like matrix и 24h soak. Capacity result публикует hardware/kernel/NIC, versions/digests, fixtures, topology, workload axes, knee points, headroom и raw artifacts.

## 16. Operations contract

### 16.1 Drain and update

```text
SERVING -> STOP_NEW -> DRAINING -> FORCE_BATCH -> UPDATING -> SMOKE -> SERVING
                                                     \-> ROLLBACK | QUARANTINED
```

Initial drain deadline — 15m. Forced batch не превышает одну media node и 5% fleet readers. Smoke window — 5m. Возврат в `SERVING` разрешён только после успешного observation window; failed smoke переводит node в `QUARANTINED` либо запускает rollback. Single-node maintenance честно означает media interruption, если отдельная proven redundancy отсутствует.

Liveness не падает из-за dependency и не создаёт restart loop. Readiness снимает только роль, которая не может безопасно работать. Config typed и валидируется до admission; secrets не смешиваются с ordinary config.

### 16.2 Rollback and backups

Release manifest хранит immutable совместимые пары app/schema/MediaMTX/config. DB changes следуют expand-contract; destructive down migration не является production rollback.

PostgreSQL backup + WAL PITR и backup encryption keys хранятся раздельно. Restore drill выполняется ежемесячно на production-volume; critical game day — ежеквартально. Restore проверяет catalog, audit chain, key availability/crypto-erasure outcomes и reconciliation.

### 16.3 Logs and runbooks

Structured logs имеют bounded buffers, rotation/retention, backpressure policy и redaction assertions. Запрещены credentials, URL userinfo, Authorization, raw source URLs и unbounded stderr.

Runbooks покрывают DB/media/auth/queue outage, reconcile stuck/drift, probe backlog, saturation, certificate/credential rotation, backup restore, drain, rollback и failed migration. Runbook считается готовым только после drill другим оператором.

## 17. Release и migration contract

Preflight создаёт immutable release/capacity manifest и reconciliation snapshot. Старая и новая системы могут работать параллельно только при рассчитанной overlap capacity и ясном ownership, исключающем duplicate source pulls.

Recommended progression после lab evidence:

```text
lab -> pilot 10 -> pilot 100 -> 500 -> 1000 -> следующие измеренные waves
```

Initial rollout contract:

- canary 5%;
- soak windows 24h / 7d / 48h согласно типу wave/gate;
- old-link compatibility 30d;
- abort по SLO, auth/security breach, unexplained disconnects, saturation/headroom, reconcile drift или rollback impairment;
- решение каждой волны: `GO | HOLD | ROLLBACK` с owner sign-off.

Rollback matrix отдельно рассматривает application, DB schema, MediaMTX digest/config, cohort mapping, data, credentials и certificates.

Автоматический rollback FFmpeg clients возможен только при централизованно управляемом target: supervisor config, service discovery, DNS или cohort mapping. Cohort с hardcoded URLs блокируется до появления такого механизма. Ручная массовая правка не считается rollback strategy.

## 18. Execution order после разрешения владельца

### Phase 0 — evidence foundation

- Добавить ADR template, SLI definitions и release manifest.
- Pin versions/digests; выполнить MediaMTX API/auth/hot-update/metrics compatibility spike.
- Создать reproducible load harness; снять untuned baseline и single-node knee.
- Принять topology ADR: single node либо запустить gateway/L7 spikes.
- Выполнить initial failure/restore/security experiments, необходимые для выбора architecture.

### Phase 1 — control/data/media foundation

- #2 Foundation → #3 Data → #4 Dashboard/RBAC → #5 Reconciler → #6 Health.
- Каждая vertical slice включает migrations, contract tests, audit/security и rollback compatibility.

### Phase 2 — cross-cutting contracts

- #7 Observability, #8 FFmpeg compatibility, #9 Security.
- Полная #11 load/chaos matrix и публикация safe envelope.

### Phase 3 — operations and release

- #12 drain/deploy/PITR/runbook drills.
- #13 lab → pilot 10 → pilot 100 → controlled waves.

Параллельная работа допустима только там, где не скрывает dependency/evidence gate. Multi-node и rollout не опережают single-node capacity и compatibility proof.

## 19. Evidence registry

Полные acceptance criteria и evidence gates являются нормативной частью плана:

| Issue | Contract | Consensus |
|---|---|---|
| #1 | ADR, SLO, capacity, failure domains | [comment](https://github.com/zl0nline/RTSP_proxy/issues/1#issuecomment-5203616016) |
| #2 | Foundation/control plane | [comment](https://github.com/zl0nline/RTSP_proxy/issues/2#issuecomment-5203644293) |
| #3 | PostgreSQL data model | [comment](https://github.com/zl0nline/RTSP_proxy/issues/3#issuecomment-5194579027) |
| #4 | Dashboard/RBAC | [comment](https://github.com/zl0nline/RTSP_proxy/issues/4#issuecomment-5203578073) |
| #5 | Desired state/reconciler | [comment](https://github.com/zl0nline/RTSP_proxy/issues/5#issuecomment-5194355988) |
| #6 | Health/probes | [comment](https://github.com/zl0nline/RTSP_proxy/issues/6#issuecomment-5194293178) |
| #7 | Observability | [comment](https://github.com/zl0nline/RTSP_proxy/issues/7#issuecomment-5203665154) |
| #8 | FFmpeg compatibility | [comment](https://github.com/zl0nline/RTSP_proxy/issues/8#issuecomment-5203693281) |
| #9 | Security | [comment](https://github.com/zl0nline/RTSP_proxy/issues/9#issuecomment-5194410911) |
| #10 | Scale/topology | [comment](https://github.com/zl0nline/RTSP_proxy/issues/10#issuecomment-5194243909) |
| #11 | Performance/chaos | [comment](https://github.com/zl0nline/RTSP_proxy/issues/11#issuecomment-5203727239) |
| #12 | Operations | [comment](https://github.com/zl0nline/RTSP_proxy/issues/12#issuecomment-5203753769) |
| #13 | Release/migration | [comment](https://github.com/zl0nline/RTSP_proxy/issues/13#issuecomment-5203778377) |
| #14 | Final planning verdict | [comment](https://github.com/zl0nline/RTSP_proxy/issues/14#issuecomment-5203794735) |

## 20. Основные незакрытые execution risks

1. Фактическая capacity одного MediaMTX node неизвестна.
2. Окончательная multi-node topology не выбрана; consensus определяет порядок spikes.
3. API/auth/hot-update/metrics/drain semantics pinned MediaMTX ещё не доказаны.
4. Client rollback зависит от централизованно управляемого target.
5. Реальные OMNY/WAN/NAT/DNS/kernel/NIC и overlap старой системы могут изменить envelope.

Эти риски не отменяют готовность planning, но блокируют соответствующие implementation/release gates.

## 21. Definition of Done

Planning завершён, когда contracts согласованы — это уже выполнено. Product/release считается готовым только когда:

- оператор выполняет штатный CRUD/diagnostics без доступа к DB/MediaMTX config;
- изменение одного path не обрывает остальные, что доказано executable test;
- FFmpeg + supervisor проходит pinned compatibility matrix;
- authz/no-oracle/revoke, secrets, audit/WORM и browser leak gates зелёные;
- published capacity envelope подтверждён load/chaos evidence;
- restore, drain, rolling update, rollback и runbooks прошли drills;
- pilot exit criteria выполнены, owner дал явный GO;
- claims о 10k ограничены реально измеренным workload envelope.

До отдельного разрешения владельца следующий допустимый шаг — только решение `START PHASE 0`, изменение scope либо сохранение `NO-GO`.
