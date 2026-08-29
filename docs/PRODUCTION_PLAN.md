# Production-план RTSP Proxy

> Актуализировано 13 августа 2026 года по owner consensus и текущим телам
> [issues #1–#14](https://github.com/zl0nline/RTSP_proxy/issues).
>
> **ARCHITECTURE: BOUNDED MEDIA NODES · IMPLEMENTATION: IN PROGRESS ·
> PRODUCTION: NO-GO UNTIL EVIDENCE**

Этот документ — нормативный план продукта и реализации. Он заменяет прежнюю
гипотезу «один MediaMTX до 10k, затем gateway/L7». Текущая topology выбрана
владельцем: один Linux-сервер содержит несколько независимых MediaMTX nodes,
каждая ограничена 100 зарегистрированными камерами и собственным внешним RTSP
портом. Исторические issue comments и research notes не применяются там, где
они противоречат этому документу и актуальным телам issues.

Документ не утверждает, что product behavior уже реализован или что один сервер
обязательно выдержит 50/100 nodes. Такие характеристики появляются только после
воспроизводимых испытаний на конкретном hardware profile.

## 1. Иерархия решений

Приоритет источников:

1. Accepted ADR и явно приложенные evidence-артефакты.
2. Этот production-план.
3. Актуальные тела GitHub issues #1–#14.
4. README и эксплуатационная документация.
5. Исторические comments/research notes.

При изменении решения одновременно обновляются ADR, issues, план, README,
runbooks и executable tests. Нельзя молча ослабить лимит, SLO или security
boundary.

Численные значения имеют разный смысл:

- **hard product invariant** — например 100 registered cameras/node;
- **configuration limit** — default `max_nodes=50`, configurable до 100;
- **SLO** — пользовательский/эксплуатационный target;
- **evidence gate** — pass/fail испытания;
- **capacity envelope** — измеренная комбинация workload и hardware.

## 2. Цель продукта

Система скрывает private camera endpoint и source credentials за ordinary RTSP
endpoint выбранной media node:

```text
rtsp://<downstream-user>:<downstream-password>@<server>:<node_port>/<public_id>
```

Consumer выполняет стандартные DESCRIBE/SETUP/PLAY/TEARDOWN и считает endpoint
обычной RTSP-камерой. Proxy-specific protocol, redirect, RTSPS scheme или
дополнительный gateway handshake отсутствуют. Если канал недоверенный,
confidentiality обеспечивает внешний VPN/private L3 transport без изменения
`rtsp://`.

Control plane должен:

- управлять всеми nodes одного Linux-сервера;
- автоматически или вручную размещать cameras;
- не превышать 100 зарегистрированных cameras/node;
- управлять жизненным циклом node, drain, move и port change;
- агрегировать health/statistics всех nodes;
- применять IP allowlist до camera login/password;
- допускать только одного downstream reader/camera;
- уведомлять по email об аварии и восстановлении node;
- не участвовать в RTP forwarding.

## 3. Термины и invariants

### 3.1 Server

Один поддерживаемый Linux host. На нём работают control plane, PostgreSQL и
media nodes. Multi-server cluster, автоматический failover и межсерверная
миграция не входят в текущую версию.

### 3.2 Media node

Один independently managed MediaMTX runtime:

- отдельный process и systemd instance;
- отдельный generated config, runtime directory и log identity;
- один внешний RTSP listener port;
- loopback-only management API/metrics ports;
- не более 100 registered cameras;
- отдельный media failure domain.

Node может содержать 0..100 камер. Распределение 50/10/80/100 валидно.

### 3.3 Camera и placement

Camera — catalog record одного source path. Registered camera считается в
лимите независимо от enabled/active/occupied состояния. Camera имеет ровно одну
current placement на node.

Move создаёт новую placement generation. Поскольку внешний порт принадлежит
node, move может изменить URL. Transparent routing/redirect не обещается.

### 3.4 Occupied stream

Path занят, если у него есть один active downstream reader. Второй reader не
ждёт slot и получает RTSP `453 Not Enough Bandwidth`. После TEARDOWN/disconnect
slot освобождается.

### 3.5 Drain

Drain запрещает новые downstream sessions и новые placements на node, но
сохраняет текущий reader до disconnect/deadline. Forced completion требует
явного подтверждения и имеет показанный blast radius.

## 4. Scope и non-goals

В scope:

- Python 3.12, FastAPI, Jinja2/HTMX, PostgreSQL;
- pinned MediaMTX/FFmpeg/ffprobe;
- ordinary RTSP interleaved TCP снаружи и до source;
- on-demand source pull;
- node registry, port allocator, lifecycle и config generation;
- automatic/manual placement и camera moves;
- internet/local CIDR policies и per-camera downstream credentials;
- dashboard, RBAC, audit, metrics, probes и email incidents;
- direct Linux systemd deployment на amd64/arm64;
- load/chaos, backup/restore, rollback и pilot.

Не входят:

- Docker/Kubernetes/container runtime;
- RTSPS/TLS listener и UDP/multicast media;
- multi-server cluster, gateway tier и единый внешний порт;
- automatic camera failover/migration при node failure;
- сохранение TCP session при restart/forced move;
- более одного downstream reader/camera;
- NVR/archive, transcoding, HLS/WebRTC;
- публичный third-party integration API.

## 5. Logical architecture

```text
Operator browser
      |
      | HTTPS, management LAN
      v
Dashboard / Control API ---------> PostgreSQL
      |                               |
      +-> outbox / workers            +-> nodes / cameras / placement
      +-> reconciler                  +-> ACL / credentials / audit
      +-> metrics collector
      |
      +---- loopback ----> Media node A: RTSP :p1 -> cameras A
      +---- loopback ----> Media node B: RTSP :p2 -> cameras B
      +---- loopback ----> Media node N: RTSP :pN -> cameras N

External consumer -------- RTSP/TCP :pN/<public_id> --------^
```

Python не проксирует, не декодирует и не транскодирует media. Для каждой node
control plane знает stable node id и внутренние API/metrics endpoints. Browser
никогда не обращается к MediaMTX API напрямую.

## 6. Node configuration

### 6.1 Global settings

Typed schema включает минимум:

```text
max_nodes = 50                 # 1..100
node_port_range_start
node_port_range_end
node_port_reserved = [...]
node_management_freshness_seconds = 30
management_https_bind
mediamtx_api_loopback_range
mediamtx_metrics_loopback_range
drain_default_timeout
smtp settings / recipients
```

Validation fail-fast:

- `max_nodes` вне 1..100;
- пустой/перевёрнутый/слишком маленький port range;
- пересечение external range с internal/control/reserved ports;
- unknown config keys;
- non-loopback node API/metrics bind;
- architecture/release manifest mismatch.

### 6.2 Per-node desired config

- stable UUID/node id и display name;
- external RTSP port;
- internal API/metrics ports;
- desired lifecycle/admin state;
- config generation and applied generation;
- maintenance/drain policy;
- pinned MediaMTX release id.

Config генерируется во временный root-owned file, полностью валидируется и
атомарно активируется. Secret material не пишется в world-readable config.

### 6.3 Config mutation classes

| Class | Examples | Behavior |
|---|---|---|
| live-control | UI limits, email routing | typed reload |
| reconcile-path | camera source/auth/ACL | target path CRUD, no restart |
| restart-node | external port/listener/transport | drain/force + only this node restart |
| restart-control | DB pool, HTTPS bind | control-plane rolling restart |

## 7. Port allocation

### 7.1 Automatic

1. Read allowed range and exclusions.
2. Lock allocation namespace/rows in PostgreSQL.
3. Compute DB-free candidate set.
4. Select candidate randomly, not lowest-first.
5. Reserve by unique constraint.
6. Verify host bindability before activation.
7. On race/conflict perform bounded retry.
8. If exhausted, return `нет свободных портов для регистрации новой ноды`.

Random selection is placement policy, not a security primitive. Testability is
provided by an injected random-choice boundary.

### 7.2 Manual/change

Manual port must be in range, not reserved, unique in DB and bindable. Port
change follows:

```text
VALIDATE -> DRAIN or FORCE -> STOP -> RESERVE/SWAP -> GENERATE
-> START -> RTSP SMOKE -> COMMIT
```

Failure after stop rolls back to previous reserved port/config when possible.
Port is not reusable until old listener is proven stopped and DB transition is
committed.

## 8. Node placement

### 8.1 Eligibility

Eligible automatic/manual target:

- desired/runtime state is RUNNING;
- health green and management observation newer than the configured
  DB-clock freshness deadline;
- not maintenance/draining/deleting;
- registered count <100;
- current release/config compatible.

### 8.2 Automatic selection

Default policy:

1. minimum registered camera count;
2. minimum active source count;
3. stable node id.

Selection and admission use a transaction/lock and recheck count before
commit. Runtime active count is only a tie-breaker; correctness never depends
on a stale metric.

If eligible target is absent, auto placement may create a new node if:

- current node count < `max_nodes`;
- a free external port exists;
- process/config provisioning succeeds.

Otherwise the API returns a typed `node_capacity_exhausted`,
`max_nodes_reached` or exact no-free-port error.

### 8.3 Manual selection

Operator may choose a specific eligible node. Capacity 100 is never bypassed.
Maintenance/admin workflows may prepare a stopped target only through a
separate privileged command; ordinary create never silently selects it.

## 9. Node lifecycle

Canonical states:

```text
PROVISIONING -> STOPPED -> STARTING -> RUNNING
RUNNING -> DRAINING -> MAINTENANCE/STOPPING -> STOPPED
STARTING/RUNNING/... -> FAILED
STOPPED/FAILED + zero cameras -> DELETING
```

Every transition has desired state, observed state, generation, actor, reason,
deadline and audit record.

### 9.1 Operations

- **Create:** reserve port, persist node, generate config, start, smoke, RUNNING.
- **Start:** reject stale config/release/port collision, then smoke.
- **Stop:** requires drained/no readers or force confirmation.
- **Restart:** scoped to node; same drain/force rule.
- **Maintenance:** removes node from placement and new-session admission.
- **Port change:** disruptive restart of all streams on node.
- **Delete:** only empty and stopped/failed; release port after cleanup proof.

### 9.2 Failure

FAILED node keeps camera placements unchanged. No auto migration/failover.
Incident lifecycle and message delivery are independent state machines:

```text
incident:          HEALTHY -> OPEN -> RECOVERED -> CLOSED
failure delivery: NOT_REQUESTED -> PENDING -> SENT | FAILED_FINAL
recovery delivery: NOT_REQUESTED -> PENDING -> SENT | FAILED_FINAL
```

Recovery can be recorded regardless of failure-email delivery outcome. If both
messages are pending, outbox ordering preserves failure-before-recovery. Every
message has its own stable dedupe key and bounded delivery retries. A recovery
message identifies the incident and failure-delivery outcome; recurring outage
reminders are forbidden.

SMTP is an at-most-once submission boundary rather than a false exactly-once
claim: every claim durably consumes one attempt and carries a lease token. If a
worker dies after relay acceptance but before durable completion, the message
becomes `FAILED_FINAL/notification_delivery_ambiguous` and is not submitted
again. The stable Message-ID/dedupe key supports relay/operator correlation;
the recovery message reports the terminal failure-notification outcome.

## 10. PostgreSQL model

### 10.1 Core entities

- `media_nodes`;
- `cameras`;
- `camera_placements` and append-only placement history;
- `camera_access_policies`;
- `camera_credentials` / secret references;
- `reconcile_targets/jobs`;
- `groups/memberships`;
- `probe_observations`;
- `notification_incidents`;
- `audit_events` and transactional outbox.

### 10.2 Database invariants

- unique external node port;
- one current placement/camera;
- max 100 camera placements/node enforced transactionally;
- delete node blocked by FK/current placement;
- canonical `public_id`: lowercase base32, 26 chars, ≥128-bit CSPRNG,
  non-reserved and permanently tombstoned;
- optimistic revisions on nodes/cameras/access policies;
- normative desired state, audit and outbox in one synchronous transaction.

Telemetry may use a different durability policy. Normative audit is never
`synchronous_commit=off`.

### 10.3 Secrets

Camera source secrets use envelope encryption/key versions. Downstream
passwords use a slow salted verifier or high-entropy generated secret with
one-time display. Raw secrets never enter audit/outbox/log/metrics/SSE.

## 11. Control API and dashboard

### 11.1 Public application seams

Tests and clients observe only:

- HTTP control API for node/camera commands and queries;
- Linux process adapter for systemd/process lifecycle;
- Media-node adapter for pinned MediaMTX API;
- ordinary external RTSP endpoint;
- PostgreSQL behavior through application commands.

Private repository/helper call order is not a contract.

### 11.2 Node API

- list/detail/create;
- automatic/manual port;
- start/stop/restart;
- drain/maintenance/force;
- port change;
- delete empty;
- health/stats/incidents.

### 11.3 Camera API

- create with auto placement default or manual node;
- edit/enable/disable/delete;
- move ordinary/forced;
- rotate downstream credentials/public id;
- internet/local CIDR policy;
- current endpoint and occupied state.

Disruptive commands require a short-lived confirmation token bound to current
revision and exact blast radius. Stale revision returns 409 with a safe diff.

### 11.4 Dashboard

- server capacity/port overview;
- all nodes with state, cameras, active/occupied counts and resources;
- node detail/actions;
- camera catalog/groups/search/filter;
- placement/move/ACL/auth forms;
- incident and email delivery status;
- keyset pagination and bounded metric queries;
- keyboard/focus/contrast/semantic status accessibility.

Management UI/API listens only on configured management interface and HTTPS.

## 12. Camera lifecycle and move

Camera create/update/delete A uses targeted path config and must not restart
node or interrupt B..N.

### 12.1 Move saga

```text
VALIDATE
-> PREPARE_TARGET
-> VERIFY_TARGET
-> CLOSE_TARGET_ADMISSION
-> QUIESCE_AND_RECHECK_SOURCE
-> SWITCH_PLACEMENT
-> DELETE_SOURCE_PATH
-> ACTIVATE_TARGET
-> COMPLETE
```

- Unoccupied camera may move immediately.
- Occupied ordinary move returns conflict.
- Forced move requires confirmation and disconnects current reader.
- Response includes old/new node, port and URL.
- Target capacity is rechecked inside switch transaction.
- Crash recovery leaves exactly one current placement and converges cleanup.

Because there is no gateway, seamless endpoint switch is not promised.

## 13. Reconciler and MediaMTX adapter

One active logical writer per node. Writer obtains PostgreSQL advisory/session
lock, reads node inventory and performs minimal convergent writes.

Apply sequence:

1. Verify node id, pinned version/API and generation.
2. Read configured path state.
3. Compare normalized desired state.
4. Replace/delete only target path.
5. Read configured state back synchronously.
6. Observe runtime state asynchronously.
7. Commit applied revision with fencing condition.
8. Unknown outcome -> read-back and forward repair.

Configured state and runtime ready/readers are separate. On-demand path with no
reader may be correctly configured and idle.

Startup rebuild is bounded by 100 paths/node. A node is not RUNNING-ready until
required platform config and registered path set are applied.

## 14. RTSP/media contract

- `rtsp://server:<node_port>/<public_id>`;
- RTSP interleaved TCP only on both legs;
- MediaMTX pulls source on demand;
- no consumer knowledge of proxy/source credentials;
- one downstream reader/path;
- second concurrent reader receives RTSP 453;
- after reader exit, a later reader can acquire slot;
- new sessions denied during drain;
- existing session continues during drain;
- restart/port change/forced move disconnects only affected node/path;
- camera CRUD on A preserves RTP progress of B.

Pinned native tests cover H.264/H.265, cold/warm, source offline/recovery,
simultaneous connects, ACL/auth and absence of media UDP sockets on amd64/arm64.

Pinned upstream MediaMTX v1.20.0 does not natively produce both exact 453 and a
race-safe non-disruptive admission fence. The product therefore builds
`v1.20.0-rtsp-proxy.3` from exact commit
`1b943637a4b5778bb929a7af7687b048fecaa03f` plus the reviewed SHA-256-bound
patch in `patches/mediamtx-v1.20.0/` and a narrowly scoped, SHA-256-bound
gortsplib v5.6.3 race fix plus a separately hash-bound deterministic regression.
The production patches make `maxReaders` a synchronous hot-only
update, keep an established session alive, map late SETUP to 453, and serialize
the RTSP RECORD state transition against metrics reads. The build proves stock
v5.6.3 fails the exact regression, then runs the patched dependency and
MediaMTX race tests before each architecture build. If this contract stops
applying, another bounded admission mechanism must be accepted and proven;
silently returning another code is not acceptable.

## 15. Access control and auth

Each camera access policy contains two independent normalized CIDR sets:

- `internet`;
- `local`.

Authorization order:

1. Observe TCP peer address directly.
2. If both sets empty, pass IP stage.
3. Otherwise require membership in at least one configured set.
4. Only then verify camera username/password.
5. Acquire the single-reader slot.

Forwarded headers are ignored. Unknown path, denied IP, unknown username and
wrong password use a stable no-oracle response shape allowed by the pinned RTSP
contract. Metrics classify reasons internally without exposing them to client.

Plain RTSP is unencrypted. Internet use without trusted/private L3 or an
explicit accepted risk is production NO-GO.

## 16. Health and probes

Health has independent layers:

- control/dependency readiness;
- node process/API/metrics/listener health;
- configured path convergence;
- source probe health;
- occupied reader/session progress.

Routine `path_probe` must not consume the only downstream reader slot. It runs
only when unoccupied or uses a pinned non-reader observation mechanism.
Scheduler has global server, per-node and per-site limits, jitter, fairness,
deadline aging and bounded subprocess isolation.

Node FAILED suppresses retry storms. Recovery triggers one bounded smoke and
the recovery incident transition.

## 17. Observability and email

### 17.1 Node/server signals

- node count/max, used/free ports;
- desired/observed state and freshness;
- registered/enabled/active/occupied counts;
- CPU/RSS/FD/sockets/ephemeral ports;
- NIC bytes/packets;
- restarts, reconcile queue/lag/errors;
- port allocation and capacity failures.

### 17.2 Camera signals

- assigned node/port;
- desired/applied revision;
- source ready, reader 0/1, bitrate/progress;
- connect/ACL/auth/453 counters;
- probe freshness/result;
- move/drain status.

Credentials, raw source URLs, client IPs and unbounded errors are forbidden in
labels.

### 17.3 Email semantics

Node outage produces one email per incident. No periodic reminder. Recovery
produces one confirmation. Outbox/dedupe state survives process restart; SMTP
retry is bounded and observable.

## 18. SLO and capacity

### 18.1 Initial SLO

| Metric | Target |
|---|---:|
| Warm DESCRIBE->PLAY p99 | <=500 ms |
| Cold proxy overhead p99 | <=1 s |
| Cold end-to-end | informative <=1 s + GOP_max |
| Catalog read API p99 | <=200 ms |
| CRUD/node command p99 | <=1 s |
| Control availability | >=99.5% / month |
| Established media availability | >=99.0% / month |
| Camera CRUD unrelated interruption | 0 |
| Cross-node lifecycle interruption | 0 |
| Second reader result | RTSP 453 |
| Hard-resource headroom | >=30% |
| Candidate soak | 24 h |
| PostgreSQL PITR RPO | <=5 min |
| Control-plane recovery RTO | <=30 min |

Warm/cold/error distributions are separate. Cold waits for random-access unit;
GOP component is reported separately from proxy overhead.

### 18.2 Per-node qualification

Ladder:

- registered 1/10/50/80/100;
- active sources 10/50/100;
- readers 10/50/100 with max one/path;
- H.264/H.265, representative audio;
- 1/2/4/8 Mbit/s and GOP profiles;
- warm/cold, churn/burst, source outage;
- camera CRUD and reader race.

### 18.3 Per-server qualification

Node ladder 1/5/10/25/50. Optional 100 only after config/port range change and
evidence. Include balanced and uneven occupancy, simultaneous process count,
collector/reconciler/DB overhead and lifecycle isolation.

No per-node cgroup quotas are required in baseline. Therefore capacity decision
is based on server aggregate plus per-process attribution. `max_nodes=50` is a
configuration default, not proof that any host can run 50 fully active nodes.

### 18.4 Gates

- every hard resource <70% over representative window;
- RSS slope <=1%/h, no FD/session/port leak;
- clean profile proxy-added RTP loss = 0;
- no interruption outside intended path/node;
- one failure/recovery notification record per incident, with at-most-once SMTP
  submission and explicit ambiguous terminal outcome;
- raw evidence binds commit, binaries, config, hardware, clock and workload;
- amd64/arm64 functional equality, capacity published per hardware profile.

## 19. Direct-Linux deployment

Immutable layout:

```text
/opt/rtsp-proxy/releases/<release-id>/
/opt/rtsp-proxy/current -> releases/<release-id>
/etc/rtsp-proxy/control-plane/
/etc/rtsp-proxy/nodes/<node_id>/mediamtx.yml
/etc/rtsp-proxy/nodes/<node_id>/management.json
/etc/rtsp-proxy/nodes/<node_id>/runtime.env
/var/lib/rtsp-proxy/nodes/<node_id>/
```

Systemd:

- control API and background role units;
- `rtsp-proxy-media@<node_id>.service` instance unit;
- dedicated non-login users/groups and tmpfiles/sysusers;
- hardening: NoNewPrivileges, ProtectSystem/Home, PrivateTmp, bounded writable
  paths, AF/syscall/capability restrictions.

Media process should not mutate release/config. Root/helper boundary performs
strict allowlisted instance operations requested by control plane; browser/web
never receives arbitrary systemctl authority.

Each media instance uses `DynamicUser`, a systemd credential copy of its own
config and a release-specific absolute MediaMTX path stored by the root helper.
Per-node random Basic credentials protect loopback API/metrics; the process
never receives another node's credential file. Helper requests have a bounded
deadline and all lifecycle commands for one UUID are serialized by a
PostgreSQL advisory lock and exact desired revision. Lifecycle lock acquisition
uses a replica-local bounded pool and timeout; startup convergence runs with the
same configured concurrency instead of serially multiplying one unhealthy-node
deadline across the server. Contention on an existing node is a typed retryable
`node_lifecycle_busy` response, never a generic 500 or false state conflict. If
manual create has already committed its reservation when provisioning meets
contention, create returns `201` with that `PROVISIONING` node and its
`Location`; the operator continues through the node's start endpoint instead of
retrying create and reserving another port.

## 20. Operations

Required runbooks:

- create/start/stop/restart node;
- drain/force and stuck reader;
- port change/rollback;
- no free ports/max_nodes;
- move ordinary/forced;
- delete-empty;
- node failure/recovery with no auto migration;
- reconcile drift/orphan/missing paths;
- DB/PITR restore and report-only reconcile;
- SMTP outage/dedupe;
- resource/FD/NIC saturation;
- release upgrade/rollback.

Control-plane update must not restart media nodes. MediaMTX update proceeds one
drained node at a time. Restore regenerates configs and validates current host
ports before any node start.

The supported one-server topology has no automatic PostgreSQL failover.
Normative desired/audit/outbox writes still use synchronous durable
transactions on the active database, while disaster recovery is a separate
PITR target: RPO <=5 minutes and control-plane RTO <=30 minutes.

## 21. Implementation roadmap

Каждая фаза выполняется как vertical slice: failing public test -> minimal
implementation -> refactor -> full gates -> Standards/Spec review -> fixes.

### Phase A — consensus and specifications

- [x] Rewrite issues #1–#14 for bounded-node topology.
- [x] Update production plan, README, domain language and ADR.
- [x] Review documentation for stale single-port/gateway claims.

Exit: one non-contradictory normative model.

### Phase B — node registry and placement foundation

- [x] extend typed settings (`max_nodes`, port range/exclusions);
- [x] packaged PostgreSQL/Alembic foundation and migration runner;
- [x] `media_nodes`, `cameras`, current/append-only placement,
  audit/outbox migrations;
- [x] random/manual port allocator with bounded recheck and race tests;
- [x] node create/query commands with desired/applied revisions;
- [x] separate revisioned desired transitions from expiring runtime
  observations;
- [x] auto/manual placement onto already provisioned eligible nodes, full
  eligibility and 100-camera admission;
- [x] control API endpoints and error contracts.

Exit: API tests prove max_nodes, port exhaustion/collisions, deterministic
least-loaded placement and no 101st camera.

Status: **COMPLETE**. Implementation and independent Standards/Spec reviews
passed; all six native amd64/arm64 jobs are green in
[CI run 31547513916](https://github.com/zl0nline/RTSP_proxy/actions/runs/31547513916).
Source credentials remain fail-closed until the encrypted secret-reference
slice; this Phase B code never persists URL userinfo/query tokens. The binary
and release manifest are bound to the packaged Alembic head named by the
current phase; startup rejects any older or newer live database revision.

### Phase C — per-node Linux runtime

- [x] per-node config renderer and secure directory layout;
- [x] systemd instance unit and narrow process adapter;
- [x] create/start/stop/restart/health smoke;
- [x] automatic missing-target reservation -> provision -> smoke -> camera
  placement, with no placement committed before provisioning success;
- [x] unique loopback API/metrics allocation;
- [x] node lifecycle persistence/recovery;
- [x] native two-node isolation test amd64/arm64.

Exit: lifecycle operation on node A cannot change node B PID/listener/RTP.

Status: **COMPLETE**. Independent Standards/Spec reviews passed and all six
native amd64/arm64 jobs are green in
[CI run 31565179680](https://github.com/zl0nline/RTSP_proxy/actions/runs/31565179680).
The control plane uses one bounded
Unix-socket command for an exact UUID; its absolute deadline leaves a reserved
cleanup window, same-node requests serialize and different nodes use a bounded
worker pool. The cleanup reserve exceeds the media unit stop timeout and keeps a
separate final status/listener-proof budget. The root helper accepts only pinned
port ranges and current-or-optionally-previous catalogued patched release
identity and translates it to one systemd instance. Config is
installed with no-follow directory descriptors and fsync/rename. A healthy
runtime observation binds PID, `/proc` start ticks, boot id, config SHA-256,
release and desired revision. Automatic placement is serialized across
PostgreSQL requests, requires `applied_revision == desired_revision`, and
commits no camera before provision + API/metrics/plain
RTSP/TCP smoke succeeds. A failed provision leaves an empty FAILED automatic
node that can be retried; it never creates a ghost camera placement.

Management and path-scoped runtime-reader credentials are different root-only
secrets. The native isolation contract gates on first decodable AU and proves
RTP packet progress after restart and stop of the other node. Startup recovery
observes every node independently and converges persisted RUNNING/STOPPED
intent after host reboot. Empty-node rolling activation drains/stops one node,
performs a revision-fenced release transition, then starts/smokes it. The
Phase-E non-empty `.1 → .2` migration instead uses blast-radius-confirmed
reconfigure and retains every camera/public path. `.1` is historical provenance,
not rollback, because it lacks callback-compatible management auth. A future
compatible previous-release entry must be independently proven before rollback
is enabled; stock v1.20.0 is never rollback. Recovery is bounded-parallel; one
slow node does not delay observation/convergence of every
other node, and PostgreSQL advisory-lock connections are capped per replica.
Recovery re-reads current desired state while holding the same-node lifecycle
guard across observe, decision and convergence, so stale startup snapshots
cannot overwrite a newer operator STOP/release intent.

The native test runs two real systemd MediaMTX instances, maintains an ordinary
RTSP/TCP reader and RTP packet progress on node B while node A is restarted and
stopped, and binds each process to the pinned executable digest. Exec identity
and listener teardown use bounded convergence; completed TCP `TIME_WAIT` is not
misclassified as a live listener.

The Phase-B-to-Phase-C `0005_node_runtime` migration is deliberately
fail-closed when the old registry is non-empty: the old rows have no trustworthy
management-port, release digest or per-node credential identity. Operators must
export camera intent, drain/remove old node rows, migrate, then recreate nodes
through the Phase-C provision path. The migration never fabricates runtime
identity or silently remaps ports.

The Phase-C-to-Phase-D `0009_camera_move_safety` migration is likewise an
offline, fail-closed boundary. It rejects a non-empty node registry because a
legacy node cannot prove that it runs the patched, non-disruptive admission
fence. Use the private canonical/checksum-bound export while still on `0008`,
drain/delete cameras, stop/remove all node rows, back up PostgreSQL, migrate,
activate the catalog-bound release, then run the transactional idempotent
restore. It enforces the current max-node, port-range/reservation and listener
availability policy before its synchronous desired/audit/outbox transaction,
continues normative node revisions, preserves camera UUIDs, permanent
tombstones, immutable `/<public_id>` paths and stable desired lifecycle/admin
state. Transitional node state blocks export; restore never promotes a stopped,
failed or maintenance node to running. It is not exposed over HTTP. Editing
legacy release digests in place is forbidden.

### Phase D — camera reconciler and move

- [x] node-aware MediaMTX client factory;
- [x] per-node writer lock/inventory/reconcile;
- [x] camera CRUD targeted path updates;
- [x] occupancy observation;
- [x] drain/maintenance placement fencing; new-session admission follows in
  Phase E;
- [x] move saga and forced confirmation;
- [x] source/target writer guards, admission fence, current-reader recheck,
  inaccessible prepared target and bounded abort/restore cleanup;
- [x] persisted old/new move ports and URLs;
- [x] source-update/disable/delete confirmation bound to current reader count,
  desired revision and exact mutation digest;
- [x] absolute helper deadlines, cancellation-aware PostgreSQL writer-lock
  waits and cooperative reconciler shutdown;
- [x] versioned MediaMTX trust catalog with historical `.1` provenance and an
  optional separately verified callback-compatible previous activation entry;
  current `.2` has no rollback target;
- [x] checksum-bound Phase-C→D export/restore preserving UUIDs/public paths,
  stable node intent, current host policy, synchronous durability and monotonic
  revision;
- [x] port-change rollback/recovery and delete-empty;
- [x] port-change confirmation bound to desired revision, camera count and
  exact `camera_id:placement_generation` SHA-256; the persisted saga rechecks
  that blast radius under the placement lock and fences camera mutations.

Status: **complete**. All six jobs in the
[native amd64/arm64 Phase-D CI run](https://github.com/zl0nline/RTSP_proxy/actions/runs/31658505374)
passed, including the real systemd two-node/RTP-isolation contract.
The review cycle found and closed the move occupancy TOCTOU, duplicate prepared
target, missing writer guards, stale helper request and disruptive CRUD gaps.
Ordinary camera CRUD never restarts a node. Port change is intentionally disruptive only to that node,
retains its credentials, waits for the old listener to disappear, and commits
the new endpoint only after runtime evidence. Crash recovery rolls an
incomplete saga back to its old port. Delete stops the exact empty node,
verifies listener teardown and removes only its owned config directory before
the registry row and port are released.

Exit: contract tests prove CRUD isolation, crash convergence and exact blast
radius. The native systemd contract executes node-scoped CRUD, cross-node move,
port change and empty-node delete while an unaffected RTSP/TCP reader continues
to receive RTP; CI runs it on amd64 and arm64.

### Phase E — access and one-reader contract

- [x] access policy/grant schema and API (operator dashboard is implemented in Phase F);
- [x] IPv4/IPv6 CIDR normalization;
- [x] ACL-before-password verifier;
- [x] one-time URL-safe downstream credentials, versioned pepper,
  explicit temporary/service kind, server-derived bootstrap creator/last-use
  metadata, rotation/revoke
  and no plaintext database/audit value;
- [x] dedicated loopback callback with per-node HMAC Basic identity, exact
  node/path binding, bounded body deadline and no positive decision cache;
- [x] integrate the Phase-D exact-453 admission primitive with ACL/auth/drain;
- [x] prove simultaneous reader admission remains race-safe;
- [x] bounded callback/global, per-peer and per-grant admission plus uniform
  malformed/oversized/overload denial, per-peer pending cap and a bounded
  auth-only PostgreSQL statement/connect budget;
- [x] dual-key pepper rotation with revision-fenced rehash-on-use;
- [x] bounded redacted decision-event seam for internal audit/metrics;
- [x] authenticated per-node API/metrics/runtime probe before callback fallback;
- [x] idempotent least-privilege PostgreSQL auth-role grants and native denial
  of control-plane camera mutation;
- [x] drain + blast-radius-confirmed reconfigure/restart + resume workflow for
  existing nodes, preserving their external port and registered cameras;
- [x] Phase-D transition restore creates the required allow-all access-policy
  row and normative event for every restored camera;
- [x] ordinary FFmpeg H.264/H.265 contract tests;
- [x] additive host/L4 per-node, per-peer and SYN connection controls for the
  configured node-port range;
- [x] independent security/RTSP review and native amd64/arm64 CI.

Status: **complete**. Independent Spec and Standards reviews are PASS. All six
jobs in the
[native amd64/arm64 Phase-E CI run](https://github.com/zl0nline/RTSP_proxy/actions/runs/31689056322)
passed at commit `0ffdffbfd7030ed1a8bf85a1a921af0033ddc61a`, including real
PostgreSQL migration, owned nftables reconciliation, patched MediaMTX,
H.264/H.265 auth/ACL/revoke/single-reader behavior and systemd node isolation.
This closes the functional access/security phase only; Phase F dashboard/email
and Phase G hardware capacity/soak remain Production NO-GO gates.

Migration `0010_camera_access` creates normalized
internet/local policy and revocable grant state. Media nodes call the exact
loopback `/internal/v1/media-auth/<node-id>` route; unknown canonical paths use
the reserved matcher and reach the same empty-401 path. Policy lookup checks
camera placement plus RUNNING/non-maintenance node state, evaluates observed
peer IP before reading a grant, and verifies a generated high-entropy token by
constant-time HMAC-SHA-256. Creation explicitly chooses `temporary` or
`service` and expiry; rotation also requires an explicit replacement lifetime,
so there is no implicit unattended-client TTL. Authenticated Phase-F writes
derive creator from the operator account; the compatibility seam uses the
fixed server-side `bootstrap-control-plane` principal, never caller input. The
raw token is a one-time API response and is never stored
or emitted to audit/outbox. Safe creator/last-use fields remain queryable;
failed last-use persistence is visible at the auth service's loopback-only
`/internal/v1/metrics` endpoint; its labels are limited to bounded
reason/action/protocol/family classes.

There is deliberately no positive/negative authorization cache, so new-session
revoke, ACL and drain take effect on the next callback. Established sessions
continue when the callback/DB is down or the grant is revoked; the patched
MediaMTX owns occupancy and exact 453 atomically. A bounded callback in-flight
gate, global request bucket, per-peer pending/rate gates and post-lookup
per-camera/grant bucket fail closed without revealing denial reason. The
generated node config pins `readTimeout: 10s`, and the pinned patch binds that
value to the RTSP library idle/request deadline so an incomplete header cannot
retain a socket past the bound. The additive nftables policy caps tracked
connections at 128 per node and per peer/node pair and admits a 100/s,
burst-200 SYN recovery wave per peer/node on IPv4 and IPv6. Its node-port
interval must equal the configured range; native syntax/loading and RTSP
behavior remain part of the Phase-E CI exit gate.

Existing `.1` nodes must be drained after the helper is switched to the `.2`
callback policy. The operator calls `POST /api/v1/nodes/<id>/reconfigure/preview`, verifies the
returned exact port/camera-count/placement digest plus target release ID and
binary SHA-256, and supplies that token to
`POST /api/v1/nodes/<id>/reconfigure`; only then does the helper atomically render,
restart and smoke the node. The desired state remains DRAINING until explicit
`POST /api/v1/nodes/<id>/resume`. A failed attempt remains fail-closed and can be
retried from DRAINING even when runtime is FAILED/STOPPED. Patched `.1` remains
historical provenance but is not callback-compatible, so the first `.1 → .2`
activation has no binary rollback target. Recovery retries `.2`; rollback stays
NO-GO until a future callback-compatible previous release is catalogued and
proven. The race-only `.2 → .3` / `0.2.0 → 0.2.1` transition now supplies the
first callback-compatible rollback pair; it does not change node config or the
ordinary RTSP contract. It never installs allow-all/static users.
Ordinary `rtsp://` interleaved TCP and the external port remain unchanged.

Exit: **met** — security/RTSP review PASS and native amd64/arm64 contracts
green. The exact evidence boundary is recorded in
[`docs/evidence/phase-e-access-security-contract.md`](evidence/phase-e-access-security-contract.md).

### Phase F — dashboard, metrics and notifications

Status: **IN PROGRESS**. The bounded collector, generation-bound per-path
metrics, persisted fleet snapshot API, incident state machine, durable SMTP
dispatcher, digest-only PostgreSQL operator sessions, authoritative
`authz_version` fencing, CSRF/RBAC HTTP boundary, browser-bound OIDC Code+PKCE
with exact MFA claims, and durable break-glass TOTP audit/email admission are
implemented locally. Live OIDC discovery/claims compatibility is polled through
bounded readiness and emits one durable failure/recovery alert per transition.
The management HTTPS slice is implemented, independently reviewed and green on
direct Linux plus native amd64/arm64 CI. WEB rejects wildcard, IPv4
limited-broadcast and
multicast binds, requires TLS for management-LAN exposure, and applies exact
HSTS even to early denials and sanitized server errors. The systemd unit passes
one immutable combined PEM through `LoadCredential`; the operator rotation
transaction is lock-serialized, durable, generation/fingerprint-bound and
rollback-verified. All seven jobs passed at commit
`32ac6138777e460846a1caed1e46174138ebc9d5` in
[CI run 33253244053](https://github.com/zl0nline/RTSP_proxy/actions/runs/33253244053),
including the real root-systemd contract on both server architectures; see
[`docs/evidence/phase-f-management-https-contract.md`](evidence/phase-f-management-https-contract.md).
The bounded live-dashboard slice is implemented, independently reviewed and
green in the full local/direct-Linux suites plus all seven native/external CI
jobs at commit `a77db2daead18cc15afa5a497fdd9c5ca1a217f0` in
[CI run 33265832444](https://github.com/zl0nline/RTSP_proxy/actions/runs/33265832444).
The overview polls only the persisted
aggregate snapshot every 10 seconds by default with a server-enforced 5–30
second range. A camera detail has one bounded SSE stream per operator session,
15-second heartbeat, authorization before replay and a shared one-second
read-only batch of session epochs; an in-memory fence runs before every state
delivery and the 750-millisecond batch deadline keeps revocation below two
seconds. History/resume, `resync_required`,
slow-client/write deadlines and bounded polling fallback. Snapshot reads and
SSE reconnects use separate durable account buckets; clients use one in-flight
request with a five-second deadline and bounded backoff. The server shares one
bounded single-flight snapshot refresh, indexes paths once per snapshot, expires
inactive channels and persists per-path bitrate derived from monotonic elapsed
time. Wall-clock observation time is freshness metadata only; counter resets,
metric gaps, missing N−1 detail and wrong-node path evidence fail closed.
Camera placement changes discard queued/history state from the previous node,
emit `resync_required` and immediately start an exact new-node epoch. One
bounded secret-free placement batch over active SSE cameras discovers the move
without another browser request. Shutdown
waits for tracked bounded snapshot/authz workers before closing their stores.
The browser never reads a media-node API or metric endpoint. The completed
probe event source is implemented by the independently reviewed Phase-G
schema-0020 foundation and is green in all seven native/external jobs in
[CI run 33273481381](https://github.com/zl0nline/RTSP_proxy/actions/runs/33273481381):
it reads only generation-fenced, secret-free durable observations. No production
source executor is enabled; privileged executor evidence plus production
load/cardinality evidence remain open. Exact live-update scope is
recorded in
[`docs/evidence/phase-f-dashboard-live-updates-contract.md`](evidence/phase-f-dashboard-live-updates-contract.md).
The camera access-administration slice is also implemented locally: it renders
the two independent internet/local CIDR policies, a bounded secret-free grant
inventory, recent-MFA issue/rotate/revoke forms and a one-time no-store RTSP
credential page. Secret-bearing issue/rotation uses session-bound UUIDv4
idempotency keys and migration 0017 commits the immutable request digest with
the grant and operator audit/outbox pair; replay never re-renders the secret.
The one-time page auto-clears in at most 30 seconds. Grant inventory reads append
a durable sanitized sensitive-read event, while independent durable
per-account `secret_issue` and `access_mutation` buckets return 429 with
`Retry-After` and a denial audit when exhausted. JSON rotation/revoke is nested
under the camera and requires the exact current grant revision. Replay,
idempotency-conflict, not-found and stale-revision rejections append their own
sanitized synchronous audit/outbox pair after rollback and fail closed when
that journal is unavailable.
The camera-registration workflow is also implemented locally. Dashboard and
JSON API accept automatic least-loaded or exact manual eligible-node placement
and require one session-scoped UUIDv4 key. Migration 0018 commits the immutable
request digest as a synchronous pending intent before any placement or node
provisioning side effect. Its complete state and resulting camera UUID commit
atomically with desired camera, tombstone, placement, default access-policy and
audit/outbox state. Replays resume or return the original camera; changed reuse
and a missing prior target produce a sanitized, durably audited 409. A separate
durable per-account `camera_mutation` bucket returns an audited 429 before any
intent is reserved. If
automatic placement must provision a node, its create/start events inherit the
original camera request's operator account, session, action and idempotency key.
During the 0.10.0/0017 bridge this write path returns a bounded 503 while
existing catalog/access/node workflows remain available. Local Chromium,
isolated direct-Linux amd64/PostgreSQL, independent review and all seven
native/external CI jobs are green at commit
`a7f2324a5354969fd773f70fc6f13b04247e51b3` in
[CI run 32743179524](https://github.com/zl0nline/RTSP_proxy/actions/runs/32743179524).
The foundation passed independent Spec/Standards review and all six native
amd64/arm64 CI jobs at commit `292a0302590838451e4f454322930804271b4d71`;
the exact evidence boundary is recorded in
[`docs/evidence/phase-f-operator-observability-foundation.md`](evidence/phase-f-operator-observability-foundation.md).
The authenticated server-rendered server/node overview and node-detail pages
passed all six native amd64/arm64 jobs at commit `808e74e121b5ed56f6626490a20bc919ab8328eb`
([CI run 31784945654](https://github.com/zl0nline/RTSP_proxy/actions/runs/31784945654)).
They use fail-closed snapshot freshness, semantic tables, keyboard focus, local
assets and strict browser security headers. A separate bounded camera-catalog
read model passed all six native jobs at commit
`3edb3026d1f2ececaebd86ddbdcebda3b32fb877`
([CI run 31790262853](https://github.com/zl0nline/RTSP_proxy/actions/runs/31790262853)).
It provides PostgreSQL keyset pagination, `pg_trgm`-indexed case-sensitive
literal search (minimum three characters), indexed node/state filters, a
two-second WEB database deadline, `control.read` authorization and no
`source_url` field. The 10k-camera contract asserts the
search plan can use the catalog index instead of relying on the page `LIMIT`.
Release 0.6.0 originally enabled the route on exact schema 0014 after canonical
read-back of the extension and all four indexes. Current release 0.7.0 runs
compatibly on 0012/0013/0014/0015 during rollout but enables catalog/detail only
on exact 0015. Migration 0015 performs a bounded fail-closed legacy-name
preflight before installing the shared 1..128/no-control-character contract; it
reports only a bounded set of non-deleted camera UUIDs, never rejected names or
source URLs. Operators remediate those rows through the revisioned camera API
while the DB remains at 0014, then retry. Immutable deleted rows have no
placement or API remediation seam; they remain permanently tombstoned, are
excluded from reads and are deliberately exempt from the display-name
constraint. Index/name drift fails closed rather than scanning or rendering
unsafe live data. After 0015 commits, rollback to an application
manifest capped at 0014 is explicitly NO-GO; recovery is fix-forward or
restoration of the pre-migration PostgreSQL backup with the control plane
stopped. Collector/worker compatibility across the declared bridge is retained.
A secret-free camera detail page using the same bounded projection passed all
six native jobs at commit `e38af30dc492984956f1bb8f55434ce9430fe127`
([CI run 31794353270](https://github.com/zl0nline/RTSP_proxy/actions/runs/31794353270)).
It shows only the ordinary `rtsp://` endpoint template, placement and revision
state. It requires `control.read` plus the exact
`camera:<uuid>` scope, while `server:*` remains the explicit global superset;
cross-camera denials are resolved before lookup and expose no existence oracle.
Server-rendered update/enable/disable/delete workflows passed all six native
amd64/arm64 jobs at commit `a6b2fd4cb1e9538dc679c581b4f1a81a5d2cb4f6`
([CI run 31805146878](https://github.com/zl0nline/RTSP_proxy/actions/runs/31805146878)).
Unsafe forms use a session-bound hidden CSRF token, a 32 KiB/eight-field/two-second
parser, exact camera scope and `control.mutate`. An unoccupied path is changed
immediately after runtime preview, but only through CAS against the revision
submitted by the rendered form. An occupied one-reader path requires the
existing short-lived revision/blast-radius confirmation; a supplied token is
always verified even if that reader disconnects before apply. Stale revisions
return a redacted 409 showing only expected/current revision. Camera names share
one 1..128-character, no-control-character contract across UI, domain,
in-memory and PostgreSQL adapters. Existing rows are admitted only by the
fail-closed 0015 preflight; catalog projection revalidates them on every read.
The new source URL is never repeated in confirmation HTML and must be re-entered
exactly. Camera routes and mutation
orchestration live in a dedicated controller/router rather than the application
composition root. The move UI passed all six native amd64/arm64 jobs at commit
`ffd12509e99fdff6336ffc5676cf3e9363b1fe66`
([CI run 31811342043](https://github.com/zl0nline/RTSP_proxy/actions/runs/31811342043)).
It lists only eligible non-full targets sorted
by load, binds preview/apply to the submitted camera revision and invalidates an
occupied-reader confirmation if its target or reader count changes. It starts
the durable move saga and redirects to a camera-scoped persisted `move_id`; the
status page reads its actual state and reports accepted—not completed. Target
enumeration uses the store's DB-clock eligibility projection and excludes
prepared source/target port changes, while the switch transaction rechecks all
conditions. The ordinary public path stays immutable while the node port
changes. Real-browser OIDC/login, keyboard focus, occupied-reader confirmation
and CSRF-protected logout E2E passed independent Spec/Standards review and the
dedicated external-client job at commit
`a6166e3aa6a6a3c6d87991d509ea126e0d48bd09`
([CI run 32676065004](https://github.com/zl0nline/RTSP_proxy/actions/runs/32676065004));
the exact evidence boundary is recorded in
[`docs/evidence/phase-f-dashboard-browser-contract.md`](evidence/phase-f-dashboard-browser-contract.md).
The real-Chromium job is an external-management-client gate and runs on amd64
because the pinned driver has no Linux arm64 browser bundle. Server-side
templates, OIDC/session, CSRF and logout contracts remain in the identical
amd64/arm64 application test matrix; this does not weaken Linux server parity.
A revision-fenced break-glass rotation CLI and
accepted/rejected notification drill passed independent Spec/Standards review
and all six native amd64/arm64 jobs at commit
`df35a2c0089564d1833c62fb65d256f09864fbde`
([CI run 32428149162](https://github.com/zl0nline/RTSP_proxy/actions/runs/32428149162)).
The shared-boundary denial-class/logout matrix, with representative semantic
targets, passed independent Spec/Standards review and all seven CI jobs at commit
`ef0e1f3fdfb74c174ac0dffa9f88213291ab19b5`
([CI run 32678955187](https://github.com/zl0nline/RTSP_proxy/actions/runs/32678955187)).
It binds an allowlisted semantic action, canonical object type/id, exact scope,
identity source, roles, session/account version and response correlation ID to
each durable audit/outbox pair without raw IP, user-agent, cookies, CSRF or URL
data. PostgreSQL fault injection proves authentication denial, authorization
denial and logout fail closed without a half-pair; logout revocation rolls back
when either normative append fails. Self-session logout is available to scoped
operators without granting `server:*`. Exact evidence is recorded in
[`docs/evidence/phase-f-operator-security-audit-contract.md`](evidence/phase-f-operator-security-audit-contract.md).
The historical recursively generated inventory exercised all 48 protected
route-method pairs, including nested included-router prefixes, and passed both
reviews plus all seven jobs at commit
`39b29814d726d9020c1d19100521b4dfe729b91e`
([CI run 32680412385](https://github.com/zl0nline/RTSP_proxy/actions/runs/32680412385)).
Future export/bulk routes remain activation-gated until they enter that
inventory and add their surface-specific security evidence.
The prior published inventory contained 57 protected route-method pairs after
the first node-action router slice. It passed independent Spec/Standards review
and all seven jobs in
[CI run 32693949200](https://github.com/zl0nline/RTSP_proxy/actions/runs/32693949200)
on commit `2f6b012d91ab4de2ad07d631f4cdfa46b2422255`.

Dashboard node registration and start/stop/drain/maintenance/resume/delete are
published and CI-green. Automatic registration selects a random free
external port from configured policy; manual registration validates the exact
requested port. Both dashboard and JSON API pass through the same
operator-attributed command seam. Every lifecycle action carries the rendered
or explicit expected `desired_revision` and source state into the synchronous
PostgreSQL transaction before any privileged runtime call. Registration uses a
session-bound UUIDv4 idempotency key and canonical request digest. Migration
0016 creates an immutable request ledger; the ledger row, desired node and
matching audit/outbox pair commit atomically. Replays return the original node,
changed payloads conflict, and deleting the node cannot make an old key create
a replacement. Release 0.8.0 remains rolling-compatible with 0015, but this
specific write path returns a bounded 503 until exact schema 0016 is current.
Exact local/Linux/review evidence is tracked in
[`docs/evidence/phase-f-node-operations-contract.md`](evidence/phase-f-node-operations-contract.md).
The last published implementation adds port-change and reconfigure preview/apply and
contains 63 route-method pairs. The published access-administration slice
brings the generated protected inventory to 70 route-method pairs. The
published camera-registration slice brings it to 72; independent review and all
seven native/external CI jobs passed at commit
`a7f2324a5354969fd773f70fc6f13b04247e51b3` in
[CI run 32743179524](https://github.com/zl0nline/RTSP_proxy/actions/runs/32743179524).
The published live-update delta brings the current generated inventory to 75
by adding one-camera snapshot/SSE and bounded live diagnostics. Independent
review, direct-Linux validation and all seven native/external CI jobs are green
at commit `a77db2daead18cc15afa5a497fdd9c5ca1a217f0` in
[CI run 33265832444](https://github.com/zl0nline/RTSP_proxy/actions/runs/33265832444).
Both
dashboard and JSON API require exact desired revision/source state. Port change
and DRAINING reconfigure/restart additionally require recent MFA plus the
complete registered-camera and active-reader sets. A RUNNING node binds exact
PID/start/boot/release; STOPPED/FAILED reconfigure binds process absence. An
empty RUNNING-node restart remains the ordinary revision/state-fenced action.
RUNNING-node confirmed apply closes admission on every
existing path without recreating absent disabled/deleting paths. One absolute
60-second fence budget allocates 50 seconds to fence/runtime/port rollback and
the final 10 seconds only to exact path restoration; the root helper still
retains its own configured cleanup reserve of at least 20 seconds. Two applies
may run concurrently per web process and excess work fails retryably before
mutation. Exact review and direct-Linux evidence is tracked in
[`docs/evidence/phase-f-node-disruption-contract.md`](evidence/phase-f-node-disruption-contract.md);
all seven native amd64/arm64 and external-browser jobs passed at commit
`466e72feb6c5401dd4b281baabc07095b7173669` in
[CI run 32708863738](https://github.com/zl0nline/RTSP_proxy/actions/runs/32708863738).
No Phase-F completion claim is made yet.

- [x] node/camera pages and actions (read-only server/node overview, bounded
  camera catalog/detail and update/enable/disable/delete CI-green; camera move
  UI CI-green; node registration and bounded lifecycle actions CI-green;
  disruptive port-change/reconfigure/restart implementation, review and native
  publication CI complete);
- [x] RBAC/CSRF/OIDC/break-glass foundation, revision-fenced rotation/drill and
  shared-boundary authentication/authorization-denial/logout classes with
  representative semantic targets;
- [x] recursively generated route-method negative matrix (the 75-route live
  surface is independently reviewed and green in direct-Linux plus all seven
  native/external CI jobs);
  future export/bulk routes must extend it before activation;
- [x] camera-scoped access dashboard/API list, two-level ACL edit and
  recent-MFA grant issue/rotate/revoke with one-time no-store secret output,
  30-second auto-clear, durable sensitive-read audit, separate action-rate
  buckets, exact revision fencing, session-bound idempotency and fail-closed
  durable rejection audit
  (local/direct-Linux validation and independent review green; application and
  patched MediaMTX/load jobs passed on amd64 and arm64, while the external
  Chromium job passed on amd64, at commit
  `9b0695605e7bf9efe00db0760d90f9906da85579` in
  [CI run 32730353917](https://github.com/zl0nline/RTSP_proxy/actions/runs/32730353917));
- [x] camera registration dashboard/API with automatic least-loaded and manual
  eligible-node placement, session-bound pending-before-side-effect schema 0018
  ledger, durable rejection audit and operator-context propagation through
  automatic node provisioning
  (implementation, local Chromium, isolated direct-Linux validation,
  independent review and all seven native/external CI jobs green at commit
  `a7f2324a5354969fd773f70fc6f13b04247e51b3` in
  [CI run 32743179524](https://github.com/zl0nline/RTSP_proxy/actions/runs/32743179524); see
  [`docs/evidence/phase-f-camera-registration-dashboard-contract.md`](evidence/phase-f-camera-registration-dashboard-contract.md));
- [x] metrics collector and bounded queries;
- [x] aggregate overview polling and one-camera SSE with bounded resume,
  pre-replay/batched pre-delivery authz epoch fencing, two-second revocation
  ceiling, backpressure/write timeout, single-flight indexed refresh,
  collector-owned monotonic per-path bitrate, durable read/reconnect buckets,
  move-scoped live epochs, fail-closed freshness/reset state, owned worker
  shutdown, resync and bounded polling fallback
  (independent review, local/direct-Linux functional evidence and all seven
  native/external CI jobs green; the schema-0020 completed-probe projection is
  a separately reviewed and CI-green Phase-G foundation, while the production
  executor and capacity evidence remain open);
- [x] incident outbox, failure email and recovery confirmation;
- [x] SMTP retry/dedupe with explicit ambiguous terminal outcome;
- [x] browser E2E for OIDC/login, confirmations, keyboard accessibility and
  logout (external Chromium client on amd64; server contract in amd64/arm64
  application jobs; independent review and dedicated CI green).

Collector helper/DB operations and notification DB operations have hard
deadlines. The collector shutdown budget remains below its 30-second systemd
stop limit for every supported interval; SMTP plus DB completion remains below
the notifier's 45-second stop limit for every supported SMTP timeout. Metrics
are accepted only when one atomic helper response binds exact process
PID/start/boot/release and the complete sorted per-path counter set.

Exit: operator workflows complete without direct DB/systemctl/MediaMTX access.

### Phase G — probes and production evidence

Status: **IN PROGRESS / PRODUCTION NO-GO**. The independently reviewed and
native-CI-green foundation implements a
bounded single-flight scheduler, hard global/per-node/per-site and independent
SOURCE/PATH caps with typed diagnostics, controlled
borrowing from the spike 4/3/3 class reservations, pending routine-to-manual
promotion, reservation-first deadline aging and bounded lease/backoff. Every claim repeats
admission from a current batch before execution; occupied/session-constrained
work is removed without a side effect; PATH is also forbidden while source pull
is active. SOURCE and PATH health stay independent,
and infrastructure/output failures are `INCONCLUSIVE`: they affect freshness,
not camera health. Schema 0020 stores only the latest immutable, DB-clock-bounded
normalized observation. PATH results additionally bind exact node applied
revision and PID/start/boot/release identity; stale placement/revision/process
results are cleared from live replay. Camera create/source update uses a bounded,
concurrency-limited Linux NSS resolver, validates every normalized A/AAAA address
against one explicit site key and its configured source CIDRs, then atomically
persists literal IP, port, site/policy digest, URL digest and an opaque endpoint
generation. The default empty CIDR set is deny-all. A policy change invalidates
prior admissions until explicit source re-registration.
Probe work carries that generation and never resolves a hostname. Admission hides credentials plus
path/query material from diagnostics, pins one literal
`rtsp://` destination and generates the pinned TCP/microsecond-timeout ffconcat
input without persisting source URL or credentials.

Re-registration is executable through the ordinary camera update seam: when
the endpoint row is missing or its policy digest differs, resubmitting the same
source URL performs a new bounded admission, increments the camera revision and
atomically replaces the endpoint generation. It is not treated as a no-op and
does not require an artificial URL change.

The completed-probe SSE/dashboard event consumes only that safe store. It does
not imply that a deployable executor exists. Research proved that a user-manager
unit is not an enforcement boundary and that `IPAddressAllow=` cannot restrict
the destination port. ADR 0004 therefore remains Proposed until a narrow root
broker, system-manager transient service, root-attached cgroup
`connect4`/`connect6` tuple guard, controlled no-redirect ffprobe build and
credential/log/cleanup canaries pass on native Linux amd64 and arm64. The fixed
4/3/3 weights and concurrency values remain spike hypotheses until media-plane
impact is measured.

- [x] bounded scheduler/result/state foundation with claim-time one-reader and
  source-session admission, controlled reservations and separate
  SOURCE/PATH/INCONCLUSIVE semantics;
- [x] additive schema-0020 durable observation and secret-free dashboard/SSE
  projection (independent Spec/Standards review PASS; all seven jobs green in
  [CI run 33273481381](https://github.com/zl0nline/RTSP_proxy/actions/runs/33273481381));
- [x] generation-bound durable resolve-once literal/site/CIDR admission, exact
  type/default/constraint/index/privilege readiness and pinned ffconcat TCP/timeout builder
  (compatibility mechanism only);
- [x] versioned exact-tuple cgroup `connect4`/`connect6` map ABI and privileged
  attach-before-release/ownership-safe cleanup contract (direct-Linux amd64,
  independent review and privileged amd64/arm64
  [CI run 33280195424](https://github.com/zl0nline/RTSP_proxy/actions/runs/33280195424)
  green; executor still disabled);
- [x] anonymous canonical ffconcat input primitive with a 16 KiB cap,
  `CLOEXEC` and immutable sealed-memfd validation (direct-Linux amd64 green;
  independent review and native amd64/arm64 CI pending; descriptor transport
  and executor still disabled);
- [ ] accept isolated probe boundary ADR 0004 after privileged native evidence;
- [ ] implement the broker/executor, periodic risk-based producer and durable
  health-state orchestration;
- per-node 100-camera matrix;
- multi-node server ladder and 24h soak;
- chaos/failure/email/restore game days;
- publish architecture/hardware-specific capacity envelope.

Exit: explicit GO/HOLD for pilot.

### Phase H — pilot

Waves: one node 10 -> one node 50 -> one node 100 -> 5 -> 10 -> 25 -> 50
nodes. Up to 100 nodes requires explicit config/evidence approval.

Every wave has soak, comparison, incident review and GO/HOLD/ROLLBACK.

## 22. Review and CI policy

After each phase:

1. run unit/integration/contract tests, Ruff, mypy, build and diff check;
2. run Standards review against repository rules;
3. run Spec review against current issues/ADR/plan;
4. fix all High/Medium findings;
5. rerun reviews and both-architecture CI;
6. update status/evidence links before starting next phase.

Native functional CI is not a capacity claim. Physical-hardware/24h evidence
cannot be replaced by mocks, emulation or generic hosted runners.

## 23. Product Definition of Done

Product is complete only when:

- nodes enforce 100 registered cameras and configured max_nodes;
- automatic/manual placement and random/manual ports are correct under races;
- ordinary RTSP/TCP URL works and second reader receives 453;
- ACL order, credentials and management boundary pass security tests;
- camera/node operations respect declared blast radius;
- drain/move/port-change/delete and failure/recovery email work end-to-end;
- dashboard aggregates all nodes on the server;
- direct-Linux amd64/arm64 install/upgrade/rollback passes;
- backup/restore and all runbooks are exercised;
- per-node and server capacity envelopes are published with raw evidence;
- no unresolved High/Medium Standards or Spec findings remain;
- owner signs production GO.
