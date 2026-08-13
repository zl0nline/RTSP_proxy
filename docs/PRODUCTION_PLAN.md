# Production-план RTSP Proxy

> Актуализировано 12 августа 2026 года по owner consensus и текущим телам
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
`v1.20.0-rtsp-proxy.1` from exact commit
`1b943637a4b5778bb929a7af7687b048fecaa03f` plus the reviewed SHA-256-bound
patch in `patches/mediamtx-v1.20.0/`. The patch makes `maxReaders` a synchronous
hot-only update, keeps an established session alive, and maps late SETUP to
453. If this contract stops applying, another bounded admission mechanism must
be accepted and proven; silently returning another code is not acceptable.

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
- incident/recovery exactly once;
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
intent after host reboot. Rolling activation drains/stops one node, performs a
revision-fenced release transition, then starts/smokes it. From the second
patched release onward, healthy old nodes stay manageable through a temporary
previous-release catalog entry. Initial release `0.1.0` has no previous patched
target and never treats stock v1.20.0 as rollback. Recovery is
bounded-parallel; one slow node does not delay observation/convergence of every
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
- [x] versioned MediaMTX trust catalog with an optional separately verified
  previous patched release; initial `0.1.0` honestly has no rollback target;
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

- access policy schema/API/UI;
- IPv4/IPv6 CIDR normalization;
- ACL-before-password verifier;
- downstream credential rotation/revoke;
- integrate the Phase-D exact-453 admission primitive with ACL/auth/drain;
- prove simultaneous reader admission remains race-safe;
- no-oracle and connection abuse controls;
- ordinary FFmpeg H.264/H.265 tests.

Exit: security/RTSP review PASS and native amd64/arm64 contracts green.

### Phase F — dashboard, metrics and notifications

- node/camera pages and actions;
- RBAC/CSRF/session/audit;
- metrics collector and bounded queries;
- incident outbox, failure email and recovery confirmation;
- SMTP retry/dedupe;
- browser E2E for confirmations and accessibility.

Exit: operator workflows complete without direct DB/systemctl/MediaMTX access.

### Phase G — probes and production evidence

- isolated probe boundary ADR 0004;
- source/path probe budgets respecting one-reader slot;
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
