# RTSP Proxy

Платформа управления RTSP-прокси на одном Linux-сервере. Media plane разбит
на независимые bounded nodes: каждая node — отдельный MediaMTX process/systemd
instance, один внешний RTSP port и не более 100 зарегистрированных камер.

> **Статус на 29 августа 2026**
>
> - Bounded-node architecture: **согласована**, issues #1–#14 обновлены.
> - Phase 0A MediaMTX/ordinary-RTSP compatibility: **complete** на native
>   Linux amd64/arm64.
> - Phase 0B reproducible load/netem harness: **functional foundation complete**;
>   production hardware capacity/24h soak ещё не выполнены.
> - Node registry/placement, isolated per-node Linux runtime, Phase-D
>   administration and Phase-E access/security: **complete on native
>   amd64/arm64 CI**.
> - Phase-F observability and operator-auth foundation: **reviewed and green in
>   native amd64/arm64 CI** — bounded fleet collector, persisted dashboard snapshot API and
>   durable failure/recovery email dispatcher, plus digest-only PostgreSQL
>   sessions, RBAC version fencing, CSRF boundary, browser-bound OIDC Code+PKCE
>   and audited break-glass password+TOTP login. Authenticated read-only
>   server/node dashboard pages and a bounded, keyset-paginated, secret-free
>   camera catalog with search/filter and a secret-free camera detail page are
>   green in native CI. Server-rendered update/enable/disable/delete workflows
>   with bounded form CSRF, optimistic revision fencing and reader-aware
>   confirmation are also green in native amd64/arm64 CI;
>   revision-fenced camera move UI is also green in native amd64/arm64 CI;
>   a revision-fenced break-glass rotation CLI and accepted/rejected delivery
>   drill are independently reviewed and green in native amd64/arm64 CI.
>   Real-browser OIDC/login, keyboard focus, occupied-reader confirmation and
>   CSRF-protected logout E2E прошёл independent Spec/Standards review,
>   isolated Linux amd64 stand и dedicated CI с browser evidence artifact.
>   The shared protected HTTP boundary also has a durable
>   authentication/authorization-denial and logout class matrix with
>   representative semantic targets:
>   identity source, scope and correlation ID are audit/outbox-bound and
>   PostgreSQL append failures fail closed without partial revocation.
>   The generated matrix now covers all 75 protected route-method pairs,
>   including camera access, camera registration, one-camera live snapshot/SSE
>   and bounded live diagnostics. The published 72-route registration slice is
>   independently reviewed and green in native amd64/arm64 CI plus the external
>   Chromium job; the 75-route live-update delta is also independently reviewed
>   and green in all seven native/external CI jobs. Future export/bulk routes must
>   extend the matrix before activation.
>   The browser is an external management client, so the real-Chromium job runs
>   on amd64 because the pinned driver has no Linux arm64 browser bundle;
>   server-side templates/OIDC/session/CSRF/logout tests remain identical in the
>   amd64 and arm64 application jobs.
> - Phase-F node operations: **independently reviewed and green in native
>   amd64/arm64 CI**. Dashboard and JSON API share one revision/state-fenced,
>   operator-attributed command boundary. Node registration uses a
>   session-scoped UUIDv4 idempotency key persisted atomically with the node and
>   its audit/outbox pair, so a lost response or repeated submit cannot allocate
>   another port or node. Schema 0016 activates this write path fail-closed;
>   all seven jobs passed in [CI run 32693949200](https://github.com/zl0nline/RTSP_proxy/actions/runs/32693949200)
>   on commit `2f6b012d91ab4de2ad07d631f4cdfa46b2422255`.
> - Phase-F disruptive node workflows: **implemented, independently reviewed
>   and green in direct-Linux plus native amd64/arm64 CI**. Port change and
>   DRAINING reconfigure/restart require recent MFA and an exact
>   camera/reader confirmation; a running process is also generation-bound.
>   Empty-node restart remains the ordinary revision/state-fenced action.
>   Admission remains fenced through the bounded runtime action;
>   timeout/rollback retains a separate path-restoration reserve. This does not
>   close Phase F or production readiness.
> - Phase-F management HTTPS boundary: **implemented, independently reviewed
>   and green in direct-Linux plus native amd64/arm64 CI**.
>   WEB rejects wildcard/broadcast/multicast binds, terminates TLS directly,
>   applies HSTS to every response and consumes one immutable combined PEM from
>   systemd `LoadCredential`; plaintext is rejected. All seven jobs passed in
>   [CI run 33253244053](https://github.com/zl0nline/RTSP_proxy/actions/runs/33253244053)
>   on commit `32ac6138777e460846a1caed1e46174138ebc9d5`, including the real
>   root-systemd contract on both server architectures. Exact evidence is
>   recorded in
>   [`docs/evidence/phase-f-management-https-contract.md`](docs/evidence/phase-f-management-https-contract.md).
> - Phase-F dashboard live updates: **implemented, independently reviewed and
>   green on direct Linux plus native amd64/arm64 CI**. Server overview
>   polls the persisted aggregate snapshot at a configurable 5–30 seconds
>   (default 10). A camera detail uses one bounded SSE stream per operator
>   session with a 15-second heartbeat, authorization before replay and a shared
>   batched epoch fence before every state delivery (one-second cadence plus a
>   750-millisecond deadline), bounded to a two-second revocation ceiling,
>   `resync_required`, slow-consumer disconnect and bounded polling fallback.
>   The browser never reads MediaMTX directly. Exact local/Linux scope and open
>   gates are recorded in [CI run 33265832444](https://github.com/zl0nline/RTSP_proxy/actions/runs/33265832444)
>   and
>   [`docs/evidence/phase-f-dashboard-live-updates-contract.md`](docs/evidence/phase-f-dashboard-live-updates-contract.md).
> - Phase-G probe foundation: **implemented locally; independent review and
>   native CI pending**. It adds a bounded single-flight scheduler with hard
>   server/node/site and separate SOURCE/PATH budgets, controlled class
>   reservations, claim-time
>   admission and reservation-safe deadline aging. PATH is forbidden while the
>   source pull is active; PATH results are fenced by exact node
>   applied-revision/PID/start/boot/release identity; schema 0020 keeps immutable,
>   DB-clock-bounded durable observations. Camera create/source-update atomically
>   stores a resolve-once, explicitly configured site/CIDR-approved literal
>   endpoint generation; an empty CIDR list is deny-all. Schema readiness
>   checks exact column types/defaults, constraint definitions, index shape and
>   privileges. The completed-probe SSE/dashboard projection is secret-free.
>   This is not a
>   production source-probe runner. ADR 0004 remains Proposed: a narrow root
>   broker, system-manager transient unit, exact cgroup `IP:port` guard,
>   no-redirect ffprobe build and privileged amd64/arm64 evidence are still
>   mandatory. See
>   [`docs/evidence/phase-g-probe-foundation.md`](docs/evidence/phase-g-probe-foundation.md).
> - Production: **NO-GO** до всех evidence gates.

Нормативная спецификация: [Production plan](docs/PRODUCTION_PLAN.md).

## Как выглядит endpoint

```text
rtsp://<user>:<password>@<server>:<node_port>/<public_id>
```

Это обычный RTSP URL. FFmpeg выполняет стандартные
DESCRIBE/SETUP/PLAY/TEARDOWN и не знает, что за endpoint находится proxy, а не
камера. Поддерживается только RTSP interleaved TCP. RTSPS, UDP/multicast и
proxy-specific redirects не входят в контракт.

Camera source address и credentials остаются внутри платформы. Для
недоверенной сети шифрование обеспечивает внешний WireGuard/IPsec/VPN/private
L3 transport, не меняющий `rtsp://` handshake.

## Node model

- Один поддерживаемый server — один Linux host.
- Одна media node — один MediaMTX process, systemd instance, config/log и
  внешний RTSP port.
- Hard limit — 100 registered cameras/node, включая disabled/idle.
- `max_nodes=50` по умолчанию, configurable до 100.
- Фактическое число nodes, выдерживаемое сервером, определяется load tests, а
  не значением config.
- Node port автоматически выбирается случайно из configured range; manual port
  тоже поддерживается.
- Если ports закончились, API возвращает:
  `нет свободных портов для регистрации новой ноды`.
- Node не обязана быть заполнена полностью: распределение 50/10/80/100
  допустимо.
- Multi-server cluster и automatic failover пока не поддерживаются.

## Placement и lifecycle

Camera создаётся с automatic placement по умолчанию или с manual node.
Автоматический выбор:

1. только desired/runtime RUNNING, healthy nodes со свежим management
   observation вне maintenance/drain;
2. минимальное число registered cameras;
3. минимальное число active sources;
4. stable node id.

Если eligible node нет, control plane может создать новую при наличии
`max_nodes` и свободного port.

Dashboard/API управляет create/start/stop/restart, maintenance/drain, port
change, delete и camera move. Delete разрешён только для empty stopped/failed
node.
Смена port перезапускает node и все её streams. Dashboard сначала показывает
точные Public IDs зарегистрированных cameras и активных readers; apply требует
свежий MFA, неизменные revision/process/reader fingerprints и короткоживущий
confirmation token. Временный запрет поздних readers удерживается до
завершения bounded restart или rollback и снимается из отдельного cleanup
reserve. Остальные nodes не затрагиваются.

Unoccupied camera можно перемещать сразу. Occupied ordinary move запрещён;
forced move требует подтверждения текущего blast radius и disconnect. Move
держит writer locks обеих nodes, сначала закрывает admission source/target,
повторно проверяет reader, удаляет source и лишь затем открывает target. Saga
имеет deadline и после pre-switch failure удаляет target и восстанавливает
source. API сохраняет и возвращает старый/новый port и URL; transparent redirect
не обещается. Source update, disable и delete активной camera используют такой
же preview/confirmation contract.

## Access contract

- На camera допускается один downstream reader.
- Второй concurrent reader получает RTSP `453 Not Enough Bandwidth`.
- Access policy имеет два независимых CIDR-набора: `internet` и `local`.
- Если оба списка пусты, IP stage разрешает доступ всем.
- Если policy активна, сначала проверяется напрямую наблюдаемый TCP peer IP,
  затем camera username/password.
- Forwarded headers не используются для RTSP authorization.
- Downstream grants explicitly choose `temporary` or `service` and expiry;
  there is no implicit one-hour service credential, including rotation.
  Authenticated dashboard/API writes derive creator from the operator account;
  the unauthenticated compatibility seam uses the fixed server-side
  `bootstrap-control-plane` principal. Caller input cannot forge either. Raw
  URL-safe secret is shown once, while PostgreSQL stores only a versioned-
  pepper HMAC verifier plus safe creator/last-use metadata.
- Pepper rotation loads the new primary plus bounded verify-only previous keys;
  a successful use of an old-key grant atomically rehashes it under the primary
  key with a revision-fenced audit/outbox event.
- Rotation has bounded overlap; revoke/ACL/drain affects the next RTSP session
  immediately because positive auth caching is absent. Established stream is
  not disconnected by those non-disruptive policy changes.
- New-session authorization is a loopback HTTP callback with a per-node HMAC
  Basic identity bound to the exact node/path. A credential for node A cannot
  call node B. Unknown path, bad IP/user/password, malformed/slow request, auth outage
  and callback overload produce one no-oracle denial shape.
- Auth work has bounded global concurrency/rate, per-peer pending/rate and
  per-camera/grant rate gates plus a bounded PostgreSQL statement/connect
  budget; these never disconnect an established stream.
- A non-blocking typed decision sink keeps bounded reason/action/protocol/IP
  family counters and a bounded safe audit handoff containing node/path/grant,
  directly observed peer IP and reason; it never contains credentials.
- MediaMTX API/metrics всех nodes доступны только loopback и сохраняют точные
  per-node Basic credentials даже при внешнем HTTP auth callback.
- Central dashboard/control API доступен из management LAN по HTTPS и RBAC.

## Failure behavior

- Camera CRUD A не перезапускает node и не прерывает streams B..N.
- Node operation A не должна влиять на node B.
- Drain блокирует новые sessions, existing reader продолжает работу.
- Port change/restart/forced move прерывают только заявленный blast radius.
- При node failure camera placements не переносятся автоматически.
- Оператор получает одно email об аварии и одно подтверждение после recovery;
  repeated reminders отсутствуют.

## Архитектура

```text
Operator -> HTTPS Dashboard/API -> PostgreSQL
                    |                 |
                    |                 +-> nodes/cameras/placement/ACL/audit
                    v
       workers / reconciler / collector / bounded probes
             | loopback       | loopback       | loopback
             v                v                v
        Media node A      Media node B     Media node N
        RTSP :port-A      RTSP :port-B     RTSP :port-N
             |                |                |
             +------------ cameras ------------+

External FFmpeg ---------- ordinary RTSP/TCP ----------^
```

- Control plane: Python 3.12, FastAPI, Jinja2/HTMX, PostgreSQL.
- Media plane: pinned MediaMTX; Python не передаёт RTP.
- PostgreSQL хранит desired state, placement, ACL, audit и outbox.
- Reconciler применяет target path changes через loopback API конкретной node.
- Collector агрегирует metrics всех nodes для dashboard.
- Deployment напрямую на Linux amd64/arm64, без Docker.

## Initial gates

| Contract | Initial target |
|---|---:|
| Warm DESCRIBE→PLAY p99 | ≤500 ms |
| Cold proxy overhead p99 | ≤1 s |
| Catalog read / mutation API p99 | ≤200 ms / ≤1 s |
| Camera CRUD unrelated interruption | 0 |
| Cross-node lifecycle interruption | 0 |
| Second reader | RTSP 453 |
| Hard-resource headroom | ≥30% |
| Candidate soak | 24 h |
| PostgreSQL PITR / control RTO | ≤5 min / ≤30 min |

Capacity квалифицируется отдельно:

- per-node: до 100 registered/active/readers с max one reader/path;
- per-server: 1/5/10/25/50 nodes;
- 100 nodes — optional profile после config change и отдельного evidence.

`max_nodes=50` не означает, что любой server выдержит 50 полностью активных
nodes.

## План реализации

1. **Consensus/docs** — issues, ADR, plan, README.
2. **Node foundation** — PostgreSQL migrations, registry, random/manual port
   allocator, max_nodes, automatic/manual placement, 100-camera admission.
3. **Linux runtime** — per-node config/systemd instance, lifecycle and health.
4. **Media control** — node-aware reconciler, camera CRUD, drain, move, port
   change and delete-empty.
5. **Access** — internet/local ACL and credentials integrated with the
   Phase-D one-reader/RTSP 453 admission primitive, with authenticated
   dashboard administration and one-time secret delivery.
6. **Dashboard/observability** — UI, RBAC, metrics aggregation and email
   incident/recovery.
7. **Evidence/pilot** — per-node 100-camera and multi-node server matrix,
   chaos, restore and rollout waves.

После каждой фазы выполняются tests/lint/types/build, Standards review, Spec
review, fixes и native amd64/arm64 CI.

## Текущее содержимое репозитория

Уже реализованы:

- Python package и role readiness scaffold;
- Phase B candidate: typed node settings, packaged PostgreSQL/Alembic
  migrations, node registry, random/manual port allocation, auto/manual camera
  placement onto eligible provisioned nodes, 100-camera admission, append-only
  placement history and transactional audit/outbox;
- public node/camera HTTP commands with desired/applied revisions, strict
  eligibility with DB-clock freshness expiry and PostgreSQL race tests;
- release/startup schema gate bound to packaged Alembic head;
- architecture/digest-aware release verifier;
- direct-Linux systemd/sysusers/tmpfiles baseline;
- typed MediaMTX adapter plus the reproducible
  `v1.20.0-rtsp-proxy.3` source build pinned to upstream commit
  `1b943637a4b5778bb929a7af7687b048fecaa03f`;
- native ordinary RTSP/TCP H.264/H.265 compatibility contracts;
- reproducible GStreamer load generator/readers;
- tamper-evident resource/runtime/fixture evidence;
- scoped IFB/netem WAN evidence and direct-control comparison.

Phase B **complete**: independent Standards/Spec review и все шесть jobs
[native amd64/arm64 CI](https://github.com/zl0nline/RTSP_proxy/actions/runs/31547513916)
прошли. Credentialed/query-token source URLs сейчас fail closed: они не будут
приниматься до encrypted secret-reference flow.

Phase C **complete**: independent Standards/Spec review and all six jobs in
[native amd64/arm64 CI](https://github.com/zl0nline/RTSP_proxy/actions/runs/31565179680)
passed. Per-node generated configs,
`rtsp-proxy-media@<uuid>.service`, scoped root helper over a bounded Unix
socket with parallel different-node execution and an end-to-end deadline,
unique loopback API/metrics ports, PID/start/boot/config/release identity,
startup convergence and automatic
reserve→provision→smoke→place are in code. The two-node native contract proves
that restart/stop of node A does not change node B process or its established
ordinary RTSP/TCP session or packet progress. Restart is transactionally fenced
against placement; future rolling activation may use a separately catalogued
callback-compatible previous release while empty stopped nodes transition one
at a time.
Release `0.2.1` is the race-safe native target and keeps independently verified,
callback-compatible `0.2.0` as its rollback identity; `0.1.0` remains historical
trust provenance only. Stock MediaMTX is never accepted. The native
test executes real systemd instances and proves process/listener/RTP isolation;
its release identity and listener teardown checks remain fail closed while
correctly accounting for exec transitions and completed TCP `TIME_WAIT` state.

Каждая node получает разные случайные credentials для loopback API/metrics и
path-scoped runtime RTSP probe, а также отдельный `DynamicUser`; process видит
только собственный config через systemd
credentials. Runtime использует абсолютный binary path конкретного verified
release, поэтому переключение `/opt/rtsp-proxy/current` не подменяет MediaMTX у
уже созданной node. Lifecycle одной node сериализован и не блокирует startup
convergence другой: startup reconciliation выполняется bounded-параллельно,
а PostgreSQL lifecycle locks имеют отдельный ограниченный pool и timeout.

Phase D **complete** ([native amd64/arm64 CI evidence][phase-d-ci]):
node-scoped reconciler and camera CRUD, occupancy-fenced/revision-fenced move
saga with bounded abort cleanup, disruptive-camera confirmations,
drain/maintenance,
blast-radius-confirmed port change with crash recovery, and empty-node deletion
are implemented. A prepared port change freezes the exact camera placement set
and reserves both ports; failed/restarted operations converge to the old port.
Phase D owns the binary admission primitive and proves exact one-reader RTSP
`453` behavior without interrupting the established reader.

Phase E **complete** ([native amd64/arm64 CI evidence][phase-e-ci]): it
integrates that primitive with drain, two-level CIDR ACL, generated revocable
credentials and a dedicated node-authenticated loopback authorization service.
All six CI jobs passed on both architectures, including PostgreSQL migrations,
owned nftables read-back, patched MediaMTX management isolation, H.264/H.265
ACL/revoke/single-reader behavior and ordinary RTSP/TCP node isolation. This is
functional security evidence, not a production capacity result.

[phase-d-ci]: https://github.com/zl0nline/RTSP_proxy/actions/runs/31658505374
[phase-e-ci]: https://github.com/zl0nline/RTSP_proxy/actions/runs/31689056322

The Phase-C→D schema transition is intentionally offline and fail closed:
`0009` rejects a non-empty legacy node registry because those rows cannot prove
the patched non-disruptive admission behavior. The operator must export camera
intent, drain/delete cameras, stop/remove nodes, back up PostgreSQL, migrate,
activate the catalog-bound release, then run the private checksum-bound
`rtsp-proxy-phase-d-transition restore`. The round trip preserves exact camera
UUIDs and immutable `/<public_id>` paths, enforces the current host node/port
policy, preflights every restored listener before writing desired state and
preserves stable RUNNING/STOPPED/DRAINING/MAINTENANCE/FAILED intent. Transitional
node states cannot be exported. It is not exposed over HTTP.

OIDC Code+PKCE с MFA claim contract и break-glass password+TOTP login уже
реализованы и прошли независимый review и native amd64/arm64 CI вместе с
durable audit/email каждого emergency-login. Точная граница доказанного
foundation зафиксирована в
[`docs/evidence/phase-f-operator-observability-foundation.md`](docs/evidence/phase-f-operator-observability-foundation.md).
Read-only operator dashboard для server/node overview и bounded camera catalog
с keyset pagination, index-backed literal search/filter, отдельным
`control.read` permission и проекцией без `source_url` прошли native
amd64/arm64 CI. Secret-free camera detail с exact `camera:<uuid>` scope и
глобальным `server:*` superset также прошёл native CI. Server-rendered update,
enable, disable и delete прошли native amd64/arm64 CI в commit
`a6b2fd4cb1e9538dc679c581b4f1a81a5d2cb4f6`
([run 31805146878](https://github.com/zl0nline/RTSP_proxy/actions/runs/31805146878)):
form body ограничен, CSRF связан
с сессией, каждое действие связано с показанной `desired_revision`, а занятый
single-reader stream требует свежий confirmation token. Stale revision
возвращает безопасный 409 без source URL; имя камеры одинаково ограничено 128
символами без управляющих знаков в UI, domain и обоих storage adapters. Read
contract активируется только после fail-closed 0015 preflight; его ошибка
содержит UUID только доступных для исправления камер, но не имена или source
URL. Неизменяемые удалённые строки сохраняются лишь как внутренние tombstones и
не блокируют upgrade. Новый source URL не повторяется в confirmation HTML.
Camera move UI прошёл все шесть amd64/arm64 CI jobs в commit
`ffd12509e99fdff6336ffc5676cf3e9363b1fe66`
([run 31811342043](https://github.com/zl0nline/RTSP_proxy/actions/runs/31811342043)):
оператор выбирает только eligible
незаполненную ноду, форма несёт показанную revision, а occupied stream требует
confirmation, связанный с точным target и числом читателей. Public path не
меняется, новый внешний URL отличается портом; source URL не попадает в HTML.
После POST dashboard открывает camera-scoped status по persisted `move_id` и
показывает фактический state saga, а не доверяет query-параметру.
Revision-fenced break-glass rotation и accepted/rejected notification drill
прошли независимый review и все шесть native amd64/arm64 jobs в
[run 32428149162](https://github.com/zl0nline/RTSP_proxy/actions/runs/32428149162)
на commit `df35a2c0089564d1833c62fb65d256f09864fbde`. Real-browser E2E для
OIDC/login, клавиатурного focus, occupied-reader confirmation и защищённого
logout прошёл independent Spec/Standards review и dedicated CI в commit
`a6166e3aa6a6a3c6d87991d509ea126e0d48bd09`
([run 32676065004](https://github.com/zl0nline/RTSP_proxy/actions/runs/32676065004));
точная evidence boundary записана в
[`docs/evidence/phase-f-dashboard-browser-contract.md`](docs/evidence/phase-f-dashboard-browser-contract.md).
Real Chromium проверяется как внешний management client на amd64; одинаковый
server-side auth/template/CSRF/logout contract исполняется application CI на
amd64 и arm64. Shared-boundary denial-class/logout audit matrix прошла
independent review и все семь CI jobs на commit
`ef0e1f3fdfb74c174ac0dffa9f88213291ab19b5`
([run 32678955187](https://github.com/zl0nline/RTSP_proxy/actions/runs/32678955187));
точная граница записана в
[`docs/evidence/phase-f-operator-security-audit-contract.md`](docs/evidence/phase-f-operator-security-audit-contract.md).
The historical generated negative coverage for 48 protected route-method pairs
including nested included-router prefixes, прошла оба независимых review и все
семь jobs в commit `39b29814d726d9020c1d19100521b4dfe729b91e`
([run 32680412385](https://github.com/zl0nline/RTSP_proxy/actions/runs/32680412385)).
Будущие export/bulk routes должны расширить эту матрицу до активации.
The prior published inventory contained 57 protected route-method pairs after
the first node-action UI slice; it passed both independent reviews and all seven
jobs in [run 32693949200](https://github.com/zl0nline/RTSP_proxy/actions/runs/32693949200).
Dashboard node registration supports automatic random allocation or an exact
operator-selected port, then shows the persisted result even when privileged
provisioning fails. Start, stop, drain, maintenance, resume and empty-node
delete forms share the same CSRF/RBAC, expected revision/state and redacted
operator audit context as the JSON API. Registration retries reuse one
session-bound UUIDv4 key; PostgreSQL 0016 stores that key in an immutable
request ledger in the same synchronous transaction as `media_nodes`, audit and
outbox. Reusing the key for another payload is a 409, and deleting the target
node does not make the old key reusable. The complete slice is published at
commit `2f6b012d91ab4de2ad07d631f4cdfa46b2422255` with native amd64/arm64,
packaged PostgreSQL migration, MediaMTX/load and real-browser jobs green.
The current published inventory contains 63 protected route-method pairs
after adding port-change and reconfigure preview/apply. These disruptive forms
require recent MFA (300 seconds by default), bind the exact registered-camera
and active-reader lists, and bind the MediaMTX generation when a process is
running; an inactive reconfigure instead binds exact process absence. Empty
RUNNING-node restart uses the ordinary revision/state fence because its camera
blast radius is zero. The admission fence remains held through one absolute
runtime/rollback deadline. Exact review and direct-Linux evidence is recorded in
[`docs/evidence/phase-f-node-disruption-contract.md`](docs/evidence/phase-f-node-disruption-contract.md);
all seven native amd64/arm64 and external-browser jobs passed at commit
`466e72feb6c5401dd4b281baabc07095b7173669` in
[CI run 32708863738](https://github.com/zl0nline/RTSP_proxy/actions/runs/32708863738).
The current access-administration slice raises the generated inventory to 70
route-method pairs. It adds a camera-scoped dashboard for the independent
internet/local CIDR lists, bounded secret-free grant inventory, recent-MFA
issue/rotate/revoke workflows and a one-time no-store RTSP credential page.
Issue and rotation carry session-bound UUIDv4 idempotency keys; migration 0017
stores the immutable request digest in the same synchronous transaction as the
grant and audit/outbox pair. The dashboard removes the visible secret after at
most 30 seconds; a replay never reveals it. Grant-list reads are durably
audited, and independent durable per-account buckets rate-limit secret issuance
and ACL/revoke mutations with sanitized 429/`Retry-After` responses. The JSON
rotate/revoke routes are camera-scoped and require exact grant revisions.
Replay, idempotency, not-found and stale-revision rejections append a separate
sanitized audit/outbox pair after rollback and fail closed if that journal is
unavailable. Exact
local and direct-Linux evidence is recorded in
[`docs/evidence/phase-f-camera-access-dashboard-contract.md`](docs/evidence/phase-f-camera-access-dashboard-contract.md).
Independent Spec/Standards review passed. Application, packaged PostgreSQL and
patched MediaMTX/load jobs passed on both amd64 and arm64; the external Chromium
job passed on amd64 at commit `9b0695605e7bf9efe00db0760d90f9906da85579` in
[CI run 32730353917](https://github.com/zl0nline/RTSP_proxy/actions/runs/32730353917).
The published camera-registration slice adds automatic least-loaded and
manual eligible-node placement through a keyboard-operable server-rendered
form and the JSON API. Both boundaries require a session-scoped UUIDv4 key;
migration 0018 stores only its canonical request digest, pending/complete state
and resulting camera UUID. The pending intent commits synchronously before any
automatic node provisioning; its final transition commits atomically with
camera/tombstone/placement/default access-policy state plus audit/outbox. Exact
replay resumes or returns the original camera, while changed or target-missing
reuse is a durably audited 409. A separate durable per-account camera-mutation
bucket returns audited 429 before reserving an intent. Automatic node
provisioning inherits the same
operator account/session/action/key attribution. Independent Spec/Standards
review, local Chromium, isolated direct-Linux amd64 PostgreSQL and all seven
native/external CI jobs are green at commit
`a7f2324a5354969fd773f70fc6f13b04247e51b3` in
[CI run 32743179524](https://github.com/zl0nline/RTSP_proxy/actions/runs/32743179524).
Exact evidence is recorded in
[`docs/evidence/phase-f-camera-registration-dashboard-contract.md`](docs/evidence/phase-f-camera-registration-dashboard-contract.md).
The management HTTPS slice is also locally and direct-Linux validated, has
passed both independent reviews and is green in native amd64/arm64 CI at
commit `32ac6138777e460846a1caed1e46174138ebc9d5` in
[run 33253244053](https://github.com/zl0nline/RTSP_proxy/actions/runs/33253244053).
The exact boundary is recorded in
[`docs/evidence/phase-f-management-https-contract.md`](docs/evidence/phase-f-management-https-contract.md).
The live dashboard delta raises the generated protected inventory from the
published 72 pairs to 75. Overview state uses only the persisted aggregate
snapshot and polls every 10 seconds by default (server-enforced 5–30 seconds).
A camera detail opens at most one SSE stream per operator session with bounded
history/resume, `resync_required`, a 15-second heartbeat, initial authorization
and a shared batched in-memory epoch fence before every delivery with a
two-second revocation ceiling. Snapshot
reads and reconnects use separate durable buckets; browser requests are
single-flight with a five-second timeout and bounded backoff. Per-camera bitrate
is computed in the collector from monotonic elapsed time; wall-clock timestamps
are freshness metadata only, and freshness/reset/gap markers fail closed. A
camera move clears prior-node history, emits `resync_required` and starts an
exact new-node live epoch; one bounded secret-free placement batch discovers
it without another browser lookup. Shutdown waits for bounded snapshot/authz
workers before closing their stores. It passed independent Spec/Standards
review, the full local and direct-Linux suites, and all seven native/external CI
jobs at commit `a77db2daead18cc15afa5a497fdd9c5ca1a217f0` in
[CI run 33265832444](https://github.com/zl0nline/RTSP_proxy/actions/runs/33265832444).
Exact
scope is recorded in
[`docs/evidence/phase-f-dashboard-live-updates-contract.md`](docs/evidence/phase-f-dashboard-live-updates-contract.md).
Phase F остаётся в работе до завершения остальных операторских workflows.
Наличие load harness и
зелёного functional CI не
означает готовый product или published capacity.

## Локальная разработка

```sh
uv sync --locked --all-groups
uv run pytest
uv run ruff check src tests
uv run mypy
uv build
git diff --check
```

External media contracts запускаются отдельно с проверенными binaries:

```sh
MEDIAMTX_BINARY=/path/to/mediamtx \
FFMPEG_BINARY=/path/to/ffmpeg \
FFPROBE_BINARY=/path/to/ffprobe \
uv run pytest -m contract tests/contract
```

Direct-Linux layout описан в [deploy/README.md](deploy/README.md), а load
harness — в [tools/load/README.md](tools/load/README.md).

## Документация

- [Production plan](docs/PRODUCTION_PLAN.md)
- [Engineering context](CONTEXT.md)
- [ADR registry](docs/adr/README.md)
- [SLI catalog](docs/SLI_CATALOG.md)
- [Camera profile](docs/CAMERA_PROFILE.md)
- [Capacity worksheet](docs/CAPACITY_WORKSHEET.md)
- [Failure-domain matrix](docs/FAILURE_DOMAIN_MATRIX.md)
- [Risk register](docs/RISK_REGISTER.md)
- [EPIC #14](https://github.com/zl0nline/RTSP_proxy/issues/14)

## License

Проект распространяется по лицензии
[PolyForm Noncommercial 1.0.0](LICENSE). Для коммерческого использования
требуется отдельное письменное разрешение правообладателя.
