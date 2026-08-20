# RTSP Proxy

Платформа управления RTSP-прокси на одном Linux-сервере. Media plane разбит
на независимые bounded nodes: каждая node — отдельный MediaMTX process/systemd
instance, один внешний RTSP port и не более 100 зарегистрированных камер.

> **Статус на 14 августа 2026**
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
>   Complete automated browser E2E remains pending.
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
Смена port перезапускает node и все её streams. Остальные nodes не
затрагиваются.

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
  there is no implicit one-hour service credential, including rotation. Until
  Phase F authenticates operators, creator is the server-derived
  `bootstrap-control-plane` principal and cannot be supplied by a caller. Raw
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
   Phase-D one-reader/RTSP 453 admission primitive.
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
на commit `df35a2c0089564d1833c62fb65d256f09864fbde`. Полный
автоматизированный browser E2E ещё не реализован, поэтому Phase F целиком не
завершена.
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
