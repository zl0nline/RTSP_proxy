# RTSP Proxy

Платформа управления RTSP-прокси на одном Linux-сервере. Media plane разбит
на независимые bounded nodes: каждая node — отдельный MediaMTX process/systemd
instance, один внешний RTSP port и не более 100 зарегистрированных камер.

> **Статус на 12 августа 2026**
>
> - Bounded-node architecture: **согласована**, issues #1–#14 обновлены.
> - Phase 0A MediaMTX/ordinary-RTSP compatibility: **complete** на native
>   Linux amd64/arm64.
> - Phase 0B reproducible load/netem harness: **functional foundation complete**;
>   production hardware capacity/24h soak ещё не выполнены.
> - Node registry, PostgreSQL catalog, placement, dashboard и production
>   lifecycle: **implementation in progress**.
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

1. только RUNNING/healthy nodes вне maintenance/drain;
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
forced move требует подтверждения и disconnect. Move может изменить port/URL.
Transparent redirect не обещается.

## Access contract

- На camera допускается один downstream reader.
- Второй concurrent reader получает RTSP `453 Not Enough Bandwidth`.
- Access policy имеет два независимых CIDR-набора: `internet` и `local`.
- Если оба списка пусты, IP stage разрешает доступ всем.
- Если policy активна, сначала проверяется напрямую наблюдаемый TCP peer IP,
  затем camera username/password.
- Forwarded headers не используются для RTSP authorization.
- MediaMTX API/metrics всех nodes доступны только loopback.
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
5. **Access** — internet/local ACL, credentials, one-reader/RTSP 453.
6. **Dashboard/observability** — UI, RBAC, metrics aggregation and email
   incident/recovery.
7. **Evidence/pilot** — per-node 100-camera and multi-node server matrix,
   chaos, restore and rollout waves.

После каждой фазы выполняются tests/lint/types/build, Standards review, Spec
review, fixes и native amd64/arm64 CI.

## Текущее содержимое репозитория

Уже реализованы:

- Python package и role readiness scaffold;
- architecture/digest-aware release verifier;
- direct-Linux systemd/sysusers/tmpfiles baseline;
- typed MediaMTX v1.20.0 adapter;
- native ordinary RTSP/TCP H.264/H.265 compatibility contracts;
- reproducible GStreamer load generator/readers;
- tamper-evident resource/runtime/fixture evidence;
- scoped IFB/netem WAN evidence and direct-control comparison.

Ещё не реализованы production node registry, database catalog/migrations,
placement API, dashboard, one-reader admission, access policies, notifications
и complete operations workflows. Наличие load harness не означает готовый
product или published capacity.

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
