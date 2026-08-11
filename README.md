# RTSP Proxy

Проект единой управляемой точки доступа к RTSP-камерам через один configurable
TCP endpoint.

> **Текущий статус**
>
> - Planning consensus: **COMPLETE** — issues #1–#14 согласованы, сквозные
>   противоречия исправлены.
> - Phase 0: **IN PROGRESS** — owner authorization получено 10 августа 2026.
> - Foundation implementation: **REVIEWED** — fail-closed role readiness,
>   release verifier, Python package, native amd64/arm64 CI и direct-Linux
>   systemd artifacts прошли Standards/Spec review.
> - Phase 0A compatibility lab: **COMPLETE** — MediaMTX adapter и внешний
>   ordinary-RTSP contract прошли Standards/Spec exit review и native
>   amd64/arm64 CI; Proposed auth/security gates всё ещё блокируют production.
> - Phase 0B load harness: **IN PROGRESS** — native GStreamer pull sources,
>   scalable TCP readers и reproducible tamper-evident run bundles реализованы;
>   hardening закрывает повторное вычисление summaries, warm anchors внутри
>   заявленной reader-когорты, общие UTC ramp/measurement/soak epochs,
>   post-workload sampling barrier,
>   typed fixture semantics, process/cgroup/binary binding, phase RTP и
>   обязательный независимый SUT resource/session/loss ряд для каждого proxy и
>   расширенные leak/soak gates для capacity, а также per-host
>   architecture/hardware/GStreamer runtime manifests. Предыдущий native
>   amd64/arm64 CI run `31499414349` подтверждает предшествующий native harness;
>   runtime-manifest slice добавляет отдельный privileged capture/binding contract
>   на обоих native runners и требует нового опубликованного CI результата.
>   Выделенный
>   production-equivalent Spike #0 и 24h soak ещё не выполнены; WAN/netem и
>   probe/CRUD drivers пока fail closed.
> - Product behavior: **EVIDENCE GATED** обязательными Phase 0 fork decisions.
> - Production: **NO-GO**.
> - Scale-out: **EVIDENCE BLOCKED** до single-node Spike #0.
> - 10k: **NOT CLAIMED** — capacity определяется только измерениями.

Полная нормативная спецификация:
[docs/PRODUCTION_PLAN.md](docs/PRODUCTION_PLAN.md).

## Задача

Вместо отдельного внешнего порта на каждую камеру система должна предоставлять
единый endpoint и opaque path:

```text
rtsp://<external-user>:<external-password>@<host>:9999/<public_id>
```

Это обычный RTSP URL: FFmpeg выполняет стандартный DESCRIBE/SETUP/PLAY и не
должен знать, что endpoint является proxy, а не прямой камерой.
`external-user`/`external-password` — access grant прокси, не credentials
камеры. Если канал недоверенный, шифрование обеспечивает внешний VPN/private
network, не меняющий `rtsp://` URL и RTSP handshake.

Целевые свойства:

- consumer не получает IP и source credentials камеры;
- поддерживаемый transport — RTSP-over-TCP interleaved снаружи и до source;
- reference consumer — FFmpeg вместе с supervisor;
- dashboard и Python control plane не участвуют в media datapath;
- CRUD одной камеры не перезапускает MediaMTX и не обрывает другие streams;
- PostgreSQL хранит desired state, audit и outbox;
- registered paths, active sources и readers измеряются независимо;
- security, restore, rollback и capacity являются release gates.

## Архитектура

```text
Operator -> HTTPS Dashboard/API -> PostgreSQL
                    |                 |
                    |                 +-> desired state / audit / outbox
                    v
          workers / reconciler / bounded probes
                    |
External FFmpeg -> RTSP/TCP :9999 -> MediaMTX -> cameras
                                      |
                                      +-> metrics/events -> collector / TSDB
```

- Control plane: Python 3.12, FastAPI, Jinja2/HTMX, PostgreSQL.
- Media plane: pinned MediaMTX version/binary SHA-256; Python не
  proxy/transcode media.
- Delivery: synchronous desired+audit+outbox transaction и идемпотентный
  reconciler.
- Health: MediaMTX signals + bounded `source_probe`/`path_probe` через pinned
  sandboxed ffprobe.
- Observability: versioned signal inventory, cardinality/query/SSE budgets.
- Security: separated source secrets/access grants, envelope encryption,
  authz epochs, no-oracle и append-only/WORM audit.
- Operations: role health, expand-contract migrations, PITR,
  post-restore report-only, drain/quarantine и runbooks.
- Deployment: напрямую на Linux hosts — versioned root-owned releases,
  dedicated users и hardened `systemd` units; amd64/arm64 имеют одинаковые
  release gates, Docker не используется.

## Ключевые инварианты

1. Один внешний endpoint; порт configurable, default `9999`.
2. RTSP-over-TCP interleaved only; UDP/multicast выключены.
3. `public_id` — не credential: `^[a-z0-9]{25}$`, равномерный CSPRNG,
   ≈129.25-bit space, never reused.
4. PostgreSQL — production source of truth; JSON/CSV только import/export.
5. API сообщает `desired accepted`; `applied` подтверждает reconciler.
6. Desired state, обязательный audit и outbox коммитятся одной synchronous
   quorum transaction; async commit для `audit_events` запрещён.
7. Established sessions продолжаются при control-plane/DB outage на живом media
   node; new sessions зависят от доказанной auth-cache/fail-closed policy.
8. L4 не выбирает origin по RTSP path; `L4 -> assigned shard` отвергнут.
9. Single-node измеряется первым; gateway/L7 появляются только после evidence.
10. Cold start зависит от GOP: SLO относится к `proxy_overhead`, а не к
    безусловному end-to-end `≤3s`.
11. Linux amd64 и arm64 поддерживаются независимо проверенными release
    manifests, native CI и MediaMTX contract tests.

## Initial SLO и gates

| Contract | Initial value |
|---|---:|
| Warm `DESCRIBE→PLAY` | p99 `≤500ms` |
| Cold proxy contribution | p99 `≤1s` |
| Cold end-to-end | informative `≤1s + GOP_max` |
| Catalog read / CRUD | p99 `≤200ms / ≤1s` |
| Deep observation freshness | `≥95%` within `2 × configured_interval` |
| Manual add/change confirmation start | `≥99%` within queue-delay SLO |
| Control-plane availability | `≥99.5% / month` |
| Established media-session availability | `≥99.0% / month` |
| Dashboard authz revoke | `≤2s`, fail closed |
| Media-grant revoke-new | candidate `≤10s`, positive cache `≤5s` |
| FFmpeg supervisor recovery | p95 `≤10s`, max `≤35s` |
| Resource envelope | every hard resource `<70%`, headroom `≥30%`, soak `24h` |
| PostgreSQL PITR / control RTO | `≤5m / ≤30m` |

Это planning targets. Они становятся доказанными характеристиками только после
reproducible tests. Ослабление требует versioned ADR.

## Camera profile

До pilot каждая model/firmware получает versioned profile:

- main/sub paths и codec/audio;
- bitrate и packet rate;
- GOP/keyframe interval;
- `max_concurrent_rtsp_sessions`;
- RTSP-over-TCP и timeout/keepalive behavior.

Профиль связывает cold-start SLO, probes, load generation и migration preflight.
Неизвестный session limit нельзя заменять предположением при rollout.

## Scale-out: single-node first

Заявление «поддерживает 10k» запрещено без evidence. Spike #0 измеряет
registered paths, active sources, readers, bitrate/GOP, packet rate, CPU, RAM,
FD и network per hop.

Single-node проходит только после 24h soak с faults/churn, SLO и ≥30% headroom.
Если target workload помещается, baseline остаётся single-node; HA проектируется
отдельно.

Если не помещается:

1. Spike #1 проверяет replicated MediaMTX gateway tier перед origin shards.
2. При провале SLO/security/capacity проверяется готовый RTSP-aware L7 router.
3. Собственный router — последний резерв.

L4 перед gateway допустим только потому, что любой gateway знает external paths;
сам L4 path не читает.

## План реализации

Phase 0 и foundation implementation явно разрешены владельцем 10 августа 2026.
Product behavior, зависящий от неподтверждённых MediaMTX/auth/topology forks, не
принимается как готовый до соответствующего evidence gate.

### Pre-Phase 0

- ADR/SLI/risk registries;
- camera profile template;
- release/compatibility manifest;
- capacity worksheet и failure-domain matrix.

### Phase 0 — evidence foundation

- pin MediaMTX/FFmpeg/ffprobe versions and artifact checksums;
- prove API/auth/hot-update/restart/metrics and transparent RTSP semantics;
- build pull-mode RTSP load harness;
- find single-node knee and publish safe envelope;
- run gateway/L7 topology spikes only if single-node is insufficient.

### Phase 1 — foundation and vertical slices

- #2 foundation/config/CI/migrations;
- #3 catalog/data/secrets/audit;
- #4 dashboard/RBAC;
- #5 reconciler/media hot-update;
- #6 health scheduler/probes.

### Phase 2 — production contracts

- #7 observability;
- #8 FFmpeg/supervisor compatibility;
- #9 security/auth/network-boundary/hardening;
- #11 full load/chaos and published envelope.

### Phase 3 — operations and release

- #12 deploy/drain/PITR/restore/runbook drills;
- #13 lab → pilot 10 → pilot 100 → measured 500/1k waves;
- `GO | HOLD | ROLLBACK` owner decision at every gate.

## Migration safety

- New system runs shadow validation without a second upstream pull.
- Camera session limit is checked under current load before cutover.
- Legacy compatibility lasts at least 30 days after the last cohort.
- Legacy path disables only after 7 consecutive full days with fresh
  `legacy_active_sessions = 0`; stale/unknown data blocks shutdown.
- Hardcoded client URLs without managed rollback channel block the cohort.
- Post-PITR reconciler starts in `report-only`; deletes require separate approval.

## Repository status

Репозиторий содержит исполняемый Phase 0 foundation: Python package,
role-specific fail-closed readiness scaffold, checksum/path/version/
architecture release verifier, tests, direct-Linux systemd artifacts и native
amd64/arm64 CI. В Phase 0A уже реализованы типизированный MediaMTX management
adapter и исполняемый внешний контракт против реальных
MediaMTX/FFmpeg/ffprobe: обычный `rtsp://` по TCP, on-demand pull, hot-update
изоляция, restart/cold-restore, internal/HTTP auth, revoke/outage, no-oracle
fallback и pinned metrics schema. Exit review фазы пройден на обеих нативных
архитектурах; это compatibility evidence, а не production approval.

Production ffprobe runner намеренно не поставляется: первоначальный runner был
удалён после exit review, потому что до отдельной Unix/cgroup/egress границы он
оставлял бы source credentials в argv и допускал SSRF. Кандидатная граница
зафиксирована в ADR 0004 и должна быть реализована в health/security slices.

Catalog продукта, PostgreSQL, grant verifier, reconciler/task loops и dashboard
ещё не реализованы. Phase 0B load harness теперь связывает profile, fixture и
SHA load binaries с точным per-host launch plan; reader измеряет отдельно
`DESCRIBE→PLAY` и первый parser-aligned IDR/IRAP random-access unit, отклоняет
header-only, delta, decode-only, corrupted и gap buffers и поддерживает steady/ramp/
burst/outage и парный direct-control. Все shards используют единые будущие UTC
anchor/ramp/measurement/soak epochs; completion связан с profile/plan/host,
точными lifecycle slots и clock-sync evidence, проверяемым до завершения
workload. Для warm proxy один reader из `total_readers` на каждый active path
работает как anchor за 60 секунд до измеряемого ramp, а typed API polling
проверяет anchors до и на границе ramp. Cold proxy перед стартом parallel
reset/recreate целевые on-demand paths, требует один reader на active path и
`single` lifecycle; до отдельного масштабного доказательного прогона preflight
имеет implementation safety cap: 512 paths и 32 API workers. Generator
headroom проверяет точный `cgroup.procs`,
executable digest/start time, host/process/RLIMIT, NIC packets/MTU, effective
ephemeral TCP capacity с учётом reserved ports и usage каждого ограничивающего
cgroup v2 ancestor, а не только leaf scope; measurement
и soak проверяются раздельно, а post-workload
barrier оставляет PID доступным до завершающей resource sample. Каждый proxy
run также требует независимый MediaMTX PID/cgroup/NIC series; capacity добавляет
24h leak/soak gates. Finalizer заново
строит планы и summaries из raw evidence до хэширования bundle. Capacity bundle
дополнительно требует kernel clock proof,
rolling 6h RSS, включая границу measurement/soak,
FD/all-session/runtime-path drain, identity-recomputed RTP/RTCP/path error
deltas и per-cycle/per-reader/per-track sent-sequence/received phase RTP
reconciliation с проверкой темпа и границ connected interval. Один stalled
video/Opus reader не маскируется зелёным aggregate. Fixture manifest связывает pinned
FFmpeg/ffprobe с измеренными codec/FPS/bitrate/GOP. Обязательный per-host runtime
manifest двумя clock proofs ограничивает весь capture и связывает native architecture,
CPU/RAM/NIC/kernel/sysctl, effective
cgroup/RLIMIT и PID/start/executable identity; на generator hosts он также
фиксирует exact dpkg build и SHA/device/inode реально mmap'нутых GStreamer
библиотек. Cold A/B дополнительно копирует и хэширует direct runtime manifests и
отвергает drift machine/boot/kernel/sysctl/cgroup/RLIMIT/GStreamer среды. Эти
механизмы не публикуют capacity envelope без фактических
выделенных стендов, typed WAN/netem и probe/CRUD drivers, полной matrix и 24h
soak. FFmpeg/ffprobe
зафиксированы как Phase 0 candidate,
но upstream artifact не имеет GitHub attestation и ещё не прошёл security
provenance gate. Наличие Phase 0-кода не означает доказанную production
характеристику. Issue #10 остаётся evidence blocker для scale-out topology;
issues #1–#14 — execution map.

## Локальная разработка

```sh
uv sync --locked --all-groups
uv run pytest
uv run ruff check src tests
uv run mypy
uv build
```

External media contract запускается отдельно с проверенными binaries:

```sh
MEDIAMTX_BINARY=/path/to/mediamtx \
FFMPEG_BINARY=/path/to/ffmpeg \
FFPROBE_BINARY=/path/to/ffprobe \
uv run pytest -m contract tests/contract
```

Direct-Linux layout и activation contract описаны в
[deploy/README.md](deploy/README.md).

## Нормативные ссылки

- [Production plan](docs/PRODUCTION_PLAN.md)
- [Engineering context](CONTEXT.md)
- [Initial SLI catalog](docs/SLI_CATALOG.md)
- [Camera profile contract](docs/CAMERA_PROFILE.md)
- [Capacity worksheet](docs/CAPACITY_WORKSHEET.md)
- [Failure-domain matrix](docs/FAILURE_DOMAIN_MATRIX.md)
- [Risk register](docs/RISK_REGISTER.md)
- [Phase 0 MediaMTX candidate ADR](docs/adr/0001-mediamtx-v1.20.0-phase-0-candidate.md)
- [EPIC #14](https://github.com/zl0nline/RTSP_proxy/issues/14)
- [Architecture/SLO/capacity #1](https://github.com/zl0nline/RTSP_proxy/issues/1)
- [Foundation #2](https://github.com/zl0nline/RTSP_proxy/issues/2)
- [Data model #3](https://github.com/zl0nline/RTSP_proxy/issues/3)
- [Dashboard/RBAC #4](https://github.com/zl0nline/RTSP_proxy/issues/4)
- [Reconciler #5](https://github.com/zl0nline/RTSP_proxy/issues/5)
- [Health #6](https://github.com/zl0nline/RTSP_proxy/issues/6)
- [Observability #7](https://github.com/zl0nline/RTSP_proxy/issues/7)
- [FFmpeg compatibility #8](https://github.com/zl0nline/RTSP_proxy/issues/8)
- [Security #9](https://github.com/zl0nline/RTSP_proxy/issues/9)
- [Scale/topology #10](https://github.com/zl0nline/RTSP_proxy/issues/10)
- [Performance/chaos #11](https://github.com/zl0nline/RTSP_proxy/issues/11)
- [Operations #12](https://github.com/zl0nline/RTSP_proxy/issues/12)
- [Release/migration #13](https://github.com/zl0nline/RTSP_proxy/issues/13)

## License

Проект распространяется по лицензии
[PolyForm Noncommercial 1.0.0](LICENSE): использование, изменение и
распространение разрешены только для некоммерческих целей. Для коммерческого
использования требуется отдельное письменное разрешение правообладателя.
