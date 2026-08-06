# RTSP Proxy

Production-oriented план единой точки доступа к RTSP-камерам через один configurable TCP endpoint.

> **Текущий статус**
>
> - Planning: **READY** — решения #1–#13 согласованы и прошли внешнее критическое ревью.
> - Implementation: **NOT AUTHORIZED** — код и deployment не начинаются без отдельного решения владельца.
> - Production: **NOT READY** — spikes, tests, security, restore и pilot gates ещё не выполнены.
> - 10k: **NOT CLAIMED** — capacity определяется только измерениями.

Полный нормативный документ: [docs/PRODUCTION_PLAN.md](docs/PRODUCTION_PLAN.md). Итоговый planning verdict: [EPIC #14](https://github.com/zl0nline/RTSP_proxy/issues/14#issuecomment-5203794735).

## Задача

Вместо отдельного внешнего порта на каждую камеру система должна предоставлять адреса вида:

```text
rtsp://<external-user>:<external-password>@<host>:9999/<public_id>
```

При этом:

- внешний клиент не получает IP и credentials камеры;
- поддерживаемый media transport — RTSP over TCP interleaved;
- эталонный клиент — FFmpeg вместе с supervisor;
- dashboard и Python control plane не участвуют в медиапотоке;
- изменение одной камеры не должно обрывать остальные streams;
- registered paths, active sources и readers измеряются независимо.

## Согласованная архитектура

```text
Operator -> HTTPS Dashboard/API -> PostgreSQL
                    |                 |
                    |                 +-> desired state / audit / outbox
                    v
             workers / reconciler / bounded probes
                    |
External FFmpeg -> RTSP/TCP :9999 -> MediaMTX -> cameras
                                      |
                                      +-> metrics/events -> TSDB
```

- Control plane: Python 3.12, FastAPI, Jinja2/HTMX, PostgreSQL.
- Media plane: pinned MediaMTX digest; Python не proxy/transcode media.
- Desired state: PostgreSQL + transactional outbox + idempotent reconciler.
- Health: дешёвые MediaMTX signals + bounded sandboxed ffprobe.
- Observability: versioned signal catalog, bounded cardinality/query/SSE budgets.
- Security: separated source secrets/access grants, envelope encryption, RBAC/authz epochs, append-only/WORM audit.
- Operations: role-specific health, expand-contract migrations, PITR, drain/rollback state machine и проверяемые runbooks.

## Ключевые инварианты

1. Один внешний RTSP endpoint, порт задаётся конфигурацией, default `9999`.
2. PostgreSQL — production source of truth; JSON используется только для import/export.
3. CRUD одной камеры не вызывает reload/restart MediaMTX и не влияет на другие paths.
4. Established media sessions продолжаются при потере control plane/DB в доказанных границах.
5. L4 не умеет выбирать shard по RTSP path; схема `L4 -> assigned shard` исключена.
6. Сначала измеряется safe envelope одного node. Multi-node включается только после отдельного ADR/spike.
7. FFmpeg reconnect обеспечивается supervisor: full handshake, exponential full-jitter backoff `1s -> 30s`.
8. Security, audit, observability, restore, rollback и capacity — release gates, а не отложенная работа.

## Scale-out: single-node first

Заявления вида «поддерживает 10k streams» запрещены без evidence. Сначала измеряется single-node envelope по registered paths, active sources, readers, bitrate, packet rate, RAM, CPU, FD и network per hop.

Single-node проходит gate после 24h soak с faults/churn, выполненными SLO и запасом не менее 30% по каждому hard limit. Достижение/прогноз 70% любого hard limit запускает scale-out planning.

Если одного node недостаточно:

1. проверяется replicated MediaMTX gateway tier с on-demand pull к origin shards;
2. при провале его SLO/security/capacity — готовый RTSP-aware L7 router;
3. собственный RTSP router остаётся последним резервом.

## Initial numerical gates

- RTSP connect: warm `<=500ms`, cold `<=3s`, измеряются p95 и p99;
- catalog read `<=200ms`, CRUD `<=1s`;
- authz downgrade/revoke `<=2s`, fail closed;
- supervisor recovery p95 `<=10s`, max `<=35s`;
- successful steady handshakes `>=99.9%`;
- probes: throughput loss `<=5%`, latency regression `<=10%`, errors `<=0.1pp`;
- PostgreSQL RPO `<=5m`, control-plane RTO `<=30m`;
- metrics budget `<=100k` active series и `<=6` per enabled camera;
- canary 5%, затем gated soak/waves; pilot exit требует `>=99%` readable и ноль system-caused disconnects healthy streams в exit window.

Это planning budgets. Они становятся доказанными характеристиками только после reproducible tests; ослабление требует versioned ADR.

## План исполнения

Реализация пока не разрешена. После явного `START PHASE 0` порядок такой:

### Phase 0 — evidence foundation

- ADR/SLI/release manifests;
- pinned MediaMTX API/auth/hot-update/metrics compatibility spike;
- reproducible load harness, untuned baseline и single-node knee;
- topology decision на измерениях.

### Phase 1 — foundation

- control plane и migrations;
- PostgreSQL data model;
- dashboard/RBAC;
- reconciler/hot-update;
- health scheduler/probes.

### Phase 2 — production contracts

- observability;
- FFmpeg compatibility;
- security;
- полная load/chaos matrix и published safe envelope.

### Phase 3 — operations and release

- deployment/drain/PITR/restore/runbook drills;
- lab -> pilot 10 -> pilot 100 -> controlled waves;
- отдельный `GO | HOLD | ROLLBACK` на каждом gate.

## Repository status

Репозиторий сейчас содержит архитектурный план. Наличие описанной функции в документации не означает, что соответствующий код уже существует. EPIC #14 остаётся открытой execution map; consensus дочернего issue означает «контракт согласован», а не «готово».

## Нормативные ссылки

- [Подробный production-план](docs/PRODUCTION_PLAN.md)
- [EPIC #14 и итоговый verdict](https://github.com/zl0nline/RTSP_proxy/issues/14)
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

См. [LICENSE](LICENSE).
