# Production-план RTSP Proxy

## 1. Цели и границы

Система должна обслуживать до 10 000 зарегистрированных камер при условии достаточных CPU, RAM, файловых дескрипторов и пропускной способности сети. Число зарегистрированных камер, одновременно активных источников и внешних клиентов — разные параметры; гарантируемая ёмкость определяется нагрузочными испытаниями, а не только размером каталога.

Внешний RTSP endpoint имеет вид `rtsp://<user>:<password>@<host>:<port>/<public_id>`. Порт по умолчанию — `9999`, но задаётся конфигурацией. Клиентом является FFmpeg, поэтому обязательны контрактные тесты `DESCRIBE/SETUP/PLAY/TEARDOWN`, RTSP-over-TCP, повторные подключения, таймауты и корректные коды ошибок.

Dashboard предназначен для оператора: количество камер, фильтры и группы, добавление/редактирование/безопасное удаление, готовая внешняя ссылка, ручная и плановая проверка потока, состояние источника, активные readers, входящий/исходящий bitrate и история ошибок. Dashboard не декодирует видео и не находится в медиапути.

## 2. Архитектурные принципы

```text
Operator -> HTTPS Dashboard/API -> PostgreSQL
                    |                 |
                    |                 +-> desired state + audit log
                    v
                 Job queue -> bounded ffprobe workers -> cameras
                    |
                    v
             reconciler/config controller
                    |
                    v
External FFmpeg -> TCP load balancer:9999 -> MediaMTX node(s) -> cameras
                                              |
                                              +-> metrics/events -> collector -> time-series metrics
```

- **Control plane:** Python 3.12, FastAPI, server-rendered Jinja2/HTMX dashboard, PostgreSQL, отдельный reconciler и фоновые workers. HTTP API внутренний и нужен самому dashboard; публичным интеграционным API он становится только после отдельного решения.
- **Media plane:** закреплённая версия MediaMTX. На первом этапе один узел; горизонтальное масштабирование — несколько независимых узлов за TCP load balancer с детерминированным распределением путей. Python не проксирует медиаданные.
- **Desired/reported state:** PostgreSQL хранит желаемое состояние камеры и ревизию; reconciler идемпотентно применяет diff на нужном MediaMTX-узле и записывает фактический результат. Изменение одной камеры не вызывает перезапуск или полную перегенерацию работающих узлов.
- **On-demand:** источники поднимаются только при наличии reader, если бизнес-режим не требует постоянного чтения. Проверка живости выполняется отдельно и ограничивается по concurrency/rate.
- **Простота:** один deployable control-plane на старте, PostgreSQL и MediaMTX. Redis/NATS, Kubernetes и HA добавляются только по измеренной необходимости; интерфейсы очереди и размещения узлов проектируются заранее.

## 3. Модель данных

JSON-файл не подходит для нескольких операторов, аудита и атомарной синхронизации 10 000 объектов. PostgreSQL хранит:

- `cameras`: внутренний UUID, непрозрачный `public_id`, имя, группа, модель/профиль, private IP/port/path, enabled, revision, assigned media node;
- `camera_secrets`: зашифрованные credentials источника и внешние credentials/политика доступа;
- `camera_groups` и memberships;
- `probe_results`: время, latency, codec/resolution/fps, итог и безопасная нормализованная ошибка;
- `media_nodes`: состояние, capacity/weight, heartbeat, applied revision;
- `audit_events`: кто, когда и что изменил, без секретов;
- `jobs`: состояние фоновых проверок и повторов (для начальной DB-backed очереди).

Удаление по умолчанию двухфазное: disable/revoke, затем soft-delete. Физическое удаление — отдельная привилегированная операция после retention-периода. Все изменения optimistic-lock по revision и транзакционны.

## 4. Безопасное применение изменений

1. API валидирует запись, проверяет права и сохраняет новую revision в транзакции.
2. Reconciler назначает камеру media node, вычисляет минимальный diff и вызывает только локальный/management API закреплённой версии MediaMTX.
3. После read-back verification фиксируется applied revision. Ошибка оставляет объект в состоянии `degraded/pending`, запускает retry с backoff и не затрагивает другие пути.
4. Запрещены штатные рестарты MediaMTX при CRUD камеры. Rollout версии выполняется узел за узлом с drain readers.
5. Для удаления сначала отзываются внешние credentials и удаляется только один path. Активная сессия обрабатывается по явно выбранной политике: immediate revoke либо graceful drain.

## 5. Проверка живости и статистика

- `ffprobe` запускается в sandboxed worker без shell, с жёсткими timeout, memory/CPU/process limits, RTSP-over-TCP и ограничением размера stderr.
- Планировщик использует jitter, bounded concurrency и per-subnet/per-camera rate limit. Массовая кнопка «проверить все» создаёт пакет jobs, а не 10 000 процессов одновременно.
- Базовая живость берётся из состояния MediaMTX и результатов probes; probe подтверждает, что поток реально читается и сообщает codec/resolution/fps.
- Горячая статистика media nodes собирается из metrics/API: active paths, readers, bytes/bitrate, errors/reconnects, CPU/RAM/FD/network. История хранится в Prometheus-совместимом TSDB; PostgreSQL не используется для высокочастотных метрик.
- Dashboard показывает агрегаты с server-side pagination/filtering. Обновление — SSE или умеренный polling; не создаём WebSocket на каждую камеру.

## 6. Масштабирование media plane

- Один публичный порт сохраняется через L4 TCP load balancer. Для RTSP/TCP требуется session affinity/deterministic routing, чтобы все запросы сессии и путь попадали на правильный узел.
- Каталог камер партиционируется по `public_id` с rendezvous hashing или явным assignment в БД. Rebalancing выполняется управляемо, небольшими пакетами.
- Нельзя обещать «10k streams» без профиля нагрузки. Capacity model учитывает active sources, readers per source, bitrate, TCP connections, kernel socket buffers, FD, egress и reconnect storm.
- До production обязательны ступенчатые tests: 100/500/1k/5k/10k зарегистрированных путей; отдельно 100/500/1k/... активных synthetic streams до найденного предела. Проверяются steady state, cold start, camera outage, node loss и reconnect storm.
- Транскодирование не входит в proxy: MediaMTX выполняет remux/proxy. Если появится транскодирование, это отдельный FFmpeg worker pool с собственным capacity planning.

## 7. Доступ и защита

- Наружу открыт только настраиваемый RTSP/RTSPS endpoint; dashboard — HTTPS в management VPN/allowlist.
- RBAC минимум: admin и operator; MFA/SSO предпочтительно. Сессии secure/httpOnly/sameSite, CSRF-защита, rate limits и lockout.
- Credentials камер шифруются envelope encryption (KMS/Vault либо master key вне БД), никогда не возвращаются после сохранения и не попадают в URL, логи, метрики, trace или audit.
- Внешний доступ — per-camera или per-group credentials с ротацией и отзывом. Непрозрачный `public_id` не считается средством авторизации.
- MediaMTX API/metrics доступны только management-сети с аутентификацией. Камерные IP валидируются против разрешённых CIDR, чтобы dashboard не превратился в SSRF-сканер.
- Контейнеры non-root, read-only filesystem где возможно, pinned images/digests, минимальные capabilities, регулярное обновление зависимостей, backup/restore drills.

## 8. Надёжность и эксплуатация

- Health/readiness endpoints различают доступность API, БД, очереди и media nodes.
- Structured logs с correlation ID и redaction; метрики и alerting для availability, probe backlog, reconcile failures, auth failures, FD/network saturation.
- PostgreSQL backup + PITR, резервная копия ключей отдельно, документированные restore и disaster recovery.
- Rolling upgrade: dashboard/workers/reconciler независимо; media nodes по одному с drain. Версия MediaMTX и её API закреплена и проверяется при старте.
- SLO и retention задаются до реализации алертов: доступность control plane, успешность RTSP connect, freshness health checks, RPO/RTO.

## 9. Этапы реализации

1. Зафиксировать ADR, capacity assumptions, SLO, threat model и FFmpeg contract.
2. Развернуть production foundation: PostgreSQL, migrations, secrets, config, CI, pinned MediaMTX.
3. Реализовать каталог, RBAC dashboard, группы, безопасный CRUD и аудит.
4. Реализовать reconciler и hot-update одного path с read-back/rollback/retry.
5. Реализовать bounded probe scheduler/workers и профили OMNY.
6. Реализовать metrics collector, dashboard статистики и alerts.
7. Провести security hardening и backup/restore drills.
8. Провести ступенчатые load/chaos tests, определить предел одного media node.
9. При необходимости включить L4 frontend и sharding нескольких MediaMTX nodes.
10. Пилот 100 камер, затем контролируемые волны миграции; реализация начинается только после утверждения issues.

## 10. Definition of Done продукта

- оператор выполняет весь штатный CRUD и диагностику из dashboard;
- изменение/добавление/удаление одной камеры не обрывает остальные потоки;
- FFmpeg-клиент стабильно работает через configurable single port, RTSP-over-TCP;
- секреты защищены, действия операторов аудируются, management endpoints не опубликованы наружу;
- доказанная нагрузочными тестами capacity envelope и documented scaling procedure;
- проверены rolling update, node/camera outage, reconnect storm, backup restore и credential rotation;
- runbooks позволяют дежурному диагностировать и восстановить систему без ручного редактирования БД или MediaMTX config.
