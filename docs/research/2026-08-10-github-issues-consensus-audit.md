# Аудит и remediation GitHub issues RTSP Proxy

Дата проверки: 2026-08-10

Репозиторий: `zl0nline/RTSP_proxy`
Проверенная ветка/commit: `main` / [`81e2d191c5f5013396c688670c1157669f56fe1d`](https://github.com/zl0nline/RTSP_proxy/tree/81e2d191c5f5013396c688670c1157669f56fe1d)

## Статус после remediation

После первичного аудита владелец поручил устранить найденные противоречия.
10 августа 2026 года через `gh issue edit` обновлены тела
[#3](https://github.com/zl0nline/RTSP_proxy/issues/3),
[#5](https://github.com/zl0nline/RTSP_proxy/issues/5),
[#7](https://github.com/zl0nline/RTSP_proxy/issues/7),
[#10](https://github.com/zl0nline/RTSP_proxy/issues/10),
[#11](https://github.com/zl0nline/RTSP_proxy/issues/11),
[#13](https://github.com/zl0nline/RTSP_proxy/issues/13) и
[#14](https://github.com/zl0nline/RTSP_proxy/issues/14).

| Finding | Resolution |
|---|---|
| Audit RPO0 против async `audit_events` | Нормативный audit всегда входит в synchronous quorum transaction; async разрешён только probes/ненормативной telemetry |
| `public_id` 22 base36 против ≥128 bit | Canonical `^[a-z0-9]{25}$`, uniform CSPRNG rejection sampling, ≈129.25-bit space |
| #11 p95 / cold `≤3s` | Pass/fail синхронизирован с #1: p99 warm `≤500ms`, cold proxy overhead `≤1s`, end-to-end informative `≤1s + GOP_max` |
| RAM `≤75%` против 30% headroom | Применяется пересечение gates: CPU `≤65%`, NIC/pps `≤60%`, FD/RAM `<70%` |
| Отсутствующие gateway/legacy signals | В #7 добавлены conditional signals, provenance, staleness/cardinality и evidence gates |
| Неопределённый legacy zero-session period | Минимум 30 дней compatibility + 7 consecutive full days fresh zero sessions |

Повторный автоматизированный поиск по всем 14 текущим телам не нашёл старые
22-char ID, async normative audit, unconditional cold `≤3s`, API p95-as-SLO,
RAM 75% или неопределённый zero-session period.

Открытый blocker #10 сохранён намеренно: это evidence gate на выбор scale-out
topology до Spike #0, а не внутреннее противоречие спецификации. Реализация и
production readiness по-прежнему не заявлены.

Ниже сохранён исходный аудит до remediation как traceability record.

## Исходный вердикт до исправлений

На момент первичного аудита строгое условие «серьёзных замечаний по реализации
нет» **не было выполнено**.

Причины:

1. В репозитории пока нет реализации: на `main` находятся только `README.md`, `docs/PRODUCTION_PLAN.md` и `LICENSE`. Поэтому подтвердить отсутствие дефектов реализации невозможно; можно оценить только план и его исполнимость ([текущий README прямо признаёт это](https://github.com/zl0nline/RTSP_proxy/blob/81e2d191c5f5013396c688670c1157669f56fe1d/README.md#L122-L124)).
2. [Issue #10](https://github.com/zl0nline/RTSP_proxy/issues/10) прямо имеет статус «архитектурный BLOCKER не снят»: финальная topology неизвестна до Spike #0. Это не мешает начать ограниченную evidence-фазу, но блокирует утверждение, что production-архитектура выбрана.
3. Для pinned MediaMTX остаются обязательные развилки и contract spikes: semantics management API/hot update/restart в [#5](https://github.com/zl0nline/RTSP_proxy/issues/5), механизм external auth/static users и TLS lifecycle в [#9](https://github.com/zl0nline/RTSP_proxy/issues/9). Они блокируют соответствующие implementation decisions.
4. После обновления тел issues остались две существенные спецификационные ошибки: конфликт durability-аудита в #5 и несоответствие алфавита `public_id` заявленным 128 битам в #3. Их нужно закрыть до реализации data/security foundation.

При этом **ремонтная переработка** `PRODUCTION_PLAN.md` полезна и не должна ждать выполнения spikes, если документ честно сохраняет `NO-GO`, не выдаёт гипотезы за выбранную архитектуру и перечисляет противоречия как обязательные pre-implementation decisions. Нельзя переписывать план с выводом «серьёзных замечаний нет» или оставлять статус `PLANNING: READY` без уточнения, что готов только consensus по процессу доказательства.

## Метод и полнота

GitHub-данные получены исключительно через GitHub CLI:

- `gh issue list --state all --limit 1000` — полный реестр;
- `gh issue view <n> --json body,comments,...` — тело и все комментарии каждого issue;
- `gh api repos/zl0nline/RTSP_proxy/issues/comments/<id>` — полное чтение длинных комментариев без усечения;
- `gh api repos/zl0nline/RTSP_proxy/commits/main` — проверка текущего commit.

Проверено **14 issues: 14 open, 0 closed**, всего **83 комментария**. Pull requests не подменялись issues. Все тела, consensus-комментарии, последующее внешнее ревью и поправка к ревью #1 прочитаны полностью. Веб-браузинг не использовался.

## Как читать статус consensus

Consensus в этих issues означает «согласован контракт и способ доказательства», а не «решение реализовано и подтверждено». Это явно закреплено в итоговом verdict [#14](https://github.com/zl0nline/RTSP_proxy/issues/14#issuecomment-5203794735) и подтверждено [Кошем](https://github.com/zl0nline/RTSP_proxy/issues/14#issuecomment-5203800651):

- planning discussion complete;
- implementation не авторизована;
- production не готов;
- capacity 10k не доказана;
- topology, MediaMTX semantics и rollback внешних клиентов остаются evidence-dependent.

Поздний внешний аудит обнаружил, что исполнимая спецификация должна находиться в телах issues, а не только в длинных комментариях ([#14 external audit](https://github.com/zl0nline/RTSP_proxy/issues/14#issuecomment-5239002700)). Большинство замечаний после этого внесено в тела, однако сквозные хвосты ниже остались.

## Реестр всех issues

| Issue | Comments | Принятый результат | Текущий риск / статус |
|---|---:|---|---|
| [#1 Architecture](https://github.com/zl0nline/RTSP_proxy/issues/1) | 8 | Initial p99 SLO, capacity formulas, failure domains, ADR template, 70% trigger/30% headroom, RPO/RTO/retention ([consensus](https://github.com/zl0nline/RTSP_proxy/issues/1#issuecomment-5203616016)) | Тело обновлено после аудита: cold start разделён на proxy overhead и GOP; TCP-only внесён как инвариант. Первое возражение по health freshness было [снято самим аудитором](https://github.com/zl0nline/RTSP_proxy/issues/1#issuecomment-5239205856). |
| [#2 Foundation](https://github.com/zl0nline/RTSP_proxy/issues/2) | 4 | Immutable MediaMTX digest, executable compatibility, DB connection budget, tracing, role health, dev/prod images, Alembic ([consensus](https://github.com/zl0nline/RTSP_proxy/issues/2#issuecomment-5203644293)) | Тело обновлено: restart-level config, effective-config readiness и forward-only production rollback учтены ([audit](https://github.com/zl0nline/RTSP_proxy/issues/2#issuecomment-5239000477)). |
| [#3 Data](https://github.com/zl0nline/RTSP_proxy/issues/3) | 7 | Catalog/groups/grants/secrets/audit, alias rotation, lifecycle/admin mode, revision-aware health ordering, partition/backup/HA contracts ([consensus](https://github.com/zl0nline/RTSP_proxy/issues/3#issuecomment-5194579027)) | **HIGH:** regex `^[a-z0-9]{22,}$` не обеспечивает заявленные ≥128 бит. Остальные замечания аудита по endpoint uniqueness, namespace и bloat отражены ([audit](https://github.com/zl0nline/RTSP_proxy/issues/3#issuecomment-5239000672)). |
| [#4 Dashboard/RBAC](https://github.com/zl0nline/RTSP_proxy/issues/4) | 6 | Authz version fencing, no-oracle, SSE epoch checks, merge matrix, bounded bulk, secret reveal, WORM audit ([consensus](https://github.com/zl0nline/RTSP_proxy/issues/4#issuecomment-5203578073)) | Тело обновлено: URL без userinfo по умолчанию, clipboard boundary, три conflict/apply состояния, closed bulk enum ([audit](https://github.com/zl0nline/RTSP_proxy/issues/4#issuecomment-5239000855)). |
| [#5 Reconciler](https://github.com/zl0nline/RTSP_proxy/issues/5) | 7 | Transactional outbox, active writers, target fencing, placement saga, read-back, forward repair, delete/drain, startup inventory ([consensus](https://github.com/zl0nline/RTSP_proxy/issues/5#issuecomment-5194355988)) | **BLOCKED ON EVIDENCE:** strict HA correctness and per-path isolation depend on pinned MediaMTX. **HIGH:** internal contradiction on audit durability. Runtime/config verification and media-node restart risks incorporated after [audit](https://github.com/zl0nline/RTSP_proxy/issues/5#issuecomment-5239001002). |
| [#6 Health](https://github.com/zl0nline/RTSP_proxy/issues/6) | 7 | Two-level health, separate health/freshness/admin states, guaranteed interval plus risk sampling, bounded fairness, SSRF containment ([consensus](https://github.com/zl0nline/RTSP_proxy/issues/6#issuecomment-5194293178)) | Тело обновлено: `source_probe`/`path_probe`, camera session limit и pinned ffprobe timeout units ([audit](https://github.com/zl0nline/RTSP_proxy/issues/6#issuecomment-5239001142)). |
| [#7 Observability](https://github.com/zl0nline/RTSP_proxy/issues/7) | 5 | Signal inventory, TSDB/cardinality/query budgets, bitrate/reset/staleness, OTel, polling/SSE, alerts/baselines ([consensus](https://github.com/zl0nline/RTSP_proxy/issues/7#issuecomment-5203665154)) | Тело обновлено для absent on-demand series, alert provenance, dead-man switch и proxy-safe SSE ([audit](https://github.com/zl0nline/RTSP_proxy/issues/7#issuecomment-5239001308)). Но обязательные gateway-amplification и legacy-path metrics, на которые ссылаются #10/#13, здесь не перечислены. |
| [#8 FFmpeg](https://github.com/zl0nline/RTSP_proxy/issues/8) | 4 | FFmpeg + supervisor, TCP-only, recovery/backoff, keepalive budget, credential/argv boundary, regression matrix ([consensus](https://github.com/zl0nline/RTSP_proxy/issues/8#issuecomment-5203693281)) | Тело обновлено: активный UDP negative test, on-demand transitions и `/proc` secret check ([audit](https://github.com/zl0nline/RTSP_proxy/issues/8#issuecomment-5239001491)). |
| [#9 Security](https://github.com/zl0nline/RTSP_proxy/issues/9) | 7 | Separate access grants, verifier/pepper rotation, revoke/cache, layered rate limits, RTSPS, secret encryption, hardening ([consensus](https://github.com/zl0nline/RTSP_proxy/issues/9#issuecomment-5194410911)) | **BLOCKED ON EVIDENCE:** auth callback vs static users, established-session behavior, selective kill, cert hot reload/source-IP preservation. Media-node log leakage, KEK rotation and new-session dependency added after [audit](https://github.com/zl0nline/RTSP_proxy/issues/9#issuecomment-5239001677). |
| [#10 Scale](https://github.com/zl0nline/RTSP_proxy/issues/10) | 6 | L4→assigned-shard отвергнут; single-node first; gateway→origin only after capacity failure; ready-made L7 next; custom router last ([consensus](https://github.com/zl0nline/RTSP_proxy/issues/10#issuecomment-5194243909)) | **ARCHITECTURAL BLOCKER EXPLICITLY OPEN.** Тело исправлено на external routing vs origin ownership после [audit](https://github.com/zl0nline/RTSP_proxy/issues/10#issuecomment-5239001923). Есть численный headroom tail и отсутствующая связь с concrete #7 signals. |
| [#11 Performance](https://github.com/zl0nline/RTSP_proxy/issues/11) | 4 | Reproducible GStreamer load harness, LAN/WAN, baseline ladder, churn/chaos, A/B cost, cadence and gates ([consensus](https://github.com/zl0nline/RTSP_proxy/issues/11#issuecomment-5203727239)) | Pull-server generator, GOP и generator headroom внесены после [audit](https://github.com/zl0nline/RTSP_proxy/issues/11#issuecomment-5239002113). **HIGH doc tail:** pass/fail table всё ещё ссылается на отменённый cold `p95 ≤3s`. |
| [#12 Operations](https://github.com/zl0nline/RTSP_proxy/issues/12) | 5 | Immutable deploy, typed config, role health, drain/rollback, expand-contract, PITR/keys, logs and runbook drills ([consensus](https://github.com/zl0nline/RTSP_proxy/issues/12#issuecomment-5203753769)) | Тело обновлено: post-restore report-only safety, new-session auth window и restart-level network runbook ([audit](https://github.com/zl0nline/RTSP_proxy/issues/12#issuecomment-5239002326)). |
| [#13 Release](https://github.com/zl0nline/RTSP_proxy/issues/13) | 5 | Preflight/reconciliation states, canaries/waves/soak/abort, coexistence, rollback matrix, decision rights ([consensus](https://github.com/zl0nline/RTSP_proxy/issues/13#issuecomment-5203778377)) | Тело обновлено для camera session limits and client rollback boundary ([audit](https://github.com/zl0nline/RTSP_proxy/issues/13#issuecomment-5239002514)). Legacy-path metric отсутствует в #7, а zero-session close period не задан числом. |
| [#14 EPIC](https://github.com/zl0nline/RTSP_proxy/issues/14) | 8 | Dependency map, invariants, camera contract, evidence ordering, R1–R5; planning consensus does not authorize implementation ([verdict](https://github.com/zl0nline/RTSP_proxy/issues/14#issuecomment-5203794735)) | Тело issues в основном исправлено после [external audit](https://github.com/zl0nline/RTSP_proxy/issues/14#issuecomment-5239002700), но чекбокс «контракты непротиворечивы» сейчас преждевременен из-за перечисленных tails. |

## Замечания, которые блокируют безусловный вывод «можно реализовывать»

### B1. Реализации нет, а topology blocker открыт

Это не code-review finding, а граница доступного доказательства. [README](https://github.com/zl0nline/RTSP_proxy/blob/81e2d191c5f5013396c688670c1157669f56fe1d/README.md#L122-L124) прямо говорит, что репозиторий содержит архитектурный план. [#10](https://github.com/zl0nline/RTSP_proxy/issues/10) сохраняет BLOCKER до Spike #0; [EPIC #14](https://github.com/zl0nline/RTSP_proxy/issues/14) сохраняет R1–R5 и запрещает начинать реализацию без отдельного owner decision.

Следствие: допустимый следующий scope — evidence foundation/Phase 0, а не полный product build и не production readiness claim.

### B2. MediaMTX contract и auth/TLS fork не доказаны

[Reconciler consensus #5](https://github.com/zl0nline/RTSP_proxy/issues/5#issuecomment-5194355988) честно оставляет открытыми idempotency, per-path isolation, delete/auth semantics и API throughput. Поздний аудит добавил persistence after restart and runtime/config distinction ([#5 audit](https://github.com/zl0nline/RTSP_proxy/issues/5#issuecomment-5239001002)).

[Security consensus #9](https://github.com/zl0nline/RTSP_proxy/issues/9#issuecomment-5194410911) называет binary fork external callback vs static config users, revoke behavior, established sessions и certificate lifecycle обязательным spike. Эти ответы меняют data-at-rest boundary, auth availability и возможность выполнять заявленный revoke SLA; их нельзя оставить «на усмотрение реализации».

### B3. Audit durability в #5 противоречит itself и #4

В текущем [#5](https://github.com/zl0nline/RTSP_proxy/issues/5) одновременно записано:

- для desired state **и audit** production target RPO=0 при planned/automatic failover, API подтверждает write только после quorum synchronous acknowledgement;
- для `probe_results`/**`audit_events`** допустим `synchronous_commit=off`.

Это повторено в [consensus #5](https://github.com/zl0nline/RTSP_proxy/issues/5#issuecomment-5194355988). Но [#4](https://github.com/zl0nline/RTSP_proxy/issues/4) требует durable audit admission и fail-closed для destructive/security-sensitive operations.

В текущей модели `audit_events` — единственная заявленная таблица аудита, поэтому async commit может потерять именно событие, без которого destructive operation не должна считаться принятой. До Phase 1 нужно выбрать и записать один из двух проверяемых вариантов:

1. mutation/security-critical audit находится в той же synchronous quorum transaction, что desired state; async разрешён только отдельной явно non-critical telemetry/read-audit категории;
2. весь нормативный `audit_events` synchronous, а `synchronous_commit=off` остаётся только для `probe_results`.

Также нужно различать два корректно совместимых recovery target: HA failover RPO=0 для critical transaction и backup/PITR RPO≤5 min из [#1](https://github.com/zl0nline/RTSP_proxy/issues/1) / [#12](https://github.com/zl0nline/RTSP_proxy/issues/12).

### B4. `public_id` regex не даёт заявленные 128 бит

[#3](https://github.com/zl0nline/RTSP_proxy/issues/3) одновременно требует CSPRNG URL-safe identifier с энтропией ≥128 бит и разрешает форму `^[a-z0-9]{22,}$`.

Для алфавита из 36 символов 22 позиции дают:

```text
log2(36^22) = 22 * log2(36) ≈ 113.7 bit
```

То есть валидатор допускает identifier, который не соответствует собственному security contract. Поскольку `public_id` является внешним RTSP path и участвует в no-oracle/namespace boundary, это HIGH specification defect. Нужен canonical encoder и фиксированная длина, например base36 не короче 25 символов, либо другой явно заданный alphabet/length, действительно кодирующий ≥128 random bits. Regex и генератор должны проверяться одним executable contract.

## Остаточные сквозные противоречия и doc tails

### T1. #11 всё ещё использует отменённый latency contract

Канонический текущий [#1](https://github.com/zl0nline/RTSP_proxy/issues/1) устанавливает:

- warm `DESCRIBE→PLAY` **p99 ≤500 ms**;
- cold `proxy_overhead` **p99 ≤1 s**;
- cold end-to-end только информативно: **≤1 s + GOP_max**.

Однако [#11](https://github.com/zl0nline/RTSP_proxy/issues/11) в `Initial pass/fail thresholds` оставляет `warm p95 / cold p95 ≤500 ms / ≤3 s (#1)`, а catalog/CRUD — p95 вместо p99. Выше в том же #11 уже правильно написано, что cold измеряется при нескольких GOP и SLO относится к `proxy_overhead`, поэтому таблица противоречит и #1, и собственному тексту #11.

Это не новый архитектурный blocker, а **HIGH executable-spec tail**: тестовый harness будет реализован по таблице и даст ложный pass. Таблицу #11 и документы нужно привести к p99 contract #1; p95 можно сохранять как публикуемую диагностическую percentile, но не ссылаться на неё как на SLO #1.

### T2. Headroom RAM в #10 слабее общего gate

[#1](https://github.com/zl0nline/RTSP_proxy/issues/1), [#11](https://github.com/zl0nline/RTSP_proxy/issues/11) и [#13](https://github.com/zl0nline/RTSP_proxy/issues/13) требуют ≥30% headroom / `<70%` каждого hard resource. [#10](https://github.com/zl0nline/RTSP_proxy/issues/10) задаёт отдельные ceilings CPU≤65%, NIC≤60%, FD≤70%, **RAM≤75%**, то есть оставляет только 25% RAM headroom.

Это MEDIUM numeric tail. До ADR следует применять пересечение, то есть более строгий предел: CPU≤65%, NIC/pps≤60%, FD<70%, RAM<70%; любое ослабление — отдельный ADR по #1.

### T3. #10 требует production signals, которых нет в #7

[#10](https://github.com/zl0nline/RTSP_proxy/issues/10) объявляет обязательными `active_gateway_copies_per_path` и `origin_egress_amplification` и говорит, что они входят в signal inventory #7. Текущее тело [#7](https://github.com/zl0nline/RTSP_proxy/issues/7) их не перечисляет ни в catalog minimum, ни в alert table, ни в evidence gates.

Это MEDIUM cross-reference tail, не topology blocker. В плане они должны быть conditional signals, обязательными только если Spike #0 приводит к gateway tier; #7 должен иметь owner/source/availability semantics и alert threshold, полученный из Spike #1.

### T4. #13 требует legacy-path metric, которого нет в #7, и не задаёт N

[#13](https://github.com/zl0nline/RTSP_proxy/issues/13) фиксирует compatibility window 30 дней и закрытие окна после «нуля сессий в течение согласованного периода», ссылаясь на signal inventory #7. В [#7](https://github.com/zl0nline/RTSP_proxy/issues/7) такой signal отсутствует, а продолжительность zero-session периода `N` нигде не задана.

Это MEDIUM release-spec tail. Он не блокирует Phase 0/1, но блокирует migration exit gate. План должен оставить `N` явным required owner decision до pilot, а не молча выбрать число; signal должен получить source, freshness/reset semantics, retention и alert/owner.

### T5. Старый README и production plan повторяют старый cold SLO

Текущий README заявляет `warm <=500ms, cold <=3s, измеряются p95 и p99` ([строка 78](https://github.com/zl0nline/RTSP_proxy/blob/81e2d191c5f5013396c688670c1157669f56fe1d/README.md#L76-L86)). Предыдущий production plan повторяет это в numerical contract ([строки 390–393](https://github.com/zl0nline/RTSP_proxy/blob/81e2d191c5f5013396c688670c1157669f56fe1d/docs/PRODUCTION_PLAN.md#L388-L393)). Оба расходятся с обновлённым #1 и должны быть исправлены.

Также previous plan вводит established-media 99.5% как «consolidated gate» ([строки 394–408](https://github.com/zl0nline/RTSP_proxy/blob/81e2d191c5f5013396c688670c1157669f56fe1d/docs/PRODUCTION_PLAN.md#L394-L408)), тогда как текущий #1 фиксирует 99.0%, а control plane — 99.5%. Если 99.5% media сохраняется как release guardrail, его нужно явно отделить от согласованного product SLO, а не приписывать текущему consensus.

### T6. README показывает credential-bearing plain RTSP как основной URL

[README lines 16–20](https://github.com/zl0nline/RTSP_proxy/blob/81e2d191c5f5013396c688670c1157669f56fe1d/README.md#L16-L20) показывают `rtsp://user:password@...` как основной адрес. Но текущие contracts требуют:

- RTSPS для untrusted/external networks; plain RTSP только для explicit trusted VPN/private profile ([#9](https://github.com/zl0nline/RTSP_proxy/issues/9));
- URL без userinfo как default copy flow и отдельный audited secret reveal ([#4](https://github.com/zl0nline/RTSP_proxy/issues/4)).

README должен показывать безопасный default `rtsps://<host>:<port>/<public_id>` и отдельно объяснять grant provisioning/client configuration, не нормализуя долгоживущий пароль в URL/clipboard. Для trusted private profile можно привести явно маркированный `rtsp://` вариант.

### T7. Статус `PLANNING: READY` требует уточнения

README называет planning READY ([lines 5–10](https://github.com/zl0nline/RTSP_proxy/blob/81e2d191c5f5013396c688670c1157669f56fe1d/README.md#L5-L10)), а previous plan повторяет это ([lines 29–37](https://github.com/zl0nline/RTSP_proxy/blob/81e2d191c5f5013396c688670c1157669f56fe1d/docs/PRODUCTION_PLAN.md#L29-L37)). Это допустимо только в значении «consensus по evidence-first process завершён». Оно не означает «implementation spec непротиворечива»: #10 сохраняет BLOCKER, а B3/B4/T1 требуют решения/исправления.

Рекомендуемая формулировка: `PLANNING CONSENSUS: COMPLETE; SPEC CORRECTIONS: REQUIRED; PHASE 0: AWAITING OWNER AUTHORIZATION; PRODUCTION: NO-GO; 10K: NOT CLAIMED`.

## Принятые решения, которые новый план обязан сохранить

### Архитектурные инварианты

- Python/FastAPI — control plane, никогда media datapath; pinned MediaMTX — media plane ([#1](https://github.com/zl0nline/RTSP_proxy/issues/1)).
- RTSP-over-TCP interleaved only, external и source side; `sockets_per_session=1`; transport change — restart-level + ADR/capacity recalculation ([#1](https://github.com/zl0nline/RTSP_proxy/issues/1), [#2](https://github.com/zl0nline/RTSP_proxy/issues/2), [#8](https://github.com/zl0nline/RTSP_proxy/issues/8)).
- PostgreSQL — единственный desired-state source; JSON — только import/export; mutations atomically write desired revision, audit and outbox ([#3](https://github.com/zl0nline/RTSP_proxy/issues/3), [#5](https://github.com/zl0nline/RTSP_proxy/issues/5)).
- Established media sessions survive control-plane/DB outage on a live media node; new sessions depend on bounded auth-cache/fail-closed policy ([#1](https://github.com/zl0nline/RTSP_proxy/issues/1), [#9](https://github.com/zl0nline/RTSP_proxy/issues/9), [#12](https://github.com/zl0nline/RTSP_proxy/issues/12)).
- Ordinary CRUD is path-local and never restarts/reloads MediaMTX; isolation must be proven on the pinned digest ([#5](https://github.com/zl0nline/RTSP_proxy/issues/5)).
- Single-node capacity measured first. Gateway→origin and ready-made RTSP-aware L7 are conditional fallbacks; custom router last ([#10](https://github.com/zl0nline/RTSP_proxy/issues/10), [#14](https://github.com/zl0nline/RTSP_proxy/issues/14)).

### Canonical numerical contract

Until a versioned ADR changes it, use current #1/#4/#6/#8/#9/#11/#12/#13 values:

| Contract | Canonical value |
|---|---:|
| Warm `DESCRIBE→PLAY` | p99 ≤500 ms |
| Cold proxy contribution | `proxy_overhead` p99 ≤1 s |
| Cold end-to-end | informative ≤1 s + profile `GOP_max` |
| Catalog read / CRUD mutation | p99 ≤200 ms / ≤1 s |
| Deep observation freshness | ≥95% routine-enabled cameras no older than `2 × configured_interval`, by site/subnet |
| Manual add/change start | ≥99% within queue-delay SLO |
| Control-plane availability | ≥99.5% per month excluding planned maintenance |
| Established media-session availability | ≥99.0% per month, attributed platform vs camera-origin |
| Dashboard authz downgrade/revoke | ≤2 s, fail closed; upgrade ≤30 s |
| Media-grant revoke-new | ≤10 s; positive cache ≤5 s |
| FFmpeg supervisor recovery | p95 ≤10 s, max ≤35 s |
| Steady session establishment | ≥99.9% outside injected failures |
| Resource envelope | ≥30% headroom, 24h soak; use stricter per-resource #10 ceiling where applicable |
| PostgreSQL PITR / control recovery | RPO≤5 min / RTO≤30 min |
| Observability | ≤100k active series; ≤6 per enabled camera; query p95≤2 s |
| Retention | audit hot 12m/WORM 3y; probes raw 30d/aggregates 12m; metrics high-res 30d/downsampled 13m |
| Release | canary 5%; soak 24h/7d/48h; batch readable ≥99%, canary 100%; compatibility window 30d |

HA failover RPO=0 for critical desired+audit transaction is a separate stronger durability target and must not be conflated with PITR RPO≤5 min.

### Camera contract

The new plan should make the shared camera profile a first-class artifact as required by [#14](https://github.com/zl0nline/RTSP_proxy/issues/14): GOP/keyframe interval, `max_concurrent_rtsp_sessions`, main/sub paths, codec/audio and TCP support. These fields feed SLO, probes, load generation and migration preflight and need an owner before pilot.

### Phase ordering

1. Pre-Phase-0 specification corrections: B3, B4, T1–T4; ADR/SLI templates and owners.
2. Phase 0 evidence: pin digests, MediaMTX API/auth/TLS/restart spikes, pull-mode load harness, single-node knee, topology ADR.
3. Phase 1 foundation: #2→#3→#4→#5→#6, with vertical contract/security/migration tests.
4. Phase 2: #7/#8/#9 and full #11 load/chaos envelope.
5. Phase 3: #12 drills and #13 lab/pilot/waves with explicit go/no-go.

## Решение по запрошенной переработке документации

### Если понимать условие пользователя буквально

Не следует утверждать, что «серьёзных замечаний нет», и не следует выпускать план как implementation-ready. Нужно сначала сообщить о B1–B4 и получить решение владельца: исправлять спецификацию/evidence plan либо остановиться.

### Если разрешена переработка именно как remediation

`PRODUCTION_PLAN.md` и README можно и стоит переписать сейчас, но с такими условиями:

1. статус не выше `planning consensus complete / implementation NO-GO`;
2. B3/B4 и T1–T4 вынесены в обязательный pre-Phase-0 checklist;
3. #10 представлен как decision tree, а не выбранный gateway design;
4. current issue bodies являются нормативнее исторических consensus-комментариев там, где поздний аудит уже изменил contract;
5. historical [EPIC numerical comment](https://github.com/zl0nline/RTSP_proxy/issues/14#issuecomment-5203794735) не используется для возврата отменённых `cold ≤3s`, swapped availability или p95-as-SLO;
6. README не показывает insecure external URL как безопасный default;
7. ни один feature/capacity/security claim не описывается в настоящем времени как реализованный.

## Итог

Обсуждение качественное и в основном достигло устойчивого consensus: rejected L4 sharding удалён, late external-audit findings почти полностью встроены в тела issues, а неизвестные возможности оформлены как evidence gates. Но текущая спецификация всё ещё не даёт оснований сказать «серьёзных замечаний нет».

Наиболее важные действия до реализации:

1. исправить audit durability contract #5/#4;
2. исправить canonical `public_id` encoding/length #3;
3. синхронизировать #11 и документацию с current #1 cold-start/p99 contract;
4. добавить conditional gateway и legacy migration signals в #7 и определить owner/`N`;
5. выполнить Phase 0 spikes, после которых только и выбираются topology, auth и certificate lifecycle.
