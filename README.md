# RTSP Proxy

[![CI](https://github.com/zl0nline/RTSP_proxy/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/zl0nline/RTSP_proxy/actions/workflows/ci.yml)
[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB.svg)](https://www.python.org/)
[![Linux amd64 / arm64](https://img.shields.io/badge/Linux-amd64%20%7C%20arm64-FCC624.svg)](deploy/PILOT_INSTALL.md)
[![License: PolyForm NC](https://img.shields.io/badge/license-PolyForm%20Noncommercial-blue.svg)](LICENSE)

Платформа управления RTSP-прокси на одном Linux-сервере. Камеры распределяются
по независимым MediaMTX-нодам: каждая нода работает отдельным systemd-процессом,
занимает один внешний RTSP-порт и обслуживает не более 100 зарегистрированных
камер.

> [!IMPORTANT]
> Проект готов к контролируемой установке на pilot-сервер, но пока имеет статус
> **Production NO-GO**. До промышленного развёртывания нужны испытания с реальными
> камерами, замер ёмкости целевого сервера и 24-часовой soak test. Начинайте с
> одной ноды и нескольких камер.

## Что даёт система

- до 100 зарегистрированных камер на одну ноду;
- отдельный внешний RTSP-порт и отдельный MediaMTX-процесс для каждой ноды;
- `max_nodes=50` по умолчанию, с возможностью увеличить лимит до 100;
- автоматическое размещение на наименее загруженной ноде или ручной выбор;
- добавление и изменение камеры без остановки остальных потоков ноды;
- отдельные поля логина/пароля исходной камеры с шифрованием в PostgreSQL;
- перенос камер между нодами с проверкой активного reader и blast radius;
- один downstream-клиент на камеру; второй получает RTSP `453`;
- отдельные CIDR allowlist для internet и local access;
- HTTPS dashboard, RBAC, встроенный локальный вход, необязательный OIDC для
  локального IdP и аварийный break-glass вход;
- агрегированную статистику по серверу, нодам и камерам;
- email при аварии и одно подтверждение после восстановления;
- immutable releases, проверяемые обновления и автоматический health rollback.

Клиент подключается к обычному RTSP endpoint:

```text
rtsp://<server>:<node_port>/<public_id>
```

Поддерживается стандартный RTSP interleaved TCP. Адрес исходной камеры и её
credentials остаются внутри платформы. Для доступа клиент использует отдельный
выданный grant; секрет показывается только один раз.

## Модель нод

```text
                                  ┌─ Media node A ─ RTSP :port-A ─ ≤100 cameras
FFmpeg / VLC ─ ordinary RTSP/TCP ─┼─ Media node B ─ RTSP :port-B ─ ≤100 cameras
                                  └─ Media node N ─ RTSP :port-N ─ ≤100 cameras
                                              ▲
                                              │ loopback control
Operator ─ HTTPS dashboard/API ─ control plane ─ PostgreSQL
```

Нода не обязана быть заполнена полностью: конфигурация `50 / 10 / 80 / 100`
камер корректна. Порт выбирается случайно из настроенного диапазона или задаётся
оператором. При исчерпании диапазона создание ноды завершается явной ошибкой.

Операции с одной нодой не должны затрагивать другие ноды. Смена порта или
restart прерывает только потоки выбранной ноды и требует подтверждения
фактического blast radius. Удалить ноду можно только после удаления всех камер
и остановки процесса. Автоматического failover и multi-server cluster пока нет.

## Текущий статус

| Область | Статус |
|---|---|
| Registry нод, размещение камер и lifecycle | Реализовано |
| Изоляция MediaMTX-процессов и портов | Реализовано, native amd64/arm64 CI |
| Camera CRUD, move, drain и one-reader `453` | Реализовано |
| Двухуровневые ACL и camera grants | Реализовано |
| Dashboard, RBAC, local login, optional local OIDC, audit и email | Реализовано |
| HTTPS management boundary | Реализовано |
| Immutable install, update и rollback tooling | Реализовано |
| Глубокие source/path probes | Кандидат проверен; production scheduling выключен |
| Реальные камеры, capacity и 24h soak | Прямая диагностика начата; proxy acceptance и нагрузочные gates не закрыты |
| Production admission | **NO-GO** |

Подробная матрица реализованных фаз и оставшихся gates находится в
[Production plan](docs/PRODUCTION_PLAN.md), а воспроизводимые результаты — в
[`docs/evidence/`](docs/evidence/).

Текущие результаты и очередь работ:
[аудит pilot-контура от 5 сентября 2026](docs/evidence/production-audit-2026-09-05.md).

## Быстрый старт для pilot-сервера

Поддерживаемый контур: direct Linux без Docker, Ubuntu 24.04 (amd64 или arm64),
Python 3.12, systemd, PostgreSQL и nftables. Ubuntu 26.04 допускается для pilot
mechanism testing с отдельно установленными Python 3.12 и проверенным `uv`.

Полная пошаговая инструкция: **[Pilot installation, update and rollback](deploy/PILOT_INSTALL.md)**.

Примеры установки соответствуют кандидату `0.15.1`; используйте только bundle
из полностью успешного CI для его точного коммита. Release `0.13.1`
исправляет загрузку local-auth credentials, а `0.13.2` также убирает скрытую
зависимость installer-а от development venv в source checkout. Release `0.13.3`
нормализует release tree, `0.13.4` — и root-managed Python независимо от
пользовательского `umask`, а `0.13.5` создаёт закрытые runtime socket
directories с группами, которым разрешено обращаться к helper-процессам. Release
`0.13.6` также не изменяет владельца `.git/index` при проверке checkout из-под
`sudo`, поэтому последующие обновления остаются доступны обычному оператору.
Release `0.13.7` ожидает readiness до 30 секунд после systemd restart и не
откатывает исправный релиз только из-за обычного времени запуска процессов.
Release `0.13.8` разрешает встроенным local operator accounts выполнять
штатные мутации нод и камер с тем же аудитом, что OIDC и break-glass identities.
Release `0.13.9` сохраняет закрытые каталоги отдельных media nodes, но даёт их
DynamicUser право пройти через общие runtime/state/log parents.
Release `0.13.10` разрешает runtime helper только необходимый `CAP_SYS_PTRACE`
для проверки identity DynamicUser-процесса и принимает канонический формат
management permissions из MediaMTX API.
Release `0.14.0` устраняет блокеры пилотного добавления камер: явно показывает
пустую source-CIDR policy, принимает credentials камеры только отдельными полями,
хранит их в PostgreSQL в шифрованном виде, сохраняет безопасные поля формы при
ошибке и добавляет смену пароля локального оператора через dashboard/API/CLI.
Кандидат `0.15.0` добавляет отмену диагностических запросов, политику периодических
проверок и атомарное хранение состояния в schema 0023. Фоновый worker ещё
выключен; это не допуск к production. Установленный pilot `0.14.0` автоматически
не обновляется. Подробнее: [границы реализации](docs/evidence/phase-g-routine-health-state.md).
Кандидат `0.15.1` дополнительно запрещает специальные адреса независимо от ширины
source CIDR и проверяет поддельные протоколы на входе broker. Schema остаётся 0023;
фоновый worker по-прежнему не включён.
Release
`0.13.0` несовместим с фактическим mode системных credentials и после
активации уходит в restart loop. Dashboard привязывается к конкретному IP
management LAN; доступ с другого компьютера требует маршрута и разрешённого
TCP 8000 до этого IP.

Минимальный порядок действий:

1. Скачать architecture-specific release bundle из успешного CI run.
2. Checkout exact commit из manifest и проверить чистоту working tree.
3. Проверить или установить host prerequisites:

   ```sh
   sudo --preserve-env=RTSP_PROXY_DEPLOY_UV \
     ./tools/bootstrap_rtsp_proxy_host.sh --check
   ```

4. Установить immutable release и статические host assets без запуска сервисов:

   ```sh
   sudo --preserve-env=RTSP_PROXY_DEPLOY_UV \
     ./tools/install_rtsp_proxy.sh --bundle /srv/rtsp-proxy-bundles/<release>-<arch>
   ```

5. Настроить PostgreSQL, management TLS, secrets, nftables и environment files
   по [`deploy/PILOT_INSTALL.md`](deploy/PILOT_INSTALL.md).
6. Явно задать сети камер и создать локальный keyring командой
   `tools/configure_camera_sources.sh`; пустой список сетей означает deny-all.
7. Выполнить migration и одной интерактивной командой создать первого
   локального администратора. Для этого не нужен IdP.
8. Активировать release и включить сервисы в указанном в runbook порядке.
9. Проверить backup/restore, update rollback и только затем подключить несколько
   тестовых камер.

Installer намеренно не создаёт secrets, не меняет активные env-файлы, не
мигрирует БД, не переключает `current` и не запускает сервисы. Это отдельные
явные операторские шаги.

## Вход операторов без облака

RTSP Proxy не требует внешнего сервера авторизации и не передаёт учётные данные
в облако. После первой migration установщик локальной авторизации создаёт
обычного администратора в PostgreSQL; вход выполняется по локальному имени и
паролю на `/auth/local/login`. TOTP можно добавить сразу, но он необязателен для
обычного входа и нужен для действий, требующих недавнего MFA.

Пароль меняется в меню оператора «Сменить пароль». Текущая сессия остаётся
активной, остальные сессии этой учётной записи отзываются. Если WEB недоступен,
используйте интерактивный CLI с `--rotate-password --username admin`; CLI
отзывает все web-сессии учётной записи.

Если в закрытом контуре уже есть собственный IdP, OIDC можно включить как второй
способ входа. Локальные аккаунты при этом продолжают работать. `break-glass` —
отдельная аварийная учётная запись, а не повседневный локальный логин. Точный
порядок первичной настройки описан в
[pilot-runbook](deploy/PILOT_INSTALL.md#5-создание-первого-локального-администратора).

## Добавление камер и source credentials

До первой камеры укажите точные camera/VLAN CIDR. Пустой
`RTSP_PROXY_PROBE_SOURCE_CIDRS` намеренно запрещает регистрацию любой камеры и
отображается предупреждением в dashboard. Подготовить policy и локальный
keyring сразу для WEB и reconciler можно одной командой:

```sh
sudo ./tools/configure_camera_sources.sh \
  --release-id 0.15.1 \
  --source-cidrs '10.180.5.0/24,192.168.50.0/24'
```

В форме камеры вводите `rtsp://camera-host/path` без userinfo, а логин и пароль —
в отдельных полях. Они шифруются AES-256-GCM локальным versioned keyring,
привязанным к UUID камеры; API, dashboard, аудит и таблица `cameras` их не
возвращают. Не удаляйте `camera-source-keys.json`: без него credentialed-камеры
fail closed.

## Обновление и rollback

Application update выполняется тем же проверенным release bundle:

```sh
sudo --preserve-env=RTSP_PROXY_DEPLOY_UV \
  ./tools/update_rtsp_proxy.sh \
  --bundle /srv/rtsp-proxy-bundles/<new-release>-<arch> \
  --environment-file /etc/rtsp-proxy/control-plane/rtsp-proxy.env \
  --health-url https://management.example.net:8000/health/ready \
  --ca-file /etc/ssl/certs/ca-certificates.crt
```

Update проверяет manifest, artifact digests, source commit, lock file и
совместимость live schema. Затем он атомарно переключает `/opt/rtsp-proxy/current`,
перезапускает только ранее активные control-plane units и проверяет HTTPS
readiness. При ошибке symlink автоматически возвращается на совместимый
предыдущий release.

Media nodes не перезапускаются массово: смена MediaMTX release выполняется
отдельной drain/preview/confirmed операцией для конкретной ноды. Alembic
downgrade в работающей системе не поддерживается; после несовместимой migration
нужен fix-forward или восстановление заранее сделанного PostgreSQL backup.

## Проверка pilot

Перед увеличением числа камер зафиксируйте:

- exact release manifest и deployment receipt;
- успешный PostgreSQL backup/restore drill;
- HTTPS, local login, при включении OIDC, break-glass и SMTP accepted/rejected drills;
- create/start/stop/restart ноды и полный camera CRUD/move;
- сохранение работающего потока при изменении другой камеры;
- `453` для второго reader;
- ordinary FFmpeg RTSP/TCP playback для каждого профиля камеры;
- CPU, RAM, file descriptors, network, PostgreSQL и MediaMTX metrics;
- update с автоматическим health rollback;
- 24-часовой soak и не менее 30% hard-resource headroom.

Значение `max_nodes` — это config limit, а не обещание ёмкости. Фактический
предел определяется только измерениями на конкретном сервере.

## Разработка

```sh
uv sync --locked --all-groups
uv run pytest
uv run ruff check src tests
uv run mypy
uv build
git diff --check
```

Контракты с внешними media binaries запускаются отдельно:

```sh
MEDIAMTX_BINARY=/path/to/mediamtx \
FFMPEG_BINARY=/path/to/ffmpeg \
FFPROBE_BINARY=/path/to/ffprobe \
uv run pytest -m contract tests/contract
```

## Документация

| Документ | Назначение |
|---|---|
| [Pilot install](deploy/PILOT_INSTALL.md) | Первая установка, update, rollback и real-camera gate |
| [Deployment runbook](deploy/README.md) | Полный direct-Linux layout, security и operations |
| [Production plan](docs/PRODUCTION_PLAN.md) | Нормативная архитектура, roadmap и Definition of Done |
| [Engineering context](CONTEXT.md) | Инварианты и правила разработки |
| [ADR registry](docs/adr/README.md) | Принятые архитектурные решения |
| [Evidence](docs/evidence/) | Native CI и воспроизводимые contract results |
| [SLI catalog](docs/SLI_CATALOG.md) | Метрики и SLI/SLO definitions |
| [Capacity worksheet](docs/CAPACITY_WORKSHEET.md) | Шаблон квалификации сервера |
| [Failure-domain matrix](docs/FAILURE_DOMAIN_MATRIX.md) | Blast radius и recovery behavior |
| [Risk register](docs/RISK_REGISTER.md) | Открытые технические и operational risks |
| [Load harness](tools/load/README.md) | Reproducible load/netem qualification |

## Ограничения

- один Linux server; cluster и automatic camera failover отсутствуют;
- только RTSP interleaved TCP; RTSPS, UDP/multicast и redirects не входят в
  media contract;
- один downstream reader на camera;
- management API доступен только через HTTPS, node API/metrics — только через
  loopback;
- Production admission невозможен без hardware-specific capacity/soak evidence.

## License

Проект распространяется по лицензии
[PolyForm Noncommercial 1.0.0](LICENSE). Для коммерческого использования
требуется отдельное письменное разрешение правообладателя.
