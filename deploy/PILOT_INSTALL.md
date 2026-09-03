# Пилотная установка, обновление и откат

Эта инструкция предназначена для первых испытаний на direct-Linux сервере. Она
устанавливает ту же структуру неизменяемых релизов и те же systemd-компоненты,
которые проверяются в CI, но **не является допуском к промышленной эксплуатации**:
production scheduling для Phase G, испытания с реальными камерами, soak test и
подтверждение ёмкости оборудования пока не завершены.

Интерфейс развёртывания содержит шесть команд:

- `install` размещает один проверенный релиз и устанавливает статические файлы
  хоста, но намеренно не переключает `current` и не запускает сервисы;
- `stage` размещает только неизменяемый релиз;
- `install-assets` устанавливает версионированные определения
  systemd/sysusers/tmpfiles;
- `activate` проверяет текущую ревизию PostgreSQL, переключает `current`,
  перезапускает только ранее активные компоненты control plane и проверяет HTTPS
  readiness;
- `update` объединяет размещение релиза, обновление системных файлов и активацию
  с автоматическим возвратом symlink при ошибке readiness, если manifest
  предыдущего релиза всё ещё поддерживает неизменившуюся ревизию БД;
- `rollback` активирует уже установленный релиз, только если его manifest
  поддерживает текущую ревизию БД. Команда никогда не запускает Alembic
  downgrade.

Эти команды никогда не перебирают и не перезапускают экземпляры media nodes.
Смена версии MediaMTX конкретной ноды остаётся отдельной операцией
drain/preview/confirmed reconfigure, описанной в
[deploy/README.md](README.md).

## 1. Требования к pilot-серверу

Используйте выделенный systemd-сервер с Ubuntu 24.04 на amd64 или arm64, где
установлены:

- Python 3.12, `uv`, PostgreSQL, nftables, curl, jq и git;
- systemd с socket activation и transient services;
- bpffs, смонтированный в `/sys/fs/bpf`, и подходящий рабочий `bpftool` для
  тестов probe broker;
- один management-адрес с сертификатом и диапазон внешних RTSP-портов нод;
- работающие DNS и NTP до начала установки.

Ubuntu 26.04 также допускается для проверки pilot-механизма, но её системный
Python новее версии, которую поддерживает приложение. Сначала установите
проверенный принадлежащий root исполняемый файл `uv`, затем разрешите bootstrap
разместить Python 3.12 внутри неизменяемого префикса приложения:

```sh
cd /srv/rtsp-proxy-source
sudo --preserve-env=RTSP_PROXY_DEPLOY_UV \
  ./tools/bootstrap_rtsp_proxy_host.sh --install
sudo --preserve-env=RTSP_PROXY_DEPLOY_UV \
  ./tools/bootstrap_rtsp_proxy_host.sh --check
```

Bootstrap устанавливает только системные зависимости и отдельный Python 3.12.
Он не устанавливает RTSP Proxy, не изменяет данные PostgreSQL, не монтирует
bpffs, не редактирует firewall и не включает сервисы. Скрипт намеренно не
скачивает `uv`: оператор должен самостоятельно установить проверенный релиз как
обычный файл mode `0755`, принадлежащий root. Это исключает непроверенный
curl-to-shell bootstrap в привилегированном контуре.

PostgreSQL и источники камер должны находиться только в сетях, явно разрешённых
политикой хоста. Не публикуйте node API/metrics и сокет probe broker за пределами
сервера. Первое испытание проводите на одной ноде и небольшом числе камер;
продуктовый лимит остаётся равным 100 зарегистрированным камерам на ноду.

## 2. Получение точного исходного кода и release bundle

Скачайте `rtsp-proxy-release-amd64` или `rtsp-proxy-release-arm64` из успешного
CI run для устанавливаемого коммита. Артефакт содержит manifest, wheel и
architecture-specific binaries; конфигураций и секретов в нём намеренно нет.

На сервере переключитесь на точный коммит из manifest и убедитесь, что checkout
не содержит изменений:

```sh
git clone https://github.com/zl0nline/RTSP_proxy.git /srv/rtsp-proxy-source
cd /srv/rtsp-proxy-source
git checkout --detach '<manifest-git-commit>'
test -z "$(git status --porcelain=v1 --untracked-files=all)"
```

Создавать source-venv командой `uv sync` на сервере не требуется: installer
сам экспортирует только runtime-зависимости из проверенного lock-файла и
создаёт отдельный venv внутри release directory. `uv sync --all-groups` нужен
только разработчику, который собирается запускать тесты из checkout.

Checkout может принадлежать обычному оператору, который затем запускает
installer через `sudo`. Installer передаёт Git одноразовый локальный параметр
`safe.directory` только для чтения `HEAD` и статуса этого точного каталога. Он
не изменяет глобальную конфигурацию Git, поэтому выполнять
`git config --global --add safe.directory ...` или менять владельца всего
checkout не требуется.

Распакуйте CI-артефакт в принадлежащий root staging-каталог, например
`/srv/rtsp-proxy-bundles/0.13.4-amd64`. Не переименовывайте файлы внутри него.
Перед созданием целевого virtual environment installer требует точного
совпадения исходного `HEAD`, digest файла `uv.lock` и commit из manifest.

Если `uv` расположен не в `/usr/local/bin/uv`, задайте абсолютный путь к
принадлежащему root исполняемому файлу:

```sh
export RTSP_PROXY_DEPLOY_UV=/root/.local/bin/uv
```

Installer отвергает `uv`, принадлежащий не root или доступный для записи группе
либо остальным пользователям.

## 3. Размещение первого релиза и системных файлов

Запускайте команду из точного чистого checkout исходного кода:

```sh
cd /srv/rtsp-proxy-source
sudo --preserve-env=RTSP_PROXY_DEPLOY_UV \
  ./tools/install_rtsp_proxy.sh \
  --bundle /srv/rtsp-proxy-bundles/0.13.4-amd64
```

Команда выполняет следующие действия:

1. захватывает эксклюзивную блокировку `/run/lock/rtsp-proxy-deploy.lock`;
2. копирует symlink-free bundle в приватный staging-каталог;
3. получает фиксированные runtime dependencies из точного чистого source lock;
4. создаёт venv непосредственно внутри будущего неизменяемого release path;
5. запускает упакованный `rtsp-proxy-verify-release` для каждого артефакта;
6. запрещает запись группе и остальным пользователям и атомарно переименовывает
   релиз;
7. устанавливает systemd/sysusers/tmpfiles assets и примеры env-файлов;
8. запускает `systemd-sysusers`, `systemd-tmpfiles` и
   `systemctl daemon-reload`.

При копировании bundle сохраняются обычные POSIX permission bits, включая
executable bit у `mediamtx`, `ffmpeg`, `ffprobe` и служебных binaries. Перед
установкой каждый исполняемый артефакт запускается verifier из нового venv.

Команда **не** создаёт секреты, не редактирует активные env-файлы, не мигрирует
PostgreSQL, не переключает `/opt/rtsp-proxy/current`, не включает units и не
запускает media nodes. Примеры размещаются в `/etc/rtsp-proxy/examples/` и
никогда не используются сервисами напрямую.

## 4. Настройка сервера

Перед активацией:

1. скопируйте необходимые примеры в active paths; минимальный набор для WEB и
   reconciler показан ниже. Не запускайте сами файлы через `source` — это
   systemd environment files;
2. установите management TLS как один принадлежащий root combined PEM и
   атомарный symlink;
3. создайте PostgreSQL-роли с минимально необходимыми правами с помощью SQL
   artifacts из точного checkout;
4. установите access peppers и, если используются, SMTP/OIDC/break-glass
   credentials через `LoadCredential`; никогда не размещайте секреты в
   env-файлах или аргументах командной строки;
5. установите принадлежащую приложению nftables policy с фактическим диапазоном
   портов нод, затем включите её reconciliation unit;
6. перед включением проверьте каждый unit.

Создайте минимальные active environment files:

```sh
sudo install -d -o root -g rtsp-proxy-access -m 0750 \
  /etc/rtsp-proxy/control-plane
sudo install -o root -g rtsp-proxy-access -m 0640 \
  /etc/rtsp-proxy/examples/rtsp-proxy.env.example \
  /etc/rtsp-proxy/control-plane/rtsp-proxy.env
sudo install -o root -g rtsp-proxy-access -m 0640 \
  /etc/rtsp-proxy/examples/rtsp-proxy-role.env.example \
  /etc/rtsp-proxy/control-plane/rtsp-proxy-reconciler.env
```

Откройте оба файла редактором и обязательно замените
`RTSP_PROXY_DATABASE_URL`, `RTSP_PROXY_CONFIRMATION_SECRET`, release identity,
SHA-256 MediaMTX и диапазоны портов. Не добавляйте пустую строку
`RTSP_PROXY_NODE_PORT_RESERVED=`: если резервируемых портов нет, параметр должен
отсутствовать. Остальные роли копируйте только при их фактическом включении:
`collector.env.example` → `/etc/rtsp-proxy/collector.env`,
`notifier.env.example` → `/etc/rtsp-proxy/notifier.env`,
`node-runtime.env.example` → `/etc/rtsp-proxy/node-runtime.env`,
`probe-broker.env.example` → `/etc/rtsp-proxy/probe-broker.env` и
`rtsp-proxy-auth.env.example` →
`/etc/rtsp-proxy/control-plane/rtsp-proxy-auth.env`.

Проверьте unit-файлы:

```sh
sudo systemd-analyze verify \
  /etc/systemd/system/rtsp-proxy-*.service \
  /etc/systemd/system/rtsp-proxy-*.socket
```

Для новой базы данных запускайте migration из размещённого релиза, а не из
source venv:

```sh
sudo systemd-run --wait --pipe --collect \
  --uid=rtsp-proxy --gid=rtsp-proxy \
  --property=EnvironmentFile=/etc/rtsp-proxy/control-plane/rtsp-proxy.env \
  /opt/rtsp-proxy/releases/0.13.4/.venv/bin/rtsp-proxy-migrate
sudo -u postgres psql --dbname rtsp_proxy --tuples-only --no-align \
  --command 'SELECT version_num FROM alembic_version;'
```

Вторая команда должна вывести `0021_local_operator_login`. Отсутствие вывода
первой команды само по себе не считается успехом; проверяйте её exit status и
фактическую ревизию schema до создания администратора.

Перед каждым последующим изменением schema создавайте backup PostgreSQL.
Alembic downgrade на работающей системе не поддерживается.

## 5. Создание первого локального администратора

Внешний IdP для работы RTSP Proxy не требуется. После migration выполните одну
интерактивную команду; пароль дважды читается с терминала и не попадает ни в
argv, ни в environment file, ни в журнал команд:

```sh
cd /srv/rtsp-proxy-source
sudo ./tools/configure_local_auth.sh \
  --release-id 0.13.4 \
  --username admin \
  --display-name 'Administrator' \
  --with-totp
```

Скрипт создаёт защищённый локальный encryption key, сначала записывает
администратора в PostgreSQL, затем включает local login в WEB environment,
устанавливает systemd `LoadCredential` drop-in и выполняет `daemon-reload`.
При ошибке создания аккаунта local login не активируется. Сохраните показанный
`otpauth://` URI в локальном authenticator: он выводится один раз. Параметр
`--with-totp` можно опустить — вход по имени и паролю останется полноценным, но
операции, требующие недавнего MFA, будут закрыты.

OIDC — необязательный второй способ входа для собственного IdP внутри закрытого
контура. Его можно включить позже по разделу authentication в
[полном deployment runbook](README.md), не отключая локальные аккаунты. RTSP
Proxy не устанавливает, не вызывает и не требует облачный IdP. Аварийный
`break-glass` настраивается отдельно и не используется как обычный аккаунт.

## 6. Первая активация

Активируйте релиз только после полной готовности конфигурации, TLS и базы данных:

```sh
sudo /opt/rtsp-proxy/releases/0.13.4/.venv/bin/rtsp-proxy-deploy activate \
  --release-id 0.13.4 \
  --environment-file /etc/rtsp-proxy/control-plane/rtsp-proxy.env \
  --health-url https://management.example.net:8000/health/ready \
  --ca-file /etc/ssl/certs/ca-certificates.crt
```

При первой активации активных units ещё нет, поэтому команда только переключит
symlink, не запуская их. Явно включите sockets/services в документированном
порядке зависимостей, затем потребуйте успешную readiness-проверку и выполнение
native probe-broker contract. Из шаблонного unit включайте только
`rtsp-proxy@reconciler.service`: отдельная роль `rtsp-proxy@probe.service` в
этом релизе не реализована, а unit намеренно пропустит её запуск без restart
loop. Пока не включайте production probe scheduling.

Полезные команды для проверки:

```sh
sudo /opt/rtsp-proxy/current/.venv/bin/rtsp-proxy-deploy status
readlink /opt/rtsp-proxy/current
sudo systemctl --failed
sudo journalctl -u 'rtsp-proxy*' --since '-10 min' --no-pager
```

Не содержащий секретов deployment receipt хранится в
`/var/lib/rtsp-proxy/deployment.json`, принадлежит root и имеет mode `0600`.

После запуска WEB откройте
`https://<management-address>:8000/auth/local/login` и проверьте успешный вход,
неверный пароль и выход. Если OIDC настроен, страница локального входа также
покажет отдельную ссылку на локальный IdP.

`RTSP_PROXY_HTTP_HOST` должен содержать конкретный IP интерфейса management LAN,
а не `127.0.0.1` и не wildcard `0.0.0.0`. Сертификат обязан содержать этот IP в
Subject Alternative Name. Проверьте доступ сначала на сервере, а затем с
другого компьютера той же сети:

```sh
sudo ss -ltnp | grep ':8000'
curl --fail --cacert /path/to/management-ca.crt \
  https://<management-address>:8000/health/ready

# Следующую команду выполните уже с другого компьютера management LAN.
curl --fail --cacert /path/to/management-ca.crt \
  https://<management-address>:8000/auth/local/login
```

Оба запроса должны пройти без `--insecure`. Если локальный запрос успешен, а
удалённый получает `connection refused` или `network unreachable`, проверьте
маршрут от клиентской подсети и входной firewall/ACL до TCP 8000. Доступный
SSH-порт через NAT или port forwarding сам по себе не означает, что внутренний
management-IP маршрутизируется с рабочего компьютера. Не меняйте bind на
`0.0.0.0` для обхода этой проблемы.

## 7. Обновление приложения

Никогда не обновляйте систему из dirty checkout или непроверенного произвольного
каталога. Скачайте новый architecture-specific artifact, переключитесь на его
точный commit, проверьте чистоту checkout и создайте backup PostgreSQL. Source
venv для update не нужен: runtime-зависимости создаются installer-ом из
проверенного lock-файла.

Перед переключением команда update проверяет, что *текущая* ревизия базы данных
находится в rolling window manifest нового релиза:

```sh
cd /srv/rtsp-proxy-source
sudo --preserve-env=RTSP_PROXY_DEPLOY_UV \
  ./tools/update_rtsp_proxy.sh \
  --bundle /srv/rtsp-proxy-bundles/0.13.4-amd64 \
  --environment-file /etc/rtsp-proxy/control-plane/rtsp-proxy.env \
  --health-url https://management.example.net:8000/health/ready \
  --ca-file /etc/ssl/certs/ca-certificates.crt
```

Перезапускаются только units, которые были активны до переключения. Media nodes
продолжают обслуживать обычные RTSP/TCP sessions. Если HTTPS readiness не
проходит, `current` возвращается на предыдущий релиз и те же units запускаются
на прежней версии — но только пока неизменившаяся schema остаётся с ней
совместима.

Для релиза с additive schema последовательность намеренно разделена:

1. обновить все процессы control plane до bridge-compatible кандидата;
2. выполнить smoke-проверку dashboard, helpers, collector/notifier и одного
   обычного потока;
3. один раз запустить migration из нового неизменяемого релиза;
4. повторно применить PostgreSQL role artifacts, необходимые новой ревизии;
5. по очереди перезапустить роли и выполнить smoke list для этой ревизии.

Deploy tool не объединяет шаги 1 и 3, потому что migration может навсегда
сделать предыдущее приложение несовместимым. После migration rollback разрешён,
только если manifest целевого релиза всё ещё содержит точную live revision.

## 8. Откат и fix-forward

Чтобы откатить код приложения на установленный совместимый релиз:

```sh
sudo /opt/rtsp-proxy/current/.venv/bin/rtsp-proxy-deploy rollback \
  --release-id 0.12.0 \
  --environment-file /etc/rtsp-proxy/control-plane/rtsp-proxy.env \
  --health-url https://management.example.net:8000/health/ready \
  --ca-file /etc/ssl/certs/ca-certificates.crt
```

`database_schema_incompatible_with_release` — безусловная остановка операции.
В таком состоянии используйте проверенный fix-forward релиз либо остановите
control plane и восстановите backup PostgreSQL, сделанный перед migration.
Никогда не редактируйте `alembic_version`, не запускайте live downgrade и не
перенаправляйте `current` вручную.

Откат binary media node выполняется отдельно и требует activation-compatible
identity из catalog, а также node drain/confirmation workflow. Deploy tool
намеренно не умеет массово перезапускать media nodes.

## 9. Gate первого испытания с реальными камерами

Начните с одной ноды и нескольких камер. Перед увеличением их количества
зафиксируйте:

- точный release manifest и deployment receipt;
- результат проверки backup/restore базы данных;
- accepted/rejected drills для HTTPS и local login; OIDC только если он включён;
- отдельные accepted/rejected drills для break-glass и SMTP;
- create/start/stop ноды, add/update/move/delete камеры и `453` при занятом
  потоке;
- обычное FFmpeg-воспроизведение через interleaved TCP для каждого профиля
  камеры;
- success, refusal, timeout и cleanup для source/path probes при всё ещё ручном
  управлении scheduling;
- CPU, RSS, file descriptors, network, PostgreSQL и MediaMTX metrics;
- update с health rollback и один явный schema-compatible rollback.

Только после стабильной работы малого pilot-контура переходите к проверке
лимита 100 камер на ноду или нескольких нод. Ёмкость сервера определяется
измерениями и не должна выводиться из настроенного значения `max_nodes`.

## 10. Если установка остановилась

Installer завершает операцию без частично активированного релиза и печатает
диагностический код. Для ошибки внешней команды сообщение содержит безопасное
имя команды, exit code и ограниченный stderr, если он был захвачен, например:

```text
deployment failed: host_command_failed command=git exit_code=128 stderr=...
```

Наиболее частые проверки:

| Сообщение | Что проверить |
|---|---|
| `source_checkout_not_exact_release_commit` | `git rev-parse HEAD`, отсутствие modified/untracked файлов и commit из manifest |
| `source_lock_mismatch` | файл `uv.lock` взят из того же точного commit |
| `uv_unavailable` | `RTSP_PROXY_DEPLOY_UV` указывает на существующий executable |
| `uv_untrusted` | файл `uv` принадлежит root и недоступен для записи группе/остальным |
| `release_bundle_contains_unexpected_entry` | bundle распакован без переименования или добавления файлов |
| `version_probe_failed:<artifact>` | выбран bundle нужной архитектуры и его binaries не повреждены |
| `database_schema_incompatible_with_release` | live schema входит в compatibility window выбранного manifest |
| `local operator CLI missing` | `--release-id` совпадает с установленным release directory |
| `RTSP_PROXY_DATABASE_URL is missing` | активный WEB env содержит непустой URL PostgreSQL |
| `operator_auth_file_invalid` сразу после local-auth bootstrap | установлен release не ниже 0.13.1; он корректно принимает root-owned systemd credentials mode `0440` |
| migration завершилась с `status=203/EXEC`, `126` или `Permission denied` | установлен release не ниже 0.13.4; он нормализует release tree и root-managed Python при любом `umask` оператора |
| `local_operator_store_unavailable` | migration 0021 применена и PostgreSQL доступен локально |
| `local_operator_password_confirmation_failed` | пароль не короче 12 символов и оба ввода совпадают |

После исправления причины безопасно повторите ту же команду: незавершённый
приватный staging-каталог удаляется автоматически, а уже установленный релиз
принимается повторно только при точном совпадении manifest.

Не исправляйте установку ручным переключением `current`, отключением verifier,
изменением `alembic_version` или выдачей `0777`. Если причина всё ещё неясна,
сохраните полный текст команды и её вывода, предварительно убедившись, что в нём
нет локальных путей или иной информации, которую нельзя публиковать.
