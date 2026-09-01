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
uv sync --locked --all-groups
```

Распакуйте CI-артефакт в принадлежащий root staging-каталог, например
`/srv/rtsp-proxy-bundles/0.12.0-amd64`. Не переименовывайте файлы внутри него.
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
  --bundle /srv/rtsp-proxy-bundles/0.12.0-amd64
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

Команда **не** создаёт секреты, не редактирует активные env-файлы, не мигрирует
PostgreSQL, не переключает `/opt/rtsp-proxy/current`, не включает units и не
запускает media nodes. Примеры размещаются в `/etc/rtsp-proxy/examples/` и
никогда не используются сервисами напрямую.

## 4. Настройка сервера

Перед активацией:

1. скопируйте каждый необходимый пример в документированный active path и
   замените все placeholder endpoints, release IDs, architecture digests и
   диапазоны портов;
2. установите management TLS как один принадлежащий root combined PEM и
   атомарный symlink;
3. создайте PostgreSQL-роли с минимально необходимыми правами с помощью SQL
   artifacts из точного checkout;
4. установите access peppers и SMTP/OIDC/break-glass credentials через
   `LoadCredential`; никогда не размещайте секреты в env-файлах или аргументах
   командной строки;
5. установите принадлежащую приложению nftables policy с фактическим диапазоном
   портов нод, затем включите её reconciliation unit;
6. перед включением проверьте каждый unit:

```sh
sudo systemd-analyze verify \
  /etc/systemd/system/rtsp-proxy-*.service \
  /etc/systemd/system/rtsp-proxy-*.socket
```

Для новой базы данных запускайте migration из размещённого релиза, а не из
source venv:

```sh
sudo systemd-run --quiet --wait --pipe --collect \
  --uid=rtsp-proxy --gid=rtsp-proxy \
  --property=EnvironmentFile=/etc/rtsp-proxy/control-plane/rtsp-proxy.env \
  /opt/rtsp-proxy/releases/0.12.0/.venv/bin/rtsp-proxy-migrate
```

Перед каждым последующим изменением schema создавайте backup PostgreSQL.
Alembic downgrade на работающей системе не поддерживается.

## 5. Первая активация

Активируйте релиз только после полной готовности конфигурации, TLS и базы данных:

```sh
sudo /opt/rtsp-proxy/releases/0.12.0/.venv/bin/rtsp-proxy-deploy activate \
  --release-id 0.12.0 \
  --environment-file /etc/rtsp-proxy/control-plane/rtsp-proxy.env \
  --health-url https://management.example.net:8000/health/ready \
  --ca-file /etc/ssl/certs/ca-certificates.crt
```

При первой активации активных units ещё нет, поэтому команда только переключит
symlink, не запуская их. Явно включите sockets/services в документированном
порядке зависимостей, затем потребуйте успешную readiness-проверку и выполнение
native probe-broker contract. Пока не включайте production probe scheduling.

Полезные команды для проверки:

```sh
sudo /opt/rtsp-proxy/current/.venv/bin/rtsp-proxy-deploy status
readlink /opt/rtsp-proxy/current
sudo systemctl --failed
sudo journalctl -u 'rtsp-proxy*' --since '-10 min' --no-pager
```

Не содержащий секретов deployment receipt хранится в
`/var/lib/rtsp-proxy/deployment.json`, принадлежит root и имеет mode `0600`.

## 6. Обновление приложения

Никогда не обновляйте систему из dirty checkout или непроверенного произвольного
каталога. Скачайте новый architecture-specific artifact, переключитесь на его
точный commit, выполните `uv sync --locked --all-groups` и создайте backup
PostgreSQL.

Перед переключением команда update проверяет, что *текущая* ревизия базы данных
находится в rolling window manifest нового релиза:

```sh
cd /srv/rtsp-proxy-source
sudo --preserve-env=RTSP_PROXY_DEPLOY_UV \
  ./tools/update_rtsp_proxy.sh \
  --bundle /srv/rtsp-proxy-bundles/0.13.0-amd64 \
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

## 7. Откат и fix-forward

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

## 8. Gate первого испытания с реальными камерами

Начните с одной ноды и нескольких камер. Перед увеличением их количества
зафиксируйте:

- точный release manifest и deployment receipt;
- результат проверки backup/restore базы данных;
- accepted/rejected drills для HTTPS, OIDC/break-glass и SMTP;
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
