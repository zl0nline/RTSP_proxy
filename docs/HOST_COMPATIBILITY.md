# Совместимость Linux-хоста

RTSP Proxy поддерживает не список названий дистрибутивов, а профиль
`modern-systemd-linux-v1`. Дистрибутив считается совместимым, если конкретный
хост проходит `rtsp-proxy-host-doctor`; совпадение только по `ID` или
`VERSION_ID` из `/etc/os-release` ничего не гарантирует.

Это правило относится к запуску приложения. Допуск конкретного production
сервера дополнительно требует site evidence из
[production runbook](../deploy/PRODUCTION_RUNBOOK.md). Совместимость ОС не
является доказательством производительности и не заменяет camera/profile,
soak, recovery или capacity gates.

## Профиль `modern-systemd-linux-v1`

| Свойство | Минимум | Зачем требуется |
|---|---:|---|
| Архитектура | native `amd64` или `arm64` | Для этих архитектур выпускаются и проверяются MediaMTX, FFmpeg, probe ffprobe, BPF object и `bpftool` |
| Системный Python | 3.12 | Нужен только для bootstrap/doctor до установки приложения |
| Runtime Python | ровно 3.12 | Устанавливается отдельно в `/opt/rtsp-proxy/python`; системный Python 3.13/3.14 не подменяет runtime |
| glibc | 2.39 | Нижняя ABI-граница нативных release artifacts; musl не поддерживается |
| Linux kernel | 6.8 | Проверенная нижняя граница BPF/cgroup и process-isolation contract |
| systemd | 255, PID 1, state `running` | Нужны socket activation, transient units, credentials и sandbox directives |
| cgroup | unified cgroup v2 с `cpu`, `memory`, `pids` controllers | Exact destination guard и resource limits прикрепляются к transient probe unit |
| bpffs | смонтирован в `/sys/fs/bpf` | Хранит только project-owned pins и ownership receipts probe broker |
| Kernel BTF | читаемый `/sys/kernel/btf/vmlinux` | Нужен CO-RE BPF object |
| libc/runtime tools | обязательные команды и канонические `/usr/bin`, `/usr/sbin` paths | Deployment и systemd units используют проверенные абсолютные пути |

Проверка fail closed: старый kernel/systemd/glibc/Python, другой init, cgroup v1,
отсутствующий bpffs/BTF, неподдерживаемая архитектура или недостающая команда
дают стабильный `BLOCKER` code и ненулевой exit status. Bootstrap не пытается
«починить» kernel, переключить cgroup hierarchy или смонтировать bpffs.

IPv6 не является обязательным для IPv4-only site. Doctor проверяет bind на
`::1` и при отключённом IPv6 оставляет `supported=true`, но публикует capability
`ipv6=false` и `LIMITATION: ipv6_unavailable`. На таком хосте разрешены только
IPv4 management/source/client адреса; IPv6 camera CIDR или endpoint нельзя
допускать до включения IPv6 и повторной проверки. Exact-port BPF guard всё равно
загружает обе программы и fail-closed защищает доступное семейство. Native
contract проверяет доступные семейства, а полная dual-stack матрица остаётся
обязательной в CI. Bootstrap сам IPv6 не включает и sysctl не меняет.

## Дистрибутивы и package adapters

Автоматическая установка prerequisite-пакетов реализована для четырёх package
manager interfaces. Производный дистрибутив, например Armbian, определяется по
доступному manager и фактическим возможностям, а не отбрасывается из-за имени.

| Adapter | Семейства | PostgreSQL client | BPF dependency package |
|---|---|---|---|
| `apt-get` | Debian, Ubuntu и производные | `postgresql-client` | `bpftool` |
| `dnf` | Fedora, RHEL 10, Rocky 10, AlmaLinux 10 и производные | `postgresql` | `bpftool` |
| `zypper` | openSUSE Tumbleweed и совместимые современные профили | `postgresql` | `bpftool` |
| `pacman` | Arch Linux и производные | `postgresql-libs` | `bpf` |

Версия дистрибутива не зашита в код. Практическая нижняя граница — первый его
релиз, одновременно предоставляющий Python 3.12, glibc 2.39, systemd 255 и
kernel 6.8 либо более новые версии. Например, это включает Ubuntu 24.04 и
современные Fedora/RHEL-family releases; Debian 13, rolling openSUSE Tumbleweed
и Arch обычно проходят с более новыми версиями. Итог всегда определяет doctor
на конкретном хосте, а не эта иллюстрация.

На неизвестном systemd-дистрибутиве `--check` работает независимо от package
manager. Если все пакеты установлены вручную и профиль проходит, runtime
поддерживается. `--install` требует один из четырёх adapters и не угадывает
команды неизвестного manager.

## Bootstrap и doctor

Из точного чистого source checkout выполните:

```sh
sudo ./tools/bootstrap_rtsp_proxy_host.sh --install
./tools/bootstrap_rtsp_proxy_host.sh --check
```

`--install` выполняет только следующие действия:

1. выбирает package adapter и устанавливает prerequisite-пакеты;
2. повторно проверяет весь capability profile;
3. скачивает официальный архив `uv 0.12.3` для текущей архитектуры только по
   HTTPS URL из `deploy/bootstrap-artifacts.json`, ограничивает размер,
   проверяет SHA-256 и атомарно публикует root-owned mode `0755` binary;
4. через этот `uv` устанавливает отдельный CPython 3.12 в
   `/opt/rtsp-proxy/python` и нормализует read/execute permissions для service
   identities.

Скрипт не использует `curl | sh`, не создаёт RTSP Proxy users/configuration, не
запускает units, не меняет nftables policy, не создаёт/мигрирует PostgreSQL и не
монтирует bpffs. Package manager может обновить уже установленные зависимости,
включая systemd и libc, согласно политике репозитория ОС. До дальнейшей
установки проверьте `systemctl is-system-running`, сообщения package manager и
требование reboot; не активируйте RTSP Proxy поверх незавершённого обновления.

После установки release доступен тот же стабильный machine-readable interface:

```sh
/opt/rtsp-proxy/current/.venv/bin/rtsp-proxy-host-doctor --json
```

JSON содержит `profile`, `supported`, `blockers`, normalised architecture,
distribution metadata, versions, capability flags, `limitations` и выбранный
package adapter. Не парсите человекочитаемый текст и не определяйте поддержку
повторно в своих скриптах. Admission automation должна отдельно отклонять
IPv6 site configuration при наличии `ipv6_unavailable`.

Для закрытого контура заранее зеркалируйте pinned `uv` archive и изменяйте URL
только вместе с reviewed catalog/digest change. Существующий `uv` принимается
лишь как root-owned, не group/world-writable executable точной pinned версии.
Путь можно изменить через `RTSP_PROXY_DEPLOY_UV`; передача секрета для этого не
нужна.

## Почему `bpftool` находится в release

Системный пакет `bpftool` устанавливается для операторской диагностики и
проверки package adapter, но probe broker его не исполняет. Package builds
разных дистрибутивов имеют разные digests, поэтому доверять произвольному
`/usr/sbin/bpftool` означало бы ослабить BPF admission contract.

Каждый schema-5 release manifest включает architecture-specific
`libexec/rtsp-proxy-probe/bpftool`. Release verifier проверяет его SHA-256 по
встроенному trust catalog, исполнимость на текущем хосте и архитектуру до
activation. Broker получает путь
`/opt/rtsp-proxy/current/libexec/rtsp-proxy-probe/bpftool`; затем независимо
проверяет root ownership, permissions, digest, BPF object digest, тип и map graph
загруженных программ, точный map value, cgroup attachments и behavioural
canary. Обновление системного пакета не меняет исполняемый broker tool.

Загруженный BPF program tag намеренно не сравнивается со статическим значением
из build-host catalog. Tag вычисляется по уже CO-RE-relocated инструкциям и на
другом BTF/kernel может закономерно измениться при том же точном object digest.
Статическая проверка сделала бы «широкую поддержку» скрытым allowlist одного
kernel build. Подмена при этом не становится возможной: production branch при
каждой операции открывает root-owned `bpftool` и object по descriptor, повторно
сверяет их SHA-256, загружает object в новый owned pin scope, проверяет program
type, единственный exact map ID/value и оба attachment ID, а gate открывается
только после behavioural allow/deny canary. Runtime tag всё равно обязан иметь
валидный kernel format; reference tags остаются воспроизводимым CI evidence.

Если bundled tool не загружается из-за ABI/shared-library ошибки, release
verification останавливает установку. Нельзя обходить это подстановкой stock
tool, добавлением его digest «для удобства» или отключением connect guard.

## Distro-specific обязанности оператора

Capability profile намеренно не скрывает различия эксплуатации:

- PostgreSQL server может быть локальным или внешним; создание cluster/role,
  authentication policy, backup и WAL archive остаются distro/site-specific;
- firewalld, nftables managers и облачный firewall не должны перезаписывать
  project-owned table или открывать management/loopback listeners;
- SELinux enforcing требует site policy для точных executables, paths, sockets,
  BPF и network ports; bootstrap не отключает SELinux;
- AppArmor profile, если добавлен оператором, должен допускать те же точные
  paths/capabilities; bootstrap не переводит AppArmor в complain mode;
- CA bundle, management certificate, DNS, NTP, journald persistence, log
  retention и reboot policy настраиваются средствами дистрибутива;
- hardened kernels могут запретить BPF даже root с заявленными capabilities.
  Это выявляет native broker contract, а не название дистрибутива;
- пути приложения `/opt/rtsp-proxy`, `/etc/rtsp-proxy`,
  `/var/lib/rtsp-proxy` и `/run/rtsp-proxy-*` одинаковы на всех adapters; их не
  следует переносить distro-specific symlink-ами.

После kernel, systemd, libc, `bpftool`, nftables или security-policy upgrade
повторите doctor, release verification, `systemd-analyze verify`, nftables
read-back и native probe-broker smoke до возврата production admission.

## Проверочная матрица

- Основной native CI выполняет полный suite на Ubuntu 24.04 `amd64` и `arm64`.
- Package-adapter CI устанавливает реальные пакеты в Debian 13, Fedora 42,
  Rocky Linux 10, openSUSE Tumbleweed и Arch containers. Контейнеры проверяют
  userspace/package names, но не считаются systemd PID1/BPF evidence.
- Отдельный ARM hardware smoke выполняется на Armbian/Ubuntu 26.04 `arm64` с
  systemd 259, kernel 6.18, glibc 2.43, системным Python 3.14 и отключённым
  IPv6. Он проверяет detection/limitation, clean-host bootstrap, isolated
  Python, native release artifacts и IPv4 systemd/BPF contracts; это не
  нагрузочный стенд. Dual-stack BPF contract независимо проходит в native CI.
  Точный sanitized результат для 0.17.6 записан в
  [hardware evidence](evidence/host-compatibility-0.17.6-arm64-2026-09-11.md).

Каждый новый distro family или снижение минимальных версий требует реального
package-adapter job, native host evidence для kernel-facing частей и обновления
этого документа. Один успешный запуск приложения не расширяет опубликованный
контракт автоматически.
