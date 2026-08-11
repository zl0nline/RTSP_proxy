# RTSP Proxy domain language

Этот файл определяет язык проекта. Implementation details, status и планы
находятся в [docs/PRODUCTION_PLAN.md](docs/PRODUCTION_PLAN.md); архитектурные
решения — в [docs/adr](docs/adr).

## Server

Один Linux host, на котором работают control plane, PostgreSQL и media nodes.

_Не называйте server «node»: в проекте node всегда означает один MediaMTX
runtime внутри server._

## Control plane

Dashboard/API, workers, reconciler, collector и PostgreSQL-состояние, которые
управляют media plane, но не передают RTP.

## Media node

Один независимо управляемый MediaMTX process/systemd instance с собственными
config, runtime identity, log и одним внешним RTSP port. Media node содержит
не более 100 registered cameras и является отдельным media failure domain.

_Не называйте media node «shard», «gateway» или физическим server._

## Node port

Уникальный внешний TCP port media node на server. Он выбирается из configured
range автоматически случайным образом или задаётся оператором вручную. Смена
node port — disruptive node restart.

## Camera

Catalog object одного private RTSP source. Camera учитывается в node capacity,
пока зарегистрирована, независимо от enabled, source-ready или occupied state.

## Registered camera

Camera с current placement на media node. Hard limit — 100 registered cameras
на node.

_Не используйте active source или reader count вместо registered count при
admission._

## Source

Private camera RTSP endpoint, который MediaMTX pulls on demand. Source address и
credentials никогда не раскрываются downstream consumer.

## Public ID

Opaque immutable external path name camera. Public ID идентифицирует path, но
не является credential.

## Placement

Authoritative binding camera к ровно одной media node. Placement определяет
node port и, следовательно, внешний endpoint camera.

## Automatic placement

Default placement policy: eligible node с минимальным registered count, затем
минимальным active source count, затем минимальным stable node id. Если eligible
node отсутствует, orchestrator может создать новую в пределах max_nodes/ports.

## Manual placement

Явный выбор eligible target node оператором. Manual placement не может обойти
лимит 100 cameras/node.

## Camera move

Audited change placement generation. Move может изменить внешний URL. Occupied
ordinary move запрещён; forced move требует подтверждения и disconnect.

_Не называйте move failover: автоматического failover в текущем продукте нет._

## Desired state

Node/camera/config state, принятый control plane и committed в PostgreSQL.

## Applied state

Desired configuration, read-back verified на конкретной media node.

## Runtime state

Observed process/path/source/reader state. Runtime state не является source of
truth и может быть stale/absent.

## Eligible node

RUNNING, healthy, fresh, not draining/maintenance/deleting media node с менее
чем 100 registered cameras.

## Occupied stream

Camera path с одним active downstream reader. Второй concurrent reader получает
RTSP 453 и не становится ожидающим вторым consumer.

## Consumer

External client, обычно FFmpeg, читающий ordinary
`rtsp://server:node_port/public_id` по interleaved TCP.

## Access policy

Два независимых CIDR-набора `internet` и `local`. Если оба пусты, IP stage
разрешает всех. Иначе directly observed TCP peer должен входить хотя бы в один
набор. IP stage выполняется до downstream credential verification.

## Downstream credentials

Camera-specific username/password, которыми consumer авторизуется у proxy.
Они отделены от source credentials.

## Drain

Node state, запрещающий new sessions и placements при сохранении existing
reader до disconnect/deadline. Force завершает remaining sessions после
explicit confirmation.

## Maintenance

Administrative node state вне automatic placement/admission. Maintenance может
следовать после drain и не означает node failure.

## Failure incident

Один непрерывный outage media node. Incident создаёт одно failure email и после
recovery одно confirmation email; repeated reminder отсутствует.

## Reconciler

Control-plane process, converging PostgreSQL desired state и configured state
конкретных media nodes посредством targeted loopback management API calls.

## Probe

Bounded observation source/path/node health. Probe не должен занимать или
вытеснять единственный downstream reader slot.

## Capacity envelope

Измеренная workload/hardware комбинация. Per-node envelope и per-server
node-count envelope публикуются отдельно. `max_nodes` — configuration limit, не
capacity evidence.

## Blast radius

Набор cameras/sessions, которые допустимо затронуть disruptive operation.
Camera CRUD имеет path-only radius; node restart/port change — node-only radius;
cross-node interruption запрещён.
