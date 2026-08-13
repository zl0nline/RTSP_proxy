# Direct Linux deployment

Docker/container runtime не входит в deployment contract. Target —
systemd-based Linux host с Python 3.12 и несколькими bounded MediaMTX nodes.
Linux amd64/arm64 имеют одинаковые functional/security/release gates; capacity
публикуется отдельно для конкретного hardware.

## Desired immutable layout

```text
/opt/rtsp-proxy/
├── releases/
│   └── <release-id>/
│       ├── .venv/
│       ├── bin/{mediamtx,ffmpeg,ffprobe}
│       ├── dist/rtsp_proxy-<version>-py3-none-any.whl
│       ├── release-manifest.json
│       └── uv.lock
└── current -> releases/<release-id>

/etc/rtsp-proxy/
├── control-plane/rtsp-proxy.env
└── nodes/<node-id>/mediamtx.yml

/var/lib/rtsp-proxy/
└── nodes/<node-id>/
```

Release directories and `current` are root-owned and immutable to runtime
users. Per-node config is generated atomically from PostgreSQL desired state by
a narrow privileged installation boundary. Browser/web input cannot become an
arbitrary path, unit name or command.

## Services

- `rtsp-proxy-web.service` — management HTTPS/control application boundary.
- `rtsp-proxy@worker|reconciler|probe|collector.service` — background roles.
- `rtsp-proxy-media@<node-id>.service` — one MediaMTX process per media node.

Each media instance has:

- one external ordinary RTSP/TCP port from the node registry;
- unique loopback API/metrics ports;
- stable node id in environment/log identity;
- config/state paths restricted to that node;
- no access to another node's writable state.

`rtsp-proxy-media@<node-id>.service`, the per-node renderer and the scoped
`rtsp-proxy-node-runtime.socket`/helper implement the Phase C runtime. The
original single `mediamtx.service` and `mediamtx.yml.example` remain only as
Phase 0 compatibility-lab artifacts; they are not a multi-node installer.

The web process never executes `systemctl`. It sends one strict JSON line to
`/run/rtsp-proxy-node-runtime/control.sock`. The root helper validates the UUID,
allowed external/API/metrics ranges, pinned release and binary SHA-256; it can
address only `rtsp-proxy-media@<uuid>.service`. Configure its identical policy
in `/etc/rtsp-proxy/node-runtime.env` from `node-runtime.env.example`, then
enable the socket and helper. API and metrics always bind loopback; the external
ordinary `rtsp://` listener is TCP-only.

The helper, not the web process, creates separate random Basic credentials for
loopback management and the path-scoped `__rtsp_proxy_runtime_probe` reader,
renders the complete config, writes root-only `management.json`, `reader.json`
and `runtime.env`, and pins the absolute verified binary path. Neither identity
can perform the other's actions. The MediaMTX instance
uses `DynamicUser` and receives only its own config through systemd credentials;
it cannot traverse `/etc/rtsp-proxy/nodes` or read another node's management
secret. Keep control/helper port ranges, release id and binary SHA identical;
the shipped example files are checked together in CI.

## Global config

Typed control config includes:

- external node port range and reserved ports;
- management observation freshness deadline (30 seconds by default);
- `max_nodes=50`, configurable to at most 100;
- management HTTPS bind;
- PostgreSQL pools;
- node API/metrics loopback ranges;
- drain timeout;
- SMTP recipients/delivery policy;
- architecture-specific release manifest.

Unknown fields, invalid/overlapping ranges, non-loopback node management binds
and architecture/digest mismatch fail before readiness.

## Node lifecycle

Create:

1. transactionally reserve a random/manual external port;
2. persist node and internal endpoints;
3. render/validate/fsync/rename config;
4. start exact systemd instance;
5. verify PID/release/config identity and loopback API/metrics;
6. run ordinary RTSP/TCP smoke;
7. mark RUNNING.

Stop/restart/port change require drained state or explicit force confirmation.
Only the selected instance is touched. Delete requires zero camera placements
and stopped/failed state. Port is released only after listener/process cleanup
proof.

Lifecycle reconciliation uses
`RTSP_PROXY_NODE_LIFECYCLE_LOCK_POOL_SIZE` bounded workers/connections per web
replica and fails a lock acquisition after
`RTSP_PROXY_NODE_LIFECYCLE_LOCK_TIMEOUT_SECONDS` with retryable
`node_lifecycle_busy`/`Retry-After: 1` for operations on an existing node. If a
manual create has already committed its node/port reservation, it instead
returns `201`, the `PROVISIONING` node and its `Location`; continue with that
node's `/start` endpoint and do not retry the create request. The root helper
requires at least 20 seconds of cleanup reserve; the default reserves 25
seconds of its 55-second operation budget for cleanup; the media unit stops in
at most 15 seconds and the remaining time is kept for systemd status and port
release proof.

## Artifact catalog and activation

`artifact-catalog.json` pins FFmpeg/ffprobe URLs and digests. MediaMTX is built
directly on Linux by `tools/build_mediamtx.sh` from one exact upstream commit,
one SHA-256-bound local patch and Go `1.26.5`; resulting amd64/arm64 binary
digests and the distinct `v1.20.0-rtsp-proxy.1` identity are pinned in the same
catalog. The patch makes `maxReaders` a synchronous non-disruptive hot update
and maps a rejected late SETUP to RTSP 453. Example release manifests bind the
resulting identity. Python wheel is platform-independent; native artifacts are
verified per architecture.

Before changing `current`, run from candidate environment:

```sh
/opt/rtsp-proxy/releases/<release-id>/.venv/bin/rtsp-proxy-verify-release \
  --manifest /opt/rtsp-proxy/releases/<release-id>/release-manifest.json
```

Verifier reads actual Linux architecture, validates artifact paths/digests and
version/schema compatibility. Missing/mutable/symlink-escaped artifacts abort
activation.

Before starting a control-plane release, apply the migrations packaged inside
that exact wheel environment:

```sh
RTSP_PROXY_DATABASE_URL='postgresql+psycopg://rtsp_proxy@127.0.0.1:5432/rtsp_proxy' \
  /opt/rtsp-proxy/releases/<release-id>/.venv/bin/rtsp-proxy-migrate
```

The runner upgrades to the packaged `head` and uses the same direct native
PostgreSQL contract on amd64 and arm64. The release manifest and application
are bound to that exact head; startup reads live `alembic_version` and fails
closed on an older or newer revision. Backup/restore and rollback gates still
apply; an older binary must never start against an unsupported newer schema.

`0005_node_runtime` intentionally rejects an upgrade when legacy Phase-B
`media_nodes` rows exist. Those rows lack trustworthy per-node management
ports, credentials and a release-specific binary identity. Export camera
intent, drain and remove those old node records, apply the migration, then
recreate nodes through the Phase-C create/provision workflow. Do not patch in
placeholder digests or arbitrary ports.

`0008_node_administration` adds durable port-change sagas and removes only the
node foreign keys from append-only placement/move history. Historical UUIDs
remain immutable evidence after an empty stopped node is deleted; current
placements still prevent deletion.

`0009_camera_move_safety` adds a bounded abort/cleanup state machine, current
reader blast-radius confirmation, persisted old/new RTSP ports and URLs, and a
closed prepared-target state. It also introduces the repository-owned patched
MediaMTX admission fence. The migration therefore refuses every non-empty
Phase-C node registry: an old row cannot prove that changing `maxReaders` is
non-disruptive. Stop control-plane writers and export an exact private manifest
while the database is still on `0008`:

```sh
sudo systemd-run --quiet --wait --pipe --collect \
  --uid=rtsp-proxy --gid=rtsp-proxy \
  --property=EnvironmentFile=/etc/rtsp-proxy/control-plane/rtsp-proxy.env \
  /opt/rtsp-proxy/current/.venv/bin/rtsp-proxy-phase-d-transition export \
  --manifest /var/lib/rtsp-proxy/phase-d-transition.json
```

Record the printed SHA-256 separately. Drain/delete the cameras through the
normal reconciler, stop/remove every node, and take a database backup. Apply
`0009`, activate the catalog-bound release, then run:

```sh
sudo systemd-run --quiet --wait --pipe --collect \
  --uid=rtsp-proxy --gid=rtsp-proxy \
  --property=EnvironmentFile=/etc/rtsp-proxy/control-plane/rtsp-proxy.env \
  /opt/rtsp-proxy/current/.venv/bin/rtsp-proxy-phase-d-transition restore \
  --manifest /var/lib/rtsp-proxy/phase-d-transition.json \
  --manifest-sha256 '<recorded-sha256>'
```

Restore reads the same control-plane environment as normal node registration.
It rejects a manifest above current `max_nodes`, outside current external/API/
metrics ranges, on a reserved external port, or when any listener is already in
use. The checks happen under the restore locks before any synchronous desired/
audit/outbox write; no node is started until the entire transaction commits.
Restore is idempotent,
validates tombstones, continues each node's normative revision and preserves
exact camera UUIDs, node ports and immutable `/<public_id>` paths. It is a local
maintenance command. Stable desired node state and maintenance intent are
restored exactly; transitional PROVISIONING/STARTING/STOPPING/DELETING state
blocks export, and a stopped/failed/maintenance node is never promoted to
running by restore. The command is never an HTTP endpoint. Do not rewrite old digests or
perform an in-place non-empty upgrade. Existing terminal history may retain
null endpoint snapshots when its deleted node no longer makes the old port
reconstructible; all new and active moves require exact endpoint snapshots.

Activation atomically switches `current`, reloads systemd and updates control
roles. The packaged versioned trust catalog supports a current pin and, during
a future rollout, one previous patched pin. Release `0.1.0` is the first patched
release and intentionally has no previous entry: stock v1.20.0 is not a safe
rollback target. Before an N→N+1 rollout, the new wheel must catalogue both N
and N+1 with distinct architecture-specific digests; only then may the helper's
three `PREVIOUS_*` values be set. Upgrade each node by draining it, stopping it, calling
`PUT /api/v1/nodes/<uuid>/release` with the new release id/digest, and starting
it again. The revision-fenced transition refuses a running, unconverged or
non-empty node. Remove the previous pin only after every node is upgraded.
When such a catalogued previous release exists, rollback uses the same
stopped-node transition and validation/smoke path.

## Security

- dedicated control-plane users and per-instance systemd `DynamicUser`;
- `NoNewPrivileges`, `ProtectSystem`, `ProtectHome`, `PrivateTmp`, bounded
  `ReadWritePaths`, address-family/syscall/capability restrictions;
- node API/metrics/auth callback on loopback only and protected by a unique
  per-node Basic credential;
- external listener ordinary RTSP/TCP only;
- no Docker socket or container dependency;
- secrets absent from argv, logs and world-readable config.

## Production admission

These artifacts are not an install approval by themselves. Production requires
node-instance isolation tests, PostgreSQL migrations/restore, ACL/auth/RTSP 453,
drain/move/port rollback, native amd64/arm64 contracts and measured per-node/
per-server capacity evidence described in the production plan.
