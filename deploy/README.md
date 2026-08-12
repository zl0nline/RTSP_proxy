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

The helper, not the web process, creates a random Basic credential for each
node, renders the complete config, writes root-only `management.json` and
`runtime.env`, and pins the absolute verified binary path. The MediaMTX instance
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

## Artifact catalog and activation

`artifact-catalog.json` pins MediaMTX, FFmpeg and ffprobe versions, URLs and
architecture-specific SHA-256. Example release manifests show resulting
identity. Python wheel is platform-independent; native artifacts are verified
per architecture.

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

Activation atomically switches `current`, reloads systemd and updates control
roles. It does not restart healthy media nodes unless the release procedure
explicitly drains and upgrades those instances one at a time. Rollback switches
to the last verified release and uses the same validation/smoke path.

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
