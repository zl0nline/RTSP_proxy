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
- `rtsp-proxy@reconciler|probe.service` — mutable background roles.
- `rtsp-proxy-collector.service` — dedicated read-only fleet collector.
- `rtsp-proxy-notifier.service` — dedicated SMTP incident dispatcher.
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

Install `collector.env.example` as `/etc/rtsp-proxy/collector.env` and
`notifier.env.example` as `/etc/rtsp-proxy/notifier.env`, replacing the database,
artifact digest and SMTP endpoint values. The notifier password is deliberately
absent from the env file; install it separately as the root-owned credential
source consumed by `LoadCredential`.

The web process never executes `systemctl`. It sends one strict JSON line to
`/run/rtsp-proxy-node-runtime/control.sock`. The root helper validates the UUID,
allowed external/API/metrics ranges, pinned release and binary SHA-256; it can
address only `rtsp-proxy-media@<uuid>.service`. Configure its identical policy
in `/etc/rtsp-proxy/node-runtime.env` from `node-runtime.env.example`, then
enable the socket and helper. API and metrics always bind loopback; the external
ordinary `rtsp://` listener is TCP-only.

The collector does not share that control socket. It runs as the dedicated
`rtsp-proxy-collector` user and can reach only
`/run/rtsp-proxy-node-metrics/metrics.sock`; its separate root helper is
configured `READ_ONLY=true` and accepts only node `observe` plus MediaMTX
`metrics`. Provision/start/stop/reconfigure and path CRUD fail closed on this
socket even if the collector process is compromised.

Create the two least-privilege PostgreSQL roles before enabling those units:

```sh
sudo -u postgres psql --dbname rtsp_proxy --set DBNAME=rtsp_proxy \
  --file deploy/postgresql/rtsp_proxy_collector.sql
sudo -u postgres psql --dbname rtsp_proxy --set DBNAME=rtsp_proxy \
  --file deploy/postgresql/rtsp_proxy_notifier.sql
```

The collector can read only the non-secret node inventory and maintain fleet
snapshots/incidents. The notifier can only claim and complete existing
notification rows. Neither role can read camera source URLs/access grants nor
mutate node or camera desired state. Configure their local passwords, peer or
certificate authentication outside source control.

SMTP delivery also has a dedicated `rtsp-proxy-notifier` identity. systemd
copies the root-owned `/etc/rtsp-proxy/control-plane/smtp-password` into the
service credential directory as a single-link owner-only file; the source
secret is never exposed through an environment variable or to web/reconciler.
STARTTLS with hostname and CA verification is mandatory, and one absolute
deadline covers connect, EHLO, TLS, login and send.
The collector uses two-second helper/database calls and an eight-second maximum
collection cycle; its interruptible interval wait and 20-second join remain
inside `TimeoutStopSec=30s`. Notifier database operations are capped at two
seconds. With the supported 30-second SMTP deadline and eight-second join grace,
shutdown remains inside `TimeoutStopSec=45s`; a locked PostgreSQL statement
cannot leave either worker unbounded.

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

Ordinary stop requires an empty node. An empty RUNNING node can be restarted
directly. A non-empty DRAINING node uses the reconfigure/restart confirmation
workflow, while a RUNNING port change has its own confirmation workflow and
restarts every stream on that node. Both previews and applies require recent
MFA (`RTSP_PROXY_OPERATOR_RECENT_MFA_SECONDS=300` by default), exact rendered
revision/state, and the complete displayed camera/reader blast radius. Only the
selected instance is touched. Delete requires zero camera placements and
stopped/failed state. Port is released only after listener/process cleanup
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
release proof. A disruptive RUNNING-node fence has a separate 60-second
end-to-end deadline: the first 50 seconds include the helper action and any
port rollback, while the final 10 seconds are reserved exclusively for exact
path-admission restoration. At most two such applies run concurrently per web
process; a third fails with retryable `node_disruption_busy` before mutation.

## Artifact catalog and activation

`artifact-catalog.json` pins FFmpeg/ffprobe URLs and digests. MediaMTX is built
directly on Linux by `tools/build_mediamtx.sh` from one exact upstream commit,
two SHA-256-bound production patches, one deterministic race-regression patch,
and Go `1.26.5`; resulting amd64/arm64 binary
digests and the distinct `v1.20.0-rtsp-proxy.3` identity are pinned in the same
catalog. The MediaMTX patch makes `maxReaders` a synchronous non-disruptive hot
update and maps a rejected late SETUP to RTSP 453. The gortsplib v5.6.3 patch
locks the RECORD state transition that concurrent metrics collection reads.
The build first proves the regression fails on stock v5.6.3, then proves it and
the MediaMTX race suites pass after patching. Example release
manifests bind the resulting identity. Python wheel is platform-independent;
native artifacts are verified per architecture.

Before changing `current`, run from candidate environment:

```sh
/opt/rtsp-proxy/releases/<release-id>/.venv/bin/rtsp-proxy-verify-release \
  --manifest /opt/rtsp-proxy/releases/<release-id>/release-manifest.json
```

Verifier reads actual Linux architecture, validates artifact paths/digests and
version/schema compatibility. Missing/mutable/symlink-escaped artifacts abort
activation.

MediaMTX release `0.2.1` remains the race-safe native node target. Application
release `0.5.0` is the additive operator-login schema bridge: its manifest and
startup gate accept both `0012_operator_sessions` and `0013_operator_login`,
while release `0.4.0` remains on 0012. Deploy and smoke 0.5.0 on every
control-plane process before the database advances to 0013. This ordering
makes the N/N-1 window executable rather than merely declarative.
Existing OIDC account/session rows remain valid across this additive step.
Because schema 0012 did not carry verifiable password/TOTP material, migration
atomically disables an existing `break_glass` row, increments its authz fence
and revokes its sessions. The packaged `rtsp-proxy-break-glass` command upgrades
that same disabled identity with fresh password/TOTP material and another
monotonic authz revision; it never invents credentials in SQL. Readiness remains
red until this explicit reprovisioning and the accepted/rejected SMTP drill pass.

On a fresh installation, apply the migrations packaged inside the exact wheel
environment before starting any control-plane process:

```sh
RTSP_PROXY_DATABASE_URL='postgresql+psycopg://rtsp_proxy@127.0.0.1:5432/rtsp_proxy' \
  /opt/rtsp-proxy/releases/<release-id>/.venv/bin/rtsp-proxy-migrate
```

The runner upgrades to the packaged `head` and uses the same direct native
PostgreSQL contract on amd64 and arm64. For an additive rolling upgrade, do not
apply the new revision first: install, verify and smoke the bridge release on
every process while PostgreSQL remains at the old supported revision, then run
the packaged migration once. Release `0.5.0` declares the rolling window
`0012_operator_sessions..0013_operator_login`: first deploy the new
web/reconciler while PostgreSQL remains on 0012, then apply 0013. Keep
operator authentication disabled until every WEB process has the complete,
root-owned OIDC and break-glass configuration; once enabled it is a single
fail-closed runtime boundary, not an independently switchable set of stores.
The existing WORKER continues incident delivery while the database is on 0012
and deliberately does not touch the 0013 security-alert queue. Immediately
after applying 0013, rerun `deploy/postgresql/rtsp_proxy_notifier.sql` and
restart every WORKER. Its readiness stays red with
the stable external reason `outbox_unavailable` until that restart creates the
security-alert dispatcher (the internal diagnostic is
`security_dispatcher_restart_required`); this prevents a pre-migration worker
from reporting a false-green outbox boundary.

Application release `0.6.0` adds the index-only
`0014_camera_catalog_projection` revision. The release remains executable on
`0012_operator_sessions`, `0013_operator_login` and 0014 while processes are
rolled; install 0.6.0 everywhere before advancing PostgreSQL to 0014. Migration
0014 installs the trusted `pg_trgm` extension plus the camera name/public-path,
state and node-placement catalog indexes. Before running it, briefly suspend
dashboard camera mutations and clear long control-plane database transactions;
established RTSP sessions and media-node processes keep running. The migration
sets a one-second lock wait and a 30-second statement deadline. Either all four
indexes and the revision commit together, or PostgreSQL leaves the database at
0013 with no partial catalog indexes. A timeout is an operator-visible failed
migration: remove the blocking transaction and retry the same packaged command.

Application release `0.7.0` adds `0015_camera_name_contract`. It remains
executable on 0012, 0013 and 0014 while processes are rolled, but its camera
catalog/detail routes deliberately remain unavailable until exact revision 0015.
Install and smoke 0.7.0 on every control-plane process before advancing the
database. Established media-node processes and ordinary RTSP/TCP sessions are
not restarted by this control-plane rollout.

Migration 0015 scans only IDs and names of non-deleted cameras under the same
one-second lock wait and 30-second statement timeout. It aborts atomically with
`camera_name_contract_preflight_failed`, a bounded count and at most twenty
camera UUIDs if an old row is empty, whitespace-only, or contains a Unicode
control/format character. It never prints `source_url` or the rejected name.
Keep PostgreSQL at 0014, correct every reported camera through the authenticated
camera update API using a valid 1..128-character name, the current full source
URL and `expected_revision`, then retry the packaged migration. Do not repair
these rows with ad-hoc SQL: the normal API preserves revision/audit/outbox
semantics. Immutable `deleted` rows have no placement or supported update seam,
are excluded from every camera read, and retain their permanent public-ID
tombstone; 0015 deliberately preserves them without applying the display-name
contract. Migration success adds `ck_cameras_name` for every non-deleted row;
future application writes also use the stricter Unicode-aware domain validator.

At exact revision 0015 the camera page additionally requires `pg_trgm` and exact
canonical definitions for all four catalog indexes on every request. Missing or
drifted projection state, including a name that bypassed the application after
migration, returns a sanitized unavailable response; it never falls back to an
unindexed scan. WEB database operations also carry a two-second
statement/connect/pool deadline. After migration, open the camera catalog and
verify every WEB and background process is ready before ending the mutation
window.

Release `0.5.0` is a rollback target only while PostgreSQL has not advanced past
0013. After revision 0014 commits, application rollback to a manifest whose
maximum schema is 0013 is **NO-GO**. Fix forward with verified 0.6.0 artifacts,
or stop the control plane and restore the pre-migration PostgreSQL backup; an
Alembic downgrade is not a supported product rollback. Media nodes and ordinary
`rtsp://` interleaved-TCP sessions are outside this control-plane rollback
boundary.

Likewise, after revision 0015 commits, rollback to application 0.6.0 (maximum
schema 0014) is **NO-GO**. Fix forward with verified 0.7.0 artifacts or restore
the pre-0015 PostgreSQL backup with the control plane stopped. Do not Alembic
downgrade a live deployment.

Application release `0.8.0` adds `0016_node_registration_keys`. Install and
smoke 0.8.0 on every WEB/background process while PostgreSQL is still at 0015.
Existing read, collector and media-node operation contracts remain available,
but authenticated node registration deliberately returns a sanitized 503 until
the database reaches exact 0016. Temporarily suspend node creation during this
window; established ordinary RTSP/TCP sessions and node processes are not
restarted.

Migration 0016 creates only the bounded `node_registration_requests` ledger
with a composite `(actor_session_id, idempotency_key)` primary key and a
canonical request digest check. The ledger has no delete cascade from
`media_nodes`: deleting a node must never make an already accepted registration
request reusable. Each new registration inserts the ledger row in the same
synchronous transaction as desired node state and its matching audit/outbox
pair. After the migration, verify every process is ready, submit one node
registration with a fresh UUIDv4 `Idempotency-Key`, repeat it unchanged and
confirm the same `Location`; reuse with a changed payload must return 409.

After revision 0016 commits, rollback to application 0.7.0 (maximum schema
0015) is **NO-GO**. Recover by fixing forward with the verified 0.8.0 release or
restore the pre-0016 PostgreSQL backup with the control plane stopped. A live
Alembic downgrade is not supported.
The five WEB authentication files are delivered by installing
`deploy/systemd/rtsp-proxy-web-auth.conf.example` as
`/etc/systemd/system/rtsp-proxy-web.service.d/auth.conf`, running
`systemctl daemon-reload`, and restarting WEB. The drop-in uses
`LoadCredential=`; the environment file contains
only IdP endpoints/client ID and the exact accepted ACR/AMR policy. Before
enabling those variables, provision exactly one enabled `break_glass` account,
verify that readiness can decrypt its TOTP material, and verify SMTP delivery
of both an accepted and a rejected drill. Every attempt is admitted through a
bounded concurrency gate plus durable per-IP and per-account progressive
lockout, and creates both a sanitized audit/outbox event and a dedicated
durable email alert.

WEB readiness polls the configured IdP discovery document through verified TLS
with a bounded response. It requires the exact issuer/endpoints, Code+PKCE S256,
RS256 support and the `sub`, display-name, groups, nonce, audience, lifetime and
MFA claim families used by the local mapping. The check is cached for at most
30 seconds. A healthy→failed or failed→healthy transition creates exactly one
durable `operator.oidc_claim_contract` SMTP alert; repeated probes in the same
state update health without flooding the outbox.

Provision the emergency identity from the same release virtual environment.
Use one immutable UUID for its entire lifetime. The encryption-key and TOTP
files contain unpadded or padded base64url (32 and at least 20 decoded bytes),
are regular non-linked files owned by the effective command UID with mode
`0400` or `0600`, and must be prepared over an offline operator-controlled
channel. The password is read twice from the controlling terminal and is never
accepted in argv or the environment:

```sh
export RTSP_PROXY_DATABASE_URL='postgresql+psycopg://rtsp_proxy@127.0.0.1:5432/rtsp_proxy'
export RTSP_PROXY_BREAK_GLASS_ENCRYPTION_KEY_FILE=/root/rtsp-proxy-break-glass.key
export RTSP_PROXY_BREAK_GLASS_TOTP_FILE=/root/rtsp-proxy-break-glass.totp
/opt/rtsp-proxy/releases/<release-id>/.venv/bin/rtsp-proxy-break-glass \
  --account-id 11111111-2222-4333-8444-555555555555 \
  --username emergency-admin \
  --actor operator:alice \
  --reason 'initial emergency credential provisioning'
```

Run the command as root with the shown `/root` inputs, or as the dedicated
service UID with equivalently protected files it owns. The command writes the
credential material and a sanitized
`operator.break_glass_provisioned` audit/outbox pair in one synchronous
transaction. It refuses a different UUID for an existing subject and refuses
to overwrite an enabled account. Its success output includes the committed
`authz_version`; retain that non-secret revision in the operator evidence.
Remove the one-use TOTP input file after a successful enrollment, then restart
WEB and complete both accepted and rejected SMTP drills before declaring
readiness.

Scheduled rotation is a separate explicit compare-and-swap operation. Prepare
a new TOTP file through the same offline channel, use the same immutable account
UUID and username, and supply the last committed revision printed by the prior
provision/rotation command:

```sh
/opt/rtsp-proxy/releases/<release-id>/.venv/bin/rtsp-proxy-break-glass \
  --account-id 11111111-2222-4333-8444-555555555555 \
  --username emergency-admin \
  --actor operator:alice \
  --reason 'scheduled emergency credential rotation' \
  --rotate \
  --expected-authz-version 3
```

Rotation synchronously replaces only the password/TOTP verifier material,
increments the authoritative revision, resets TOTP replay state, revokes every
active session for the account and writes one identical
`operator.break_glass_rotated` audit/outbox event without either secret. A stale
revision, changed UUID/username, disabled account or concurrent winner aborts
the credential mutation and writes a separate sanitized
`operator.break_glass_rotation_rejected` audit/outbox event. Record the newly
printed revision and remove the input TOTP file. Then, from the approved
management path, make exactly one deliberate
old/invalid login and require its rejected security email; make one login with
the new password/TOTP and require its accepted email, then log out. Do not
declare the drill complete if either message is missing/duplicated, the old
session remains usable, or readiness is red.
Exactly one WEB health monitor performs the external discovery/token and local
store probes at startup and every 30 seconds. HTTP `/health/ready` only reads
its immutable synchronized result; requests cannot fan out IdP/DB work or race
the durable failure/recovery transition recorder.

Existing canonical `oidc:<sha256(issuer NUL sub)>` accounts remain unchanged.
Any noncanonical legacy OIDC row blocks new account provisioning with
`oidc_account_mapping_required`, even when its old subject text equals the
verified IdP `sub`: that text has no issuer provenance and is never sufficient
to inherit its UUID, roles, scopes or sessions. Resolve the row through an
offline audited maintenance transaction that binds the exact issuer and
subject before enabling OIDC account provisioning. Login traffic never guesses
or rewrites this mapping.

Retire 0.4.0 only after all processes run 0.5.0 and login, session revocation,
and break-glass recovery are exercised. Any schema outside the declared window
fails closed; an older binary must never start against an unsupported newer
schema.

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
roles. The packaged trust catalog records current race-safe `0.2.1`, previous
callback-compatible `0.2.0`, and historical patched `0.1.0` with distinct
architecture-specific digests; stock v1.20.0 is never trusted. Phase-E
`.1 → .2` uses the later documented drained,
blast-radius-confirmed reconfigure because the ordinary release endpoint
remains intentionally limited to empty stopped nodes. `.1` is not configured
as a rollback target: it lacks callback-compatible management auth. The
`0.2.0 → 0.2.1` race-only transition is the first pair for which `PREVIOUS_*`
may be set after both architecture artifacts are verified.

## Security

Install `/etc/rtsp-proxy/rtsp-proxy.nft` from
`deploy/nftables/rtsp-proxy.nft` as a root-owned regular file, mode `0644`,
change only the `node_ports` interval to the configured external node-port
range, review it alongside the host's existing firewall, then enable and start
`rtsp-proxy-nftables.service`. Never load the file directly. On every boot the
serialized reconciler refuses a same-name table without the exact ownership
marker, then atomically replaces absent or owned state from the full policy
transaction. Consequently drift in ports, sizes, timeouts, expressions, caps
or rates is repaired rather than accepted. Timeout-after-apply is retried as an
owned atomic replacement; a partial owned post-state is removed and startup
fails closed. The owned additive table keeps
the host policy unchanged, limits both each node port and each source IP on that
port to 128 tracked connections, and limits new SYN packets to 100/s with burst
200 per source/port for both IPv4 and IPv6. The 128-session ceiling leaves
bounded reconnect headroom above the product limit of 100 registered cameras
and allows a single NVR/NAT address to read every camera on one node. Empty
application ACLs still mean allow-all after this coarse abuse boundary. Monitor
all three named rule comments/counters. Do not run `flush ruleset` and do not
delete the table during normal operation. Stop media nodes first; explicit
removal remains scoped to `nft delete table inet rtsp_proxy` after verifying
the marker `rtsp-proxy-owned:v1`.

The patched MediaMTX maps `readTimeout` to its idle request deadline. A partial
first RTSP request is therefore closed at that bound, while established
interleaved RTP/RTCP sessions retain their normal keepalive behavior.

- dedicated control-plane users and per-instance systemd `DynamicUser`;
- `NoNewPrivileges`, `ProtectSystem`, `ProtectHome`, `PrivateTmp`, bounded
  `ReadWritePaths`, address-family/syscall/capability restrictions;
- node API/metrics and auth callback bind loopback only. The patched HTTP-auth
  mode checks exact per-node internal credentials before the callback, so API,
  metrics and the runtime probe remain authenticated rather than excluded;
  the auth URL itself is scoped to the configured node UUID;
- external listener ordinary RTSP/TCP only;
- no Docker socket or container dependency;
- secrets absent from argv, logs and world-readable config.

Phase-E activation requires a root-owned regular
`/etc/rtsp-proxy/control-plane/access-peppers.json`, mode `0640`, owner
`root:rtsp-proxy-access`, with this bounded shape (one primary and at most one
verify-only previous key; use at least 32 random bytes/key):

```json
{"primary_key_id":"2026-08","keys":{"2026-08":"<64-or-more-hex>"}}
```

Never put pepper bytes in an environment file. Run migration
`0010_camera_access`, start `rtsp-proxy-auth.service`, and verify its loopback
`/health/ready` before adding
`RTSP_PROXY_NODE_HELPER_AUTH_CALLBACK_PORT=8010` to the privileged helper.
Install the dedicated `rtsp-proxy-auth.env` from its example and grant that
database role only the operations required by the callback:

```sh
sudo -u postgres psql --dbname rtsp_proxy --set DBNAME=rtsp_proxy \
  --file deploy/postgresql/rtsp_proxy_auth.sql
```

The idempotent artifact creates `rtsp_proxy_auth` without broad database or
schema privileges, grants exact callback reads plus `EXECUTE` on two constrained
`SECURITY DEFINER` operations (last-use and revision-fenced rehash), and denies
direct grant mutation, audit/outbox insertion, and all control-plane
node/camera mutation. Configure its local password, peer or certificate auth
separately according to the host PostgreSQL policy; never place it in this SQL
artifact or source control.

Pepper rotation is an explicit two-key operation:

1. atomically replace the root-owned file with `{new primary, old verify-only}`;
2. restart auth first, then restart the node-runtime helper so both processes
   load the same primary; require auth `/health/ready` and a successful bounded
   helper observation before continuing;
3. smoke both a new-key grant
   and one existing old-key grant (the latter rehashes on successful use);
4. only then restart web so it can issue new-key grants; if either smoke fails,
   atomically restore the old file, restart auth and helper, verify both, and
   only then restart web;
5. reconfigure one canary through the confirmed workflow, read back its
   root-only generated config, and require the comment
   `rtsp-proxy-auth-primary-key-id: <new-id>` plus a successful new RTSP read;
   then reconfigure every remaining node so its callback Basic identity is
   rendered from the new primary;
6. keep the old key until every still-live grant has been rehashed, rotated,
   revoked or expired and every node config has been reconfigured/smoked.
   Verify that no database row references it before an atomic primary-only file
   replacement and auth-then-helper-before-web restart. Removing the previous
   key without restarting and verifying the helper is a fail-closed NO-GO.

A suspected pepper compromise does not use the overlap flow: stop new grant
issuance, install a fresh key, revoke and reissue every grant referencing the
compromised key, notify affected operators, and retain the old key only as long
as needed to complete the bounded revocation transaction. Raw tokens are never
recovered or bulk rehashed.

Restart the helper after changing its environment. Existing node configs are
not silently rewritten. For every existing node:

1. call `POST /api/v1/nodes/<uuid>/drain` and wait until the operator-approved
   disruption window;
2. call `POST /api/v1/nodes/<uuid>/reconfigure/preview` and verify the returned
   external port, registered-camera count, placement fingerprint, target
   release ID and target MediaMTX SHA-256;
3. call `POST /api/v1/nodes/<uuid>/reconfigure` with
   `{"confirmation_token":"<preview-token>"}`;
4. require RUNNING runtime, matching desired/applied revisions and the same
   external port, then call `POST /api/v1/nodes/<uuid>/resume`.

The reconfigure/restart disconnects all streams of that node, but never any
other node. A failed attempt leaves desired state DRAINING and is retriable
from runtime FAILED/STOPPED with a fresh preview token. A generic restart does
not rewrite a non-empty node and must not be used for this migration.
New sessions fail closed while auth/DB is unavailable; established streams are
not reauthorized. This initial Phase-E activation is a one-way `.1 → .2`
transition: `.1` cannot preserve authenticated management under callback mode
and is therefore not an activation/rollback target. A binary rollback is NO-GO
until a future callback-compatible previous release is packaged and proven.
Recovery retries `.2` with a fresh confirmation; it must never replace the
callback with an allow-all rule.

## Production admission

These artifacts are not an install approval by themselves. Production requires
node-instance isolation tests, PostgreSQL migrations/restore, ACL/auth/RTSP 453,
drain/move/port rollback, native amd64/arm64 contracts and measured per-node/
per-server capacity evidence described in the production plan.
