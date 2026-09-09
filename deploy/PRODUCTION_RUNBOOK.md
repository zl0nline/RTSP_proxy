# Production runbook

This runbook is the operator-facing admission procedure for one direct-Linux
RTSP Proxy server. It complements the installation mechanics in
[PILOT_INSTALL.md](PILOT_INSTALL.md) and the detailed component reference in
[README.md](README.md). Passing CI is necessary but is not a capacity claim.

The supported production shape is Ubuntu 24.04, Python 3.12, systemd,
PostgreSQL and native `amd64` or `arm64` release artifacts. Ubuntu 26.04 can be
used to exercise the pilot mechanics, but it is not a published production OS
profile. Docker, Kubernetes, UDP media, RTSPS and multi-server failover are not
part of this release.

## 1. Admission record

Create one private evidence directory per attempt. Never reuse it after a
failed or completed attempt.

```sh
admission_id=2026-09-10T000000Z-site-a
sudo install -d -m 0700 -o root -g root \
  "/var/lib/rtsp-proxy/admission/$admission_id"
sudo sha256sum /opt/rtsp-proxy/current/release-manifest.json | \
  sudo tee "/var/lib/rtsp-proxy/admission/$admission_id/release.sha256" >/dev/null
sudo cp --preserve=mode,timestamps \
  /var/lib/rtsp-proxy/deployment.json \
  "/var/lib/rtsp-proxy/admission/$admission_id/deployment.json"
```

Record, without secrets:

- owner, site and decision time;
- exact release ID, git commit, manifest SHA-256 and architecture;
- supported OS, kernel, CPU, RAM, NIC, storage and time-sync state;
- configured `max_nodes`, port range and the smaller measured node envelope;
- admitted camera model/firmware profiles;
- links or hashes for every drill and load artifact below;
- exclusions and residual risks. A configured limit is never evidence.

All files in the evidence directory are private until they have passed the
repository's secret scan. Raw camera URLs, source/downstream credentials,
private keys, session cookies, TOTP seeds and client IPs must not be published.

## 2. Preflight

Stop immediately if any command fails.

```sh
sudo /srv/rtsp-proxy-source/tools/bootstrap_rtsp_proxy_host.sh --check
sudo /opt/rtsp-proxy/current/.venv/bin/rtsp-proxy-verify-release \
  --manifest /opt/rtsp-proxy/current/release-manifest.json
sudo systemctl --failed --no-pager
sudo systemctl is-active \
  rtsp-proxy-web.service \
  rtsp-proxy-auth.service \
  rtsp-proxy@reconciler.service \
  rtsp-proxy@probe.service \
  rtsp-proxy-collector.service \
  rtsp-proxy-node-runtime.socket \
  rtsp-proxy-node-metrics.socket \
  rtsp-proxy-probe-broker.socket
curl --fail --silent --show-error \
  --cacert /etc/rtsp-proxy/control-plane/management-tls-current/management-tls.pem \
  https://management.example.net:8000/health/ready
```

Require exact schema head, synchronized time, at least 30% free RAM/storage/FD
and no unresolved priority-warning journal entry since the current release was
activated. Every configured node must have fresh process identity and metrics;
an idle on-demand camera is not an error.

## 3. Recovery set

The recovery set has two separately protected parts:

1. a consistent PostgreSQL custom archive plus its generated manifest;
2. an encrypted off-host copy of `/etc/rtsp-proxy` and the deployment receipt.

The database operation never puts the connection URL or password in a child
process argument. Run it as a PostgreSQL role that can read the application
database. The local peer-authenticated `postgres` role is the reference direct-
Linux configuration.

```sh
backup_id=2026-09-10T000000Z
sudo install -d -m 0700 -o postgres -g postgres /var/backups/rtsp-proxy
sudo -u postgres env \
  RTSP_PROXY_OPERATIONS_DATABASE_URL=postgresql:///rtsp_proxy \
  /opt/rtsp-proxy/current/.venv/bin/rtsp-proxy-operations \
  backup-database \
  --output "/var/backups/rtsp-proxy/$backup_id.dump" \
  --release-manifest /opt/rtsp-proxy/current/release-manifest.json
```

The command:

- exports one repeatable-read PostgreSQL snapshot;
- binds `pg_dump` to that snapshot;
- writes a custom archive without ownership/ACL replay;
- verifies the archive with `pg_restore --list`;
- records exact release/schema, archive digest, every public-table count and
  restore invariants in a mode-`0600` manifest.

Exercise a real restore into a randomly named temporary database. The command
compares the complete table inventory and invariants, writes a private report
and removes the temporary database before reporting success.

```sh
sudo -u postgres env \
  RTSP_PROXY_OPERATIONS_DATABASE_URL=postgresql:///rtsp_proxy \
  /opt/rtsp-proxy/current/.venv/bin/rtsp-proxy-operations \
  verify-database-restore \
  --archive "/var/backups/rtsp-proxy/$backup_id.dump" \
  --manifest "/var/backups/rtsp-proxy/$backup_id.dump.manifest.json" \
  --report "/var/backups/rtsp-proxy/$backup_id.restore.json" \
  --release-manifest /opt/rtsp-proxy/current/release-manifest.json
```

Back up the control assets as root. They contain enough material to decrypt
camera credentials and authenticate existing grants, so a plaintext copy on
the same server is only a short-lived staging artifact, not the production
backup.

```sh
sudo tar --create --file "/var/backups/rtsp-proxy/$backup_id.control.tar" \
  --directory=/ --acls --xattrs --numeric-owner \
  etc/rtsp-proxy var/lib/rtsp-proxy/deployment.json
sudo chmod 0600 "/var/backups/rtsp-proxy/$backup_id.control.tar"
sudo sha256sum "/var/backups/rtsp-proxy/$backup_id.control.tar" \
  "/var/backups/rtsp-proxy/$backup_id.dump" \
  "/var/backups/rtsp-proxy/$backup_id.dump.manifest.json" \
  "/var/backups/rtsp-proxy/$backup_id.restore.json"
sudo tar --compare --file "/var/backups/rtsp-proxy/$backup_id.control.tar" \
  --directory=/ --acls --xattrs --numeric-owner
```

Transfer the recovery set immediately to a site-approved encrypted, off-host,
versioned repository. Test retrieval and digest verification from that
repository. PostgreSQL WAL archival or backup frequency must demonstrate RPO
at most five minutes; the isolated restore above must demonstrate control-plane
RTO at most 30 minutes. A same-disk archive, an untested remote upload or a
database dump without the original keyrings is a failed gate.

Never regenerate `camera-source-keys.json`, `access-peppers.json`, local/OIDC/
break-glass encryption keys or TLS private material as a substitute for a
restore. Regeneration makes existing encrypted values or credentials unusable.

## 4. Install, update and rollback

Use only an architecture-specific bundle from one fully successful CI run.
The bundle manifest, source checkout and staged release must name the same
40-character commit. Follow [PILOT_INSTALL.md](PILOT_INSTALL.md) for the initial
install and schema bridge.

Before any migration, complete section 3. Migrations are forward-only. After a
schema change, binary rollback is permitted only when the target release
manifest admits the live schema; otherwise use a verified fix-forward or stop
the control plane and restore the pre-migration recovery set.

Application update must preserve media processes:

```sh
sudo --preserve-env=RTSP_PROXY_DEPLOY_UV \
  /srv/rtsp-proxy-source/tools/update_rtsp_proxy.sh \
  --bundle /srv/rtsp-proxy-bundles/<release>-<arch> \
  --environment-file /etc/rtsp-proxy/control-plane/rtsp-proxy.env \
  --health-url https://management.example.net:8000/health/ready \
  --ca-file /etc/rtsp-proxy/control-plane/management-tls-current/management-tls.pem
```

Keep an established reader on a non-target camera during the update. Its PID,
TCP session and RTP counters must continue. Update restarts only active control
roles; a MediaMTX binary transition is a separate, one-node-at-a-time drain and
confirmed reconfigure operation.

Test automatic health rollback with a deliberately non-ready *test release*
whose manifest still supports the live schema. Never corrupt a real bundle or
edit an installed release. Preserve the failed update receipt and journal.

## 5. Operator and downstream access

At least two named local administrators are required. Enroll TOTP for each with
the offline CLI, store the one-time URI in the site's secret manager and verify
that enrollment revokes existing sessions. Break-glass is separate, sealed and
drilled; OIDC is optional and must remain inside the trusted contour.

Issue a short temporary or explicitly owned service grant from the camera page.
The secret is shown once. Consumers use:

```text
rtsp://<grant-user>:<one-time-secret>@<server>:<node-port>/<public-id>
```

Test with FFmpeg using interleaved TCP. Keep credentials out of shell history,
process listings and evidence. Use an owner-only credential file or a service
manager credential boundary for unattended readers. The camera source URL and
source credentials are never downstream credentials.

## 6. Required game days

Run every row against the exact candidate release and restore the original
state after each injection. Keep one unaffected RTSP reader active whenever a
row claims isolation.

| Drill | Inject | Required outcome |
|---|---|---|
| Control restart | Restart WEB, auth, reconciler and collector, not media | Established RTP continues; new auth fails closed only while its dependency is unavailable; readiness recovers |
| Camera CRUD isolation | Add/update/disable/delete a different test camera | Unrelated reader has zero RTP interruption; no node restart |
| Drain | Drain a node with an established reader | New sessions/placements denied; existing reader continues until disconnect/deadline |
| Force/restart | Confirm exact current reader/camera blast radius | Only the selected node disconnects; other node PIDs/listeners/RTP remain |
| Move | Ordinary occupied move, then confirmed force in a disposable case | Ordinary move is denied; force uses the shown new port/URL and leaves no old path |
| Port rollback | Make the proposed port unavailable during confirmed change | Old port/config/process identity is restored or node remains fail-closed; other nodes are unchanged |
| Media failure | Kill one MediaMTX instance | Only that node fails; no automatic camera migration; one incident is opened and recovery closes it |
| Port exhaustion | Occupy/reserve the complete test range or reach `max_nodes` | Existing streams continue; create returns the typed no-free-port/max-nodes error; no leaked node/port |
| Delete guard | Try to delete a non-empty node and then a running node | Both are rejected; deletion succeeds only at zero cameras and stopped/failed state |
| PostgreSQL outage | Stop DB briefly inside the maintenance window | Desired mutations/auth fail closed; established media behavior matches the recorded contract; no split-brain writes |
| Collector loss | Stop collector | Media continues; snapshot becomes stale, not healthy; recovery does not mix PID/port generations |
| Probe failure | Stop broker/worker or reject a target | Readiness/diagnostics fail as documented; camera/media state is not fabricated and no reader is displaced |
| SMTP reject/outage | Use the production STARTTLS relay's rejected-recipient and unavailable cases | Bounded retry and durable typed terminal state; no duplicate or reminder storm |
| Node alert/recovery | Fail and recover one node with notifier enabled | Exactly one failure message and one recovery message for the incident |
| Restore | Run section 3 from the retrieved off-host set | Exact schema/table counts/invariants/keyrings recover inside RPO/RTO |

For each drill record steady state, injection time, command or dashboard action,
detection, expected degraded behavior, recovery, final readiness, journal range,
unaffected-reader counters and cleanup proof. A manually edited PASS field is
not evidence.

## 7. SMTP admission

`rtsp-proxy-notifier.service` is required in production. Configure a real
authenticated STARTTLS relay, CA trust, sender and recipient in
`/etc/rtsp-proxy/notifier.env`; keep the password only in
`/etc/rtsp-proxy/control-plane/smtp-password` mode `0600` and pass it through
`LoadCredential=`.

Before GO, exercise all three outcomes against the configured relay:

1. accepted failure and recovery messages;
2. deterministic recipient rejection before `DATA`;
3. relay outage followed by recovery within the bounded retry window.

Verify durable message/incident rows and recipient delivery. A local fake SMTP
server proves the client state machine in CI but does not admit a production
relay.

## 8. Camera profiles and ingest diagnostics

Complete [CAMERA_PROFILE.md](../docs/CAMERA_PROFILE.md) for every admitted
model/firmware/path. Source username/password fields are raw values: never
percent-encode them manually. The control plane encodes reserved characters
exactly once and warns before accepting percent-looking input.

For `sourceOnDemand` cameras the live state is intentionally split:

- `idle`: no authorized demand, or a previously successful source is closed;
- `connecting`: an authorized reader recently started source acquisition;
- `unavailable`: the source did not become ready within the bounded start
  window;
- `ready`: source media and counters are present;
- `stale`/`unknown`: evidence is not current or not available.

The generic on-demand failure does not guess whether the cause was credentials,
network or camera behavior. A permitted isolated SOURCE probe supplies the
sanitized `authentication`, `connect_timeout`, `transport` or `codec` class.
Unknown or single-session source capacity is passive-only and must never gain a
second diagnostic connection.

## 9. Soak and capacity

Use the sealed native harness in [tools/load/README.md](../tools/load/README.md).
Record registered, active and occupied counts independently. A production
capacity run has at least 15 minutes warm-up, 30 minutes measurement, 24 hours
soak, two independent generator hosts, synchronized clocks and complete SUT/
generator resource evidence.

The hard product invariant is at most 100 registered cameras per node. It is
not a promise that a node can sustain 100 active cameras of every profile.
Publish only the combinations actually measured with at least 30% headroom,
RSS slope at most 1% per hour, zero FD/session leak and zero proxy-added RTP
loss in the clean profile.

If the 100-camera trial is explicitly deferred, the release may be described
as **production-functional** or **release-ready**, but the deployment remains
Production HOLD. State the smaller tested envelope; do not relabel it as the
100-camera gate. Likewise, `max_nodes=50` remains a configuration ceiling until
the target server ladder establishes a smaller or equal qualified maximum.

## 10. Decision

Production GO requires all of the following for the target site:

- exact candidate bundle and native `amd64`/`arm64` CI are green;
- supported host profile and management/network boundaries pass;
- database plus control-asset recovery is retrieved and restored inside RPO/RTO;
- control update/rollback and every game day in section 6 pass;
- real STARTTLS failure/recovery notifications pass exactly once;
- every admitted camera profile passes ordinary RTSP/TCP and source recovery;
- the 24-hour workload and hardware-specific node/camera envelope pass;
- the per-node 100-camera gate passes unless the decision explicitly remains
  HOLD for that excluded test;
- no unresolved High/Medium review or security finding remains;
- owner signs the exact envelope, exclusions and residual risks.

If any item is missing, write `HOLD` with the missing evidence. Never infer GO
from service health, a short pilot smoke, configured limits or CI alone.
