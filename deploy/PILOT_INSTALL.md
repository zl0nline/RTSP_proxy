# Pilot installation, update and rollback

This runbook is for the first direct-Linux server trials. It installs the same
immutable release layout and systemd assets used by CI, but it is **not** a
Production admission: Phase G scheduling, real-camera soak and hardware
capacity evidence remain open.

The deploy interface has six commands:

- `install` stages one verified release and installs static host assets, but
  deliberately does not change `current` or start a service;
- `stage` stages only the immutable release;
- `install-assets` installs versioned systemd/sysusers/tmpfiles definitions;
- `activate` checks the live PostgreSQL revision, switches `current`, restarts
  only previously active control-plane units and checks HTTPS readiness;
- `update` combines stage, asset update and activation with automatic symlink
  rollback when readiness fails and the previous manifest still supports the
  unchanged database revision;
- `rollback` activates an already installed release only when its manifest
  supports the live database revision. It never runs Alembic downgrade.

Media-node instances are never enumerated or restarted by these commands.
Changing a node's MediaMTX release remains the drain/preview/confirmed
reconfigure operation documented in [deploy/README.md](README.md).

## 1. Supported pilot host

Use a dedicated Ubuntu 24.04 systemd host, amd64 or arm64, with:

- Python 3.12, `uv`, PostgreSQL, nftables, curl, jq and git;
- systemd with socket activation and transient services;
- bpffs mounted at `/sys/fs/bpf` and the matching working `bpftool` for probe
  broker tests;
- one management address/certificate and an external RTSP node-port range;
- DNS/NTP working before the first installation.

Ubuntu 26.04 is accepted for pilot mechanism testing as well, but its system
Python is newer than the application contract. Install a reviewed root-owned
`uv` binary first, then let the bootstrap place Python 3.12 under the immutable
application prefix:

```sh
cd /srv/rtsp-proxy-source
sudo --preserve-env=RTSP_PROXY_DEPLOY_UV \
  ./tools/bootstrap_rtsp_proxy_host.sh --install
sudo --preserve-env=RTSP_PROXY_DEPLOY_UV \
  ./tools/bootstrap_rtsp_proxy_host.sh --check
```

The bootstrap installs only OS prerequisites and a dedicated Python 3.12. It
does not install RTSP Proxy, touch PostgreSQL data, mount bpffs, edit firewall
policy or enable services. `uv` is deliberately not downloaded by this script:
the operator must install one reviewed release as a root-owned mode-0755
regular file, avoiding an unaudited curl-to-shell bootstrap in the root path.

Keep PostgreSQL and camera sources on networks explicitly allowed by host
policy. Do not expose node API/metrics or the probe broker socket outside the
host. The initial trial should use a small camera set and one node; the product
limit remains 100 registered cameras per node.

## 2. Obtain exact source and release bundle

Download `rtsp-proxy-release-amd64` or `rtsp-proxy-release-arm64` from the
successful CI run for the commit being deployed. The artifact contains the
manifest, wheel and architecture-specific binaries; it intentionally contains
no configuration or secret.

On the server, check out the exact manifest commit and keep the checkout clean:

```sh
git clone https://github.com/zl0nline/RTSP_proxy.git /srv/rtsp-proxy-source
cd /srv/rtsp-proxy-source
git checkout --detach '<manifest-git-commit>'
test -z "$(git status --porcelain=v1 --untracked-files=all)"
uv sync --locked --all-groups
```

Extract the CI artifact into a root-owned staging directory, for example
`/srv/rtsp-proxy-bundles/0.12.0-amd64`. Do not rename files inside it. The
installer requires the source `HEAD`, `uv.lock` digest and manifest commit to
match before it generates the target virtual environment.

If `uv` is not `/usr/local/bin/uv`, set its absolute root-owned executable path:

```sh
export RTSP_PROXY_DEPLOY_UV=/root/.local/bin/uv
```

The installer rejects a group/other-writable or non-root-owned `uv` binary.

## 3. Stage the first release and host assets

Run from the exact clean source checkout:

```sh
cd /srv/rtsp-proxy-source
sudo --preserve-env=RTSP_PROXY_DEPLOY_UV \
  ./tools/install_rtsp_proxy.sh \
  --bundle /srv/rtsp-proxy-bundles/0.12.0-amd64
```

This command:

1. takes the exclusive `/run/lock/rtsp-proxy-deploy.lock` lock;
2. copies only a symlink-free bundle into a private staging directory;
3. derives pinned runtime requirements from the exact clean source lock;
4. creates the venv directly under the future immutable release path;
5. runs the packaged `rtsp-proxy-verify-release` against every artifact;
6. removes group/other write permission and atomically renames the release;
7. installs systemd/sysusers/tmpfiles assets and example env files;
8. runs `systemd-sysusers`, `systemd-tmpfiles` and `systemctl daemon-reload`.

It does **not** create secrets, edit active env files, migrate PostgreSQL,
change `/opt/rtsp-proxy/current`, enable units or start media nodes. Examples
are placed under `/etc/rtsp-proxy/examples/` and are never consumed directly.

## 4. Configure the host

Before activation:

1. copy every required example to its documented active path and replace all
   placeholder endpoints, release IDs, architecture digests and port ranges;
2. install management TLS as one root-owned combined PEM and atomic symlink;
3. create the least-privilege PostgreSQL roles with the SQL artifacts in the
   exact checkout;
4. install access peppers, SMTP/OIDC/break-glass credentials using
   `LoadCredential`; never place secret bytes in env files or command args;
5. install the owned nftables policy with the actual node-port interval, then
   enable its reconciliation unit;
6. validate every unit before enabling it:

```sh
sudo systemd-analyze verify \
  /etc/systemd/system/rtsp-proxy-*.service \
  /etc/systemd/system/rtsp-proxy-*.socket
```

For a fresh database, run the migration from the staged release, not from the
source venv:

```sh
sudo systemd-run --quiet --wait --pipe --collect \
  --uid=rtsp-proxy --gid=rtsp-proxy \
  --property=EnvironmentFile=/etc/rtsp-proxy/control-plane/rtsp-proxy.env \
  /opt/rtsp-proxy/releases/0.12.0/.venv/bin/rtsp-proxy-migrate
```

Take a PostgreSQL backup before every later schema advance. Live Alembic
downgrade is unsupported.

## 5. First activation

Activate only after config, TLS and the database are ready:

```sh
sudo /opt/rtsp-proxy/releases/0.12.0/.venv/bin/rtsp-proxy-deploy activate \
  --release-id 0.12.0 \
  --environment-file /etc/rtsp-proxy/control-plane/rtsp-proxy.env \
  --health-url https://management.example.net:8000/health/ready \
  --ca-file /etc/ssl/certs/ca-certificates.crt
```

On a first activation no units are active, so the command switches the symlink
without starting them. Enable sockets/services explicitly in the documented
dependency order, then require readiness and the native probe-broker contract.
Do not enable probe scheduling yet.

Useful inspection:

```sh
sudo /opt/rtsp-proxy/current/.venv/bin/rtsp-proxy-deploy status
readlink /opt/rtsp-proxy/current
sudo systemctl --failed
sudo journalctl -u 'rtsp-proxy*' --since '-10 min' --no-pager
```

The non-secret deployment receipt is
`/var/lib/rtsp-proxy/deployment.json`, root-owned mode `0600`.

## 6. Application update

Never update from a dirty checkout or an unverified ad-hoc directory. Download
the new architecture artifact, check out its exact commit, run `uv sync
--locked --all-groups`, and take a PostgreSQL backup.

The update command verifies that the *current* database revision is inside the
candidate manifest's rolling window before switching:

```sh
cd /srv/rtsp-proxy-source
sudo --preserve-env=RTSP_PROXY_DEPLOY_UV \
  ./tools/update_rtsp_proxy.sh \
  --bundle /srv/rtsp-proxy-bundles/0.13.0-amd64 \
  --environment-file /etc/rtsp-proxy/control-plane/rtsp-proxy.env \
  --health-url https://management.example.net:8000/health/ready \
  --ca-file /etc/ssl/certs/ca-certificates.crt
```

Only units active before the switch are restarted. Media nodes continue their
ordinary RTSP/TCP sessions. If HTTPS readiness is red, `current` is restored
and those same units are restarted on the previous release, but only while the
unchanged schema is compatible with it.

For an additive schema release, the sequence is deliberately:

1. update all control-plane processes to the bridge-compatible candidate;
2. smoke dashboard, helpers, collector/notifier and one ordinary stream;
3. run the migration once from the new immutable release;
4. rerun PostgreSQL role artifacts required by that revision;
5. restart roles one at a time and complete the revision-specific smoke list.

The deploy tool does not combine steps 1 and 3 because a migration may make
the previous application permanently incompatible. After migration, rollback
is allowed only if the target manifest still contains the exact live revision.

## 7. Rollback and fix-forward

To roll back application code to an installed compatible release:

```sh
sudo /opt/rtsp-proxy/current/.venv/bin/rtsp-proxy-deploy rollback \
  --release-id 0.12.0 \
  --environment-file /etc/rtsp-proxy/control-plane/rtsp-proxy.env \
  --health-url https://management.example.net:8000/health/ready \
  --ca-file /etc/ssl/certs/ca-certificates.crt
```

`database_schema_incompatible_with_release` is a hard stop. In that state use
a verified fix-forward release, or stop the control plane and restore the
pre-migration PostgreSQL backup. Never edit `alembic_version`, run a live
downgrade or repoint `current` manually.

Rollback of a media-node binary is separate and requires an activation-
compatible catalog identity plus the node drain/confirmation workflow. The
deploy tool intentionally cannot bulk-restart media nodes.

## 8. First real-camera trial gate

Start with one node and a handful of cameras. Before increasing the count,
record:

- exact release manifest and deployment receipt;
- database backup/restore result;
- HTTPS, OIDC/break-glass and SMTP accepted/rejected drills;
- node create/start/stop, camera add/update/move/delete and occupied-stream 453;
- ordinary FFmpeg interleaved-TCP playback for every camera profile;
- source/path probe success, refusal, timeout and cleanup with scheduling still
  manually controlled;
- CPU, RSS, file descriptors, network, PostgreSQL and MediaMTX metrics;
- update health rollback and one schema-compatible explicit rollback.

Only after this small pilot is stable should the server test move toward the
100-camera per-node limit or multiple nodes. Server capacity is empirical and
must not be inferred from the configured `max_nodes` value.
