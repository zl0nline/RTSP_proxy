# Direct Linux deployment artifacts

Docker and container runtimes are not part of the deployment contract. The
target is a systemd-based Linux host with Python 3.12. Linux amd64 and arm64 are
equally supported; neither architecture may ship on evidence from the other.

## Immutable layout

```text
/opt/rtsp-proxy/
├── releases/
│   └── <release-id>/
│       ├── .venv/
│       ├── bin/mediamtx
│       ├── dist/rtsp_proxy-<version>-py3-none-any.whl
│       ├── release-manifest.json
│       └── uv.lock
└── current -> releases/<release-id>

/etc/rtsp-proxy/
├── mediamtx.yml
└── rtsp-proxy.env
```

Release directories and the `current` symlink are root-owned. Runtime users do
not receive write access to them. Config and secrets are separately root-managed.

## Host integration

- `sysusers.d/rtsp-proxy.conf` creates separate non-login `rtsp-proxy` and
  `mediamtx` users.
- `tmpfiles.d/rtsp-proxy.conf` creates the allowed state/log/config paths.
- `systemd/rtsp-proxy-web.service` runs the control-plane HTTP process.
- `systemd/mediamtx.service` runs the pinned media-plane binary.
- `mediamtx.yml.example` exposes ordinary RTSP/TCP on `:9999`; API and metrics
  remain on loopback and all unused media listeners are disabled.

The files are a Phase 0 baseline, not a production install bundle. Database,
secrets, auth and resource-limit values must pass their later gates before a
host is admitted.

`release-manifest.amd64.example.json` and
`release-manifest.arm64.example.json` show the architecture-specific release
identity and MediaMTX checksum. The Python wheel remains platform-independent;
external binaries and every native dependency are verified per architecture.

## Activation contract

Before changing `current`, installation automation must run from the candidate
release environment:

```sh
rtsp-proxy-verify-release \
  --manifest /opt/rtsp-proxy/releases/<release-id>/release-manifest.json \
  --python-version 3.12
```

The verifier maps native Linux `x86_64` to `amd64` and `aarch64` to `arm64`.
`--arch` is an explicit CI/offline-build override, not a normal host setting.
Any other machine architecture is unsupported and fail-closed. A checksum,
Python-version, architecture, missing-file, symlink-escape or manifest-schema
failure aborts activation.

Activation creates a temporary symlink in `/opt/rtsp-proxy`, atomically renames
it to `current`, reloads systemd, starts the units and checks role readiness plus
the external RTSP smoke. Rollback performs the same atomic switch to the last
verified release; it does not modify an old release in place.
