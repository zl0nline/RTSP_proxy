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
│       ├── bin/{mediamtx,ffmpeg,ffprobe}
│       ├── dist/rtsp_proxy-<version>-py3-none-any.whl
│       ├── release-manifest.json
│       └── uv.lock
└── current -> releases/<release-id>

/etc/rtsp-proxy/
├── control-plane/       # 0750 root:rtsp-proxy
│   └── rtsp-proxy.env
└── mediamtx/            # 0750 root:mediamtx
    └── mediamtx.yml
```

Release directories and the `current` symlink are root-owned. Runtime users do
not receive write access to them. The shared config parent contains no secrets
and is traversable; each service can traverse and read only its root-managed
subdirectory.

## Host integration

- `sysusers.d/rtsp-proxy.conf` creates separate non-login `rtsp-proxy` and
  `mediamtx` users.
- `tmpfiles.d/rtsp-proxy.conf` creates the allowed state/log/config paths.
- `systemd/rtsp-proxy-web.service` runs the control-plane HTTP process.
- `systemd/rtsp-proxy@.service` gives `worker`, `reconciler`, `probe` and
  `collector` separate process/readiness boundaries. Their task loops and real
  dependency providers are delivered by later phases; the current scaffold is
  deliberately not ready when a provider is absent.
- `systemd/mediamtx.service` runs the pinned media-plane binary.
- `mediamtx.yml.example` exposes ordinary RTSP/TCP on `:9999`; API and metrics
  remain on loopback and all unused media listeners are disabled.

The files are a Phase 0 baseline, not a production install bundle. Database,
secrets, auth and resource-limit values must pass their later gates before a
host is admitted.

`artifact-catalog.json` is the machine-readable source of candidate MediaMTX,
FFmpeg and ffprobe versions, download URLs and architecture-specific SHA-256
values. `release-manifest.amd64.example.json` and
`release-manifest.arm64.example.json` show the resulting release identity. The
Python wheel remains platform-independent; external binaries and every native
dependency are verified per architecture. The current FFmpeg autobuild has no
GitHub artifact attestation, so its catalog entry is a Phase 0 candidate and
cannot pass the production provenance gate without an accepted security ADR.

## Activation contract

Before changing `current`, installation automation must run from the candidate
release environment:

```sh
rtsp-proxy-verify-release \
  --manifest /opt/rtsp-proxy/releases/<release-id>/release-manifest.json
```

The verifier accepts no architecture or Python override. It reads the running
interpreter and maps the native Linux machine `x86_64` to `amd64` or `aarch64`
to `arm64`; non-Linux and every other architecture fail closed. It validates
the lock, wheel, MediaMTX, FFmpeg and ffprobe checksums and executable versions,
plus application/config/database schema compatibility. Any mismatch, missing
file, symlink escape or invalid manifest aborts activation.

Activation creates a temporary symlink in `/opt/rtsp-proxy`, atomically renames
it to `current`, reloads systemd, starts the units and checks role readiness plus
the external RTSP smoke. Rollback performs the same atomic switch to the last
verified release; it does not modify an old release in place.
