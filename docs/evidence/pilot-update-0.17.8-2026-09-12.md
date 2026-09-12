# Pilot update evidence: 0.17.8

Date: 2026-09-12.

This record covers the existing pilot only. It is release and continuity evidence,
not a Production GO or a substitute for the remaining site-admission gates.

## Release identity

- Application release: `0.17.8`.
- Exact source and manifest commit:
  `539efcc4bb5f2693a5aa9d17dafe52f50f469f54`.
- Functional design commit: `15f209e564a02d0328b6766c7a3ea9dc40762dbe`.
- CI run: [34686875711](https://github.com/zl0nline/RTSP_proxy/actions/runs/34686875711),
  all 14 jobs passed.
- Linux amd64 application suite: 1,893 passed, 77 skipped, 90.03% coverage.
- The downloaded amd64 bundle declared release `0.17.8`, the exact commit above,
  architecture `amd64`, and schema window
  `0012_operator_sessions..0025_permanent_service_grants`.
- All eight manifest-bound files were independently SHA-256 checked before and
  after transfer. The source checkout was clean and detached at the manifest
  commit.

## Update sequence

The pilot started at application `0.17.4` and schema
`0024_camera_probe_profiles`. Seven required control-plane services, the probe
worker/broker boundary and four media units were active; readiness passed and no
service was failed.

Before activation, a new custom-format PostgreSQL archive was created as
`pre-0.17.8-0024-20260912T100657Z.dump`. `pg_restore --list` passed and the
archive SHA-256 is
`7beaf0347f22357c9bafef052763679a516a0ba5ed73133e2a2d18feb9057bee`.
This is an on-host restore-list check, not a new isolated restore drill.

The first install attempt stopped before activation with
`unsafe_media_environment_binary`: the node helper still referenced a removed
legacy application-release path. The new shared MediaMTX target, its release
manifest digest and the helper's configured expected digest were all identical.
The operator therefore atomically normalized that one helper path to the
root-owned immutable `/opt/rtsp-proxy/media/0.2.1/mediamtx`. No media unit was
restarted and no trust check was bypassed.

The second update attempt activated `0.17.8` while the database remained on
0024. Bridge smoke then proved:

- exact current symlink and manifest commit;
- all required control-plane and probe units active, zero failed units;
- HTTPS readiness with database, schema, session store and probe observation
  checks passing;
- local-login page HTTP 200 and the packaged Albedo stylesheet served;
- no warning-or-higher application journal entries after activation;
- all four media unit PIDs byte-for-byte identical to the pre-update snapshot.

After that smoke, the exact installed migration advanced the database to
`0025_permanent_service_grants`. The least-privilege auth role artifact was
reapplied from the exact source commit and WEB, auth and reconciler were
restarted. A single immediate readiness request raced the WEB listener restart;
the subsequent bounded verification found every required unit active, zero
failed units, readiness passing and no warning-or-higher entries.

The control-plane activation intentionally did not restart media units. A
follow-up process inspection then showed that their environment files already
selected the shared immutable binary, but the four processes themselves still
held the legacy `0.17.4` application-release executable. All four management
APIs reported zero readers, so the operator activated the shared binary with a
one-node-at-a-time rolling restart. Each node had to become active under
`/opt/rtsp-proxy/media/0.2.1/mediamtx` and answer its authenticated management
API before the next restart began. The PID transition was:

- `498728` -> `1360110`;
- `498751` -> `1362685`;
- `498752` -> `1363258`;
- `498738` -> `1363835`.

The final process-level check found all four executables at the shared path and
zero MediaMTX processes under `/opt/rtsp-proxy/releases/0.17.4`. HTTPS readiness
remained green, no service was failed, and no warning-or-higher media journal
entry appeared during the rolling activation window.

## Dashboard verification

An authenticated browser session reached the pilot through a temporary SSH
tunnel. The operator inspected overview, camera catalog, camera status,
monitoring, access and management, plus camera/node creation forms. Evidence was
captured at 1440, 1024 and 390 CSS pixels in both themes. The camera tab model
preserved hash deep links and keyboard Home/End behavior. Document scroll width
equalled the viewport at 1024 and 390 pixels, and browser console/errors were
empty. No mutation or stream operation was performed for this visual check.

The HTTP asset bytes matched the installed wheel exactly:

- `dashboard.css`:
  `43d9025484a61ea83c70d0a3548e528d85483439951556f12993b279cd9fec4e`;
- `dashboard.js`:
  `01c434600010d90c8e1aa4bd7ce0d07ce205c7c187c097c6374071cef71ebb04`.

The final pilot state is application `0.17.8`, exact commit `539efcc`, schema
0025, four MediaMTX processes executing the shared immutable `0.2.1` binary,
green readiness and a verified pre-migration backup. This update did not repeat
an established-reader smoke, an isolated database restore, SMTP delivery, the
24-hour soak or supported-host admission; those gates remain open.
