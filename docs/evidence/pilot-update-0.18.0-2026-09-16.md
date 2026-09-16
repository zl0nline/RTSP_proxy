# Pilot update evidence: 0.18.0

Date: 2026-09-16.

This record covers the existing pilot only. It is release, migration,
MediaMTX-transition and operator-workflow evidence, not a Production GO or a
substitute for the remaining site-admission gates.

## Release identity

- Application release: `0.18.0`.
- Exact source and manifest commit:
  `20f79cdeceac8bec37b0196b121c15d88bd462d8`.
- CI run: [35067011035](https://github.com/zl0nline/RTSP_proxy/actions/runs/35067011035),
  all 14 jobs passed.
- Linux amd64 application suite: 1,910 passed, 77 skipped, 90.03% coverage.
- Both amd64 and arm64 native media jobs built the patched binary and passed
  the effective listener, RTSP transparency and source-unavailable contracts.
- The downloaded amd64 bundle declared the exact release and commit above,
  architecture `amd64`, database maximum `0026_probe_source_networks`, and
  MediaMTX `v1.20.0-rtsp-proxy.4` / release `0.2.2`.
- All eight manifest-bound artifacts were independently SHA-256 checked before
  and after transfer. MediaMTX SHA-256 was
  `fe0aab850ac24fa409f9ab3520b138bad97500048d032b2b7713c7f44ba4775c`.

## Bridge activation and migration

The pilot started at application `0.17.9`, schema
`0025_permanent_service_grants`, one running MediaMTX `0.2.1` process and zero
failed services. A root-owned Git index left by the preceding deployment made
the unprivileged cleanliness check invalid. A privileged read-only check first
proved that the checkout was clean and still at the exact `0.17.9` commit;
ownership of that one index file was then restored before fetching and
detaching at the candidate commit.

Application `0.18.0` was first activated against schema 0025. HTTPS readiness
and local login passed and the running MediaMTX PID and executable were
byte-for-byte unchanged. Before migration, a custom-format PostgreSQL archive
was created as `pre-0.18.0-0026-20260916T072813Z.dump`. `pg_restore --list` and
the sidecar checksum passed; its SHA-256 is
`26e786b0aac3ebd87eba00151658344dce24e96e032b199fe522253c87507653`.

Migration from 0025 to `0026_probe_source_networks` then ran from the immutable
new release. The auth, collector and notifier least-privilege PostgreSQL role
artifacts were reapplied before active application roles restarted. The static
source CIDRs remain the maximum envelope; existing admitted camera endpoints
remain effective `/32` entries while the audited operator-managed table starts
empty. The control-plane and collector target identity was changed to MediaMTX
`0.2.2`; the privileged helper was configured with `0.2.1` as the verified
previous identity. The recent-MFA setting changed from 300 to 1,800 seconds.

## Explicit MediaMTX transition

Application activation did not restart media. In an authenticated dashboard
session, the sole node reported two registered cameras, zero active sources and
zero downstream readers. The operator drained it and requested a reconfigure
preview. The signed preview named target release `0.2.2`, exactly two affected
public IDs and zero active readers. Applying that confirmation replaced only
the selected node process. The node was then resumed.

Independent post-transition checks proved:

- desired/runtime state `running` / `running`, health `healthy`;
- desired and applied revision `9 / 9`;
- desired and observed MediaMTX release both `0.2.2`;
- executable `/opt/rtsp-proxy/media/0.2.2/mediamtx`, PID `654103`, with the
  exact release SHA-256 above;
- all ten expected active application/helper/socket units active and zero
  failed services;
- application `0.18.0`, exact manifest commit, schema 0026, HTTPS readiness and
  the pre-migration backup checksum all passing.

## Operator workflow verification

The real browser showed live node health/runtime/bitrate/readers projection,
explicit zero-reader labels and the 30-minute MFA countdown. Camera registration
offered an explicit credentials/no-auth choice plus `/32` and `/24` source
network choices and displayed the configured site envelope.

Two one-hour temporary grants, one for each existing pilot camera, were issued
only to exercise the deployed downstream and cleanup paths. Both sources were
currently operational and returned an RTSP `200` DESCRIBE through the new
MediaMTX binary. Therefore this pilot could not reproduce a live upstream-401
failure; the exact `503 Service Unavailable` mapping is supported by the
successful native amd64/arm64 release contracts, not claimed as a pilot-camera
observation.

Both temporary grants were immediately revoked and the new recent-MFA purge
operation was executed for each camera. It also removed older revoked or
expired rows on those cameras, leaving 11 registered grants and recording 15
`camera.access_grant_purged` audit events during the verification window. No
grant password, operator password, TOTP value, source URL or session value is
retained in this record.

The final pilot state is application `0.18.0`, schema 0026 and MediaMTX `0.2.2`
with green readiness and no failed units. This update did not repeat an
isolated database restore, SMTP delivery, the 24-hour soak, an actual
unavailable pilot camera or supported-host admission; those gates remain open.
