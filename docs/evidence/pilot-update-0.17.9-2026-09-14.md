# Pilot update evidence: 0.17.9

Date: 2026-09-14.

This record covers the existing pilot only. It is release, continuity and
permanent-grant regression evidence, not a Production GO or a substitute for
the remaining site-admission gates.

## Release identity

- Application release: `0.17.9`.
- Exact source and manifest commit:
  `985c93d25e1af4ad459e713c3c60af25506de86e`.
- CI run: [34884167970](https://github.com/zl0nline/RTSP_proxy/actions/runs/34884167970),
  all 14 jobs passed.
- Linux amd64 application suite: 1,894 passed, 77 skipped, 90.03% coverage.
- The downloaded amd64 bundle declared release `0.17.9`, the exact commit above,
  architecture `amd64`, database head `0025_permanent_service_grants` and
  MediaMTX release `0.2.1`.
- All eight manifest-bound files were independently SHA-256 checked before and
  after transfer. The source checkout was clean and detached at the manifest
  commit.

## Update and continuity

The pilot started at application `0.17.8` and schema
`0025_permanent_service_grants`. The 12 required control-plane, probe and
socket units were active, readiness passed, and no service was failed. One
media unit was currently running at PID `1360110` from the shared immutable
`/opt/rtsp-proxy/media/0.2.1/mediamtx` path.

An initial operator wrapper preflight stopped before backup or activation
because it carried the historical expectation of four running media units.
Read-only verification confirmed that the current pilot intentionally had one
running media unit and that application `0.17.8` was unchanged. The wrapper was
corrected to snapshot every currently running media unit and require at least
one, without weakening executable-path or PID continuity checks.

Before the successful activation, a new custom-format PostgreSQL archive was
created as `pre-0.17.9-0025-20260914T192306Z.dump`. `pg_restore --list` and the
sidecar checksum both passed. Its SHA-256 is
`9645dfa1a0d951800fd61d9d9041795a39b69b8cec16f2a748bc60fa71ace0c7`.
This is an on-host restore-list check, not a new isolated restore drill.

The verified update activated `0.17.9` without a schema or MediaMTX release
change. Independent post-update checks proved:

- exact current symlink, manifest commit and clean source commit;
- schema still at `0025_permanent_service_grants`;
- all 12 required units active and zero failed services;
- HTTPS readiness with database, schema, session-store and probe-observation
  checks passing, plus local-login HTTP 200;
- the installed dashboard template contains the explicit `permanent` lifetime
  sentinel;
- no warning-or-higher RTSP Proxy journal entries after activation;
- media unit, PID `1360110` and shared executable path byte-for-byte identical
  to the pre-update snapshot.

## Permanent service grant verification

An authenticated browser session reached the pilot through a temporary SSH
tunnel. After a real TOTP step-up, the operator selected `service` and
`Бессрочно (только service)` in the dashboard and submitted the issuance form.
The one-time credential screen was returned successfully, and the access table
showed the new grant as `service` with expiry `Бессрочно` and revision 1.

The test grant was immediately revoked through the dashboard confirmation
flow. The final table row showed `service`, `revoked`, `Бессрочно` and revision
2. No credential, TOTP seed or session value is retained in this record.

The final pilot state is application `0.17.9`, exact commit `985c93d`, schema
0025, one active MediaMTX process unchanged at the shared immutable `0.2.1`
binary, green readiness, zero failed units and a verified pre-update backup.
This update did not repeat an established-reader smoke, an isolated database
restore, SMTP delivery, the 24-hour soak or supported-host admission; those
gates remain open.
