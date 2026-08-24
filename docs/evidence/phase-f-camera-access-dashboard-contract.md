# Phase F camera access dashboard contract

- Last reviewed: 2026-08-24
- Status: implementation, direct-Linux validation, independent review and native CI complete
- Server contract: identical direct-Linux amd64/arm64 application code, no Docker
- Production status: NO-GO

## Evidence boundary

This slice exposes the Phase-E per-camera access model to authenticated
operators. It does not change media routing: external consumers still connect
to ordinary `rtsp://server:node_port/public_id` over interleaved TCP, and the
patched MediaMTX process still owns the exact one-reader/RTSP-453 admission
race.

The implemented dashboard and JSON boundary includes:

- a camera-scoped page for independent `internet` and `local` CIDR lists;
- explicit empty-policy semantics: no CIDRs means allow every directly
  observed peer IP, while any configured policy is evaluated before password;
- a bounded list of at most 100 secret-free grant summaries;
- explicit `temporary`/`service` issue, bounded-overlap rotation and revoke;
- recent-MFA and exact grant/policy revision fences on both dashboard and JSON
  routes, with rotation/revoke nested under the camera scope;
- server-derived `operator:<account UUID>` creator and the shared sanitized
  operator mutation context in the normative audit/outbox transaction;
- a one-time secret response with no-store/CSP/referrer protections, an
  ordinary RTSP URL and automatic return to the secret-free list in at most 30
  seconds;
- a durable sanitized sensitive-read audit for every successful grant-list
  response and independent durable per-account `secret_issue` and
  `access_mutation` rate buckets with 429/`Retry-After` denial evidence;
- a separate sanitized synchronous audit/outbox pair for rejected replay,
  idempotency-conflict, not-found and stale-revision mutations, written after
  rollback with fail-closed 503 behavior when the journal is unavailable; and
- a separate revoke confirmation stating that an established RTSP session is
  not disconnected and the change applies to the next admission.

The list query selects only safe columns. It does not read or render
`token_verifier` or `pepper_key_id`. Source URLs and camera credentials are not
part of any access template or response.

## Idempotency and migration

Issue and rotation forms carry a session-bound UUIDv4 key. Migration
`0017_access_grant_keys` creates an immutable request ledger keyed by operator
session and key, containing only actor/camera/operation identity, a canonical
SHA-256 request digest and the replacement grant UUID. It also adds the bounded
durable action-rate table keyed by account and bucket. Reservation, grant write
and audit/outbox append use one synchronous PostgreSQL transaction.

An identical replay returns a secret-free 409 because the raw token cannot be
reconstructed. Reusing the key for another payload also returns a secret-free
409. Both outcomes are durably recorded without the secret. During a
0.9.0/0016 rolling window all access-administration writes are
suspended and return a bounded sanitized 503 before touching an absent 0017
table; RTSP authorization, secret-free grant reads, node operations and
established streams remain outside this write gate.

The protected HTTP inventory now contains 70 route-method pairs. The generated
negative matrix proves anonymous denial, role/permission separation, exact
camera scope and representative semantic audit targets for the new routes.
Public regressions prove that own-camera access reaches the handler while a
cross-scope and nonexistent camera produce the same pre-lookup denial.

## Validation performed

On the development host, Ruff, strict mypy and the full non-browser application
suite passed with `893 passed, 19 skipped`; statement coverage was `90.01%`
against the mandatory `90%` gate. The skipped tests are separately gated
privileged MediaMTX/load/netem/systemd contracts.

The same dirty implementation tree was copied to an isolated temporary
directory on the direct-Linux Ubuntu amd64 host `grob`. `uv 0.10.8` provisioned
the locked CPython 3.12.13 environment without Docker or system package
changes. With PostgreSQL 18 binaries added to the test-process PATH, the full
suite again passed with `893 passed, 19 skipped` and `90.02%` statement
coverage; Ruff and strict mypy were also green.

A fresh Linux `agent-browser 0.26.0`/Chrome-for-Testing 152 session then passed
the real HTTPS browser workflow: OIDC login, node registration, camera access
navigation, two-level ACL text, one-time grant issue, secret presence only on
the issuance page, automatic one-second lab return to the secret-free grant
list, secret absence after that return, keyboard focus, occupied-reader
confirmation and logout (`3 passed`). The lab host disables Chromium
user namespaces through AppArmor, so only this disposable external browser
used the repository's explicit `RTSP_PROXY_BROWSER_NO_SANDBOX=1` switch. The
server and production deployment never launch Chromium. No `sudo` was used.

## Published review and CI

The frozen implementation passed independent Spec and Standards review. Commit
`9b0695605e7bf9efe00db0760d90f9906da85579` then passed all seven jobs in
[CI run 32730353917](https://github.com/zl0nline/RTSP_proxy/actions/runs/32730353917):
application/PostgreSQL/package/systemd/nftables on amd64 and arm64, patched
MediaMTX binaries on both architectures, native load/RTSP-TCP isolation on both
architectures, and the external Chromium dashboard workflow.

This closes only the camera-access administration slice. Other unfinished
Phase-F operator workflows, Phase-G hardware/WAN/fault/24-hour evidence and
Phase-H pilot rollout remain open; Production remains **NO-GO**.
