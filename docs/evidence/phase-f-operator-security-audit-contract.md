# Phase F operator security-audit contract

- Last reviewed: 2026-08-24
- Status: current protected route-method matrix complete; Phase F remains in progress
- Commits: denial/logout implementation `ef0e1f3fdfb74c174ac0dffa9f88213291ab19b5`;
  generated matrix `39b29814d726d9020c1d19100521b4dfe729b91e`
- CI: [run 32678955187](https://github.com/zl0nline/RTSP_proxy/actions/runs/32678955187)
  and [run 32680412385](https://github.com/zl0nline/RTSP_proxy/actions/runs/32680412385)

## Evidence boundary

This evidence covers the shared operator HTTP boundary: authentication
failures, CSRF/permission/scope denials and logout, plus the representative
semantic targets listed below. A generated inventory additionally covers every
current protected route-method pair. Future export, SSE or bulk-operation
routes are not covered until they are added to the inventory and pass their own
scope/no-oracle, redaction, rate/admission and durable-audit tests.

Each request receives a UUID correlation identifier. The durable event uses an
allowlisted semantic action plus canonical object type/id and resource scope;
known sessions also bind the authoritative OIDC or break-glass identity source,
effective roles/scopes, account/session and `authz_version`. Source IP and user
agent are represented only by bounded SHA-256 values. Raw cookies, CSRF tokens,
URLs, query strings, source IP and user agent are absent from audit/outbox.

Self-session read and logout do not require `server:*`: a camera- or
group-scoped operator can revoke its own credential, while CSRF and the
authoritative session/version checks remain mandatory. Unsupported HTTP methods
are normalized to `OTHER`/`request.unsupported` and follow the same audited,
fail-closed boundary instead of raising an unaudited 500.

## Executable matrix

The public HTTP/PostgreSQL matrix covers:

- unknown, revoked, expired and stale sessions;
- missing or malformed CSRF form/header input;
- permission and exact camera-scope denial without an existence lookup;
- successful and repeated API/browser logout;
- distinct node create/restart/delete and camera edit/move/move-status targets;
- exact audit/outbox pair equality, unique response correlation IDs and
  secret/raw-client-metadata redaction;
- injected failure of either `audit_events` or `outbox_messages` for
  authentication denial, authorization denial and logout. Every case returns a
  retryable 503, leaves no half-pair and rolls back session revocation.

The generated public HTTP matrix recursively expands included FastAPI routers,
composes nested prefixes and currently discovers all 48 protected route-method
pairs under `/api/v1` and `/dashboard`. Every pair is exercised anonymously and
must return one correlated, semantic 401 audit event. Except for the four
explicit self-session read/logout routes, the same inventory is exercised with
a camera-scoped viewer and must return one semantic permission/scope 403 before
the handler. A nested `/api/v1/nested/future` regression proves that a future
prefixed router becomes visible to the generator instead of silently escaping
the matrix.

Local validation after the generated matrix completed with `789 passed, 19
skipped`; Ruff, mypy and diff-check were clean. The skipped tests are opt-in
external/native contracts, not silent pass substitutes. Independent Spec and
Standards reviews both returned PASS on the exact generated-matrix staged tree
`6b6f05215f47ba648997595931831bb0b8798b16`.

CI run 32678955187 executed the exact commit above. All seven jobs passed:
application/PostgreSQL, patched MediaMTX and RTSP/load contracts on Linux amd64
and arm64, plus the external-management-client Chromium job on amd64. The real
browser remains an external client; server behavior is architecture-neutral.

CI run 32680412385 executed the generated matrix commit `39b2981`. All seven
jobs passed again: application/PostgreSQL, patched MediaMTX and RTSP/load
contracts on Linux amd64 and arm64, plus the external Chromium client on amd64.

## Remaining gates

Phase F remains **IN PROGRESS** until the remaining operator workflows are
available without direct database, `systemctl` or MediaMTX access. Any future
export, SSE or bulk surface must enter the generated inventory and add its
consensus-required scope/no-oracle, redaction, rate/admission and durable-audit
evidence before activation. Phase G
physical capacity/fault/WAN/24-hour evidence and Phase H rollout are also open;
Production remains **NO-GO**.
