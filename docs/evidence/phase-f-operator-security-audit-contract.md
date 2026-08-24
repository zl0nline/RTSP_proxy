# Phase F operator security-audit contract

- Last reviewed: 2026-08-24
- Status: denial/logout slice complete; Phase F remains in progress
- Commit: `ef0e1f3fdfb74c174ac0dffa9f88213291ab19b5`
- CI: [run 32678955187](https://github.com/zl0nline/RTSP_proxy/actions/runs/32678955187)

## Evidence boundary

This evidence covers the shared operator HTTP boundary: authentication
failures, CSRF/permission/scope denials and logout, plus the representative
semantic targets listed below. It is not a generated route-method inventory and
does not claim that every current route—or future export, SSE or bulk-operation
routes—has passed its own negative authorization matrix.

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

Local validation completed with `787 passed, 19 skipped`; Ruff, mypy and
diff-check were clean. The skipped tests are opt-in external/native contracts,
not silent pass substitutes. Independent Spec and Standards reviews both
returned PASS on the exact staged tree
`7931251e376bea1d293abd3aeecb7c5b001154bd`.

CI run 32678955187 executed the exact commit above. All seven jobs passed:
application/PostgreSQL, patched MediaMTX and RTSP/load contracts on Linux amd64
and arm64, plus the external-management-client Chromium job on amd64. The real
browser remains an external client; server behavior is architecture-neutral.

## Remaining gates

Phase F remains **IN PROGRESS** until the generated protected route-method
negative matrix and remaining operator workflows are
available without direct database, `systemctl` or MediaMTX access. Any future
export, SSE or bulk surface must add its consensus-required scope/no-oracle,
redaction, rate/admission and durable-audit evidence before activation. Phase G
physical capacity/fault/WAN/24-hour evidence and Phase H rollout are also open;
Production remains **NO-GO**.
