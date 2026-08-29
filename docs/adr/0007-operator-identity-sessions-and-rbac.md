# ADR-0007: Operator identity, server-side sessions and scoped RBAC

- Status: Accepted
- Date: 2026-08-13
- Owners: project / technical / security / operations
- Related issues: #4, #7, #9, #14

## Context

The dashboard and control API may be reachable from a management LAN, while
MediaMTX management endpoints remain loopback-only. Hiding actions in the UI is
not authorization. Role or scope downgrade must fence an already-issued browser
session without trusting a cache invalidation race. Production login also needs
an IdP-independent emergency path without turning a local password into the
normal authentication mechanism.

## Decision

- Production login uses OIDC authorization code flow with PKCE. The IdP must
  report MFA in a configured exact `acr`/`amr` contract before a browser session is
  issued. SAML is not implemented in the initial release.
- Authorization state is additionally bound to a short-lived
  `Secure`/`HttpOnly` browser flow cookie whose digest is stored with the
  one-time flow. State copied from another browser is rejected before token
  exchange.
- A separate local break-glass identity is allowed only with the
  `break_glass` role, mandatory TOTP MFA, an operator-owned rotation runbook and
  a durable alert for every successful or failed use.
- The browser receives an opaque random session identifier in the
  `__Host-rtsp_proxy_session` cookie. The cookie is `Secure`, `HttpOnly`,
  `SameSite=Strict`, has path `/`, no Domain and contains no roles or identity.
- PostgreSQL stores only SHA-256 session/CSRF token digests. Idle and absolute
  timeouts are independent: 30 minutes and 12 hours by default. A user may have
  at most five active sessions; issuing another revokes the oldest.
- Unsafe methods require an unpredictable session-bound CSRF token in
  `X-CSRF-Token`. Rejected CSRF, permission or scope checks never extend idle
  expiry.
- Authorization is deny-by-default and evaluates permission × resource ×
  scope. Roles are `viewer`, `operator`, `admin`, `auditor` and `break_glass`.
  Current global API operations require `server:*`; group/camera projections
  will require their exact resource scope.
- Every request compares the session `authz_version` with the authoritative
  account row. Role/scope/enable changes increment the version in the same
  synchronous transaction as audit/outbox. A mismatch invalidates the session;
  cache invalidation is only an optimization.
- Session issuance, logout, failed login, denial, role/scope change,
  break-glass use and sensitive read/reveal operations are security-audited
  without tokens, claims, passwords or raw secrets.
- Health endpoints remain available to local service supervision. The entire
  `/api/v1` control surface is protected when operator authentication is
  activated; partial per-route activation is forbidden.
- Unauthenticated login paths have bounded concurrency, durable per-IP and
  per-account progressive limits, bounded active OIDC flows, and expired-flow
  cleanup. The OIDC account key is a digest of the canonical issuer + subject,
  not `sub` alone.
- Startup and periodic readiness validate the live discovery contract used by
  claim mapping (issuer/endpoints, Code+PKCE, RS256 and required identity/MFA
  claims). A single writer owns those bounded probes; HTTP readiness reads its
  synchronized cached state and never starts provider work. Health transitions
  enqueue one durable failure/recovery alert.

## Consequences

The database is on the operator request path and its outage makes new logins and
control requests fail closed, while established RTSP sessions continue. OIDC
outage blocks new normal logins; already-issued sessions remain valid until
their bounded expiry and break-glass is the audited recovery path. PostgreSQL
gets a separate small session pool/budget so browser traffic cannot exhaust the
node lifecycle pool. Dashboard reads and SSE reconnects use independent durable
per-account buckets. A stream authorizes before replay; one read-only batch
refreshes all active session epochs at most once per second and every state
delivery passes an in-memory epoch fence. With a 750-millisecond batch deadline,
role/scope downgrade stays below the two-second ceiling without per-push SQL
reads or session-touch writes and cannot drain an already queued camera event.

## Alternatives

- Signed stateless JWT sessions were rejected because immediate revocation and
  authoritative role downgrade would require a second blacklist/version store.
- A local username/password database as the primary login was rejected because
  it duplicates IdP lifecycle, MFA and account-recovery controls.
- SAML alongside OIDC in the first release was rejected as a second protocol
  surface without an owner requirement. It can be added through a separate ADR.

## Failure domains and security boundary

| Failure | User-visible effect | Blast radius | Detection | Recovery | SLI impact |
|---|---|---|---|---|---|
| PostgreSQL/session pool down | control requests and login fail closed | operator plane on one server | readiness and bounded auth errors | restore DB/pool | control availability |
| IdP down/claim drift | new OIDC login denied; active sessions remain bounded | normal operator login | OIDC health/claim contract alert | fix IdP or audited break-glass | login availability |
| role/scope downgrade | old session becomes stale before mutation | changed account only | authz-version denial/audit | fresh login | authz enforcement |
| break-glass use | emergency session plus immediate alert | one emergency account | security audit/email | review and rotate | security incident |
| browser cookie theft | attacker acts until revocation/idle/absolute expiry | one session and its scopes | anomaly/audit/session list | revoke session/account | operator security |

## Evidence

- [x] Opaque digest-only session, CSRF, idle/absolute expiry and parallel-request tests
- [x] PostgreSQL restart persistence and authoritative downgrade fence test
- [x] OIDC PKCE/browser binding/MFA/claim-drift and IdP outage contract tests
- [x] Break-glass TOTP, safe provisioning CLI, durable alert/rate-limit and
  revision-fenced rotation drill
- [x] Shared-boundary RBAC/scope/no-oracle denial classes, representative
  semantic targets and a recursively generated matrix for all 48 protected
  route-method pairs present at that commit are complete; the later node-action
  and camera administration routers expanded the published inventory to 72
  pairs. The current one-camera snapshot/SSE and live-diagnostics delta enters
  the matrix at 75 pairs with its own scope, pre-delivery authz,
  resume/backpressure and separate read/reconnect-bucket evidence.
  Future export/bulk routes must enter the matrix and add their
  surface-specific evidence before activation
- [x] Browser cookie/security-header/leak and accessibility E2E

## Rollout and rollback

Application release `0.5.0` first runs against `0012_operator_sessions`; then
the additive `0013_operator_login` migration is applied. Operator auth is
enabled only after pinned JWKS/group mapping and break-glass readiness both
pass. Rollback before migration returns to `0.4.0`. After migration, `0.4.0` is
no longer schema-compatible; rollback uses a rebuilt `0.5.x` that understands
0013 rather than an older binary.
