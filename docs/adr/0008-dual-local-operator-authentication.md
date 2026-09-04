# ADR-0008: Dual local operator authentication

- Status: Accepted
- Date: 2026-09-03
- Owners: project / technical / security / operations
- Related issues: #18, #19
- Supersedes: the “IdP-only normal login” part of ADR-0007

## Context

ADR-0007 made OIDC the only normal login mechanism and reserved the local
password for emergency break-glass use. That makes dashboard availability
depend on a separately installed IdP and leaves a fresh pilot installation
without an obvious normal username/password login. The deployment is intended
to remain inside a trusted local network and must not require a cloud identity
provider.

## Decision

- RTSP Proxy supports two normal identity sources at the same time: a built-in
  local operator account and an optional OIDC account from a locally operated
  IdP.
- Local login never contacts an IdP or another network service. PostgreSQL
  stores a salted memory-hard password verifier, not the password.
- A local account may also have local TOTP. Password-only login creates a
  normal session; actions that require recent MFA remain unavailable until the
  login includes a valid TOTP. This preserves the existing sensitive-action
  boundary without making MFA mandatory for read-only and routine workflows.
- The first local administrator is provisioned by an interactive CLI. Password
  and TOTP material are never accepted in argv or environment variables.
- Local operators rotate their password through the authenticated dashboard or
  API. The current session advances to the new authorization version and every
  other session is revoked atomically. The CLI fallback revokes all sessions.
- Local and OIDC identities use the same revocable PostgreSQL sessions, CSRF,
  scoped RBAC, progressive rate limiting and audit boundary.
- Break-glass remains a distinct single emergency identity with critical
  alerts. It is not presented as a substitute for normal local login.
- OIDC remains supported for a local IdP, but is optional. No cloud IdP is
  installed, contacted or required by the pilot installation.

## Consequences

A one-server deployment can be installed and operated without any identity
service beyond RTSP Proxy and PostgreSQL. Operators that already run a local
IdP can enable OIDC without disabling local accounts. Local credential
lifecycle, password rotation and TOTP recovery become responsibilities of the
control plane and have dashboard, API, audit and CLI/runbook coverage.

## Alternatives

- Keeping IdP-only normal login was rejected because it makes a second service
  a mandatory availability and installation dependency.
- Reusing break-glass as the normal account was rejected because it destroys
  the emergency-only audit and alert semantics.
- Requiring a cloud IdP was rejected because the deployment must operate
  without sending identity data outside the local contour.

## Failure domains and security boundary

| Failure | User-visible effect | Blast radius | Recovery |
|---|---|---|---|
| Local IdP unavailable | OIDC login unavailable; local login continues | OIDC users only | repair IdP or use local operator |
| PostgreSQL unavailable | all new login/session checks fail closed | operator plane | restore PostgreSQL |
| Local password compromised | affected account can be used within its RBAC scope | one account | disable/rotate account and revoke sessions |
| Local TOTP unavailable | password login works, recent-MFA actions are denied | one account | rotate TOTP through offline CLI |

## Rollout and rollback

The additive schema creates local credential rows without changing existing
OIDC or break-glass identities. Enable local login only after provisioning at
least one local administrator and testing accepted/rejected login. Rollback to
an older application requires a schema-compatible release; do not downgrade the
live database.
