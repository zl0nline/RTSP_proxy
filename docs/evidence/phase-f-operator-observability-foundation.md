# Phase F operator and observability foundation

- Last reviewed: 2026-08-21
- Status: foundation complete; Phase F remains in progress
- CI: https://github.com/zl0nline/RTSP_proxy/actions/runs/31782530517
- Commit: `292a0302590838451e4f454322930804271b4d71`
- Architectures: Linux amd64 and arm64, identical contract
- Deployment: direct Linux/systemd, no Docker

This evidence covers the non-UI Phase F foundation. It includes the bounded
fleet collector and generation-bound per-path metrics, persisted fleet
snapshot API, failure/recovery incident state machine, durable SMTP dispatcher,
digest-only PostgreSQL operator sessions, monotonic authorization fencing,
RBAC and CSRF HTTP boundaries, browser-bound OIDC Code+PKCE with exact MFA
claims, and audited break-glass password+TOTP admission.

Live OIDC discovery and claim compatibility are checked with bounded startup
and periodic readiness. Break-glass failures and successes enter the durable
security audit/notification path. Callback, collector, PostgreSQL and SMTP
operations have bounded admission and shutdown behavior. Secrets are delivered
through the documented systemd credential boundary; direct Linux service and
PostgreSQL least-privilege contracts remain part of the test suite.

CI run `31782530517` completed successfully at the exact commit above. All six
jobs passed:

- `test (amd64)` and `test (arm64)`: 698 tests passed with 18 expected
  native-only skips and 90.16% coverage, followed by Ruff, mypy, release build,
  SBOM/audit, clean-wheel install, native PostgreSQL migrations, systemd unit
  verification and owned nftables validation;
- `media-binaries-contract (amd64)` and `(arm64)`: pinned patched MediaMTX and
  FFmpeg/ffprobe release verification plus effective listener contracts;
- `pull-load-generator-contract (amd64)` and `(arm64)`: pinned runtime and
  netem evidence, ordinary H.264/H.265 RTSP/TCP pull paths, and two-node RTP
  isolation.

Independent Spec and Standards reviews found no remaining High or Medium issue
in the published foundation and CI remediation. The systemd verifier is scoped
to standalone `.service` and `.socket` units; the web-auth drop-in remains
parsed and asserted by the deployment contract tests instead of being treated
as a standalone unit.

This is functional evidence for the non-UI foundation, not Phase F completion
or production capacity evidence. Subsequent server-rendered dashboard evidence
is tracked outside the foundation boundary: server/node pages passed run
`31784945654` at commit `808e74e121b5ed56f6626490a20bc919ab8328eb`,
and the bounded camera catalog passed run `31790262853` at commit
`3edb3026d1f2ececaebd86ddbdcebda3b32fb877`. The secret-free camera detail page
with exact `camera:<uuid>` scope and global `server:*` superset passed run
`31794353270` at commit `e38af30dc492984956f1bb8f55434ce9430fe127`.
Server-rendered update/enable/disable/delete forms with bounded CSRF parsing,
exact submitted-revision CAS and reader-aware confirmation passed all six jobs
at commit `a6b2fd4cb1e9538dc679c581b4f1a81a5d2cb4f6`
([CI run 31805146878](https://github.com/zl0nline/RTSP_proxy/actions/runs/31805146878)).
The supplied confirmation token remains mandatory and
digest/revision-bound even if the observed reader disconnects before apply;
stale conflicts expose only expected/current revisions. One bounded camera-name
contract is enforced by UI, domain, in-memory and PostgreSQL adapters. Name
activation additionally requires the bounded 0015 legacy preflight; it reports
only non-deleted camera UUIDs and the catalog revalidates visible names
fail-closed. Immutable deleted rows remain hidden permanent tombstones and do
not block the migration. The server-rendered move workflow passed all six
native amd64/arm64 jobs at commit
`ffd12509e99fdff6336ffc5676cf3e9363b1fe66`
([CI run 31811342043](https://github.com/zl0nline/RTSP_proxy/actions/runs/31811342043)).
It lists only
eligible non-full target nodes, carries the rendered camera revision through
preview/apply and requires a target/reader-count-bound token before disrupting
an occupied path. Candidate enumeration is a DB-clock store projection that
excludes prepared port changes; the transactional switch still rechecks it.
The camera-scoped status route binds a persisted `move_id`, shows its actual
state and does not claim completion early. The public path is unchanged and no
source URL is rendered. Automated real-browser accessibility, confirmation,
OIDC and logout evidence is recorded separately in
[`phase-f-dashboard-browser-contract.md`](phase-f-dashboard-browser-contract.md).
The durable authentication/authorization-denial and logout matrix is recorded
in
[`phase-f-operator-security-audit-contract.md`](phase-f-operator-security-audit-contract.md).
That later evidence also includes the recursively generated matrix for all 48
protected route-method pairs present at its commit, green in CI run
[`32680412385`](https://github.com/zl0nline/RTSP_proxy/actions/runs/32680412385).
The later aggregate overview polling and one-camera SSE projection is tracked
in
[`phase-f-dashboard-live-updates-contract.md`](phase-f-dashboard-live-updates-contract.md);
its local/direct-Linux functional gate is green while independent review/native
CI and completed-probe/capacity evidence remain open. Physical-hardware
capacity and the 24-hour soak remain open. Revision-fenced
break-glass rotation with atomic
session revocation and an accepted/rejected notification drill passed
independent Spec/Standards review and all six native amd64/arm64 jobs at commit
`df35a2c0089564d1833c62fb65d256f09864fbde`
([CI run 32428149162](https://github.com/zl0nline/RTSP_proxy/actions/runs/32428149162)).
The rotation contract rejects stale revision, identity and concurrent attempts
through the same secret-free audit/outbox seam, and fences session issuance
against credentials authenticated immediately before a successful rotation.
Production therefore remains NO-GO.
