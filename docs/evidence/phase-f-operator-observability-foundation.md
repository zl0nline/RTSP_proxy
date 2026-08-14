# Phase F operator and observability foundation

- Last reviewed: 2026-08-14
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
or production capacity evidence. Server-rendered dashboard work is tracked by
later commits and CI outside this evidence boundary. Camera mutations, complete
browser accessibility/confirmation E2E, the operator rotation drill,
physical-hardware capacity and the 24-hour soak remain open. Production
therefore remains NO-GO.
