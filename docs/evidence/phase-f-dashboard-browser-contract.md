# Phase F dashboard browser contract

- Last reviewed: 2026-08-24
- Status: browser slice complete; Phase F remains in progress
- CI: https://github.com/zl0nline/RTSP_proxy/actions/runs/32676065004
- Commit: `a6166e3aa6a6a3c6d87991d509ea126e0d48bd09`
- Server architectures: Linux amd64 and arm64, identical application contract
- Browser architecture: Linux amd64 external management client
- Deployment: direct Linux/systemd, no Docker

## Evidence boundary

This evidence covers the automated dashboard browser slice, not Phase F or
production completion. The HTTPS browser lab uses the real application routes,
templates, session and CSRF middleware, domain controls and a same-origin test
OIDC provider. Only external dependencies such as the IdP and media runtime are
bounded lab adapters.

The browser scenario proves:

- anonymous dashboard to OIDC Code+PKCE login and authenticated return;
- keyboard-only traversal with a first-focus skip link and real Tab/Enter input;
- server, node, bounded camera catalog and secret-free camera detail rendering;
- occupied single-reader disable preview, cancellation, fresh confirmation and
  successful apply through the production confirmation seam;
- focus on the autofocus confirmation heading and a labelled assertive alert
  region on both preview passes;
- CSRF-protected logout, server-side session revocation and secure cookie clear;
- computed WCAG contrast checks for the rendered state; and
- absence of the source-secret canary from DOM, cookies, browser storage,
  CacheStorage, resource URLs, browser errors and retained artifacts.

Three bounded screenshots and four semantic browser snapshots are uploaded as
the `dashboard-browser-e2e-amd64` CI artifact. Before success, the runner
requires that exact seven-file set, non-empty bounded snapshots and valid
non-empty PNG signatures. It then cleans
its HTTPS process group and escalates bounded cleanup from `SIGTERM` to
`SIGKILL`; regressions cover both an ignored TERM and a shell leader that exits
while a descendant remains.

## Architecture boundary

The browser is an external management client, not part of the deployed server.
The pinned browser driver reports that Chrome for Testing publishes no Linux
arm64 build, so the real-Chromium job runs on amd64. This does not reduce the
server contract: the same dashboard templates, OIDC/session, CSRF, logout,
RBAC, packaging, migrations and direct-Linux unit checks execute in both
`test (amd64)` and `test (arm64)`.

CI run `32676065004` completed successfully at the exact commit above. All
seven jobs passed:

- `browser-e2e (external client, amd64)` executed the real HTTPS scenario and
  uploaded its evidence artifact;
- `test (amd64)` and `test (arm64)` passed the application, lint, type,
  packaging, PostgreSQL migration, systemd and nftables gates;
- `media-binaries-contract (amd64)` and `(arm64)` verified the pinned patched
  MediaMTX and FFmpeg/ffprobe release/listener contract; and
- `pull-load-generator-contract (amd64)` and `(arm64)` passed ordinary
  H.264/H.265 RTSP/TCP pull, runtime/netem and two-node RTP-isolation gates.

Independent Spec and Standards reviews found no remaining High or Medium issue
in this slice. The same browser scenario also passed on an isolated direct
Linux amd64 stand; the stand additionally rebuilt the pinned MediaMTX binary,
compiled the GStreamer load tools and passed the ordinary RTSP/TCP transparency
and two-node isolation contracts, then removed its temporary privileged units,
configuration and processes.

## Remaining gates

Phase F remains **IN PROGRESS** until the complete authorization-denial and
logout audit matrix is implemented, reviewed and CI-green. Phase G physical
hardware capacity, fault/WAN evidence and the 24-hour soak, followed by Phase H
pilot rollout, also remain open. Production is therefore **NO-GO**.
