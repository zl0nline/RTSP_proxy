# Release 0.13.10 native node startup evidence

- Date: 2026-09-03
- Commit: `bd8f40aa7484a0a257b7feec2fd5e985f1a8a782`
- Target: direct-Linux amd64 pilot server, systemd `DynamicUser`, MediaMTX
  `v1.20.0-rtsp-proxy.3`
- CI: [run 33782724395](https://github.com/zl0nline/RTSP_proxy/actions/runs/33782724395)

## Failure chain reproduced

An authenticated built-in local administrator could submit the create-node
form, but the request failed before persistence because the normative mutation
context accepted only OIDC and break-glass identity sources. After accepting
the already-authorized `local` source, provisioning exposed two native-systemd
contract defects:

1. the MediaMTX DynamicUser could not traverse the shared state/log parents and
   systemd reported `status=200/CHDIR`;
2. the root lifecycle helper could not resolve `/proc/<pid>/exe` for the
   DynamicUser-owned process after its capability set had been emptied;
3. after process identity succeeded, lifecycle smoke rejected MediaMTX's
   canonical config API response because pathless `api` and `metrics`
   permissions are returned with an explicit empty `path`.

No camera credential, callback credential, management password or complete
MediaMTX configuration was written to test output or this evidence.

## Fixed contract

- Local, OIDC and break-glass operator identities enter the same audited node
  mutation boundary after authentication and authorization.
- Shared runtime/state/log parents use mode `0751`; per-node directories remain
  `0750`.
- `rtsp-proxy-node-runtime.service` receives only `CAP_SYS_PTRACE`, which is
  needed for exact DynamicUser process identity verification. The diagnostic
  drop-in was removed after installing the packaged unit.
- Lifecycle smoke expects MediaMTX's canonical empty `path` for management
  permissions while continuing to compare credentials and all listener/auth
  settings exactly.

## Verification

- Local suite: `1545 passed, 105 skipped`; Ruff and mypy passed.
- GitHub Actions completed successfully on amd64 and arm64, including external
  browser, patched MediaMTX, native media-binary and RTSP/load contracts.
- The official amd64 artifact was installed as release `0.13.10`.
- Dashboard empty-node restart returned HTTP `303`; the resulting desired and
  runtime states were both `running`, and node health was `healthy`.
- The management readiness endpoint returned HTTP `200`.
- The exact empty test node was then stopped and deleted through Dashboard; its
  systemd instance became inactive and its node configuration was removed.

This evidence closes risk R3 only for the pinned MediaMTX build. Any MediaMTX
upgrade must rerun the canonical configuration, auth, lifecycle and native
process-identity contracts.
