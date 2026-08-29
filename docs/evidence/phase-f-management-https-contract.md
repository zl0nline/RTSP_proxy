# Phase F management HTTPS contract

- Last reviewed: 2026-08-29
- Status: implementation, independent review and native amd64/arm64 CI complete
- Deployment: direct Linux/systemd, no Docker
- Server architectures: amd64 direct-Linux passed; amd64/arm64 native CI passed
- Media transport: ordinary `rtsp://` with interleaved TCP; unchanged by this slice

## Evidence boundary

This slice implements, independently reviews and publishes the production
management-listener HTTPS boundary on native Linux amd64 and arm64. It does not
close Phase F, qualify server capacity or change the external camera transport.
Live dashboard polling/SSE is independently reviewed and green in native CI.
The schema-0020 completed-probe projection is a separate local Phase-G
foundation awaiting review/native CI; its production executor does not exist.
Full resource/incident operator projection, Phase G hardware/WAN/fault/24-hour
evidence and rollout remain Production **NO-GO** gates. The exact live boundary
is recorded in
[`phase-f-dashboard-live-updates-contract.md`](phase-f-dashboard-live-updates-contract.md).

## Implemented contract

- WEB binds one explicit loopback or management-interface address. IPv4/IPv6
  wildcard, IPv4 limited broadcast and multicast addresses fail before listener
  startup. A non-loopback bind requires an absolute certificate/private-key
  identity.
- Uvicorn terminates TLS directly. Plain HTTP on that port is rejected. Every
  management HTTPS response receives the exact
  `Strict-Transport-Security: max-age=31536000` policy, including early
  authentication/authorization/session-outage responses and sanitized
  unexpected 500 responses.
- The production systemd unit loads one combined certificate/private-key PEM
  with `LoadCredential`. The same immutable credential path is passed through
  CLI arguments as both Uvicorn TLS inputs, so `EnvironmentFile` cannot redirect
  the process to operator-controlled paths and a concurrent start cannot combine
  files from different versions.
- The native systemd contract verifies a CA-signed certificate with the exact
  IP SAN and hostname validation, a read-only credential with no other-user
  permissions, regular-file/nlink constraints, the configured service UID,
  HSTS, plaintext rejection and bounded unit/PID/listener cleanup. Successful
  HTTPS startup also proves that the service identity can read the
  manager-protected credential.
- The renewal runbook distinguishes IP SAN from DNS SAN, supports bracketed
  IPv6 URL authorities, validates candidate and rollback PEM identities, holds
  an exclusive root-only lock, fsyncs the versioned bundle and directory entries,
  switches one symlink atomically, bounds every restart/readiness call and binds
  convergence to a changed systemd `InvocationID` plus the exact served leaf
  certificate fingerprint. Failure restores and verifies the previous target.

## Local and direct-Linux checks

The final implementation passed:

- local full suite: 924 passed / 20 opt-in external-contract skips, with 90.07%
  statement coverage;
- Ruff and mypy over `src` and `tests`, `git diff --check`, and `bash -n` for the
  documented rotation transaction;
- focused management/config/deployment/operator suites: 126 passed / one
  expected opt-in native skip; and
- direct Linux amd64 on `grob` (Ubuntu 26.04, systemd 259): one real
  user-systemd `LoadCredential`/combined-PEM/CA-SAN/HSTS contract, one real
  standalone Uvicorn TLS/plaintext-rejection contract and the deterministic
  timeout-cleanup regression passed.

No sudo credential was read, stored or logged during the remote validation. The
temporary test directory and transient unit were removed after the run.

## Independent review and publication

Independent Spec and Standards reviews found no remaining High or Medium issue
in the frozen implementation/runbook slice. The final review seam required a
successful nonempty baseline systemd `InvocationID`, a different active
invocation after restart, and exact served-certificate fingerprints for both
forward activation and rollback.

The final implementation and both CI-remediation diffs passed independent Spec
and Standards review without remaining High or Medium findings. On commit
`32ac6138777e460846a1caed1e46174138ebc9d5`, all seven jobs passed in
[CI run 33253244053](https://github.com/zl0nline/RTSP_proxy/actions/runs/33253244053).
The amd64 and arm64 application jobs each executed the opt-in native
root-systemd suite (two tests passed on each architecture), proving the fixed
service UID, protected combined-PEM `LoadCredential`, verified CA/IP-SAN HTTPS,
HSTS, plaintext rejection and bounded cleanup. Phase F remains **IN PROGRESS**
and Production remains **NO-GO**.
