# Phase F disruptive node-operation contract

- Last reviewed: 2026-08-24 (Spec/Standards PASS)
- Status: implementation, independent review, direct-Linux validation and native CI complete
- Commit: `466e72feb6c5401dd4b281baabc07095b7173669`
- CI: [run 32708863738](https://github.com/zl0nline/RTSP_proxy/actions/runs/32708863738)
- Architectures: one identical Linux amd64/arm64 server contract
- Deployment: direct Linux/systemd, no Docker

## Evidence boundary

This slice covers the remaining disruptive node workflows in the authenticated
dashboard and JSON API. It does not claim Phase F, Phase G capacity evidence or
production completion.

The implemented boundary includes:

- RUNNING-node external-port preview/apply;
- non-empty DRAINING-node reconfigure/restart preview/apply;
- restart of an empty RUNNING node and trusted-release update of an empty
  STOPPED node;
- exact revision/source-state fencing for every action;
- operator session/account/authorization version and recent-MFA fencing for
  port change and non-empty reconfigure/restart; and
- one shared redacted audit/outbox mutation context for dashboard and API.

`RTSP_PROXY_OPERATOR_RECENT_MFA_SECONDS` defaults to 300 seconds and is bounded
to 30..900 seconds. A disruptive preview and apply both require a still-current
MFA proof. The confirmation page shows the exact sorted registered-camera
Public IDs and the exact active-reader subset. It never shows a source URL,
source credential, downstream secret or MediaMTX binary digest. Empty-node
restart has zero camera blast radius and therefore uses the ordinary
revision/state-fenced action without a disruption token.

## Admission and process proof

For a RUNNING node, preview reads a fresh, process-bound exact reader set from
the root helper. Apply acquires the same per-node writer guard used by lifecycle
and reconciliation, then hot-updates each existing camera path to
`maxReaders=-1`, reads every update back, and captures one final metrics sample.
Registered disabled/deleting cameras whose runtime path is absent remain absent;
the fence never recreates them.

For a RUNNING node, the short-lived confirmation binds:

- node, desired revision, source state, external port and target release;
- exact camera placement fingerprint and registered-camera count;
- exact reader fingerprint and reader count; and
- MediaMTX PID, process start ticks, boot ID and observed release.

Any changed placement, reader set, process generation, operator session,
authorization version or MFA timestamp invalidates apply. At most two
disruptive node applies execute concurrently per web process; saturation is a
retryable `503 node_disruption_busy`.

STOPPED/FAILED reconfigure has no process generation to bind. It instead
requires the root helper's exact proof that no process exists and binds that
inactive runtime state into the confirmation and durable audit context.

The production fence has one 60-second absolute budget. The first 50 seconds
cover path fencing plus the runtime action and any port-change rollback. The
root helper retains its independently configured cleanup reserve of at least
20 seconds (25 seconds by default) inside that deadline. The final 10 seconds
are reserved only for restoring every owned path to its exact original config
when apply does not complete. A timeout cannot start another unbounded helper
operation. Ambiguous committed path updates are treated as owned and restored
with exact read-back.

After a successful restart/port change the prior MediaMTX process no longer
owns the hot fence, so the lease is completed instead of writing stale config
into the new generation. Only the selected node is touched; established streams
on every other node remain outside the blast radius.

## Validation status

Independent Spec and Standards reviews passed on the exact implementation tree.
Ruff, strict mypy and diff-check are clean. A direct-Linux Ubuntu amd64 run on
the isolated `grob` lab host passed `851 passed, 19 skipped` with exact 90.00%
coverage. The skips are the separately gated MediaMTX/load/netem, privileged
systemd and opt-in browser contracts. The real browser contract then passed
`3 passed` in 40.13 seconds against the same tree. Because that disposable lab
host disables Chromium user namespaces through AppArmor, only the external
browser client used the repository's explicit
`RTSP_PROXY_BROWSER_NO_SANDBOX=1` lab switch; the application/server and
production deployment never launch Chromium. No Docker or `sudo` was used.

The macOS application run excluding the three separately executed browser
tests passed `849 passed, 18 skipped` at 90.00% coverage; both POSIX browser
process-group cleanup regressions then passed separately.

CI run 32708863738 executed the exact implementation commit above. All seven
jobs passed: application/PostgreSQL, packaged migrations, systemd/nftables,
patched MediaMTX and RTSP/load contracts on Linux amd64 and arm64, plus the
external-management-client Chromium job on amd64. The generated protected
HTTP inventory in that run contains all 63 current route-method pairs. The
real browser remains an external client; the server contract is identical on
amd64 and arm64.

## Remaining gates

Phase F remains **IN PROGRESS** for the remaining access-policy/grant operator
workflow. Phase G hardware capacity, WAN/fault and 24-hour soak evidence, plus
Phase H pilot rollout, are still open. Production remains **NO-GO**.
