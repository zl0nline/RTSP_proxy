# Phase F node operations contract

- Last reviewed: 2026-08-24 (Spec/Standards PASS)
- Status: independently reviewed and published in native amd64/arm64 CI
- Architectures: Linux amd64 and arm64, identical server contract
- Deployment: direct Linux/systemd, no Docker

## Evidence boundary

This slice covers operator node registration and the bounded lifecycle actions
available from both the server-rendered dashboard and JSON API. It does not
claim Phase F or production completion.

The contract requires:

- automatic random or exact manual external-port registration under the
  configured range/reserved/max-node policy;
- at most 100 registered cameras per node, unchanged by this control-plane
  work;
- one shared CSRF/RBAC and operator-attribution seam for dashboard and API;
- expected revision and source-state fencing before every normative lifecycle
  mutation or privileged runtime call;
- start, stop, drain, maintenance, resume and empty-node delete without direct
  `systemctl`, PostgreSQL or MediaMTX access;
- a persisted registration status page that remains valid when privileged
  provisioning fails after desired state commits; and
- a session-scoped UUIDv4 idempotency key whose canonical request digest,
  target node, desired state, audit and outbox commit atomically.

Migration `0016_node_registration_keys` stores registration requests in an
immutable ledger separate from `media_nodes`. An unchanged replay returns the
original node and URL without another port allocation or runtime provision.
The same key with another payload conflicts. Node deletion leaves the ledger
entry in place and a later stale replay fails closed instead of creating a new
node. During a 0.8.0/0015 rolling window the authenticated registration route
returns a bounded 503 until exact 0016 is current.

## Validation status

The final CI application suite passed `810 passed, 19 skipped` on both amd64
and arm64 with exact coverage `90.03%`; Ruff, mypy,
diff-check and wheel-content verification were clean. The opt-in real Chromium
HTTPS/OIDC scenario also passed after adding production-router node
registration to its keyboard/CSRF workflow.

An isolated direct-Linux Ubuntu amd64 stand (`grob`) installed PostgreSQL 18
and passed the same `805 passed, 19 skipped` suite in 119.25 seconds, including
the real migration chain and PostgreSQL concurrency/atomicity tests; Ruff and
mypy were clean. The 19 skips are the separately gated MediaMTX/load/netem and
privileged systemd contracts unaffected by this slice, plus the browser job
already executed locally. No Docker was used.

The recursively generated protected-route inventory contains 57 route-method
pairs. Independent Spec/Standards review passed on the implementation tree.
All seven jobs in
[CI run 32693949200](https://github.com/zl0nline/RTSP_proxy/actions/runs/32693949200)
completed successfully on commit
`2f6b012d91ab4de2ad07d631f4cdfa46b2422255`: application/coverage,
packaged PostgreSQL migration, MediaMTX and pull/load contracts on native
amd64/arm64, plus the external-client Chromium E2E job.

## Remaining gates

This node-operation slice does not close the remaining Phase F workflows,
Phase G hardware capacity/WAN/fault/24-hour evidence or Phase H pilot rollout.
Production remains **NO-GO**.
