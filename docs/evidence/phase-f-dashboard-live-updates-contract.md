# Phase F dashboard live-update contract

- Last reviewed: 2026-08-29
- Status: implementation, independent review, direct-Linux validation and
  native/external CI complete for this bounded slice
- Deployment: direct Linux/systemd, no Docker
- Server architectures: architecture-neutral Python/ASGI contract for amd64 and arm64
- Media transport: ordinary `rtsp://` over interleaved TCP; unchanged by this slice

## Evidence boundary

This slice implements the bounded real-time UI model agreed in issue #7. It
does not close Phase F, implement a probe-result event source, qualify the
10,000-camera cardinality budget or publish production capacity evidence.

The browser never contacts a MediaMTX API or metrics endpoint. Both overview
polling and camera live state read the collector's persisted aggregate
`FleetSnapshot`; request-time fan-out to media nodes is absent.

## Implemented contract

The server overview polls `/api/v1/dashboard/snapshot` every 10 seconds by
default. `RTSP_PROXY_DASHBOARD_POLL_INTERVAL_SECONDS` is typed and constrained
to 5–30 seconds. Stable node topology updates text-only summary, node metrics,
per-node observation time, freshness and the counter-reset/unknown-continuity
marker in place. A topology
change reloads the server-rendered page instead of
constructing untrusted HTML in JavaScript.
Polling has one in-flight request, a five-second deadline covering both headers
and complete JSON body consumption, and bounded exponential backoff. Dashboard
reads use a durable per-account minute bucket.

One camera detail view can open one SSE stream for its authoritative operator
session. A second stream under the same session is rejected with bounded 429;
the process-wide default is 256 streams. The stream projects only the selected
camera's public ID on its authoritative node, source-ready state, occupied 0/1
state and collector-derived input/output bitrate from contiguous monotonic
epochs in the aggregate snapshot. Wall-clock `metric_observed_at` is freshness
metadata only; it is never a rate denominator. Per-path reset and gap markers
suppress cross-generation or stale rates. Source URL,
credentials and peer IP are absent.

The live adapter has these explicit defaults:

- aggregate refresh every 5 seconds;
- one bounded two-second single-flight refresh waiter shared by concurrent
  requests, with one path index built per aggregate snapshot;
- one secret-free read-only batch of authoritative placements for active SSE
  cameras on each refresh (at most the 256 admitted streams), so a move is
  discovered without a second browser request;
- heartbeat every 15 seconds, authorization before admission/replay and an
  in-memory epoch fence before every state delivery;
- one shared read-only batch of all active session epochs at most once per
  second, with a 750-millisecond lookup deadline, so interval plus lookup stays
  below the two-second revocation ceiling without per-event SQL reads/writes;
- a five-second deadline at the outer ASGI boundary that performs the actual
  socket write, plus shielded subscription cleanup;
- eight queued events per subscriber, 128 events per camera history and at
  most 10,000 tracked camera channels; inactive channels expire after five
  minutes;
- a slow/full subscriber queue disconnects that subscriber instead of growing;
- state payloads are coalesced at the aggregate refresh boundary; and
- shutdown cancels the refresher, waits for every tracked bounded snapshot and
  authorization worker, and removes all active subscriptions before the
  application store is closed.

`Last-Event-ID` accepts only a canonical positive decimal integer of at most 19
digits. An available bounded history is replayed. A missing, expired or
non-resumable position emits `resync_required`; the browser refreshes the one
camera JSON snapshot. A changed/revoked/unavailable authoritative session emits
`authz_epoch` and closes the stream. A heartbeat keeps direct and correctly
configured proxy connections alive.

A camera placement change discovered by that server-side batch starts a new
live epoch: queued/history events from the previous node are discarded,
existing subscribers receive
`resync_required`, and the camera is immediately projected against the exact
new `(node_id, public_id)` even when the aggregate snapshot timestamp has not
changed. An old `Last-Event-ID` cannot replay a previous-node projection.

The response is `text/event-stream` with `Cache-Control: no-store, no-cache,
must-revalidate`, `X-Accel-Buffering: no` and `X-Content-Type-Options: nosniff`.
The stream declares a five-second EventSource reconnect floor. A separate
durable per-account reconnect bucket admits one attempt per five seconds and
returns `429` plus exact `Retry-After` when exhausted.
The dashboard CSP allows only same-origin local script and same-origin
connections. JavaScript writes via `textContent`; it does not use `innerHTML`.
After three SSE failures the camera view closes EventSource and falls back to
the same bounded 5–30 second aggregate-snapshot polling interval, with one
request in flight, five-second timeout and bounded backoff.

The new per-path payload is stored in an additive node-level `path_metrics`
object. Its presence is also the detailed-signal availability marker: absence
in an N−1 snapshot is `unknown`, never idle. Paths are keyed by exact
`(node_id, public_id)`, so stale source-node evidence after a move cannot be
projected as target state. Aggregate `metrics` retains the exact N−1 shape, so
the previous WEB reader ignores the extension safely while a new COLLECTOR is
rolled out. The
new WEB accepts both schema 0018 (existing dashboard reads remain available but
live reconnect is fail-closed) and schema 0019; after migration and WEB restart,
both durable buckets become active.

The protected surface now contains 75 generated route-method pairs. The camera
snapshot, camera SSE and internal live-diagnostics routes enter the same
authentication, exact camera scope and safe semantic audit-target matrix as the
existing dashboard. Diagnostics expose only bounded counts for active/tracked,
resume/resync/rejection, slow-client and authz disconnect outcomes.

## Functional validation

The final local application gate passed with `970 passed, 20 skipped` and
`90.04%` coverage against the unchanged 90% floor.
Ruff, strict
mypy over `src` and `tests`, JavaScript syntax, shell syntax and diff hygiene
were green.

The dirty implementation tree was copied to a disposable directory on `grob`
(Ubuntu 26.04, Linux amd64) without Docker or sudo. Locked CPython 3.12.13
dependencies passed `802 tests` with `175` environment-specific native or
PostgreSQL skips; Ruff, strict mypy, JavaScript and shell checks were green.

The same Linux host ran `agent-browser 0.26.0` with Chrome for Testing 152 as
an external management client. Its real HTTPS scenario passed in `87.28s` and
exercised OIDC, node and camera registration, the live connected/occupied
camera projection, fail-closed fresh/stale/reset DOM transitions, delayed-body
abort semantics, access-grant one-time secret handling, occupied-reader
confirmation and logout. Three PNG
screenshots and four semantic
snapshots remained bounded and secret-canary free. Ubuntu's AppArmor policy required the
repository's explicit no-sandbox switch only for this disposable external
browser; the deployed server never launches Chromium.

The implementation and the coverage-only remediation both passed independent
Spec and Standards review without High or Medium findings. The published
implementation is commit
[`21ce96ee4db43db6901bac923c50a314a9e0d2db`](https://github.com/zl0nline/RTSP_proxy/commit/21ce96ee4db43db6901bac923c50a314a9e0d2db);
the final test-only remediation is commit
[`a77db2daead18cc15afa5a497fdd9c5ca1a217f0`](https://github.com/zl0nline/RTSP_proxy/commit/a77db2daead18cc15afa5a497fdd9c5ca1a217f0).
All seven jobs passed in
[CI run 33265832444](https://github.com/zl0nline/RTSP_proxy/actions/runs/33265832444):
application/coverage, migrations, packaging, systemd and nftables checks on
amd64 and arm64; patched MediaMTX and native RTSP/RTP load contracts on both
architectures; and the external HTTPS Chromium workflow on amd64.

## Remaining gates

The completed-probe SSE event remains unavailable until the production probe
result source exists. Polling/SSE capacity, query/cardinality budgets at the
50×100 and optional 100×100 profiles, reverse-proxy timeout/buffering evidence,
physical hardware fault/WAN tests and the 24-hour soak remain open. A future
reverse proxy must preserve the 15-second heartbeat, disable response buffering
and allow a client-write timeout longer than the heartbeat; direct Uvicorn TLS
is the currently supported deployment boundary.

Phase F remains **IN PROGRESS** and Production remains **NO-GO**.
