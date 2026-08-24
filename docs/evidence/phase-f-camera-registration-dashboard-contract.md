# Phase F camera registration dashboard contract

- Last reviewed: 2026-08-24
- Status: implementation and direct-Linux validation complete; independent review and CI pending
- Deployment: direct Linux/systemd, no Docker
- Server architectures: Linux amd64 and arm64, identical application contract
- Transport: ordinary `rtsp://` with interleaved TCP; unchanged by this slice

## Evidence boundary

This slice adds the operator camera-registration workflow. It does not claim
Phase F completion, production capacity or a completed Phase G soak.

The server-rendered dashboard now provides:

- `GET /dashboard/cameras/new` with one fresh session-scoped UUIDv4
  idempotency key, camera name and credential-free RTSP source fields;
- automatic placement on the least-loaded eligible node, with automatic node
  provisioning when policy allows it;
- manual placement on an exact eligible node shown with registered-camera
  count, capacity, external port and active-source count;
- `POST /dashboard/cameras` through the same RBAC, CSRF, source validation and
  operator-attribution seam used by the JSON API; and
- a redirect to the persisted secret-free camera detail after success.

The browser lab submits the form by keyboard, verifies the newly registered
camera in the catalog/detail workflow and proves that the source canary is not
present in DOM, cookies, browser storage, CacheStorage, resource URLs, browser
errors or retained artifacts. The protected route inventory is now 72
route-method pairs.

## Idempotency and attribution

Migration `0018_camera_registration_keys` creates the immutable
`camera_registration_requests` ledger with a composite
`(actor_session_id, idempotency_key)` primary key. A canonical request SHA-256
binds name, validated source and manual/automatic target identity. The ledger
stores no second source-URL copy.

Every `camera.create` request first consumes the independent durable
per-account `camera_mutation` bucket. Exhaustion returns an audited 429 with
`Retry-After` before a pending intent or camera row can be written.

The request intent and digest commit with `status = pending` and
`synchronous_commit = on` before placement or automatic node provisioning can
have side effects. The camera row, permanent public-ID tombstone,
current/history placement, default two-level access policy, transition of that
same ledger row to `complete` with the camera UUID, and matching
operator-attributed audit/outbox events then commit in one synchronous
transaction. An unchanged replay resumes a pending intent or returns the
original camera; changed payload under the same key returns 409. A retry after
target deletion also conflicts instead of creating a replacement. Both
rejection classes append a sanitized durable mutation-rejection audit/outbox
pair and fail closed when that audit journal is unavailable.

Automatic capacity carries the original camera mutation context through node
registration/start. Consequently `media_node.created`,
`media_node.desired_state_changed`, `camera.created` and
`camera.access_policy_created` share the same account, session, action,
request and idempotency attribution without copying the source URL into audit.

During the 0.10.0/0017 rolling window, catalog/access/node operations stay
available but camera registration fails closed with a bounded 503. Exact 0018
activates the write path. Downgrading a live 0018 schema to an application whose
maximum is 0017 is not supported.

## Local and direct-Linux checks

The current implementation passed:

- local full Python suite before the final documentation-only edits;
- focused camera registration, migration bridge, release/deployment, health
  and observability suites;
- Ruff and mypy over `src` and `tests`;
- real local Chromium: 3 scenarios passed, including the keyboard camera form;
  and
- isolated direct-Linux amd64 on `grob`: pinned CPython 3.12.13, `uv 0.12.3`,
  an unprivileged PostgreSQL 18 test cluster, 903 passed / 19 external-contract
  skips, plus Ruff green.

The Linux directory and Python runtime were temporary and required no Docker or
privileged mutation. The external MediaMTX/load/systemd contracts were skipped
because this slice does not alter those previously published seams.

## Remaining gates

Independent Spec and Standards review, native amd64/arm64 CI and publication of
the exact commit/run remain required before this evidence status can be marked
reviewed and green. Phase F still has other operator workflows, and Phase G
still requires hardware capacity, WAN/fault evidence and the 24-hour soak.
Production remains **NO-GO**.
