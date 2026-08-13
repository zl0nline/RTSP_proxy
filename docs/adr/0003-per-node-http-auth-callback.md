# ADR 0003: Loopback HTTP callback for per-node RTSP access

- Status: Accepted
- Date: 2026-08-10
- Updated: 2026-08-13
- Decision owners: technical owner, security owner, operations owner
- Related issues: #1, #4, #8, #9, #10

## Context

External consumers use ordinary RTSP Basic Auth while camera source credentials
remain private. IP policy must be evaluated before password verification,
reader admission is limited to one consumer/camera, and new-session revocation
must not require MediaMTX restart.

Every bounded media node runs on the same Linux server as the control plane and
has a loopback-only auth callback endpoint. A callback decision must be scoped
to exact node id, canonical path, directly observed peer IP and credential
revision.

## Decision

Use pinned MediaMTX HTTP auth callback per media node, bound to loopback.
External `read` decisions include node identity, user/password, action,
canonical path, protocol and peer IP.

Authorization order in the callback:

1. validate target node/path generation;
2. evaluate `internet`/`local` CIDRs against directly observed peer IP;
3. verify downstream username/password;
4. enforce drain/maintenance admission.

The implementation performs the node/path/enabled/drain/maintenance lookup in
one authoritative PostgreSQL query, evaluates the normalized peer-IP policy
before reading any grant row, then checks the generated high-entropy token with
constant-time HMAC-SHA-256 under a versioned pepper. Raw tokens are one-time
outputs and are never stored. Grant kind, explicit expiry, server-derived
creator and safe last-use metadata are persisted. Until Phase F authenticates
operators, creator is the fixed bootstrap control-plane principal rather than
caller input. There is no positive or negative decision
cache.
During pepper rotation, the primary key signs new grants while explicitly
configured previous keys are verify-only. A successful old-key verification
atomically rehashes the verifier under the primary key with an optimistic
revision check and normative audit/outbox event; a concurrent revoke/rotation
causes that new session to fail closed.

The callback has a bounded global in-flight gate, bounded global request rate,
a per-peer concurrent-pending cap, a coarse per-peer token bucket before HMAC
work and a per-camera/grant bucket after identity lookup. All maps are capacity
bounded. PostgreSQL pool/connect/statement time is independently bounded for
the auth role. Malformed,
oversized, unknown, denied and overloaded requests return the same empty 401
shape. An additive host nftables table owns only the configured node-port
range: it caps tracked connections at 128 per node and per peer/node pair, and
permits a 100/s, burst-200 SYN recovery wave per peer/node for both IP families.
The ceiling is deliberately above the 100-camera node limit so one NVR/NAT can
read every camera. The generated config pins `readTimeout: 10s`; the pinned
patch maps it to the RTSP library idle/read deadline, so an incomplete first
request cannot hold a connection beyond that bound.

After successful authentication, the accepted patched-MediaMTX admission fence
from ADR 0006 atomically admits one reader or returns exact RTSP 453. Occupancy
is not maintained in the callback or database.

MediaMTX remains the RTSP server; consumer sees only ordinary `rtsp://` and
Basic Auth. The reviewed MediaMTX patch checks exact loopback per-node internal
users for API/metrics/runtime probe before callback fallback; `authHTTPExclude`
is empty, so management is never an unauthenticated bypass.

Keep one reserved, lowest-priority canonical-path matcher so unknown canonical
IDs reach the same fail-closed auth path as existing IDs. The reconciler treats
it as platform-owned and excludes it from the 100-camera count.

Do not introduce a positive access cache until revoke/ACL/occupancy semantics
and callback availability are proven. Established sessions may continue through
control outage; new sessions fail closed.

## Consequences

Every media node depends on local control-plane authorization for new sessions
but keeps media bytes and the one-reader race outside Python. Failure remains
scoped to new admission; no automatic cross-node failover is introduced. Exact
453 semantics and non-disruptive admission are owned by ADR 0006.

## Alternatives

- **Static MediaMTX users:** rejected as primary storage because per-camera
  ACL/revoke/occupancy would require broad runtime config mutation.
- **Positive auth cache:** deferred because it weakens fail-closed revoke,
  drain and one-reader correctness.
- **Gateway/edge admission:** rejected for current direct-node topology; it
  would add a proxy boundary and obscure directly observed source IP.

## Failure domains and security boundary

| Failure | User-visible effect | Blast radius | Detection | Recovery | SLI impact |
|---|---|---|---|---|---|
| Callback/control down | New sessions fail closed; established sessions continue | all nodes using callback | callback errors/readiness | restart auth service and admission smoke | new-session availability |
| Wrong node/path binding | Access decision rejected fail closed | requested path | generation/node mismatch metric | reconcile trusted binding | denied connection |
| DB down | New sessions fail closed | all new admissions | DB/readiness | restart/PITR | new-session availability |
| Occupancy leak | Legitimate next reader receives 453 | one camera | session reconciliation | fenced slot cleanup | camera availability |

Security boundary: MediaMTX and callback communicate only over loopback with a
per-node HMAC-derived Basic identity accepted for that node UUID only; peer IP,
node id and path are accepted only from the pinned local integration. Passwords
are secret inputs and never observable output.

## Constraints

- callback request bodies and credentials are never logged;
- MediaMTX API/metrics/callback listeners stay on loopback;
- node id is derived from trusted listener/process configuration, not client
  input;
- forwarded headers are ignored;
- external RTSP reaches nodes directly or through a network preserving peer IP;
- cross-host callback and unauthenticated proxy metadata are unsupported;
- callback latency/availability is part of new-session admission;
- the configured node-port range and installed nftables interval must match;
  host rule loading/counters remain an operator-owned boundary.

## Evidence

- native amd64/arm64 payload, ACL-before-password, revoke and outage tests;
- simultaneous-reader race: exactly one PLAY, remaining clients RTSP 453;
- slot release after TEARDOWN/disconnect and no stale occupancy after crashes;
- unknown path/user/password/IP denial no-oracle parity;
- callback overload/SQL-deadline behavior, bounded incomplete-header lifetime
  and native host/L4 policy loading;
- credential redaction across application, MediaMTX, logs and traces;
- exact node/path binding prevents cross-node authorization.

## Rollout and rollback

Roll out on one isolated node with synthetic credentials, then one pilot camera,
then one node cohort. Existing nodes use the explicit `drain → reconfigure
preview → blast-radius-confirmed reconfigure/restart → resume` operation; a
generic restart is not a migration mechanism. The token binds node, port,
revision, camera count and exact placement fingerprint. Abort on no-oracle
drift, incorrect IP ordering, stale reader slots, non-453 admission or
established-stream interruption. The initial `.1 → .2` rollout has no binary
rollback target because `.1` lacks callback-compatible internal management
auth. Recovery retries `.2`; later rollback is enabled only after a compatible
previous release is catalogued and proven. It never falls back to an unaudited
allow-all/static-user mode.
