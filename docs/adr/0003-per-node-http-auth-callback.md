# ADR 0003: Loopback HTTP callback for per-node RTSP access

- Status: Proposed
- Date: 2026-08-10
- Updated: 2026-08-12
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
4. enforce drain/maintenance admission;
5. atomically admit one reader or return the contract mapped to RTSP 453.

MediaMTX remains the RTSP server; consumer sees only ordinary `rtsp://` and
Basic Auth. API/metrics callback exclusions are exact loopback management
actions, never broad path bypasses.

Keep one reserved, lowest-priority canonical-path matcher so unknown canonical
IDs reach the same fail-closed auth path as existing IDs. The reconciler treats
it as platform-owned and excludes it from the 100-camera count.

Do not introduce a positive access cache until revoke/ACL/occupancy semantics
and callback availability are proven. Established sessions may continue through
control outage; new sessions fail closed.

## Consequences

Every media node depends on local control-plane admission for new sessions but
keeps media bytes outside Python. Failure remains scoped to new admission; no
automatic cross-node failover is introduced. If pinned MediaMTX cannot preserve
exact IP ordering or RTSP 453 semantics through HTTP auth, another bounded
admission mechanism requires a new ADR.

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
| Callback/control down | New sessions fail closed; established sessions follow pinned MediaMTX behavior | all nodes using callback | callback errors/readiness | restart control and admission smoke | new-session availability |
| Wrong node/path binding | Access decision rejected fail closed | requested path | generation/node mismatch metric | reconcile trusted binding | denied connection |
| DB down | New sessions fail closed | all new admissions | DB/readiness | restart/PITR | new-session availability |
| Occupancy leak | Legitimate next reader receives 453 | one camera | session reconciliation | fenced slot cleanup | camera availability |

Security boundary: MediaMTX and callback communicate only over loopback; peer IP,
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
- incomplete-header/flood controls require a proven host/edge boundary.

## Evidence

- native amd64/arm64 payload, ACL-before-password, revoke and outage tests;
- simultaneous-reader race: exactly one PLAY, remaining clients RTSP 453;
- slot release after TEARDOWN/disconnect and no stale occupancy after crashes;
- unknown path/user/password/IP denial no-oracle parity;
- callback overload/timeout and incomplete-header/flood protection;
- credential redaction across application, MediaMTX, logs and traces;
- two real media nodes cannot authorize against the wrong node/path state.

## Rollout and rollback

Roll out on one isolated node with synthetic credentials, then one pilot camera,
then one node cohort. Abort on no-oracle drift, incorrect IP ordering, stale
reader slots, non-453 admission or established-stream interruption. Rollback
drains the node and restores the last verified config/release; it never falls
back to an unaudited allow-all/static-user mode.
