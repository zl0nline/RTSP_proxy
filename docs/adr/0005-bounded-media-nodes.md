# ADR 0005: Bounded MediaMTX nodes on one Linux server

- Status: Accepted
- Date: 2026-08-12
- Decision owner: project owner
- Related issues: #1, #2, #5, #10, #11, #12, #14

## Context

The previous plan tried to discover whether one MediaMTX could carry a 10k
workload and conditionally introduced a gateway/origin tier. That made the
topology, routing contract, failure radius and capacity target depend on one
large experiment. It also delayed product implementation while the load harness
was hardened for a scale the initial deployment does not need per process.

The owner chose an explicit operational partition: bounded independent media
nodes on one physical Linux server.

## Decision

- One media node is one MediaMTX process, systemd instance, config/state/log
  identity and one external RTSP port.
- A node contains at most 100 registered cameras.
- Camera placement is explicit in PostgreSQL; automatic placement chooses the
  least registered eligible node, then least active, then stable node id.
- `max_nodes` defaults to 50 and is configurable up to 100.
- External ports come from a configured range and are allocated randomly by
  default; manual selection is supported.
- A camera endpoint contains its node port. Move/port change can change the URL
  and may be disruptive.
- Node restart/port change affects all streams on that node and no other node.
- There is no automatic failover or migration after node failure.
- Dashboard/control plane manages and aggregates every node on the server.
- MediaMTX management API and metrics remain loopback-only.
- Every node has a unique random management credential and systemd
  `DynamicUser`; its process receives only its own config and cannot traverse
  another node's root-owned config/credential directory.
- Shared runtime, state and log parents allow traversal only (`0751`) so the
  isolated DynamicUser can enter its own `0750` per-node directory; this does
  not grant directory listing or sibling-content access.
- The root-owned lifecycle helper retains only `CAP_SYS_PTRACE` so Linux permits
  it to verify `/proc/<pid>/exe` for a DynamicUser-owned MediaMTX process before
  accepting that process identity.
- Multi-server topology, gateway tier and one unified external port are not part
  of this product version.

## Rationale

The 100-camera boundary is a product admission invariant, not an estimate of
MediaMTX's ultimate limit. It provides a fixed reconciliation inventory, bounded
process blast radius and straightforward lifecycle isolation. Adding nodes
scales the server workload without introducing path-aware network routing.

The number of nodes a server can sustain remains empirical. Default 50 limits
control-plane state; it does not promise that 5,000 cameras are active on every
server. Optional 100 nodes requires a wider port range and measured capacity.

## Consequences

Positive:

- camera CRUD and node lifecycle have explicit bounded blast radii;
- no custom RTSP gateway/router is needed;
- per-node config/reconcile/startup stays bounded at 100 paths;
- failures and metrics are attributable to one process/node;
- direct Linux systemd naturally represents the runtime model.

Costs:

- consumers need node-specific ports;
- moving a camera may require distributing a new URL;
- more processes/listeners/configs/log streams must be managed;
- a physical server remains a shared failure/resource domain;
- no transparent availability after node/server failure.

## Alternatives rejected

### One unbounded MediaMTX process

Rejected as the product topology because it creates a large failure domain and
makes every release depend on a high single-process capacity target. It remains
useful only as historical performance evidence.

### Replicated gateway to origin shards

Rejected for this version because it adds a second media hop, duplicate pulls,
gateway auth/ownership and a new failure domain solely to preserve one port.

### Custom RTSP-aware router

Rejected because it places complex RTSP parsing/routing in a component the
product otherwise does not need.

### Automatic failover/migration

Rejected for now. Camera session limits, endpoint changes and split-brain
placement make silent migration unsafe. Operations receives failure/recovery
notifications and decides manually.

## Failure domains and security boundary

| Failure | User-visible effect | Blast radius | Detection | Recovery | SLI impact |
|---|---|---|---|---|---|
| One media node | Its cameras/sessions unavailable | at most 100 registered cameras | remote RTSP + node health | notify and manually restart | node-scoped media availability |
| Control plane/DB | New admission/management fail closed; established media may continue | server management/new sessions | readiness/callback errors | restart or PITR | control/new-session availability |
| Physical server | All nodes unavailable | full server | external host probes | manual host recovery | full media outage |
| Port allocation conflict | Node cannot start | new/changed node | bind/preflight | rollback/reserve another port | operation failure |

External node RTSP ports are the media security boundary. Management API,
metrics and auth callback stay on loopback; dashboard is separately protected
on management HTTPS. One node process/config identity must not read or mutate
another node's writable state.

## Evidence

Acceptance records the architecture decision, not production capacity.
Implementation must prove:

- concurrent admission never exceeds 100 cameras/node;
- port/max_nodes allocation is race-safe;
- create/restart/delete node A does not affect node B;
- camera CRUD does not interrupt unrelated paths;
- per-node 100-camera and per-server node ladders meet SLO/headroom;
- native Linux amd64/arm64 deployment and ordinary RTSP/TCP contracts;
- drain/move/port-change and failure/recovery notification semantics.

## Rollout and rollback

Changing the 100-camera invariant, introducing a unified port, multi-server
placement or automatic failover requires a superseding ADR plus updated issues,
plan, docs, migrations and compatibility tests. Existing node/port placements
must remain readable during any future migration.

Rollout starts with one node and advances through the waves in #13. Abort on
cross-node interruption, capacity/resource gate, port/placement inconsistency or
failed rollback. Rollback stops only the affected new node/config generation and
restores its previous verified placement/port state; it does not rewrite other
nodes.
