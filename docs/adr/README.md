# Architecture decision records

ADRs live in this directory as `NNNN-short-title.md` and use
[`0000-template.md`](0000-template.md).

An ADR is `Accepted` when its decision owner commits to the architecture.
Acceptance does not turn unexecuted capacity/security claims into evidence:
those remain explicit validation gates in the ADR and production plan.

Required early ADRs:

- bounded media topology and server capacity;
- queue/outbox semantics;
- browser session storage;
- authorization model;
- merge/conflict semantics;
- RTSP transport invariant;
- Linux release/rollback layout.

Current records:

| ADR | Status | Subject |
|---|---|---|
| [0001](0001-mediamtx-v1.20.0-phase-0-candidate.md) | Proposed | MediaMTX v1.20.0 Phase 0 candidate |
| [0002](0002-ffmpeg-phase-0-candidate.md) | Proposed | FFmpeg/ffprobe Phase 0 candidate and provenance gate |
| [0003](0003-per-node-http-auth-callback.md) | Proposed | Per-node loopback HTTP callback for RTSP access |
| [0004](0004-isolated-probe-execution-boundary.md) | Proposed | Isolated source-probe process and egress boundary |
| [0005](0005-bounded-media-nodes.md) | Accepted | Up to 100 cameras per MediaMTX node on one Linux server |
| [0006](0006-patched-mediamtx-admission-fence.md) | Accepted | Non-disruptive reader fence and exact RTSP 453 |
| [0007](0007-operator-identity-sessions-and-rbac.md) | Accepted | OIDC/break-glass identities, revocable sessions and scoped RBAC |
