# Architecture decision records

ADRs live in this directory as `NNNN-short-title.md` and use
[`0000-template.md`](0000-template.md).

An ADR remains `Proposed` until every item in its Evidence section is linked to
an executable test or retained experiment artifact. Planning consensus alone
does not make an ADR `Accepted`.

Required early ADRs:

- media topology and scale-out;
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
| [0003](0003-single-node-http-auth-callback.md) | Proposed | Loopback HTTP callback for dynamic RTSP grants |
| [0004](0004-isolated-probe-execution-boundary.md) | Proposed | Isolated source-probe process and egress boundary |
