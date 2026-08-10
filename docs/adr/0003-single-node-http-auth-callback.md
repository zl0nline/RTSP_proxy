# ADR 0003: Loopback HTTP callback for single-node RTSP grants

- Status: Proposed
- Date: 2026-08-10
- Decision owners: technical owner, security owner, operations owner

## Context

External consumers must use ordinary RTSP Basic Auth while camera credentials
remain private. Grant revocation must affect new sessions quickly without
disconnecting established sessions. MediaMTX v1.20.0 supports internal users,
an HTTP callback and JWT; the Phase 0 fork compares internal and HTTP behavior.

## Candidate decision

Use `authMethod: http` for the single-node baseline, with the callback bound to
loopback. Exclude only loopback management API and metrics actions. Every
external `read` decision is evaluated by the callback using user, password,
action, canonical path, protocol and client IP. MediaMTX remains the RTSP server;
the client sees only a standard `rtsp://` URL and Basic Auth challenge.

Keep one reserved, lowest-priority `~^[a-z0-9]{25}$` path configuration. Exact
camera configurations take precedence; the reserved matcher exists only so a
nonexistent canonical public ID reaches the same fail-closed auth callback as
an existing ID. Without it, v1.20.0 returns `400` for an unknown path but `401`
for bad credentials and exposes a path-existence oracle. The executable
contract requires byte-identical `401` response headers for wrong password,
unknown user and unknown canonical path. The reconciler must classify this
matcher as platform-owned and never delete or include it in camera counts.

Do not introduce an application-side positive grant cache initially. The
executable v1.20.0 contract shows that a revoked grant blocks a new session
within the candidate 10-second budget, callback outage fails new sessions
closed, and an established FFmpeg reader continues through revoke/outage.

Internal static users are retained only for the controlled comparison and
emergency procedure; using them as the primary grant store would require global
runtime config mutation and would weaken per-grant revoke semantics.

## Constraints

- callback request bodies contain credentials and must never be logged;
- loopback HTTP is allowed only while callback and MediaMTX share a host;
- the single-node candidate accepts external RTSP only by direct trusted/private
  L3 delivery. An L4 proxy, NAT boundary that hides the client, or cross-host
  callback is a deployment NO-GO until a separate accepted source-IP and
  authenticated-encryption design passes native network tests;
- an outer WireGuard/IPsec/private-L3 transport may terminate on the same host
  only when the inner client IP reaches MediaMTX unchanged; the client still
  uses ordinary `rtsp://` and no TLS-aware RTSP configuration;
- API/metrics listeners and callback stay off the external RTSP interface;
- callback latency and availability are part of new-session admission, not
  established media-session availability.
- MediaMTX v1.20.0 `readTimeout` bounds the external HTTP auth request but does
  not bound an incomplete initial RTSP header: a native contract keeps a
  partial header open past the configured one-second timeout. Production
  admission therefore still requires an accepted edge/host control for
  handshake deadline, connection caps and rate limiting. Direct exposure before
  that control is a NO-GO.

## Evidence required before Accepted

- native amd64 and arm64 callback payload, revoke-new, outage and established
  session tests pass on the pinned artifacts;
- unknown, revoked and existing path responses pass no-oracle parity tests;
- callback overload/timeout budgets and rate limits pass the security spike;
- incomplete-header, connection-flood and brute-force controls pass without
  interrupting established readers;
- credential redaction covers application logs, MediaMTX logs, traces and
  internal probe/supervisor failures;
- security and operations owners approve the cross-host rule and emergency
  static-user procedure.

## Consequences

Phase 1 can implement the callback interface and grant verifier for the
single-node topology. Scale-out cannot reuse loopback assumptions; it remains
blocked on topology and network-boundary evidence.
