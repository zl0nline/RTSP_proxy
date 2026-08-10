# ADR 0004: Isolated execution boundary for source probes

- Status: Proposed
- Date: 2026-08-10
- Decision owners: technical owner, security owner, operations owner

## Context

An ffprobe command needs a camera endpoint and credentials. Passing a URL with
userinfo directly from the control-plane process exposes credentials through
same-UID process inspection, and letting ffprobe resolve an arbitrary hostname
creates an SSRF/rebinding boundary that application error redaction cannot fix.

The first Phase 0A implementation placed such a runner in the production
package. Exit review rejected it. It has been removed; the executable lab uses
only synthetic credentials and is not a deployable dependency provider.

## Candidate decision

Production source probes run behind a dedicated execution boundary, not inside
the web, scheduler or reconciler process:

- a target-admission component resolves once, applies IPv4/IPv6 CIDR policy,
  rejects metadata/link-local/loopback/management ranges unless explicitly
  assigned to a controlled camera network, and emits an immutable target with a
  pinned literal address;
- a separate non-login Unix identity receives only the admitted target and one
  short-lived credential reference over a local authenticated IPC interface;
- source credentials never appear in the caller environment, logs, exception,
  trace fields or persistent argv visible to the control-plane UID;
- the executor starts a fresh process group with an allowlisted environment,
  bounded stdout/stderr, deadline, CPU/RSS/PID/FD limits and egress restricted
  to the pinned target; timeout kills the whole process group;
- codec output models `codec_type`; video dimensions are optional at parsing
  and required only by the relevant camera profile, while audio streams remain
  valid observations.

The exact IPC/credential-delivery mechanism is deliberately not selected until
the Linux spike compares a systemd socket-activated helper with a continuously
running worker. A transient helper that requires broad sudo or D-Bus authority
from the web process is not acceptable.

## Evidence required before Accepted

- native Linux amd64 and arm64 `/proc` tests prove source credentials are not
  visible to control-plane or unrelated service identities;
- DNS rebinding, IPv4/IPv6 special ranges, redirects and alternate-protocol
  payloads fail before execution;
- timeout and cancellation kill descendants and leave no PID/FD/cgroup leak;
- output flood, malformed JSON, video-only, audio-only and mixed streams stay
  within resource budgets and return credential-free results;
- the egress policy blocks every address except the admitted camera target.

## Consequences

Phase 0A can retain a black-box compatibility lab, but no production probe
runner is shipped until this boundary is implemented and accepted in the
health/security slices.
