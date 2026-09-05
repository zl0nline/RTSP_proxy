# ADR 0004: Isolated execution boundary for source probes

- Status: Accepted
- Date: 2026-08-10
- Accepted: 2026-09-06
- Decision owners: technical owner, security owner, operations owner

## Context

An ffprobe command needs a camera endpoint and credentials. Passing a URL with
userinfo directly from the control-plane process exposes credentials through
same-UID process inspection, and letting ffprobe resolve an arbitrary hostname
creates an SSRF/rebinding boundary that application error redaction cannot fix.

The first Phase 0A implementation placed such a runner in the production
package. Exit review rejected it. It has been removed; the executable lab uses
only synthetic credentials and is not a deployable dependency provider.

## Decision

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

The unprivileged periodic worker connects to a root-owned, socket-activated
broker over authenticated AF_UNIX. It sends a bounded request envelope and one
sealed memfd containing the short-lived ffconcat input. The broker validates
the peer, target, deadline and descriptor, then owns a transient systemd unit
and its cgroup/connect guard through terminal cleanup. The web and reconciler
receive no sudo or D-Bus authority.

The address-and-port enforcement primitive is selected more narrowly after the
2026-08-29/30 amd64 spike: the root boundary attaches project-owned cgroup
`connect4` and `connect6` programs configured with one versioned map value for
exactly one literal address family, address and port. A trusted launcher remains
blocked until the map is populated, both programs are attached and read back,
and a behavioural canary passes. Missing, malformed, wrong-family and
wrong-port state denies the connect. systemd `IPAddressDeny=any` plus one
literal `IPAddressAllow=` remains defense in depth, not the exact-port control.

The throwaway mechanism proof is retained outside `main` at
[`prototype/phase-g-connect-guard`](https://github.com/zl0nline/RTSP_proxy/tree/prototype/phase-g-connect-guard/tools/prototypes/phase_g_connect_guard)
(`f984814`). On `grob`, systemd admitted two ports on each allowed loopback
address; attaching the programs before the run gate preserved the chosen port
and denied the second for IPv4 and IPv6, followed by explicit detach and zero
pin/cgroup/process residue. The parameterized ABI and native contract live in
the production tree.

## Evidence required before Accepted

- native Linux amd64 and arm64 `/proc` tests prove source credentials are not
  visible to control-plane or unrelated service identities;
- DNS rebinding, IPv4/IPv6 special ranges, redirects and alternate-protocol
  payloads fail before execution;
- timeout and cancellation kill descendants and leave no PID/FD/cgroup leak;
- output flood, malformed JSON, video-only, audio-only and mixed streams stay
  within resource budgets and return credential-free results;
- the egress policy blocks every address except the admitted camera target.

All gates passed before acceptance. The reproducible records are:

- [integrated installed broker contract](../evidence/phase-g-integrated-probe-broker-contract.md);
- [sealed transport contract](../evidence/phase-g-probe-broker-transport-contract.md);
- [cancellation and cleanup](../evidence/phase-g-probe-cancellation.md);
- [network/special-range policy](../evidence/phase-g-probe-network-policy.md);
- [systemd execution contract](../evidence/phase-g-probe-systemd-contract.md).

The worker additionally prevents concurrent copies through a PostgreSQL
session lock. The broker independently retains destination ownership through
terminal cleanup, so a caller timeout, worker restart or stale lease cannot
open a second probe to the same camera endpoint while the first remains alive.

## Consequences

Production active probes are permitted only through this boundary and only for
an explicit camera monitoring profile whose confirmed upstream capacity is
greater than one. Single-session and unconfigured cameras remain passive-only.
An unavailable broker, ownership lock or durable projection makes monitoring
inconclusive/unready; it never marks a camera failed and never affects its
existing media stream.
