# Phase G probe-broker transport contract

- Date: 2026-08-30
- Status: implementation, direct-Linux amd64 contract, independent Spec/
  Standards review and native amd64/arm64 CI green
- Production decision: NO-GO

## Scope

This slice implements the local descriptor-transfer primitive between a probe
producer and the future privileged broker:

- a deterministic, 1 KiB-capped, four-byte length-prefixed JSON schema carries
  only UUIDv4 request/generation identifiers, canonical literal IP, port and an
  absolute deadline; path, query and credentials never enter the frame;
- the receiver requires a Linux AF_UNIX stream, exact `SO_PEERCRED` UID and GID,
  one absolute monotonic 10 ms to 5 s deadline shared by all frame reads, and a
  request deadline no more than 60 seconds in the future that is checked against
  the authoritative wall clock after receipt and again before handoff;
- exactly one descriptor is accepted through `SCM_RIGHTS`; ancillary truncation,
  unknown control messages, zero/multiple descriptors and partial frames fail
  closed;
- `MSG_CMSG_CLOEXEC` plus an explicit inheritable-bit reset protect the received
  descriptor, whose sealed canonical payload is parsed again and must match the
  secret-free request's literal IP and port;
- send consumes its local secret fd even on mismatch, interruption or ambiguous
  transport failure; receive owns and closes every installed fd on all rejected
  paths, preserving primary and cleanup failures; and
- the returned ownership object is context-managed, secret-free in diagnostics
  and supports one explicit detach for the next trusted boundary.

The direct Linux test on `grob` passed 33 cases covering canonical codec and
policy validation, exact peer credentials,
successful one-fd transfer, sender consumption, CLOEXEC, target/deadline/peer
rejection, oversized frames, unsealed and zero/two/three descriptors, bounded
request deadlines, one absolute sender/receiver I/O deadline,
slow-drip and expires-during-read rejection, interruption during descriptor
registration and result handoff, grouped ownership failures, and `/proc/self/fd`
leak checks. The temporary test tree was removed afterward.

[CI run 33283293698](https://github.com/zl0nline/RTSP_proxy/actions/runs/33283293698)
completed successfully at commit `ebdd15dc9e826812c40a9f65466cfbfd68f119c6`:
all seven jobs passed, and both Linux architecture jobs ran the public transport
tests as part of `1108 passed, 21 skipped` with 90.03% total coverage. This is
evidence for the transport primitive only; it is not broker/executor evidence.

## Deliberately excluded

A socket-activated root broker and executor are now implemented as an
unpromoted integrated candidate. They add filesystem ownership for the socket,
fixed-name-to-UID peer resolution, root-owned site/CIDR revalidation,
system-manager transient properties, BPF attach/readback/run gating and bounded
normalized responses. Native amd64/arm64 CI still has to prove the complete
descriptor handoff, controlled no-redirect ffprobe execution, cancellation,
restart and zero-residue transaction before promotion. ADR 0004 therefore stays
Proposed and Phase G remains IN PROGRESS / Production NO-GO.
