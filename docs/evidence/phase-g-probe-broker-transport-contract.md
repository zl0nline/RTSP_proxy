# Phase G probe-broker transport contract

- Date: 2026-08-30
- Status: implementation and direct-Linux amd64 contract green; independent
  review and native amd64/arm64 CI pending
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

The direct Linux test on `grob` passed 19 cases covering exact peer credentials,
successful one-fd transfer, sender consumption, CLOEXEC, target/deadline/peer
rejection, zero/two/three descriptors, one absolute sender/receiver deadline,
slow-drip and expires-during-read rejection, interruption during descriptor
registration and result handoff, and `/proc/self/fd` leak checks. The temporary
test tree was removed afterward.

## Deliberately excluded

There is still no socket-activated root broker service and no probe is executed.
Filesystem ownership for the production socket, caller-name-to-UID resolution,
site/CIDR revalidation by the root boundary, system-manager transient-unit
properties, BPF attach/readback/run gating, descriptor handoff to a DynamicUser
launcher, no-redirect ffprobe, bounded output and cancellation/residue evidence
remain mandatory. ADR 0004 therefore stays Proposed, the executor stays disabled
and Phase G remains IN PROGRESS / Production NO-GO.
