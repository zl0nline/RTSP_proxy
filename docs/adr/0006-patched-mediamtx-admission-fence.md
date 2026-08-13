# ADR 0006: Patched MediaMTX admission fence

- Status: Accepted
- Date: 2026-08-12
- Decision owners: technical owner, security owner, operations owner
- Related issues: #1, #8, #9, #10, #11, #14

## Context

Each camera allows one downstream reader. Camera source changes, disable,
delete and move must first reject late readers without disconnecting the one
established reader. A rejected late RTSP SETUP must receive exact status 453.

Stock MediaMTX v1.20.0 returns 400 when `maxReaders` rejects SETUP and recreates
the path when that field changes. Recreating the path disconnects the existing
reader before occupancy can be checked, so it cannot implement the required
fence.

## Decision

Build `v1.20.0-rtsp-proxy.3` directly on Linux from upstream commit
`1b943637a4b5778bb929a7af7687b048fecaa03f` and
`patches/mediamtx-v1.20.0/0001-hot-reader-limit-and-rtsp-453.patch`, with
the pinned gortsplib v5.6.3 RECORD-state race fix and deterministic regression
in `patches/gortsplib-v5.6.3/`.

The patch:

- hot-updates only `maxReaders` without recreating the path;
- acknowledges configuration reload only after every affected path actor
  applies it; reload fan-out stays asynchronous to the path-manager actor so
  source-ready/offline callbacks cannot form an actor-cycle deadlock;
- preserves the established reader while `maxReaders` changes from `1` to
  `-1` and back;
- maps reader-limit rejection to RTSP `453 Not Enough Bandwidth`.
- checks node-internal API/metrics users before the external callback, so the
  loopback management plane remains credentialed and node-scoped.
- serializes gortsplib's successful RECORD transition with its public state
  readers, preventing concurrent metrics collection from racing RTSP publish.

The artifact catalog binds upstream commit, patch SHA-256, Go version, patched
version strings, all patch SHA-256 values, and the resulting amd64/arm64 binary
SHA-256 values. The regression must fail before and pass after the dependency
patch; the MediaMTX race suites then run before compilation.
Release verification rejects stock or otherwise different binaries.

## Consequences

The project owns a small upstream delta and must rebase and review it for every
MediaMTX upgrade. Native CI must prove on both architectures that RTP continues
for the established reader, a late reader receives exact 453, and a later
reader is admitted after reopening. Failure of any proof blocks release.

## Alternatives

- Stock `maxReaders`: rejected because its hot mutation is disruptive and its
  RTSP response is not 453.
- HTTP auth callback occupancy: deferred; its rejection maps to authentication
  responses rather than exact 453 and would make DB/control availability part
  of the one-reader race.
- Additional RTSP gateway: rejected because it changes the direct ordinary
  `rtsp://` node boundary and introduces another media hop.

## Rollout and rollback

Only catalog-verified binaries may be activated. Release `0.2.1` is the current
race-safe identity; callback-compatible `0.2.0` is its rollback target. The
packaged trust catalog is
versioned by deployment release ID and architecture. During an N→N+1 rollout it
contains both the current N+1 identity and the previous N identity with their
distinct binary digests; the helper validates each release ID against its own
entry. Release `0.2.0` catalogues the prior patched `0.1.0` identity and its
distinct architecture-specific digests as historical provenance only. Since
`.1` predates internal-user-before-callback behavior, it is not an activation
or rollback target for Phase E. Rollout uses the blast-radius-confirmed
non-empty `.1 → .2` reconfigure path. Race-safe `0.2.1` keeps callback-compatible
`0.2.0` as its verified previous target; stock v1.20.0 is never a fallback.
