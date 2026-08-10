# ADR 0002: FFmpeg and ffprobe Phase 0 candidate

- Status: Proposed
- Date: 2026-08-10
- Decision owners: technical owner, security owner, operations owner

## Context

The external-client, supervisor and deep-probe contracts require reproducible
FFmpeg and ffprobe executables on native Linux amd64 and arm64. The selected
BtbN autobuild publishes both architectures from one release, but GitHub
artifact attestation verification is unavailable for these archives.

## Decision

Use the exact candidate version, release tag, URLs and archive/executable
SHA-256 values in
[`deploy/artifact-catalog.json`](../../deploy/artifact-catalog.json) for Phase 0
testing. CI downloads each architecture independently, verifies the archive and
extracted executables, and checks their reported versions. Every immutable
release manifest also pins and verifies both executables.

This pin is not production approval. The absent upstream attestation remains a
supply-chain risk. Production admission requires one of:

- a verifiable upstream attestation for the exact artifacts;
- a reproducible, controlled internal build with retained source/build
  provenance and SBOM;
- an explicit security-owner exception with compensating controls and expiry.

Distribution and use of the GPL build must also pass the project's licensing
review before production packaging.

## Acceptance before status can become Accepted

- native amd64 and arm64 download/checksum/version CI is green;
- full external RTSP-over-TCP consumer and supervisor matrix is retained;
- ffprobe sandbox/resource-limit tests pass for source and path probes;
- build provenance, SBOM and licensing decision are attached;
- release rollback repeats the same binary and compatibility verification.

## Consequences

Phase 0 tests may use this candidate. A release cannot claim production
readiness while the provenance and licensing gates above remain unresolved.
