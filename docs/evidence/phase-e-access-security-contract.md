# Phase E access and security contract

- Last reviewed: 2026-08-13
- Status: complete; independent review and native amd64/arm64 CI green
- CI: https://github.com/zl0nline/RTSP_proxy/actions/runs/31689056322
- Commit: `0ffdffbfd7030ed1a8bf85a1a921af0033ddc61a`
- Architectures: Linux amd64 and arm64, identical contract
- Deployment: direct Linux/systemd, no Docker

Phase E protects each ordinary `rtsp://server:node_port/public_id` downstream
session without changing RTSP transport semantics. MediaMTX remains the RTP
proxy and forces interleaved TCP; the Python control/auth services never relay
media. The product admits at most one downstream reader per camera. A
simultaneous second reader receives exact RTSP `453 Not Enough Bandwidth`, while
the established reader continues receiving RTP.

Each camera has independent `internet` and `local` normalized CIDR sets. Empty
sets allow all peers. When a set is active, the callback checks the directly
observed TCP peer address before reading or verifying a grant. Forwarded
headers are not trusted. Downstream grants explicitly choose `temporary` or
`service` and an expiry. The URL-safe secret is returned once; PostgreSQL stores
only a versioned-pepper HMAC verifier and bounded metadata. Revoke and ACL/drain
changes affect the next session and do not disrupt an already established
stream.

Media nodes call a dedicated loopback auth service with a per-node HMAC Basic
identity. The path node UUID and canonical public ID are bound before request
body parsing. Duplicate or invalid metadata, oversized/slow/disconnected body,
callback overload, unknown path, wrong peer/grant, database outage and auth
outage all fail closed with the same external denial shape. Admission is
bounded globally and per peer/camera/grant; safe internal counters use only a
fixed reason/action/protocol/IP-family vocabulary.

Loopback MediaMTX API, metrics and runtime probe stay on exact per-node internal
credentials and never fall through to the downstream callback. The repository
patch is built from pinned MediaMTX v1.20.0 source for both architectures; its
catalog and release manifests bind the patch and binary SHA-256. The historical
`.1` build is retained only as provenance and is not an auth-compatible rollback
target. Existing `.1` nodes use the confirmation-fenced drain/reconfigure/resume
workflow to activate `.2` without changing their external port or camera paths.

The host boundary is an additive, marker-owned nftables table limited to the
configured node-port interval. Reconciliation refuses foreign ownership,
serializes mutation, validates native kernel JSON, retries one ambiguous apply
and removes only marker-owned state before failing if the second apply remains
ambiguous. Connection and SYN controls cover IPv4 and IPv6; policy failure
prevents media-node startup.

CI run `31689056322` completed successfully at the exact commit above. Its six
jobs were:

- `test (amd64)` and `test (arm64)`: full tests with coverage, Ruff, mypy,
  package/SBOM/audit, clean-wheel install, native PostgreSQL migrations,
  systemd verification and real nftables install/read-back;
- `media-binaries-contract (amd64)` and `(arm64)`: pinned patched MediaMTX and
  FFmpeg/ffprobe release verification plus real H.264/H.265 callback,
  ACL/revoke/drain, management isolation and single-reader behavior;
- `pull-load-generator-contract (amd64)` and `(arm64)`: pinned runtime
  manifest, netem, RTSP/TCP pull endpoints and two-node systemd/RTP isolation.

Independent Spec and Standards review found no remaining High or Medium issue
in the final remediation. Local evidence at the published commit was 578 tests
passed with 18 expected native-only skips, 90% coverage, Ruff/mypy/build and
diff-check green.

This evidence is deliberately bounded. It proves functional Phase E behavior
on both supported architectures; it does not claim dashboard/operator HTTPS,
RBAC/CSRF, SMTP incidents, physical-server capacity, 24-hour soak or production
readiness. Those remain Phase F/G gates and Production stays NO-GO.
