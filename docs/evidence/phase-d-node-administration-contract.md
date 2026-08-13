# Phase D node administration contract

- Last reviewed: 2026-08-13
- Status: complete; native amd64/arm64 CI green
- CI: https://github.com/zl0nline/RTSP_proxy/actions/runs/31658505374
- Architectures: Linux amd64 and arm64, identical contract

Phase D implements bounded camera reconciliation and administration for the
one-MediaMTX-process-per-node topology. A node has one external ordinary
`rtsp://` TCP port and at most 100 registered cameras. No Docker or automatic
failover is involved.

The move saga holds source and target writer guards in stable UUID order. The
prepared target rejects readers. The source then rejects new readers and its
current reader count is checked again. Ordinary moves proceed only at zero;
forced moves require a short-lived HMAC confirmation bound to camera, source,
target, desired revision and the exact current count. Placement switches before
source removal, but the target remains closed until source deletion is verified.
Only then is the target opened and applied state committed. A five-minute
deadline converts an incomplete pre-switch move to target cleanup, restores the
source path, and records an abort reason.

The fence was first provided by repository-owned MediaMTX build
`v1.20.0-rtsp-proxy.1`: exact upstream commit plus a SHA-256-bound patch. Phase E
extends the same patch chain as `.2` to protect node management credentials. Its
configuration acknowledgement waits until the running path has applied the new
`maxReaders`; changing only this field does not recreate the path. The native
amd64/arm64 contract keeps one reader receiving RTP through `1 → -1`, checks
that a late reader receives exact RTSP 453, then restores `-1 → 1` and admits a
later reader.

Changing a camera source, disabling it, or deleting it uses an equivalent
node-guarded admission fence. A newly attached reader therefore cannot be
silently disconnected after an earlier zero-reader preview. Oversized or
otherwise invalid source URLs are rejected before persistence and by the
database constraint. Migration fails closed on legacy invalid URLs or a
nonterminal legacy move whose target admission state cannot be proven.

Root-helper media requests carry absolute deadlines. Lock waits and MediaMTX
calls share that budget, so a client timeout cannot leave an unbounded stale
PUT/DELETE queued behind a node operation. Reconciler shutdown checks a
cooperative cancellation flag between external mutations and while waiting for
each PostgreSQL node advisory lock; it closes PostgreSQL only after its worker
exits. The move expiry is rechecked from the database clock inside the same
transaction that switches placement, so an operation crossing its deadline
enters target cleanup and restores the source instead of committing late.

Migration `0009` refuses a non-empty legacy node registry. Phase-C nodes do not
carry proof of the patched hot-reader-limit behavior, so the supported transition
is an offline export/drain/delete/backup/migrate/restore procedure. The private
manifest is canonical JSON, mode 0600 and checksum-bound; transactional,
idempotent restore preserves exact camera UUID/`public_id`/ports, validates
permanent tombstones, enforces the current max-node/port/listener policy before
writing, forces synchronous desired/audit/outbox durability and continues each
node's normative revision. An operator-supplied legacy digest is never promoted
to trusted identity. Stable desired lifecycle/admin state is restored exactly;
transitional state blocks export and STOPPED/MAINTENANCE/FAILED is never
promoted to RUNNING. The versioned catalog carries current `0.2.0` and
historical patched `0.1.0` identities and never admits stock v1.20.0. Phase E
does not advertise `.1` as rollback because it lacks callback-compatible
management auth. Every later N→N+1 rollout must package and prove a compatible
previous identity before enabling its rollback pin.

Local evidence: full unit/contract suite passes with native-only contracts
skipped when Linux artifacts are unavailable. The published native Phase D
systemd test passes on both amd64 and arm64 and performs targeted CRUD, a
cross-node move, port change and empty-node delete while a reader on the
unaffected node demonstrates continuing RTP progress. Production admission
still waits for Phase E/G security and capacity evidence.
