# Phase G: authoritative camera profiles and periodic probe worker

Date: 2026-09-06. Candidate release: `0.16.0`. Application schema:
`0024_camera_probe_profiles` with a rolling bridge from
`0023_probe_health_states`.

## Implemented boundary

- An absent camera profile is revision zero, disabled and
  `max_source_sessions=1`; it cannot create active work.
- Authenticated Dashboard and JSON API profile changes require control mutation
  permission, strict optimistic revision, CSRF on the browser path and a
  normative audit/outbox event. The profile contains no endpoint or credential.
- A profile change rotates the admitted endpoint generation. Results already in
  flight under the old capacity/media requirements cannot enter the current
  observation or health projection, while the media path is not restarted.
- The unprivileged `probe` role holds one PostgreSQL session advisory lock,
  validates the exact profile/observation/health schemas and privileges, reads a
  bounded batch of enabled profiles and repeats authoritative camera, node,
  endpoint and runtime admission immediately before scheduling.
- Only enabled profiles with confirmed upstream capacity greater than one can
  submit a SOURCE probe. Single-session and unconfigured cameras remain
  passive-only even when idle. Required decoded video/audio types are applied
  before persistence.
- Execution goes only through the accepted root AF_UNIX broker. Concurrency is
  bounded globally, per node and per site. Attempt time is durable and fenced by
  profile revision; health transitions remain generation-bound.
- Final broker launch holds a camera/profile/endpoint database permit, so a
  concurrent capacity downgrade cannot commit until that bounded execution is
  gone; a change before permit acquisition cancels the scheduler lease without
  opening a connection. Loss of singleton ownership makes readiness fail and
  requests normal process termination; the systemd role uses `Restart=always`.
  Ordinary executor or infrastructure failures remain `INCONCLUSIVE` and never
  change media service.

The systemd installer ships the probe env example and three optional
`camera-source.env` drop-ins. Optional loading preserves the schema-0023 upgrade
bridge; the configuration tool then replaces one shared CIDR/key-path file
atomically for WEB, reconciler, probe worker and broker and explicitly requires
restarting an already-active broker.

## Reproducible verification

On macOS arm64 with native PostgreSQL:

```text
uv run ruff check .                         -> passed
uv run mypy src                             -> 83 source files, passed
uv run pytest -q --tb=short -rN             -> 1687 passed, 182 skipped
```

On the isolated `grob` Linux amd64 scratch tree, without modifying the installed
pilot:

```text
full application suite                       -> 1595 passed, 274 skipped
deployment/bootstrap/worker/install tests  -> 50 passed, 2 opt-in skips
systemd-analyze verify                      -> no candidate-unit errors
```

The PostgreSQL tests include singleton lock release/reacquisition, rejection of
a deliberately weakened profile constraint, passive default, optimistic-update
conflict, audit/outbox emission and old-generation result rejection. The worker
contract executes one complete admitted schedule/broker/result/persistence
cycle with bounded fakes. Dashboard coverage proves the explicit passive warning,
profile attribution and no-store API projection.

## Remaining production gates

This closes the software worker/profile/ADR gate, not Phase G as a whole.
Per-node 100-camera capacity, the multi-node ladder, physical-camera reader-race
and fault campaigns, restore game day and 24-hour soak remain open. Production
status therefore remains **NO-GO**.
