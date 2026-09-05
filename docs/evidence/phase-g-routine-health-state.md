# Phase G: routine policy and durable health projection

Status: implementation candidate. The production `probe` role is still disabled;
this slice is not a deployable periodic worker.

## Implemented contract

- `CameraProbeProfile` distinguishes configured upstream session capacity and
  required decoded media from observations. Defaults are disabled, one source
  session, required video, five-minute routine interval, 30-second confirmation
  interval, 15-second execution timeout. These are conservative initial settings,
  not capacity-calibrated recommendations. Profile persistence/management is not
  yet wired. Confirmation spacing is bounded to one hour and cannot exceed the
  routine interval, matching the durable health writer's accepted range.
- Media requirements apply only to a decoded `HEALTHY` result. Missing required
  audio/video becomes `UNHEALTHY/CODEC`; `INCONCLUSIVE` is never reclassified as a
  camera fault. This does not add new codecs to the controlled ffprobe build.
- A bounded producer feeds only due SOURCE work to the existing scheduler.
  SUSPECT and RECOVERING use confirmation priority; confirmed UNHEALTHY uses
  routine cadence to avoid permanent fast retries. Failed/stopped/non-running
  nodes suppress automatic probes. Existing eligibility and single-flight rules
  still apply; a full queue stops the batch without unbounded buffering.
- Due times use the persisted last attempt (including inconclusive attempts),
  or registration time for the first attempt. Stable positive per-camera jitter
  of less than 20% does not shorten confirmation spacing or depend on process
  startup time. The caller must supply current generation-checked snapshots.
- Additive schema `0023_probe_health_states` stores independent SOURCE/PATH
  state, confirmation counters and timestamps. It contains no source URL or
  credential material. Generation changes reset the projection to UNKNOWN;
  PATH additionally binds the node runtime generation. The generation fingerprint
  uses versioned canonical JSON of primitive identity fields, shared with in-memory
  generation comparisons rather than Python object representations.
- `record_if_current(..., confirmation_spacing=...)` writes the latest accepted
  observation and health transition in the same PostgreSQL transaction. Replays
  do not count twice; rejected old-generation observations do not update health;
  infrastructure results leave health unchanged. Health write failure rolls back
  the observation as well. Closing and reopening the store retains state.
- `assert_health_ready()` validates exact column/constraint definitions and all
  required read/write privileges before a future worker may be enabled.

## Tests

```sh
uv run pytest -q tests/test_probe_routine.py tests/test_probes.py
uv run ruff check src tests
uv run mypy src
```

Tests cover configuration bounds, media requirements, stable jitter, confirmation
priority, occupied single-session suppression, bounded queue/single-flight,
durable failure confirmation, replay, inconclusive outcomes, generation reset,
transaction rollback and weakened-constraint rejection on real PostgreSQL.

## Remaining integration work

This slice must not be described as completing automatic health monitoring.
Still required: authoritative profile management and snapshot producer, singleton
worker ownership, execution/result persistence loop, fresh admission at dispatch,
shutdown wiring, dashboard health projection and manual-trigger workflow.
The final worker must resolve the race between an idle single-session SOURCE
probe and a new downstream reader; an idle snapshot alone is not a reservation.
Profile changes must also invalidate incompatible health interpretations.
Do not enable active probes merely because this policy module exists.

Broker promotion still depends on remaining network-policy contracts and ADR
acceptance. Installation/upgrade needs a new immutable release supporting schema
0023; the already-installed pilot 0.14.0 has not been changed by this work.
