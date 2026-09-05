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

Independent re-review of `443320c...83f8107`: Standards PASS, Spec PASS.
The initial review's confirmation-bound mismatch was fixed, with an accepted
one-hour PostgreSQL boundary test. Prior schema 0020–0022 feature readiness is
preserved and regression-tested. Local verification: 1,618 tests passed before
the final review fixes; the updated focused suite passed 253 tests. Ruff and
mypy passed. The updated native Linux/PostgreSQL full suite passed 1,688 tests,
with 49 opt-in contracts skipped and 90.10% coverage. Native CI results must be
recorded before closing this slice.

Additional readiness audit reproduced seven false-positive readiness cases:
PostgreSQL's comma-separated privilege argument accepts any listed privilege,
not all of them. The observation/endpoint readiness queries now require each
permission independently. Regression tests revoke each required permission from
a real restricted role and require readiness rejection.

Post-fix verification: 77 local policy/store tests and 260 native Linux
policy/store/API tests passed. The readiness delta also passed both independent
reviews. CI run 33961920864 hit the ffprobe arm64 job's ten-minute infrastructure
budget after seven minutes of snapshot package installation and nearly three
minutes of compilation. The job budget was increased to twenty minutes without
changing test-level deadlines or release admission checks; this run is not a
successful CI result.

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
acceptance. The 0.15.0 candidate bundle templates admit schema 0023, with a
regression check against the application's schema head on both architectures.
The initial templates still declared 0022 after the migration was added; that
packaging error was reproduced by two failing tests and corrected before
deployment. Installation/upgrade requires the verified new immutable bundle;
the already-installed pilot 0.14.0 has not been changed by this work.

Packaging re-review also caught an unsafe schema-0022 bridge: exact-head checks
hid existing encrypted credentials/endpoints and rejected camera writes before
migration. These reads/writes and the completed-observation runtime now use a
feature-specific schema gate. A real PostgreSQL regression exercises encrypted
camera registration, admission, credential-preserving source update, credential
replacement, move restoration and reopening after 0023 migration, starting from
both 0022 and the current head. Exact-head reporting remains separate.
