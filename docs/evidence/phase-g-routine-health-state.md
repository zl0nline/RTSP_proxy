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

Independent final re-review of `443320c...f783dd8`: Standards PASS, Spec PASS.
The initial review's confirmation-bound mismatch was fixed, with an accepted
one-hour PostgreSQL boundary test. Prior schema 0020–0022 feature readiness is
preserved and regression-tested. Final verification of `f783dd8`:

- local full suite: 1,634 passed, 113 platform/opt-in skips;
- native Linux/PostgreSQL full suite: 1,698 passed, 49 opt-in skips;
- release/deployment regression suite: 74 passed;
- Ruff, mypy (80 source files), sdist/wheel build passed;
- locked dependency audit reported no known vulnerabilities;
- installed-binary media contracts and the limited real-camera smoke are
  recorded [separately](phase-g-live-camera-media-smoke.md).

All nine native CI jobs passed for `f783dd8` in
[run 33963164548](https://github.com/zl0nline/RTSP_proxy/actions/runs/33963164548),
including both architecture release bundles, installed root-broker contracts,
media/load contracts and the browser gate. The amd64 application job passed
1,698 tests with 49 expected opt-in skips and 90.11% coverage. This verifies this
slice, not the deferred worker or production capacity.

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
The owner has selected passive-only monitoring for single-session cameras,
including idle cameras: no separate SOURCE/PATH probe and no reader delay.
The [admission policy](phase-g-passive-only-policy.md) now enforces this rule.
The final worker must still bind authoritative profiles and passive observations;
an idle snapshot alone must never be treated as a reservation.
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
