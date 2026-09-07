# Pilot issues #25–#29 audit

Date: 2026-09-07  
Code baseline: [`4ee4f3e`](https://github.com/zl0nline/RTSP_proxy/commit/4ee4f3e269ee9770889b6dc321fb3a1267897c4c) (`main`)  
Rollout baseline: installed candidate `0.16.0`, schema
`0022_camera_source_credentials`, verified pre-migration backup; migration to
`0024_camera_probe_profiles` has not run.

## Verdict

Pilot expansion and schema migration should remain **HOLD**. The five newest
issues are real operator findings, but some proposed diagnoses/remedies are too
broad. Immediate order is:

1. contain the credential exposure in #25;
2. freeze automatic placement and fix #28 before adding cameras;
3. use a second MFA-enabled local administrator to unblock an authenticated
   playback test (#27), without weakening MFA or writing a grant directly;
4. reproduce #25 against the exact same camera endpoint/path and correct the
   stored credential using its raw value;
5. design the demand-aware ingest signal for #26;
6. implement #29 after the operational blockers.

The issues have no comments or assignees/milestones at audit time. The only
GitHub timeline relation is #29 cross-referencing #28.

| Issue | Severity | Reproducibility | Decision |
|---|---|---|---|
| [#25](https://github.com/zl0nline/RTSP_proxy/issues/25) credential encoding | **P0 containment / P1 functional** | Encoding behavior deterministic; camera proof incomplete | Rotate exposed credential first; preserve raw-field contract |
| [#28](https://github.com/zl0nline/RTSP_proxy/issues/28) automatic-node churn | **P0 pilot blocker** | Strong, code and pilot DB evidence agree | Freeze auto placement; refresh/persist before provisioning |
| [#27](https://github.com/zl0nline/RTSP_proxy/issues/27) MFA dead end | **P1 pilot blocker** | Deterministic for a local account provisioned without TOTP | Provision a second MFA account; add supported enrollment later |
| [#26](https://github.com/zl0nline/RTSP_proxy/issues/26) invisible ingest failure | **P1 observability/release blocker** | Failure is real; `ready=false` alone is not proof | Add separate demand-aware ingest state; keep node health separate |
| [#29](https://github.com/zl0nline/RTSP_proxy/issues/29) navigation | **P3 usability** | Mostly confirmed; one requested item already exists | Implement after blockers; narrow acceptance criteria |

## Immediate security containment: #25

The public issue body contains a literal source credential and internal camera
endpoints. They are deliberately not reproduced here. Treat that credential as
compromised: rotate it at the camera, remove it from the public body and review
whether it was reused. Sanitizing the issue does not substitute for rotation.

The functional mechanism is confirmed. Separate credential fields are treated
as decoded/raw strings and `attach_source_credentials()` percent-encodes them
exactly once ([implementation](https://github.com/zl0nline/RTSP_proxy/blob/4ee4f3e269ee9770889b6dc321fb3a1267897c4c/src/rtsp_proxy/camera_secrets.py#L170-L185),
[existing special-character test](https://github.com/zl0nline/RTSP_proxy/blob/4ee4f3e269ee9770889b6dc321fb3a1267897c4c/tests/test_camera_secrets.py#L77-L81)).
Supplying an already encoded value therefore encodes `%` again. This is not a
safe reason to automatically `unquote`: a literal password containing `%24`
is valid and indistinguishable from a pre-encoded dollar sign.

The correct contract is: `source_username` and `source_password` accept **raw
credentials**, while only the URL assembler encodes them. Add explicit UI/API
wording, a warning/confirmation for percent-escape-looking input, and an
end-to-end regression covering raw `$`, `%`, `@` and `:`. Do not silently
normalize.

The issue's successful direct `ffprobe` targets a different IP and path from
the runtime MediaMTX record. It proves that some credential/stream combination
works, not that the failing tuple is solely an encoding fault. Reproduce after
rotation against the exact same authorized endpoint/path, without putting the
secret in argv, logs, issue comments or this repository.

## #28: automatic placement consumes one node per camera

This is the highest-confidence code defect. PostgreSQL placement requires a
healthy observation newer than 30 seconds
([query](https://github.com/zl0nline/RTSP_proxy/blob/4ee4f3e269ee9770889b6dc321fb3a1267897c4c/src/rtsp_proxy/database.py#L2137-L2187)).
On a miss, `CameraControl` invokes automatic capacity provisioning and retries
([fallback](https://github.com/zl0nline/RTSP_proxy/blob/4ee4f3e269ee9770889b6dc321fb3a1267897c4c/src/rtsp_proxy/nodes.py#L3518-L3565));
`ensure_automatic_capacity()` creates another identically named
`automatic-node` when it sees no eligible/retryable node
([provisioning path](https://github.com/zl0nline/RTSP_proxy/blob/4ee4f3e269ee9770889b6dc321fb3a1267897c4c/src/rtsp_proxy/nodes.py#L2424-L2469)).

There is a subtle split-brain of observations. `FleetCollector` does call the
runtime observer every collection cycle, but `ReadOnlyRuntimeObserver` only
returns an in-memory `replace()` projection; it does not persist
`management_observed_at`
([collector adapter](https://github.com/zl0nline/RTSP_proxy/blob/4ee4f3e269ee9770889b6dc321fb3a1267897c4c/src/rtsp_proxy/runtime.py#L990-L1008)).
That is consistent with the collector's read-only SQL boundary. Thus the
dashboard may show current healthy snapshots while the placement table is stale.

Immediate mitigation: stop automatic camera creation. If an urgent placement
is necessary, explicitly observe the intended node and create with `node_id`
within the freshness window; do not delete nodes that already own cameras.

Fix the write-capable placement/orchestration boundary, not the read-only
collector: under the provisioning lock, observe and persist all plausible
under-capacity candidates, retry selection, and create a node only after a
complete fresh result proves that no capacity exists. An observation failure
must return a typed degraded-observability error, not consume another port/node.
Add a provisioning cooldown, unique human-readable auto-node names and tests
where all stored observations are older than 30 seconds. This preserves the
authoritative placement rule in [#10](https://github.com/zl0nline/RTSP_proxy/issues/10).

## #27: MFA bootstrap dead end

Grant issue/rotation/revoke intentionally require recent MFA
([dashboard boundary](https://github.com/zl0nline/RTSP_proxy/blob/4ee4f3e269ee9770889b6dc321fb3a1267897c4c/src/rtsp_proxy/camera_dashboard.py#L494-L507),
[API boundary](https://github.com/zl0nline/RTSP_proxy/blob/4ee4f3e269ee9770889b6dc321fb3a1267897c4c/src/rtsp_proxy/app.py#L2879-L2903)).
The bootstrap CLI can create TOTP only during initial provisioning, while its
rotation mode changes only the password
([CLI](https://github.com/zl0nline/RTSP_proxy/blob/4ee4f3e269ee9770889b6dc321fb3a1267897c4c/src/rtsp_proxy/local_operator_cli.py#L39-L98),
[rotation](https://github.com/zl0nline/RTSP_proxy/blob/4ee4f3e269ee9770889b6dc321fb3a1267897c4c/src/rtsp_proxy/local_operator_cli.py#L162-L201)).
The runbook warns that omitting `--with-totp` closes MFA-required operations,
but offers no recovery/enrollment flow
([runbook](https://github.com/zl0nline/RTSP_proxy/blob/4ee4f3e269ee9770889b6dc321fb3a1267897c4c/deploy/PILOT_INSTALL.md#L231-L264)).

Safe current workaround: provision a **second**, distinctly named local admin
with `--with-totp`, enroll it, log in with the code and issue a normal audited
temporary grant. Do not weaken recent-MFA policy and do not insert a grant into
PostgreSQL. The durable fix is authenticated TOTP enrollment/replacement with
one-time secret display, password/TOTP reauthentication, session revocation,
audit and recovery tests.

## #26: ingest failure is not represented correctly

The collector already preserves per-path `ready` and byte counters
([metric model](https://github.com/zl0nline/RTSP_proxy/blob/4ee4f3e269ee9770889b6dc321fb3a1267897c4c/src/rtsp_proxy/observability.py#L70-L79),
[MediaMTX parser](https://github.com/zl0nline/RTSP_proxy/blob/4ee4f3e269ee9770889b6dc321fb3a1267897c4c/src/rtsp_proxy/observability.py#L1746-L1839)).
What is missing is an attributable last-attempt failure and a persistent ingest
state. Current projection deliberately maps `ready=false` to `idle`
([projection](https://github.com/zl0nline/RTSP_proxy/blob/4ee4f3e269ee9770889b6dc321fb3a1267897c4c/src/rtsp_proxy/live_updates.py#L1085-L1123)).

That mapping is necessary for `sourceOnDemand=true`: without a downstream
reader no pull has been attempted, so `ready=false` is normal idle and cannot
mean authentication failure. A passive/single-session profile also forbids
creating an extra probe merely to classify it
([policy](https://github.com/zl0nline/RTSP_proxy/issues/6)).

Add a separate state machine such as `idle_without_demand → connecting →
source_unavailable(reason) → ready`, driven by an actual downstream demand,
structured/redacted MediaMTX source events, or an admitted active probe when the
profile permits it. Authentication, network and timeout reasons require a real
attempt signal; they cannot be inferred from zero bytes. Alert only after a
bounded sustained failure and include evidence freshness.

Do **not** redefine node process health based on one camera. Keep node health and
per-camera ingest health separate; expose an aggregate ingest field/count in the
fleet snapshot. Also investigate the independent symptom that the page remains
at the initial `Подключение…`: the JavaScript has labels for idle/unavailable,
so an unchanged initial label means the live/poll delivery path itself did not
apply any snapshot
([client behavior](https://github.com/zl0nline/RTSP_proxy/blob/4ee4f3e269ee9770889b6dc321fb3a1267897c4c/src/rtsp_proxy/assets/dashboard.js#L209-L259)).

## #29: navigation

Two core findings are confirmed: the node summary has no link to filtered
cameras
([node template](https://github.com/zl0nline/RTSP_proxy/blob/4ee4f3e269ee9770889b6dc321fb3a1267897c4c/src/rtsp_proxy/templates/dashboard/node.html#L15-L21)),
and the camera catalog expects a raw UUID text field
([catalog template](https://github.com/zl0nline/RTSP_proxy/blob/4ee4f3e269ee9770889b6dc321fb3a1267897c4c/src/rtsp_proxy/templates/dashboard/cameras.html#L15-L39)).

One requested item is already implemented on `main`: camera detail displays the
node name as a link and the UUID as secondary text
([camera template](https://github.com/zl0nline/RTSP_proxy/blob/4ee4f3e269ee9770889b6dc321fb3a1267897c4c/src/rtsp_proxy/templates/dashboard/camera.html#L26-L32)).
Narrow acceptance accordingly. A node select must preserve pagination/query
semantics and must not turn the page into an unbounded node listing; the current
configured limit is at most 100, so a bounded select is acceptable.

## Rollout gate and dependency order

The README requires ordinary RTSP/TCP playback and observability before scaling
the pilot ([pilot checks](https://github.com/zl0nline/RTSP_proxy/blob/4ee4f3e269ee9770889b6dc321fb3a1267897c4c/README.md#L233-L249));
after an incompatible migration rollback requires fix-forward or backup restore
([rollback boundary](https://github.com/zl0nline/RTSP_proxy/blob/4ee4f3e269ee9770889b6dc321fb3a1267897c4c/README.md#L222-L231)).
Therefore these findings strengthen the existing decision not to migrate beyond
schema 0022 yet.

Recommended implementation dependencies:

1. security containment is immediate and independent;
2. #28 is a schema-free orchestration fix and blocks any further automatic
   placement/wave;
3. #27 enrollment and the safe second-account workaround unblock grant-backed
   playback;
4. exact-tuple playback then distinguishes #25 credential handling from camera
   endpoint/configuration faults;
5. #26 depends on a pinned, redacted source-attempt event contract and must be
   verified for both on-demand idle and real failure;
6. #29 is independent UI work but should follow the pilot blockers.

After fixes, build a new immutable patch candidate with the existing
schema-0022 bridge, run the full CI/security suite, deploy with health rollback,
repeat exact camera playback, and only then make a separate GO/HOLD decision for
the 0024 migration.
