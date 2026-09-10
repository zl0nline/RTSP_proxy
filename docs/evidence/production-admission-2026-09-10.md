# Production-admission pilot execution, 2026-09-10

Decision: **Production HOLD**. Release `0.17.4` is functionally verified on the
authorized pilot, including a real media session, upgrade continuity, guarded
camera movement and an isolated database restore. The pilot runs Ubuntu 26.04,
which is explicitly a pilot-only mechanism rather than the supported Ubuntu
24.04 production platform. The site-only gates at the end of this record have
not been waived.

This document is deliberately sanitized. It contains no host address, camera
address or path, downstream credential, source credential, TOTP seed, database
DSN, keyring or private certificate material.

## Exact candidate

| Item | Evidence |
|---|---|
| Release | `0.17.4`, native `amd64` bundle |
| Git commit | `32a29ad49a225e8a80ff747fa38fd0cabcab69f0` |
| Release-manifest SHA-256 | `4c1a043adda661a282750cc8d1120e4a9075425e4072b12b3f53fbef2f01653b` |
| Database revision | `0024_camera_probe_profiles` |
| Media runtime | `v1.20.0-rtsp-proxy.3` |
| Release CI | [run 34454644038](https://github.com/zl0nline/RTSP_proxy/actions/runs/34454644038), all 9 jobs passed |
| Linux full suite | 1,836 passed, 77 skipped, 90.05% coverage |
| Installed source | clean detached checkout at the exact manifest commit |

The local targeted regression set passed 308 tests together with Ruff, strict
mypy, package build, dependency audit, shell/JavaScript syntax, internal-link
and diff checks. A local macOS full-suite run reached 1,730 passed and 182
skipped; its two failures were the known macOS `killpg` `EPERM` cleanup race in
the browser harness, and the isolated rerun passed. Linux CI is the admission
authority for that platform-specific path.

## Defects found by the live admission loop

The live loop rejected three earlier immutable candidates instead of treating
their successful CI as production evidence:

1. `0.17.2` restarted the shared nftables service during activation. Media
   units require that service, so systemd stopped all media processes and the
   established reader ended at activation. The updater now restarts only an
   explicit application-unit allowlist and defensively filters adapter output.
2. `0.17.3` preserved media correctly, but a move preview could return no
   targets when persisted management observations had aged out. Move selection
   now refreshes plausible candidates through the guarded write-side lifecycle
   helper before applying freshness filters.
3. The earlier collector incident predicate only recognized runtime `failed`.
   A real unexpectedly inactive systemd process is observed as `stopped`; the
   corrected predicate opens an incident when desired state is running and
   observed runtime is stopped, while retaining the expected-stop exclusion.

Each defect received a deterministic regression before its fix. Candidates
`0.17.2` and `0.17.3` remain immutable and are explicitly documented as
non-admission targets.

## Pilot game-day observations

| Scenario | Result |
|---|---|
| Real ordinary RTSP/TCP session | One on-demand H.264 source sustained about 20 fps for 57 min 57 s with zero reported duplicate or dropped frames before the deliberately confirmed move disconnected it |
| Update continuity | Activation of both `0.17.3` and `0.17.4` preserved every media PID and the nftables activation timestamp; the established reader continued through the exact `0.17.4` activation |
| Control-plane restart | Web, auth, reconciler and collector restarted while the established media reader and its media PID continued |
| Camera CRUD isolation | A disposable camera was created, updated, disabled, enabled and deleted on another node without interrupting the established reader |
| Drain/resume | The established reader continued on a draining node, a new reader was rejected, and resume restored the persisted running state |
| Media-process failure | `SIGKILL` of an empty media node auto-restarted it; a longer unexpected stop opened exactly one durable failure message and recovery produced exactly one durable recovery message, without reminder duplicates |
| Collector loss | Stopping the collector made the dashboard snapshot explicitly stale/unavailable while media continued; restart restored a fresh fleet snapshot |
| Probe-plane loss | Stopping the probe worker, broker and socket made probe readiness unavailable while media continued; restarting them restored all probe checks |
| Database loss | Web and auth readiness failed closed with HTTP 503 while the established media session continued; PostgreSQL restart returned both readiness endpoints to 200 within the observed one-second check interval |
| Configured limits | Temporary `max_nodes=4` and a one-port external range each rejected creation with the explicit limit reason; restoring the configuration left four nodes and no disposable camera |
| Port-change rollback | An occupied target port was rejected without mutation. A deterministic one-shot activation fault aborted the saga, restored the original port/configuration and left no prepared saga or fault fixture |
| Guarded camera move | With one reader connected, preview required confirmation of one downstream disconnect. The move completed, the old node stopped serving the path and the new node served video. The reverse move completed with zero readers, restored the original endpoint and removed the temporary path |
| Local security workflow | Local password plus TOTP login, MFA step-up, grant issue/use and audited revocation completed through the dashboard; final state has zero valid and zero unrevoked temporary grants |
| Final service state | Web, auth, reconciler, probe and collector readiness passed; four media services and all helper sockets were active; systemd reported zero failed units and the final five-minute log check had no warning/error record |
| Resource snapshot | 94.6% memory available, 75% filesystem free, synchronized system time and fresh process identity/management observations for all four nodes |

The database retained two completed move sagas and no in-progress move. The
working camera was restored to its original node and endpoint. The other
configured sources were not promoted to evidence: one timed out and one lacks
admitted source credentials. A single working H.264 source is not a camera
profile matrix.

## Exact-candidate recovery set

The final state was backed up after all temporary grants were revoked:

`production-admission-0.17.4-final-20260910T090726Z`

| Artifact | SHA-256 |
|---|---|
| PostgreSQL custom archive | `a29edfeaf84a44426a0a1cfed04115a715c8b2a3eae9af3c86c41a26601bc5b9` |
| Generated archive manifest | `cc37d9e25f863e4ef2e792c4e1ed2a9c69c7a74e0a1c927823dc56eeae1962e0` |
| Isolated-restore report | `980d6c98bf4ffeedbac56691e1e4f2147772529ea70d0e7e1593710cc34fa162` |
| Control-assets archive | `9c8e61c42de0fafc89213c1a6ca0a930605e2c907748684ab5568e2a9edbf5ce` |

The backup completed in 0.39 seconds. The isolated restore completed in 1.80
seconds, compared all 32 public tables and all five invariants, and removed its
temporary database. `tar --compare` passed for the control-assets archive and
the generated checksum set verified all four artifacts. Database/report files
are owned by the database account, control artifacts by root, and every file is
mode `0600`.

This is still only a same-disk recovery set. No encrypted off-host retrieval,
continuous WAL/RPO proof or restore onto a replacement supported host was
performed, so it cannot satisfy the production recovery gate by itself.

## Gates that remain open

Production GO still requires site evidence for all of the following:

- Ubuntu 24.04 on the actual admitted hardware, with the site CA-issued
  management certificate and final secret inventory;
- encrypted off-host backup retrieval, RPO no greater than five minutes and a
  replacement-host restore using the retained control keyrings;
- real SMTP relay delivery of one failure and one recovery notification;
- ordinary-reader proof for every admitted camera model, firmware, codec and
  source-authentication profile;
- the complete failure-domain matrix on the admitted network and power design,
  including host reboot and upstream/network faults;
- a 24-hour production-equivalent soak with non-zero churn and at least 30%
  hard-resource headroom;
- a measured independent-server ladder and an operational node/camera cap;
- named owner, security and operations sign-off.

The physical 100-camera-on-one-node trial remains **DEFERRED by owner**. No
statement in this record converts the hard admission limit of 100 into a tested
capacity claim.
