# Phase 0B native load harness

The harness runs directly on dedicated Linux hosts. Docker and other container
runtimes are outside the deployment and evidence contract. Functional jobs
compile and execute the same source natively on Linux `amd64` and `arm64`;
capacity envelopes are measured and published separately for each architecture.

The source side is pull-only. `rtsp-pull-server` exposes prepared H.264/H.265
fixtures as camera-like RTSP endpoints and MediaMTX connects on demand. Every
remote source process verifies the profile-pinned fixture SHA-256 before
announcing `READY`, so same-path/different-byte drift fails closed. The
external reader always uses ordinary `rtsp://` with interleaved TCP. Neither a
publisher into MediaMTX nor a different external protocol is part of the test
path: the remote consumer sees the same ordinary RTSP server contract as a
direct camera.

The source process reparses video to one H.264/H.265 access unit per buffer.
Each constructed RTSP media instance passes its first access unit immediately
for preroll, then paces video against rational absolute monotonic deadlines at
the profile FPS. When a buffer arrives more than one frame interval after its
deadline, the scheduler rebases and waits one interval instead of producing a
catch-up burst; otherwise it preserves the absolute deadline schedule.
Configured Opus uses 960 samples at 48 kHz and the same absolute scheduler at 50
raw buffers/s before encoding and RTP payloading. Pacing therefore neither
waits for the RTSP media pipeline clock during prepare nor accumulates
per-buffer processing delay over a soak.

`rtsp-load-reader` consumes a strict TSV plan (`path`, reader count, first
global reader ID, warm-anchor count, first measured schedule index), timestamps
outgoing DESCRIBE and PLAY requests, and records
the first parser-aligned IDR/IRAP random-access video unit. Header-only,
delta, decode-only, corrupted and gap buffers are rejected. It therefore
publishes separate
`DESCRIBE→PLAY`, `PLAY→first decodable` and end-to-end values instead of
mislabeling the first RTP buffer as the SLO. Stable global IDs allow a cold
proxy run to be paired with the corresponding direct-control run.

## Native build

On Ubuntu 24.04 install the architecture-native packages:

```sh
sudo apt-get update
sudo apt-get install --yes --no-install-recommends \
  build-essential iproute2 pkg-config libgstrtspserver-1.0-dev \
  gstreamer1.0-tools gstreamer1.0-plugins-base \
  gstreamer1.0-plugins-good gstreamer1.0-plugins-bad
make -C tools/load
```

Record `gst-launch-1.0 --version`, the exact dpkg `Version` of
`libgstreamer1.0-0` as `gstreamer_build_id`, and SHA-256 of both binaries in the
profile. The evidence collector currently targets the documented Ubuntu 24.04
native host shape on both architectures. CI proves compatibility only;
distro/package drift invalidates comparisons.

## Prepared fixture

Prepare media before the measured run. The builder refuses to overwrite:

```sh
mkdir -p /srv/rtsp-load/fixtures
bash tools/load/prepare_fixture.sh \
  /opt/rtsp-proxy/current/bin/ffmpeg \
  /srv/rtsp-load/fixtures/h264-2mbit-gop50.h264 \
  h264 2000000 25 50 120
```

Replace the fixture SHA-256 in the immutable run profile, then generate the
mandatory typed sidecar with the pinned tools:

```sh
rtsp-proxy-load inspect-fixture /srv/rtsp-load/profiles/run.json \
  --ffmpeg-binary /opt/rtsp-proxy/current/bin/ffmpeg \
  --ffprobe-binary /opt/rtsp-proxy/current/bin/ffprobe
```

The exclusive `<fixture>.manifest.json` binds the fixture bytes and tool hashes
to probed codec/FPS, frame count, bitrate and every keyframe interval. `prepare`
copies and hashes it as `fixture-manifest.json`; missing, stale or semantically
incompatible fixture evidence fails before any process is launched. The final
keyframe-to-loop-restart interval is checked as part of the GOP contract; a
finite file with a valid internal cadence but a shortened/extended loop boundary
is rejected.

Create separate compatible profile pairs for typical and worst measured OMNY
GOP. The schema accepts only `none` or `opus`, matching the native source
server; unsupported AAC cannot silently become Opus.

## Prepare one evidence-bound run

Copy `profiles/smoke.example.json` and replace every placeholder. `prepare`
verifies the fixture and both load-binary digests, creates the canonical
profile, catalog, per-host reader plans and exact argv-only launch plan with
exclusive writes:

```sh
LOAD_START_MS=$(( ($(date +%s) + 180) * 1000 ))
rtsp-proxy-load validate /srv/rtsp-load/profiles/run.json
rtsp-proxy-load prepare \
  /srv/rtsp-load/profiles/run.json \
  /srv/rtsp-load/runs/2026-08-10T180000Z-amd64 \
  --pull-server-binary /opt/rtsp-load/bin/rtsp-pull-server \
  --load-reader-binary /opt/rtsp-load/bin/rtsp-load-reader \
  --start-unix-ms "$LOAD_START_MS"
```

Do not reconstruct reader/source arguments manually. Execute each `argv` from
`launch-plan.json` on its named generator host under a dedicated systemd scope.
Reader shards use global IDs, common future Unix-millisecond start/lifecycle
epochs, a derived warm-anchor start, ramp end, measurement start/end, one
absolute soak/workload end and coordinated schedule indexes. Completion
evidence carries exact per-shard counts and lifecycle slots, profile/plan
digests, host, actual/scheduled workload windows and Linux `adjtimex` proof
sampled through workload completion. Finalization rejects early or late shard
launches, clock loss, missing 10/100 disconnect slots, a shifted/wrong seeded
outage cohort and any shortened shard workload.

Phase 0B profiles are intentionally IPv4-only. DNS names and IPv4 literals are
accepted, while IPv6 literals fail profile validation until both native source
listeners and every evidence identity are proven dual-stack.

For a proxy run, apply paths only through a literal loopback HTTP management
listener on the SUT; DNS names, userinfo and non-loopback addresses fail closed:

```sh
rtsp-proxy-load apply-paths \
  /srv/rtsp-load/runs/2026-08-10T180000Z-amd64 \
  --api-url http://127.0.0.1:9997
```

A cold proxy profile is deliberately limited to one reader per active path and
the `single` lifecycle. The current implementation safety cap is 512 active
paths and 32 concurrent API workers; it is not a proven scale claim. Larger
cold profiles fail validation until a bulk MediaMTX snapshot/reset path is
proven. After `apply-paths`, run the mandatory reset preflight
on the SUT no more than 30 seconds before the coordinated start:

```sh
rtsp-proxy-load preflight-cold \
  /srv/rtsp-load/runs/2026-08-10T180000Z-amd64 \
  --api-url http://127.0.0.1:9997
```

The command deletes and recreates each exact target with its pinned on-demand
source mapping using at most 32 concurrent API workers, reads every mapping
back, then requires every recreated path to remain unavailable. It
writes typed, profile/start-bound `raw/cold-preflight.json` containing both the
reset and unavailable sets. Cold finalization rejects a missing, stale, altered
or post-reset-ready preflight; this prevents a previous/partially started pull
or warm fan-out sample from being mislabeled as cold establishment. Both cold
and warm preflights run against loopback on the SUT and bind fail-closed Linux
kernel clock proofs before and after their bounded observation windows.

A warm proxy run reserves exactly one reader from `total_readers` per active
path as an anchor; therefore every warm run requires
`total_readers > active_sources`. Anchors start 60 seconds before the measured
ramp and must deliver a decodable access unit before that boundary. They remain
ordinary downstream sessions: after the measured cohort is active, steady and
outage lifecycles may select them like any other reader. Launch every prepared reader process
and its sampler immediately after `prepare`, before the anchor epoch. During the
last 30 seconds before ramp start, run the blocking warm preflight on the SUT:

```sh
rtsp-proxy-load preflight-warm \
  /srv/rtsp-load/runs/2026-08-10T180000Z-amd64 \
  --api-url http://127.0.0.1:9997
```

It uses bounded bulk MediaMTX runtime sweeps through the coordinated ramp boundary
and requires `ready=true` plus at least one downstream reader on every path at
every sample. The typed `raw/warm-preflight.json` is profile/start-bound;
and records each sweep start/end, exact path-set digest, reader-count digest and
maximum gap. Missing, stale, slow or interrupted anchor evidence makes warm proxy finalization
fail closed. Anchors are not extra hidden load: they are part of
`workload.total_readers`, the same reader process/cgroup and generator headroom.

The optional external Basic Auth file is not included in argv contents. It
must be an owner-owned regular file, mode `0600`/`0400`, no symlink, and contain
exactly username and password on separate non-empty lines.

## Scoped WAN/netem evidence

The named WAN profile is exact: `50 ms` added RTT, `10 ms` jitter and `0.5%`
random loss at camera-side receiver ingress. Because only the incoming
camera-to-receiver leg is delayed, the configured netem delay is the specified
added RTT. `chaos` uses the separate exact `150 ms`/`2%` profile; arbitrary
values must not be mislabeled as either named gate.

The profile names the real receiver-side camera interface in
`network.interface`, an otherwise unused IFB in `network.ifb_interface`, the
common MTU and the explicit queue limit. Create and raise the IFB on every
receiver before the run; the harness never creates or deletes links:

```sh
sudo ip link add rtspifb0 type ifb
sudo ip link set dev rtspifb0 mtu 1500 up
```

The IFB must have no routable address, must retain exactly its kernel-default
root qdisc before install, and must not be shared with other traffic-control
owners. An automatic IPv6 link-local address is accepted. The ingress interface
must already be `UP` with the exact profile MTU. Use a root-controlled operator
session or transient service with `CAP_NET_ADMIN`; the application services do
not receive that capability.

For a proxy profile, run the following on the SUT with site `sut`. For a
direct-control profile, run it on every receiving generator host that has a
reader shard, using that host's profile name as `SITE` (for example
`generator-a`):

```sh
RUN_DIR=/srv/rtsp-load/runs/2026-08-11T180000Z-amd64
SITE=sut
TC_BIN=$(readlink -f "$(command -v tc)")
IP_BIN=$(readlink -f "$(command -v ip)")

sudo /opt/rtsp-proxy/current/bin/rtsp-proxy-load install-netem "$RUN_DIR" \
  --site "$SITE" --tc-binary "$TC_BIN" --ip-binary "$IP_BIN"

sudo /opt/rtsp-proxy/current/bin/rtsp-proxy-load sample-netem \
  "$RUN_DIR" "$RUN_DIR/raw/netem-$SITE.jsonl" \
  --site "$SITE" --tc-binary "$TC_BIN" --ip-binary "$IP_BIN"

sudo /opt/rtsp-proxy/current/bin/rtsp-proxy-load summarize-netem \
  "$RUN_DIR" "$RUN_DIR/raw/netem-$SITE.jsonl" \
  "$RUN_DIR/summary/netem-$SITE.json" --site "$SITE"

sudo /opt/rtsp-proxy/current/bin/rtsp-proxy-load remove-netem "$RUN_DIR" \
  --site "$SITE" --tc-binary "$TC_BIN" --ip-binary "$IP_BIN"
```

Install before source/anchor traffic and start the blocking sampler no later
than the warm-anchor epoch. Run the media workload concurrently. The sampler
uses the immutable launch epochs and stops only after the role-specific drain:
the direct receiver follows generator completion, while the SUT includes the
pinned on-demand close and SUT drain window. Do not remove netem before the
sampler exits and the summary is written.

The driver creates one owned `clsact`, one chain-0 flower per exact source
IPv4/TCP listen endpoint, and one root netem qdisc on the IFB. It records the
resolved regular `tc`/`ip` paths, hashes and versions; ordinary distro symlinks
are resolved before execution. The workload `seed` controls scenario/lifecycle
selection only. Ubuntu 24.04 iproute2 6.1 has no supported deterministic netem
packet-loss seed, so the evidence gates the observed loss statistically instead
of claiming an identical dropped-packet sequence.

Summary recomputation requires every scoped flow to carry traffic, zero flower
action drops/overlimits, monotonic counters, queue occupancy below the configured
limit, drops within the random-loss envelope, exact flower-input versus
netem-dequeue/drop packet accounting, empty boundary queues and two final
quiescent samples. A neighboring control flow is not redirected. For cold WAN
A/B, `compare-cold` copies the direct raw/summary/launch/runtime evidence into
the proxy bundle; finalization recomputes it and checks compatible iproute2
versions instead of trusting stored `valid` flags.

Install and remove are ownership-safe and fail closed on foreign ingress,
egress, non-zero-chain, duplicate or IFB qdisc state. A timeout after a possible
kernel mutation triggers exact read-back cleanup. If cleanup reports
`netem_install_failed_cleanup_incomplete`, stop the run and inspect
`tc -s -j qdisc` plus both ingress and egress `tc -s -j filter` inventories;
do not blindly delete `clsact` or the IFB. Rerun `remove-netem` only after the
observed partial state is proven to belong to the same immutable site plan.

## Runtime and hardware manifest

After the prepared source/reader processes are running, capture each generator
host's immutable runtime inventory. Capture after its GStreamer processes have
loaded the media path, no earlier than five minutes before the anchor epoch and
no later than measurement start:

```sh
rtsp-proxy-load capture-generator-runtime RUN_DIR \
  --generator-host generator-a \
  --source-pid 1234 --reader-pid 1235 \
  --cgroup rtsp-load.slice \
  --gst-launch-binary /usr/bin/gst-launch-1.0
```

Run the equivalent command on the SUT for every proxy run and every capacity
run. A direct-control functional run has no SUT process in its data path and
does not require this file:

```sh
rtsp-proxy-load capture-sut-runtime RUN_DIR \
  --mediamtx-pid 4321 --cgroup mediamtx.service
```

The commands write exclusive `raw/runtime-generator-<host>.json` and
`raw/runtime-sut.json` files. Each manifest binds the canonical profile and
brackets the complete capture with synchronized Linux clock proofs. It binds native
`amd64`/`arm64`, machine/boot identity, CPU model
and count, RAM, NIC link speed/MTU, kernel, OS release digest, a fixed sysctl
set, the full cgroup v2 constraint-chain digest, effective CPU/memory/pids limits and per-process
RLIMIT/PID/start-time/executable SHA. Generator manifests additionally bind the
exact installed GStreamer dpkg inventory and core package build to SHA-256,
device and inode identities of the libraries actually mapped by every workload
process. Capture rechecks process identity and every hard denominator before its
completion proof. Missing, stale, cross-host or profile-label-only manifests fail
finalization. A cold proxy/direct pair copies the finalized direct generator
manifests into the proxy bundle and compares stable machine, boot, kernel, sysctl,
cgroup/RLIMIT and GStreamer inventory fields; environment drift invalidates A/B.

## Churn and outage primitives

One immutable profile selects one lifecycle:

- `single`: functional or steady-state hold without injected disconnects;
- `steady`: aggregate 10/s or 100/s connect/disconnect;
- `ramp`: controlled 100 readers/s;
- `burst`: at least 1000 measured readers at 1000 readers/s after warm anchors
  are reserved, with bounded retry/backoff/jitter;
- `outage`: an exact global 10%, 25% or 100% cohort, followed by deterministic
  jitter across the configured backoff window.

Raw events include anchor/ramp start, PLAY, first-decodable, error, injected disconnect and
scheduled reconnect points. SIGINT/SIGTERM, incomplete initial starts, missing
decodable readers or an unrecovered injected cohort always return non-zero;
`--allow-failures` cannot turn an interrupted run into valid evidence.
Every injected disconnect binds the deterministic configured backoff to the
same cycle's `reconnect_scheduled` event and the next cycle's ordered
start→PLAY→first-decodable chain within the profile lateness budget. Orphan or
skipped cycles fail finalization.
Video and configured Opus RTP pads are sequence-checked independently per
reader and reconnect generation. Completion publishes phase-bound received
packet/gap counts for every reader/track and reconciles them with shard totals.
Measurement and soak are checked separately, including the packet spanning
their boundary. Every reader must make progress during its typed connected
portion of each phase; only intervals bounded by an injected-disconnect and its
matching reconnect event are exempt. A stalled track, aggregate mismatch or
any sequence gap invalidates the run even if the total packet rate is healthy.
The receiver treats the RTP sequence-number span as sent packets and compares
it with successfully parsed received packets for each cycle/track/phase
segment. Video must also sustain at least 80% of the pinned fixture FPS (and
Opus 40 packets/s), and the first/last successful packet must remain within one
second of the typed connected interval boundaries. A trailing full-stream
stall cannot hide behind a gap-free final sequence number.

## Generator headroom

Run every source and reader process inside one finite-limit cgroup per generator
host. The sampler has no public fake-root or free-form cadence option: cadence
comes from the stored profile, `/proc` and cgroup v2 come from the real host,
and every workload PID is explicit. It also binds the stable Linux ephemeral
port range, subtracts `ip_local_reserved_ports`, and counts in-use non-listening TCP ports, so socket exhaustion cannot
be misattributed to the SUT. Capacity profiles enforce CPU `<=65%`, NIC byte and
packet rate `<=60%`, and RAM/FD/socket/cgroup-pids `<70%`; functional profiles
retain the generic `<70%` safety gate.

The argument order is `sample-generator RUN_DIR OUTPUT`; for example:

```sh
rtsp-proxy-load sample-generator \
  /srv/rtsp-load/runs/2026-08-10T180000Z-amd64 \
  /srv/rtsp-load/runs/2026-08-10T180000Z-amd64/raw/generator-generator-a.jsonl \
  --generator-host generator-a \
  --source-pid 1234 --reader-pid 1235 \
  --cgroup rtsp-load.slice

rtsp-proxy-load summarize-generator \
  /srv/rtsp-load/runs/2026-08-10T180000Z-amd64 \
  /srv/rtsp-load/runs/2026-08-10T180000Z-amd64/raw/generator-generator-a.jsonl \
  /srv/rtsp-load/runs/2026-08-10T180000Z-amd64/summary/generator-generator-a.json \
  --generator-host generator-a
```

The PID set must equal `cgroup.procs`; every PID must report that cgroup in
procfs and retain its pinned executable digest and process start time. Validation
uses host CPU/RAM/NIC byte and packet rates, actual interface MTU, maximum
per-process single-core CPU/RLIMIT_NOFILE consumption and finite cgroup
CPU/memory/pids limits. The sampler walks every non-root cgroup v2 ancestor and
gates CPU, memory and PID usage wherever a controller constraint exists, so
sibling usage in a limiting systemd slice cannot create false headroom. The
resource-control-exempt mount root is covered by the separate host CPU/RAM gates,
as required by the kernel cgroup v2 contract. NIC speed, total RAM, effective
limits, constraint chain and every
process RLIMIT remain immutable across samples and must equal the runtime
manifest. Machine/boot identity, sample cadence and coverage of
the complete scheduled workload window are checked. Capacity runs require
different machine IDs for their generator hosts. Crossing the tier-specific
ceiling (CPU `>65%`, NIC bytes/packets `>60%`, or any other hard resource
`>=70%`), a missing host summary or a short/gapped sample window invalidates
finalization.
The finalizer also compares the executable-digest multiset with the exact
prepared source/reader roles; a self-consistent raw series from different
binaries is rejected.
The fixed sysctl inventory is typed and canonical. In particular,
`ip_local_port_range` plus `ip_local_reserved_ports` must recompute the exact
range, usable socket capacity and reservation digest observed in every resource
sample; arbitrary strings or label-only manifests fail finalization.

## Proxy and capacity SUT evidence

Every proxy run and every capacity run requires a dedicated MediaMTX systemd
cgroup, the exact MediaMTX PID and loopback metrics listener. A functional
direct-control run has no SUT in its path and does not require this series:

```sh
rtsp-proxy-load sample-sut RUN_DIR RUN_DIR/raw/sut.jsonl \
  --mediamtx-pid 4321 --cgroup mediamtx.service \
  --metrics-url http://127.0.0.1:9998/metrics
rtsp-proxy-load summarize-sut \
  RUN_DIR RUN_DIR/raw/sut.jsonl RUN_DIR/summary/sut.json
```

The typed series binds PID/start time/executable SHA/cgroup, CPU/RAM/FD/NIC and
the pinned MediaMTX session/path RTP/RTCP error families. Every sample carries
its own Linux kernel clock proof. Per-session and per-path counters are retained
cumulatively across churn and gated as monotonic deltas from the
pre-measurement baseline. Exact unlabeled `0` is accepted only as an empty-family
sentinel for a family with no labeled members. Session history uses stable
`id+remoteAddr` identity across legal `idle(path="") → read(path=...)`
transitions, while every sample still requires exact matching `id`, `path`,
`remoteAddr` and `state` labels across all selected families. State-specific
counter sets and top-level totals must reconcile exactly. An observed path
`ready ↔ notReady` transition starts a new counter generation; a decrease while
the same path state remains continuously observed fails closed. Reader RTP
sequence evidence covers sessions that begin and end between MediaMTX scrapes.
Sampling continues past the pinned 10-second on-demand close
timer plus a 30-second drain budget and final cadence interval. Capacity finalization rejects a
missing SUT series, generator/SUT machine overlap, resource ceiling breach,
RSS growth above `1%/h` in any 6h+ window, including windows crossing the
measurement/soak boundary, FD leak above `0.1%` or 10, non-zero
post-workload RTSP sessions or ready runtime paths, and any positive
measurement/soak RTP loss/error delta.
Functional proxy finalization uses the same independently recomputed SUT identity,
session/path reconciliation, drain and zero-loss evidence with its `<70%` safety
headroom policy; the 6h/24h leak conclusions remain capacity-only because a short
functional run cannot establish them.

## Reader and cold A/B summaries

When a run has multiple reader processes, merge their exclusive raw files and
then summarize:

```sh
rtsp-proxy-load merge-readers RUN_DIR RUN_DIR/raw/readers.jsonl \
  RUN_DIR/raw/readers-generator-a.jsonl \
  RUN_DIR/raw/readers-generator-b.jsonl
rtsp-proxy-load summarize-readers RUN_DIR RUN_DIR/raw/readers.jsonl \
  RUN_DIR/summary/readers.json
```

Warm proxy pass/fail uses p99 `DESCRIBE→PLAY ≤500 ms` only from the measured
ramp readers after the per-path anchors are active; anchor establishment is
excluded from that percentile. First-decodable
percentiles remain separate diagnostics. Cold proxy output has no standalone
latency pass. First finalize and verify the compatible direct-control run, then
bind its final-manifest digest into the proxy comparison:

```sh
rtsp-proxy-load finalize DIRECT_RUN_DIR
rtsp-proxy-load verify DIRECT_RUN_DIR
rtsp-proxy-load compare-cold \
  PROXY_RUN_DIR PROXY_RUN_DIR/raw/readers.jsonl \
  DIRECT_RUN_DIR DIRECT_RUN_DIR/raw/readers.jsonl \
  PROXY_RUN_DIR/summary/cold-comparison.json
```

The paired profiles must match byte-for-byte except `endpoint_mode`. Cold p99
`proxy_overhead` is the proxy-minus-direct difference of `DESCRIBE→PLAY`, gated
at one second. Direct and proxy `PLAY→first-decodable` percentiles are published
separately as GOP/keyframe contributions; unsynchronized source GOP phases are
never subtracted from one another.

## Finalization and evidence boundary

```sh
rtsp-proxy-load finalize RUN_DIR
rtsp-proxy-load verify RUN_DIR
```

Finalization does not trust stored `valid` flags. It regenerates the catalog,
reader plans and launch arguments from the canonical profile, re-parses raw
reader/generator/SUT evidence into exact typed summaries, validates the exact
per-host runtime/hardware manifests, checks the shard/process/machine/time-window
sets, checks cold inactivity or warm anchor evidence, and
reproduces cold A/B from a copied finalized direct reference. Only then does it
hash every input/raw/summary file, seal files/directories to `0440`/`0550`, and
write the final manifest as the completion marker. Verification checks both
hashes and exact modes; an interrupted last chmod remains unverifiable but can
be safely completed by rerunning `finalize`. The completion marker itself is
fsynced off-path and atomically linked into the run directory, followed by a
directory fsync; a partial marker left by an older finalizer is recoverable by
rerunning the complete semantic finalizer.
This is locally tamper-evident and read-only, not magical WORM: production
evidence must then be transferred to root-owned immutable storage or the
approved WORM target.

Hardened native amd64/arm64 CI run `31527148623` proves compilation,
runtime-manifest capture against real procfs/cgroup v2/dpkg/mapped libraries,
scoped Linux camera-ingress `clsact/flower→IFB→netem`, H.264/H.265/Opus
decodability, independent paths, fan-out, timing events, interruption failure
and TCP-only sockets on Linux amd64/arm64. The same slice passed repeat
Standards/Spec review. This does not prove production capacity. Spike #0 still
requires dedicated hardware, production-equivalent LAN and camera-side WAN A/B, typical and
worst GOP, untuned 100/500/1000 baselines, the full lifecycle/fault matrix and
a 24-hour production-equivalent soak. Until typed non-zero probe/CRUD drivers
land, profiles containing those axes fail closed instead of silently producing
partial evidence.

Run durations are not one undifferentiated hold: `ramp_end`,
`measurement_start`, `measurement_end` and `soak_end` are deterministic launch
and completion fields. Injected steady/outage work begins at measurement start;
the profile is rejected when warm-up cannot cover the pinned GOP plus readiness
budget. Reader health, phase RTP rates and generator/SUT headroom report/gate
measurement and soak separately, so anchor/warm-up traffic cannot silently
become measurement evidence.
