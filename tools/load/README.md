# Phase 0B native load harness

The harness runs directly on dedicated Linux hosts. Docker and other container
runtimes are outside the deployment and evidence contract. Functional jobs
compile and execute the same source natively on Linux `amd64` and `arm64`;
capacity envelopes are measured and published separately for each architecture.

The source side is pull-only. `rtsp-pull-server` exposes prepared H.264/H.265
fixtures as camera-like RTSP endpoints and MediaMTX connects on demand. The
external reader always uses ordinary `rtsp://` with interleaved TCP. Neither a
publisher into MediaMTX nor `rtsps://` is part of the primary test path.

`rtsp-load-reader` consumes a strict TSV plan (`path`, reader count, first
global reader ID), timestamps outgoing DESCRIBE and PLAY requests, and records
the first parsed non-delta video access unit. It therefore publishes separate
`DESCRIBE→PLAY`, `PLAY→first decodable` and end-to-end values instead of
mislabeling the first RTP buffer as the SLO. Stable global IDs allow a cold
proxy run to be paired with the corresponding direct-control run.

## Native build

On Ubuntu 24.04 install the architecture-native packages:

```sh
sudo apt-get update
sudo apt-get install --yes --no-install-recommends \
  build-essential pkg-config libgstrtspserver-1.0-dev \
  gstreamer1.0-tools gstreamer1.0-plugins-base \
  gstreamer1.0-plugins-good gstreamer1.0-plugins-bad
make -C tools/load
```

Record `gst-launch-1.0 --version`, exact package build IDs and SHA-256 of both
binaries in the profile. CI proves compatibility only; distro/package drift
invalidates comparisons.

## Prepared fixture

Prepare media before the measured run. The builder refuses to overwrite:

```sh
mkdir -p /srv/rtsp-load/fixtures
bash tools/load/prepare_fixture.sh \
  /opt/rtsp-proxy/current/bin/ffmpeg \
  /srv/rtsp-load/fixtures/h264-2mbit-gop50.h264 \
  h264 2000000 25 50 120
```

Create separate compatible profile pairs for typical and worst measured OMNY
GOP. The schema accepts only `none` or `opus`, matching the native source
server; unsupported AAC cannot silently become Opus.

## Prepare one evidence-bound run

Copy `profiles/smoke.example.json` and replace every placeholder. `prepare`
verifies the fixture and both load-binary digests, creates the canonical
profile, catalog, per-host reader plans and exact argv-only launch plan with
exclusive writes:

```sh
rtsp-proxy-load validate /srv/rtsp-load/profiles/run.json
rtsp-proxy-load prepare \
  /srv/rtsp-load/profiles/run.json \
  /srv/rtsp-load/runs/2026-08-10T180000Z-amd64 \
  --pull-server-binary /opt/rtsp-load/bin/rtsp-pull-server \
  --load-reader-binary /opt/rtsp-load/bin/rtsp-load-reader
```

Do not reconstruct reader/source arguments manually. Execute each `argv` from
`launch-plan.json` on its named generator host under a dedicated systemd scope.
Reader shards use global IDs and coordinated schedule indexes, so proxy and
direct-control runs have the same path/readers distribution and aggregate
connect/disconnect rate.

For a proxy run, apply paths only through a literal loopback HTTP management
listener on the SUT; DNS names, userinfo and non-loopback addresses fail closed:

```sh
rtsp-proxy-load apply-paths \
  /srv/rtsp-load/runs/2026-08-10T180000Z-amd64 \
  --api-url http://127.0.0.1:9997
```

The optional external Basic Auth file is not included in argv contents. It
must be an owner-owned regular file, mode `0600`/`0400`, no symlink, and contain
exactly username and password on separate non-empty lines.

## Churn and outage primitives

One immutable profile selects one lifecycle:

- `single`: functional or steady-state hold without injected disconnects;
- `steady`: aggregate 10/s or 100/s connect/disconnect;
- `ramp`: controlled 100 readers/s;
- `burst`: 1000 readers/s with bounded retry/backoff/jitter;
- `outage`: an exact global 10%, 25% or 100% cohort, followed by deterministic
  jitter across the configured backoff window.

Raw events include start, PLAY, first-decodable, error, injected disconnect and
scheduled reconnect points. SIGINT/SIGTERM, incomplete initial starts, missing
decodable readers or an unrecovered injected cohort always return non-zero;
`--allow-failures` cannot turn an interrupted run into valid evidence.

## Generator headroom

Run every source and reader process inside one finite-limit cgroup per generator
host. The sampler has no public fake-root or free-form cadence option: cadence
comes from the stored profile, `/proc` and cgroup v2 come from the real host,
and every workload PID is explicit.

The argument order is `sample-generator RUN_DIR OUTPUT`; for example:

```sh
rtsp-proxy-load sample-generator \
  /srv/rtsp-load/runs/2026-08-10T180000Z-amd64 \
  /srv/rtsp-load/runs/2026-08-10T180000Z-amd64/raw/generator-a.jsonl \
  --generator-host generator-a --pid 1234 --pid 1235 \
  --cgroup rtsp-load.slice

rtsp-proxy-load summarize-generator \
  /srv/rtsp-load/runs/2026-08-10T180000Z-amd64 \
  /srv/rtsp-load/runs/2026-08-10T180000Z-amd64/raw/generator-a.jsonl \
  /srv/rtsp-load/runs/2026-08-10T180000Z-amd64/summary/generator-a.json \
  --generator-host generator-a
```

Validation uses host CPU/RAM/NIC plus maximum per-process single-core CPU and
RLIMIT_NOFILE consumption and cgroup CPU/memory/pids hard limits. Identity,
boot ID, expected sample count and maximum cadence gap are checked. Any hard
resource reaching 70%, a missing host summary or a short/gapped sample window
invalidates finalization.

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

Warm proxy pass/fail uses p99 `DESCRIBE→PLAY ≤500 ms`; first-decodable
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
`proxy_overhead` is gated at 1 second; the direct path's
PLAY-to-first-decodable value publishes the GOP/keyframe contribution.

## Finalization and evidence boundary

```sh
rtsp-proxy-load finalize RUN_DIR
rtsp-proxy-load verify RUN_DIR
```

Finalization requires a green reader summary (when readers are configured), a
green digest-bound headroom summary for every generator host, and the cold A/B
summary when applicable. It hashes every input/raw/summary file, creates an
exclusive final manifest, then changes files/directories to `0440`/`0550`.
This is locally tamper-evident and read-only, not magical WORM: production
evidence must then be transferred to root-owned immutable storage or the
approved WORM target.

The current CI smoke proves native compilation, H.264/H.265 decodability,
independent paths, fan-out, timing events, interruption failure and TCP-only
sockets on Linux amd64/arm64. It does not prove production capacity. Spike #0
still requires dedicated hardware, LAN and camera-side WAN/netem, typical and
worst GOP, untuned 100/500/1000 baselines, the full lifecycle/fault matrix and
a 24-hour production-equivalent soak.
