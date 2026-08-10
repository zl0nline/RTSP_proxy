# Phase 0B native load harness

This harness runs directly on dedicated Linux hosts. It does not use Docker or
another container runtime. Functional contracts run natively on both `amd64`
and `arm64`; capacity evidence is published separately for each architecture.

The source side is pull-only: `rtsp-pull-server` exposes independent GStreamer
RTSP server endpoints backed by a prepared H.264 or H.265 fixture. MediaMTX
initiates each source connection on demand. Publishing fixtures into MediaMTX
is not an accepted substitute.

`rtsp-load-reader` creates many GStreamer RTSP consumers in one process, forces
TCP, records first-packet latency/errors as JSONL and can read synthetic Basic
Auth credentials from a two-line file. Credentials never appear in its argv or
event output. A bounded matrix of pinned FFmpeg readers remains required for
reference-consumer diversity during the real spike.

## Native packages and build

On Ubuntu 24.04 install the architecture-native packages:

```sh
sudo apt-get update
sudo apt-get install --yes --no-install-recommends \
  build-essential pkg-config libgstrtspserver-1.0-dev \
  gstreamer1.0-tools gstreamer1.0-plugins-base \
  gstreamer1.0-plugins-good gstreamer1.0-plugins-bad
make -C tools/load
```

Record `gst-launch-1.0 --version`, the exact `dpkg-query` package versions and
SHA-256 of both built binaries in every run profile. CI only proves functional
compatibility; distro package drift invalidates comparisons between load runs.

## Prepared fixture

Use the pinned FFmpeg artifact to prepare the elementary stream before starting
load. The builder refuses to overwrite an existing artifact:

```sh
mkdir -p /srv/rtsp-load/fixtures
bash tools/load/prepare_fixture.sh \
  /opt/rtsp-proxy/current/bin/ffmpeg \
  /srv/rtsp-load/fixtures/h264-2mbit-gop50.h264 \
  h264 2000000 25 50 120
```

Create distinct profiles for the typical and worst measured GOP. Record the
fixture SHA-256 in each profile. Do not generate/encode media during a measured
run.

## Immutable run inputs

Copy `profiles/smoke.example.json` and replace every placeholder with values
measured on the target hosts. The capacity tier additionally requires two
generator hosts, at least 15 minutes warm-up, 30 minutes measurement and a
24-hour soak.

```sh
rtsp-proxy-load validate /srv/rtsp-load/profiles/run.json
rtsp-proxy-load init \
  /srv/rtsp-load/profiles/run.json \
  /srv/rtsp-load/runs/2026-08-10T180000Z-amd64
rtsp-proxy-load render-catalog \
  /srv/rtsp-load/profiles/run.json \
  /srv/rtsp-load/runs/2026-08-10T180000Z-amd64/path-catalog.json
rtsp-proxy-load render-reader-paths \
  /srv/rtsp-load/profiles/run.json \
  /srv/rtsp-load/runs/2026-08-10T180000Z-amd64/reader-paths.txt
```

All writers use exclusive creation and mode `0640`; reuse a new run directory
instead of editing evidence from an earlier run.

## Source hosts

Start one source-server process for each non-overlapping range from
`generator_hosts`. This example serves indices 0 through 99:

```sh
tools/load/rtsp-pull-server \
  --address 0.0.0.0 --port 8554 \
  --source-start 0 --source-count 100 \
  --fixture /srv/rtsp-load/fixtures/h264-2mbit-gop50.h264 \
  --codec h264 --fps 25
```

Apply the corresponding on-demand catalog only through the MediaMTX loopback
management listener on the SUT:

```sh
rtsp-proxy-load apply-paths /srv/rtsp-load/profiles/run.json \
  --api-url http://127.0.0.1:9997
```

## Readers and generator headroom

The credentials file contains exactly the synthetic external username and
password on separate lines and must be readable only by the load user.

```sh
tools/load/rtsp-load-reader \
  --host proxy.load.internal --port 9999 \
  --paths-file /srv/rtsp-load/runs/2026-08-10T180000Z-amd64/reader-paths.txt \
  --readers-per-path 1 --connect-rate 100 --hold-seconds 600 \
  --credentials-file /run/rtsp-load/external-basic.txt \
  --events-file /srv/rtsp-load/runs/2026-08-10T180000Z-amd64/raw/readers.jsonl
rtsp-proxy-load summarize-readers /srv/rtsp-load/profiles/run.json \
  /srv/rtsp-load/runs/2026-08-10T180000Z-amd64/raw/readers.jsonl
```

Set `endpoint_mode` to `proxy` or `direct-control` and
`session_temperature` to `warm` or `cold` in separate immutable profiles.
Warm proxy runs enforce the 500 ms p99 gate. Cold proxy output is deliberately
marked `requires_direct_control_decomposition`; it cannot claim the 1 second
proxy-overhead SLO until paired with the same fixture/GOP direct-control run.

Run the host sampler for the entire profile duration on every source and reader
generator host:

```sh
rtsp-proxy-load sample-host /srv/rtsp-load/profiles/run.json \
  /srv/rtsp-load/runs/2026-08-10T180000Z-amd64/raw/generator-a.jsonl
rtsp-proxy-load summarize-generator /srv/rtsp-load/profiles/run.json \
  /srv/rtsp-load/runs/2026-08-10T180000Z-amd64/raw/generator-a.jsonl
```

A summary is invalid when the observation window is short or CPU, RAM, global
FD allocation, or NIC utilization reaches `70%`. At least 30% generator
headroom is mandatory; adding load hosts is the remedy, not accepting the run.

## Evidence boundary

The current CI smoke proves buildability, H.264/H.265 decodability, independent
paths, fan-out readers and TCP-only sockets on Linux `amd64` and `arm64`. It
does not prove a single-node capacity envelope. A valid Spike #0 still requires
dedicated source/reader hosts, LAN and measured WAN/netem profiles, untuned
100/500/1000 baselines, separate typical/worst GOP runs, the full churn/fault
matrix and a 24-hour production-equivalent soak.
