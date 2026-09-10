# Host compatibility evidence for 0.17.6, 2026-09-11

Decision: **the `modern-systemd-linux-v1` implementation and release artifact
are compatible with the tested ARM host**. This is platform and code evidence,
not a production site admission and not a camera-capacity or 100-camera test.
Production remains `HOLD` under the main readiness matrix.

This record is sanitized. It contains no host address, login credential,
camera endpoint, application secret or private infrastructure identifier.

## Exact candidate and CI

| Item | Evidence |
|---|---|
| Release | `0.17.6`, schema-5 native `arm64` bundle |
| Git commit | `36c317ff4f1efbf8c360d4088fae13ffa0398231` |
| Release-manifest SHA-256 | `8499673b2986ecdd507e293649403e06202659ec4de690156641d47dd853c2b8` |
| Release CI | [run 34540965495](https://github.com/zl0nline/RTSP_proxy/actions/runs/34540965495), all 14 jobs passed |
| Linux full suite | 1,877 passed, 77 skipped on each of amd64 and arm64; 90.06% coverage on each |
| Privileged BPF contract | 12 passed on each native CI architecture |
| Package adapters | Real package installation passed in Debian 13, Fedora 42, Rocky Linux 10, openSUSE Tumbleweed and Arch containers |

Both native release jobs also passed the MediaMTX/FFmpeg/probe artifact
verification, root broker transaction and effective listener contracts. The
downloaded ARM artifact matched the manifest for all eight checksum-bound
assets before it was copied to the hardware host.

## Hardware capability result

The dedicated test host reported:

| Capability | Observed value |
|---|---|
| Distribution | Armbian 26.08 based on Ubuntu 26.04 |
| Architecture | `arm64` / AArch64 |
| Kernel | `6.18.37-ophub` |
| systemd | 259, PID 1 and operational |
| glibc | 2.43 |
| System Python before bootstrap | 3.14.4 |
| Isolated application Python | 3.12.13 |
| cgroup | Unified v2 with `cpu`, `memory` and `pids` controllers |
| BPF prerequisites | bpffs mounted and kernel BTF readable |
| Package adapter | `apt-get` |
| IPv6 | Disabled; reported as `LIMITATION: ipv6_unavailable` rather than a compatibility blocker |

The human and JSON doctor interfaces both returned
`profile=modern-systemd-linux-v1`, `architecture=arm64`, no blockers and
`supported=true`. The JSON also returned `capabilities.ipv6=false` and the
machine-readable limitation. This host is therefore admissible only for an
IPv4-only site configuration unless IPv6 is enabled and the checks are
repeated.

## Bootstrap and exact artifact checks

The host initially had no RTSP Proxy users, units, configuration or release.
The bootstrap preflight identified the missing package prerequisites before
mutation. Its apt transaction installed `bpftool`, `nftables`,
`postgresql-client`, `systemd-container` and their new dependencies. Because
the distribution repositories carried newer dependency revisions, the same
transaction also updated systemd, util-linux, OpenSSL, curl and their related
libraries. This is expected package-manager behaviour and is why the runbook
requires a reboot/status check after bootstrap. The host reported no reboot
requirement and zero failed units afterwards.

Bootstrap installed the checksum-pinned official `uv 0.12.3` AArch64 binary as
root-owned mode `0755` at `/usr/local/bin/uv` and isolated CPython 3.12.13
under `/opt/rtsp-proxy/python`. It did not create application configuration,
database objects, nftables policy or RTSP Proxy units.

On the exact 0.17.6 bundle, the native release verifier returned
`verified release 0.17.6`. The bundled probe `bpftool` ran as v7.4 with all
shared libraries resolved. Its SHA-256 was
`b7f52227fcb546f62d30351ab69f9e651712e37fae09daea9c38f90638265243`;
the BPF object SHA-256 was
`cc30367d34573672788403a935dcced86513d019ae75bd05a87cfacbcf4b7ece`.

## Native systemd and BPF result

A temporary root-owned runtime, tool copy, object copy and `current` symlink
were created only for the contract. The complete hardware contract finished
with 9 passed and 3 skipped tests. The skips were exactly the exhaustive
dual-stack case and the two IPv6-target parameters, because the host kernel
configuration disables IPv6. The IPv4 production manager path, transient
systemd execution, exact map and attachment read-back, allowed/denied
behavioural canary, cancellation and cleanup paths all passed.

This hardware loop rejected 0.17.5 before admission: the same checksum-bound
CO-RE object received a different valid program tag on kernel 6.18 than on the
6.8 build host. Release 0.17.6 correctly treats that tag as post-relocation
runtime evidence rather than an artifact digest. It still reopens and verifies
the root-owned tool and object by descriptor and digest for every operation,
validates the loaded program/map/attachment graph and requires the behavioural
canary before opening the child run gate. ADR 0004 records this security
boundary.

## Cleanup and limits of this evidence

After the contract, the temporary root runtime, tool/object copies, symlink,
source tree and bundle were removed. Checks found no RTSP Proxy configuration
or units, no project BPF pins, no transient probe cgroups and no failed systemd
units. The bootstrap-installed prerequisite packages, pinned `uv` and isolated
Python were intentionally retained.

No PostgreSQL server, camera, MediaMTX node, management endpoint, SMTP relay,
production certificate, recovery set, soak workload or load generator was
configured on this host. In particular, this run supplies no 100-camera or
sustainable-node-count claim. Exact production hardware must repeat the
doctor, bundle verification and native broker checks and still satisfy every
`SITE REQUIRED` row in [`PRODUCTION_READINESS.md`](../PRODUCTION_READINESS.md).
