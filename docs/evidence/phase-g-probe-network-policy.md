# Phase G: special-address and untrusted-protocol boundary

Status: reviewed and native-CI verified through `c10b4a4`, based on `25efd66`.
This network-policy slice is closed. It does not
enable the production probe worker or accept ADR 0004. The candidate bundle is
`0.15.1`, retaining schema 0023 and the reviewed schema-0022 bridge.

## Contract

- Source admission and restoration reject unspecified, loopback, link-local,
  multicast and reserved addresses, including normalized mapped IPv4 addresses.
  They also reject the known non-link-local metadata/credential endpoints below.
  Every DNS answer must pass; one unsafe answer rejects the whole admission.
- The broker repeats special-use denial after authenticated receipt of the
  sealed descriptor. A broad CIDR does not override it. Ordinary configured ULA
  camera addresses remain valid. For native installed fixtures only, a
  loopback-only broker CIDR can explicitly admit a controlled loopback listener;
  a broad `/0` is not such an assignment. Camera admission itself still rejects
  loopback even under a loopback CIDR.
- Test-only hostile clients bypass caller-side validation and send a genuinely
  sealed descriptor over AF_UNIX/SCM_RIGHTS to the installed root broker. HTTP,
  HTTPS, file, pipe, raw TCP/UDP, RTSPS, concat, alternate RTSP transport,
  redirect-enabling options, a hostname in the input, a second file directive,
  and mismatched address/port tuples must be refused before executor allocation.
  The production client has no bypass mode.
- Native denial checks require no transient unit, unit journal entry, BPF pins
  or ownership receipt. Hostile-input cases also require unchanged broker PID/FD
  count and continued availability. The normal production client maps refusal
  to infrastructure `INCONCLUSIVE`, not a camera fault.
- An installed broad-policy regression temporarily replaces the dedicated CI
  broker CIDRs with `/0`, tests only IPv4/IPv6 loopback targets, and restores the
  exact original configuration with a restart in `finally`. Even a regression
  cannot contact metadata services. This distinguishes the new special-use
  check from ordinary CIDR mismatch. The rest of the installed special-address
  matrix uses narrow CIDRs; broad-policy coverage for those destinations runs
  through the real Linux transport with a non-networking stub executor.

## Non-link-local platform endpoint sources

These exact addresses are not covered by generic link-local classification:

- EC2 IMDS IPv6 `fd00:ec2::254`:
  [AWS IMDS documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html).
- EKS Pod Identity credentials IPv6 `fd00:ec2::23`:
  [AWS considerations](https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html#pod-id-considerations).
- Alibaba metadata IPv4 `100.100.100.200`:
  [Alibaba instance metadata documentation](https://www.alibabacloud.com/help/en/ecs/user-guide/view-instance-metadata/).

This explicit denylist complements, and does not replace, a narrow operator-owned
camera-site CIDR policy. It is not a claim of an exhaustive inventory of every
provider's private services. Empty source policy remains deny-all. No cloud
service, SDK, external identity provider or container runtime is added; tests
never query a cloud metadata service. Provider documentation identifies addresses
to refuse, not services to integrate.

## Reproduction and verification

Before the fix, IPv6 metadata literal/DNS admission tests failed by accepting a
forbidden destination. Adding the workload-credential and non-link-local IPv4
cases reproduced the same issue. Nine initial real Linux broker-transport cases
also reached the stub executor under broad CIDRs when they should have been
refused. The fixes share one special-use predicate between admission/restoration
and broker policy; explicitly controlled loopback remains a broker-only exception.

The first native hostile-sender run exposed a test portability issue: supported
Python 3.12 builds need not export `fcntl.F_ADD_SEALS`. The fixture now uses the
same Linux ABI value as the production sealer. Thread failures are collected
instead of leaving unhandled test-thread warnings.

Independent Spec review identified that the original installed special-address
matrix could pass solely through CIDR mismatch. The dedicated broad-policy
loopback regression above addresses that evidence gap; Standards found no
actionable issue. Final re-review through `c10b4a4`: Standards PASS, Spec PASS.

The first native run, [33965851594](https://github.com/zl0nline/RTSP_proxy/actions/runs/33965851594),
passed 40 installed contracts on each architecture but failed the first hostile
FD-baseline check after restart (`7 != 4`). `Type=simple` had reported active
before startup recovery initialized the persistent D-Bus event-loop descriptors.
The remaining 14 hostile cases passed without accumulating descriptors. The test
now waits for the real accept loop using a bounded root-peer refusal, with no
request or input descriptor, before taking the baseline. Exact PID/FD equality
and no-execution assertions remain unchanged; the failed run is not acceptance.

Final [CI run 33966428098](https://github.com/zl0nline/RTSP_proxy/actions/runs/33966428098)
passed all nine jobs on `c10b4a4`, including all 41 installed root-broker
contracts on each native architecture, verified release bundles, media/load
contracts and browser acceptance. Local full tests before the opt-in readiness
addition: 1,659 passed, 171 platform/opt-in skips. The grob scratch full suite:
1,754 passed, 76 opt-in skips. The readiness fix changes only the privileged
contract; it is covered by the final native run, not by those skipped local cases.
Ruff, mypy (80 source files), wheel/sdist build and diff checks passed.

```sh
uv run pytest -q tests/test_probe_security.py tests/test_probe_policy_payloads.py \
  tests/test_probe_broker_service.py
uv run ruff check src tests
uv run mypy src
```

The installed root contracts remain opt-in and must run only in their dedicated
native CI environment. Do not run their `/opt/rtsp-proxy/current` fixture over
the running pilot installation. The installed pilot on grob remains 0.14.0.
