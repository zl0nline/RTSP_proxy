# Phase G: cooperative caller and broker shutdown cancellation

Status: cancellation slice verified on native amd64/arm64; production worker remains disabled.
This slice does not enable the production probe worker or accept ADR 0004.

## Contract

- The unprivileged client accepts an optional `cancelled` predicate. Cancellation
  before input creation has no IPC side effect. During response wait, including
  a fragmented header/body, cancellation returns only `INCONCLUSIVE/EXECUTOR`
  and closes the request's socket. It is never a camera-health failure.
- Each broker request owns one authenticated connection. EOF, connection error,
  or unexpected extra request bytes cancel that execution only. No separate
  request-ID cancellation endpoint or cross-request authority is introduced.
- Shutdown closes admission and publishes cancellation before joining workers.
  This applies to explicit shutdown, listener failure and the existing
  SIGINT/SIGTERM handler's `SystemExit`. Cleanup failures also cancel active work.
- The coordinator checks cancellation between ownership handoffs and immediately
  before gate release. Waiting for executor output polls cancellation at 100 ms.
  Already-running bounded systemd/BPF setup calls finish their bounded operation
  before cancellation is observed; this is cooperative, not asynchronous thread
  interruption. Existing absolute execution and cleanup deadlines still apply.
- Cleanup is not cancellable: collect the exact unit first, then release its
  guard, channels and sealed input. Failed cleanup retains ownership for retry
  and closes broker admission. A cancelled caller does not receive an assurance
  that privileged cleanup has already completed.

## Verification

`tests/test_probe_cancellation.py` exercises real Linux socket/credential/fd
transport, including stalled and partial responses, caller cancellation and
service shutdown. Coordinator tests cover cancellation before allocation,
after unit start and after guard installation, with no gate release. The pipe
test proves a 30-second output wait can be cancelled without waiting its deadline.

Linux pilot scratch checkout (not installed release): 212 focused tests passed,
then 50 transport/cancellation tests passed after fixing the final-response race.
Full Linux suite with PostgreSQL: 1657 passed, 49 opt-in contracts skipped.
Standards review: zero actionable findings. Spec review: two findings fixed
(response completion race and nondeterministic partial-frame synchronization),
then PASS. All nine jobs, including the installed privileged caller/shutdown
contracts on amd64/arm64, passed in
[CI run 33959755605](https://github.com/zl0nline/RTSP_proxy/actions/runs/33959755605),
commit `443320c`.

```sh
uv run pytest -q tests/test_probe_execution.py tests/test_probe_systemd.py \
  tests/test_probe_broker_service.py tests/test_probe_broker.py \
  tests/test_probe_client.py tests/test_probe_broker_runtime.py \
  tests/test_probe_cancellation.py
```

The privileged installed contract adds caller and shutdown cases against a
stalled synthetic source with a 60-second request deadline. It requires prompt
inconclusive completion, unit collection, BPF pin/receipt removal and continued
broker availability. Run only in the dedicated CI contract environment: it
uses `/opt/rtsp-proxy/releases/probe-contract`, not a running pilot installation.

Before broker promotion: the remaining network-policy contracts and ADR
acceptance. Real-camera smoke does not replace these cancellation/failure tests.
