# Phase G Linux probe execution boundary

Date: 2026-08-29

Scope: the production execution boundary required by
[`ADR 0004`](../adr/0004-isolated-probe-execution-boundary.md), for direct
Linux deployments on amd64 and arm64. This note evaluates systemd 259,
cgroup-BPF IP filtering, transient identities, secret-bearing file descriptor
transport, and the pinned FFmpeg source revision. It does not approve a
production probe runner.

## Verdict

The boundary is implementable, but only as a **system-manager transient
service created by a narrow privileged broker**. A per-user transient unit is
not an acceptable security boundary. The control-plane UID must not receive
generic `org.freedesktop.systemd1.manage-units` authority.

The current production decision remains **NO-GO** until the privileged native
Linux spikes listed below pass independently on amd64 and arm64. In particular:

- systemd accepts `IPAddressDeny=`/`IPAddressAllow=` even when their BPF
  enforcement is unavailable and applies the firewall best-effort;
- those properties restrict addresses, not destination ports;
- the pinned FFmpeg RTSP demuxer follows RTSP 3xx redirects; and
- the concat demuxer can log the full nested URL, including credentials, on an
  error.

Therefore property acceptance, `systemctl show`, a successful
`systemd-run --user`, and hiding the URL from argv are each insufficient
evidence. Production admission requires a behavioural egress canary, a
redirect-refusal solution, and native `/proc`/log/cleanup evidence.

A system-manager transient service alone cannot enforce an exact approved
`IP:port`: systemd's documented filter vocabulary ends at address prefixes.
Meeting that stricter boundary requires a port-aware kernel guard in addition
to systemd's address filter, or a documented relaxation of the requirement.

The observed `grob` result is consistent with upstream implementation, not an
unexplained host anomaly. On Ubuntu 26.04 amd64 with
`systemd 259.5-0ubuntu3.4`, cgroup v2 and Linux 7.0,
`systemd-run --user -p IPAddressDeny=any` accepted the setting but both the
supposedly denied loopback and external `connect_ex` calls succeeded. This is
negative evidence for the user-manager boundary; it is not evidence about the
system manager, which still requires a privileged behavioural test.

A follow-up system-manager spike on the same host answered the exact-port
question positively. A `DynamicUser` transient service with systemd's literal
loopback allow rules reached two listeners on each allowed IPv4/IPv6 address.
The next service was held behind a run gate while root attached project-owned
cgroup `connect4` and `connect6` programs; after release it reached only the
configured port and the second port failed for both families. Explicit detach
left no project BPF pin, transient unit, cgroup, runtime directory or process.
The throwaway primary source is branch `prototype/phase-g-connect-guard`, commit
`f984814`. This validates the kernel mechanism on amd64, not the production
broker, credential/no-redirect boundary or arm64 parity.

## Primary-source findings

### `StartTransientUnit` and `systemd-run --pipe`

`StartTransientUnit()` creates and starts a uniquely named transient unit and
takes its unit settings as typed property pairs. The transient unit is released
when it is no longer running or referenced. The system-manager operation is
protected by the broad `org.freedesktop.systemd1.manage-units` polkit action
([systemd v259 D-Bus contract](https://github.com/systemd/systemd/blob/v259/man/org.freedesktop.systemd1.xml#L1597-L1606),
[security contract](https://github.com/systemd/systemd/blob/v259/man/org.freedesktop.systemd1.xml#L1915-L1934)).

The authorization check is performed using the requested unit name and `start`
verb **before** the transient properties are parsed. Consequently, a polkit
rule that only restricts the name to `rtsp-probe-*.service` still lets that
caller choose `ExecStart`, `User`, capabilities and sandbox properties. This
would be an unsafe privilege delegation to the web or scheduler process
([systemd v259 implementation](https://github.com/systemd/systemd/blob/v259/src/core/dbus-manager.c#L1115-L1157)).

`systemd-run --pipe` is a useful executable reference for the native spike. It
passes its original stdin, stdout and stderr descriptors to the service as-is
and waits for the service to terminate
([systemd v259 manual](https://github.com/systemd/systemd/blob/v259/man/systemd-run.xml#L374-L407)).
Its implementation sends the three descriptors as
`StandardInputFileDescriptor`, `StandardOutputFileDescriptor` and
`StandardErrorFileDescriptor` properties in the transient-unit D-Bus request
([systemd v259 source](https://github.com/systemd/systemd/blob/v259/src/run/run.c#L1504-L1524)).
This mode is service-only, local-only and incompatible with `--no-block`; it is
not a scope boundary
([systemd v259 source](https://github.com/systemd/systemd/blob/v259/src/run/run.c#L837-L849)).

Production should call `StartTransientUnit` from the broker directly rather
than spawn a shell or expose a general `systemd-run` interface. The broker must
construct an immutable property set and fixed executable argv; its IPC schema
must not accept arbitrary unit names, properties, executable paths or argv.

### Why the user manager is rejected

systemd 259 explicitly refuses `DynamicUser=yes` for a user-manager unit
([systemd v259 source](https://github.com/systemd/systemd/blob/v259/src/core/unit.c#L4302-L4317)).
`ProtectProc=` and `ProcSubset=` are system-service-only settings
([systemd v259 contract](https://github.com/systemd/systemd/blob/v259/man/system-only.xml#L8-L15)).

More importantly, the IP firewall is implemented by loading and attaching
cgroup-BPF programs. The implementation warns that it is “not running as root”
when the operation fails for privilege reasons
([systemd v259 source](https://github.com/systemd/systemd/blob/v259/src/core/bpf-firewall.c#L787-L807)).
Normal cgroup `Delegate=` hands a service ownership of a cgroup subtree; it is
not proof that the delegate can load and attach network BPF programs
([systemd v259 resource-control contract](https://github.com/systemd/systemd/blob/v259/man/systemd.resource-control.xml#L1379-L1406)).
systemd's newer BPF-token delegation is a separate `PrivateBPF=` plus
`BPFDelegate*=` mechanism with kernel and user-namespace dependencies, not an
implicit property of a user manager
([systemd v259 execution contract](https://github.com/systemd/systemd/blob/v259/man/systemd.exec.xml#L2573-L2603)).

The project should let host PID 1 attach the filter. It should not delegate BPF
capabilities or a BPF token to the control plane or probe process.

### `IPAddressDeny`/`IPAddressAllow` are necessary but not self-proving

For egress traffic, systemd checks the destination IPv4/IPv6 address. An allow
match wins first, then a deny match, otherwise traffic is allowed. Parent-slice
lists are combined with the leaf unit's lists. Upstream recommends
`IPAddressDeny=any` on an upper-level slice plus per-service allows
([systemd v259 contract](https://github.com/systemd/systemd/blob/v259/man/systemd.resource-control.xml#L766-L812)).

That supports this structure:

```text
rtsp-probe.slice:                  IPAddressDeny=any
  rtsp-probe-<random>.service:     IPAddressAllow=<literal>/32 or <literal>/128
```

It does **not** provide a fail-closed guarantee by itself. systemd explicitly
states that the settings have no effect when cgroup-BPF support is unavailable
and advises against relying on them exclusively for IP security
([systemd v259 contract](https://github.com/systemd/systemd/blob/v259/man/systemd.resource-control.xml#L861-L868)).
The implementation calls firewall application “best-effort”, returns when
compilation fails, and ignores load/install errors
([systemd v259 source](https://github.com/systemd/systemd/blob/v259/src/core/cgroup.c#L1308-L1319));
the BPF layer itself says it proceeds without a firewall when support is absent
([compile path](https://github.com/systemd/systemd/blob/v259/src/core/bpf-firewall.c#L537-L556),
[install path](https://github.com/systemd/systemd/blob/v259/src/core/bpf-firewall.c#L678-L707)).

There are two additional limitations:

1. `IPAddressAllow=` accepts an address/prefix, not a destination port. It
   cannot alone pin `192.0.2.10:554` rather than every port on `192.0.2.10`.
2. An inherited socket from a socket unit is governed by the socket unit's
   policy, not retroactively by the activated service's policy. The probe must
   create its own camera socket; the broker must not pass a connected Internet
   socket into it
   ([systemd v259 contract](https://github.com/systemd/systemd/blob/v259/man/systemd.resource-control.xml#L803-L809)).

For exact `IP:port` enforcement, the smallest compatible follow-up is a
root-owned cgroup `connect4`/`connect6` BPF guard that rejects every connect
whose destination address **or** network-byte-order `user_port` differs from
the admitted tuple. Linux exposes those attach types and fields directly
([Linux 7.0 BPF program types](https://github.com/torvalds/linux/blob/v7.0/Documentation/bpf/libbpf/program_types.rst#L35-L48),
[`bpf_sock_addr` ABI](https://github.com/torvalds/linux/blob/v7.0/include/uapi/linux/bpf.h#L6865-L6890)).
It must be attached by the trusted root boundary before the launcher receives
the credential or any run gate is released; the application and probe receive
no BPF capability. This is a proposed mechanism, not an accepted design, until
the native spike proves race-free attachment, inheritance, IPv4/IPv6 matching,
cleanup and fail-closed startup on both architectures.

The operational gate must therefore exercise the actual transient-service path:
one admitted address must be reachable and at least one denied IPv4 and denied
IPv6 address must remain unreachable. An inconclusive or skipped canary disables
deep probes. `systemctl show` is diagnostic evidence only.

### `DynamicUser` and `/proc`

`DynamicUser=yes` assigns a transient UID/GID and releases it after the unit
stops. It also implies `RemoveIPC=`, `NoNewPrivileges=`,
`RestrictSUIDSGID=`, `ProtectSystem=strict` and `ProtectHome=read-only`.
The UID can later be reused, so the probe must not leave persistent files owned
by it
([systemd v259 contract](https://github.com/systemd/systemd/blob/v259/man/systemd.exec.xml#L694-L735)).

`ProtectProc=invisible` hides other users' process metadata from the service,
but root and `CAP_SYS_PTRACE` are unaffected. It can also become a no-op on a
kernel without per-mount `hidepid` support. It must be paired with a non-root
identity and an empty capability set, then verified behaviourally
([systemd v259 contract](https://github.com/systemd/systemd/blob/v259/man/systemd.exec.xml#L392-L421)).
`ProcSubset=pid` hides non-process `/proc` APIs, but upstream warns it is not
suitable for most non-trivial programs; ffprobe compatibility must be proven
before enabling it
([systemd v259 contract](https://github.com/systemd/systemd/blob/v259/man/systemd.exec.xml#L425-L444)).

`ProtectProc=` primarily limits what the probe sees from inside its mount
namespace. It does not make host root unable to inspect the probe. Protection
from the control-plane UID also depends on the separate `DynamicUser` UID and
normal `/proc/<pid>/fd` ptrace access checks. Root remains part of the trusted
computing base.

### Secret transport: credential IPC, pipe and sealed memfd

Plain `SetCredential=` is rejected for camera secrets: upstream says its
literal value is accessible to unprivileged processes through IPC. In contrast,
`LoadCredential=` can read once from an absolute AF_UNIX stream socket, and
systemd copies the value into a read-only, per-unit credential location backed
by non-swappable memory when possible. The location is accessible to the
unit's `User=`/`DynamicUser=` and root
([systemd v259 credential contract](https://github.com/systemd/systemd/blob/v259/man/systemd.exec.xml#L3752-L3790),
[plaintext warning](https://github.com/systemd/systemd/blob/v259/man/systemd.exec.xml#L3944-L3962)).

There are two viable implementations, both requiring the native spike:

- preferred wrapper design: the transient launcher receives a fixed
  `LoadCredential=source:<AF_UNIX socket>` credential, constructs exactly one
  ffconcat record in memory, and feeds it to its ffprobe child through an
  anonymous pipe;
- sealed-memfd design: the credential component creates a constant-named,
  size-bounded memfd, writes the generated ffconcat record, rewinds it and adds
  `F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL`; the broker transfers
  the descriptor to the transient service and promptly closes every extra
  copy.

`memfd_create()` creates an anonymous RAM-backed file. Its diagnostic name is
visible under `/proc/<pid>/fd`, so the name itself must never contain camera or
credential data. `MFD_ALLOW_SEALING` enables seals; `MFD_CLOEXEC` closes the
descriptor across `execve()` unless the caller explicitly duplicates or
transfers it as an inherited non-CLOEXEC descriptor
([Linux `memfd_create(2)`](https://man7.org/linux/man-pages/man2/memfd_create.2.html)).

Both transports keep the URL out of `/proc/<pid>/cmdline` and
`/proc/<pid>/environ`; neither removes it from kernel pipe/memfd pages or
ffprobe memory while the probe runs. Different UID isolation, bounded lifetime,
closing descriptors and the `/proc` tests remain mandatory.

### The pinned ffprobe can read an RTSP URL from `pipe:` or `fd:`

The audited project build identifies FFmpeg source commit
[`9b6c8969e05b4f0b29f0f85cd501be6b3e582e6b`](https://github.com/FFmpeg/FFmpeg/tree/9b6c8969e05b4f0b29f0f85cd501be6b3e582e6b).
At that exact revision:

- `pipe:` defaults to fd 0 for input and can address another numeric inherited
  descriptor
  ([FFmpeg source](https://github.com/FFmpeg/FFmpeg/blob/9b6c8969e05b4f0b29f0f85cd501be6b3e582e6b/libavformat/file.c#L439-L482));
- `fd:` reads the descriptor selected with its `fd` option and detects whether
  that descriptor is seekable
  ([FFmpeg source](https://github.com/FFmpeg/FFmpeg/blob/9b6c8969e05b4f0b29f0f85cd501be6b3e582e6b/libavformat/file.c#L486-L528));
- the concat demuxer accepts a protocol-bearing `file` entry when `safe=0`
  ([FFmpeg source](https://github.com/FFmpeg/FFmpeg/blob/9b6c8969e05b4f0b29f0f85cd501be6b3e582e6b/libavformat/concatdec.c#L95-L143));
- per-file `option` directives are supported only in unsafe mode and are
  supplied to the nested input
  ([directive parsing](https://github.com/FFmpeg/FFmpeg/blob/9b6c8969e05b4f0b29f0f85cd501be6b3e582e6b/libavformat/concatdec.c#L444-L458),
  [option application](https://github.com/FFmpeg/FFmpeg/blob/9b6c8969e05b4f0b29f0f85cd501be6b3e582e6b/libavformat/concatdec.c#L551-L593)); and
- the concat demuxer copies the outer protocol allow/deny lists into the nested
  input before opening it
  ([FFmpeg source](https://github.com/FFmpeg/FFmpeg/blob/9b6c8969e05b4f0b29f0f85cd501be6b3e582e6b/libavformat/concatdec.c#L336-L365)).

The fixed conceptual input is:

```text
ffconcat version 1.0
file 'rtsp://<percent-encoded-user>:<percent-encoded-password>@<literal>:<port>/<canonical-path>'
option rtsp_transport tcp
option rw_timeout <bounded-microseconds>
```

The fixed ffprobe argv uses `-v quiet`, `-f concat`, `-safe 0`, and an exact
protocol whitelist. The working pinned-build pipe case required
`file,pipe,rtsp,rtp,tcp`; a future fd case should substitute `fd` for `pipe`
only after it passes the native matrix. UDP, HTTP, HTTPS, TLS and arbitrary
other nested protocols are not admitted. Because concat unsafe mode makes
`file` and `rtp` available to the nested stack, strict launcher-side script
generation and the network boundary remain essential. FFmpeg documents that
`rtsp_transport=tcp` selects RTP interleaving on the RTSP control channel
([FFmpeg protocol contract](https://github.com/FFmpeg/FFmpeg/blob/9b6c8969e05b4f0b29f0f85cd501be6b3e582e6b/doc/protocols.texi#L1321-L1355)).

Because `safe=0` is required, the launcher—not an operator string—must generate
the entire script. It must parse and canonicalize the source first,
percent-encode userinfo and unsafe path bytes, bracket IPv6 literals, and reject
NUL, CR and LF. Exactly one `file` and an allowlisted set of `option` directives
are permitted.

A bounded amd64 `grob` compatibility run provides mechanism evidence for this
path. The pinned `ffprobe n8.1.2` read a script from `pipe:0` and connected to an
ordinary TCP-only GStreamer RTSP generator. The script used
`option rtsp_transport tcp` and `option rw_timeout 5000000`; argv was limited to
`-v quiet -f concat -safe 0 -protocol_whitelist file,pipe,rtsp,rtp,tcp -i
pipe:0`, and neither `/proc/<pid>/cmdline` nor `/proc/<pid>/environ` contained
the secret. Without quiet logging, stderr repeated the full credential-bearing
nested URL. This test does not establish arm64 compatibility, system-manager
isolation, fd-content secrecy or egress enforcement.

### Two stock-FFmpeg blockers

FD transport alone does not protect logs. On an input error, the concat demuxer
logs `file->url` verbatim
([exact pinned source](https://github.com/FFmpeg/FFmpeg/blob/9b6c8969e05b4f0b29f0f85cd501be6b3e582e6b/libavformat/concatdec.c#L360-L369)).
The service must therefore use `-loglevel quiet`, must not send ffprobe stderr
to journald, and must map the exit status to a closed sanitized failure enum.
Only a size-bounded stdout pipe is parsed. `format.filename`, raw metadata,
free-form errors and unrequested fields are not admitted to the result.

The pinned RTSP demuxer also follows any 3xx response carrying `Location:` and
restarts its connection loop with the returned URL
([exact pinned source](https://github.com/FFmpeg/FFmpeg/blob/9b6c8969e05b4f0b29f0f85cd501be6b3e582e6b/libavformat/rtsp.c#L2179-L2197)).
It rejects a redirected scheme other than `rtsp`, `rtsps` or `satip`, but it
does not expose a no-follow option in this path
([protocol check](https://github.com/FFmpeg/FFmpeg/blob/9b6c8969e05b4f0b29f0f85cd501be6b3e582e6b/libavformat/rtsp.c#L1910-L1924)).

`IPAddressAllow=` blocks a redirect to another address when BPF enforcement is
working, but it permits another port on the same admitted address. That is not
the “redirects fail” evidence required by ADR 0004. Before production, the
project needs one of these reviewed solutions:

1. a controlled, provenance-retained ffprobe build with a minimal option/patch
   that refuses RTSP 3xx before following `Location:`; or
2. a separate exact address-and-port connect guard plus an explicit ADR change
   accepting same-endpoint redirects.

Option 1 matches the current ADR. The existing third-party ffprobe artifact is
therefore adequate for compatibility work, not production source probes.

## Proposed fail-closed boundary

```text
scheduler (no secret, no system bus privilege)
    -> admission/credential service (camera ID, DNS/CIDR policy, secret access)
        -> authenticated AF_UNIX IPC: immutable literal target + one-time ref
            -> narrow root broker (fixed policy and StartTransientUnit only)
                -> system PID 1 -> rtsp-probe-<random>.service
                    -> DynamicUser launcher -> pipe/memfd -> pinned ffprobe
                <- bounded sanitized JSON / closed failure enum
```

The components and checks are:

1. The admission service resolves once, rejects non-RTSP schemes, user-supplied
   redirect material, NUL/CR/LF, and all IPv4/IPv6 special, metadata,
   loopback, link-local and management ranges except explicitly configured
   camera-network CIDRs. It emits one canonical literal address, port, path,
   desired revision and placement generation.
2. The broker authenticates the peer with AF_UNIX filesystem permissions and
   `SO_PEERCRED`, enforces a small length-delimited schema, revalidates the
   literal/CIDR/port bounds, consumes a one-time credential reference and never
   logs request bytes. No shell is involved.
3. The broker alone calls the system manager. It creates a random unit name,
   pins it to `rtsp-probe.slice`, supplies the fixed executable path and argv,
   and never accepts caller-provided systemd properties.
4. The transient service has, at minimum, `Type=exec`, `DynamicUser=yes`,
   `ProtectProc=invisible`, an empty capability/ambient-capability set,
   `NoNewPrivileges=yes`, `PrivateTmp=disconnected`, `PrivateDevices=yes`,
   `ProtectSystem=strict`, `ProtectHome=yes`, kernel/control-group protections,
   `RestrictSUIDSGID=yes`, `LockPersonality=yes`, `RestrictRealtime=yes`, a
   narrow `RestrictAddressFamilies=`, `SocketBindDeny=any`, and no writable
   persistent directory. `ProcSubset=pid` is enabled only after compatibility
   evidence.
5. The leaf receives `IPAddressDeny=any` and exactly one
   `IPAddressAllow=<literal>/32|/128`; the parent slice retains its own
   `IPAddressDeny=any` defense. The ffprobe script repeats only that literal and
   uses TCP interleaving. If exact-port isolation remains required, the root
   boundary also attaches the verified `connect4`/`connect6` tuple guard before
   releasing the credential/run gate.
6. `MemoryMax`, `MemorySwapMax`, `TasksMax`, `LimitNOFILE`, CPU quota,
   `RuntimeMaxSec`, `TimeoutStopSec`, `KillMode=control-group` and
   `SendSIGKILL=yes` are finite. `RuntimeMaxSec` requires a non-oneshot service;
   `KillMode=control-group` kills all remaining descendants and is the default
   recommended lifecycle mode
   ([runtime limit](https://github.com/systemd/systemd/blob/v259/man/systemd.service.xml#L745-L764),
   [kill semantics](https://github.com/systemd/systemd/blob/v259/man/systemd.kill.xml#L63-L103)).
7. ffprobe stderr is `/dev/null` or a non-logging bounded sink. stdout is capped
   before JSON parsing; exceeding the cap stops the whole unit. The parser
   allowlists codec/profile fields and returns no URL, IP, credential, raw
   metadata or raw ffprobe error.
8. Timeout, cancellation, output overflow, policy uncertainty, BPF-canary
   failure, release-hash mismatch and result-contract failure all produce a
   closed executor failure. None can mark the camera healthy.

The broker is a small privileged trust boundary and should itself be a hardened
system service with no external network access. Granting a less-privileged
broker `manage-units` through a unit-name-only polkit rule is not an equivalent
design because the authorized transient properties remain arbitrary.

## Required privileged native-Linux spikes

All results are architecture-local. An amd64 pass does not admit arm64, and a
kernel/systemd upgrade invalidates the enforcement preflight until rerun.

1. **System-manager BPF enforcement:** as root, create the real parent slice
   and exact transient service. Prove admitted IPv4/IPv6 access succeeds while
   denied loopback, metadata, link-local and second-address traffic fails.
   Repeat a deliberately unsupported/misconfigured case and prove the platform
   disables probes rather than continuing. With two listeners on the admitted
   IP, first demonstrate that `IPAddressAllow=` alone permits the wrong port,
   then attach the tuple-aware `connect4`/`connect6` guard and prove only the
   exact admitted port works, including before credential release and after
   cancellation/reuse.
2. **Port and redirect containment:** prove a camera endpoint cannot cause a
   connection to another address or port. Exercise RTSP 301/302/303, DNS
   rebinding, alternate schemes and IPv4-mapped IPv6. Select and verify the
   no-follow ffprobe build/patch before ADR 0004 can be accepted.
3. **System D-Bus authority:** prove the application UID cannot call
   `StartTransientUnit`, `systemd-run` or alter `rtsp-probe.slice`; prove only
   the broker socket's expected peer can request a fixed probe; fuzz the broker
   schema and reject arbitrary argv/property injection.
4. **Descriptor and credential secrecy:** inspect `cmdline`, `environ`, `fd`,
   unit properties, journal and process listings from the control-plane UID,
   another service UID and a concurrent probe UID. Test normal success, auth
   failure, malformed input and cancellation. Root visibility is expected and
   documented as trusted.
5. **systemd credential or SCM_RIGHTS lifecycle:** verify one-time AF_UNIX
   credential reads or sealed-memfd transfer, seal validation, descriptor
   closure, unit garbage collection and zero readable residue after completion.
6. **Whole-cgroup termination:** force timeout, parent/child hangs, output
   flood and cancellation. Prove no remaining PID, fd, memfd, credential
   directory, cgroup or attached-BPF leak after repeated runs.
7. **Hard limits:** exhaust stdout, stderr, RSS, CPU, PIDs and FDs independently
   and prove bounded termination plus a credential-free result for each case.
8. **Sandbox compatibility:** run the exact release ffprobe/launcher with every
   proposed systemd property. In particular, test `ProcSubset=pid`, address
   families, syscall filtering and `MemoryDenyWriteExecute` instead of assuming
   they are compatible.

The same pinned ffprobe must also pass non-privileged compatibility cases on
both architectures: pipe and memfd input, credentials containing reserved
characters, bracketed IPv6, video-only, audio-only, mixed streams, malformed
JSON, and strict output-field selection. These tests alone do not replace the
privileged boundary matrix.

## Acceptance consequence for ADR 0004

ADR 0004 may move from Proposed to Accepted only after the selected broker,
credential transport, no-follow ffprobe build and behavioural egress policy
pass the full privileged matrix on native Linux amd64 and arm64. Until then the
safe implementation scope is scheduler, persistence, UI and synthetic/path
probe foundations that do not ship the production source-probe executor.
