# Phase G sealed probe-input contract

- Date: 2026-08-30
- Last reviewed: 2026-08-31
- Status: five-line no-redirect sealed input, independent review and native
  amd64/arm64 controlled-artifact plus integrated success/denial matrix green;
  integrated failure matrix pending
- Production decision: NO-GO

## Scope

This slice implements the anonymous input primitive required by the isolated
probe boundary:

- one typed serializer/parser is shared with endpoint admission; only its
  canonical five-line ffconcat form is accepted: one literal IPv4 or bracketed
  IPv6 `rtsp://` authority with an explicit port, interleaved TCP, the
  controlled demuxer's `rtsp_flags=no_redirect` and a bounded canonical-decimal
  microsecond read/write timeout;
- the payload is capped at 16 KiB and rejects NUL, CR, extra directives,
  alternate transport and an out-of-policy timeout before any descriptor is
  created;
- Linux creates an anonymous `memfd` with `CLOEXEC` and applies
  `F_SEAL_WRITE`, `F_SEAL_GROW`, `F_SEAL_SHRINK` and `F_SEAL_SEAL`;
- receiver-side validation requires an unlinked regular file, all four seals,
  an exact stable size and the same canonical payload, then rewinds the shared
  file description without returning secret bytes to diagnostics; and
- every construction failure, including process-level interruption, closes
  the descriptor while preserving the primary and any cleanup failure.

The direct test on `grob` proved the descriptor was non-inheritable, rewound,
immutable and readable without mutation; it also proved an otherwise identical
unsealed memfd, a hostname target, a noncanonical timeout and a backslash path
were rejected, and that interruption after descriptor creation did not leak
the secret fd. The temporary test tree was removed afterward.

The Linux-specific sealed-input suite then passed in the amd64 and arm64
`test` jobs, while all seven jobs completed successfully in
[CI run 33281241877](https://github.com/zl0nline/RTSP_proxy/actions/runs/33281241877)
at commit `3f7f400`.

## Deliberately excluded

This primitive does not itself run ffprobe. The exact-source controlled binary,
redirect contract, architecture digests and release admission are now complete.
A separately documented transport covers authenticated `SO_PEERCRED` plus one
`SCM_RIGHTS` descriptor, and a socket-activated root service/system-manager/BPF
executor now exists as an unpromoted integrated candidate. CI run 33426435190
proves its sealed-descriptor handoff, attach/readback-before-release, decoded
H264 result, policy denial and successful-path zero residue on amd64 and arm64.
The bounded timeout/cancellation/output-flood/restart failure matrix remains
pending. Consequently ADR 0004 stays Proposed, production scheduling stays
disabled and Phase G remains IN PROGRESS / Production NO-GO.
