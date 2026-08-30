# Phase G sealed probe-input contract

- Date: 2026-08-30
- Status: four-line base implementation and native matrix green; mandatory
  five-line no-redirect extension implemented locally, review/CI pending
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

This primitive does not run ffprobe. An exact-source controlled candidate and
behavioral redirect contract now exist, but architecture digests and release
admission are not yet complete. A separately documented transport
primitive now covers authenticated `SO_PEERCRED` plus exactly one `SCM_RIGHTS`
descriptor, but it is not a deployed root service. The broker service,
system-manager unit, BPF attach/readback/run gate, controlled ffprobe promotion,
bounded output and complete cancellation/residue matrix remain required. Consequently
ADR 0004 stays Proposed, the production executor stays disabled and Phase G
remains IN PROGRESS / Production NO-GO.
