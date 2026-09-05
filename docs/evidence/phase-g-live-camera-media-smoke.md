# Phase G: live-camera media smoke, 2026-09-05

Result: PASS for the isolated media-adapter scenario. This is not a production
readiness or full Dashboard acceptance result.

## Environment and safety

The check ran on the authorized Linux pilot host against the working camera.
It used the installed 0.14.0 MediaMTX/FFmpeg binaries and the current checkout's
`MediaMtxClient`. A separate unprivileged proxy listened only on randomly
allocated loopback RTSP/API ports. The installed node, database, release symlink
and systemd services were not modified.

Camera credentials entered through SSH stdin, not command arguments or files.
The source URL was delivered to the loopback MediaMTX API in memory. Proxy
configuration used an anonymous descriptor; process logs were discarded. The
reader's command line contained only the credential-free loopback proxy URL.
Both test processes were stopped in a bounded `finally` cleanup.

## Observations

- A real upstream RTSP/TCP source produced decoded video: the first sampled
  progress event reported 23 frames.
- While that reader remained connected, a second ffprobe reader was rejected
  with RTSP **453**.
- Registering another on-demand path through the production media adapter did
  not restart the proxy or disconnect the existing reader. Its decoded frame
  count advanced to 53; the API still reported one reader and a ready path.
- The additional path was removed after the check. It was not read and therefore
  did not create a second upstream pull to the same physical camera.
- The installed web, auth, collector, node-runtime and reconciler services were
  active after the test; `current` remained `releases/0.14.0`.
- Separately, all four synthetic RTSP transparency contracts passed on this
  host with the installed binaries (`tests/contract/test_rtsp_transparency.py`,
  90.60 seconds). These used isolated listeners and synthetic media.

## Limits

This proves a short real-camera check of the media adapter and one-reader
behavior, not camera creation through Dashboard, ACL/authentication behavior,
health-worker safety, codec coverage, 100-camera capacity or a 24-hour soak.
Synthetic native CI contracts remain the reproducible regression suite. Camera
addresses and credentials are deliberately omitted from this evidence.
