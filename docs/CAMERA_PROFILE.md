# Camera profile contract

A camera model/firmware profile is required before production admission and is
complete before pilot 100.

## Identity

| Field | Requirement |
|---|---|
| Vendor/model | Exact manufacturer and model |
| Firmware | Exact tested version/range |
| Profile owner | Person/team responsible for validation |
| Evidence date | Date of the latest compatibility run |

## Media contract

| Field | Requirement |
|---|---|
| Main/sub paths | Canonical paths, no guessed discovery outside allowlist |
| Codec/audio | H264/H265 and audio layout |
| Bitrate/packet rate | Typical and measured peak |
| GOP/keyframe interval | Typical and worst supported value |
| RTSP transport | TCP interleaved must pass |
| Keepalive/timeouts | Observed camera behavior |
| Maximum concurrent RTSP sessions | Measured under current load |

## Required evidence

- ordinary FFmpeg `rtsp://` DESCRIBE/SETUP/PLAY/TEARDOWN;
- source outage and recovery;
- main/sub path validation;
- cold start at typical and worst GOP;
- additional-session preflight under existing load;
- credential encoding cases without log leakage.

Unknown GOP or session limit blocks migration unless the owner records an
explicit risk acceptance.
