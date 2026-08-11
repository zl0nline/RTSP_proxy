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
| Maximum source RTSP sessions | Measured under current load |
| Proxy downstream readers | Exactly one; second client must receive RTSP 453 |

## Required evidence

- ordinary FFmpeg `rtsp://` DESCRIBE/SETUP/PLAY/TEARDOWN;
- source outage and recovery;
- main/sub path validation;
- cold start at typical and worst GOP;
- additional-session preflight under existing load;
- credential encoding cases without log leakage.

Unknown GOP or session limit blocks migration unless the owner records an
explicit risk acceptance.

The camera record also carries placement-independent access policy: normalized
`internet` and `local` CIDRs plus downstream credentials. Empty CIDR sets mean
allow-all at IP stage. Moving a camera to another media node may change its
external port/URL but does not change the source profile.
