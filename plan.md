# python-AiDot — Pre-Publication Status

*Last updated: 2026-05-30  |  Branch: claude/fix-camera-user-info-eL6Pt*

This is a camera-capable fork of the lights-only upstream
`AiDot-Development-Team/python-aidot`. **All camera functionality here is
original** — upstream (library and HA component) has no camera code.

---

## Status Summary

| Area | Status |
|---|---|
| SDES streaming (A001513 / A001064) | ✅ Complete and confirmed |
| DTLS streaming (A000088) | ✅ Complete; reliability fixed (cert + reorder + retry) |
| DTLS audio cutoff (~25s) | ✅ Resolved — verified audio runs full session |
| Camera controls + PTZ | ✅ Complete |
| Snapshots (live + SDES frame-extract) | ✅ Complete |
| Cloud recordings + thumbnails | ✅ Complete (auth fixed) |
| Two-way audio (talk) — DTLS path | ✅ Implemented + live-confirmed |
| Two-way audio — SDES path | ⏳ Future (avSendAudioData + SFrameInfo) |
| MQTT parity (APK-accurate) | ✅ Complete — getDevAttrReq removed |
| HA custom component | ✅ Complete + reviewed; light/camera/switch/select/number/button |
| HA manifest installable | ✅ Real deps listed; lib installed from git (README) |
| Credential storage | ✅ Fernet-encrypted, cross-platform |
| Security audit | ✅ Complete |
| Validation pass (pre-review) | ⏳ In progress |
| Code review | ⏳ Pending |
| Git squash for publication | ⏳ Outstanding (task #49) |

---

## Recently resolved (this work cycle)

- **#42 DTLS reliability** — three fixes:
  - `915e3652` old-pyOpenSSL cert incompatibility (the Pi's 100% failure) +
    `_send_rtcp_pli` signature fix (restored video decode).
  - `656561b1` rebuild reordered/4-section H265 camera answers.
  - `5f1501e1` bounded connect retry (`--webrtc-retries`, default 3) for the
    intermittent ICE port-nomination issue (camera exposes two candidate pairs;
    aioice picks the wrong port ~50% of the time — root cause confirmed via
    port-traffic analysis; retry re-rolls and reliably connects).
  - Audio-cutoff verified gone: ffprobe of a 40s recording shows the audio
    stream running the full session.
- **#45 two-way audio (DTLS)** — `5b2d6862` PCMA sender track + SPEAKERSTART(848),
  `--talk` CLI flag, pure-Python A-law encoder (`tools/g711_tone.py`).
- **#48 siren + speaker_volume** HA entities.
- **#50 manifest pin** — replaced unsatisfiable `python-aidot>=0.4.0` with real
  third-party deps; library installed from git (documented in README).
- **#46/#47** cloud-recording auth + speculative-auth cleanup.

---

## Outstanding before publication

1. **Validation pass** (this cycle) — exercise every feature against live
   cameras and record pass/fail.
2. **Code review** — `/code-review` on the branch diff.
3. **#49 Git squash** — collapse the branch into clean logical commits.

## Future / non-blocking

| Item | Notes |
|---|---|
| SDES-path two-way audio | TUTK `avSendAudioData` + `SFrameInfo` (separate transport from DTLS) |
| HA two-way-audio entity | Bridge browser mic → camera (go2rtc/WebRTC backhaul) |
| `#35` Frida intercept | Blocked on AVD/hardware; protocol already understood without it |
| Deeper ICE fix | Override aioice nomination to follow the camera's active port (high risk; retry suffices) |

---

## Architecture (quick reference)

- **Lights:** fully local (TCP 10000, AES) after credential cache.
- **Cameras:** cloud MQTT broker (`{region}-mqtt.arnoo.com`) for signaling;
  WebRTC media is pure LAN once ICE completes.
- **DTLS path (A000088):** aiortc; video H264, audio PCMA both directions.
- **SDES path (A001064/A001513):** hand-built SDP + ffmpeg; SCTP inside 0xC8.
- **Thumbnails/recordings:** cloud-only (`{region}-smarthome.arnoo.com`).
- **HA video:** go2rtc RTSP republish; `async_stream_source()` returns the RTSP URL.
