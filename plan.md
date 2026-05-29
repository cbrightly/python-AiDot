# Plan: Fix Camera User Info ICE Failure (LK.IPC.A001064)

## Problem Summary

Camera `LK.IPC.A001064` ("Rear of Garage PTZ") fails WebRTC ICE after 30s.
The log shows ICE going from `checking` → `closed` without ever receiving STUN
probes from the camera or a real `webrtcResp` with camera ICE candidates.

Additionally, connection setup has unnecessary sequential delays that add up to
~10–17 s of overhead before ICE can even begin.

---

## Root Cause Analysis

### Confirmed observations from the log

1. `batchGetDeviceUserInfo` returns keys `['deviceId', 'userId', 'userUuid']`
2. We extract `userId` (numeric: `1348043005373399042`) but **never extract or use `userUuid`**
3. Camera only echoes our `webrtcReq` — no real `webrtcResp` or `iceCandidateReq` arrives
4. The echo-only path fires; synthetic ICE candidates are added at **wrong ports**:
   - `192.168.1.217:60705` and `192.168.1.217:47324` (our aiortc ports, not camera's)
5. ICE probes those wrong ports, gets no response, exhausts retransmissions → closed

### Root cause A: missing `userUuid` MQTT subscription (fixed — commit 8b74fa7)

When the camera sends its real `webrtcResp` (answer with its own SDP and ICE candidates),
it publishes to `iot/v1/c/{camera_userUuid}/IPC/webrtcResp`.

Previously we subscribed to:
- `iot/v1/c/{app_uuid}/#`
- `iot/v1/c/{device_id}/#`
- `iot/v1/c/{numeric_userId}/#`

If `camera_userUuid` ≠ any of those, the camera's real response was silently
dropped — we only saw broker echoes of our own messages.

### Root cause B: echo-only synthetic candidates use wrong ports (fixed — this PR)

When we fall into the echo-only path, `_rr_cam_ports` is populated from the
echo SDP (which is our own `webrtcReq`). Those ports are our aiortc-allocated
ports (e.g. 60705, 47324), not the camera's. Injecting synthetic host
candidates as `{camera_IP}:{our_port}` probes an address the camera never
listens on → ICE fails for the full timeout.

### Connection delay sources

| Phase | Current delay | Notes |
|---|---|---|
| `batchGetDeviceUserInfo` HTTP | up to 10 s | Was sequential before MQTT |
| `async_get_ice_config_http` HTTP | up to 10 s | Was sequential after user-info |
| Camera wake (`getIceConfigReq`) | up to 17 s (12 s + 5 s retry) | Waits for camera_ready_ev |
| `asyncio.sleep(0.5)` post-livePlayReq | 0.5 s fixed | Burns full time even on fast echo |
| Echo secondary wait | was 6 s | Waiting for camera's real response |

The two HTTP calls had no dependency on each other — parallelising them alone
saves up to ~10 s.

---

## Fixes Implemented

### Fix 1 (Primary — latency): Parallelize HTTP pre-flight calls

**File**: `aidot/device_client.py` — at `async_open_webrtc_stream` start

`batchGetDeviceUserInfo` and `async_get_ice_config_http` are now run
concurrently with `asyncio.gather` instead of sequentially.

```python
_fetch_http_ice = not _skip_ice_config and _ice_config is None
if _fetch_http_ice:
    _cam_user_info, _http_ice_config = await asyncio.gather(
        self.async_get_device_user_info(all_device_ids=...),
        self.async_get_ice_config_http(),
    )
else:
    _cam_user_info = await self.async_get_device_user_info(...)
    _http_ice_config = None
```

**Expected gain**: up to ~10 s on sessions where both HTTP calls take
meaningful time (common in practice — different API servers).

### Fix 2 (Latency): Replace `sleep(0.5)` with event-driven wait

**File**: `aidot/device_client.py` — post-livePlayReq wait

```python
# Old: await asyncio.sleep(0.5)
try:
    await asyncio.wait_for(liveplay_echo_ev.wait(), timeout=0.5)
except asyncio.TimeoutError:
    pass
```

Proceeds immediately when the broker echoes livePlayReq; falls through
after 0.5 s otherwise.

**Expected gain**: 0–0.4 s when broker acknowledges quickly.

### Fix 3 (Latency): Reduce echo secondary wait 6 s → 3 s

**File**: `aidot/device_client.py` — echo-only detection block

The secondary wait for the camera's real `webrtcResp` (after an echo is
received) was 6 s. With the userUuid subscription fix in place, a real
response arrives in <1 s if it's coming at all. 3 s is still generous.

**Expected gain**: 3 s saved for true echo-only cameras.

### Fix 4 (Connectivity): Guard echo-only synthetic candidate injection

**File**: `aidot/device_client.py` — role-reversal path

```python
# Old:
if _cam_local_ip and _rr_cam_ports and cam_ip_q.empty():
    cam_ip_q.put_nowait(_cam_local_ip)

# New:
if _cam_local_ip and _rr_cam_ports and cam_ip_q.empty() and not _rr_echo_only:
    cam_ip_q.put_nowait(_cam_local_ip)
```

For echo-only cameras, `_rr_cam_ports` contains **our** aiortc ports (from
the echoed SDP), not the camera's. Injecting synthetic host candidates at
`{camera_IP}:{our_port}` probes the wrong endpoint and burns the full ICE
timeout. Instead, the echo-only path relies on:

1. **Arnoo TURN relay** (already appended to `_ice_servers` when no TURN is in
   `getIceConfigResp`) — allows the camera to reach us via relay without
   knowing its direct IP/port.
2. **`second_answer_fut` candidates** (processed in the ICE wait loop) — if
   the camera sends a real `webrtcResp` after receiving our `webrtcResp`, its
   actual ICE candidates will be applied.

### Fix 5 (Diagnostics): Log echo-only skip reason

When echo-only path skips the cam_ip_q pre-seed, log the ports that were
skipped and why, so future debugging is easier.

---

## Earlier Fixes (already committed on this branch)

### Fix A: Subscribe to `userUuid` MQTT topics (commit 8b74fa7)

Extracts `userUuid` from `batchGetDeviceUserInfo` and subscribes to
`iot/v1/c/{userUuid}/#`, `iot/v1/cb/{userUuid}/#`, `lds/v1/c/{userUuid}/#`.

### Fix B: Add `wPayload.answer` to `webrtcResp` (commit 077faaf)

Newer firmware (LK.IPC.A001064) parses `payload.wPayload.answer.sdp` to
extract ICE credentials. Without this, the camera cannot form valid STUN
binding requests.

### Fix C: Flip DTLS to passive for echo-only cameras (commit b0a0fff)

For echo-only cameras, sending `setup:passive` in `webrtcResp` makes the
camera the DTLS active/client (ICE-controlling). The camera then allocates
a TURN relay and sends `iceCandidateReq` → ICE connects via relay.

---

## Implementation Order

1. ✅ Fix A: Subscribe to userUuid topics (commit 8b74fa7)
2. ✅ Fix B: Add wPayload.answer to webrtcResp (commit 077faaf)
3. ✅ Fix C: Flip DTLS setup to passive for echo-only (commit b0a0fff)
4. ✅ Fix 1: Parallelize HTTP pre-flight calls (this PR)
5. ✅ Fix 2: Event-driven liveplay_echo_ev wait (this PR)
6. ✅ Fix 3: Reduce echo secondary wait 6 s → 3 s (this PR)
7. ✅ Fix 4: Guard echo-only cam_ip_q pre-seed (this PR)
8. ✅ Fix 5: Log echo-only diagnostic info (this PR)

## Files Modified

- `aidot/device_client.py`:
  - Lines ~2632: parallelize gather
  - Lines ~2795: replace serial fetch with status log
  - Line ~3168: `sleep(0.5)` → `wait_for(liveplay_echo_ev, 0.5)`
  - Line ~3838: `timeout=6.0` → `timeout=3.0`
  - Lines ~4038: `and not _rr_echo_only` guard + diagnostic log

## Testing

Run `python test_camera.py` against camera `12b144cb12da4994945bffd4f1acfd0c`
and check:
- Does ICE succeed (`ICE connectionState → connected`)?
- Is the "parallel fetch" status logged (confirms both HTTP calls ran concurrently)?
- Does "echo-only: skipping cam_ip_q pre-seed" appear when applicable?
- Are frames received within 5 s of stream open (vs previous ~20–30 s)?
