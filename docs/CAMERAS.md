# Camera support

This fork adds live streaming, snapshots, cloud recordings, real-time-ish motion
events, and two-way (push-to-talk) audio for AiDot/Leedarson cameras, on top of
the upstream lights-only library.

## Supported cameras

The transport is auto-selected per camera from its model id (`LK.IPC.*`):

| Model (`LK.IPC.*`) | Type | Transport | Power | Notes |
| --- | --- | --- | --- | --- |
| A000088 | M3 Pro (incl. A000088-1) | DTLS-SRTP | Wired/mains | Advertises two consecutive ICE ports; the high-port nomination fix applies. |
| A001513 | "L2" battery cam | SDES-SRTP | Battery | AVIO keepalive + cloud keep-alive renew; woken on demand. Must **not** get the `liveStreamParam` pre-connect (see below). Validated end-to-end. |
| A001064 | PTZ | SDES-SRTP | Wired/mains | Role-reversal handshake; excluded from SDES fast-liveplay for correctness. |
| A001108, A001360 | battery cams | SDES-SRTP | Battery | Same battery handling as A001513 (recognized in code; not validated on the reference account). |

Model ids are matched by **substring**, so a firmware/hardware revision suffix
(`LK.IPC.A001513-1`, the way `A000088-1` exists on the DTLS side) resolves to the
same handling as the base model rather than falling through to the generic path.

Battery models sleep between events and are woken on demand; mains-powered models
also expose the LAN-direct control path. Any other `LK.IPC.*` model defaults to
the SDES-SRTP path.

### Battery detection (why it matters)

`is_battery_camera` gates *every* battery protection at once: the SDES TURN relay
pre-allocation is force-kept (a camera woken through the cloud has no LAN host
candidate, so the relay is its only return path), the cloud `setKeepAliveTime` is
renewed mid-view, the HTTP wake fires before signaling, adaptive fast-connect is
refused, and the camera is told `powerType=2`.

It is therefore resolved from the camera's **own cloud data first** - a numeric
`Battery_remaining` (the same signal `lan_control.is_mains_powered` inverts), or
`batteryMode == 2` - and only then from the model list above. A
battery camera that isn't recognized as one loses all of those protections
simultaneously, and the resulting failure is asymmetric by consumer: a standalone
run leaves the LAN-direct options at their relay-keeping defaults and streams
fine, while Home Assistant - where those options are actually set - gets a session
that negotiates and never delivers a frame. Evidence can only *add* a camera to
the battery set; absence of evidence falls through to the list, so a wired camera
never loses its LAN-direct optimizations.

### The `liveStreamParam` pre-connect is disabled

The official app's `KVSPreConnectStrategy.fetchKvsParams` POSTs to
`/api/ipc/liveStream/liveStreamParam` before signaling. It was added here to cure
a `-50019` ("not ready") `livePlayResp` from waking battery cameras - but `-50019`
is benign (mains cameras emit it too and recover via ICE), and the call's real
effect is to provision the camera's session toward **AWS KVS**, which is not the
transport this library uses. The camera then sends its media to KVS: the session
negotiates, the SDES bridge binds, and no video RTP ever arrives. Validated live
on an A001513 - with the call it serves nothing, without it h264 1280x960 + PCMA.

Because the call was only ever made for battery cameras, the set of cameras it can
affect is exactly the set it breaks. So it is not a tunable: the decision lives in
`_resolve_live_stream_param` and is always "no". `AIDOT_LIVESTREAM_PARAM` and
`start_keepalive(live_stream_param=...)` are accepted and ignored (one warning if
set) so an existing caller doesn't break. Re-enabling needs a code change plus
fresh on-hardware evidence that some camera actually requires it.

## Streaming

Cameras use WebRTC over the AiDot/Leedarson MQTT signaling channel (an
AWS-KVS-derived flow), not a local API. Two media-key paths exist and are
auto-selected per camera:

- **DTLS-SRTP** - A000088 models (e.g. M3 Pro, A000088-1).
- **SDES-SRTP** - other models (keys carried in the SDP).

```python
session = await device_client.async_open_webrtc_stream(on_frame=cb, timeout=30.0)
# ... session.stop() when done
```

`scripts/smoke_stream.py` exercises the full path against a real camera
(`python scripts/smoke_stream.py --list`, then `--name "<name>" --hold 15`; it
exits non-zero if no media arrives). It is in the git repo, not the wheel, so it
needs a clone rather than a pip install. See
its `--help`.

### Signaling handshake (MQTT)

Before any media flows the library exchanges JSON messages with the camera over
MQTT. The non-obvious wire facts (learned the hard way - keep them here so they
don't have to be re-discovered):

- **`peer_id` format:** `{32-hex session}_{6-hex rand}_{liveType}_{streamId}_{version}`,
  where the trailing `version` is `1` for SDES and `2` for DTLS. The camera
  **echoes our exact `peer_id` back** in its responses.
- **`livePlayResp` is matched on `peerid`, not `devId`.** The response payload
  carries **no `devId`** - it echoes back our `peerid`. Matching on `devId` (an
  earlier bug) means the match never fires and the wait runs to its full timeout
  every time. Match on the echoed `peerid` (with a `devId` fallback).
- **Reject codes:** `livePlay=0` is an unambiguous refusal - fast-fail on it.
  Other non-OK `code` values are **transient and recoverable**, most importantly
  `-50019` ("not ready"), which battery cameras emit routinely and recover from
  via ICE; treat these as transient and proceed rather than aborting. A camera
  already at its viewer limit returns a terminal ack (`-50002` / `-50015`) -
  see the busy handling below.
- **SDES role-reversal (A001064 PTZ):** this model echoes our offer back as its
  own `webrtcReq` *before* doing ICE, so it must be armed before our `webrtcReq`
  is sent. The `sdes_fast_liveplay` optimisation sends `webrtcReq` ~4.5 s earlier
  and breaks this model specifically, so A001064 is excluded from that flag
  (`_NO_FAST_LIVEPLAY_MODELS`).

The `livePlayResp` wait returns as soon as the response arrives; its timeout is
only paid when the camera never answers. `sdes_fast_liveplay`
(`AIDOT_SDES_FAST_LIVEPLAY` env / `sdes_fast_liveplay=` kwarg) skips this wait and
goes straight to webrtcReq/ICE - **on by default**, matching the official app
(which never waits for `livePlayResp`). Role-reversal models (A001064) are always
excluded. Disable with `AIDOT_SDES_FAST_LIVEPLAY` in `{0,false,no,off}`.

### Battery cameras and the first open

A battery camera (A001513 and friends) is asleep between views, so the first
open has to wake it. Three things follow from that, and all three are app
parity rather than invention - the official client's live view fires its
keep-alive on mount, sends the wake, and shows a sleeping placeholder instead of
opening a session until the device reports itself awake.

- **Offer immediately; do not wait for the camera.** The app's live view waits
  for the device to report itself awake before opening a session, and
  `AIDOT_BATTERY_WAKE_GATE_S` implements that - but it is **shipped off**,
  because measuring it showed the live-play signalling is itself what wakes the
  camera. At a 20 s budget, on a camera settled for ten minutes, the gate ran
  its whole budget with the camera silent, the offer went out at +20.9 s, the
  camera's own `wakeupStatus` arrived at +23.6 s (after the offer) and first
  media at +27.0 s - against 5.4-10.0 s on the same camera with no gate.
- **The keep-alive is re-asserted when the camera turns up.** `setKeepAliveTime`
  at open time reaches a sleeping camera not at all, and the renew loop runs on
  a cadence measured from the open rather than from the camera's wake. A camera
  that woke for us and got no session went back to sleep about 29 s later with
  the handshake still running.
- **A stalled attempt is abandoned to the retry.**
  `AIDOT_BATTERY_STALE_OFFER_GRACE_S` (15 s, `0` disables) ends the first-media
  wait early when the camera turned up mid-wait and still sent nothing, rather
  than holding the full 75 s.

None of this wakes a camera that nobody is watching. Snapshots for a dashboard
card come from a cached cloud thumbnail, the periodic attribute fetch skips
battery cameras outright, and startup prewarm excludes them; motion prewarm does
run, but only when the camera has already woken itself to record.

The **DTLS** path has the targeted equivalent (0.9.0): `dtls_fast_liveplay`
(`AIDOT_DTLS_FAST_LIVEPLAY` env / `_dtls_fast_liveplay_opt`) skips only the
up-to-2 s `livePlayResp` wait while keeping the full ICE/TURN/DTLS handshake - so
remote/relay viewing is unaffected (unlike `fast_connect`, which also strips
TURN). **On by default**; ~2 s off a cold LAN open. Separately, the HTTP ICE
config is cached until just before its server-provided `ttl` (capped 1 h), saving
the ~2 s `iceConfig` fetch on a re-open after the warm session lapses.

### Diagnostics

- `WebRTCSession.get_stats()` (0.9.0) - best-effort connection-health snapshot:
  the nominated ICE candidate pair (host/srflx/relay/prflx - relay-vs-direct) plus
  inbound RTP packets received/lost and jitter. Audio counters are reliable; the
  *video* count is undercounted (this path bridges video outside aiortc's RTP
  receiver - trust decoded-frame rate for video health).
- `CameraStatus.wifi_rssi` (0.9.0) - the camera's cloud-reported Wi-Fi RSSI (dBm),
  surfaced by HA as a diagnostic sensor; the fastest way to spot a marginal link.
- `scripts/camera_diag.py` - maintained on-hardware probe: handshake time,
  time-to-first-frame, per-second fps timeline + gaps, nominated ICE path, RTP
  health, RSSI. `python scripts/camera_diag.py --name <substr>`.

### Adaptive fast-with-fallback (SDES keepalive, opt-in)

For SDES cameras the keepalive loop can run an **adaptive** strategy
(`AIDOT_SDES_ADAPTIVE`, opt-in, default off; set `=1` to enable): the first open
tries the fast path (skip the livePlay waits + the TURN relay pre-allocation) with
a short 45 s open timeout / 40 s media grace. If that attempt delivers no media it
**falls back** to the full, patient relay path for the rest of the loop. It is
off by default because a fast *failure* costs ~40 s (the grace) before fallback
while a fast *success* saves only ~7 s - the real-world failure rate should be
characterised before making it a default. This makes fast-by-default safe regardless of
reachability - a LAN-direct camera gets the fast connect; a strict-NAT / non-LAN
camera loses one fast attempt then connects over the relay. A per-device cache
(`_fast_path_unavailable`) remembers a camera whose fast attempt failed so later
views skip straight to the full path, bounding the fast-timeout cost to once per
camera per session. The relay pre-allocation itself is also separately skippable on
the fast path via `AIDOT_SDES_SKIP_TURN_PREALLOC` (it does two synchronous TURN
Allocate round-trips, ~2-3 s, unused on a LAN).

**Never applied to battery cameras**, whatever the option/env say. The saving
adaptive chases is the TURN pre-allocation, which is force-kept for a battery
camera (its only return path), and fast-liveplay is already on by default - so a
battery "fast" attempt runs the very same handshake as the patient one and differs
only in being given 45 s to open and a 40 s media grace, *inside* the documented
25-70 s battery cold-start window. A slow-but-healthy wake would then be scored as
a fast-path failure: it latches `_fast_path_unavailable`, escalates the backoff,
and burns a camera-side session on a device that frees them slowly.

### Connection reuse (`AIDOT_PERSISTENT_MQTT`, on by default)

Historically every device command, attribute fetch, and **stream open** opened
and tore down its own cloud MQTT WebSocket. The official app instead keeps ONE
persistent connection per login session and reuses it for everything. By default
(matching the app), `_PersistentMqtt` holds a single account-level
connection (the broker binds auth to the one authorized `client_id`, so there can
only be one), subscribes once, replays subscriptions on reconnect, and carries
commands, attributes, AND the stream-open signaling - without tearing down on
stream stop. This removes the per-open connect churn that otherwise rate-limits
the cloud account; live 7-camera soaks showed SDES `NO_MEDIA` dropping from
~57 % to ~11-19 % with the flag on. On by default; disable with `AIDOT_PERSISTENT_MQTT`
in `{0,false,no,off}` or per-camera `_persistent_mqtt_opt=False` (the explicit opt
always wins).

**Persisting `login_info` yourself?** This connection (and its guarding lock)
live on the same `login_info` dict `AidotClient` hands you - a live
`asyncio.Lock` isn't JSON-serializable, so once this connection exists,
`json.dump(client.login_info, ...)` raises `TypeError`. Use
`AidotClient.serializable_login_info()` instead of serializing `login_info`
directly; it returns the same dict with the runtime-only keys excluded.

### Connection reliability (DTLS / A000088)

A000088 cameras advertise **two consecutive ICE ports** `[P, P+1]` and only
proceed to DTLS when the client nominates the **higher** one (their live DTLS
socket). The library forces `USE-CANDIDATE` onto the highest remote port, which
lifts the per-attempt connect rate from ~25% to ~75-87%. The fix is **scoped to
DTLS-camera connections only** - SDES cameras and non-camera devices are a strict
no-op. Combined with retries (`--webrtc-retries`, default 5, jittered backoff)
the effective connect rate is high. The fix is unconditional (it self-gates to
A000088 DTLS connections, so it is a strict no-op everywhere else).

If a camera is already serving its maximum number of viewers it returns a
terminal ack (`-50002` / `-50015`); the library raises `AidotCameraBusy` and
stops retrying rather than burning the retry budget.

### The SDP handed to ffmpeg carries ONE codec (0.14.0)

The ffmpeg-input SDP advertises both video codecs (`m=video ... 96 97`) and both
audio ones (`m=audio ... 0 8`), because which pair a camera uses varies per
session. It **must** be narrowed to the ones actually in use before ffmpeg
launches, and getting it wrong is expensive in two different ways:

- ffmpeg binds each depacketizer to the **first** payload type on the m-line and
  silently discards packets carrying any other, so the wrong video type means no
  picture and the wrong audio type means the mpegts mux never writes its PAT/PMT
  - which loses the video too;
- an un-narrowed video line makes the RTSP-push ANNOUNCE carry a parameterless
  H.265 stream, which **go2rtc rejects outright**: no publisher attaches and
  every viewer gets a 404.

Narrowing normally uses the payload type observed on the session's first RTP
packet. When no video packet arrives before the serve launches, the codec is
taken from the camera's **answer SDP** instead - a negotiated fact rather than a
guess - via `video_pt_from_answer_sdp()`. That returns the payload type *this
package's* template writes for the codec (96 H.264 / 97 H.265); a camera may
number the same codec differently, and narrowing to a number our SDP does not
contain would drop the video line entirely. An answer naming no codec we write
leaves the SDP unchanged.

Before 0.14.0 there was no fallback, so a session whose media started late served
nothing at all - and the serve-restart path rebuilt the same un-narrowed SDP on
every watchdog cycle, so it stayed broken until the process restarted. The
`SDES: narrowed ffmpeg SDP to ...` status line is the signal that narrowing ran;
its absence is the fault.

### What a cold SDES open costs

Measured on the reference A001064 (mains, LAN-direct), cold opens forced by a
config-entry reload, `1.0.0rc8`:

| stage | when |
|---|---|
| `webrtcReq` sent | +0.5 s |
| camera's answer accepted | +0.7 s |
| STUN window leaves, USE-CANDIDATE sent | +0.8 s |
| SCTP up, AVIO `LIVING` sent | +2.4 s |
| first SRTP | **+2.5 s** |

That was 6.7 s until two waits on the path were measured and found to be
spending time on things that had already happened.

The **ICE responder window** was written when the camera's answer arrived after
it closed. Shortening an earlier wait inverted that, and the window then sat for
seconds holding the credentials the nomination needed - it blocks the event
loop, so `answer_fut` cannot resolve from inside it. The MQTT thread now marks
the answer ready and the window leaves as soon as the credentials are in hand
*and* the camera has answered a connectivity probe. Leaving early costs nothing:
an incoming media packet already broke out of the window, a camera that never
probes already left on the pre-STUN idle, and the bridge thread - which is what
learns peer-reflexive candidates and re-nominates every 2.5 s - takes the
responder role back about 30 ms later. A camera that has answered no probe keeps
its previous behaviour, which is every relay-path battery camera measured.

The **`webrtcReq`-echo wait** was a flat 2.0 s for role-reversal models. Across
18 h of one deployment, of 61 SDES opens the 17 that took the wait timed out 17
times out of 17, and the `webrtcResp` it exists to build was never sent once.
See `AIDOT_SDES_ECHO_WAIT_S` in the README for how it is sized now and what
happens on a fleet whose echo band is not empty.

Battery models take neither wait; their cold open is dominated by the camera
waking, and is unchanged.

#### The older figures scattered through the tree predate this

`25-70 s cold on SDES` and `15-21 s on DTLS` appear in roughly twenty comments
across the library and the integration. They are pre-`rc8` and should not be
read as current for a MAINS live open. Confirmed on the fleet 2026-09-07 over
**11 real cold opens** (7 SDES, 4 DTLS, mains, taken from production logs rather
than forced): the serve bound in **2.6-3.6 s, median 2.9 s**, with no meaningful
split between transports.

Two cautions before deleting any of them:

- They do not all describe the same operation. Some size an **SD listing**,
  which needs the session *and* an SCTP handshake on top, and that has not been
  re-measured. Some describe a **battery** wake, which is dominated by the
  camera and was never what `rc8` changed.
- Several **size a timeout**. An over-sized upper bound on a wait that ends
  early costs nothing, while an under-sized one reintroduces the failure it was
  written for. Re-measure the specific path before retuning any of them; do not
  propagate this number by search-and-replace.

### Connection reliability (SDES / battery)

SDES cameras - including battery models (A001513) - stream end-to-end once the
ICE/SCTP handshake completes. Battery cameras require a periodic AVIO keepalive
(`HEARTBEAT`, every 10 s) sent as an **encrypted SCTP DATA chunk** over the
control channel; without it the firmware tears the session down at ~18-22 s. The
library sends this automatically (matching the official app's `DataChannel`
keepalive timer), so battery streams hold while the camera is awake - validated
at 72 s / 49 s holds on two A001513 cameras.

Separately, a battery camera runs its own low-power timer that returns it to
sleep ~25 s after the last cloud keep-alive, **even mid-view** - so a one-shot
keep-alive at open would let the stream drop partway through. For the duration of
a battery stream the library re-issues the cloud `setKeepAliveTime`
(`keepAliveTime=25`) every 20 s - inside that 25 s window, so there is no sleep
gap - matching the official app, which renews it throughout a live view. Mains
cameras never sleep, so this loop runs only for battery models.

Battery cameras sleep between events. The library wakes them on demand via the
cloud **HTTP low-power endpoint** (`async_wake_camera()`, also fired automatically
at the start of a stream open) in addition to the MQTT `lowPowerActiveStateReq` -
the HTTP wake is forwarded by the cloud to the camera's always-on channel, so it
reaches a deeply-sleeping camera that has dropped its MQTT session (matching the
app, which sends both). Validated on three A001513 cameras (woken with no motion).

## Two-way audio (push-to-talk)

Two-way audio works on **both** camera paths through the same API. Open with
`talk=True`, then push frames:

```python
session = await device_client.async_open_webrtc_stream(..., talk=True)
await session.async_start_talk(pcm_provider)   # provider() -> 320B s16le PCM (20ms @ 8kHz), or None
# ... speak ...
await session.async_stop_talk()
```

...or the higher-level helper, which opens a session, plays the clip, and tears
down (used by the Home Assistant `aidot.talk` service):

```python
await device_client.async_speak(pcm_provider, max_seconds=30)
```

`pcm_provider()` returns 320-byte signed-16-bit-LE PCM frames at 8 kHz (one per
20 ms), or `None` when the clip is finished. On the wire the audio is G.711
A-law (PCMA, PT=8) - the codec the camera negotiates.

- **DTLS cameras (A000088):** talk rides the same PeerConnection via an
  always-present `sendrecv` audio transceiver toggled at runtime (present-but-idle
  sends no RTP, so it never triggers a silence teardown).
- **SDES cameras (A001513 battery, etc.):** a `talk=True` open advertises the
  audio m-section `sendrecv` + `a=ssrc` so the camera builds a receive path; the
  library opens the speaker with AVIO `SPEAKERSTART`/`SPEAKERSTOP` over the SCTP
  control channel and pumps PCMA as SRTP to the camera's media address. Validated
  audibly on an A001513 (the camera ACKs `SPEAKERSTART` with `851`). Pure-streaming
  opens stay `recvonly` and are unaffected.

`tools/talk_test.py` (a local developer script) plays a 440 Hz tone for a few
seconds (validated audibly).

**Releasing the speaker on teardown:** when a session that used talk is stopped,
the library sends `SPEAKERSTOP(849)` and gives the transport a brief flush window
before closing it, so the camera actually frees its speaker/talk channel. Without
this the channel stays bound to the dead session and the next push-to-talk (ours
or the official app's) gets `851` "mic occupied". This runs on every teardown
path where talk was active - not just a clean `async_stop_talk`.

## Motion events

Cameras do **not** push motion to a passive MQTT subscriber (alarm attributes are
only sent during an active live view; background motion goes via FCM). The
working path is **cloud-event polling**:

```python
await device_client.async_start_motion_polling(callback, interval=30.0)
# callback(event) fires per new motion/person event (deduped, in time order)
await device_client.async_stop_motion_polling()
```

## On-device (SD card) recordings

What the camera holds on its own card, read over a session that already exists.

```python
if device_client.has_live_session:                       # sends nothing
    result = await device_client.async_get_sd_recordings(days=7)
```

**Listing needs a WebRTC session** - historically 15-21 s on DTLS and 25-70 s
cold on SDES (pre-`rc8`; the session itself is now ~3 s, but the listing's own
SCTP handshake has not been re-measured), and
it wakes the camera - where the cloud equivalent is one ~200 ms request. So the
library never opens one for a listing: it asks the session it is handed, or
answers `None`. Deciding when a listing is worth a session is policy, and policy
belongs to the caller that knows what one costs.

`has_live_session` exists because `start_keepalive` returns before the handshake
it schedules has produced anything. A caller that wants to ride the session it
just asked for can wait on this flag without sending anything - and must, because
probing with a real request means that once the session is up, the probe IS the
request.

### Three outcomes, not two

A caller that collapses any two of these shows a user the same empty list for
opposite reasons:

| Answer | Meaning |
| --- | --- |
| `None` | there was no session to ask through. **Nothing was sent.** |
| `answered=False` | the requests went out and the camera said nothing. This is what a model that does not implement the commands looks like, and also what a channel that just died looks like. It is **not** a statement about the card. |
| `answered=True` | the camera replied. Only now does an empty `records` mean the card holds nothing in that window. |

`complete=False` means the reply's end flag never arrived or a page did not
decode - there may be more on the card than came back. The reply is paged and
there is no known continuation request, so this reports the truncation rather
than inventing a second request.

Measured 2026-08-13: one A001064 answered nothing to five asks over 84 s on a
live session. **That reading was ours, not the camera's, and 1.0.0b34 fixes it.**
The camera did reply; the reply is ~2.8 KB and arrives as several SCTP fragments,
and the SDES receive path parsed each fragment as a whole AVIO frame - so the
first was correctly refused as truncated and the rest decoded as junk command
ids. `answered=False` was reporting a reply we had thrown away. The DTLS path
reassembles in its SCTP stack, which is why only SDES cameras ever looked mute.

`answered=False` still means exactly what the table says, and it is still the
honest answer for a model that genuinely does not implement the commands - but
it is no longer evidence that any particular model is one of those. No model on
the reference fleet currently is.

### Is there even a card?

```python
device_client.status.sd_card_present   # True | False | None
```

Read from the cloud attributes (`SDcardExistFlag`, falling back to
`SDcardBaseInfo[0]`), so it costs nothing and opens no session. **`None` means
nobody reported** - four of seven cameras measured carried neither key, including
a model whose siblings report normally - so it is NOT evidence that a model
cannot report. Only an explicit `False` says the slot is empty.

### Playing one back is NOT offered, and that is a finding

Listing what a card holds works. **Playing a recording off the card does not,
and the library does not pretend to** - `can_play` is False on every SD record.

This was investigated to a conclusion rather than skipped. The session a
playback needs is fully understood and reproducible: an SD-mode peer id, an
offer carrying no local audio sender, and the AVIO session-mode command
(`0x1500`) set to SD rather than the LIVING every session uses. A camera accepts
all of it. It then acknowledges the play command in about 50 ms and sends no
media at all - no video RTP on any payload type, no video RTCP sender report,
and none of the progress messages the vendor app drives its seek bar from.

What was ruled out along the way, so nobody assumes it is one line of work: the
channel byte, the event-type byte (swept across every plausible value on a card
whose records all carry event 0), and the codec - this firmware declines to
negotiate H265 both as an extra payload type in the video section and as a
section of its own, so a decode path would have nothing to decode.

If that changes, it will be because someone captures a real playback off the
wire. Reading the vendor app has been taken as far as it goes.


## Local (LAN-direct) streaming

The camera **media is peer-to-peer**: when the client and the camera are on the
same network, WebRTC ICE nominates the camera's LAN host candidate and the
DTLS-SRTP / SDES-SRTP video flows **directly to the camera's LAN IP** - it does
not traverse the internet or a cloud media relay. This was verified by
packet-capturing the official AiDot app, which streams these cameras the same way
(STUN/ICE + media straight to `192.168.x.y` camera addresses).

The cloud is used **only for signaling**: MQTT to exchange the SDP offer/answer
and ICE candidates, plus STUN/TURN for rendezvous. In normal same-LAN operation
the bandwidth-heavy media therefore stays on the LAN.

> These cameras stream over **WebRTC**, not TUTK IOTC P2P. The TUTK scaffolding in
> the library is unused for streaming - which is also why `getP2pId` returns null
> (there is no TUTK UID to fetch for a WebRTC-streamed camera).

## Known limitations

- **No fully-offline mode.** The cameras expose no local signaling API (and no
  RTSP/ONVIF/HTTP), so establishing a stream still needs the cloud signaling path
  (MQTT + STUN/TURN). Only the *media* is LAN-direct; the *handshake* is not.
- **Connect is per-attempt probabilistic** for DTLS cameras; rely on retries (the
  high-port nomination fix substantially raises the per-attempt rate).

## Choosing a video decoder

Only one place in this library decodes video: the drain that keeps ffmpeg
consuming SRTP while proving the stream is usable. Serving, publishing and
recording are all `-c copy` and decode nothing, so a decoder choice cannot help
them and is not applied there.

The drain decodes deliberately, and that must not be "optimised" away. Decoding
is what distinguishes media arriving from media that can be turned into
pictures. A copy-only check demuxes perfectly happily while every frame is
undecodable, which is exactly how one camera looked healthy for two days while
showing a black picture.

`camera/hwaccel.py` picks the decoder by proving candidates rather than reading
a list. `ffmpeg -decoders` reports what the binary was compiled with, not what
the machine can run: a Raspberry Pi 4 advertises `h264_cuvid` with no Nvidia
hardware present, and advertises `h264_v4l2m2m` while failing to open it even
with `/dev/video10` present. Two forms are tried, and they are not
interchangeable:

    ["-c:v", "<name>"]        a named decoder, e.g. h264_v4l2m2m
    ["-hwaccel", "<method>"]  an acceleration method, e.g. videotoolbox

VideoToolbox and VAAPI expose no decoder at all - ffmpeg lists both as
*encoders* - so naming them with `-c:v` can never work. Each form is looked up
in the list that describes it. Both are input options and must precede `-i`;
after `-i`, ffmpeg reads `-c:v` as an encoder.

A candidate must produce frames, not merely exit cleanly, or a decoder that
consumes the stream and emits nothing would qualify - the black-picture failure
again.

Hardware is not assumed faster. On an Apple M1, VideoToolbox decodes H.264 about
three times slower than software, measured through the same `-f null` pipeline
used in production. Candidates are ranked by measured time, so software wins
where it deserves to.

Cost is kept off the hot paths. `warm_decoder_cache()` probes on a daemon thread
and is idempotent; `cached_decoder()` is the event-loop-safe reader and returns
None for "not measured yet", which simply means ffmpeg chooses as it always did.
Candidates the machine plainly cannot host are ruled out by a device check
before anything is spawned, and if none survive, no sample is even encoded -
that case answers in about three milliseconds. Only H.264 is measured, because
only H.264 is ingested.

## Advanced tuning environment variables

These finer-grained knobs are read by the camera client but rarely need changing
- the defaults are tuned to work out of the box. The headline streaming knobs
(concurrency caps, fast-connect, persistent MQTT, serve relay, etc.) are in the
[README](../README.md#camera-streaming--tuning); the ones below are the deeper
internals.

| Variable | Purpose | Default |
| --- | --- | --- |
| `AIDOT_STREAM_IDLE_S` | Seconds of stream idle before an idle release. | `120` |
| `AIDOT_SDES_IDLE_RELEASE` | Set to `0` to disable idle release for SDES streams. | `1` (enabled) |
| `AIDOT_ICE_DISCONNECT_S` | ICE-disconnect debounce, in seconds, before tearing down. | `8` |
| `AIDOT_DTLS_RETRY_GATE_S` | Minimum spacing, in seconds, between DTLS open retries. | `15` |
| `AIDOT_BUSY_RETRY_S` | Delay, in seconds, before retrying when a camera reports busy. | `45` |
| `AIDOT_OFFLINE_RECHECK_S` | While a device is cloud-offline, how often the paused keepalive retry re-checks the online flag. | `30` |
| `AIDOT_OFFLINE_PROBE_S` | While a device is cloud-offline, how often one real open attempt still probes it (guards against a stale cloud flag). | `600` |
| `AIDOT_GOP_PLI_S` | Interval, in seconds, between PLI (keyframe) requests. | `2.0` |
| `AIDOT_STALL_PLI_S` | If muxed frames stall for this many seconds (a dropped GOP on a jittery link), request an IDR keyframe immediately instead of waiting out the full `AIDOT_GOP_PLI_S` cadence. Mains DTLS cameras only; `0` disables. | `1.0` |
| `AIDOT_SDES_PLI_GAPS` | Comma-separated second offsets for the early PLI burst on SDES cameras, to pull the first keyframe in faster on cold start. | `0,1.5,2,3` |
| `AIDOT_SDES_SERVE_AUDIO` | Serve audio on SDES cameras (a silence-base mix keeps the audio encoder fed so battery-camera audio streams smoothly). Set to `0`/`false`/`no`/`off` to disable. | on |
| `AIDOT_SDES_AUDIO_GAIN_DB` | Gain (dB) applied when SDES audio is served. | `-8` |
| `AIDOT_AUDIO_TARGET_DBFS` | Target loudness (dBFS) for two-way audio normalization. | `-15` |
| `AIDOT_AUDIO_MAXGAIN_DB` | Maximum gain (dB) applied by the audio normalizer. | `30` |
| `AIDOT_AUDIO_MINGAIN_DB` | Minimum gain (dB) applied by the audio normalizer. | `-12` |
| `AIDOT_AUDIO_GATE_DBFS` | Noise-gate threshold (dBFS) for two-way audio. | `-45` |
| `AIDOT_FAST_CONNECT_HOST_ONLY` | Within `AIDOT_FAST_CONNECT`, narrows only the local `RTCPeerConnection` to host candidates (skips the ~5 s srflx gather stall). **On-subnet only** - drops srflx/relay fallback. Opt-in. | unset (off) |
| `AIDOT_SPROP_DIR` | Directory where captured SPS/PPS (sprop) parameter sets are cached. Set to a writable path if the default location is read-only. | `<package dir>` |
| `AIDOT_SDES_NACK` | Ask the camera to resend video RTP packets that never arrived (RTCP Generic NACK). Loss on a weak link otherwise reaches the player as a truncated H.264 slice, which WebRTC conceals and MSE treats as fatal. **On by default**; `0`/`false`/`no`/`off` disables. | enabled (on) |
| `AIDOT_SDES_CONNECTION_MODE` | Which media path the SDES offer proposes: `auto` (default - every reachable candidate, and ICE priority prefers the LAN with the relay as last resort; measured on the full fleet, six of seven cameras stream direct and only the unit with no route to us rides the relay), `lan` (no relay at all - same lever as `AIDOT_SDES_SKIP_TURN_PREALLOC`, and battery cameras keep the relay regardless because a cloud-woken camera has no other path back), or `relay` (EXPERIMENTAL, and on the reference fleet it does not steer: even with `c=`/`m=` moved to the relay allocation and the WAN permission pre-installed, an A001064 and an A001513 both dialed our host address directly, learning it from our own ICE probes - forcing the relay for real would mean suppressing every direct-path outbound, which is unbuilt). Per-open `sdes_connection_mode` beats the env. Every session reports the path its media actually took as `media_stats().media_path` (`direct`/`relay`). | unset (`auto`) |
| `AIDOT_SDES_OFFER_BANDWIDTH_KBPS` | Add a `b=AS:<kbps>` receive-bandwidth ceiling (RFC 4566) to the video section of the SDES offer. **Measured to do nothing** on an A001064 over ten sessions; kept, off, alongside `AIDOT_REMB_TARGET_BPS` for the same reason. Run as a strict ABAB campaign it appeared to give a decisive 2.1x reduction - that was a codec split, not the knob. | unset (no `b=` line) |
| `AIDOT_SDES_TMMBR_BPS` | Ask the camera not to exceed a bitrate, in bits per second, via RTCP TMMBR (RFC 5104). Distinct from `AIDOT_REMB_TARGET_BPS`: REMB reports an *estimate* of available bandwidth, TMMBR states a *bound*, and firmware can honour one without the other. This camera acts on RTCP feedback it never negotiated (our offer advertises no `a=rtcp-fb` at all, yet NACK recovers 98.4% of losses), so the absence of `ccm tmmbr` from its answer is not a reason to assume it is ignored. **Measured on an A001064 and it does nothing** - within-session, 0.748 against a control of 0.705, i.e. marginally higher. Shipped off. | unset (off) |
| `AIDOT_SDES_TMMBR_AFTER_S` | Seconds of media to let pass before the first TMMBR, so a bound can be measured *within* one session - window A before it, window B after - instead of between sessions. Measured from the first video packet, not from the open, so a slow-waking camera does not spend window A already capped. | `0` (send from the first video packet) |
