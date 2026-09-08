# What 1.0.0 is waiting on

> Cameras are named by role: "the PTZ" is the single A001064; "unit 88-A..D" are the four A000088s (D retired); "unit 13-A..C" are the three battery A001513s, 13-A being the one on the separate IoT SSID whose sessions ride the TURN relay.

Written 2026-08-07, updated 2026-08-08 after an audit-closing day. The point of
this file is to make the bar checkable, so that "are we ready" stops being a
matter of opinion.

What 1.0.0 asserts is **not** that there are no known issues. It asserts that we
understand the system and its shape has settled.

## Already met

- **A clean public surface.** The reference consumer reaches into zero private
  attributes of this library - measured, not assumed. See
  [API-STABILITY.md](API-STABILITY.md).
- **A release gate with teeth.** Unit tests on musl (the runtime target), an
  end-to-end fake-lab tier, install checks against two Home Assistant versions,
  a downstream integration run, and validation against real cameras on a LAN
  runner before anything reaches PyPI.

  Qualified on 2026-08-08, because the gate was partly scoring its own homework:
  its SDES PASS signal is `media_stats.packets`, the very counter that was
  counting undecryptable packets as delivered media, with `recorded_bytes` from
  a `-c copy` pipeline as the fallback - neither requires a packet to have
  decrypted or decoded. And the harness never configured logging, so every INFO
  and DEBUG line the library emitted was discarded in every run. Both are fixed:
  the harness now decodes the recording and reports real frame counts, and the
  aidot loggers are raised. The gate is meaningfully stronger than the sentence
  above claimed when it was written.

- **The audit backlog is closed.** Every item in the 2026-08-08 findings list
  landed: media counted only when the consumer can use it, the SDES receive
  session rebuilt on rekey, the `webrtcResp` future resolved in one loop hop,
  three decorative tests replaced with real ones, snapshot cancellation
  propagated, and a latent SCTP TSN mapping corrected.

- **Local (LAN) control is demonstrably working.** Ten devices across four model
  families return 200 for the owning account. It had appeared broken; the
  devices were rejecting the shared-home account the CI runner deliberately
  uses. No library defect existed. See the READMEs.

- **The coverage holes are decided.** The `liveType=0` / TUTK path is out of
  scope for 1.0.0 with a stated reason, and the `async_set_resolution` ack read
  has coverage that joins the setter to a real session on DTLS. Item 4 below
  keeps its number and records both decisions; it no longer gates anything.

## Open

**As of 2026-09-04 exactly one item is open: number 1.** Items 2 to 7 are
closed above, each on its own terms and each saying which terms - two of them
are "documented as accepted" rather than "solved", and they say so in their own
words rather than in a summary that rounds them up. Read the item, not this
line.

### 1. The discovery rate is still high

Fourteen releases in the four days to 2026-08-07, and the finds were structural
rather than cosmetic: inbound AVIO on SDES was being decoded, logged and dropped
so the whole response path was dead on that transport; a `-50002` backoff waited
300 s for a camera measured to clear in 8.

**2026-08-08 set this back rather than advancing it.** Roughly ten changes
landed in a day, and three were structural: undecryptable packets counted as
delivered media, so a black stream could report healthy indefinitely and the
abandon ceiling could never fire; the SDES receive session latched behind a
`hasattr` so a camera that rekeyed reached nothing; and four logging sites
printing SRTP key material into logs users paste into public issues.

That is not a settling cadence. The clock has not started.

The bar: **two weeks with no streaming-breaking release.** The cadence is the
evidence.

**Status 2026-09-01: the clock still has not started, and rc2 did not start it.**
The last four weeks kept finding structural defects rather than cosmetic ones:

- **2026-08-31, the 80.2 s cliff.** Root cause was our own SCTP receiver: it
  never sent a SACK, so the camera's retransmission timer ran out and it tore
  the association down, and it never reassembled fragmented DATA, so multi-
  fragment SD listing replies were discarded. Both shipped in `1.0.0b34`.
- **2026-08-31, a regression caught only by the live gate.** Pinning the peer
  id's client class to `0` was generalised from A001064 firmware to the whole
  fleet and took three A000088 cameras from 3/3 to 0/3. 1684 unit tests and a
  30-minute soak passed it; only real cameras caught it.
- **2026-09-01, two more streaming defects landed unreleased.** New consumers
  were spliced onto an audio random-access point rather than a video keyframe,
  and push cameras registered a go2rtc producer on a port nothing binds.

Three of those four are the kind of find this item exists to count, and two are
not yet in any release. So the discovery rate is still high and 1.0.0 stable is
not warranted. `1.0.0rc1`/`rc2` are the right shape: PEP 440 pre-releases, so
plain `pip` and HACS do not pick them up.

Day zero is the first release that carries the two unreleased fixes above and is
not itself followed by a structural find. It has not happened yet.

#### Corrected 2026-09-02: both fixes shipped, and the finds have moved off the streaming path

The block above says the keyframe-splice and go2rtc-producer fixes "are not yet
in any release". That stopped being true within hours of it being written, and
the sentence stood for a day. Resolved against the tags rather than the commit
log, because two release tags do not point at a `chore:` commit and reading the
log order gets this wrong:

| fix | commit | first release |
|---|---|---|
| splice on a real video keyframe | `6fbe888` | **`v1.0.0rc3`** (`4e09be5`) |
| wait for the publish target before serving | `ecfb116` | **`v1.0.0rc4`** (tag points at `ecfb116` itself) |

So the stated precondition for day zero -- a release carrying both -- was met by
`1.0.0rc4` on 2026-09-01.

**What has been found since, and how it classifies.** The bar is specifically
*streaming-breaking*, so each find has to be placed, not counted:

| release | find | streaming-breaking? |
|---|---|---|
| `rc5` | `async_query_device_action` opened a second MQTT session on a duplicate `mqttClientId`, and the broker evicted the integration's live one | No -- control path. Streaming never used that call |
| `rc5` | one camera could read another's `devActionReq` reply; four cameras reported identical SD figures | No -- control path |
| `rc6` | the reply matcher required an echoed `seq`, so a camera that answers reads as silent | No -- control path |
| `rc6` | a camera on an unreachable subnet reported `first media never arrived` instead of naming the cause | No -- diagnostic wording; detection only, no behaviour change |
| `rc6` | the standalone CLI's env reader folded every non-`"1"` value to an explicit `False`, so `AIDOT_FAST_CONNECT=true` disabled fast connect and `AIDOT_SDES_SERVE_AUDIO=` would have dropped audio | No -- `aidot-go2rtc` only. Home Assistant sets these per camera and never goes through that reader |

**None of the five broke streaming**, and the shape of the finds has changed:
four of the five are in the control/config path that the property-exposure work
opened up, and the fifth is confined to the standalone CLI. That is a different
class from the SCTP receiver or the peer-id regression, both of which took real
cameras from streaming to not streaming.

**Day zero is therefore `1.0.0rc4`, 2026-09-01.** Two weeks from it is
**2026-09-15**, and the clock runs only while no streaming-breaking release
intervenes -- any such release resets it to zero. *(Superseded on 2026-09-04 --
see below. `rc7` reset it.)*

**Two cautions against reading this as further along than it is.** First, the
count is honest but the observation window is not clean: `rc5` and `rc6` each
fixed real defects, and a control-path defect being non-streaming is a
classification, not an absence. Second, the finds moved into the control path
because that is where the new work was; a quiet streaming path may partly
reflect where attention went. The evidence for 1.0.0 stable is a fortnight of
this cadence, not the fact that day zero can now be dated.

#### Re-dated 2026-09-04: `rc7` reset the clock, so day zero is 2026-09-03

Three releases went out without being classified here, and the tracker stood
stale for three days while they did. Placing them against the same bar:

| release | date | find | streaming-breaking? |
|---|---|---|---|
| `rc7` | 2026-09-03 | A battery camera went back to sleep in the middle of its own handshake. Measured on an A001513: awake at +10.9 s, asleep again at +39.8 s with the handshake still running, **no media ever arrived**, and the open finished at +103.6 s. The matching integration fix (2.19.12) describes the user-visible half: a battery camera's first view failed about half the time | **Yes** |
| `rc8` | 2026-09-04 | Two waits on the SDES connect path were spending time on things that had already happened -- the ICE responder window sat on an answer it already held, and the `webrtcReq`-echo wait timed out 17 times out of 17. Cold first media 6702 ms -> 2695 ms | No -- latency. A slow connect is not a broken one, and no session failed |
| `rc9` | 2026-09-04 | Three findings from reviewing `rc8`: the shortened echo wait could silently disable the branch that echo drives, our own echoed answer could resolve the future the nomination reads, and the answer-ready marker was per-camera while the decision was per-open | No, but this is the borderline one. The middle finding would strand a session that can never be nominated -- it is counted as non-breaking because it is pre-existing rather than introduced, and was never observed on this fleet. If it is ever seen in the wild, re-date to `rc9` |

**Day zero is therefore `1.0.0rc7`, 2026-09-03. Two weeks from it is
2026-09-17.**

*Superseded the same day by the scope decision in item 7: the quality campaign
ran first. It finished on 2026-09-04 and item 7 is closed, so the clock starts
now rather than at rc7.*

#### The clock starts 2026-09-04

**Day zero is `1.0.0rc9`, 2026-09-04. Two weeks from it is 2026-09-18.**
*Superseded 2026-09-06 -- this window was broken by instrumentation on
09-05 and does not count. See "The clock restarts 2026-09-06" below; the
cautions in the rest of this section still stand.* The
campaign ended that afternoon and the fleet was left alone from then; rc9 is the
release in the field, and the box was verified running it - pip metadata
1.0.0rc9, integration 2.20.1, and `sdes_open.py`/`webrtc_open.py` hashing
byte-identical to the released wheel. A soak measured on hot-patched files
measures nothing, so that check is part of dating day zero rather than a
formality.

**The soak covers eight cameras, not nine.** `camera.deck` is an orphaned
registry entry - `restored: True`, no device behind it, the integration does not
log it at all - and it was already in that state before any of 2026-09-04's
work. It is not a streaming failure and must not be scored as one.

Read `sh ~/source/aidot-soak-check.sh` for the running count. It is read-only,
and it attributes tracebacks rather than printing a raw total, because 96 of one
day's 111 were throwaway instrumentation.

**What the fleet shows so far.** Over the container log window 2026-09-03 23:10
to 2026-09-04 15:22: 164 opens reached first media, 564 reached a serve, with
**zero** first-media stalls, **zero** camera refusals and **zero** `ERROR` lines
from this library. Of 111 tracebacks in that window, 96 were throwaway probe
instrumentation added and removed the same day; of the remaining 15, six are
inside Home Assistant's own `go2rtc` preload path during a restart, two are
Frigate, and the one on a thread named `_dtls_av_mux_run` is `yoto_api` reported
on whichever thread ran its callback. None are this library's.

**A third caution, and it is the important one.** That window is not a soak. It
is a day of the box being driven hard: a dozen Home Assistant restarts,
site-packages hot-patched repeatedly, and roughly eighty forced cold opens. A
quiet library under that is worth something, but it is the opposite of the
evidence the bar asks for, which is a fortnight of *ordinary* use with nobody
touching it. Read the numbers above as "nothing broke while being provoked", not
as soak progress.

#### The clock restarts 2026-09-06

**Day zero is 2026-09-07. Two weeks from it is 2026-09-21.**

By the RELEASE rule alone it would still be 2026-09-06: `rc11` set it, and
`rc12`, `rc13` and `rc14` are each classified below as not streaming-breaking,
so none of them resets the clock.

It moves anyway, for the other reason this document already gives: **2026-09-07
was not ordinary use.** Two releases went out, Home Assistant was restarted
four times, the config entry was disabled and re-enabled repeatedly to run
read-only probes and a drained-fleet screen against real cameras, the mains
warm-hold was changed from 0 to 120 s, and a dozen opens were forced by hand.
That is "nothing broke while being provoked", which the bar explicitly does not
accept as soak evidence.

The clock therefore runs from the box settling on `1.0.0rc14` + integration
`2.21.1` on the evening of 2026-09-07. Everything before that is provocation,
not soak.

The rc9 window is void, and for the reason that made checking the box part of
dating day zero in the first place. On 2026-09-05 the box was hot-patched with
throwaway `_WIREPROBE` instrumentation, to settle whether the camera needs ICE
credentials in each m-section. It answered the question, but a soak measured on
files that are not the released ones measures nothing, so 09-04 to 09-05 does
not count and cannot be salvaged.

The restore afterwards was itself a hot patch, which is the part worth
recording. The box was put back by copying `rc10`'s files over site-packages,
leaving **pip metadata reporting `1.0.0rc9` while every file was byte-identical
to `rc10`** -- the same lying version this project has been caught by before.
Corrected 2026-09-06 with a real install rather than a file copy.

Two releases went out in the meantime, and the bar asks them to be classified
rather than assumed:

| release | date | find | streaming-breaking? |
|---|---|---|---|
| `rc10` | 2026-09-05 | A camera that cannot stream at all was still having a serve launched for it, so every attempt spawned an ffmpeg that failed on the spot and retried into the same thing -- 11 attempts and 6 stalls in 25 minutes on a camera that had dropped off the WiFi. Also: a battery session could lose its audio for its whole length when the first packets arrived a fraction of a second after the wait ended, and a malformed `AIDOT_ABANDONED_MEDIA_GRACE_S` stopped the library importing | **Borderline -- counted yes.** The doomed-serve half only affected cameras that could not stream regardless. The audio half degraded sessions that were otherwise working, and the import failure took the integration down at setup for anyone who set that variable wrong. Either alone would be arguable; together they are enough to reset |
| `rc11` | 2026-09-06 | Every SDES session signed its video connectivity checks with a password the camera had never been given: the offer carried a credential pair per m-section and only the first survives compression. Also out-of-spec ICE characters in about half of all passwords | No. Nothing was observed broken and no session failed -- the cameras tolerated it. It is a correctness fix, and it is day zero only because it is the release that happens to be in the field |
| `rc12` | 2026-09-06 | The library was the loudest module in the HA log -- HA's own limiter fired against it twice in ten minutes on an idle box. Also: a bridge diagnostic wrote a camera's decrypted payload to the log in the clear at INFO, and the post-failure transport dump could hide every transport after an unreadable one, or escape into aiortc's event dispatch if its log channel raised | No. Nothing that runs during a working session changed behaviour -- the moves are severity-only, and the failure-dump fix runs only after a connection has already failed. Same day as rc11, so day zero does not move |
| `rc13` | 2026-09-07 | The cameras type their detections - human, vehicle, package, pet - and the library exposed only motion on/off plus a sensitivity number. Adds `getRoiHuman`/`setRoiHuman` as `async_get_detection_types` / `async_set_detection_type`. Probed read-only on an A000088 and an A001064 first, then the setter verified on both and the cameras restored | No. A settings path; nothing on the streaming path changed. Read-only probes preceded every write, and a camera that does not answer reads as unknown rather than all-off |
| `rc14` | 2026-09-07 | The peer id announced a random client class, out of the vendor's range 11 times in 16; it now announces 2 (WEB), what the vendor web app sends. Screened at 9/9 A000088 across three runs including one on a drained fleet with HA disabled, against 0/9 for the class-0 arm reverted on 08-31 | No. Nothing on the media path changed; the class was screened under the same condition the earlier failure was found in before shipping |

**The box was verified on the released build before the clock was started.**
pip metadata `1.0.0rc11`, and `sdes_open.py`, `client.py`, `webrtc_open.py`,
`exceptions.py` and `__init__.py` all hashing byte-identical to the published
wheel -- checked against the loaded module after the restart, not just the files
on disk.

**And verified streaming, not merely installed.** rc11's change is entirely in
`sdes_open.py`, so the WebRTC sessions that came up on their own after the
restart prove nothing about it - `webrtc_open.py` is byte-identical between
rc10 and rc11. A deliberate SDES open on the PTZ was driven instead
(`camera.record`, 12 s): first video RTP at **+2.5 s**, serving at **+3.0 s**,
1.6 MB written, SRTP decrypting with RTCP PLI/NACK and SCTP SACKs flowing, and
zero library ERROR lines, stalls or tracebacks in the window. A `camera_proxy`
still is not this check - it returns a cached image in under a second without
opening anything.

**Updated 2026-09-06 22:19: the box now runs `1.0.0rc12` and integration
`2.20.3`.** Driven through HACS (`hacs/repository/refresh` then `download` --
the refresh is required, the cached list still offered 2.20.1) and a core
restart, confirmed by the restart's own log signature rather than by the
command returning.

**Verified on the LOADED module, not the files.** rc12 rewrote the
`ICE servers:` line to print the relay COUNT at INFO and move the URL list to
DEBUG; the log now reads `ICE servers: STUN=... relayx8` with no trailing
list, which rc11 could not emit. Alongside it, six line families rc11 logged
at INFO are absent (`camera replied`, `connectionState ->`, `SDP m-sections`,
`Offer m-sections (patched)`, `addIceCandidate (answer SDP)`, `readyState:`)
while every lifecycle line is present: Camera awake, livePlayReq/webrtcReq
sent, getIceConfigReq sent, WebRTC stream open and serving, all x3 for the
three mains cameras that came up.

**And verified streaming, not merely installed.** A deliberate SDES open on the
PTZ (`camera.record`, 12 s): first media **+2769 ms**, serving **+2999 ms**,
H264 video and PCMA audio, SCTP SACKs flowing -- the same shape as the rc11
baseline of +2.5 s / +3.0 s.

**The measured point of the release.** Steady state fell from ~3400 library
INFO lines an hour to **39** (1.6-minute quiet window, one line). HA's rate
limiter has not fired since the restart. This is the live count the change was
projected on, now confirmed against the real box.

**Day zero does not move.** rc12 was cut and installed on 2026-09-06, the same
day rc11 set day zero, and it is not streaming-breaking. Target stays
2026-09-20.

**Box configuration changed 2026-09-07 14:05: mains warm-hold 0 -> 120 s.**
Not a release, so the clock is untouched, but it changes behaviour under soak
and any window that straddles it is not comparable. Mains cameras now go
dormant 120 s after the last viewer instead of being held warm forever.

The reason is the A001064 PTZ. It stops sending media when nobody is watching
and drops its ICE transport, so it cannot be held warm at all: the watchdog was
restarting it indefinitely - 6 restarts in 20.7 h - and each teardown left the
dying serve ffmpeg draining late RTP, emitting a burst of non-monotonic DTS
(215 lines in 8 bursts, median 0.300 s backward, max 3.201 s against a 0.500 s
reorder window). Live view tolerates it; Home Assistant's mp4 recorder does
not, which is how a `camera.record` on a cold PTZ returned 500 while the stream
itself was healthy. 7 of 8 bursts follow the stall/watchdog/ICE-gone triple
within 3-9 s.

**Verified working the same hour.** A primed session, then 180 s with no
viewer, then a second open: `first-media +2588 ms`, `serving +2894 ms` with two
full bridge/ffmpeg starts - a genuine cold open, where a warm session would
have been instant. This also settles that idle-release works in SDES push mode
(the go2rtc viewer query answers, so the `add stream ... 400` seen at setup is
not blocking it) and that the cold-open cost is ~2.9 s, not the 15-22 s the
integration's comments claimed.

**What to watch:** `no media in watchdog window` for the PTZ should stop
appearing. It fired every ~2.6 h before the change.

*One caveat recorded rather than hidden:* the FIRST `camera.record` on the PTZ
returned 500 with an mp4 muxer error (`non monotonically increasing dts`) on a
COLD open; an immediate retry on the now-warm session returned 200. rc12
changes no media-path code, so this is not attributable to it, but it is the
cold-open join case worth a look on its own.

**`camera.kitchen` is expected to be `unavailable`, and it is not the orphan.**
It is `L2_F8A3`, the A001513 that sits on `192.168.100.x` while Home Assistant
is on `192.168.0.x` -- the same camera the live-validation run reports as its
one tolerated `ERROR`. Its root cause is routing, not this library. So two of
the entities are down by design: `camera.deck` (orphaned registry entry, no
device) and `camera.kitchen` (unroutable). Neither is a soak failure, and a
window that shows them down is not showing a regression.

**One thing to know before reading a quiet window as a quiet fleet.**
`webrtc_open` logs every AVIO data-channel message at INFO, keepalives
included -- about one line per camera per 5 s, 156 lines in ten minutes across
three cameras, enough that Home Assistant's own limiter fired twice with
"Module aidot_cameras.camera.webrtc_open is logging too frequently". It is
long-standing rather than new, so under the release rule it does not justify a
release of its own, but it makes this module by far the loudest thing in the
log the soak classifier reads. A sudden absence of these lines means a session
ended, not that the fleet went quiet.

### 2. A 1.2x bitrate difference - premise corrected 2026-08-11

**Read this section before any of the history below it. The number this item was
named for was never measured, and it is wrong.**

Everything under "The original premise, and how it stood for four days" was
written against the claim that an A001064 takes 1900-3700 Kbps where the vendor
app takes **225-500 Kbps** from the same camera. On 2026-08-11 the app was
finally captured doing it, and it does not.

#### What was measured

Capture `aidot-bitrate-20260811-143007.pcap`, with a marker file stamping each
tap so the windows are exact rather than inferred from the rate changes being
measured. One live session on the A001064, quality tapped SD then HD:

    window                       secs    pkts      MB      kbps
    HD / Auto (before any tap)   16.0    3467    3.58    1795.7
    after tapping SD             27.6    3591    2.99     866.3
    after tapping HD             25.2    5461    5.61    1777.5

Against this library's own measured rate for the same camera - 2228 kbps mean
across the interleaved codec campaign, computed from each recording's own
duration:

    vendor app, HD    ~1796 kbps
    this library      ~2228 kbps      -> 1.24x, not 5x
    vendor app, SD     ~866 kbps      -> what a working SD control would buy

**So there is no 5x gap.** There is a 24% difference at equivalent quality, and
a separate 2:1 saving available from a control that works in the app and does
not work here. Those are two different, much smaller problems than the one
thirteen hypotheses were spent on.

Where 225-500 came from is not established. It is not in any measurement in this
repository, and this capture contradicts it by a wide margin at both quality
settings.

#### How the app changes it

Three facts from the same capture, and together they say the mechanism is the
one this library already implements:

* **No renegotiation.** The media 5-tuple `48649 -> 49679` carried 12,701
  packets across both rates. The session was never rebuilt, so the app is not
  re-offering at a new quality.
* **No cloud call.** There is 92 KB of HTTPS near the SD tap and nothing at all
  at the HD tap. A mechanism that only appears for one of two taps is not the
  mechanism.
* **Therefore in-band and mid-session**, on the existing flow - which is exactly
  what `SETSTREAMCTRL` (0x320) is, and exactly how this library sends it.

The command packet itself could not be isolated: outbound traffic is dense
66-74 byte RTCP and STUN, the 126-166 byte packets that stand out recur every
~2 s throughout rather than at the taps, and the payload is encrypted anyway.

#### Measured inside one session, 2026-08-11

The fourteen-session sweep judged `SETSTREAMCTRL` by the profile the NEXT
session came back with, and what it read was **dimensions** - "h264 1280x720",
per frame. The app's own SD tap changes neither of those: same session, same
5-tuple, and a rate that halves. So that table is not evidence about bitrate in
either direction, and the command could have been working the whole time while
being scored against the wrong observable.

It was not. `scripts/live_validate.py --quality-arms` measures the rate either
side of the command **inside one session**: settle 3 s, window A 12 s, send,
gap 2 s, window B 12 s, with the rate taken from the bridge's own byte counter
sampled on the wall clock rather than from a file. Arms alternate per session,
and the control arm waits out the same gap and sends nothing.

Six sessions on the A001064, no voids, raw data in
`aidot-captures/aidot-quality-insession-20260811.json`:

    session  arm       window A   window B    B/A
    1        sd          1828.4     1557.7   0.852
    2        control     2048.6     1832.8   0.895
    3        sd          1846.6     1631.1   0.883
    4        control     2272.2     2135.4   0.940
    5        sd          1926.0     1657.9   0.861
    6        control     1882.8     1617.6   0.859

    sd       n=3   mean 0.865   range 0.852-0.883
    control  n=3   mean 0.898   range 0.859-0.940

The arms overlap - the lowest control ratio sits inside the sd range - and both
decline 10-14% across the same timeline. The video-only per-second series says
what that decline is: a settle over the first 8-12 s of the session, with flat
buckets either side of the tap in both arms, not a step at it. Every sd session
acked 801 to quality=5 within 0.02 s on a live command channel, so this is not a
command that failed to go out.

**The app's 2:1 is excluded.** Its SD tap is a ratio of about 0.48, which is
nowhere near either arm. An effect of a few percent cannot be excluded at this
sensitivity, but that is not the effect being looked for.

The control also disposes of its own confound. Every control session follows an
sd session, so a camera that remembered the setting would flatten both arms for
a boring reason - but the control sessions' window A is if anything higher
(2049, 2272, 1883) than the sd sessions' (1828, 1847, 1926). Nothing carried
over.

#### What is actually open now

Narrow, and worth stating precisely because the old framing was so much bigger:
**our `SETSTREAMCTRL` is byte-identical to the app's, sent in-band mid-session
on the same transport, and does not change the rate - while the app's does.**
Sweeping every quality value across fourteen sessions changed nothing, and the
in-session measurement those sessions could not make agrees with them.

The bar: **either make SD take effect, or record that it does not and why.**
The prize is now correctly sized - about 2:1 from SD, and about 24% from
whatever accounts for the HD difference - rather than the 5x this item promised.

#### ANSWERED 2026-08-23: it does not take effect, and the framing is not why

Run with `scripts/live_validate.py --quality-arms 'sd|' --arm-repeats 2` on the
A001064 - four sessions, SD alternating with a control that waits the same gap
and sends nothing, each session measured against **itself**:

| arm | n | ratios (window B / window A) | mean |
|---|---|---|---|
| sd | 2 | 0.904, 0.866 | **0.885** |
| control | 2 | 0.865, 0.862 | **0.863** |

The SD arm is indistinguishable from the control - marginally *higher*, i.e.
slightly less reduction. Both arms drift down ~14% during a session on their
own, which is exactly the confound the control exists to expose and which every
single-arm measurement before this would have read as success.

The camera acked: `set resolution sd (quality=5): camera acked 801
payload=0000000000000000`, `returned=True channel_ready=True`, tap at +15.0s of
media. Acked, and inert.

**Critically, this was measured with the framing gap closed.** `1.0.0b27` makes
our AVIO control header byte-identical to the app's, including the live-play
dSeq at offset 0 that was previously a random number. So the failure is not the
command's bytes, not its transport, not its timing, and not its framing.

**What is left.** The app's own SD tap DOES halve the rate (866 vs 1796 kbps,
measured 2026-08-11), so the camera can do SD - we cannot trigger it. The
remaining structural difference is the SESSION, not the command: the app drives
`KVSWebRTCChannel`, and this library opens an SDES-SRTP session. That is the
next thing to test, and it is a much bigger question than a control byte.

Recorded as **does not work here**, per the bar. It no longer gates 1.0.0.

#### UPDATE 2026-08-23, later: the 2:1 saving is available - as a CODEC choice

The sentence this section used to end on - "the 2:1 saving stays unavailable" -
is wrong, and the correction did not come from the session hypothesis above.

Ten sessions on the A001064 that evening, measured while chasing a different
lever entirely, separate perfectly by the video payload type they negotiated:

    H264 (pt=96)   1597, 1604, 1623, 1627, 1635, 1643, 1685 kbps
    H265 (pt=97)    766,  769,  774 kbps

No overlap, across two harnesses and three arm orders. **An H.265 session on
this camera costs about half an H.264 session** - the same ratio the vendor
app's SD tap achieves (866 vs 1796) - and unlike every control byte tried here,
codec selection is entirely ours: it is the payload-type order in our own offer
(`AIDOT_SDES_VIDEO_PT_ORDER`, and the `sdes_pin_h264` narrowing).

Two things stop this being the answer today, and neither is a bitrate number:

1. **We cannot choose it - tested, and the answer is no.** Eight sessions on
   the A001064 in blocks of two, half with `AIDOT_SDES_VIDEO_PT_ORDER=97,96`
   and half without, receipts confirming the reordered payload-type list
   reached the SDP:

   | arm | H265 sessions |
   |---|---|
   | reorder `97,96` | 2 of 4 |
   | control | 2 of 4 |

   Identical. Pre-registered acceptance was 3 of 4 and at least two more than
   the control; not met. Narrowing to 97 was already known to return no video
   at all (3 of 3 rounds), so both ways of asking are now closed: **the camera
   picks the codec itself, roughly a coin flip, and RFC 3264 preference order
   does not move it.**

   Watch for a tempting pattern in that data. The first three blocks each read
   `[96, 97]` - first session H264, second H265 - which looks like a clean
   session-position rule. The fourth block read `[97, 96]` and killed it. Four
   of eight sessions were H265 either way.

   The codec finding also exposed a hole in item 2's own record: every
   in-session SETSTREAMCTRL measurement ever made here (ten of ten across
   2026-08-11 and 2026-08-23) had landed on H264 sessions, while the app's
   demonstrated 2:1 rode H265 (pt 98 under the app's numbering). Closed the
   same night: hd sent mid-session on H265 sessions scored 0.703 and 0.694
   against controls at 0.743-0.776 - inert on that encode too. "Acked and
   inert" now stands measured on both codecs, and the capture separately
   disproved the session-type theory (zero DTLS records in 14,383 app-to-PTZ
   packets - the app gets its 2:1 on the same SDES session type we open).

   The app's one remaining visible difference - it sends a quality command AT
   CONNECT (`onConnected -> setResolution(16)`) where we send none - was also
   replicated and measured: armed 0.756 against a paired read-only control at
   0.745 on H264, no effect. The armed-H265 cell could not be filled: the
   camera answered H264 on all eight overnight attempts, where daytime runs
   see H265 roughly half the time, so the codec flip itself appears tied to
   night mode. If anyone fills that last cell, do it in daylight.

   Two last candidates closed 2026-08-24. The app does NOT restart the stream
   on a quality tap: one video SSRC spans both rate regimes in the 08-11
   capture with continuous sequence numbers and no re-offer. And connect-time
   arming - Auto(16) the moment the control channel is up, then sd 16 s
   later, mirroring the app's `onConnected()` path - has no effect either,
   against a paired read-only control (settled rates 927 vs 836 kbps, same
   codec). One n=1 curiosity on record: that sd acked in 2.11 s where enum
   values ack in 0.01-0.19 s - the only latency signal any quality value has
   ever produced. The mechanism behind the app's working toggle remains
   unexplained, and this line is deliberately stopped rather than left
   implicitly open.
2. **H.265 may be unshippable for the defect that started this.** The original
   problem is MSE playback, and browser HEVC-over-MSE support is far narrower
   than H.264. Halving the bitrate is worthless if the client that was failing
   cannot decode the result.

So the prize is real and is now located. Whether to take it is a product
decision about HEVC support in the consumer, not a measurement.

This also retires a false positive worth remembering: run as a strict ABAB
campaign, an unrelated `b=AS:800` knob looked like a decisive 2.1x win purely
because both H.265 sessions landed in its control arm. **Never alternate arms
strictly, and always record the negotiated payload type before comparing
rates.**

#### The original premise, and how it stood for four days

An A001064 takes 1900-3700 Kbps where the vendor app takes 225-500 from the same
camera.

**Twelve hypotheses have died here.** The three most recent, all 2026-08-07 and
all with the measurements recorded:

- **RTCP feedback / REMB.** The camera really does negotiate `goog-remb` - its
  answer advertises it on audio PT 8 and video PT 96 - but sending REMB at 500
  Kbps, verified transmitting and naming the video SSRC, moved nothing. The one
  clean interleaved pair had the REMB arm *higher* than its control, 3859 against
  3355 Kbps. Shipped disabled (`AIDOT_REMB_TARGET_BPS=0`).
- **The stream-quality byte.** `SETSTREAMCTRL` was swept across all six
  `AVIOCTRL_QUALITY` values AND the value 16 the app sends for "Auto" (which the
  enum does not name) - fourteen sessions, each followed by a session that sent
  nothing to catch a next-session effect. All seven acked; all fourteen sessions
  came back h264 1280x720, single dimension cluster. The device properties that
  looked like better explanations were checked too: the camera reads
  `StreamType=0`, so it is not in Auto, and `dynamicStream` is a read-only
  capability flag gating app UI, not a mode. See "The stream-quality control" in
  [APP-PARITY-STATUS.md](APP-PARITY-STATUS.md).
- **Narrowing the offer to H265.** An H265-only offer returns no video at all,
  3 of 3 rounds.

**What was found instead, and it is the first real lever:** this camera serves
*two* profiles for an identical request - h264 1280x720 at 2.5-4.0 Mbps, and hevc
2560x1440 at ~1.1 Mbps - choosing per session, on an offer that advertises both
video codecs. `AIDOT_SDES_VIDEO_PT` pins the offer
and makes the choice deterministic (96 gave h264 720p in 4 of 4). The efficient
hevc profile appears only when both codecs are offered; what selects it is still
unknown, which is why the negotiated profile is now logged at INFO on every
session.

**2026-08-08, later: the corpus exists now, and the first sample is in.** Run
`31285146195` produced three profile lines - one per SDES camera - where every
previous run produced zero:

    the PTZ (A001064)   video profile pt=96 codec=H264
    unit 13-B0fce (A001513)   video profile pt=96 codec=H264
    unit 13-A0d1e (A001513)   video profile pt=96 codec=H264

Three of three chose H264. No hevc instance appeared, so this run cannot answer
what selects it - the question needs a corpus large enough to contain both
outcomes for the same camera. Collection is proven to work; the campaign has not
been run. That is the honest state, and it is a different state from "blocked".

**2026-08-08: that logging was never reaching anyone.** The validation harness
did not configure logging, so the root logger fell back to WARNING-and-above and
every one of those INFO lines was discarded - four runs after the instrumentation
shipped produced zero of them. The standing advice not to open a fourteenth
hypothesis until a corpus accumulated was waiting on data that could never
arrive. Fixed; the first run after that fix is the first that can produce the
record this item asks for.

Note the profile also differs by model: an A001513's h264 is 1280x960, not
1280x720, so codec does not imply resolution across a mixed fleet.

**2026-08-08: "our offer expresses no preference" was wrong, checked against the
code.** RFC 3264 section 5.1 makes the `m=video` payload-type list a preference
list, most-preferred first, and the offer built at `sdes_open.py` has always
carried `96 97` - H264 first. What is true is weaker and more useful: nothing
ever *chose* that order. It arrived verbatim when the SDES open path was split
out of `client.py` and has never been varied. So the camera is already
disregarding a stated preference in the sessions where it answers H265, which
makes reordering a *weaker* candidate than the pin was, not a stronger one -
recorded here so the next reader does not inherit the stronger framing.

`AIDOT_SDES_VIDEO_PT_ORDER` makes the order settable per run, opt-in and inert
unset, because reordering is the only untried lever that leaves both codecs on
the wire - the one condition under which the hevc profile has ever appeared.
Named payload types lead and the rest are appended, so it cannot narrow the
offer, which is what killed the H265-only attempt. **The knob exists; the
hypothesis is untested on hardware.** The experiment that settles it is two
interleaved arms - `97,96` against unset - alternating rather than blocked
(this camera's bitrate varies 839-3698 Kbps on its own, so blocked arms measure
time of day), the sha and the offer's order receipt recorded per session, and
the `video profile pt=N codec=X` line read from the raw log. It is a categorical
outcome, so 3/3 against 0/3 reads and 2/3 against 1/3 does not. Two kills: hevc
at about the control rate says the camera does not read m-line order as a
constraint, and any session with no video at all says order-preference triggers
the same failure as narrowing and the knob is unsafe rather than merely opt-in.

**2026-08-11: the proper campaign ran, and the lever is dead.**

Run `31490379988`: the A001064 alone, six attempts, arms alternating PER ATTEMPT
between the shipped order and `97,96`, none of them stopping on success so both
arms were measured on the same camera in the same conditions.

     #      arm   verdict   pt      kbps   secs
     1  default      PASS   96    2321.1  26.85
     2    97,96      PASS   96    2338.0  26.85
     3  default      PASS   96    2195.8  26.75
     4    97,96      PASS   96    2134.2  26.73
     5  default      PASS   96    2167.3  26.85
     6    97,96      PASS   96    2327.4  26.45

Control mean 2228.1 kbps, pinned mean 2266.5 - a difference of +1.7%, smaller
than the spread within either arm. Codec `pt=96` in all six. Bitrate is computed
from each recording's OWN duration, not from `max_seconds`, so a short recording
cannot masquerade as a low bitrate.

**And the arms provably reached the SDP**: six `offer video codec order=97 96`
receipts in the run log. That is the check the first pin attempt lacked, when a
result "looked confirmed for two sessions before a missing receipt showed it had
never reached the SDP at all". (The artifact reported the receipts as null - the
collector had inherited a WARNING level while the receipt is an INFO line, fixed
since. The log carried them, which is why this result survives.)

**Reordering the offer changes neither the codec nor the bitrate.** This was the
last untried lever named in this item. It is now tried, with the design the item
itself specified, and it does nothing.

**2026-08-09: an earlier, weaker arm - superseded by the campaign above.**

Run `31348997269`, `AIDOT_SDES_VIDEO_PT_ORDER=97,96` on the SDES models, with the
receipt present - `SDES: offer video codec order=97 96` on all 8 opens, so this
one did reach the SDP, unlike the first attempt at the pin. Six sessions produced
a profile line and **all six were `pt=96 codec=H264`**. The control is the last
four runs on the shipped order: **23 profile lines, all H264** - lines, not
independent cameras, since a run emits one per session and several are the
snapshot's own session on a camera already counted.

Read carefully, because the kill stated above does not quite apply. It assumed a
control that produces hevc sometimes, so that "hevc at about the control rate"
would be meaningful. The control rate is zero. Six sessions therefore cannot
separate "no effect" from "a small effect", and this arm is blocked rather than
interleaved. It is evidence against the hypothesis, not the kill.

**The one qualitative result is worth more than the counts.** On one open the
camera's answer came back with TWO video m-sections - `m=video 9 RTP/SAVPF 97`
followed by `m=video 9 RTP/SAVPF 96` - where every other answer in the corpus
carries one. So under a 97-first offer this camera will acknowledge H265 in its
answer, and then send H264 anyway. That is a direct observation of the camera
declining a stated preference, which is what the ordering hypothesis needed it
not to do.

**The second kill did trigger, and is confounded.** `unit 13-A` returned no video
at all on both attempts. That is the unit with an independent, documented stall
- six of the seven stall reports in item 3 are this camera, several of them from
runs on the shipped order - and both of this run's stall reports name ICE causes
(`vetoed-self-ip`, and one with no candidates at all), not a codec cause. So it
does not indict the knob, and it does not clear it either.

`AIDOT_SDES_VIDEO_PT_ORDER` stays: it is opt-in, inert unset, proven to reach the
SDP, and it is the instrument any future arm would use. It should not be
described as promising.

The bar: **explained, or documented as accepted** with the measurements.

**2026-08-11, later: the app's own control was read out of the decompiled
client, and it is the one we already send.** Auto/HD/SD is `SETSTREAMCTRL`
(`0x320`), payload `SMsgAVIoctrlSetStreamCtrlReq` = channel int32 little-endian
+ quality byte + 3 reserved.

The app has TWO implementations and only one of them is ours to compare against:

    LdsTutkChannel.setResolution    -> channel = this.connectId   (legacy P2P)
    KVSWebRTCChannel.setResolution  -> const/4 v0, 0x0            (WebRTC)

The first looked like the answer - the app passing a session handle where this
library hardcodes zero - and it is not. Our cameras take the WebRTC path, and
that implementation sends `channel = 0`. This library sends
`struct.pack("<IB3x", 0, q)`. Byte-identical: same command, same payload, same
channel, same transport.

So the sweep of every quality value found nothing because there is nothing wrong
with what is sent. **What remains is WHEN it is sent, or what state the camera
must be in** - not a missing control. The two ways to settle that, neither of
which is source archaeology:

- capture the app doing it (the iOS capture kit exists) and read when `800`
  leaves relative to LIVING, what the camera answers, and whether the app
  renegotiates afterwards;
- or a timing campaign - `800` before LIVING, immediately after, mid-session -
  measured with the interleaved harness built for the codec arms.

**SUPERSEDED 2026-08-11 - this close does not survive the capture.** It closed
the item on a 5x gap that a measurement then showed to be 1.24x, and closed it
as unexplained when the app's own mechanism turns out to be the command this
library already sends. The accurate statement is at the top of this item. The
reasoning above it is kept because the hypotheses it eliminated are still
eliminated - only the conclusion drawn from them was wrong.
Thirteen hypotheses have been tried and none explains the gap. The last one the
item itself nominated - offer codec order - was run with the interleaved,
receipted design it specified and moved nothing. Nothing further is proposed,
because a fourteenth hypothesis with no new evidence behind it is guessing, and
this item has now cost more than the gap does.

What is accepted: an A001064 takes about 2.2 Mbps where the vendor app takes
225-500 Kbps from the same camera. It streams correctly at that rate. The cost
is bandwidth and, on a metered or congested link, contention - not a broken
feature. It should be stated in the README as a known characteristic of that
model rather than left as an open investigation implying an imminent fix.

Reopen it only on NEW evidence: a capture of the app's own session showing a
control we do not send, or a firmware change. The instrumentation to answer it
quickly is all in place - per-session codec/bitrate in every report, and a
campaign mode that can interleave arms on demand.

### 3. A camera stuck in a failing retry loop - closed 2026-08-11

An A001513 was observed relaunching its serve roughly every 95 s across an
eight-hour window, each attempt dying the same way:

    Could not find codec parameters for stream 1 (Video: h264, none): unspecified size
    [rtsp] dimensions not set
    [out#0/rtsp] Could not write header (incorrect codec parameters ?)

22 launches, 22 "no audio observed before the serve launched", 21 exits with
code 234. Another camera of the same model showed none of it, and a mains camera
hit the same failure once and recovered - so this is one unit in a loop, not a
fleet property. It is a battery camera, so the loop costs charge.

The bar: **root cause found and fixed.** The serve is being launched before
ffmpeg can establish the video dimensions; why that never resolves on this one
unit is the open question.

**2026-08-08 added a sharp clue.** Across 15 sessions the first-media outcome is
bimodal with a 63-second empty band: the slowest SDES pass was 16.8 s and the
fastest no-media was 80.1 s, with nothing in between. Media arrives fast or it
never arrives - so whatever fails here fails at setup, not by degrading.

**This is one defect wearing three names.** It is also the unit 13-A camera entity
no-media case, and the subject of the relay-only investigation: the same unit
streams fine from other hosts on the same LAN, and the one difference found is
that it sits on a different SSID from the Home Assistant host while we advertise
a host candidate it cannot reach. The loop was stopped in 0.17.1 - a battery
camera's keepalive now gives up after five futile sessions - but stopping the
loop is not fixing the cause, and the give-up explicitly does not claim to.

#### 2026-08-08 (later): the per-session gate is found

Half the bar is met. **Why any one of these sessions delivers nothing is now
confirmed. Why it repeated 22 times in a row is not.** Both halves are stated
below; do not read the first as covering the second.

Evidence: the raw logs of five fleet validation runs (31275220411, 31279366049,
31281147686, 31282396141, 31283603368), 17 SDES opens, all of them after the
harness started configuring logging, so the library's INFO breadcrumbs are
present for the first time. A sixth run, 31273232752, was read as well and
contributes no rows: it predates that harness fix, carries zero `webrtc:` lines,
and every camera passed, unit 13-A included.

**The gate.** Media only ever follows the AVIO LIVING trigger
(`sdes_open.py:3969-4015`, the `SDES: sent trigger` line), and that trigger is
armed by exactly one thing: an inbound STUN Binding Success Response
(`_bpkt[:2] == b'\x01\x01'`) from the camera. Its only other term,
`_use_plain_rtp`, is a model-id constant (`_PLAIN_RTP_MODELS`, true for every
A001513 and A001064) and is identical on both sides of the split.

    open   camera            nominated candidate      trigger  first media
    ----   ---------------   ----------------------   -------  -----------
    x5     A001064 the PTZ  <lan-ip>:<port>     yes      12.2-12.9 s
    x5     A001513 unit 13-B  54.144.38.43:<port>      yes      4.7-6.3 s
    x3     A001513 unit 13-A  54.144.38.43:<port>      yes      5.6-6.4 s
    x3     A001513 unit 13-A  <iot-subnet-ip>:<port>     NO       none
    x1     A001513 unit 13-A  (no ICE creds in answer) NO       none

13 opens sent the trigger and every one delivered first media. 4 did not and not
one delivered a byte. 17 of 17, no exception in either direction.

**Why it never arms on this unit.** USE-CANDIDATE goes only to the candidates
carried in the camera's answer, plus peer-reflexive candidates learned from the
camera's own probes (`sdes_open.py:3083-3099`, `:3788-3800`). On the three
host-only opens the answer carried exactly one candidate, `<iot-subnet-ip>`, on a
subnet this host has no route to; the fourth carried no ICE credentials at all.
Nothing we nominated could answer, so no Binding Success came back, so the
trigger never fired, so the camera never started sending.

The camera's own probes did arrive - as TURN Data Indications through our
allocation, 0.5 s after the answer, in both instrumented failures - and were not
learned. A relay-carried probe reaches `_br_obs` (`:3784`) only through
`_br_cam_peer`, which is dropped when `_is_self_peer_ip` matches the
XOR-PEER-ADDRESS; the `_bsrc` fallback is refused because `_bsrc` is the TURN
server and that equals `_hp_host`. VERIFIED: no `learned peer-reflexive` line in
any failing open, and the candidate count stays at 1 across all five permission
installs (`[setup]`, `[trickle host]`, `[trickle srflx]`, `[trickle relay]`,
`[bridge]`), so the camera sent no later candidates and none were dropped.
INFERRED, not verified: which of the two vetoes did it. Both are silent.

**Why one unit.** The cloud device records in these runs carry `ssidName`:
unit 13-A is the only camera on the IoT SSID; every other working camera is on the
main one. This is the mirror image of the disproven relay-only story, not a
revival of it. That story said *we* advertise a host candidate the camera cannot
reach. What is measured here is that *the camera* advertises a host candidate
*we* cannot reach, and nothing else. The relay finding still stands: when this
camera's answer does carry its own relay candidate it streams over the relay,
3 of 3 here, first media 5.6-6.4 s. So the remedy is not "move it to the main
SSID" - it is to make the relay path usable when the answer is host-only.

**Why a mains camera hit it once and recovered.** Same mechanism, already on
record in this codebase: `_record_peer_reflexive`'s own docstring
(`sdes_open.py:737-756`) notes the A001064 PTZ advertising an address on a different /24 as
its only candidate while it sat on that same subnet. That is what peer-reflexive
learning was added for. The PTZ now reports `<lan-ip>` and passes 5 of 5
here, and the learning covers the direct-probe case - just not the relay-carried
one, which is the only path this battery unit has.

**Why the 63-second empty band.** The trigger arms within about a second of the
answer or never. The mechanism has no slow-success state to land in.

**What is NOT established, and it is the rest of the question.** This explains a
failing session; it does not explain 22 consecutive ones. The same unit streamed
on 3 of its 7 opens in this corpus (4 of 8 counting the uninstrumented run) and
on 11 of 26 in the 2026-08-07 sweep. At that rate 22 in a row is on the order of
one in a hundred thousand, so the eight-hour loop needs either a
persistent camera-side state (no relay allocation at all for that window) or a
loop that sustains its own failure. Nothing here decides between them. Note also
that the eight-hour signature above (`[rtsp] dimensions not set`, exit 234) comes
from a Home Assistant log that is not in hand; this corpus shows the same
upstream cause through the file muxer (`[mpegts] frame size not set`, exit 255).
Consistent with, not verified identical to.

**Open sub-question that gates any fix.** A Data Indication reached us while the
only permission installed was for `<iot-subnet-ip>`. Either the cloud TURN server
does not enforce inbound permissions - in which case a Send-Indication return
path to the camera's observed address is viable - or the model of the failing
case is incomplete.

**No fix shipped, deliberately.** The change the mechanism points at - learn the
relay-observed peer address, install a permission for it, nominate it through a
Send Indication - sits on the ICE nomination path that all 13 working opens use,
and its safety turns on telling "the camera behind our own NAT" apart from "our
own mapped address", which is precisely what `_is_self_peer_ip` exists to
prevent. Nominating our own address would have us answer our own check and fire
the trigger at ourselves. That cannot be validated without a camera.

**The smallest experiment, and it settles both open points in one run.** Make
the stall self-reporting: at the first-media wait expiry (`sdes_open.py:4689`)
log at WARNING how many candidates were nominated and their addresses, whether
any Binding Success was ever received, whether the trigger was sent, and the
source of every inbound probe. Two of those facts are computed today and thrown
away - `bridge: drop TURN self-loop STUN peer` (`:3858`) is DEBUG and the
`_bsrc == _hp_host` refusal (`:3785`) logs nothing at all. `_tutk_trigger_sent`
and `_br_stun_resp_count` are bridge-thread locals; publish them on `_bridge_fn`
the way `_sprop_done` already is. One validation run then answers which veto is
the blocker and whether a host-only answer is a transient or a state the camera
holds for hours.

**The kill, stated before the sweep and not triggered by any of the 17 opens:**
an open that logs `SDES: sent trigger` and delivers no media, or one that
delivers media without it.

#### 2026-08-09: the self-reporting run happened, and it settles the open question

The stall report shipped and has now fired seven times: 31289188625 (x2),
31292208608 (x2), 31298451465 (x1), 31348997269 (x2). Counted directly from the
device id on each report line, not from a tally - an earlier draft of this
section got that count and the device wrong together. Read them before anything
above.

**1. The veto is VERIFIED, not inferred.** Every one of the reports names
`vetoed-self-ip`. The section above says "INFERRED, not verified: which of the
two vetoes did it. Both are silent." They are not silent any more and the answer
is the first one.

**2. It is the A001513s, exactly as this item always said.** An earlier version
of this section claimed the stalling unit was the A001064 PTZ. That was wrong and
is retracted: it took the device id from a log line that merely sat nearby rather
than from the device list. Verified against the list, `unit 13-A` is **unit 13-A**
and `unit 13-B` is **L2_181**, both `LK.IPC.A001513`; the A001064 is `the PTZ`
and appears in none of the reports. The lesson is one this project keeps
relearning - never source an identifier from something that only sits next to
it.

**3. There are TWO failure modes here, and now a third shape.** This is the
point that does contradict the item above, which argues one mechanism. They
differ in the field that matters, so treating them as one defect is what kept
this open:

    unit 13-A (A001513), 5 of the 7 - the unit this item describes:
      nominated=<iot-subnet-ip>:P1, <wan-ip>:P2, 54.144.38.43:P3
      use-candidate=sent; binding-success=0; trigger=not-sent
      probes=54.144.38.43:5349 via <wan-ip>:P1 -> vetoed-self-ip
             54.144.38.43:5349 via <wan-ip>:P2 -> vetoed-self-ip
             54.144.38.43:5349 via 54.144.38.43:P3  -> known

    unit 13-B = L2_181 (A001513), once:
      nominated=192.168.7.21:53246, 192.168.7.21:47093
      use-candidate=NOT-SENT; binding-success=0; trigger=not-sent
      probes=192.168.7.21:53246 -> learned; 192.168.7.21:47093 -> learned

    unit 13-A, the sixth of its reports (run 31348997269):
      nominated=none; use-candidate=not-sent; binding-success=0; probes=none

The second is not an ICE-reachability problem at all. Both probe sources were
learned, both are ordinary addresses on this host's own LAN, and then nothing
was nominated. The third is emptier still - no candidates, no probes, nothing to
nominate at all - which points at signaling or the answer rather than at ICE.
Neither is anticipated above.

**What the first mode actually says.** `P1` is the port the camera advertises on
its own host candidate, and it reappears as `<wan-ip>:P1` in the
XOR-PEER-ADDRESS - so the camera's traffic reaches the TURN server from THIS
host's public IP. The camera is behind the same NAT we are. `_is_self_peer_ip`
compares the IP alone (`_ip == _public_ip`), so it refuses the camera's own
reflexive address as if it were ours.

That also names the discriminator the section above said we did not have. Our
own mapped address is one specific ip:PORT; a peer sharing our NAT has the same
IP and a different port, and P1/P2 are never our port. Comparing the pair rather
than the address is both the ICE-correct rule and the safe one.

**It is still not a fix, and here is what is missing.** Removing the veto would
let the address be learned; it would not make it reachable. `<wan-ip>:P2`
is already nominated in all four reports and returns nothing, which is what
hairpin NAT looks like from here. The reachable return path is a Send Indication
back through our own allocation to the camera's server-side address - the change
this item already declined to ship blind - and the veto is what blocks the input
to it, not the whole of it. So the order is: narrow the veto to ip:port, confirm
the verdict changes from `vetoed-self-ip` to `learned` on the next stall, and
only then decide about nomination.

**An honest note on reproducing it.** Seven stalls in nine runs, and none in the
four most recent. Any fix here has to be validated against a failure that does
not appear on demand.

#### 2026-08-11: the A001064 is now in the persistent state, and the log went blind

`the PTZ (A001064)` (A001064) has returned no media on SIX consecutive
attempts across three runs, handshakes of 113-120 s each, zero packets and zero
bytes every time. Every other live camera passed in the same runs.

Two things about it are worth separating, because conflating them wasted a run.

**It is not a code regression.** The failure first appeared on the sha carrying
the cancellation-report change, which made that change the obvious suspect. A
control run of the PREVIOUS sha - `e56a1222`, the one that gated green for
1.0.0b3 - reproduces it exactly: same camera, both attempts, 117.9 s and
113.6 s. Same runner, same cameras, different code. The change is exonerated and
the state is camera-side or network-side.

**The log stopped carrying the evidence at the same time.** Those three runs
produced 364-375 line logs where every earlier run that day produced ~2200, with
the entire `Validate every camera` step contributing forty lines of command echo
and no output at all. So the stall report - the one line that would say WHICH
shape this is - was being written and thrown away. That is fixed by putting the
reports in `live-report.json`, which the harness writes itself, rather than
trusting the runner's log capture.

This is the shape the item has always said it could not explain: six in a row
against a per-session failure rate that has never been anywhere near certain.

**The artifact answered it on the first run, and the answer is the empty shape.**
All four reports for that camera, both attempts, both sessions each:

    nominated=none; use-candidate=not-sent; binding-success=0;
    trigger=not-sent; probes=none

Nothing nominated because the answer carried nothing to nominate, and no probe
from the camera at all. That is not ICE reachability - there is no candidate
pair to fail. It is signaling or the answer, and the investigation belongs
there, starting with what the camera's `webrtcResp` actually contained.

The same run also shows the cancellation report doing its job:
`(33s - caller cancelled the wait)` on each snapshot session, where before there
was silence.

#### 2026-08-11: the stated kill fired. The trigger is NOT sufficient for media

The kill written above, before any of this evidence existed, was:

> an open that logs `SDES: sent trigger` and delivers no media, or one that
> delivers media without it.

`L2_181` attempt 1 in run 31448429413:

    nominated=192.168.7.21:46846, 192.168.7.21:36740; use-candidate=sent;
    binding-success=4; trigger=sent; probes=192.168.7.21:46846 -> learned

Four inbound Binding Successes, the trigger sent, an ordinary LAN candidate
learned and nominated - and zero media for the full 75 s. The retry passed.

**What this kills.** The per-session model in this item is "media only ever
follows the AVIO LIVING trigger, and that trigger is armed only by an inbound
STUN Binding Success". The 17-open sweep found no exception in either direction
and the model was stated as necessary AND sufficient. It is still necessary -
nothing has ever delivered media without the trigger - but it is no longer
sufficient. Something after the trigger can also fail, and nothing above
anticipates it.

**What it does not kill.** The ICE guard fix stands: it addressed sessions where
the check was never answered at all, and those had `binding-success=0`. This is a
different failure that begins where that one ended.

**Three failure modes are now distinguished, and only one has a fix:**

    binding-success=0, probes vetoed    -> the self-check bug. Fixed 1.0.0b3.
    binding-success=0, probes=none      -> signaling/answer. Open. A001064,
                                           persistent, six attempts.
    binding-success=4, trigger SENT     -> post-trigger. Open, and new. Nothing
                                           in this item predicted it.

**2026-08-11: CLOSED, on terms narrower than the original bar.**

The bar said "root cause found and fixed". One of the three modes meets it
outright; the other two do not, and closing the item is a decision to ship with
them rather than a claim they are solved. Stated plainly so nobody later reads
this as fixed:

- **the self-check bug is found and fixed** - shipped in 1.0.0b3, confirmed on
  hardware by the addresses it now learns, and it accounted for five of the
  seven recorded stalls;
- **`probes=none`** and **post-trigger silence** are open. Both are intermittent,
  both look camera-side on the evidence there is, and neither has recurred since
  being instrumented.

What makes them shippable rather than blocking: a stalled session is bounded
(75 s, then abandoned), the keepalive retries, and every camera that hit one of
these has passed on a retry within the same run. The user-visible effect is a
slow first frame, not a dead camera. And they are now self-reporting - the
report says which mode, whether the answer arrived and carried candidates,
whether the trigger was acknowledged, and whether media arrived but could not be
decrypted - so the next occurrence explains itself without another instrumented
release.

Reopen on: a stall that does NOT clear on retry, or any of the three shapes
appearing on a mains camera repeatedly.

#### 2026-08-11 (later): the post-trigger mode is the camera sending nothing

The report gained two counters - inbound RTP counted BEFORE any decryption
decision, and decrypt failures without the cap the log uses - because a camera
that sent nothing and a camera whose media we could not decrypt wrote identical
lines. Media counters are gated on the packet being readable, correctly, so the
second case left no trace at all.

Run 31485643934, unit 13-A attempt 1:

    nominated=<iot-subnet-ip>:48195, <wan-ip>:34986, 54.144.38.43:59366,
              <wan-ip>:48195
    use-candidate=sent; binding-success=6; trigger=sent;
    inbound-media=0; decrypt-failed=0
    probes=... via <wan-ip>:48195 -> learned; ... -> known; ... -> known

**`inbound-media=0`.** The likeliest reading - that the camera sent and we could
not read it - is ruled out by measurement rather than by argument. Not one RTP
packet reached the bridge after six Binding Successes and the trigger.

Two side findings in the same line. `<wan-ip>:48195 -> learned`, and that
address in the nominated set, is the 1.0.0b3 ICE guard fix working on hardware.
And the A001064's six-attempt persistent state cleared on its own that run
(529 decoded frames), which is what the control run had already implied.

**What is left, and who owns each.** Either the trigger never reached the camera
- ours, it is SCTP DATA on a channel whose transport address we choose - or it
arrived and the camera ignored it, which is not ours. `0x1500` is
`E_CMD_AVIO_CTRL_SESSION_MODE_REQ` in the vendor's definitions and `0x1501` is
its RESP, and those answers already arrive on the channel this package parses,
so `trigger=sent` now reads `sent(acked)` or `sent(unacked)`.

**That question is not yet answered.** Run 31487606119 carried the
instrumentation and every live camera passed on its first attempt, so nothing
stalled and nothing was reported. The diagnosis is in place and waiting for a
recurrence; the honest state is that the next stall answers it, not that it is
answered.

The same applies to the `answer=` field added alongside it - unit-tested, and
never yet rendered on hardware, for exactly the same reason. Neither of these
two fields should be read as confirmed live. What IS confirmed live is the
inbound-media / decrypt-failed pair, which fired on run 31485643934 and produced
the finding above.

#### 2026-08-10: the veto is fixed, and the fix is confirmed by what it learns

`_is_self_peer_ip` compared an address where ICE compares a transport address,
so a camera behind our own NAT - same public IP, different port - was refused as
if it were us. The consequence was not only that its address went unlearned: the
branch that answers a relay-carried Binding Request by wrapping the response in a
Send Indication is guarded by the same check, so the camera's connectivity check
was never answered at all. No response, no completed check, no LIVING trigger, no
media. That is the whole of `binding-success=0; trigger=not-sent`.

Now compared as `ip:port`, against the ports our own srflx candidates advertise -
the only ports on the public IP that are this host. A caller that cannot supply a
port keeps the old conservative answer.

**The confirmation is behavioural, not merely an absence of failures.** Run
31399498436 learned four peer-reflexive candidates where every earlier run
learned one, and two of the four are `<wan-ip>:40888` and
`<wan-ip>:52183` - our own public IP on ports that are not ours, which is
precisely the address class the old check refused. All six live cameras streamed
and the run logged no stall at all, unit 13-A included at 415 decoded frames.

**A second run, 31400620372, adds the more useful kind of evidence: a stall that
still happened.** unit 13-A returned no media on its first attempt and passed on
its second. The report for it reads:

    nominated=none; use-candidate=not-sent; binding-success=0; probes=none

That is the THIRD shape, not the vetoed one. No probe reached us at all, so
there was nothing to veto and nothing to nominate - a signaling or answer
failure rather than an ICE-reachability one. Across the two post-fix runs the
`vetoed-self-ip` mode, which was 5 of the 7 reports before, has not recurred
once, while peer-reflexive learning is up from one candidate per run to four and
five, three of the latter on our own public IP.

**What is now established, and what is not.** The guard demonstrably answers
differently on exactly the input it used to get wrong, and the dominant failure
mode has not reappeared. Two runs cannot prove a mode extinct for a failure that
never appeared on demand. And the empty-shape stall is untouched by this fix -
it is a different defect that was always in the corpus, now the only one left
visible, and it needs its own investigation starting at the answer rather than
at ICE.

### 4. Coverage holes - closed 2026-08-08

The bar was: **tested, or explicitly out of scope for 1.0** and said so here.
Both holes are decided below, so this item is closed. It keeps its number
because the working notes refer to it by number.

#### The `liveType=0` / TUTK path: OUT OF SCOPE - reaffirmed by Chris, 2026-08-11

The decision moved twice in one day and both moves were evidence-driven, so the
sequence is worth keeping rather than flattening:

1. Out of scope, on the original reasoning below.
2. Brought INTO scope by Chris when SD retrieval looked like it required the
   native P2P stack - a reasonable call on what was known at that moment.
3. Returned to OUT OF SCOPE by Chris the same day, once the SDES cameras
   answered `HASLISTEVENT` and `LISTEVENT` over the ordinary WebRTC AVIO
   channel. The thing it was going to be spent on turned out not to need it.

**Reopen only on evidence that explicitly requires it** - a feature demonstrably
unreachable on the WebRTC path, not an inference that it might be. The inference
drawn on 2026-08-11 from the A000088s' silence was wrong, and it was wrong in
the direction of buying an expensive transport nobody needed.

The cost, so a future reopen is priced rather than guessed: `libIOTCAPIs.so` and
`libAVAPIs.so` are proprietary ARM binaries of about 220 KB each, shipped in the
APK for arm64-v8a and armeabi-v7a. Using them means bundling vendor binaries in
a public package - licensing and portability both, since a Home Assistant
install may be x86 - and not using them means reimplementing the IOTC protocol
from those binaries. Also worth knowing before anyone starts: `p2pId` is `None`
on all seven reference cameras, so the path may not even be provisioned for
this hardware.

One distinction has to survive all of this, because these notes have already
conflated the two once. "TUTK" names two different things here:

- **`LdsTutkChannel`, the app's camera-channel FACADE.** Never out of scope and
  always reachable: `getSDRecordList`, `setResolution` and `sdRecordSeekPlay`
  are single `sendCtrl` calls over the ordinary AVIO channel this package
  already speaks, and the class also carries `setIsDTLS`. Nothing here was ever
  blocked.
- **The native TUTK P2P stack** - `IOTC_Connect_ByUID_Parallel`,
  `connectPicChannel`, ctypes into libraries this package does not ship. This is
  what the paragraphs below mean, and what the 2026-08-11 SD probes point at:
  two A000088s answered nothing to a byte-exact `LISTEVENT`, and the app's SD
  pages open a pic channel that has no WebRTC equivalent.

So a scope change here is real work, not a flag: implementing or bundling a P2P
transport. That is why it is priced above rather than left as a one-line
decision.

#### (Superseded) The `liveType=0` / TUTK path: out of scope for 1.0.0

Not "we ran out of time". The path cannot be entered, and the part of it that
could be tested is not the part that is uncertain:

- **No device can reach it.** `async_open_live_stream` needs a TUTK UID. Every
  camera queried reports `liveType=2` with no `p2pId` field, and none of the
  three sources `async_get_p2p_uid` tries has ever returned one (the smarthome
  `getP2pId` endpoint answers 200 with a null body). So the call refuses at its
  first guard. See [DEFERRED_FEATURES.md](DEFERRED_FEATURES.md) for the fleet
  query.
- **What is past the guard is a foreign SDK.** `TutkStreamSession._start_sync`
  is ctypes against `libIOTCAPIs.so` and `libAVAPIs.so`, which this package does
  not ship, has never loaded, and cannot obtain. A test would have to mock every
  one of those C entry points, which asserts our reading of the SDK rather than
  the SDK - and the whole reason this is deferred is that the reading is
  unvalidated. Passing tests there would make the path look supported.
- **The interesting code is not even in the tree.** The four improvements the
  deferral is about (license key, session-alive timeout, `CONNECTION_CHECK_REQ`,
  the 24-byte `IPCAM_START`) were reverted; only the base scaffolding remains.
- **Nothing calls it.** The Home Assistant integration opens streams through
  `async_open_webrtc_stream`; `async_open_live_stream` is reachable only by a
  consumer who goes looking for it.

What *is* reachable is the refusal, and that now has a test:
`tests/test_tutk_path_is_out_of_reach.py` asserts that a WebRTC camera - DTLS
and SDES alike - never constructs a `TutkStreamSession`, and that the error
names `async_open_webrtc_stream` as the call to use. It asserts non-construction
rather than the `None` return on purpose: with the guard deleted the call still
returns `None`, because loading the absent native libraries fails and the
failure is swallowed, so a test on the return value alone passes against the
broken code.

Re-activating this needs a `liveType=0` camera in hand. At that point the tests
to write are integration tests against a device, not mocks written in advance.

#### The `async_set_resolution` ack read: DTLS was misdescribed here

The line this section used to carry - "the remaining gap is the DTLS models,
where the read has unit tests only" - was wrong, and two places in this repo
already said so. DTLS was the **first** transport the read was confirmed on:

- `CHANGELOG.md` 0.16.0: "An A000088 over DTLS answers SPEAKERSTART (848) with
  851 in 0.38 s, **SETSTREAMCTRL (800) with 801 in 0.01 s**, and GETSTREAMCTRL
  (802) with 803."
- [APP-PARITY-STATUS.md](APP-PARITY-STATUS.md), measured 2026-08-07 with
  `scripts/avio_probe.py`: 801 comes back in 0.01-0.03 s on an A000088, and 802
  reads the value back - 5 at session start, 5 after `sd`, **1 after `hd`**.

A read-back that changes with what was set is stronger evidence than an ack
alone, and it is on the DTLS model. The A001064 sweep extended the result to
SDES and to every value; it did not fill a DTLS hole, because there was not one.

**The real gap was in the tests, and it was a different gap.** Every existing
test of this call stubs `async_avio_request` (`test_resolution_persists.py`,
`test_control_verdicts.py`), and every existing test of the transport calls
`async_avio_request` directly with a payload of its own
(`test_avio_request.py`). Nothing joined the two: no test asserted that the
bytes the setter builds are the bytes a real `WebRTCSession` puts on the
DataChannel, or that a reply arriving at that session's receive entry point is
the one the setter reads. `tests/test_dtls_resolution_ack.py` closes that with
a real session, the real router and frames in the camera's header layout,
reached through `async_set_resolution`: the frame on the wire decodes as 800
with the quality byte where the camera looks for it; a 801 is read and reported;
an answer that arrives inside `dc.send` is still heard; silence is not dressed
up as an ack and leaves no registration behind; an unprompted 804 is not
mistaken for the reply; and a session whose DataChannel is not open returns
promptly instead of holding a service call for the ack budget.

Two residuals, stated rather than fixed:

- **The DataChannel message handlers themselves are not unit-tested.** They are
  closures inside the WebRTC open sequence, and extracting them to a testable
  helper is a change to a shipped path that this work is not the occasion for.
  They are not unexercised, though: the same router and the same handlers carry
  talk's SPEAKERSTART/851 ack, measured 0.01-0.38 s on an A000088, on every
  session where anyone presses to talk.
- **When the DataChannel is not open, the "no ack" log line still says
  "sent".** `_avio_cmd` returned False and nothing left the host. It is a log
  wording issue on a path whose return value is unaffected, and changing it was
  out of scope here; recorded so it is a decision rather than an oversight.
- **The thumbnail FAIL is the CI account, not the feature - closed
  2026-08-09.** Every fleet run reports `thumbnail=FAIL` on all six live
  cameras. The same call was then run from the OWNING account: six of seven
  cameras returned a CloudFront URL and the seventh, which is offline, returned
  None - so the cloud serves thumbnails and the shared-home member the runner
  signs in as simply gets an empty answer for them. The verdict is left as FAIL
  rather than reclassified, because the call did fail for the identity that made
  it; what changed is that it is now measured from both sides rather than
  explained from one.
- **The SDES snapshot budget was marginal, and the failures were something
  else - 2026-08-09/10.** An A001513 timed out at the 25 s budget in one of
  three runs. Rather than retune on that sample the probe was made to report
  elapsed time, and the next run gave the distribution for HEALTHY snapshots:
  SDES 17.2 / 17.5 / 23.6 s, DTLS 2.8 / 3.0 / 2.9 s. So 25 s left the slowest a
  1.4 s margin - what a budget set just above the then-known maximum always
  does, twice now, the first being 10 s. It is 40 s, about 1.7x the slowest
  sample, with a test asserting headroom rather than a number.

  **That did not stop the failures, and run 31399498436 says why.** unit 13-A
  reported `snapshot_s=50.0`, which is the outer bound (budget + 10) rather than
  a slow snapshot. Its stream session that run was healthy - first media at
  +5473 ms, 415 decoded frames - and its snapshot's OWN session logged no
  first-media line at all. The snapshot timeouts are item 3's stall landing on
  the second session, not a snapshot that needs longer. The budget is right for
  healthy snapshots and was never the cause of the failures.

  **That hid the evidence, and it is fixed as of 2026-08-10.** The stall report
  fired only when the 75 s wait expired, while the snapshot is cancelled at 50 s
  - so the session that most needed explaining was the one guaranteed not to
  explain itself, and raising the budget widened that gap. The report is now
  emitted on cancellation too, with the time actually waited and a note saying
  the caller gave up, so the two exits stay distinguishable. Cancellation still
  propagates unchanged: this package has already shipped one bug where a handler
  caught `CancelledError` and returned normally, and the re-raise is asserted
  directly rather than assumed.
- **Every press-to-talk on an SDES camera opens a second session.** Added
  2026-08-09. `async_speak` reuses `_stream_session` only when it is
  talk-capable, and none of the three loops that set it open with `talk=True`,
  so on SDES it never is. The live view keeps its session and talk opens another
  one alongside it. Nothing has measured what that costs in viewer slots, and
  the camera holds a slot for about 120 s after a session ends.
- **PTZ still reports success for bytes that left the socket, not for a camera
  that moved.** Added 2026-08-09. On SDES the command goes out through a closure
  that holds the datagram socket, so `sendto` can succeed after the session it
  belongs to has been torn down - the send is fire-and-forget by design and
  there is no acknowledgement to read on the A001064, whose firmware answers 848
  but not 802. The related two-way audio defect, where the same shape of
  reasoning produced a False success, is fixed in 1.0.0b2; this one is stated
  rather than fixed because there is no signal to condition it on. What changed
  is that the harness no longer asks a closed session, so a PASS at least means
  a live one.

### 5. No standard for keeping secrets out of logs - closed 2026-08-11

Added 2026-08-08. Four logging sites on the SDES path were printing real SRTP
key material - one of them the decoded master key AND salt in full hex, another
16 characters of two keys plus the full packet hex, unconditionally, on the
first ten packets of every session. These lines reach `home-assistant.log`,
which users paste into public issue reports.

All four now print a truncated SHA-256 fingerprint, and an AST guard over the
module fails if any logging call carries key material again. But nothing was
watching before, and "we looked once" is not a standard.

The bar: **the guard extended beyond `sdes_open`, or a stated reason it does not
need to be.** The same classes of secret (device passwords, aesKeys, tokens)
exist elsewhere in the package.

**2026-08-11: this bar is MET, and had been for days without being recorded
here.** `tests/test_no_key_material_in_logs.py` walks the whole package -
`_PACKAGE.rglob("*.py")`, with an assertion that it found more than twenty
modules so a wrong root fails loudly rather than passing vacuously - and it
matches secrets by attribute and by dict key, not only by bare local name. It is
what caught `batchGetDeviceUserInfo` being logged whole at WARNING, on a path
nowhere near `sdes_open`. Item 5 is closed.


### 6. SD-card recordings cannot be retrieved - closed 2026-08-11

Added 2026-08-09, found while verifying the features the gate never touched.

`IsSupportPlayback` is not a model capability - it says where a camera's
recordings live. Measured across the reference fleet:

    A001064, A001513 x2    IsSupportPlayback=1, no SD card   -> cloud
    A000088 x4             IsSupportPlayback=0, SDcardStatus=1 -> SD card

The library has exactly one working retrieval path -
`async_get_cloud_recordings` to list, `async_get_event_video_media` for a
playable HLS URL. (`async_open_cloud_playback`, named here as the retrieval
path until 2026-08-14, is deprecated: its MQTT handshake returns an empty
response, measured against a camera with ten clips available.) There is no
SD-card equivalent. So
four of the seven cameras on the reference account record continuously to a card
and **nothing in this package can play any of it back**.

That is a feature gap rather than a defect - nothing regressed, it was never
built - but the product describes playback without qualifying it by storage, so
either the capability or the description has to change.

The bar: **implemented, or the docs say which cameras it applies to.** The
second is cheap and honest; the first needs the vendor's SD retrieval protocol.

#### 2026-08-09: that protocol has now been looked at, and it is reachable

Scoping only - nothing is implemented and nothing has been sent to a camera.
What changed is that "has not been looked at" is no longer true, so the estimate
below is from the decompiled client rather than from nothing.

**The command ids are already enumerated** in `docs/APP-PARITY-STATUS.md`, from
`AVIOCTRLDEFs`, and three of them are this feature:

    0x318 / 792   USER_IPCAM_LISTEVENT_REQ       list recordings in a time range
    0x4b5 / 1205  USER_IPCAM_HASLISTEVENT_REQ    does this range hold anything
    0x31a / 794   USER_IPCAM_RECORD_PLAYCONTROL  play / pause / seek / stop

**The request layout is readable.** `AVIOCTRLDEFs$SMsgAVIoctrlListEventReq`
carries `channel:I`, `startutctime:[B`, `endutctime:[B`, `event:B`, `status:B`,
with the two times built by `STimeDay.parseContent(year, month, day, wday, hour,
minute, second)` - and `STimeDay`'s own fields (`year:S` plus six bytes) fix that
at 8 bytes each.

**The transport already exists.** These are ordinary AVIO IOCtrl commands, so
they ride the same channel as PTZ and SPEAKERSTART, and `AvioRequestMixin`
already sends a command and waits for a specific response id on both transports.
Nothing new is needed to ask the question.

**The transport question is now answered, and the answer is favourable.** The
app's SD surface is `LdsTutkChannel` - `getSDRecordList`, `getSDTimeList`,
`sdRecordSeekPlay`, `sdRecordPause`, `sdRecordResume`, `sdRecordRelease` - and
that name is misleading. It is the app's camera-channel FACADE, not the native
TUTK stack: the same class carries `setIsDTLS`, and its `getSDRecordList` body
does one thing, `sendCtrl(0x318, ...)`. `sendCtrl` is the same generic control
send that carries PTZ `0x1001` and SPEAKERSTART `0x350`, both of which this
package already sends on both transports.

So SD listing rides the ordinary AVIO control channel that already works here.
It is NOT behind the `liveType=0` / TUTK path - or so this read suggested. The
2026-08-11 probes contradict it: see the section below, where two cameras
answered nothing to a byte-exact request and the app's SD pages turned out to
open a pic channel with no WebRTC equivalent. TUTK is also no longer out of
scope, by Chris's decision the same day.

**One thing is genuinely unknown, and it is the work:** the RESPONSE layout.
There is no `...ListEventResp` class beside the request ones, so the reply has
to be read off the wire. Whether playback media then arrives on the existing
SRTP path or elsewhere follows from the same experiment - `RECORD_PLAYCONTROL`
is `sendCtrl` too, so the command goes out the way PTZ does, and what comes back
is the question.

**The cheap first step, if this is picked up:** send `HASLISTEVENT_REQ` to an
A000088 with a wide time range and log the reply bytes. It is one command on a
channel that already works, it changes nothing on the camera, and it either
returns a parseable answer - in which case the response format follows from a
handful of ranges - or it does not, which is equally decisive.

**2026-08-11: CLOSED on the documentation half of the bar.** The bar was
"implemented, or the docs say which cameras it applies to", and the second is
now done: the README's Known characteristics section states that recorded video
is retrievable only from cloud storage, that where a camera records is
per-camera rather than per-model and is reported as `IsSupportPlayback`, and
that on the reference fleet four of seven store to a card and cannot be played
back here.

That is the honest close. The capability is NOT implemented and this item is not
claiming otherwise - what it stops doing is implying an imminent fix. Everything
needed to start is above: the command ids, the request layout, and the finding
that it rides the ordinary control channel rather than the out-of-scope TUTK
path.

#### 2026-08-11 (final): the cameras DO answer, and no P2P is needed

Retracting the section below, which is kept because its reasoning is a fair
record of what the evidence looked like at the time and of how it misled.

Run 31497241870, the same probe against the SDES models:

    the PTZ (A001064)  HASLISTEVENT -> 0x4b6, 180 bytes
                      LISTEVENT    -> 0x319, 12 bytes
    unit 13-A (A001513) HASLISTEVENT -> 0x4b6, 180 bytes

**SD event listing works over the ordinary WebRTC AVIO channel.** The inference
that it needed the native P2P stack - drawn from the A000088s' silence plus
`connectPicChannel` having no WebRTC equivalent - was wrong. Silence on those
cameras is a per-model behaviour, not a transport limit.

**The layout, measured rather than assumed.** A 12-byte header fits both replies
exactly:

    channel uint32 LE | total uint32 LE | index | end_flag | count | reserved

`count` equals the body length in both - 168 and 0. And 168 is exactly the 7-day
range requested at one byte per hour, which is what HASLISTEVENT returns: an
occupancy map, not a list. LISTEVENT carries 12-byte records in the same body.

The published TUTK header is 24 bytes and neither reply is that long. The
decoder had been written to the published layout and REFUSED these payloads
rather than forcing them, which is the only reason the real shape was legible;
a decoder that had stretched to fit would have produced a plausible list of
nonsense.

**The event selector decides whether the camera answers at all.** On the same
camera in the same session, `event=0x12` was answered and `event=0` was not.
That variant existed to tell the selector apart from the layout, and it did.

**What is left for item 6 - and a correction to the paragraph this replaced.**
An earlier version said the SD-bearing models "do not answer" and called it a
per-model inversion. That was never established: the A000088s and the SDES
models were probed in DIFFERENT runs, never side by side, so the comparison
crossed two runs and two probe configurations. It then fell apart entirely -
run 31498856848 had the A001064 answer nothing to the same requests it had
answered an hour earlier, because the probe had grown from three requests to
seven at an 8 s timeout and was spending up to 56 s against a session whose
ffmpeg window is 28 s. The probe was measuring itself, for the second time in
this project.

Fixed: 2.5 s per request, and each request checks the session and records
`session_closed` rather than `answered: false` when it could not ask. The first
run that can actually answer the question is the full-fleet one on `d9ec799`,
where every model is probed in one run under one configuration.

**Separately, and on much firmer ground:** a capture of the vendor app shows its
event page using a DIFFERENT cloud endpoint from the one this library calls -
`getRecentEventRecordingList`, which takes a count rather than a time range -
and getting real events back for an A000088, one of the SD-card models. That is
implemented as `async_get_recent_recordings` and is now measured on every camera
in the fleet report. If it returns events, most of this item dissolves: the
recordings would be reachable from the cloud, just through a door this package
was not knocking on.

#### (Superseded) 2026-08-11: the cameras do not answer event listing on a live session

Two runs, and the second one counts. The first sent a 22-byte LISTEVENT with
event=0 and got silence from three A000088s - which meant nothing, because the
request was wrong: `SMsgAVIoctrlListEventReq` has THREE `parseConent` overloads
and the one its field list suggests is not the one the WebRTC path uses.
`KVSWebRTCChannel.getSDRecordList` calls the epoch-long overload, which
allocates `0x18` - 24 bytes - and passes an event selector of `0x12`.

Corrected to the app's exact bytes and re-run (31496516730): still silence, on
both A000088s that streamed, across three variants - HASLISTEVENT, LISTEVENT
with the app's selector, and LISTEVENT with the old one. The request is now
provably the app's, on the same AVIO channel that carries PTZ and SPEAKERSTART
successfully in the same session, so the silence is the camera's answer rather
than a malformed question.

**This makes the earlier scoping too optimistic and it should be read as
corrected.** "It rides the ordinary control channel, so this is days rather than
a rewrite" was inferred from `getSDRecordList` being a single `sendCtrl`. That is
true and insufficient: the app's SD pages call `connectPicChannel` first, which
is a TUTK concept - an extra AV channel over P2P - with no WebRTC equivalent.
On the WebRTC channel `picChannelId` is only a rotating request-slot id used by
`getThumbnais`, not a second connection. So the app may reach SD listing over a
transport this package deliberately does not implement.

What that leaves: either these cameras answer event listing only over TUTK, or
some session state the live view does not establish is required. The next
cheap discriminator is the same probe against the SDES models, since the fleet's
SD-card cameras and its cloud cameras split exactly along the transport line.

**Confirmed by observation, 2026-08-11: the vendor app does fetch SD playback on
these cameras.** That is worth more than the static reading, because it rules
out the one thing that would have made this unbuildable - the cameras
themselves serving it only over a transport this package cannot speak. The path
works on this hardware and the app uses it. What is missing here is the response
layout, which has no class in the decompiled client and has to be read off the
wire, and the answer to where playback media arrives once `RECORD_PLAYCONTROL`
starts it. Both fall out of the same one-command experiment.

### 7. The quality levers have never been measured with enough power - closed 2026-09-04

Chris's instruction of 2026-08-31: once the 80.2 s cliff is resolved,
re-evaluate Auto/SD/HD quality and the other levers previously believed
implemented. **The cliff was resolved on 2026-08-31** (the SCTP receiver never
SACKed and never reassembled fragments), so the item is due. It had been carried
only in working notes and appeared nowhere in this file until now, which is the
kind of thing this file exists to stop.

Two reasons the re-evaluation is needed, both found during the cliff hunt:

1. **Every session on the A001064 was being truncated at 80.2 s.** Any lever
   whose effect only appears over minutes - adaptive bitrate, Auto quality
   switching, encoder ramp, TMMBR/REMB response - had no time to act before the
   transport was torn down. "Implemented but does nothing" and "never got a
   chance to do anything" are indistinguishable under an 80 s ceiling.

2. **The n was far too small to judge any of them.** The outcome on this camera
   is a rate, not a value, and power against an 18 percent to 50 percent effect
   is under 25 percent at the two to six sessions per arm these levers were
   assessed with. The bitrate work closed nine angles on that basis. **Do not
   trust an earlier "measured, does nothing" verdict in this area without
   checking the n it was reached with.**

**Scope decision, 2026-09-04: this runs BEFORE 1.0.0 final, and the soak clock
in item 1 restarts when it ends.** The two cannot overlap - a campaign means
driving the fleet hard for hours, which is the opposite of the ordinary
untouched use item 1 asks for. The alternative considered and rejected was
declaring this out of scope and shipping on 09-17.

**A defect in the campaign machinery, found before the first run.**
`_interleave_arms` returned a strict `sd/control/sd/control` cycle. Balance was
the point and it had that, but a fixed period is its own hazard: this camera
varies things of its own between sessions - measured 2026-09-04, 4 of 44 cold
opens negotiated H.265 rather than H.264 - and anything of the camera's own that
shares the cycle's period lands preferentially on one arm and reads as that
arm's effect. The `b=AS` knob nearly produced a false positive from exactly this
shape. Fixed in `f9f3c84`: balanced blocks, shuffled within each block, with a
seed so a run can be repeated. The campaign had never been run, so the flaw was
ahead of us rather than behind.

The measurement design itself was already right and is unchanged: each session
is compared **against itself** - the bitrate in a window before the mid-session
command against a window after it - so this camera's 839-3698 Kbps
between-session variance never enters the comparison, and a session that
measured nothing is named as a void and re-run rather than averaged in.

#### Result, 2026-09-04: the mid-session sd and hd commands do nothing measurable

A001064 only, arms `sd | hd | control`, seed 20260904, 106 attempts all PASS,
one void named and re-run rather than averaged in. Battery models were excluded:
every attempt on one is a wake.

| arm | n | acked | mean | median | sd | IQR |
|---|---|---|---|---|---|---|
| control | 35 | - | 0.942 | 0.924 | 0.170 | 0.880-0.947 |
| sd | 35 | **35/35** | 0.916 | 0.918 | 0.074 | 0.887-0.956 |
| hd | 35 | **35/35** | 1.056 | 0.907 | 0.453 | 0.872-0.944 |

Mann-Whitney against the control, chosen because the spreads do not support
normality: **sd p=0.97, hd p=0.51.** Neither is significant.

**The command is delivered.** Both arms were acked by the camera 35 times out of
35, so this null cannot be blamed on a command that never arrived - which is the
failure the previous round of quality verdicts could not rule out, and the
reason the summary was taught to report delivery per arm before this ran.

**Read the medians, not the means.** The `hd` mean of 1.056 is an artefact of a
long tail - its own spread reaches 2.458 with an sd of 0.453 - and its median,
0.907, is *below* the control's 0.924. Reported as a mean alone, `hd` would have
looked like a 12 percent increase. All three IQRs sit on top of each other at
roughly 0.87-0.95.

**The control is what makes this readable.** Every arm drifts down about 8
percent: the stream settles on its own between the two windows. Without a
control arm occupying the same point in the same timeline, `sd`'s 0.916 would
have been reported as "sd reduces the bitrate by 8 percent". It does not; that
is what the stream does anyway.

**No cross-session memory.** Sessions following an `sd` arm opened at a median
1476 Kbps against 1475 after a control - so the camera is not remembering the
setting between sessions, which would have been a real result hiding as a noisy
control.

**What this rules out, and what it does not.** With the control's sd of 0.170 at
n=35 per arm, the smallest difference this could detect is about 0.11, i.e.
roughly 11 percent of the ratio. So a mid-session quality command that moved the
bitrate by more than ~11 percent is ruled out. A smaller effect is not, and no
claim is made about one.

**Closed on these terms.** The question the item was raised to answer - are the
quality levers doing anything, or were they only ever assessed under an 80 s
ceiling at n<=6 - is answered for the commands a viewer actually triggers: they
are delivered, acked, and do nothing measurable above about 11 percent.

**What is deliberately NOT answered, and is now out of scope rather than
pending:** Auto quality, adaptive bitrate, the encoder ramp and TMMBR/REMB
response. They are levers of a different shape - they act over minutes rather
than at a point - so two 12-second windows around a command is the wrong
instrument, and measuring them needs a design that does not exist yet. They are
listed under "Out of scope for 1.0.0" below. This is "documented as accepted"
rather than "solved", and it says so here rather than in a summary line that
rounds it up.

## Out of scope for 1.0.0

- **The slow quality levers: Auto, adaptive bitrate, the encoder ramp, TMMBR /
  REMB response.** Moved here 2026-09-04 when item 7 closed. The mid-session
  commands a viewer triggers were measured and do nothing above ~11 percent;
  these four are a different shape, acting over minutes rather than at a point,
  and no instrument for them exists yet - two 12-second windows around a command
  is not it. 1.0.0 asserts that the system is understood and its shape has
  settled, not that every lever has been measured. Whether these do anything is
  a real question and it stays open as work; it is not a 1.0.0 question.

- **The go2rtc add-on.** A private experiment in moving off HACS distribution,
  never yet run with a real camera, and marked not for public release. 1.0.0
  covers the library and the Home Assistant integration; the add-on is a
  separate line of work and should not gate this one.
