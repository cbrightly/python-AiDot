# Changelog

All notable changes to `python-aidot-cameras` are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/), and this project uses
date-less, incrementing versions published to PyPI via GitHub Releases.

## [1.0.0rc13]

### Added

- **The cameras type their detections, and now you can read and set that.**
  These models separate a person from a vehicle from a package from a pet, and
  the library only ever exposed motion on or off plus a sensitivity number.
  `async_get_detection_types()` returns `{key: bool}` and
  `async_set_detection_type(key, enabled)` arms one of them.

  Probed read-only on real hardware before anything was written: an A000088 and
  an A001064 both answer `getRoiHuman` with five flags -- `humanDetect`,
  `vehicleDetect`, `packageDetect`, `petDetect` and `publicZone` -- and
  `humanDetect` already reads 1 on both, so the hardware has been doing this
  all along.

  The setter is read-modify-write against the camera's own object rather than a
  payload built from our own key list. `publicZone` rides in the same object
  and is a real per-camera setting -- 0 on the A000088 and 1 on the A001064 in
  the same probe -- so rebuilding the payload would silently reset something the
  library does not model. Verified against both models: toggling `petDetect`
  took, read back, and left `publicZone` and `humanDetect` untouched, and both
  cameras were restored to their original state.

  A camera that does not answer reads as **unknown**, never as all-off. A
  battery A001513 answers nothing at all here because it is asleep, and
  reporting that as four disabled detectors would invent a state it never
  claimed.

## [1.0.0rc12]

### Fixed

- **The library was the loudest thing in a Home Assistant log.** HA's own rate
  limiter fired against `aidot_cameras.camera.webrtc_open` twice in ten minutes
  on an idle box with three cameras connected.

  The open reports its progress through a helper designed as a status *channel*
  for the command-line tool: when something is routing those messages to a
  screen it logs at DEBUG, and when nothing is, the log itself becomes the
  channel and it logs at INFO. Under Home Assistant nothing ever routes them,
  so every message landed at INFO -- per-packet bridge diagnostics and
  per-tick upkeep sharing a severity with the handful of lines that describe a
  session's life.

  There is now a second channel for the steady-state messages. It still feeds
  the command-line tool's stream, so nothing is lost there, but it logs at
  DEBUG whether or not anything is listening. Measured against an 11.7-hour
  window from a live box containing 14 real camera opens, INFO lines from the
  library fall from 39584 to 437 -- from roughly 3400 an hour to 37. The
  lines that describe a session are deliberately untouched.

- **A camera's decrypted payload was being written to the log in the clear.**
  One bridge diagnostic dumped the full decrypted contents of a packet as hex,
  at INFO, which put a camera's audio into a user's log file. That dump and two
  others are now bounded to a length and a 32-byte prefix. A header is what
  identifies a packet; the rest was never a useful diagnostic.

- **A connection failure could take the diagnostic that explains it with it.**
  When a WebRTC connection fails, the library prints each transport's DTLS and
  ICE state so the failure can be attributed. A single `try` wrapped both the
  reading and the reporting for every transport, with two consequences: one
  unreadable transport ended the loop and hid every transport after it, in a
  diagnostic whose whole purpose is finding the broken one; and if the
  reporting channel itself raised, the handler called that same broken channel
  a second time on its way out, and that exception escaped into the WebRTC
  stack's event dispatch. Each transport is now read and reported
  independently, and reporting cannot raise.

- **A device-list summary repeated forever.** The line naming accessories this
  library cannot drive -- Zigbee sensors, remotes -- was rebuilt and logged on
  every device-list refresh, 143 identical copies in 11.7 hours. It now reports
  when the set changes, which includes the first time and includes it going
  away, and keeps the identical repeat at DEBUG.

## [1.0.0rc11]

### Fixed

- **A camera's video connectivity checks were being answered with credentials
  it had never been given.** The offer carried a separate ICE username and
  password for each media section, but the compression step that builds the
  message the camera actually receives keeps only the *first* pair in the whole
  document and drops the rest. So the camera only ever held the audio pair,
  while the video socket signed its STUN exchanges with the video one.

  The offer now carries a single pair for the whole session, which is what the
  camera holds and what the vendor's own app sends. Confirmed on the wire: the
  camera sends connectivity checks to the video socket and completes them
  there, so it does inherit the session pair rather than needing one per
  section.

  Nothing was visibly broken by this - the cameras tolerated it - but every
  session was authenticating one of its two sockets against credentials the far
  end did not have.

- **ICE credentials now use the character set the standard defines.** RFC 5245
  allows letters, digits, `+` and `/`; we were generating URL-safe base64, which
  substitutes `-` and `_`. Measured over 4000 generations, that put an
  out-of-spec character into 12.5% of usernames and 49.9% of passwords. The
  password is also 24 characters now rather than 22 - the standard's floor, and
  what the vendor app sends.

## [1.0.0rc10]

### Fixed

- **A camera that cannot stream no longer costs 86 seconds and a dead ffmpeg on
  every attempt.** When an open observed no video at all, the serve was launched
  anyway; ffmpeg then failed immediately -- `Could not find codec parameters ...
  unspecified size`, `dimensions not set`, `Could not write header` -- and the
  attempt retried into the same thing. Measured on a camera that dropped off the
  WiFi: 11 attempts and 6 stalls in 25 minutes, each spawning an ffmpeg that
  could not start. Such an attempt now abandons to the retry instead.

  This had been limited to one narrow path on the reasoning that the ordinary
  timeout was a transient Home Assistant's stream worker tolerated and retried
  into. That is retracted: it was a permanent failure being looped on.

  Press-to-talk, the siren and snapshots share the same open path, need no
  inbound video, and are explicitly never abandoned by this.
  `AIDOT_SKIP_DOOMED_SERVE=0` restores the old behaviour.

- **A battery camera's session no longer loses its audio to a few hundred
  milliseconds.** When the stale-offer backstop ends the wait just before the
  first packets arrive, the serve was built with nothing observed and stayed
  video-only for the whole session. It now waits a short grace first -- measured
  with media arriving 4.2 s after the wait ended. `AIDOT_ABANDONED_MEDIA_GRACE_S`
  (8 s, `0` disables).

- **A malformed `AIDOT_ABANDONED_MEDIA_GRACE_S` no longer stops the library
  importing.** It was parsed at import, so one bad value took the integration
  down at setup rather than degrading. It is now read per open and ignored if
  unparseable, which also makes the documented `0` escape hatch work without a
  restart.

- **`AidotCameraNoMedia` is importable from the package root**, like the other
  camera exceptions. Its own docstring tells callers to pace it differently from
  an open failure, which they could not do while the name resolved only inside
  `aidot_cameras.exceptions`.

## [1.0.0rc9]

### Fixed

- **The shortened echo wait no longer risks silently disabling a branch.** The
  wait cut in `1.0.0rc8` rested on one deployment's 17-out-of-17. A camera whose
  echo lands between the new value and the old 2 s would miss it -- and whether
  that echo arrives also decides whether the reply is built, whether the ICE
  window runs 20 s or 2.5 s, and whether the reconnect retry is armed, so the
  branch would go quiet and stay quiet.

  The short wait is now the wait for a camera never seen to echo. An echo seen
  at any point -- including after the wait has already expired -- is remembered
  for that camera, and every later open on it waits the full 2 s again. The late
  echo is not acted on in the open that saw it: the reply has to be sent before
  the relay allocation and the connectivity checks, so building it afterwards
  would reorder the handshake with no camera available to measure the result. It
  is logged, and the line names the setting that makes the longer wait
  permanent.

- **The broker's echo of our own answer could be mistaken for the camera's.**
  It carries our own peer id, so it passed the accept filter, and it resolved
  the future the nomination reads its addresses from -- which meant a session
  could nominate its own host and relay-reflexive candidates, with its own
  credentials, and never connect. Our own answer is now recognised by its sender
  and dropped rather than delivered. Nothing downstream wants it: the SDES path
  built that answer and already holds every value in it.

- **Two views of one camera opening at once could disturb each other's
  handshake.** The marker saying the camera's answer had arrived was stored per
  camera but read per open, so one open could leave its connectivity window on
  the other's answer, or lose its own marker to the other's reset. Both windows
  now ignore a marker older than the open reading it.

## [1.0.0rc8]

### Changed

- **A cold SDES connect is 2.5 s instead of 6.7 s.** Two waits on that path were
  spending time on things that had already happened.

  The ICE responder window was written when the camera's answer arrived after it
  closed, and shortening an earlier wait inverted that: the window then sat for
  seconds holding the credentials the nomination needed. It blocks the event
  loop while it runs, so the answer could not be seen from inside it. The answer
  is now marked ready off that thread, and the window leaves as soon as the
  credentials are in hand and the camera has started its connectivity checks --
  which is also all the window was still waiting for, because an incoming media
  packet already broke out of it, a camera that never probes already left early,
  and the media bridge takes over answering probes about 30 ms later. A camera
  that has sent no probe is untouched, which is every relay-path battery camera
  measured.

  The webrtcReq-echo wait was a flat 2.0 s for the models that were thought to
  need the reply it builds. Over 18 hours of logs, 61 opens: the 17 that took
  the wait timed out 17 times out of 17, the reply was never built once, and all
  17 streamed anyway. It is now 0.25 s, and the timeout is logged rather than
  swallowed. `AIDOT_SDES_ECHO_WAIT_S` restores the old value.

  Measured over five consecutive cold opens on the reference camera: first media
  6702 ms -> 4195 ms -> 2489 ms, nomination 4.60 s -> 2.09 s -> 0.34 s. Battery
  and DTLS cameras are unchanged; neither takes either wait.

  One caveat, stated because the evidence is one fleet: whether that echo
  arrives also selects whether the reply is built, how long the ICE window runs,
  and whether the reconnect retry is armed. An echo landing between the new
  value and the old 2.0 s would now miss it. Such an echo is logged when it
  turns up, and `AIDOT_SDES_ECHO_WAIT_S=2.0` restores the old wait without a
  build.

### Documentation

- **Retracted: the reference PTZ does not answer one codec and send another.**
  Read off the wire across 44 cold opens -- 40 negotiated H.264 and 4 negotiated
  H.265, and in every one the answer matched the bitstream. The old claim reads
  as a demux bug and very nearly bought a fix for one that does not exist.

## [1.0.0rc7]

### Fixed

- **A battery camera went back to sleep in the middle of its own handshake.**
  `setKeepAliveTime` was sent once at open time -- which on a cold camera is
  before it is awake, so it went nowhere -- and then renewed on a cadence
  measured from the open rather than from the camera's wake. Measured on an
  A001513: the camera woke at +10.9 s, stayed awake long enough to emit motion
  events, and was asleep again at +39.8 s with the handshake still running,
  after which no media ever arrived and the open finished at +103.6 s. The
  keep-alive is now re-asserted the instant the camera announces itself, which
  is what the official client's live view does on mount.

- **A stalled first attempt held the full 75 s first-media window.** When a
  battery camera was silent as the wait began, has since been heard from, and
  has still sent nothing, the attempt is now abandoned to the retry -- whose
  fresh offer is served in about 5 s. Measured from the camera's first sighting
  rather than its latest message, because a camera emitting an event every 5 s
  while its handshake goes nowhere would otherwise push the decision out until
  it had gone back to sleep. `AIDOT_BATTERY_STALE_OFFER_GRACE_S` (15 s, `0`
  disables).

- **Signalling log lines could not be attributed to a camera.** The MQTT
  connection carries the whole account and every concurrent open's dispatcher
  logs every message, so one message appeared five or six times and belonged to
  none of them in particular. Lines now carry the sender, read from `srcAddr`'s
  prefix convention, and a message that is not from a camera says so rather
  than being mislabelled as one.

### Performance

- **1.25 s of dead time removed from every SDES open.** The `livePlayReq`-echo
  wait dropped from 5.0 s to 0.25 s once it was measured, but the fast-liveplay
  path kept 1.5 s because that evidence covered the other wait only. Measured on
  its own: 22 runs, 22 timeouts at 1500-1501 ms, no echo ever received. Both
  paths now use 0.25 s. On an A001064 the cold open went from 7044 ms to
  6707-6744 ms to first media; on a battery camera the signalling ahead of
  `webrtcReq` went from ~2.15 s to ~0.82 s.

### Added

- `AIDOT_BATTERY_WAKE_GATE_S` -- hold a battery camera's offer until the camera
  itself answers, which is the official client's own shape. **Measured on
  hardware and shipped off (`0`)**: on this camera family the live-play
  signalling is itself what wakes the camera, so withholding the offer withholds
  the wake. At a 20 s budget, on a camera settled for ten minutes, the gate ran
  its whole budget with the camera silent, the offer went out at +20.9 s, the
  camera's own wake announcement arrived at +23.6 s (after the offer) and first
  media at +27.0 s -- against 5.4-10.0 s on the same camera with no gate. Kept
  as a lever for anyone re-testing on other firmware.

## [1.0.0rc6]

### Fixed

- **A camera that does not echo our `seq` had every reply discarded.** The
  reply matcher required the request's `seq`, which turns a camera that answers
  into one that appears silent -- seen live as `no reply from <device> (4
  messages seen)`. The device id remains a hard filter, because the persistent
  connection carries the whole account and without it one camera reads
  another's answer. `seq` is now only a preference. On the fleet measured every
  reply did carry a matching seq, so this removes a latent failure mode rather
  than a demonstrated one.

- **`aidot-go2rtc` turned a truthy env var into an explicit "off".** The CLI's
  env reader tested the literal `"1"`, so every other value became a `False`
  passed down to `start_keepalive` as a deliberate override. `AIDOT_FAST_CONNECT=true`
  -- the spelling the README documents and `webrtc_open` accepts -- therefore
  *disabled* fast connect rather than enabling it.

  Accepting `1/true/yes/on` is only half of it, because the library's resolvers
  do not share one convention: `AIDOT_FAST_CONNECT` is a truthy allowlist over a
  default of off, while `AIDOT_SDES_SERVE_AUDIO` is a falsy denylist over a
  default of **on**. A single reader cannot mirror both, and folding an
  unrecognised value to `False` is silently destructive on the second:
  `AIDOT_SDES_SERVE_AUDIO=` with no value -- what an empty systemd `Environment=`
  or compose entry produces -- would have dropped audio the library was going to
  serve, with nothing in the log to say why. Anything not plainly true or false
  now returns "no opinion", leaving the knob unset so the library's own resolver
  reads the environment. Verified on an A001064: opened with
  `AIDOT_SDES_SERVE_AUDIO=true` the serve delivers h264 1280x720 + aac 48000,
  where the old reader produced video only.

  Only the standalone CLI was affected. Home Assistant sets these per camera and
  never went through this reader.

- **Two CLI log lines described the wrong path.** The DTLS RTSP push advertised
  AAC while that path transcodes to G.711 (the RTSP muxer refuses the mux's ADTS
  AAC), and the warning for an SDES camera given a non-`rtsp://` output promised
  an HTTP serve for outputs that are not `http` and are in fact taken as a
  publish target.

### Changed

- **A camera on an unreachable subnet now says so.** When every ICE candidate a
  camera offers is a private address on a network this host is not on, the log
  states that directly instead of reporting `first media never arrived` 75 s
  later. Measured on an A001513 advertising `192.168.100.4` to a host on
  `192.168.0.0/24`: STUN binding successes still accumulate, so connectivity
  looks fine, but the data channel never establishes and no media ever arrives
  (`inbound-media=0` with `decrypt-failed=0` -- nothing reached us at all). The
  old wording sent people looking at the camera; the cause is that it sits on a
  different network segment, typically a mesh node, extender or guest SSID.

  Detection only. The relay is already advertised and TURN permissions are
  already installed for every camera candidate; these cameras simply do not use
  it, and forcing `AIDOT_SDES_CONNECTION_MODE=relay` is documented as not
  steering them. Public relay and reflexive candidates are never flagged, and
  when the host's own networks cannot be determined nothing is flagged at all.

## [1.0.0rc5]

### Fixed

- **Camera property reads returned nothing inside Home Assistant.**
  `async_query_device_action` opened its own MQTT session, which connects with
  the same `mqttClientId` the integration's long-lived connection already uses
  -- and a broker evicts the older session on a duplicate client id. The query
  and the integration knocked each other off, so the reply never arrived and
  the call returned `None`, indistinguishable from "this camera does not
  support the action". It only appeared to work when tested with the
  integration stopped, the one condition that hides the conflict. It now uses
  the persistent connection, exactly as `_mqtt_device_cmd` already did, and
  falls back to a per-op session only when there is none. A missing reply is
  also logged rather than returned silently.

- **One camera could read another camera's answer.** The persistent MQTT
  connection is subscribed to the whole account, so replies for every device
  arrive on it, and the matcher keyed on the action alone. Observed live: four
  cameras all reported identical SD-card figures, which belonged to whichever
  camera answered first. Replies are now matched on the device id and on the
  request's own `seq`.

## [1.0.0rc4]

### Fixed

- **A camera could fail to publish for a moment after Home Assistant restarts.**
  The serve ffmpeg is launched as soon as media arrives, and go2rtc's RTSP
  listener may not be back yet. ffmpeg's first connect was then refused, it
  reported `Could not write header (incorrect codec parameters ?)` and exited
  145 -- which reads as "stream ended" and took that camera's view down until
  something retried. Measured on a live deployment, every occurrence sat inside
  a one-minute window around a restart and none in steady state. The publisher
  now waits (bounded) for the target to accept a connection before launching,
  and still launches afterwards if it never does, so a genuinely dead target
  surfaces as ffmpeg's own error rather than a silent refusal to start.

### Added

- **Sound detection, WiFi and SD-card details.** The cameras answer several
  `devActionReq` reads with real data that nothing could reach while the only
  helper returned a bool. `async_query_device_action` returns the camera's
  reply, and on top of it: sound detection (`sound_enable`, `glass_Break`,
  `smoke_T3`, `smoke_T4`, `baby_cry`, `all_sound` on the cameras measured, read
  and write), WiFi SSID and signal, and SD-card present/total/used. A camera
  that does not answer reads as unknown, never as all-off -- battery cameras
  reply to none of these while asleep.

### Fixed

- **`devActionReq` was going out in a shape the camera ignores.** We sent only
  `devId`, `action` and `in`; the vendor app's builder also sends `seq` and
  `tst` at the top level and a `parentId` beside `devId`. Measured against a
  real camera, the short form drew no reply at all on any response topic. The
  siren (`playSound`) rides this request, so that control could not have been
  working.

### Added

- **`async_reboot()`** -- asks a camera to reboot, the same
  `devActionReq({action: "RebootFunc", in: []})` the app's camera settings page
  sends. It reports that the request was sent, not that the camera rebooted: a
  reboot succeeds by leaving the network, so waiting for an acknowledgement
  would report success as failure. It refuses when the cloud explicitly reports
  the camera offline, mirroring the app, which only offers the button on a
  reachable device. The camera is away for a few seconds afterwards.

## [1.0.0rc3]

### Fixed

- Direct-TS serve: a new consumer is spliced on a real video keyframe instead
  of a container flag. The mux knows when it is about to write one and was
  discarding that knowledge; everything downstream then tried to rediscover it
  from the container, which does not carry it -- PyAV's mpegts muxer does not
  set `random_access_indicator` on the video PID for this stream, so a sync
  gated on that flag never fires. The fallback accepted a random-access point
  on ANY pid, and AAC audio sets that flag about 50 times a second, so a late
  joiner was spliced onto audio and handed video mid-GOP referencing an SPS/PPS
  it never received -- "non-existing PPS 0 referenced", a video track that
  never produces a frame. The mux now announces the keyframe to the sink before
  muxing it. The old test survives only as a grace-period fallback for a source
  that never signals, and is disabled outright once a source has signalled.

## [1.0.0rc2]

### Changed

- SDES open: the `livePlayReq` echo wait on the models excluded from
  fast-liveplay (the A001064 and the other role-reversal cameras) drops from
  5.0 s to 0.25 s. Across 22 h of logs it ran 169 times and timed out 169
  times, and none of the 5000+ inbound messages in that window was a
  `livePlayReq`; the code proceeds on timeout anyway, so the wait has never
  changed behaviour, only delayed it. Measured live on an A001064: time to
  first media falls from 11534 ms (n=4, sd 100) to 6819 ms (n=5, sd 114) --
  4715 ms, 41% of time-to-first-frame -- with no open failures in either arm.
  Fast-liveplay models keep their 1.5 s, which came out of its own soak.
  The wait is still honoured, so a broker that does echo still short-circuits
  it. Override with `AIDOT_SDES_LIVEPLAY_ECHO_S`.

## [1.0.0rc1]

Same code as 1.0.0b34, which is published and validated; this is the version
string moving from beta to release candidate.

`docs/ROAD-TO-1.0.md` names one open item for 1.0.0 - "two weeks with no
streaming-breaking release", with the cadence as the evidence - and that clock
has not run yet. An rc says the shape is right without claiming the cadence.
Still a PEP 440 pre-release, so plain `pip install` and HACS do not pick it up.

## [1.0.0b34]

### Fixed

- **The SDES data channel is now acknowledged, which ends the A001064's 80.2 s
  streaming cliff and restores PTZ, two-way audio and SD listing for the whole
  session.** SCTP puts acknowledgement on the receiver (RFC 4960 s6.2) and this
  library never sent a SACK. The camera pushed a DATA chunk on the control
  channel, we acknowledged none of them, its retransmission timer ran to
  exhaustion, and it ABORTed the association. Measured over 47 stalled sessions,
  timed from first media:

      last camera DATA on the control channel   58.35 s   sd 0.10
      last SACK the camera sent us              60.08 s   sd 0.05
      first SCTP ABORT from the camera          61.42 s   sd 0.10
      session torn down                         80.2  s

  After the abort the AVIO heartbeat (5156) could no longer reach the camera, so
  its keepalive clock stopped being refreshed and its own 20 s watchdog closed
  the session with -50020: 80.2 - 60.08 = 20.1 s against a 20.000 s constant in
  the camera. On hardware the camera answered every heartbeat with an ABORT from
  61.4 s; with the fix it answers with a SACK and the session runs unbounded.

  The same dead channel is why PTZ, two-way audio and SD listing stopped
  answering about a minute into every session - they all ride it. A PTZ command
  issued at 470 s reached our socket and the camera never saw it.

  The camera's own send pattern is the independent confirmation: DATA used to
  arrive every ~3 s (retransmissions of unacknowledged chunks) and now arrives
  once per heartbeat.

- **A fragmented reply is reassembled before it is parsed, which makes SD card
  listing work on SDES cameras for the first time.** A DATA chunk carries B and E
  flags (RFC 4960 s3.3.1) and a ~2.8 KB listing page arrives as several ~1.2 KB
  fragments. Every fragment was handed to `parse_avio_response` as though it were
  a whole frame: the first was correctly refused (its declared payload length
  overruns the fragment) and the rest decoded as junk command ids. The reply sat
  on the wire while the caller timed out and the card read as unreadable. The
  DTLS path reassembles in its SCTP stack, which is why this only ever affected
  SDES. An A001064 now returns eight days of recordings.

- The peer id's client-class character is deliberately still random. The
  A001064 does read its client class from the first character of the peer id's
  second field - its firmware, the vendor Android app and the vendor web app all
  agree - and setting it correctly was tried in this release and reverted before
  publication. Pinning it fleet-wide stops the A000088 streaming: three of them
  went 0 for 3 over nine attempts, each completing its DTLS handshake in under
  two seconds and then receiving no media, while the same build streamed the
  A001064 on the first attempt. Reverting that one line restored 3 of 3. The
  A000088 is a different SoC whose firmware has never been read, and it does not
  ignore the byte. Nothing needs the pin - the 80.2 s cliff is fixed in the SCTP
  receiver above.

- **The peer id's install-identity field is stable for the life of the process.**
  It was six fresh random digits on every open (329 distinct ids across 836 opens
  in 19 hours), so a client reconnecting every couple of minutes looked like
  hundreds of different clients and the camera's returning-client path could
  never match.

- **A session whose ICE transport disappears is reopened immediately** rather
  than after the media watchdog expires. Measured outage 61.2 s -> 31.5 s. With
  the acknowledgement fix above this path should now be rare.

### Changed

- The measurement knobs (`EXPT_CAP_FILE`, `EXPT_PEERID_FILE`) are off unless
  `AIDOT_EXPT_CAP_FILE` / `AIDOT_EXPT_PEERID_FILE` names a file. They previously
  read a hardcoded Home Assistant config path on the event loop for every
  session, which Home Assistant's blocking-call detector reports. With no env var
  set the library performs no file I/O for either.

## [1.0.0b33]

### Fixed

- **Media is demuxed by the ANSWER's payload numbering instead of a fixed
  table, which recovers every H265 session on an A001064** - the bridge split
  a BUNDLEd stream into ffmpeg's audio and video loopbacks from a fixed table
  (96/97/98 video, 0/8 audio), and that table is wrong for this fleet.
  Measured across 107 opens: 15 of them (14%) negotiated H265 on payload
  type 0, said so in the answer (`m=video ... 0` with
  `a=rtpmap:0 H265/90000`), and then sent full-size video packets on pt=0
  while audio ran normally on pt=8. The fixed table posted every one of those
  video packets to the AUDIO loopback, so no video was ever observed, the 75 s
  first-media wait ran out, and the serve launched into an empty stream and
  exited - 82 s, then a full reopen. The other 92 opens answered
  `m=video ... 96` and worked; the separation is perfect in both directions.

  Payload numbering is per-m-section by definition, so the answer already
  named the kind of every payload type. `answer_pt_kinds()` reads it (a type
  claimed by both an audio and a video section is dropped rather than guessed
  at), the bridge consults that map before falling back to the tuples and then
  to source-socket routing, and `rewrite_rtp_payload_type()` translates a
  camera-numbered video type into the serve SDP's numbering (0 -> 97) with the
  marker bit preserved. The translation is gated on plain-RTP models and on
  the bridge having decrypted the packet, since editing a byte of a packet
  ffmpeg will itself authenticate would break the SRTP auth tag.

  On hardware a pt=0 session now binds its serve at 11.6 s instead of 82 s and
  reports `video profile pt=97 codec=H265`; sessions answering pt=96 are
  unchanged.

- **A video packet arriving before the answer no longer latches as the
  session's first audio.** The bridge starts before the answer lands, so a
  video packet on an unexpected payload type could beat the map in. Left alone
  that narrowed the serve's audio line to a type no audio uses, and the mpegts
  mux then withholds PAT/PMT waiting for a stream that never produces - which
  costs the picture, not just the sound.

## [1.0.0b32]

### Fixed

- **SDES serve input-stall tolerance**: mains serves pass `-listen_timeout 30`
  on the SDP input, whose 10 s default turned a transient media stall into a
  full serve teardown and cold reopen. Battery cameras keep 10 s - their stops
  are real sleeps. `AIDOT_SERVE_INPUT_TIMEOUT_S` overrides both.

- **Mid-session LIVING nudge**: on more than 2.5 s of media silence the bridge
  re-sends the AVIO LIVING trigger (at most 3, 2 s apart) and re-arms the PLI
  timer on resume so an IDR follows immediately. Heartbeats alone provably do
  not revive a stalled session. `AIDOT_SDES_STALL_NUDGE=0` disables it.

## [1.0.0b31]

### Added

- **`media_path` in `SdesSession.media_stats()`: the receipt for which path a
  session's media actually took** - `direct` or `relay`, classified from the
  first packet's source address against the session's TURN servers. The
  connection preference is only a preference (the camera decides where to
  send from), and until now telling the two apart needed a wire capture.
  Flows into `scripts/live_validate.py` reports automatically.

- **`AIDOT_SDES_CONNECTION_MODE` / per-open `sdes_connection_mode`: one knob
  for the media path** - `auto` (default; every reachable candidate, LAN
  preferred by ICE priority, relay as last resort - the shipped behaviour,
  now stated and instrumented), `lan` (no relay; same lever as
  `AIDOT_SDES_SKIP_TURN_PREALLOC`, composed through the same resolver so the
  battery force-keep applies - a cloud-woken camera has no other path back),
  and `relay` (experimental).

  `relay` is documented as not steering this fleet, because that was
  measured rather than assumed: with only the relay candidate on offer, and
  then again with `c=`/`m=` moved to the relay allocation and a
  CreatePermission for our own WAN address pre-installed (gated to relay
  mode - indiscriminate installs caused TURN self-loop storms), an A001064
  and an A001513 both still dialed our host address directly. The firmware
  learns it from our own ICE probes and replies to wherever packets came
  from. Forcing the relay for real means suppressing every direct-path
  outbound, which is unbuilt. The candidate blocks and c=/m= endpoints now
  come from tested helpers either way, and every non-default mode leaves a
  status receipt.


## [1.0.0b30]

### Fixed

- **A credentials-file country other than US now reaches the password login.**
  The validator's token-sharing branch published credentials into the process
  environment for the shared login helper to re-read, and the country leg of
  that shim was dead: the helper's default was bound at module import, so the
  assignment made after import could never reach it. Credentials now travel
  as explicit parameters (`_make_client(session, username=..., password=...,
  country=...)`), which also stops the decrypted password from being exported
  to every spawned child process.

### Changed

- **Quality pass over the b28/b29 code, from a four-angle review.** REMB goes
  through a `_send_video_remb` helper like its NACK and TMMBR siblings - the
  inline copy was where the raw-socket relay bug hid - and all three share
  one protect-and-send tail. The RTCP cadence guards are cost-ordered so the
  default configuration pays at most one attribute read per packet on the
  bridge's packet loop, and the readiness math and sender lookups run at most
  once a second. One `_env_positive` parser replaces three copied env
  readers; the `b=AS` knob is read once per offer so its status receipt can
  never disagree with the SDP actually sent; `build_nack` uses the RTPFB
  constants defined beside it; a dead module constant and a vacuous rebuild
  guard are gone. Missing credentials raise `CloudAuthUnavailable` instead of
  exiting from library code (the go2rtc CLI still exits). No behaviour change
  on any streaming path is intended; this release exists so the refactor
  soaks ahead of rc1 rather than having its first field exposure there.

## [1.0.0b29]

### Fixed

- **Test fixtures and docs use documentation-range and placeholder addresses
  throughout.** The role-label scrub in 1.0.0b28 renumbered the private
  addresses and stopped one token short: log excerpts in one doc and one test
  fixture still carried the real WAN address those sessions egressed from, so
  the b28 sdist ships it in a single test file (the wheel never carried it,
  and the same fixture has been in every sdist for weeks). No code change;
  the self-peer-detection semantics the fixture exercises are unchanged under
  an RFC 5737 address. This release exists so the current artifact is clean.


## [1.0.0b28]

### Fixed

- **REMB was written straight to the socket, so it never arrived on a relayed
  session.**

  This is the NACK bug, still present in the REMB path. When a camera reaches
  us through our TURN relay, the address a packet arrived FROM is the relay,
  and raw SRTCP bytes written there are parsed as a malformed STUN message and
  dropped -- while `sendto` reports success, so the send looks fine and the log
  says it went out. `_send_video_nack` takes a relay-aware `send` callable for
  exactly this reason, as do the RR and the AVIO trigger; REMB was left behind.

  It also used a literal `0xAB12CD34` where `_CAM_RTCP_SENDER_SSRC` exists. The
  SRTP TX policy is keyed on that constant, so a drifting literal is a packet
  the camera drops.

  Worth recording beyond the code: "REMB was measured to do nothing" is one of
  the reasons REMB ships off, and on a relayed session that measurement could
  not have been valid. The conclusion is not being revisited -- the measurement
  that produced it was on a direct session -- but the caveat belongs on it.

  Exercised on the relayed A001513 with `AIDOT_REMB_TARGET_BPS=500000`: the
  session passes, the receipt fires, and on the wire 41 RTCP PT=206 go to the
  camera's TURN allocation alongside 158 PT=205 NACKs. What that does not prove
  is the wrapping branch -- in that topology the camera's relay candidate is a
  real forwardable address, so `_br_cam_peer` is correctly None and the old
  code would have reached it too. The shape the fix exists for, where the
  camera arrives through OUR allocation, has not been observed here.

### Added

- **`AIDOT_SDES_TMMBR_BPS` / `AIDOT_SDES_TMMBR_AFTER_S`** -- ask the camera not
  to exceed a bitrate, via RTCP TMMBR (RFC 5104 s4.2.1). Off by default.

  Distinct from REMB, which this camera ignores: REMB reports an *estimate* of
  available bandwidth, TMMBR states a *bound*, and firmware can honour one
  without the other. The camera acts on RTCP feedback it never negotiated --
  our SDES offer advertises no `a=rtcp-fb` line at all, yet the NACKs we send
  recover 98.4% of losses -- so `ccm tmmbr` being absent from its answer is not
  a reason to assume it is ignored.

  `AIDOT_SDES_TMMBR_AFTER_S` holds the first TMMBR back by that many seconds of
  media, measured from the first video packet, so the bound can be measured
  *within* one session (window A before, window B after) rather than between
  sessions. That matters: between-session comparison produced two wrong answers
  on this camera in one day.

  **Measured 2026-08-23, and it does nothing.** Within-session on the A001064,
  the bound starting at +15 s of media so window A is uncapped and window B is
  not, both arms otherwise identical control arms that send no quality command:

      tmmbr    ratios 0.745, 0.752   mean 0.748
      control  ratios 0.737, 0.673   mean 0.705

  The TMMBR arm is marginally *higher* than the control, against a
  pre-registered acceptance of 0.65. Receipts confirm two TMMBRs went out and
  both arms negotiated the same codec where it mattered. Shipped off, like
  REMB, and for the same reason.

- **`AIDOT_SDES_OFFER_BANDWIDTH_KBPS`** -- add a `b=AS:<kbps>` receive-bandwidth
  ceiling (RFC 4566 s5.8) to the offer's video section. Off by default, and
  **measured to do nothing** over ten sessions on an A001064. Kept, off,
  following `AIDOT_REMB_TARGET_BPS`, which ships off for the same reason.

  Kept mostly for the trap it exposed. Run as a strict ABAB campaign it looked
  like a decisive 2.1x reduction (1631 vs 768 kbps). Re-run AABB it collapsed,
  and sorting all ten sessions by the payload type they negotiated explained
  every number without reference to the knob: H264 1597-1685 kbps, H265
  766-774, no overlap. The camera answered H.265 on three of ten opens on its
  own, and both landed in the control arm. **Never alternate arms strictly, and
  record the negotiated payload type before comparing rates.**

### Changed

- **`AIDOT_SDES_VIDEO_PT_ORDER` is now tested on hardware, and it does not
  select the codec.** It had shipped documented as "experimental and untested".

  The motive was real and is worth knowing: on an A001064 an H265 session costs
  about half an H264 one (766-774 against 1597-1685 kbps, ten sessions, no
  overlap), which is the same 2:1 the vendor app gets from its SD control and
  which no bitrate control we have found can produce. But eight sessions in
  blocks of two, half with `97,96` and half without and with receipts
  confirming the reordered list reached the SDP, returned H265 in 2 of 4 either
  way. Narrowing the offer to 97 was already known to return no video at all.
  The camera picks, at roughly a coin flip, and RFC 3264 preference order does
  not move it.

- **`scripts/live_validate.py` can share one login via `AIDOT_TOKEN_FILE`.**

  The AiDot cloud keeps a single live token per account, and a second login
  invalidates the first. A campaign that held a client open to read a cloud
  property between sessions lost its own session the moment the first child
  logged in -- `401 /v17/houses`, then `400 /v17/users/refreshToken`, the
  refresh token rotated out with it and no recovery. Three of its four arms
  were lost.

  The write-back token cache already existed for the go2rtc CLI; it moves to
  `aidot_cameras/cloud_auth.py` and the validator goes through the same door,
  rather than a second copy of an atomic 0600 token write. With
  `AIDOT_TOKEN_FILE` unset the validator logs in exactly as before, which is
  what the release gate does.

## [1.0.0b27]

### Changed

- **AVIO control commands now carry the session dSeq, matching the app.**

  The app's control header (`KVSWebRTCChannel`, decompiled) is 28 bytes
  little-endian and ours agreed on every field but one: at offset 0 the app
  writes a per-client counter that starts at 100 and increments on every
  control command, and we wrote `random.randint(0, 0x7FFFFFFF)`. We already
  kept that counter -- `_next_dseq`, commented "app parity" -- and used it for
  `livePlayReq` only. The app routes 16 of its 17 control commands through the
  dSeq-attaching sender and only the heartbeat (0x1424) without one.

  **This is parity, not a fix, and it is explicitly not the reason
  SETSTREAMCTRL is ignored.** `button.*_ptz_*` is AVIO 0x1001 sent through the
  identical frame builder with the same random dSeq, and it is class A on
  physical evidence -- the camera pans. A camera that pans on a random dSeq is
  not validating it. Shipping this as a cure for the quality control would have
  been hypothesis fourteen dressed as a conclusion.

  Verified on hardware after the change: the pan still works. Mean frame
  difference across a 5 s pan **35.2 and 36.0**, against no-command controls of
  11.6 and 4.0 on the same session.


## [1.0.0b26]

### Fixed

- **Retransmission requests can no longer pile load onto a link that is losing
  packets because of load.**

  Measured on the reference A001064, same camera and position, wire captures
  across one day:

  | offered | loss |
  |---|---|
  | 2.21 Mbps | 0.37% |
  | 2.59 Mbps | 0.70% |
  | 3.07 Mbps | 0.94% |
  | 3.90 Mbps | 7.25% |

  Loss rises monotonically with offered load, which rules out fixed signal
  strength -- nothing moved -- and makes the link bandwidth-limited somewhere
  above ~2 Mbps. A NACK therefore spends the exact resource it is trying to
  repair, which is why the 100 ms x 4 retry experiment collapsed recovery from
  99.2% to 73.6% rather than improving it.

  The remaining hole was burst behaviour: every number in a wide gap is
  eligible at once, so the tracker fired a full report on each of the next
  several packets -- measured, 12 sends across 31 consecutive packets, aimed at
  the moment the link was least able to carry them. Reports are now at least
  20 ms apart, which coalesces a burst into fewer, fuller requests without
  dropping a single sequence number. At the measured steady-state loss (about
  two per second) it never triggers, and 20 ms is invisible against a 45 ms
  median recovery and a 500 ms budget.

## [1.0.0b25]

### Fixed

- **A retransmission that arrives too late is now dropped instead of
  forwarded.** Asking for a lost packet only helps if the repeat beats
  ffmpeg's reorder window (`-max_delay 500000`): it is then put back in place
  and the frame is repaired. A repeat that arrives after it cannot be -- the
  damaged frame has already been emitted -- so forwarding it just inserts an
  out-of-order packet and the muxer clamps its output DTS.

  Observed in production once NACK was live: `RTP: dropping old packet
  received too late`, and on the wire repeats landing with their sequence
  number 4 to 115 behind the newest, each followed by a run of
  `Non-monotonic DTS`. Self-inflicted, and now suppressed at the source. The
  serve-exit log reports how many were dropped.

## [1.0.0b24]

### Fixed

- **The NACK now reaches a camera on a relayed session.** It was written
  straight to the address the media arrived from; when the camera reaches us
  through our TURN relay that address is the relay, and a raw write there is
  parsed as a malformed STUN message and dropped. Worse, the send "succeeded",
  so the log claimed a NACK had gone out on a path where nothing reached the
  camera. It now goes through the same relay-aware sender as the RR and the
  AVIO trigger.

- **A serve we stopped on purpose is no longer reported as a crash.** This is
  the "publisher dies every ~3 minutes" that three separate investigations
  chased on an A001513.

  The exit classifier quieted a locally-initiated teardown only when the exit
  code was NEGATIVE, on the premise that a stop "routinely ends in a signal
  death". That is not true for SIGTERM: ffmpeg installs its own handler, does
  not die by the signal, and calls `exit_program()`, which returns **255** when
  a signal was received. Python reports a negative code only when the child is
  killed BY a signal it did not handle -- so our SIGTERM-first teardown
  produced a positive 255 and fell through to WARNING every time.

  Everything that made it look like a crash follows from that: exit code
  exactly 255; no stderr at all, because ffmpeg's "Exiting normally, received
  signal 15." is INFO and the serve runs at `-loglevel warning`; and a ~3
  minute cadence, which is the idle-release window. An offline reproduction of
  the camera's real timestamp misbehaviour ran past four minutes without dying,
  because nothing was signalling it.

  255 with a teardown in flight is now the expected end of a stop. 255 with no
  teardown in flight still warns -- something outside us signalled the process,
  which is the distinction the function exists to make.

- **A camera that answers one codec and sends another no longer kills the
  serve at startup.** When video had not been observed before the serve
  launched, the SDP was narrowed to the payload type from the camera's
  *answer*. The reference A001064 answers 97 (H.265) and sends 96 (H.264) in
  every observed session, so this built an hevc-only SDP that no hevc ever
  filled: ffmpeg could not determine dimensions, could not write the RTSP
  header, and exited immediately. The pin (`AIDOT_SDES_VIDEO_PT`) was ON and
  was being ignored by that fallback. Precedence is now what was **observed**,
  then what was **pinned**, then what the camera **claimed** -- the answer is
  the weakest of the three because this model demonstrably does not honour its
  own. The failure was invisible until the exit reason stopped being flushed
  out of the stderr tail.

- **A serve that dies no longer hides why.** The exit logger kept the last 40
  stderr lines, and on a lossy camera all 40 are `Non-monotonic DTS`. Both
  camera families step their RTP timestamp backward every exactly 30.0 s
  (measured: A001064 by 0.05-0.35 s, A001513 by ~2.195 s) and `-c copy` emits
  one such line per frame until the input catches up, so the sentence that
  explains the exit was always flushed out. Three investigations of a camera
  that dies every ~3 minutes never saw it. A second, separate tail now keeps
  the last non-repetitive lines and is logged first.

### Changed

- The NACK switch is resolved once per session instead of per packet
  (`os.environ.get` was ~25% of the added per-packet cost at ~300 packets/s
  per camera), and the tracker skips its prune/report scan entirely when
  nothing is outstanding -- that scan is O(outstanding) and peaked exactly
  when the receive loop was already behind. A flip of `AIDOT_SDES_NACK` now
  takes effect on the next stream open rather than mid-stream.
- The RTCP sender SSRC is one named constant rather than four literals. It is
  load-bearing: the SRTP TX policy is keyed on it, so PLI, REMB, RR and NACK
  must agree or the camera drops the packet.
- The serve-exit log reports how many NACKs the session sent, and for how many
  packets -- counters that were previously accumulated and never read.
- The media-watchdog restart says when idle-release is off for that camera, and
  therefore that it will repeat indefinitely. Measured on the reference A001064
  with a zero idle window: a fresh session every ~2 minutes, round the clock,
  with no viewer. That is the configured behaviour, not a fault, but eleven
  restarts an hour reads as one.


## [1.0.0b23]

### Added

- **RTCP Generic NACK on the SDES bridge** -- the camera is now asked to resend
  video RTP packets that never arrived. On by default; set `AIDOT_SDES_NACK=0`
  to turn it off.

  Measured on an A001064: ~0.7% of its video packets are lost on the air, 37 of
  56 losses landing INSIDE a frame (identical RTP timestamp either side of the
  sequence gap). Nothing recovered them -- the bridge sent PLI, REMB and RR but
  never a NACK -- so ffmpeg reassembled a truncated H.264 slice and forwarded
  it. Its keyframes are ~155 packets each, which makes roughly two thirds of
  them arrive damaged. A browser's WebRTC decoder conceals that; Media Source
  Extensions treats a damaged keyframe as fatal and stops the pipeline with
  `PIPELINE_ERROR_DECODE`, which is the whole reason that camera played over
  WebRTC and not over MSE.

  The camera negotiates `nack` for both media in its own answer, so nothing new
  has to be offered. Unlike the REMB bitrate cap this defaults ON, because a
  NACK cannot degrade a camera that ignores it -- unsupported feedback is
  dropped, and a camera on a clean link generates no requests at all (a second
  camera on the same bridge measured 0.05% loss with zero mid-frame losses and
  sends none).

  Requests are capped: at most 17 sequence numbers per report, at most 3
  attempts each 150 ms apart, and abandoned once a packet is 200 behind the
  newest -- a retransmission that arrives after the decoder has moved on spends
  bandwidth on a link that is already congested and fixes nothing. A sequence
  jump larger than 250 is treated as a republished stream, not a loss, so a
  restart does not trigger a NACK storm.

  Measured on the reference install, same camera, before and after:

  | | NACK off | NACK on |
  |---|---|---|
  | losses recovered by a retransmission | 0 of 357 (and 0 of 204 in a later paired control) | 1077 of 1094 (98.4%) |

  Packet recovery is the measurement to trust here: it is direct, it was taken
  in both arms of a paired control on the same camera, and it does not depend
  on judging a player. Browser playback also improved -- runs that failed every
  attempt before the change played through afterwards -- but that camera's link
  and its publisher are unstable enough hour to hour that no honest pass-rate
  figure can be quoted for it.

  The camera retransmits on the original SSRC and payload type -- no RTX
  stream is negotiated on this path -- so ffmpeg's reorder queue absorbs the
  repeat with no change to the SDP. Recovery took 45 ms at the median and
  162 ms at p90.

  The 150 ms retry interval is measured, not chosen. Retrying every 100 ms
  with four attempts was tried on the same camera at comparable loss and made
  things markedly WORSE -- 73.6% of losses recovered against 99.2% -- because
  an interval under the p90 re-asks for packets whose repeat is still in
  flight, and the duplicate costs an uplink that is already saturated.

  It is not a complete cure on a link this poor: the recovery delay has a tail
  past ffmpeg's 500 ms `-max_delay`, and a retransmission that arrives after
  that is discarded with the frame already emitted.

## [1.0.0b22]

### Added

- **`sprop_is_unstable(device_id)`** -- public, for consumers that register a
  camera with a stream server.

  A server such as go2rtc builds its decoder configuration (the fMP4 `avcC`
  box) when a track is first published and reuses it for the life of the stream
  definition. A camera that changes its H.264 SPS between sessions is therefore
  published against parameter sets captured in an EARLIER session, and a player
  using Media Source Extensions -- which configures its decoder from that box
  once -- then fails to decode every inter-frame and updates the picture only on
  keyframes. Measured on an A001064, which changes its SPS because the declared
  frame rate is part of it and the camera lowers frame rate in night mode:

      avcC   SPS: 674d001fe900a00b742000007d20000daf8080   (earlier session)
      stream SPS: 674d001fe900a00b742000007d200004e34080   (this session)

  On a freshly created stream definition for the same camera the two match, and
  playback is correct.

  The library already tracked which cameras do this, to decide whether
  injecting cached `sprop-parameter-sets` is safe; this exposes that same
  knowledge so a consumer can drop and recreate the stream definition before
  publishing. It must be done before the publisher connects: removing a
  definition a publisher is attached to leaves it with nowhere to publish.

## [1.0.0b21]

### Fixed

- **Audio now reaches browsers on SDES cameras.** A camera published over the
  RTSP push carries G.711 (`PCMA/8000`), and the push passed it through
  untouched. G.711 is fine for WebRTC, which carries it natively -- but fMP4 /
  Media Source Extensions has no mapping for it, so any browser on the MSE path
  negotiated video only and played a silent stream. Measured on a live fleet:
  the producer advertised `audio, recvonly, PCMA/8000`, go2rtc created a
  `pcm_alaw` sender, and the MSE handshake came back `avc1.*` with no audio
  codec at all.

  The push now encodes AAC, so one publish serves both consumers. Video is
  untouched (`-c:v copy`) and is never gated on audio.

  Two behaviours are deliberately preserved:

  - A camera whose audio payload type was never observed still publishes video
    only. Announcing an audio line the RTSP server cannot accept fails the whole
    publish with `400 Bad Request`, and a silent picture beats no picture.
  - With serve audio disabled, the publish is byte-for-byte the previous
    `-c copy` passthrough.

  Battery cameras send audio sparsely, and an AAC encoder with no input samples
  emits no frames. The push therefore reuses the silence base the HTTP-listen
  serve already used for this: a continuous `anullsrc` under
  `amix(normalize=0)`, which feeds the encoder from the first moment and is a
  no-op wherever real audio is present.

## [1.0.0b20]

### Fixed

- **Home Assistant no longer restarts a stream every minute or so.** HA logged
  "Timestamp discontinuity detected: last dts = N, dts = -M" and tore the stream
  down, roughly 0.91 times a minute per camera. Root-caused by capturing both
  sides of the serve boundary:

  | | video PES | with no PTS/DTS |
  |---|---:|---:|
  | this library's mux | 64,981 | **0** |
  | the `-c copy` serve ffmpeg | 12,729 | **8** |

  The timestamps are correct when the mux hands the MPEG-TS to ffmpeg and
  missing when ffmpeg emits it. go2rtc renders a timestampless PES as RTP
  timestamp 0, and HA's rtpdec then computes `pts = 0 - base_timestamp` - the
  constant negative DTS. Verified to the tick: the base timestamp read
  independently off the capture was 756,180, and the logged backward steps were
  exactly `dts = -756180`.

  The hop earned nothing - it re-packetized MPEG-TS this library already writes
  in the form go2rtc wants - so it is gone. The mux now serves the consumer
  directly.

  Measured on four cameras for about 20 minutes each, roughly 64,500 packets:
  **0 negative timestamps and 0 discontinuity errors**, with audio unchanged at
  AAC/48 kHz and frame rate nominal. Set `AIDOT_DTLS_DIRECT_SERVE=0` to restore
  the ffmpeg hop; the library also falls back to it automatically if the serve
  port cannot be bound.

  Not fixed by rewriting timestamps, and deliberately so: `-fflags +genpts` made
  it about ten times worse and `-avoid_negative_ts make_zero` about nine times
  worse plus an unstable stream. The bytes were always right; the hop dropped
  them.


## [1.0.0b18]

### Fixed

- **Re-sent frames are no longer served a second time.** The camera re-sends
  runs of frames it has already sent - 489 of a captured 1200, 40.75%, matching
  the 41.1% and 45.7% measured live on two cameras. Those repeats reached the
  muxer, where the monotonic-DTS clamp gave each one `prev + 1`, so up to 41
  already-served frames landed in the container a single tick apart. A viewer
  got that as a burst, about twice a second.

  The camera is not at fault and neither is the unwrap correction: measured at
  the raw tap across three cameras, its timestamps are strictly increasing,
  spaced for 15 fps, with no duplicates and no backward steps, and each mux
  queue has exactly one source. The repeats only become visible after
  `_correct_ts` undoes aiortc's bogus 2**32 unwraps and recovers the camera's
  real timeline - which genuinely returns to an earlier point.

  Frames whose presentation time has already been served are now dropped rather
  than muxed a tick apart. This does not change the media rate (1.104x over the
  fixture either way, since a repeat carries no new presentation time); it
  removes the burst, and about 41% of the frames muxed and served.

- **A served DTLS camera no longer abandons an open at the instant it last asks
  again.** The per-attempt open timeout was 30 s, and the offer-resend that
  exists for exactly this case (`webrtcReq` re-published when the camera has
  not answered) fires at 15 s and again at 30 s - so the second resend went out
  as the attempt died, and any answer to it landed with nobody waiting.

  Measured on a live seven-camera fleet over 0.93 h, 122 serve-loop opens: 40
  answered inside 30 s, 65 never answered at all, and **14 answered LATE, from
  30.7 s to 99.5 s, every one of them `code=200`** - the camera had accepted the
  offer and stood a session up; only the timeout had expired. The default is now
  75 s (`AIDOT_DTLS_SERVE_OPEN_TIMEOUT_S`), which covers 11 of those 14.

  Scope worth knowing: on a healthy fleet this changes nothing. 56 opens against
  idle cameras answered with a median of 0.42 s and a maximum of 1.48 s - not
  one came within 20 s of even the old timeout. The late answers appear only
  when the fleet is already degraded, where the median is 11.73 s. So this is a
  mitigation for the bad state, not a general speed-up, and it does not by
  itself explain or fix that state.

- **The ICE wait no longer inherits the open timeout.** An open is two
  SEQUENTIAL waits - signalling, then ICE - and both read the same value, so
  raising the open timeout also doubled the worst case, all of it holding the
  global open gate (`AIDOT_MAX_CONCURRENT_OPENS`, default 2). Nothing measured
  asked for a longer ICE wait, and a long one is actively wrong: it runs past
  the roughly 30 s deadline Home Assistant's stream worker allows. ICE now takes
  its own budget (`AIDOT_DTLS_SERVE_ICE_WAIT_S`, default 30), clamped to the
  open timeout so lowering that still fails faster. Callers that pass nothing
  are unchanged.

## [1.0.0b17]

### Fixed

- **A served stream no longer runs ahead of wall clock.** A viewer received
  about 1.8 seconds of media per second, so their buffer grew for as long as
  they watched and the picture slid steadily into the past - the live view
  showing footage from minutes earlier, stalling and jumping to catch up.
  Measured end to end on two A000088 units: **1.821x before, 1.008x and 0.998x
  after**.

  Two defects, and neither is the camera. Its clock is honest - 1.004x and
  1.000x of the declared 90000 measured on the wire, 15.1 fps stamped 6030
  ticks apart.

  First, aiortc reads ANY backward timestamp step as the 32-bit RTP counter
  wrapping, and unwraps it by adding 2**32. A camera whose pictures arrive out
  of presentation order therefore produces a phantom jump of about 47,721
  seconds, and the error accumulates for the life of the session: 1200 frames
  measured on the live tap carried 22 such artifacts and spanned 22 x 2**32
  more ticks than the content they described. A running offset undoes them.

  Second, those artifacts had been masking real backward steps. The camera's
  RTP timestamp carries PRESENTATION time and its pictures do not arrive in
  presentation order - excursions reach 138060 ticks. The serve mux wrote
  `pkt.pts = pkt.dts`, so a backward step became a backward DTS, which an
  mpegts muxer rejects outright. DTS is now emitted in decode order, strictly
  increasing, with presentation trailing it by `AIDOT_REORDER_SLACK_TICKS`
  (180000, two seconds).

  The two halves must ship together: correcting the unwrap alone exposes the
  backward steps and the mux stops producing anything at all.

- **The video-presence watchdog no longer tears down a session that is
  streaming.** It read a canary reference captured when the tap was installed;
  when the session delivered on a different receiver that dict stayed at zero
  frames while another filled, and a healthy camera was re-opened every 35
  seconds. The check now resolves whichever video canary is actually being fed.

## [1.0.0b16]

### Fixed

- **A DTLS session that receives no video is no longer treated as healthy.**
  The serve loop's only liveness test was the peer-connection state, which a
  session carrying audio and no video passes indefinitely. Measured 2026-08-17
  on an A000088: 62823 audio packets, zero video, held for hours while Home
  Assistant logged "Stream has no video" on a 10/20/30/40 s retry ladder that
  never ended and nothing re-opened the camera. A connected session that has
  not produced a single video frame within `AIDOT_DTLS_VIDEO_GRACE_S` (30 s,
  `0` disables) is now torn down and re-opened.

  Noticing is only half of it. A video-less session is otherwise a *clean*
  open, so a loop that simply re-opened would clear its own backoff each time
  and wake the camera every 15 s for as long as the camera kept answering that
  way - which the camera measured here does on every open. Consecutive
  video-less sessions are counted, the backoff escalates as it would for a
  failed open, and after `AIDOT_DTLS_FUTILE_VIDEO_LIMIT` (5, `0` to keep
  retrying) the loop stops re-opening and says so. This mirrors the futile
  keepalive abandon the SDES path has carried since 0.17.1.

  **Scope, stated because the name invites the wider reading:** this catches a
  session that never delivered video, not one that delivered video and then
  went dark. The check is one-shot - once any frame has arrived the session is
  healthy as far as it is concerned - because mid-session loss is a different
  failure with a different remedy, and a check that claimed both would have to
  guess which it was looking at.

- The `serve h264 canary` log line names its camera. It counts frames at the
  tap, upstream of every queue, pipe and muxer, which makes it the measurement
  an investigation reaches for - and on a multi-camera host it could not say
  which camera it described.

## [1.0.0b15]

### Changed

- Documentation only. The README drops `AIDOT_PLAYBACK_TLS_VERIFY`, which is
  read solely by the deprecated cloud-playback path the cloud does not serve -
  documenting a security knob for code that cannot run invites someone to set
  it and believe they hardened something. It remains described in
  `DEFERRED_FEATURES.md`. `AIDOT_LIVESTREAM_PARAM` stays documented as an
  explicit no-op, because that tombstone is what stops the same mistake.

- Control coverage is now recorded per property per model in
  `docs/1.0.0-READINESS.md`: 11 of 11 confirmed by read-back on the A001064 and
  A001513, alongside the A000088 that was already complete.


## [1.0.0b14]

### Fixed

- Documentation only: **PTZ works.** Two earlier entries described it as inert
  on the reference A001064. Both were instrument failures - the camera-proxy
  still is cached (byte-identical across presses) and short repeated go2rtc
  pulls return near-identical keyframes. Measured properly, from within one
  session recording and against a no-command control: mean frame difference
  25.2 at speed 4 and 38.6 at speed 200 across a 5 s pan, versus 2.62 for the
  control. The camera advertises `ptzDirection [6,3]`, pan only, and the
  integration's button gate already honours that.


### Fixed

- `async_get_camera_attributes` returns attributes on **every** model. A
  battery camera answers the presence announce and its push is returned as-is;
  mains cameras answer with nothing at all, and rather than report failure for
  a reason that has nothing to do with the caller, it now falls back to the
  device's own `properties` - the same source that populates every entity in
  the reference integration. Measured: an A000088 goes from 0 attributes to 99
  and an A001064 from 0 to 87, while the A001513 keeps returning its live push.
  The two sources differ in shape - a push carries only what changed - so the
  docstring says to treat the result as what the camera reports rather than a
  fixed schema.

- The same method now uses the status-bearing MQTT call rather than the wrapper
  that drops it, and warns when there is no session. "The broker refused our
  connect" and "the camera stayed quiet" previously arrived as the same empty
  list, which is the ambiguity that let a rejected client id survive three
  investigations.


## [1.0.0b13]

### Fixed

- **`async_get_camera_attributes` works now.** It appended `-cmd` to the
  registered `mqttClientId`, and the broker binds the credential to that exact
  string: the connect was refused outright with CONNACK rc=4, so there was no
  session, no subscription and nothing to receive. It never worked, on any
  camera, since it was written.

  It now uses the exact id and prefers the shared persistent connection
  unconditionally - the same identity, with no second connect, which avoids
  both the refusal and evicting whoever holds the id. The one-off fallback
  declines outright while a stream is active rather than displacing it.

  Verified on hardware: an A001513 battery camera returns its pushed
  attributes where it previously returned `None`. Mains cameras answer the
  presence announce with nothing at all - which matches what the call is for,
  since the wake-then-read sequence exists to make a sleeping battery camera
  report battery, SD-card and occupancy. The deprecation added earlier today is
  withdrawn; a method that works should not carry a warning saying it cannot.

  Three earlier investigations blamed the camera for this, because the helper
  in use returns messages and drops the transport status behind a warning that
  every probe had suppressed.

- `async_open_cloud_playback` is resolved and is not fixable here: the cloud
  does not serve `getPlaybackServerInfoReq` on this account. Proven by pairing
  it in one session with a request that *is* answered - the battery wake
  handshake - on the same connection, subscription and client id: the wake
  replied with seven messages, the playback request with none in 40 s. Eleven
  messages arrived on that subscription in total, so the transport was never
  the problem. Also ruled out by measurement: contention for the client id, and
  all four `srcAddr` forms including the terminalIndex session form.

  The positive control is the lesson: "nothing came back" is not a result until
  something else on the same channel comes back.


### Fixed

- **A cancelled open orphaned its MQTT session thread for an hour.** The
  non-persistent signalling transport runs a 3600 s session in an executor and
  is stopped only by the `outgoing_q` sentinel. Nothing pushes that sentinel on
  cancellation, and nothing held a reference to the worker either - so it could
  not be reaped later. The persistent branch has registered with
  `_reap_stream_drain` for exactly this reason since it was written; the other
  branch never did.

  Executor workers are finite. Enough orphans and every `run_in_executor` in
  the process blocks, which a caller experiences as an open that never returns -
  the same symptom as the uncancellable drain fixed in 1.0.0b12, and plausibly
  the mechanism behind it. Found by asking whether that fix had siblings.


## [1.0.0b12]

### Fixed

- **An open could hang with no success, no error, and no response to
  cancellation.** The stream-signalling drain waited on `queue.get()` with no
  timeout inside `run_in_executor`. Cancelling the await cancels only the wait,
  never the worker thread, so the thread stayed blocked for the life of the
  process - and an `asyncio.wait_for` around the enclosing open then blocked
  forever, waiting on a cancellation that could never complete.

  Measured on an A001064: a second consecutive open returned nothing and did not
  respond to a 130 s hard cap wrapped around it. To a user that is a camera that
  never loads and never says why; to a caller it is worse than a failure,
  because the usual defence - wrap it in a timeout - does not work either.

  The wait is now bounded, so the task is cancellable. The stop sentinel still
  returns immediately, so the normal teardown path is unchanged. The regression
  test does not merely fail without the fix - it hangs, which is the point.


### Fixed

- The `async_get_camera_attributes` deprecation said the camera never pushes the
  notification it waits for. That was wrong, and the experiment that settles it
  has now been run: subscribing to those exact topics while a WebRTC open
  proceeded in the same window received **zero** messages, while the stream
  itself opened - so signalling demonstrably traversed the same topic prefix.
  The fault is in this subscribe path, not the camera. `_mqtt_session` is the
  suspect, `async_open_cloud_playback` fails at its own `_mqtt_session` step,
  and one client-side bug may explain both. The leading untested hypothesis is
  the `-cmd` suffix this path appends to the registered `mqttClientId` where
  the working streaming path uses it unmodified. The probe it rested on logged zero inbound messages, but its own
  control - a self-publish meant to prove the session receives anything - also
  came back empty, on a topic the broker would likely refuse, so it measured
  nothing in either direction. The symptom is unchanged and reproducible: the
  call returns None on two model families from two hosts. The streaming path
  uses the same smarthome MQTT credentials and works, so credentials are not
  the difference.


## [1.0.0b11]

### Deprecated

- `async_get_camera_attributes` is deprecated and **does not work**. It waits
  for a `setDevAttrNotif` the camera never pushes: measured 2026-08-14 as None
  for an online A000088 and an online A001064, from two different hosts. The
  obvious confound - a broker evicting us for reusing the account's
  `mqttClientId` while Home Assistant holds it - was excluded by repeating the
  call with a unique client id, which changed nothing. Nothing calls it; camera
  state comes from `async_get_all_device()`'s per-device `properties`, which is
  what populates every entity in the reference integration. Removal in 1.0.0.

### Changed

- `async_set_ir_light` documents that it **does not take on the A000088**.
  Confirmed by read-back over the local control channel on both A000088 units:
  the write is acked and the attribute keeps its previous value. The call is
  kept because the attribute is real and another model may honour it, but a
  `True` return is not evidence the camera changed anything. The reference
  integration no longer offers an IR-light switch for the same reason.


## [1.0.0b10]

### Added

- DTLS cameras can RTSP-push. `rtsp://` is now a destination for the A000088
  serve loop, the same shape SDES has always had. It was never a protocol
  limitation - by the time media reaches that point the mux has already
  produced h264 + AAC whichever transport decrypted it, and the only thing
  missing was the destination. TCP interleave, because a UDP publish fragments
  a 720p keyframe and the first loss takes the GOP with it.
  Audio is transcoded to G.711 A-law rather than copied, and that is not a
  preference: the mux writes AAC into MPEG-TS as ADTS, and ffmpeg's RTSP muxer
  refuses AAC with no global headers at header-write - the publish never
  starts and video dies with it. Reproduced deterministically off a synthetic
  stream with the exact argv, which is also how the first cut of this feature
  was caught before it shipped. `-bsf:a aac_adtstoasc` does not help; the
  header is written before the filter produces extradata. G.711 is RTP-native,
  costs almost nothing at 8 kHz mono, and is what the SDES push has always
  carried, so both push paths now put the same thing on the wire.
  Confirmed end to end on an A000088: published into a live go2rtc, pulled back
  out as `h264 1280x720` plus `pcm_alaw` audio.

  Prefer `-` (stdout) for a go2rtc `exec:` source on a DTLS camera even so. The
  push has to transcode audio down to 8 kHz G.711, where the stdout producer
  carries the mux's 48 kHz AAC untouched. Use the push when something other
  than go2rtc owns the RTSP server.

### Deprecated

- `async_open_cloud_playback` is deprecated and **does not work**. Measured
  2026-08-14 against an A001064 with ten cloud clips available: step 1, the
  MQTT `getPlaybackServerInfoReq`, returns an empty response, so the call
  returns None before a session exists. Nothing in this library, its tests, its
  CI or the reference integration calls it, which is how it stayed broken while
  the README named it as *the* retrieval path for cloud recordings. Use
  `async_get_cloud_recordings` to list and `async_get_event_video_media` for a
  playable HLS URL - which is what the integration has been doing all along.
  Removal in 1.0.0.

### Fixed

- The README and `ROAD-TO-1.0.md` named `async_open_cloud_playback` as the way
  to retrieve cloud recordings. Both now name the pair that works.
- `async_open_live_stream` says what it is: the TUTK P2P path, unusable on
  every camera seen so far because no device returns a `p2pId` and the TUTK
  native libraries are not redistributable here. Live video goes through
  `async_open_webrtc_stream` on every supported model.


## [1.0.0b9]

### Fixed

- The DTLS stdout producer - `aidot-go2rtc <id> -`, the documented way to run
  an A000088 as a go2rtc `exec:` source - never actually ran. The keepalive
  router only sent `http` URLs to the serve loop, so `-` fell through to the
  JPEG keepalive loop: a healthy WebRTC session, a live data channel, and zero
  bytes on stdout, with no error anywhere. Measured on hardware: 0 bytes before,
  1.4 MB of MPEG-TS after. The unit tests passed throughout because they called
  the spawn helper directly and never asked who calls it; there is now a test
  for the routing itself. Stdout mode also no longer idle-releases - go2rtc owns
  the process lifetime there, and with no serve port to ask about viewers the
  fallback could put a live producer to sleep underneath it.

- `on_frame` is annotated `av.VideoFrame` instead of the library's own
  `VideoFrame` dataclass. The callback always received PyAV's frame; the wrong
  annotation made a type checker bless `frame.data` / `frame.timestamp`, which
  read empty at runtime and look exactly like a dead stream, and reject
  `frame.to_ndarray()`, which is what works.

### Added

- Local-only control for four camera settings that were readable over LAN but
  had no control: the timestamp overlay (`OSDEnable`), HDR (`HDRStatus`),
  floodlight automation (`autoLightEnable`) and voice prompts (`voiceEnable`).
  Every one was toggled on live hardware and read back, because on this firmware
  an ack does not mean the write took: of fourteen attributes probed, eight
  acked and kept their own value. `SdcardRecord_Enable` was in an earlier draft
  and was removed for exactly that reason.
- `aidot-go2rtc --list` now prints a paste-ready go2rtc `streams:` block under
  the device table, each camera already paired with the output argument its
  transport needs (`{output}` for SDES, `-` for DTLS) and named from the
  camera's own name. That pairing was the one thing users had to get right by
  reading prose, and getting it wrong produces a stream that never starts. The
  existing device table is byte-for-byte unchanged, but the block is appended
  unconditionally - a script parsing `--list` output to its end will now see it.
- A README section on getting an RTSP URL. The library does not run an RTSP
  server and the cameras have no RTSP or ONVIF endpoint, so the route users
  actually want - go2rtc as the parent process, publishing
  `rtsp://host:8554/<name>` - was documented only inside a CLI docstring.

### Deprecated

- `async_open_kvs_stream`, the pre-rename alias, now emits a
  `DeprecationWarning` and is scheduled for removal in 1.0.0. It was never in
  docs/API-STABILITY.md and nothing in this project, its tests or the reference
  integration calls it - but it has been importable, so it gets a release of
  warning rather than vanishing.

### Changed

- `async_open_webrtc_stream` has a real signature instead of `*args, **kwargs`.
  On a py.typed package the untyped wrapper made `help()`, IDE completion and
  downstream type checkers see a function accepting anything. The return type is
  now `WebRTCSession | SdesSession`, which is what it always returned; a
  downstream mypy run that assumed `WebRTCSession` may newly need a narrowing
  check. Underscore-prefixed internals stay reachable but unadvertised.
- The package root now exports `CameraStatusData`, `CameraDeviceInformation`,
  `WebRTCSession` and `SdesSession`, which docs/API-STABILITY.md already
  promised. `aidot_cameras.client.__all__` no longer exports three private
  underscore names that the same document declares are not public; they remain
  importable by name.
- docs/API-STABILITY.md now declares `camera.lan_control`, `camera.go2rtc` and
  `device_session_authenticated`, which the reference integration imports and
  which were therefore already commitments in practice.
- The vendored aiortc now ships upstream's BSD licence beside it, and
  `_vendor/aiortc/VENDOR.md` records the exact delta from 1.14.0 (three import
  rewrites, nothing behavioural) and how to re-vendor. `pyproject.toml`
  previously described it as byte-identical, which it was not.
- `aidot-go2rtc --help` now prints the full environment-variable reference the
  README says it does.
- README: a runnable quickstart, the `aidot` vs `aidot_cameras` import trap
  named, ffmpeg's PATH requirement stated, and links made absolute so they work
  as the PyPI long description.

## [1.0.0b8]

Pre-release.

### Fixed

- Answer sections are matched to the offer by content when the camera shifts its
  mids. This firmware sometimes answers with an extra `m=video` carrying
  `a=rtpmap:0 H265/90000`, pushing every later mid along by one; matching purely
  by `a=mid` then handed the video slot the H265 section, which aiortc cannot
  use. On a two-section offer that was a hard `setRemoteDescription` failure; on
  a three-section one every mid mismatched on kind and the open read as a camera
  declining media. Both intermittent, both previously hidden behind the retry.
- A shifted answer now gets a 15s ICE deadline instead of 45s, and raises
  `AidotCameraNotReady` so the caller's fast retry runs. Measured over 63 opens:
  every successful open completed ICE in 8.7-10.6s and every failure ran the
  full 45s. 45s is past the ~30s Home Assistant's stream worker allows.

### Added

- The wire format for playing a recording off a camera's SD card
  (`RECORD_PLAYCONTROL`). The request and reply decode are implemented; playback
  itself is not offered, because the camera acknowledges the command and then
  sends no media. See `docs/CAMERAS.md`.

## [1.0.0b7]

Pre-release.

### Added

- **`CameraStatusData.sd_card_present`** - whether there is an SD card in the
  slot, as a tri-state: `True`, `False`, or `None` for "nobody reported".

  A camera with an empty slot and a camera that could not be asked look
  identical to every listing call: both return nothing. The cloud has been
  carrying the answer all along in `SDcardExistFlag` / `SDcardBaseInfo` and
  nothing read it, so a caller could only report "the camera did not answer"
  for a camera whose only problem was an empty slot.

  **The third state is the point.** Across seven cameras measured 2026-08-12,
  one reported `SDcardExistFlag: true`, two reported `false`, and four carried
  neither key - including a model whose siblings report normally. A missing key
  therefore cannot mean "this model cannot say"; it means unknown. Collapsing
  that into `False` would tell someone with a working camera that their slot is
  empty, which is the same invented answer that `answered` exists to prevent one
  level down.

  Parsing is defensive because the wire is not consistent: `SDcardExistFlag`
  wins where present, `SDcardBaseInfo` is the fallback and arrives as a string
  holding a JSON array (a real list is accepted too), and a value that cannot be
  decoded yields `None`, never `False`. A partial attribute update leaves a
  known reading alone.

  `SDcardBaseInfo[1..4]` are deliberately not decoded, and `sd_card_status` is
  unchanged and kept separate - it reads inverted against this on one model with
  no corroboration on any other, so the two are not reconciled on a guess.

## [1.0.0b6]

Pre-release.

### Added

- **`has_live_session`** - is a stream session up right now, answered without
  sending anything.

  `start_keepalive` returns before the handshake it schedules has produced
  anything, so a caller that wants to ride the session it just asked for had no
  way to know when that session arrived. Probing with a real request is not a
  substitute: once the session is up, the probe IS the request, and a caller
  that meant to send one request has sent two.

  Best-effort in one direction: a torn-down session reads as live on a transport
  that does not publish `is_alive`, so a listing taken on the strength of it can
  still fail and callers must handle that. It is a cheap early-out, never the
  thing that keeps a dead channel from being reported as an empty card -
  `answered` does that, on every transport.

  The underlying check is not new; `async_get_sd_recordings` already made it.
  The two now share it, so a caller waiting for a session and the listing
  deciding it has one cannot come to different answers.

## [1.0.0b5]

Pre-release.

### Added

- **`async_get_sd_recordings(*, session=None, days=7, channel=0)`** - what a
  camera holds on its own SD card, read over an existing session. Stateless:
  it asks the session it is handed and never opens one, because listing costs
  a WebRTC handshake (15-21 s DTLS, 25-70 s SDES cold) and wakes the camera,
  where the cloud equivalent is one ~200 ms request. Deciding when that is
  worth spending belongs to the caller.

  It reports three distinct outcomes rather than two, and the distinction is
  the point: `None` means there was no session to ask through, `answered=False`
  means the requests went out and the camera said nothing, and `answered=True`
  with an empty `records` means the camera replied and the card holds nothing
  in that window. A caller that collapses any two of these shows the same empty
  list for opposite reasons. `complete` is False when the reply's end flag
  never arrived or a reply could not be decoded - in both cases there may be
  more than is shown.

- **The recording-list request builders now ship in the package** -
  `stimeday`, `haslistevent_payload` and `listevent_payload` in
  `aidot_cameras.camera.sd_events`, alongside the decoder that was already
  there. They previously existed only in `scripts/`, which the package cannot
  import, so nothing in the library could ask a camera this question at all.

  The default event selector is `0` (`SD_EVENT_ANY`), not the vendor app's
  `0x12` (`SD_EVENT_APP`). Measured 2026-08-11 on an A000088 with a card: the
  same session and window answered an empty page for `0x12` and four real
  records for `0`.

### Fixed

- **An occupancy map asked for as records no longer returns invented
  recordings.** `HASLISTEVENT` answers with a per-hour occupancy map, one byte
  per hour, while `LISTEVENT` answers with 12-byte records - and a real
  168-byte map is exactly fourteen 12-byte records, so the record decode
  succeeded on it and produced fourteen recordings dated `0000-00-00`.
  `decode_list_event_response(payload, command=HASLISTEVENT_RESP_CMD)` now
  returns `None`, and the new `decode_hour_map` reads the map as what it is.
  Callers that pass no `command` are unaffected.

## [1.0.0b4]

Pre-release.

### Added

- **`async_count_cloud_recordings(start_ts, end_ts)`** - a window's event count
  in one request. The listing endpoint reports the window's true `total`
  alongside whatever page it serves, and that total is correct even on a
  one-item page. Counting by paging instead costs one request per ten events:
  a day holding 1517 events is 152 requests, and a seven-day view that counts
  by paging fires hundreds every time it is opened. Returns `None` when the
  call fails, which a caller must not read as zero.

- **`async_get_cloud_plan()`** - the camera's cloud recording subscription
  (`packageName`, `subscribeStatus`, `startTime`/`endTime` in epoch
  milliseconds, `videoLength`). It answers the question an empty event list
  cannot: whether there are no events, or no longer a plan under which events
  would be kept. Returns `None` on any failure rather than an empty dict,
  because callers test it for truthiness.

- **`scripts/browse_check.py`** - checks all of the above against real cameras
  and states a per-camera verdict, so a failed call cannot be read as a passing
  one.

### Documented

- **The cloud caps a listing page at 10 items whatever `page_size` asks for.**
  Measured across seven cameras: three holding 53, 48 and 36 events in a day
  each returned exactly 10 for a 30-item request, and paging in tens recovered
  every one. The vendor's own client hard-overwrites the field to 10 (5 for a
  multi-device request), so it is the server's rule rather than a quirk of one
  account. A caller that asks for 30 gets 10 with no indication it was
  truncated. Page; do not raise `page_size`.

- **An empty cloud event listing is a question about the account before it is
  anything else.** Both listing methods had reported zero events for every
  camera on every fleet run. On the owner account, on the same fleet, ninety
  minutes after a run that reported zero: the count method returns the full
  count it asks for on six of seven cameras, and the range query returns a full
  first page against server totals of 121-1517 over thirty days. The runs use a
  shared-home member, and report no cloud thumbnail either.

- **Cloud playback is HLS in practice.** `async_get_event_video_media`
  documents a preference for MP4 over M3U8; three cameras across three model
  families each returned exactly one entry, type 2. Anything built on it should
  be designed for HLS.

## [1.0.0b3]

Pre-release.

### Fixed

- **A camera behind the same NAT as the host could never start streaming.** ICE
  identifies a candidate by its transport address; this package's self-check
  compared the address alone. A camera in the same house reaches the cloud TURN
  server from the same public IP the host does, on a different port, so that
  check answered "that is us" about the camera.

  The consequence was worse than a missing candidate. The branch that answers a
  relay-carried STUN Binding Request - by wrapping the response in a TURN Send
  Indication back to the camera - is guarded by the same check, so the camera's
  connectivity check was never answered at all. With no response the check never
  completes, the AVIO LIVING trigger that gates media is never armed, and the
  camera sends nothing. Sessions sat for 75 seconds and delivered no video.

  The check now compares `ip:port` against the ports our own server-reflexive
  candidates advertise, which are the only ports on that address belonging to
  this host. It is exactly as strong for what it was written for - nominating our
  own address would have the host answer its own connectivity check - and it no
  longer catches the camera. A caller that cannot supply a port keeps the old,
  conservative answer.

  Confirmed on hardware rather than by absence of failure: the fleet runs after
  this change learn peer-reflexive candidates on the host's own public IP at
  ports that are not the host's - the exact address class the old check refused -
  where every earlier run learned none of them. The failure mode this addresses
  accounted for five of the seven recorded stalls and has not recurred since.

  One rarer stall shape remains and is untouched by this: a session where no
  connectivity check arrives at all, so there is nothing to learn or nominate.
  That is a signaling question rather than an ICE one and is tracked in
  `docs/ROAD-TO-1.0.md`.

### Changed

- The SDES live-view session is opened talk-capable, so two-way audio reuses it
  instead of opening a second camera session alongside it. A camera holds a
  viewer slot for about 120 seconds after a session ends, so the second session
  was not free. The offer change - audio `sendrecv` plus an `a=ssrc` - has run on
  every camera of the reference fleet across several validation runs with no
  streaming regression.

## [1.0.0b2]

Pre-release. `1.0.0b1` was tagged but never published to PyPI; this supersedes
it and is the first 1.0.0 pre-release to ship.

### Fixed

- **Two-way audio reported success for a speaker that never opened.** On the
  SDES path `async_start_talk` returned True whenever the acknowledgement wait
  expired, because the shared ack reader treats an absent or unfamiliar ack as
  acceptance. That generosity exists to interpret the camera's ANSWER - no
  genuine refusal has ever been identified, and guessing at one would break
  working cameras - and it has nothing to say about the command never being sent
  at all. The speaker flag is set on exactly one line, immediately after the
  bridge thread dispatches SPEAKERSTART, so its absence after the wait means our
  own bridge never sent it, which is what happens once ffmpeg has exited: a
  stall, a camera drop, the abandon ceiling. Both the ack and the flag are now
  required.

  `talk_supported` had the same shape of error and is fixed with it: it answered
  from the talk-state dictionary, which outlives ffmpeg, while the bridge thread
  and the pump's socket do not. It now requires the session to still be running.

  Stated precisely, because the first draft of this entry claimed more than was
  checked: that second fix closes a path nothing currently reaches. `async_speak`
  reuses `_stream_session` only when it is talk-capable, and none of the three
  loops that set it - keepalive, streaming, DTLS serve - open with `talk=True`,
  so on SDES it is never talk-capable and the reuse branch is never taken. The
  fix is correct and the class of error is real; what has actually been observed
  is the acknowledgement fail-open above.

  That leaves a measured consequence worth naming: because the live-view session
  is not talk-capable, every press-to-talk on an SDES camera opens a SECOND
  camera session while the first is still running. Nothing has measured what
  that costs in viewer slots.

  Measured on the fleet: three SDES cameras returned True and never pulled a
  single audio frame, and the run log contains no SPEAKERSTART line at all. The
  DTLS path shares the ack reader and its behaviour does not change.

### Added

- **`AIDOT_SDES_VIDEO_PT_ORDER` sets the video codec preference order in the
  SDES offer.** Opt-in, inert unless set, and it can reorder but never narrow.

  A correction first, because this file has said otherwise. The offer does not
  "express no preference": RFC 3264 section 5.1 makes the `m=video` payload-type
  list a preference list, most-preferred first, and ours has always read `96 97`
  - H264 first. What is true is that nothing ever chose that order. The line
  arrived verbatim when the SDES open path was split out of `client.py` and has
  never been varied.

  That reframes what is known rather than adding to it. On an A001064 the camera
  answers H264 most sessions and H265 occasionally for an identical request,
  which read against the offer is a camera that honours our stated first choice
  most of the time and disregards it some of the time. So expressing a
  preference is a weaker lever than pinning, not a stronger one, and this ships
  as an experiment rather than as a fix.

  It is worth having because the efficient profile - hevc 2560x1440 at about
  1.1 Mbps against h264 1280x720 at 2.5-4.0 Mbps - has only ever appeared when
  both codecs are on the wire. `AIDOT_SDES_VIDEO_PT=97` narrows the offer to
  H265 and returns no video at all, 3 of 3 rounds: narrowing removes the option
  rather than selecting it. Reordering is the only untried lever that leaves
  both codecs offered, so the camera can still fall back to H264.

  Set it to `97,96` and the offer prefers H265 while still advertising H264.
  Whatever is named leads and every advertised codec not named is appended, so
  no value can produce a narrowed or empty video m-line - a video m-line with no
  payload type is the one outcome worse than an unpinned choice. Unset, the
  offer is byte-identical to 1.0.0b1, which matters because this path is shared
  by every SDES camera and changes to shared paths have caused fleet-wide
  blackouts before.

  A status line reports the order whenever it differs from the shipped one, so a
  run can tell an effect from a coincidence. The first attempt at the pin looked
  like a confirmed result for two sessions before a missing receipt showed it had
  never reached the SDP at all.

  Untested on hardware. Whether the camera acts on m-line order is exactly the
  open question, and the default is deliberately left alone until a run answers
  it.

### Internal

- The release harness exercises snapshot, PTZ, two-way audio, thumbnails and
  cloud recordings against real hardware. Nothing had ever verified any of them;
  the gate only ever answered whether video arrives and decodes. Four outcomes
  are kept apart on purpose - unsupported, not run, passed, failed - because
  collapsing any two of them is the defect this project has now corrected
  repeatedly. `IsSupportPlayback` is the live example: it says where a camera's
  recordings live rather than whether it can record, so cloud playback is
  UNSUPPORTED on the models that store to SD, not broken.

- The probes that ride an open session now run while one is open. The recording
  window ended before the probes began, so all of them ran against a closed
  session - which is how a working two-way audio path came to be reported as
  three cameras failing. A closed session now reports NOT_RUN and names itself,
  rather than being scored against the camera.

- PTZ is scored on what the call returns. `async_ptz_move` does not raise when
  it cannot send - it logs, returns False and nothing leaves the host - and the
  probe caught only exceptions, so a run reported PTZ passing while its own log
  carried a refusal for every command. The harness also now registers the open
  session where the library's control paths look for it, which the loops Home
  Assistant goes through do and a bare stream open does not. Between them these
  mean the first real PTZ measurement on hardware is the one after this.

## [1.0.0b1]

The first pre-release of 1.0.0. **It does not assert that the 1.0.0 bar is met** -
see `docs/ROAD-TO-1.0.md`, which names what is still open. It asserts that this
is the shape 1.0.0 is intended to have.

### Fixed

- **A cloud response that can carry per-device credentials was logged whole.**
  `batchGetDeviceUserInfo` was printed in full, at WARNING on one of its two
  sites, so it reached every install's log rather than only debug ones. That
  response can carry `tutkAccount` and `tutkPassword`. It now logs the response's
  KEYS and a count, matching the adjacent branch, which had been doing it
  correctly all along.

- **A camera the cloud reports offline is no longer opened.** The integration
  guarded three doors against this and not the fourth - `stream_source`, which is
  the go2rtc lazy-pull path. A camera that has been off for weeks was still
  taking 45 seconds of the library's global open gate on every attempt, delaying
  every other camera's cold start. The check fails open, and sits where a wrongly
  stale flag can cost a cold open but can never take away a working live view.

- **The parameter-set cache no longer reports writes it did not make.** Two of
  the three outcomes in that path write nothing, and the announcement did not
  distinguish them - so a camera whose injection is permanently disabled logged a
  successful cache write on every session. It is the only observable that path
  has, and it sent an investigation looking for a cache that could not exist.

### Changed

- The secrets-in-logs guard now covers the whole package rather than one module,
  with device passwords, aesKeys, tokens and MQTT credentials added to what it
  refuses to see printed. It reports honestly on what it still cannot catch: a
  secret inside a container that is not itself named like a secret, subprocess
  output, and a rename into a local.

### Internal

- The `liveType=0` / TUTK path is **declared out of scope for 1.0.0**, with
  reasons, rather than left silent: no device can enter it, and everything past
  its guard is ctypes into libraries this package does not ship. The one
  reachable behaviour - the refusal - is now tested.
- The resolution acknowledgement read is covered end to end on DTLS over a real
  session and router. The bar had described this hole as "unit tests only on
  DTLS"; that was wrong, and the repo's own changelog and parity notes said so.
  The real gap was that nothing joined the setter to a session.

## [0.17.3b2]

Pre-release. Closes the audit backlog opened on 2026-08-07, and corrects two
things that were wrong about how this project measures itself.

### Fixed

- **A stream that could not be decrypted still reported itself healthy.** The
  SDES bridge stamped its media counters after forwarding every packet,
  including ones that failed SRTP decryption and that ffmpeg then discarded.
  Those counters are the only in-process evidence media flowed, so
  `is_stalled` never tripped, the keepalive stayed `_healthy`, and the abandon
  ceiling could never fire: a session showed black and claimed to be fine,
  indefinitely. Counting is now gated on the packet being plaintext by the time
  the consumer reads it - which depends on the camera, because on models where
  ffmpeg owns the decryption, forwarding ciphertext IS correct delivery.

- **A camera that changed its SRTP key mid-open was decrypted with the old key
  for the rest of the session, so it delivered nothing.** On the SDES path the
  bridge is the only decryptor - the ffmpeg SDP is plain RTP with no key in it -
  so the receive session's key decides whether there is any picture at all.

  That session was built once and never revisited. The guard around it was "have
  we been here before", and the first thing inside the guard answered yes, so
  every later packet skipped the block whether or not a session had actually
  been built. A build that failed - no SRTP support installed, or an unusable
  key - was therefore disabled for the life of the stream rather than retried.

  It also preferred the key parsed from the camera's *first* answer. Cameras
  that answer twice (the second answer being the real one) already trigger an
  ffmpeg restart with the new key, but the bridge kept the first key, so the
  restart could not help: the camera encrypted with one key and the only
  component able to decrypt held another.

  The session now records the key it was built from and is rebuilt when that key
  changes, nothing is stored unless construction succeeds, and the key it
  follows is the one the rest of the open negotiates. A key learned only from a
  late answer is now adopted the same way a prompt answer's key already was.

- **Two answers to one signaling request could both be lost.** The MQTT handler
  runs on an executor thread and tested a future's `done()` there while
  deferring the mutation to the loop, so the test and the set were not atomic -
  and the loop is documented as blocking for seconds inside a synchronous STUN
  select. Both now happen inside one callback. The harm was a missing log line
  and unprocessed second-answer ICE candidates, not lost video.

- **Cancelling a snapshot did not cancel it.** `async_snapshot` caught
  `CancelledError` in the same handler as `TimeoutError` and then spawned
  another ffmpeg for up to 15 s, returning normally. Cancellation now
  propagates.

- **SRTP key material was printed into logs users share.** Four sites on the
  SDES path logged real key bytes - one of them the decoded master key and salt
  in full hex, another 16 characters of two keys plus the whole packet, on the
  first ten packets of every session. These reach `home-assistant.log`, which
  people paste into public issue reports. All four now print a truncated
  SHA-256 fingerprint, which tells two keys apart without disclosing either, and
  a test walks the module to keep it that way.

- **A latent SCTP parse wrote the peer's initial TSN into our own counter.** The
  path is not currently reachable; the mapping is correct now regardless.

- **A device that offered local control and then refused it looked like a device
  that never offered it.** `CameraLanLoginRejected` now carries the ack the
  device sent, so the two can be told apart.

### Changed

- Local control is accepted only by the account that OWNS the devices. A member
  of a shared home receives a full device list from the cloud - including every
  per-device password and aesKey - and is then refused by the device itself,
  with a code that varies by model and a message that blames the password. Both
  READMEs now say so, and say to check the account first. No code changed: this
  was a documentation defect, not a protocol one.

- The RTCP transmit path records which SRTP key each sender used. Instrumentation
  only - the PLI and RR select differently and at most one can be right, but
  nothing has ever been observed to go wrong, so nothing branches on it yet.

### Internal

- The release harness now configures logging. It never did, so the root logger
  fell back to WARNING-and-above and every INFO and DEBUG line the library
  emitted was discarded in every fleet run - including the per-session video
  profile lines shipped in 0.17.1 for no other purpose than to accumulate a
  record. Four runs produced zero of them.

- The harness also decodes each recording and reports the frame count. Its other
  media signals - a packet counter and a byte count from a `-c copy` pipeline -
  are both satisfied by bytes of the right shape, which is precisely the failure
  the first entry above describes.

- Three tests that passed on prose were replaced with tests that fail when the
  code they guard is deleted. Each replacement was demonstrated failing against
  the injected fault; one of the originals passed while two independent
  stream-killing regressions were present.

## [0.17.3b1]

Same code as 0.17.2. Re-cut as a pre-release, because 0.17.2 should not have
been a final version.

Nothing in 0.17.2 is known to be broken, and it measurably improves on 0.17.1 -
the LAN login storm went from 26,229 failed logins in a 25-minute fleet run to
157. But "this specific fix is validated" is not "this release is good", and
several known problems are still open at the time of writing: the six devices
that reject LAN login still reject it (the ceiling stops the hammering, it does
not make them log in), and the audit backlog is unfinished.

Releases stay on this beta line until that is no longer true. `pip` and Home
Assistant skip pre-release versions unless asked for them, which is the point:
the version number itself now says what state the code is in, rather than a flag
on a release page that no installer reads.

0.17.2 is left on PyPI rather than yanked - yanking it would move installs back
to 0.17.1, which has the storm.

## [0.17.2]

### Fixed
- **A device that could not log in over the LAN was retried several times a
  second, forever.** Upstream's client retries a failed login with no delay and
  no ceiling: `login()` logs the error, calls `reset()`, and `reset()` ends in
  `_schedule_reconnect()`, whose last line spawns the next login immediately.
  The `call_later(60, ...)` on the line above never fires, because the next
  `reset()` cancels it first. So the period is the device's login round-trip,
  not a minute.

  Measured on one 25-minute run: 8,434 of 8,434 failures were followed by that
  device's next connection attempt within a median of 0.295 ms - about 7.6
  attempts per second for a single light, 15,376 across six devices, and it
  stopped only because the process ended.

  This was reachable from Home Assistant, not just from test harnesses. Any
  device that cannot LAN-login - wrong credentials, or another client already
  holding the session - was hammered for as long as the integration stayed
  loaded, and the only visible symptom was a very large log.

  Retries are now exponential from 1 s, capped at 60 s, and stop after six
  consecutive failures; a successful login resets the count, so an ordinary
  momentary drop still recovers on the first prompt retry.
  `AIDOT_LOGIN_RETRY_LIMIT` and `AIDOT_LOGIN_RETRY_CAP_S` override both.

  The policy applies to every device client this package hands out, camera or
  not. That is the whole point: the LAN login is the light protocol, and the six
  devices in the run above were lights. Non-camera devices now get
  `LightDeviceClient` - upstream's client plus the retry policy and nothing
  else. The policy itself lives in `aidot_cameras/lan_retry.py`, which imports
  nothing from the camera package and is tested for it, so bounding a light's
  retries does not put camera code in a light's path.

  Cameras never reached this path anyway: `async_login` returns early for IPC
  models.

- **A camera the keepalive gave up on left a dead stream registered in
  go2rtc.** The keepalive has several exits; the idle-release one tears down its
  go2rtc registration, but the exit taken when a camera delivers no media for
  long enough returned without doing so. The stream stayed registered against a
  serve port with nothing listening, so a viewer attaching to a camera that had
  gone dormant that way got "connection refused" instead of the clean miss the
  release path exists to produce.

  That exit now performs the same teardown as the idle-release one. The test is
  an AST guard that enumerates every keepalive exit rather than checking the one
  that was wrong, so an exit added later without teardown fails too.

- **A device that went silent mid-login was abandoned with its socket still
  open.** Upstream has no read timeout anywhere in its device client, so a
  device that completes the TCP handshake and then stops answering leaves the
  login parked in `readexactly` forever - inside `connect()`, which means
  `connect()`'s own cleanup never runs and the client goes on believing an
  attempt is still in flight. That wedges the retry path too: nothing new can be
  scheduled while an attempt is notionally live, so the device silently stops
  being managed.

  Observed on the same run: four of six devices ended that way rather than
  stopping cleanly, and all six emitted their single teardown error within 3 ms
  of each other - six sockets held open, one of them for 21 minutes.

  A connect/login attempt is now bounded at 20 s, after which the socket is
  closed and the device returns to the (now bounded) retry path.
  `AIDOT_LOGIN_CONNECT_TIMEOUT_S` overrides it.

## [0.17.1]

### Added
- **RTCP feedback survives SDP compression, so the camera can be told to slow
  down.** The compressor that produces the compact offer these cameras parse was
  dropping every `a=rtcp-fb` line. Payload types that survive narrowing now keep
  their feedback lines, and the camera's own answer comes back advertising
  `nack` and `goog-remb` on audio PT 8 and video PT 96 - so its compact parser
  does read them. Measured cost on a real browser offer: 263 bytes, taking the
  compressed offer to about 1300, well inside the 2048 the smallest model
  reports.

- **REMB can be sent, but is off by default.** `build_remb` /
  `decode_remb_bitrate` and the sender are included and tested;
  `AIDOT_REMB_TARGET_BPS` set to a bitrate turns it on.

  It ships disabled because it was measured and did not work. An A001064 was
  A/B'd with REMB transmitting at 500 Kbps and correctly naming the video SSRC -
  per-session receipts, interleaved arms, a control - and its bitrate did not
  fall. The one clean like-for-like pair had the REMB arm higher than its
  control, 3859 against 3355 Kbps.

  Enabling it by default would also have capped, at 500 Kbps, any model that
  *does* honour REMB - on the strength of a measurement taken on a model that
  ignores it. The other models on this fleet have not been tested. A bitrate cap
  is not something to switch on fleet-wide without evidence it helps the cameras
  it would affect.

- **The negotiated video profile is now recorded on every session.** An A001064
  was measured serving two different profiles for identical requests - H264
  1280x720 at 2.5-4.0 Mbps, and H265 2560x1440 at roughly 1.1 Mbps - varying
  per session, with nothing in the request asking for either. Codec and
  resolution moved together in all eleven sessions measured.

  Nothing recorded which one a session got, so no two bitrate figures from this
  camera were ever comparable: the codec that produced each one was never
  written down. One INFO line now names the payload type and codec when the
  first video packet lands.

- **`AIDOT_SDES_VIDEO_PT` pins the SDES offer to a single video codec.** The
  offer advertises both 96 (H264) and 97 (H265) and expresses no preference, so
  the camera decides in its answer. A consumer that cannot decode a sudden
  2560x1440 H265 stream, or cannot absorb a threefold bitrate change, has had no
  way to prevent the flip.

  Set it to `96` and the offer carries H264 only: measured h264 1280x720 in 4 of
  4 sessions, against an unpinned baseline that varies. Unset - the default -
  the offer is byte-identical to 0.17.0, which matters because this path is
  shared by every SDES camera.

  **Do not set it to `97`.** An H265-only offer returned no video at all - audio
  only, with no video stream in the recording - in 3 of 3 interleaved rounds,
  against 3 of 3 successes for `96` in the same run. The H265 profile is real
  and reproducible, but only when both codecs are offered; narrowing to it
  removes the option rather than selecting it. What does select it is not yet
  known, which is what the logging above exists to answer.

### Fixed
- **A camera's cached decoder parameters could be filled with random bytes, and
  the damage outlived the session.** The bridge mined SPS/PPS out of whatever
  packet it was holding without checking that anything had decrypted it. Two
  ordinary situations leave it holding ciphertext: no SRTP receive session at
  all - `pylibsrtp` ships in the optional `webrtc` extra, so a base install has
  none - or a decrypt that failed.

  SRTP leaves the RTP header in clear, so the payload offset is computed
  correctly and random ciphertext reaches the parameter-set parser, where the
  two values it looks for turn up by chance within seconds of a 30 fps stream.
  The result was written to `~/.config/aidot/sprop/<devid>.sprop` and injected
  into every later session as `sprop-parameter-sets=`, so a decoder was
  initialised from noise. Installing `pylibsrtp` afterwards did not clear the
  file, and the first genuine capture then disagreed with it and tripped the
  instability marker, which disables injection for that camera permanently.

  The capture is now gated on the packet having actually been decrypted. On a
  healthy session nothing changes.

- **Two kinds of "the camera is awake" evidence could never release the wake
  gate.** The gate that ends the pre-offer wait checked for MQTT topics under
  `iot/v1/c/{device_id}/` - but the client subscribes to
  `iot/v1/cb/{device_id}/#`, with a "b", so no device-channel topic ever
  matched. Separately, `wakeupStatus` - the camera announcing it is awake -
  carries no `devId` at top level or in its payload, identifying itself only
  through `srcAddr`, which nothing read. Both now count. The change is strictly
  additive: everything that released the gate before still does.

- **The SDES offer was missing `powerType` and `p2pCache`.** The DTLS
  `webrtcReq` has carried both for a long time; the SDES offer never did, so
  half the fleet sent an offer the reference client would not recognise as
  complete. Sent as strings on the SDES path, matching the reference client,
  which stringifies the values it reads. The DTLS path sends ints, is
  fleet-proven, and is left alone.

- **A battery camera was being woken for sessions that could never stream.** The
  keepalive loop had no give-up condition: when a camera opened a session but no
  media ever arrived, it reconnected indefinitely, waking the camera each time
  and spending its battery on sessions that produced nothing. Observed running
  for eight hours.

  After five consecutive no-media background sessions a battery camera's
  keepalive now stops and says so; `AIDOT_FUTILE_KEEPALIVE_LIMIT=0` disables the
  ceiling. Mains cameras are unchanged - they have no charge to protect, and
  that persistence is what recovers a stream after a router reboot or a
  power-cycle.

  Scoped to the background loop on purpose. A live view still opens a session on
  demand: a user asking to see the camera is new information, and a retry
  ceiling should not decide on their behalf that it cannot work.

  This does not address why such a camera delivers no media through a given
  host - the same unit streams fine from other machines on the same LAN. What is
  fixed is a background task repeating a failed operation forever at the
  camera's expense.

## [0.17.0]

### Fixed
- **A camera that clears in eight seconds was being rested for five minutes.**
  When a camera answers `-50002` / `-50015` ("no free session") both keepalive
  loops slept 300 s, on the reasoning that the camera "releases slowly". It does
  not. Measured on an A001064, reopening after a close:

  | gap | result |
  |-----|--------|
  | 2 s | refused `-50002` |
  | 8 s | reopened cleanly |
  | 20 s | reopened cleanly |

  That was minting a fresh peerid on every attempt - the case the old comment
  warned about - and it still recovered inside eight seconds. A camera that
  clears in seconds paired with a five-minute refusal to retry is
  indistinguishable from one that needs a long rest, and it made a brief,
  ordinary refusal look like a camera that had to be left alone.

  The wait is now 20 s, overridable with `AIDOT_BUSY_BACKOFF_S`. It is still a
  real wait: retrying instantly would hammer a camera that genuinely has none
  free, and on a battery model risks the wake-then-sleep loop the original
  backoff was guarding against.

- **Two-way audio reports whether the camera opened its speaker.**
  `async_start_talk` returned `True` unconditionally - it sent SPEAKERSTART and
  declared success whether or not the speaker ever opened. It now waits for the
  camera's 851, measured at 0.01-0.86 s across both transports, and the
  microphone is enabled only once the camera has answered. Previously
  `replaceTrack` came first, so viewer audio was already going out during the
  round trip.

  Silence still counts as success: an A001064 answers SPEAKERSTART but does not
  implement GETSTREAMCTRL at all, so a firmware with no response for a command
  is an ordinary state, and failing on it would remove two-way audio from every
  quieter camera. So does any ack - the payloads observed (`0x0064`, `0x00c8`,
  including both from one camera on consecutive sessions) all came back from
  speakers that opened, so the payload carries no verdict to read.

- **A device-attribute ack is matched to the command that sent it.**
  `async_set_device_attribute` generates a `seq` and the camera echoes it in
  `setDevAttrResp`, but nothing checked it coming back: the first message on a
  topic containing `setDevAttr` carrying code 200 was accepted, whichever
  command it belonged to. Battery cameras get a wake published in the same
  breath and Home Assistant writes attributes in bursts, so that could report
  one control landing on the evidence of another. A reply carrying our own seq
  is now proof; everything else is considered exactly as before.

  A command that draws no matching ack still succeeds - the official app is
  fire-and-forget and no-ack is normal - and a non-200 ack for our own seq is
  logged rather than acted on, because no camera has been seen sending one.

- **The SCTP association is closed at teardown.** The library built only INIT,
  INIT-ACK and DATA and never sent SHUTDOWN or ABORT, so a camera was never told
  the association was over, while the official app disposes its data channel and
  the DTLS path already sent ABORT. Measured before and after: this does **not**
  change the refusal window above - the camera releases the session on an
  application-level timeout, not on association state - so it is here as
  correctness rather than as a fix.

### Added
- `async_set_resolution` reads the camera's 801 ack and logs it, so a refusal is
  visible instead of indistinguishable from success. The return value still
  means "the command went out": how much a firmware answers is model-dependent,
  and failing on silence would break the call on the quieter cameras.

## [0.16.0]

### Added
- **The library reads the camera's replies.** Every AVIO control command was
  fire-and-forget: the camera answered and the reply was discarded, so three
  outcomes were indistinguishable from outside - the camera applied the command,
  accepted and ignored it, or refused it. That ambiguity has cost whole evenings
  of investigation more than once.

  `session.async_avio_request(cmd, payload, response_cmd=..., timeout=...)`
  sends a command and returns what the camera said, or `None` if it said nothing
  within the budget. Registration happens before the send, because a camera on
  the LAN can answer before the sending call returns. The wait is short by
  design: these sit behind Home Assistant service calls and a firmware that
  implements a request without a response must not be able to hold up a view.

  `_avio_cmd` is deliberately untouched - still synchronous, still
  fire-and-forget, still returning a bool. Every camera on both transports goes
  through it, so wanting an answer is a separate, opt-in call and no existing
  caller changes behaviour.

  Confirmed live on both transports. An A000088 over DTLS answers SPEAKERSTART
  (848) with 851 in 0.38 s, SETSTREAMCTRL (800) with 801 in 0.01 s, and
  GETSTREAMCTRL (802) with 803. An A001064 over SDES answers 848 with 851 in
  0.17 s and does not implement 802 at all - a per-model firmware difference
  that was simply invisible before, because "no reply" and "no listener" looked
  the same.

### Fixed
- **Inbound AVIO on SDES was read from the wrong channel.** Replies were being
  looked for in the TUTK-audio forward path, which handles control frames framed
  as 0xC8 audio. The camera answers on the encrypted SCTP DATA channel (PPID 53)
  instead - the same one that carries LIVING, the heartbeat and SPEAKERSTART.
  That branch had been decoding each frame and logging its command id for some
  time, then dropping it, so the acks were sitting in the log unread.

  A chunk there can also carry more than one frame - the session-mode notify
  declares a 12-byte payload and has been seen arriving in a 140-byte chunk - so
  every frame in a chunk is now read rather than just the leading one. A reply
  batched behind a notify would otherwise be dropped, and that presents as a
  camera intermittently failing to answer, which is the hardest symptom on this
  path to attribute correctly.

### Notes
- **`async_set_resolution` is confirmed to have no observable effect, and it is
  not because the camera ignores the command.** The camera accepts it, acks it,
  and reports the new value back through `GETSTREAMCTRL`: read 5 (MIDDLE) at
  session start, 5 after setting `sd`, and 1 after setting `hd`. What does not
  change is the video. Measured per frame on an A000088 with the quality
  verified by read-back first: 728 frames at quality 1, all 1280x720, 2592 bytes
  per frame; 651 frames at quality 5, all 1280x720, 2682 bytes per frame.

  Earlier checks had all been made in the `sd` direction, which sends the value
  the camera is already on - they only ever showed that setting a camera to its
  current value changes nothing. The setting also does not survive a session:
  every session opens at the camera's own default of 5.

  The command stays in the library. It is correct, the camera acknowledges it,
  and a future firmware may act on it.

## [0.15.8]

### Fixed
- **A lossy link no longer kills the stream.** Both ends of this path are
  usually wireless - the camera, and the Home Assistant host - so RTP genuinely
  arrives with gaps. Measured on the reference install: ffmpeg logged
  `RTP: missed N packets` while every socket in the path showed **zero** kernel
  drops, so those packets were lost before they ever reached the box and no
  amount of buffering here can recover them. What the serve controls is what
  happens next, and it was handling loss badly: with no reordering headroom a
  burst that arrived out of order read as loss, and with no bounded `max_delay`
  the demuxer stalled waiting for it ("max delay reached. need to consume
  packet") until its input queue backed up and the serve died - dropping every
  attached viewer over packets that were never coming.

  The serve now runs with `+discardcorrupt`, a 500-packet reorder queue (a
  keyframe here is 146-190 KB, about 130 packets, so the queue has to clear more
  than one) and a 500 ms `max_delay` so a gap is given up on rather than stalling
  the pipeline. Both are env-overridable - `AIDOT_SERVE_REORDER_QUEUE`,
  `AIDOT_SERVE_MAX_DELAY_US` - because the right values depend on the link. The
  low-latency flags are unchanged, and the e2e tier exercises the real serve
  command against a feed with every second packet dropped.

  This does not stop the loss. It stops the loss from ending the session.

## [0.15.7]

### Fixed
- **Every synthesized RTP packet carried sequence number 1.** The TUTK-to-RTP
  bridge (the `_PLAIN_RTP_MODELS` path - A001064 PTZ, A001513) keeps its
  sequence counters on the bridge function and initialised them behind
  `if not hasattr(_bridge_fn, '_tutk_seq')`. Nothing ever assigned `_tutk_seq`;
  the counters are `_tutk_seq_a` and `_tutk_seq_v`. So the guard was true on
  every packet, both counters reset to 0 each time, and every packet went out
  with sequence 1. ffmpeg reads a constant sequence as a stream of
  discontinuities and logs `RTP: missed N packets` for loss that never happened,
  then backs its input queue up behind the reordering it thinks it sees.

  Found by elimination: kernel counters showed **zero drops on every socket in
  the path** - our media sockets, and ffmpeg's own loopback receive sockets at
  5% queue depth - during a window where ffmpeg reported 21 new missed-packet
  lines. Nothing was being lost, so the gaps had to be in the numbering we
  write.

  Tests pin the guard against the counters it initialises, that both counters
  advance from their own previous value, and - generally - that no
  `hasattr(_bridge_fn, ...)` guard names an attribute nothing assigns, since
  that idiom fails silently for the whole class of state kept this way.

## [0.15.6]

### Fixed
- **Camera media sockets ran on the OS default receive buffer.** Nothing in the
  package ever set `SO_RCVBUF`, so the sockets that receive a camera's RTP used
  the kernel default - 208 KB on Home Assistant OS. An A001064 keyframe is
  146-190 KB and arrives as one burst of about 130 packets, so a single keyframe
  nearly fills that buffer; any delay in the reader (the GIL while another
  camera's bridge runs, an ffmpeg write blocking) lets the kernel drop the tail
  of the burst. ffmpeg reports that as `RTP: missed N packets` and backs its
  input queue up behind it. Both media sockets now ask for 4 MB before they
  bind, and log what the kernel granted.

  Evidence: the reference Home Assistant box carried **44.3 million
  `RcvbufErrors` against 161 million datagrams received** over four days, and
  `InErrors` equalled `RcvbufErrors` exactly - every UDP receive error on it was
  a buffer overflow, not a checksum or port error. Measured against load: a
  settled single camera dropped **0 packets in 90 s**, while the 120 s after an
  integration reload - every camera opening at once - dropped **176**. That is
  the same window in which sessions were dying after ~75 s, and it is why the
  same camera can run for over an hour untouched and then recycle every minute
  after a restart. Host-wide counters cannot attribute those drops to one
  socket, so this is not proof for any single stall; the mechanism, the timing
  and the `RTP: missed N packets` in the serve's own stderr all agree.

## [0.15.5]

### Added
- **`aidot-go2rtc <id> -` streams a DTLS camera to stdout**, so go2rtc's
  `exec:` source can own the process the way it already does for SDES cameras
  (`{output}`): spawn on the first viewer, kill when idle. Previously a DTLS
  camera could only be served on an `-listen` socket, which has to be bound
  before anyone asks for it and stays bound afterwards. The HTTP-listen serve
  is unchanged and still available. This removes the need for the private
  go2rtc add-on to carry a source patch against the library, which had drifted
  against a package path that no longer exists.

## [0.15.4]

### Fixed
- **SDES serve and bridge log lines now name the camera.** They carried no
  device id, so on an account running several SDES cameras at once a burst of
  `ffmpeg exited with code 255` lines could not be attributed to any one of
  them - during a live investigation that ambiguity produced a wrong reading of
  which camera was failing. `SdesSession` now takes the id (optional, so an
  existing caller keeps working) and both the bridge exit line and the serve
  stderr tail carry it.

### Changed
- Docs and the publish workflow's error text named `python-aidot-cameras-dev`
  as the home of the live-validation runner. It lives in
  `python-aidot-cameras-ci`; a release blocked by the gate pointed at a repo
  with no such workflow.

## [0.15.3]

### Fixed
- **SDES push live view recovered (e.g. the A001064 PTZ): every viewer got a
  `DESCRIBE ... 404`.** The SDES serve ffmpeg was spawned with `stderr=PIPE` that
  nothing ever read; ffmpeg logs H.264 warnings continuously on some streams, so it
  filled the ~64KB pipe buffer and then blocked on its next stderr write, which
  killed the RTSP-push publisher (exit 255). go2rtc was left holding only the inert
  placeholder source, so every consumer got `DESCRIBE ... 404` and the go2rtc
  provider surfaced a hard stream error. The serve's stderr is now drained
  continuously into a bounded tail on a daemon thread (ending at EOF when ffmpeg
  exits) and logged on a non-teardown exit. With the pipe drained the publisher stays
  alive and go2rtc keeps a live producer; if ffmpeg ever does exit non-zero the
  reason is now logged instead of discarded. Confirmed live: the publisher stays
  connected and streams H.264 + PCMA into go2rtc.
- **Teardown no longer loses ffmpeg's stderr.** Draining the pipe leaves it at
  EOF, so the read in `SdesSession.stop()` returns nothing and the teardown
  diagnostic - which is where a genuine mid-stream ffmpeg error surfaces - would
  have gone silent. It now falls back to the drained tail, and still demotes the
  expected "camera sent no media" shape to debug rather than warning on every
  retry.

## [0.15.2]

### Fixed
- **Changing a camera's resolution usually did nothing.** The setting is
  delivered over the live streaming session, so it could only ever arrive while
  the camera happened to be streaming. At any other time it was discarded, and
  nothing re-sent it. Since a camera is idle far more often than it is being
  watched, the ordinary result of changing this setting was no change at all -
  while the caller was told it had been applied.

  The choice is now remembered and applied when a session next starts. Changing
  it while the camera is streaming behaves as before, taking effect at once.
  Re-applying is best-effort and cannot disturb a stream that is already
  running: a picture matters more than a quality preference.

## [0.15.1]

### Fixed
- **Reading the remembered decoder could block the event loop.** Home Assistant
  detected it and reported it as a stability problem, which it was: the reader
  is consulted while a camera stream is being set up, and it fell back to
  reading a file from disk whenever the answer was not already in memory.

  The reader now only ever consults memory. The file is read once, in the
  background, by the same startup work that measures the decoder in the first
  place. If an answer is not yet in memory the caller is simply told so and lets
  ffmpeg choose, which is what happened before any of this existed.

  Affects 0.15.0 only. The effect was a few milliseconds of delay per stream
  setup rather than anything visible, but it is not something to leave in a
  release.

## [0.15.0]

Verified on real cameras before release: every reachable camera on the test
fleet streamed through Home Assistant's own live view, including the one that
had been showing a black picture.

### Fixed
- **A camera could show a permanent black picture while its stream was
  perfectly healthy.** The decoder is set up from parameter sets remembered
  from an earlier session, which is only safe while the camera keeps sending
  the same ones. One model does not, so the decoder was described a stream that
  no longer matched and decoded nothing for the whole session, while the
  picture stayed blank and everything else looked fine - the camera connected,
  the stream flowing at around 2 Mbps, eleven megabytes arriving during a
  viewing that showed nothing. A camera whose parameter sets are seen to change
  is now remembered, and the remembered copy is neither kept nor used for it
  again.

### Added
- **The fastest working video decoder is now found per machine, rather than
  assumed**, and used where it genuinely helps.

  It cannot be read off the list of decoders ffmpeg reports: that list says what
  the program was built with, not what the machine can do. A Raspberry Pi 4
  lists decoders for graphics hardware it does not have, and one for its own
  video hardware that fails to start. On Apple machines, and on Linux machines
  using VAAPI, there is no decoder to name at all - those are listed as encoders
  and the decoding side is offered only as an acceleration method. Both forms
  are tried, each looked up in the list that describes it, and every candidate
  has to decode a sample before it is used.

  Hardware is not assumed to be faster, because it is not always: on an Apple
  M1, VideoToolbox decodes H.264 about three times slower than software, so
  software is chosen there. Candidates are ranked by measured time on the
  machine itself.

  The work runs in the background and never delays startup. It costs a
  Raspberry Pi 4 about six seconds once, and a machine with no video hardware
  is answered in about three milliseconds without starting anything.

  `AIDOT_VIDEO_DECODER` forces a choice - a decoder name, or `hwaccel:` and a
  method. `AIDOT_DISABLE_HWACCEL` keeps to software decoding.

### Notes
- H.265 ingest is not part of this release. It needs the H.265 parameter sets
  handled first, and shipping it before that would invite the same blank-picture
  fault on a less-tested path.

## [0.15.0b5] - pre-release

### Changed
- **Working out which decoder to use no longer costs a small machine much of a
  minute.** On a Raspberry Pi 4 it took 54 seconds of wall clock and 26 seconds
  of processor time; it now takes about 6 and 5. Measured back to back on the
  same loaded machine.

  Three things were being paid for and not used. Hardware was being tried that
  the machine plainly does not have - a check for the device first costs a
  filesystem lookup, where trying it costs a process and a couple of seconds.
  H.265 was being worked out although only H.264 is ingested, which was nearly
  half the total. And software decoding was being measured even when nothing
  had beaten it, though in that case it wins whatever the measurement says.

  On a machine with no video hardware at all - most cloud and container
  installations - the question is now answered in about three milliseconds
  without starting anything, where before it encoded and decoded a video clip
  to reach the same conclusion.

  This is one-time work per machine that already ran in the background, so
  nothing was ever delayed by it. The point is that it no longer takes
  processor time away from streaming on machines that have little to spare.

## [0.15.0b4] - pre-release

### Fixed
- **Hardware decoding was unreachable on Apple machines and on Linux machines
  using VAAPI**, which between them are most of the desktop installations. The
  detection added in 0.15.0b3 looked for decoders by name, and on those two
  platforms there is no decoder to name: ffmpeg lists `h264_videotoolbox` and
  `h264_vaapi` as *encoders*, and offers the decoding side only as an
  acceleration method. So those machines quietly fell back to software while
  having working hardware decoding available. Both forms are now tried, each
  looked up in the list that actually describes it.

  Found by running the detection on an Apple M1, where the whole candidate list
  came back empty. It could not have been found on the Raspberry Pi this was
  first written against, which uses the naming form.

### Changed
- **The sample used for detection is now the size the cameras actually send.**
  It was much smaller, which measured the wrong thing: hardware decoding pays a
  fixed setup cost that dominates a very short job, so a decoder that wins
  comfortably on real frames could look like a loser. Correcting this changed a
  real verdict on the M1 tested, where H.265 moved from software to hardware.
- A candidate must now produce frames to qualify, not merely exit cleanly. A
  decoder that opens, consumes the stream and emits nothing would otherwise pass
  the check, and that failure shows up as a permanently black picture rather
  than as an error, which is the hardest kind to attribute.

### Notes
- Hardware decoding is not always faster, and is no longer assumed to be. On the
  Apple M1 tested, VideoToolbox decodes H.264 about three times slower than
  software, measured in the same pipeline this uses in practice; software is
  therefore selected there. Candidates are ranked by measured time on the
  machine itself, so the faster path wins whichever it turns out to be.
- `AIDOT_VIDEO_DECODER` accepts either form: a bare name for a decoder, or a
  `hwaccel:` prefix for an acceleration method (`hwaccel:videotoolbox`).

## [0.15.0b3] - pre-release

### Added
- **The fastest working video decoder is now detected per machine, rather than
  assumed.** Where a machine has video decoding hardware that genuinely works,
  it is used; where it does not, nothing changes.

  Detection cannot simply read the list of decoders ffmpeg reports, because that
  list describes what the program was built with rather than what the machine
  can do. A Raspberry Pi 4 lists decoders for Nvidia graphics hardware it does
  not have, and lists one for its own video hardware that fails to start even
  with the hardware present. Choosing from that list would not speed decoding
  up, it would stop decoding working.

  So each candidate is required to prove itself: a short clip is produced and
  decoded with it, and only a clean run qualifies it. The fastest that qualifies
  is used. On the Raspberry Pi 4 this was tested on, the two decoders that
  cannot work were correctly rejected.

  Proving a decoder takes around ten seconds per video format the first time, so
  the result is remembered and reused, and is tied to the ffmpeg program it was
  measured against - installing a different ffmpeg re-measures rather than
  trusting an answer about a different program. Reading a remembered result
  costs about two milliseconds. The measurement runs in the background so it
  never delays startup, and anything that needs an answer before it finishes
  simply proceeds as before.

  This affects the checking path, which decodes deliberately in order to prove
  that frames are not merely arriving but usable. Live viewing and recording
  pass video through without decoding it and are unchanged by design.

  `AIDOT_VIDEO_DECODER` forces a specific decoder and `AIDOT_DISABLE_HWACCEL`
  keeps to software decoding, for anyone who needs to override the choice.

## [0.15.0b2] - pre-release

### Fixed
- **A camera could show a permanent black picture while its stream was
  perfectly healthy.** The decoder is initialised from parameter sets cached
  from an earlier session, which is only safe while the camera keeps sending the
  same ones. One model does not: the cache described one set while the live
  stream had moved to another, so the decoder was initialised from a description
  that no longer matched and could not decode a single frame for the entire
  session.

  This was hard to recognise because nothing else looked wrong. The camera was
  connected, the stream was flowing at around 2 Mbps, and eleven megabytes
  arrived during a viewing that produced no picture at all.

  A camera whose parameter sets are seen to change is now remembered, and the
  cached copy is neither kept nor used for it again. Cameras that keep their
  parameter sets steady are unaffected. Nothing is lost by the change: the cache
  is only ever filled in from what the camera itself sends, so a camera it stops
  applying to is one that demonstrably sends what the decoder needs anyway.

## [0.15.0b1] - pre-release

This is a PRE-RELEASE. Live validation on real cameras passed for all three
gated models, but the terminal-ack fast-fail below only triggers when a camera
is at its viewer cap, and no camera refused during that run - so the headline
change is unproven against real firmware. `pip install` does not select
pre-releases, so this cannot reach an installation that did not ask for it.

### Added
- **The e2e "fake lab" test tier.** `tests/e2e/` drives the real client stack -
  real paho over websockets, real aiohttp, real ffmpeg - against a fake cloud, a
  fake MQTT broker, fake cameras and a go2rtc stub on 127.0.0.1. It covers what
  unit tests structurally cannot: signaling *order*, cross-component behaviour,
  terminal acks and multi-camera fleets. Run with `pytest tests/e2e -m e2e`;
  needs `amqtt`, `pytest-asyncio` and `pytest-timeout`.
- **Env seams for every cloud endpoint the camera layer contacts**
  (`AIDOT_API_BASE_TEMPLATE`, `AIDOT_SMARTHOME_URL_TEMPLATE`, `AIDOT_MQTT_URL`,
  `AIDOT_STUN_SERVERS`, `AIDOT_TURN_SERVERS`). Read at call time and defaulting
  to today's production URLs, so unset means byte-identical behaviour. These are
  what let the e2e tier run with no egress at all. Setting one to the empty
  string disables that category outright: with `AIDOT_STUN_SERVERS=""` no ICE
  server entry is advertised at all, rather than an entry naming no server, so
  only host candidates are gathered and a camera off the local network segment
  will not connect.
- **`SdesSession.media_stats()`** - `{packets, bytes, last_media_monotonic,
  video_pt, audio_pt}` counted by the bridge thread. The SDES path decodes
  nothing in-process, so `on_frame` never fires and there was previously no
  in-process proof media flowed. `scripts/live_validate.py` already looked for
  this method and silently never found it, leaving the release gate's SDES check
  resting on recorded bytes alone. Counted at every point the bridge forwards to
  ffmpeg, including the decrypted-PCMA audio path, so a camera whose audio
  arrives that way is not reported as carrying no media.

### Fixed
- **A camera at its viewer cap took ~26s to report it, instead of ~2s.** A
  terminal `webrtcResp` ack (-50002 max-streams / -50015 SD-cap) was recorded for
  both transports but only ever read by the DTLS path and by a single check
  *before* the SDES open began. The refusal lands about a second after
  `webrtcReq`, so the SDES path then waited out its pre-launch answer harvest and
  its answer budget, launched a bridge for a stream the camera had already
  declined, and only afterwards surfaced `AidotCameraBusy` - having also sent a
  pointless DTLS-fallback offer. The answer harvest, the answer wait and the
  first-media wait now all abandon the moment the refusal lands. Two of the three
  validated models take this path.
- **`tests/conftest.py` could not build a camera device client on the upstream
  shape Home Assistant pins.** The `make_camera_device_client` fixture imported
  `aidot.models.auth_model` directly - a module that exists only on the typed
  0.3.54-0.3.55 shape - so it raised `ModuleNotFoundError` on 0.3.56. It now
  resolves the account through `aidot_cameras._upstream` like the rest of the
  package.

## [0.14.0]

### Fixed
- **SDES cameras could serve nothing at all, indefinitely.** The ffmpeg SDP
  advertises both video codecs (`m=video ... 96 97`) because which one a camera
  sends varies per session, and it is narrowed to the observed payload type just
  before the serve launches. When no video packet arrived inside that window
  there was nothing to narrow on, so the dual-codec SDP went to ffmpeg unchanged
  - and that costs the picture twice over: ffmpeg binds its depacketizer to the
  first payload type and silently discards packets carrying the other, while the
  RTSP-push ANNOUNCE carries a parameterless H.265 stream that go2rtc rejects
  outright. No publisher attaches, so every viewer gets a 404, and the
  serve-restart path rebuilt the same unnarrowed SDP on each watchdog cycle - so
  a session that started badly stayed broken until the process restarted.

  The camera's answer SDP already names the codec it agreed to send, so that is
  now used when no packet has been observed - a negotiated fact rather than a
  guess. The payload type is translated to the one this package's own template
  writes for that codec (96 H.264 / 97 H.265), since the camera's numbering need
  not agree. An answer naming no codec we write leaves the SDP exactly as before.

  Measured against the reference fleet: the "narrowed ffmpeg SDP" status line was
  absent from every logged session, i.e. narrowing was never running.

### Added
- **BLE-mesh devices behind an AiDot mesh hub can now be controlled.** A mesh
  bulb has no address of its own; it is reached by talking to its hub
  (`type == "BleMesh_Hub"`) on the hub's local TCP:10000 channel and naming the
  child in the payload. That is the wire format `camera/lan_control.py` already
  speaks, so `ble_gateway.py` reuses its framing and changes only what the relay
  requires: the hub's socket/`aesKey`/`password`, `payload.parentId` set to the
  hub, and `payload.channel` `"ble"` instead of `"tcp"`.

  Session handling differs from the direct-to-device channel deliberately. That
  channel evicts an existing login whenever a second one arrives, so it is used
  one short session at a time; a hub instead multiplexes every bulb behind it,
  where connect-and-login per command is visible as slider lag. Hub sessions are
  therefore per-hub, lock-serialised, and closed after 5s idle - a brightness
  drag reuses one login, and an idle hub is released rather than held against
  the phone app.

  Mesh children never report state back, so an accepted command advances the
  status optimistically - but only after a `setDevAttrResp`, so a command the
  hub dropped cannot leave a state the device never reached.

  `is_ble_mesh_child()` requires mesh addressing (`bleMeshDeviceKey` /
  `bleMeshAddr`) in addition to a known hub id: a hub id alone also appears on
  Zigbee children and on records that merely share a house, and a mesh client
  built for one of those accepts commands and controls nothing.

  Not yet exercised against hardware - the reference account has a mesh hub but
  no mesh children paired to it.

## [0.13.2]

### Fixed
- **Mains cameras were classified as battery cameras.** Measured against the
  live cloud device list, every A000088 on the reference fleet reports
  `batteryMode: '2'` and no other battery field, while genuine battery models
  report it alongside real telemetry (`Battery_remaining`, `lowPowerStatus`,
  `charging`). `_battery_evidence` trusted the flag on its own, so four mains
  cameras were treated as battery: `powerType=2` went out on their wire payload,
  and a consumer keying its idle window on `is_battery_camera` handed them the
  battery window instead of the mains warm-hold.

  This is the same trap the code already guarded for `powerType` - whose
  neighbour `p2pCache` "reads 2 on every camera including mains ones" - so
  `batteryMode` now gets the same treatment: it counts as evidence only when at
  least one genuine battery field corroborates it. The flag is kept rather than
  dropped so a future battery model whose level field we have not seen is still
  caught, provided it reports any battery-only field.

  Detection remains one-directional: evidence can only ever ADD a camera to the
  battery set, never remove a known model from it, so no battery camera can lose
  its TURN pre-allocation, keep-alive renew or HTTP wake through this change.

## [0.13.1]

### Fixed
- **A battery camera in SDES push mode could never idle-release**, so its
  keepalive renewed forever against a camera nobody was watching. Observed live:
  a sleeping L2 still being renewed every ~100 s, each stream attempt dying at
  ~10 s, indefinitely.

  Neither half of the mechanism was wrong on its own. In push mode the "serve
  port" is go2rtc's *shared* RTSP port, where every camera's own publisher is
  connected, so a socket check there would report a viewer for every camera
  forever - `_viewer_present` rightly refuses it and answers "unknown", and
  `_idle_release_due` rightly never releases on unknown. The defect was what
  they composed into: a consumer that withholds `go2rtc_url` (to avoid a
  duplicate registration that re-points the stream mid-flight) removes the only
  viewer signal push mode has, making "unknown" the *only reachable* answer -
  at which point "never release on unknown" becomes unconditional.

  `start_keepalive(..., go2rtc_register=False)` is the way out: it keeps the
  go2rtc viewer query and skips the registration, so such a consumer can pass
  `go2rtc_url` without the duplicate-registration breakage. Default is `True`,
  so existing callers are unaffected.

  Also hardened the fallback while restructuring: the shared-port guard used to
  sit behind `if not go2rtc_url`, so configuring go2rtc and having the *query*
  fail fell straight through to the socket check that push mode cannot use. It
  is now gated on push mode itself and answers "unknown" in that case too.

  And `_deregister_go2rtc` now only removes a registration this client created.
  It gated on `go2rtc_url` alone, which was unreachable for a consumer that
  withheld the URL - so simply passing the URL for queries would have made it
  reachable and started deleting the consumer's own stream on every stop and
  idle-release, tearing down the thing it serves from.

## [0.13.0]

### Changed
- **Both live shapes of upstream `python-aidot` are now supported, and the pin
  became a range (`>=0.3.55,<0.4`).** Upstream refactored its account/device API
  to typed dataclasses in 0.3.54/0.3.55 and then **reverted** that refactor in
  0.3.56, five days later - so "newer" does not mean "further along", and the
  shape this package was written against is the one upstream abandoned. Home
  Assistant core pins `python-aidot==0.3.56` in its own `aidot` integration, so
  an exact pin here on any other version is unsatisfiable alongside it.

  Every difference is resolved in a single new module, `aidot_cameras/_upstream.py`,
  which detects the shape **by capability** (does the name import?) rather than
  by version string - upstream shipped the dict shape under both 0.3.53 and
  0.3.56, so a version comparison would encode the five-day excursion instead of
  the shape. No other module branches on the upstream version.

  What moved, renamed or vanished between the two: `DeviceModel` ->
  `DeviceInformation`; `aidot.utils.crypto` -> `aidot.aes_utils`;
  `API_URL_TEMPLATE`/`APP_ID`/`DEFAULT_REGION`/`PUBLIC_KEY_PEM` -> `aidot.login_const`;
  `CloudApi` folded into `AidotClient` as `async_get_*`; `UserInformation`,
  `DeviceState`, `AsyncTimer`, `_on_token_refreshed` and `DeviceClient.read_data`
  deleted outright; `DeviceClient.__init__` switched from typed models to raw
  dicts; `Discover` from a static class to an instance one.

### Fixed
- **The account-shared `login_info` dict could be swapped out mid-session.**
  Upstream's dict shape assigns `self.login_info = response_data` inside
  `async_post_login`, which lands while cameras already hold a reference to the
  shared dict. Rebinding there would have left the persistent-MQTT connection,
  its `asyncio.Lock` and `mqttClientId` attached to a dict nothing reads any
  more, and the next camera command would have opened a SECOND broker connection
  - which the broker answers by dropping the first, since it allows one per
  account. The `login_info` setter now updates in place, so the object identity
  is stable for the life of the client on either shape. The MQTT password is
  deliberately *not* carried across such an assignment: it rotates on every
  login, and preferring a stale copy is the confirmed-live rc=134 failure.
- **The close-time reconnect-leak fix would have gone silent on 0.3.56.** It
  cancelled `device_client._reconnect_timer` via an unguarded `getattr`, and
  upstream renamed that handle to `_reconnect_handle`; the `getattr` would have
  found nothing, cancelled nothing, and reported success. It now goes through
  `_upstream.cancel_pending_reconnect`, which returns False when it finds no
  handle, and the regression test arms the handle under whichever name the
  installed shape uses instead of hardcoding one.
- **A stored config entry could fail to load outright after an upstream bump.**
  The dict shape indexes four keys off a stored token directly
  (`token[CONF_USERNAME]` and friends) where the typed shape tolerated a partial
  dict via `update_from_json`, so an entry written under one and read back under
  the other raised `KeyError` inside upstream's constructor and the account never
  loaded. Missing keys are now filled with survivable defaults and corrected on
  the next successful login.

## [0.12.17]

### Fixed
- **SDES cameras negotiated a session and then delivered nothing.** Every
  A001513 and A001064 was affected, on released 0.12.16 and across two accounts;
  DTLS (A000088) was untouched, which is why half the fleet looked healthy and
  this stayed hidden. The harvest that reads the camera's `webrtcResp` gave the
  answer a single event-loop cycle and took it only if it had already resolved -
  but the STUN window ahead of it closes on a fixed schedule about 2.4 s BEFORE
  the answer lands (`webrtcReq` -> answer = 2.9 s measured on an A001513). The
  answer SDP was therefore always empty, and everything downstream behaved as
  though the camera had never replied: no ICE credentials, so no
  `USE-CANDIDATE`, so a **controlled** ICE agent that sits in "Checking" forever
  and never sends SRTP, and no camera SRTP keys for the bridge either. The 75 s
  first-media wait had nothing to wait for. The path now waits for the answer -
  bounded by `_PRE_LAUNCH_ANSWER_WAIT_S`, and `asyncio.shield`ed so a timeout
  cannot cancel the future the real answer await and the DTLS-fallback path
  still consume - and nominates from the answer during the first-media wait as a
  bounded fallback. Raising `_FIRST_MEDIA_WAIT_S` never helped and never could:
  that wait was tracking itself, not the camera.

  Measured on an A001513 battery camera: NO_MEDIA / 80 s / 0 bytes before, **PASS
  on the first attempt, 7.9 s, 2646 packets / 2.9 MB** after, decoding as h264
  1280x960 with `video_pt=96 audio_pt=8`. A001064 PTZ NO_MEDIA before, **PASS
  16.7 s / 2.5 MB** after.

- **The TURN relay was allocated and advertised as a candidate, but never
  used.** Three separate gaps, each of which alone makes the relay unusable as a
  fallback for a camera that cannot be reached directly. A permission was
  installed only for the candidate in the answer SDP, which is the camera's
  private host address; a TURN permission is matched against the peer's source
  address *as the relay sees it* (RFC 5766 s9), so that authorises an address
  that can never arrive. Permissions now cover every candidate, including the
  srflx and relay addresses that only appear via `iceCandidateReq` trickle, and
  are refreshed inside the permission lifetime - and two of the three allocation
  paths stored a 7-field tuple where the helper requires 8, so on those paths
  the permission was silently never sent at all. Nothing was ever *sent* through
  the allocation either: the Send indication was emitted only while handling
  data that had already arrived through the relay, which cannot bootstrap, and
  since ICE validates a candidate *pair*, a camera that only ever saw checks
  leaving from our host socket never nominated the relay candidate we
  advertised. Connectivity checks now also go out through the allocation, and
  the bridge wraps its replies when the peer reached us relayed. Finally the
  allocation itself was never refreshed, and this TURN server grants 600 s and
  drops it silently on expiry, so a held session lost its relay mid-stream.

  Measured on an A001513 before the send-side change: CreatePermission confirmed
  by the server for the camera's host, srflx and relay addresses, and still zero
  relay-carried inbound packets, because nothing we sent ever left from the
  relay.

- **L2 / battery cameras that stream from a standalone run but never under Home
  Assistant.** The same library code took two different paths because the
  battery-hostile knobs were reachable from a consumer's settings, and a
  standalone run never sets them. Three of those knobs are now decided by the
  library instead of by the caller:
  - **The `liveStreamParam` KVS pre-connect can no longer be turned back on.** It
    provisions the camera's session toward AWS KVS, so the camera sends its media
    there instead of to the SDES bridge: the session negotiates, the bridge binds,
    and no video RTP ever arrives. It is made for **battery cameras only** - i.e.
    exactly the cameras it breaks - and the `-50019` ("not ready") livePlayResp it
    was added to cure is benign (mains cameras emit it too and recover via ICE).
    0.12.15 turned it off by default but left the option/env able to re-enable it,
    which is a foot-gun aimed at one foot: a consumer that surfaces it as a
    setting (Home Assistant surfaces these because HA OS cannot set env vars)
    re-breaks every battery camera on the account, and "negotiates, then shows
    nothing, forever" looks nothing like a settings problem. The decision now
    lives in one place and is "no". `AIDOT_LIVESTREAM_PARAM` and
    `start_keepalive(live_stream_param=...)` are accepted and ignored, logging one
    warning per camera so a stuck install says why in the log.
  - **Adaptive fast-connect is refused for battery cameras.** The saving it chases
    is the TURN relay pre-allocation, which is force-kept for a battery camera
    (its only return path), and fast-liveplay is already on by default - so a
    battery "fast" attempt runs the identical handshake and differs only in being
    given 45 s to open and a 40 s media grace, *inside* the documented 25-70 s
    battery cold-start window. A slow-but-healthy wake was scored as a fast-path
    failure: it latched `_fast_path_unavailable`, escalated the backoff, and burnt
    a camera-side session on a device that frees them slowly.
  - **Battery cameras are detected from their own cloud data, not just a model
    list.** `is_battery_camera` now also resolves from a numeric
    `Battery_remaining` (the signal `lan_control.is_mains_powered` inverts) or
    `batteryMode == 2`, falling back to the model list when the cloud says
    nothing. Every battery protection hangs off this one property - the TURN relay
    pre-allocation, the cloud keep-alive renew, the HTTP wake, the adaptive
    refusal above, `powerType=2` - so an unlisted battery revision lost all of
    them at once, and lost them *only* under a consumer that sets the LAN-direct
    options. Evidence can only add a camera to the battery set, never remove a
    listed one, so mains cameras keep their optimizations. `powerType` is
    deliberately not read as evidence (it is a field we send, and its neighbour
    `p2pCache` reads 2 on every camera).
- **Model ids are matched consistently by substring.** The plain-RTP (TUTK-framed)
  set was compared for exact equality, so a revision suffix - `LK.IPC.A001513-1`,
  the way `A000088-1` already exists on the DTLS side - read as a standard-SRTP
  camera: ffmpeg then tried to decrypt TUTK frames with the announced fake key and
  the bridge never stripped the TUTK header, giving a session that negotiates and
  delivers nothing decodable. The battery-model list and the `powerType` wire value
  were also re-typed inline in three files; both now derive from one definition, so
  a guard cannot drift out of step with the payload the camera is sent.

- **A waking battery camera gets a fast retry instead of an escalating backoff**
  (the follow-up left open in 0.12.16: "a rapid third consecutive session can
  still hit `-50019` (battery wake-readiness)"). The camera answers `livePlayResp`
  with `-50019` and then sends no media - it was not refusing, it had not finished
  waking - and the SDES keepalive loop could not tell that apart from a degraded
  camera, so the pacer escalated (10 s -> 300 s) on a camera that would have been
  ready seconds later. Under a consumer that re-opens per view (HA idle-releases
  after 120 s), that is the difference between a slow first frame and a live view
  that never fills in.

  The wake signal was also being **discarded**: `sdes_fast_liveplay` is on by
  default and skips the `livePlayResp` wait, so on the SDES path - the only path
  battery cameras use - nothing ever read the code. It is now recorded whenever it
  arrives, whether or not anything is waiting for it.

  The retry reuses the DTLS serve loop's `_retry_policy`, bounded to the peerid
  reuse window so the whole burst re-offers on **one** peerid (a fresh peerid
  registers another camera-side session - the 0.12.16 wedge), then hands back to
  the normal pacer. Scoped to battery cameras: on a mains camera `-50019` is
  transient noise and a no-media session really is degraded. `-50019` still never
  aborts an open - it is benign on its own, per 0.12.15; only the retry *delay*
  keys on it, and only after a session has already failed to deliver media.

  **Validated on hardware** (A001513 under Home Assistant): the camera answers
  `-50019` and the loop now logs `camera not ready (waking, livePlayResp -50019)
  and sent no media - fast retry in 3s [1/3]` and re-offers on the same peerid,
  where before the signal was discarded entirely and the pacer escalated. The
  retry behaves as designed and is bounded.

  It does **not** by itself make that camera's live view fill in: on the fleet it
  was measured against, the camera answers `-50019` and sends no media on every
  attempt of the burst. The remaining cause is upstream of this retry and of
  every knob in this release - the open profile resolves correctly for that
  camera (`battery=True (cloud-reported=True) powerType=2 turn-prealloc=kept
  adaptive=False`), and the identical library and configuration streams the same
  camera from a different host on the same subnet. See
  `tests/test_wake_readiness_retry.py`.

### Notes
- The L2 / battery hardening in this release was measured against a live A001513
  under Home Assistant. The open profile confirms every decision now resolves
  correctly for it (`battery=True (cloud-reported=True) powerType=2
  turn-prealloc=kept adaptive=False`), and a mains SDES camera on the same fleet
  still reports `battery=False powerType=1 turn-prealloc=skipped` - so the
  battery detection change does not misclassify mains cameras or alter the
  `powerType` they are sent. The battery live view that still did not fill in
  when that work was written was **not** a host or network difference, as was
  assumed at the time - it was the SDES answer harvest above, which stopped
  every SDES camera on every host from ever being nominated. With that fixed the
  same A001513 streams in 7.9 s.
- **Battery streaming is not universally fixed.** On the reference fleet one
  A001513 passes in 7.9 s while a second unit of the same model still returns no
  media, handshaking for ~110 s and absent from `arp-scan` throughout: it is
  genuinely asleep rather than mis-negotiating, and nothing in this release
  wakes a camera that will not wake. That is the remaining battery problem, now
  cleanly isolated from the SDES bug that was masking it.

### Added
- **A one-line open profile per camera, at INFO.** Names the decisions that
  determine whether media can arrive at all - model, transport, battery (and
  whether the cloud reported it), `powerType`, whether the TURN pre-allocation was
  kept or skipped, adaptive on/off. This whole failure class (a session that
  negotiates and then delivers nothing) is usually one of these resolving the
  wrong way, and it was otherwise invisible: the handshake logs look identical
  either way. At INFO so a bug report carries it without having to re-enable DEBUG
  and reproduce.

### Changed
- `tests/test_live_stream_param.py`'s regression lock now calls the **real**
  resolver. It previously re-implemented the gate as a local helper and asserted
  against that copy, so the shipped gate was uncovered and the copy was free to
  drift from it - a flag that must stay off was "locked" by a test that could not
  see it.

## [0.12.16]

### Fixed
- **SDES cameras: honour the camera's own "no free session" refusal.** A terminal
  webrtcResp ack (`-50002` max concurrent streams / `-50015`) was recorded for
  both transports but only ever acted on by the DTLS path. On the SDES path the
  camera saying "full" looked like a generic failure, so the keepalive loop
  retried on the short backoff - and every retry minted a new peerid, i.e. yet
  another camera-side session - which is self-sustaining and can wedge a battery
  camera. The SDES branch now raises `AidotCameraBusy` on a terminal ack and the
  SDES keepalive loop backs off for the full release window, matching the DTLS
  loops.
- **SDES keepalive reuses one peerid across its retries** instead of minting a
  fresh one per attempt. A fresh peerid registers a new camera-side session and
  the camera frees old ones only slowly, so mint-per-retry stacks up sessions on
  a failing loop faster than they drain. The loop now holds one peerid across
  retries (mirroring the official app, which resends within one session) and
  rotates to a fresh one only after a session that delivered media or after a
  small reuse cap. The DTLS/mains path is unchanged (different loop; the new
  `reuse_peer_id` kwarg defaults to None).

Measured on an A001513 (L2): two back-to-back live sessions now both stream
h264 1280x960 + PCMA where previously the second in a row failed.

## [0.12.15]

### Fixed
- **A001513 "L2" battery cameras serve live video again.** The `liveStreamParam`
  pre-connect - an AWS-KVS provisioning call made only for battery cameras -
  provisions the camera's session toward KVS, and its media then goes there
  instead of to the SDES bridge: the session negotiates, the bridge binds, and
  no video RTP ever arrives. It was added to cure a `-50019` ("not ready")
  livePlayResp, but `-50019` is benign - mains cameras emit it too and recover
  via ICE - so it addressed a non-bug at the cost of the battery live view. The
  pre-connect is now **off by default**; re-enable it per camera with
  `start_keepalive(live_stream_param=True)` or `AIDOT_LIVESTREAM_PARAM=1`.
  Measured on an A001513: h264 1280x960 + PCMA, stable across a 180 s probe
  series, where before there was no media at all.
- **Battery cameras no longer skip the TURN relay pre-allocation.** A battery
  camera sleeps, is woken through the cloud, and has no LAN IP, so its media
  returns over the relay. The LAN-direct optimization (`sdes_skip_turn` /
  `AIDOT_SDES_SKIP_TURN_PREALLOC`, which Home Assistant's "LAN-direct"
  connection mode enables) would leave it with no return path. Mains SDES
  cameras still honour the option.
- **SDP payload narrowing works for every payload list.** It replaced the
  literal `" 96 97"`, so it silently stopped narrowing once the plain-RTP video
  line grew a third payload (98, the second H.265 variant). It now rewrites
  whatever list the m-line carries and drops the other codecs' `rtpmap`/`fmtp`.
- **An RTSP push no longer dies when audio is unusable.** Push copies every
  input stream, so an audio line that could not be narrowed (its payload type
  was never observed) made the ANNOUNCE fail with `400 Bad Request` and took the
  whole publish down. Push now maps video only in that case, and the serve
  command is built once - after the first-media wait resolves the real payload
  types - so both the narrowing and the push decision see the observed codecs.

## [0.12.14]

### Fixed
- **DTLS cameras serve live video again.** The serve-wait loop's viewer-check
  block ended in an unconditional `break`, so any positive idle window
  (`stream_idle_s` / `AIDOT_STREAM_IDLE_S` > 0) tore down a HEALTHY ffmpeg after
  a single 0.5 s tick and respawned it forever - ffmpeg died at output-open with
  "Immediate exit requested", go2rtc saw 404s or no data, and every DTLS camera
  went dark. `stream_idle_s=0` skips the block entirely, which is why
  never-release configurations kept working and hid the bug. The break now fires
  only on an actual idle release.
- **The A/V mux no longer lets missing audio hold video hostage.** The mux
  declares an AAC stream up front; when no audio packets arrive, libavformat's
  interleave queue (10 s of stream time by default) buffered EVERY video packet,
  so the serve ffmpeg starved at its input probe and never bound its `-listen`
  port. The muxer now runs with `max_interleave_delta=100ms`, so video flows
  whether or not audio ever shows up.
- **A dead serve pipe now ends its mux thread instead of starving the next one.**
  FFmpeg's mpegts muxer surfaces custom-IO write errors lazily (at trailer
  time), so muxing into a dead pipe appeared to succeed forever. A mux thread
  abandoned by the teardown's 2 s join then drained the SHARED packet queues
  into EPIPE, starving the replacement serve (observed live: 17 leaked threads
  per camera). A write failure recorded at the file-object layer now ends the
  thread within one iteration, and the raw pipe is closed before the container
  so the trailer flush fails fast instead of hanging.

## [0.12.13]

### Fixed
- **A dormant camera no longer leaves a dead stream in go2rtc.** Idle-release
  stopped the serve but left the stream registered, pointing at a source that no
  longer existed - so a viewer attaching while the camera slept got a hard
  `connection refused` on the serve port instead of a clean miss. In PUSH mode
  that source was never dialable at all, because the keepalive publishes INTO
  go2rtc rather than serving over HTTP. Both release paths now deregister, and a
  failure to do so cannot break going dormant.
- **A consumer disconnecting is no longer reported as a failure.** ffmpeg returns
  `AVERROR(EPIPE)` = -32 when its output consumer goes away, and a process exit
  status is an unsigned byte, so it surfaces as **224**. That is the normal end of
  a `-listen 1` serve - go2rtc disconnects and ffmpeg exits - but it was logged at
  WARNING every time, which trains the reader to ignore the log. Real failures
  still warn.

## [0.12.12]

### Fixed
- **No video at all, caused by 0.12.10's own viewer check.** The DTLS watchdog
  loops twice a second, and the viewer check added in 0.12.10 sat inside it -
  opening a fresh HTTP session to go2rtc on every tick. That is two requests per
  second per camera, aimed at the very service that also has to serve the video;
  on a small fleet it was enough to stop go2rtc answering at all, so every camera
  went black while the integration still reported them as streaming.

  The answer is now cached for 10s, so the watchdogs can ask on every tick and
  go2rtc is asked at most once per camera per interval. Idle release is measured
  in minutes, so seconds of staleness cost nothing.

## [0.12.11]

### Fixed
- **A go2rtc stream could be registered as its own source.** In push mode the
  keepalive publishes INTO go2rtc, so `_keepalive_rtsp_url` is go2rtc's own
  address for that stream - and registering it as the stream's source made go2rtc
  its own producer. The stream then lists a producer, nothing feeds it, and every
  consumer gets a connection with no media. Observed live: a camera with two
  producers, one of them its own `rtsp://127.0.0.1:8554/aidot_<id>`, answering
  HTTP 200 with a zero-byte frame. Registration is now skipped when it would
  loop - in push mode the publisher already feeds the stream, so there is nothing
  to register.

  Only reachable by a consumer that passes `go2rtc_url` to `start_keepalive`,
  which the Home Assistant integration began doing in 2.9.8 so the viewer-aware
  idle check could work. Anyone on that combination should take this.

## [0.12.10]

### Fixed
- **The DTLS cameras never released either - 0.12.9 only fixed half of it.** The
  DTLS serve loop decided idleness from pipe-progress staleness, which is the same
  unanswerable question in disguise: the pipe only backs up when nothing drains
  the serve socket, and go2rtc drains it forever as the producer. On a fleet that
  is mostly DTLS cameras the 0.12.9 fix therefore changed nothing. Both loops now
  ask who is watching, and both keep the old heuristic as a fallback when nobody
  can answer.
- **The idle check lied in push mode.** With an RTSP push URL the "serve port" is
  go2rtc's *shared* 8554, where every camera's own publisher is connected - so the
  socket check reported a viewer for every camera, forever. It now answers
  "unknown" there instead of a confident wrong "yes".
- **The SRTP key-restart undid two shipped fixes.** It rebuilds the ffmpeg SDP from
  scratch and (a) wrote `RTP/SAVP` with `a=crypto` for models where the bridge
  forwards PLAIN RTP - making ffmpeg fail authentication on every already-decrypted
  packet, so a working stream dropped to zero bytes mid-session - and (b) discarded
  the payload-type narrowing, so an H.265 camera lost all video and with it the
  PAT/PMT and the entire output. The restart now matches the primary SDP on both.
- **A failed stream slot could be lost permanently.** The serve relay was started
  outside the `try` that releases the slot; `Thread.start()` raises `RuntimeError`
  under thread exhaustion, which escaped before the `try` and burned a permit for
  the life of the process, silently shrinking the cap until nothing could stream.
- **Teardown could skip itself.** `join()` on a thread that never started raises,
  replacing the real exception and skipping the ffmpeg terminate and session stop
  that follow - orphaning ffmpeg on its serve port.
- **Background tasks leaked on every failed handshake.** Only a successful session
  cancelled them, so each failed open left an immortal 10s-tick AVIO heartbeat task
  pinning a closed peer-connection graph. A camera that fails repeatedly grew them
  without bound.
- **The cold-start wait was inside the window it waits for.** 45s sat within the
  documented 25-70s battery cold start, so a camera at the slow end still launched
  with no payload types known. Now 75s.

## [0.12.9]

### Fixed
- **Every camera streamed forever after a single view.** The idle-release check
  asked "is a TCP client connected to the serve port?" - but go2rtc attaches to
  that port as the stream's PRODUCER and stays attached for as long as the stream
  is registered, viewer or no viewer. So a peer was always present, the idle
  window never elapsed, and nothing ever went dormant: open one camera and all of
  them keep decrypting indefinitely, holding a concurrency slot each and draining
  battery models. Measured live: five cameras, nobody watching, still producing
  after 7 minutes against a 5 minute idle window.

  Presence is now asked of go2rtc, which is the only component that knows whether
  anyone is actually watching (`consumers`), falling back to the socket check when
  go2rtc is not in use. Unknown still means "do not release", so a host that can
  answer neither keeps today's behaviour.

## [0.12.8]

### Fixed
- **A camera beyond the concurrency cap never streamed at all.** The cap on
  concurrently-active serves (`AIDOT_MAX_CONCURRENT_STREAMS`, default 3) is a
  host-protection guard, but a camera holds its slot for the life of its serve -
  so on an account with more cameras than the cap, the extras did not queue
  politely, they simply never played, and nothing surfaced an error. Confirmed
  live on a fleet with 4 DTLS cameras: the library logged
  `waiting for a stream slot (cap reached)` for the fourth on every attempt, and
  that was exactly the camera that would not play in Home Assistant.

### Added
- `configure_stream_limits(max_streams)`, exported from the package, so a consumer
  that knows its camera count can raise the cap to fit. The cap only ever grows -
  shrinking would strand a camera already holding a slot - and an explicit
  `AIDOT_MAX_CONCURRENT_STREAMS` still wins, since an operator who capped a small
  host would rather cameras took turns than have the host fall over.

## [0.12.7]

### Fixed
- **Camera audio is now reliably present, not a coin flip.** 0.12.6 narrowed the
  audio payload type but could only do so if the payload type was known before the
  serve launched, which made audio intermittent. Measuring when media actually
  arrives showed the assumption behind that was wrong: audio is not late. Video and
  audio payload types arrive **40-70 ms apart** (the camera answers BUNDLE, so both
  share one 5-tuple) - what failed was that a cold session's media does not start
  for ~21 s, and the launch was gated on a 15 s deadline. It expired first, so the
  serve launched with *both* payload types unknown and the audio line kept
  advertising PCMU on a PCMA camera.

  The launch now waits for the session's first media (sized to the documented
  25-70 s cold-start window) rather than to a deadline shorter than the camera's own
  startup, and the audio grace on top is **tightened from 4 s to 1 s**, since it
  only has to absorb 40-70 ms of jitter. Waiting for first media costs no picture
  latency - ffmpeg cannot produce before media exists, and launching earlier only
  binds the wrong depacketizers.

  Verified live: launch decision at +1.72 s with both payload types known, and a
  capture of 1032192 bytes carrying an `h264 1280x960` track and an `aac` track.

## [0.12.6]

### Fixed
- **Camera audio works again, and can no longer cost the video.** Root cause: the
  SDP handed to ffmpeg advertises two payload types per media line
  (`m=video ... 96 97` for H.264/H.265, `m=audio ... 0 8` for PCMU/PCMA) because
  the camera picks one per session. ffmpeg binds each depacketizer to the FIRST
  payload type listed and silently discards the rest. The bridge synthesises PCMA
  (pt 8) while the audio line offers PCMU (pt 0) first, so every audio packet was
  discarded - and because the mpegts mux withholds its PAT/PMT until every mapped
  stream has produced a packet, the consumer received ZERO bytes, losing the video
  along with the audio. That is why enabling audio looked like it broke streaming.

  The existing H.265 fix already narrows the video line this way and was never
  applied to audio; on the TUTK-framed path the video payload type was not
  recorded either, so neither line was being narrowed there. Both payload types
  are now recorded and both lines narrowed, and the narrowing is a tested pure
  function rather than a nested closure.
- **Audio can never take the picture down again.** If the audio payload type
  cannot be characterised before the serve launches, the serve starts video-only
  with a warning instead of mapping a stream that would stall the mux. Verified
  live: with audio enabled the served mpegts now carries an H.264 1280x960 track
  AND an AAC track where it previously delivered nothing - 1.2 MB in a single
  capture, more than the 843 KB the video-only path managed - and on a session
  where no audio arrived in time it served 557 KB of video-only rather than zero.
- **Audio is on by default again**, since it can no longer cost the picture. The
  0.12.5 warning that enabling it would serve no video is removed, being no longer
  true.

### Known limitation
- **Audio is present only when the camera sends some before the serve launches.**
  It gets a short grace on top of the video payload-type wait, deliberately short
  so a camera that never sends audio does not delay the picture. A session that
  misses that window serves video-only until the next ffmpeg restart re-runs the
  wait. Measured across runs on one battery camera: some sessions carried both
  tracks (1.2 MB in a capture), others video-only (282 KB). Making this
  deterministic needs the serve to be upgraded in place once the payload type
  becomes known, which is not in this release.

## [0.12.5]

### Changed
- **Enabling serve audio now says what it costs.** 0.12.4 made audio opt-in
  because mapping it serves no video on these cameras; opting in was still a
  silent trap. The serve now logs a warning naming the symptom and how to turn it
  back off. No behaviour change - and deliberately not a fix: skipping the audio
  mapping when no audio is observed does not help, because sessions that DO
  observe audio fail the same way. The cause is not yet isolated, so the honest
  move is to warn rather than to ship a fix that does not.

## [0.12.4]

### Fixed
- **Camera audio no longer costs the video.** The mpegts mux writes its PAT/PMT
  only once every mapped stream has produced a packet, and `amix` does not emit
  until every one of its inputs has delivered a frame. On a camera that sends no
  PCMA, the AAC encoder therefore never produced, the PMT was never written, and a
  consumer got an accepted connection followed by zero bytes - no video at all,
  even though signaling was healthy and the library had logged first media. The
  continuous silence base was meant to prevent exactly this and does not. Measured
  live on a battery camera: with audio on, 0 bytes across 45 consecutive attach
  attempts; with audio off, 303 KB of 1280x960 H.264 from the same session.
  Serve audio is now opt-in (`sdes_audio` per camera, or
  `AIDOT_SDES_SERVE_AUDIO=1`), because missing audio is a worse experience while
  no video is a broken integration.

## [0.12.3]

### Fixed
- **Live video survives a restart again.** The MQTT password is a rotating cache,
  not account state: the broker issues a new one on every account login and
  allows a single connection, so a stored copy is stale the moment anything else
  logs in (the phone app is enough). It was nonetheless persisted with the rest
  of `login_info`, so a dead credential was reloaded from disk on every start and
  the broker refused it forever (`rc=134`) - which killed WebRTC signaling, and
  therefore live video, while snapshots kept working. It is now runtime-only.
- **A missing MQTT password is fetched on demand, not only at login.** Making the
  password runtime-only exposed the other half of the bug: the fetch had a single
  caller, the full login, and a restart from a stored token never reaches it (the
  proactive refresh takes the refresh-token path). Cameras now request one
  whenever it is absent, coalescing concurrent callers into a single request, with
  a floor between attempts after a refusal. Without it the credential resolver
  fell through to its last resort - the access token as an MQTT password - which
  the broker rejects, so the failure looked like working code.
- **A credential refusal now heals the whole account, not one camera.** The cached
  credential is per device client while the credential itself is per account, so
  a refusal on one camera left every sibling holding the dead password and each
  one burned its own refusal in turn. The account-shared value is now the single
  source of truth, and a cache derived from it is treated as stale once it is
  gone.
- **A refused MQTT client is shut down instead of retrying forever.** It was only
  dropped from the account cache; paho's own retry loop kept re-offering the
  rejected password to the broker for the life of the process, silently, because
  the refusal is reported once. Retiring it also releases callers that would
  otherwise wait out a full timeout on a connection that could never open.
- **The MQTT password no longer reaches storage inside the raw userConfig blob.**
  That response is kept in `login_info` for its client id and is persisted; the
  credential is now stripped out of it.
- **A broker refusal also clears the cached server URL**, so the one response that
  can carry a server-issued password is re-read on the recovery path instead of
  being skipped.

### Added
- `DeviceState` is re-exported from `aidot_cameras.device_client`, so a consumer
  can tell whether a device client's LAN session is authenticated without
  importing `aidot` directly - which for consumers is an undeclared dependency.

## [0.12.2]

### Fixed
- **A rotated MQTT password no longer breaks camera signaling permanently.** The
  broker issues a new MQTT password on every account login and allows one
  connection at a time, so anything else logging in (the phone app is enough)
  invalidates the cached one. The cached copy lives in `login_info`, where it
  short-circuits the credential fetch, so every reconnect reused the dead
  password and the broker refused it forever (`rc=134`) - which silently killed
  WebRTC signaling and therefore live video, while snapshots kept working. A
  credential refusal now clears the cached password and drops the persistent
  client so the next use fetches a fresh one.
- **go2rtc stream registrations no longer leak.** go2rtc answers the register
  call with 400 when it cannot immediately validate the source (a camera that
  has not started producing yet) but still keeps the stream registered. That was
  treated as failure, leaving the pull URL unset - and deregistration was gated
  on that URL, so every such attempt left a dead stream behind with a producer
  nothing was feeding.

## [0.12.1]

### Changed
- **Devices this library cannot build a client for are summarized, not warned
  about individually.** An account with Zigbee sub-devices, remotes or other
  accessories that carry no usable `aesKey` logged one WARNING per device on
  every device-list refresh (21 of them on a real account) for devices that were
  never supported here. Each is now DEBUG, with a single INFO line naming the
  models and counts.

### Documented
- **`docs/UPSTREAM.md` now records that upstream is LAN-only by design**: its
  cloud API is inventory plus auth with no control endpoint, and every setter
  refuses unless the LAN session is authenticated. Includes the read-only broker
  probe evidence showing the cloud carries no bulb state, so consumers do not
  mistake cloud reachability for controllability.

## [0.12.0]

### Changed

- **BREAKING: this package now extends upstream `python-aidot` instead of forking
  it, and its import name is `aidot_cameras`.** Upstream ships as a pinned
  dependency (`python-aidot==0.3.55`) and owns the `aidot` import name again; no
  upstream file is vendored or edited here. Code that imported `aidot` /
  `aidot.camera` from this distribution must import `aidot_cameras` /
  `aidot_cameras.camera` instead. The camera API itself is unchanged.
- **Non-camera devices are handled entirely by upstream.**
  `AidotClient.get_device_client()` is the single dispatch seam: cameras get this
  package's client, and lights, plugs and switches fall through to upstream's own
  `DeviceClient` with none of this package's code in their call graph.
- **Taking a new upstream release is now a dependency bump plus a test run**,
  not a merge. `tests/test_upstream_compat.py` is a seam contract that fails fast
  and names the exact upstream symbol if a release moves something this package
  builds on. See `docs/UPSTREAM.md`.
- The RGBW+CCT `active_color_mode` fix is carried as a narrow, marked override
  applied only to those bulbs while
  `AiDot-Development-Team/python-AiDot#6` is open; it is removed once that merges,
  after which those bulbs also run pure upstream code.

## [0.11.14]

### Fixed
- **RGBW+CCT bulbs no longer report a stale color while resting in white/CCT
  mode.** These bulbs report state as deltas - a color-temperature change carries
  only CCT, a color change carries only RGBW - but the login-sync (getDevAttr)
  returns both the retained RGBW register and CCT together, which is ambiguous.
  The device status now records the active color mode from unambiguous
  single-field deltas and leaves it unchanged on the ambiguous both-present sync,
  so a bulb set to a color temperature is no longer surfaced as its last RGB
  color. Exposed as `DeviceStatusData.active_color_mode` for the Home Assistant
  integration to map to color_temp vs rgbw.

## [0.11.13]

### Fixed
- **The SDES bridge no longer breaks its own stream during a key-restart.** When
  a camera's answer SRTP key differs from the offered key, the SDES ffmpeg bridge
  restarts ffmpeg. The bridge's process-observe loop could see the OLD
  (terminated) process exit during the restart window and break - tearing down
  the bridge, closing the loopback sockets, and starving the freshly restarted
  ffmpeg, which turned a fast key-restart into a 40-60s reconnect and a visible
  stream break. The observe loop now consults the teardown flag (added in
  0.11.12) and does not break on an expected local teardown; it resumes once the
  new process is live, and still breaks promptly on a genuine ffmpeg crash.

### Changed
- **The DTLS serve-open timeout is now tunable.** The per-attempt WebRTC open
  timeout for a served DTLS camera was hard-pinned at 30 s. It is now
  configurable via `AIDOT_DTLS_SERVE_OPEN_TIMEOUT_S` (default 30 at the time;
  raised to 75 in a later release, see below), so
  operators can fail faster on a known-dead camera. A malformed value falls back
  to the default.

## [0.11.12]

### Fixed
- **An idle DTLS camera no longer floods the log or burns CPU.** A DTLS camera
  (model IPC.A000088) that the cloud still reports online but that never answers
  WebRTC was retried indefinitely; each attempt drove the vendored H.264 decoder
  over corrupt frames, emitting one "H264Decoder() failed to decode" WARNING per
  frame (172 in one 11-minute capture) plus a steady stream of `aioice.ice` INFO.
  The serve path no longer feeds that decoder at all - the served H.264 already
  comes from a pre-decode tap and is muxed as a copy, so the decode was pure
  discarded work - and a lightweight keyframe/gap canary at DEBUG replaces it for
  link-health visibility.
- **`aioice.ice` / `aioice.turn` are capped at WARNING instead of INFO.** The
  prior INFO cap could not suppress the flood, which is itself INFO-level ICE
  connectivity-check state transitions; aioice emits nothing at WARNING or above,
  so the flood is silenced with no loss of a real warning. Set the logger level
  explicitly to restore ICE INFO for debugging (the NOTSET-guarded cap respects
  it).
- **The vendored H.264 decode-failure WARNING is rate-limited.** On the live-view
  path, where decode still runs, a corrupt stream no longer emits one WARNING per
  frame; the first passes through and subsequent failures collapse into a
  periodic summary carrying the suppressed count.
- **Expected ffmpeg teardown no longer logs a spurious WARNING.** A
  locally-initiated SDES bridge teardown SIGKILLs an ffmpeg that will not exit on
  a dead UDP input; that signal death (-9) is now logged at DEBUG when it follows
  a local teardown, while genuinely unexpected exits stay at WARNING.

### Changed
- **Retries for a persistently-unreachable idle DTLS camera now back off
  further.** After a threshold of consecutive failed opens (default 5,
  `AIDOT_DTLS_SLOW_PROBE_THRESHOLD`) the retry cadence widens to a slow probe and
  the per-attempt WARNING becomes a periodic summary; a successful open resets it
  immediately. This covers the idle-but-cloud-online case the existing offline
  pause did not.

## [0.11.11]

### Fixed
- **MQTT signaling session now ends promptly on a terminal disconnect.** The
  per-stream MQTT session (`_mqtt_session_sync`) only terminated its receive loop
  on a disconnect that happened *before* the first connect; a drop *after*
  connecting was always treated as transient. So a permanent post-connect
  disconnect - the account's persistent client reclaiming the same clientId
  (rc=142 "session taken over"), revoked credentials, or the broker going away -
  left the loop polling a dead socket until the full duration deadline, silently
  starving the camera of signaling (answer SDP, ICE, renewals). The loop now
  records when a post-connect drop begins, clears it on a successful reconnect,
  and ends the session with a WARNING once the disconnect has persisted past a
  short reconnect grace (`_MQTT_RECONNECT_GRACE`, 20 s) - transient blips still
  ride through paho's auto-reconnect unharmed.

### Changed
- **Removed the self-defeating `aioice` force-DEBUG on the DTLS path.** Every DTLS
  open set the `aioice` logger to DEBUG, which both flooded the log and was
  already neutralized by the package-init cap that holds `aioice.ice` /
  `aioice.turn` at INFO. Dropped it at the source; to debug ICE, set the `aioice`
  logger level explicitly (that overrides the NOTSET-guarded cap).

## [0.11.10]

### Changed
- **Capped the external `aioice` per-packet loggers too.** 0.11.7 capped the
  vendored aiortc RTP loggers, but `aioice` (the ICE/STUN library, a real
  dependency - not vendored) logs every STUN/TURN packet at DEBUG, so an active
  WebRTC connection still flooded the log when `aidot` DEBUG was enabled. On a
  microSD Home Assistant host that log I/O can starve the recorder. `aioice.ice`
  and `aioice.turn` are now capped at INFO by default (explicit user level
  respected); useful ICE connection-state DEBUG still flows.

## [0.11.9]

### Changed
- **A camera that never delivers media no longer spams the log.** When an SDES
  serve completes signaling but no SRTP media ever arrives (NO_MEDIA - e.g. a
  camera whose media never traverses the TURN relay), ffmpeg emits its expected
  "could not find codec parameters / output file is empty" stderr on every serve
  retry. That stderr now logs at debug while no media was received; it stays at
  WARNING when media WAS flowing (a genuine mid-stream ffmpeg error worth
  surfacing).

## [0.11.8]

### Changed
- **A camera that the cloud reports offline no longer drips WARNINGs.** The serve
  and keepalive loops already throttle open retries for a cloud-offline device
  (the offline pause), but still logged each failed probe at WARNING - so a
  dead/unpowered camera produced a steady trickle of "open failed ... (retry ...)"
  warnings. Those open failures now log at DEBUG while the device is explicitly
  cloud-offline; a genuine failure on an online camera still warns.

## [0.11.7]

### Fixed
- **No more blocking file read on the event loop.** The SDES SDP builder read the
  sprop cache from disk (`_inject_sprop` -> `_load_sprop` -> `open()`) as an
  eagerly-evaluated argument to `run_in_executor`, so the blocking `open()` ran on
  the event loop - which Home Assistant flags as "a blocking call ... causing
  stability issues". The read now runs inside the executor at all three SDP-write
  sites.

### Changed
- **Capped the vendored aiortc per-packet loggers.** `aiortc`'s RTP receiver and
  sender log every media packet at DEBUG; enabling DEBUG on the parent `aidot`
  logger to diagnose the integration turned that into thousands of lines per
  second (in one capture, ~99% of all log lines). `aidot._vendor.aiortc.rtcrtp`
  `receiver`/`sender` are now capped at INFO by default (an explicit user level is
  respected), so `aidot` DEBUG stays useful and the diagnostically valuable aiortc
  DEBUG (DTLS, ICE, SCTP/DCEP) still flows.
- **Demoted a benign warning to debug.** "ignoring ASCII-encoded IP ... from
  device dict" is a handled cloud quirk (the camera's LAN IP comes from WebRTC
  signaling, not that field) and is not actionable, so it no longer logs at
  WARNING.

## [0.11.6]

### Fixed
- **A cancelled SDES cold open no longer leaks sockets, a thread and a temp
  file.** Opening an SDES (battery) camera reserves two UDP sockets, starts a
  bridge thread, launches ffmpeg and writes a temp SDP, then hands them to the
  `SdesSession` that owns their teardown. If the 25-70 s handshake was cancelled
  (e.g. Home Assistant abandons a slow cold open) before that hand-off, none of
  it had an owner, so every abandoned attempt leaked two file descriptors, a
  thread and a `/tmp` SDP - eventually `OSError: Too many open files`. The open
  is now split into a wrapper that releases each resource (via an `ExitStack`)
  unless the session was actually returned.
- **Expired-token recovery on event-video and thumbnail fetches.** The cloud
  recording-list and MQTT-URL calls already refreshed the auth token and retried
  once on a `21026` ("please login again") error, but `getEventVideoUrl` and the
  latest-thumbnail fetch did not - so a snapshot or media request that happened
  to land on an expired token failed silently. They now use the same
  refresh-and-retry path.
- **Truncated H.264 parameter sets are dropped instead of cached corrupt.** When
  a STAP-A aggregation packet advertises a NAL longer than the packet itself
  (frame loss or relay truncation), the SPS/PPS parser bounded the slice to the
  packet so a short, corrupt parameter set is no longer cached (which could keep
  a camera showing no video until the cache was cleared).
- **Fire-and-forget client tasks are held by a strong reference.** The ICE-config
  prefetch and the sync `cleanup()` path scheduled work with a bare
  `create_task`; asyncio keeps only a weak reference, so either could be
  garbage-collected mid-flight. They now go through the same `_spawn_bg` helper
  the rest of the library uses.
- **A snapshot taken during a live view no longer interrupts that view.** On the
  default persistent-MQTT transport a second concurrent open on the same camera
  (a snapshot while streaming) reaped the single signaling-drain slot the live
  stream was using, freezing it until the ~30 s watchdog restarted it. Each
  session already reaps its own drain on stop, so ownership is now handed to the
  session on a successful open and the backstop slot is cleared; a concurrent
  open can no longer reap a live session's drain, while a genuinely orphaned
  (cancelled mid-handshake) drain is still released.
- **A transient MQTT broker drop no longer ends a stream's signaling early.** On
  the non-default per-stream transport (`AIDOT_PERSISTENT_MQTT` off) the signaling
  session runs for the whole lifetime of a stream, so a brief broker blip - which
  paho reconnects from automatically - used to tear the stream down. The receive
  loop now ends only on a disconnect that happens before the first successful
  connect; a later drop is left to paho's auto-reconnect, and subscriptions are
  re-established on every connect so the reconnected client is not deaf.

### Changed
- Replaced a non-ASCII token in an internal docstring with its ASCII gloss.

## [0.11.5]

### Added
- **Battery cameras stay awake for the whole live view (app parity).** A battery
  camera's low-power timer returns it to sleep ~25 s after the last cloud
  keep-alive, even mid-view, so a one-shot keep-alive at open let the stream drop
  partway through. A battery-only renew loop now re-issues `setKeepAliveTime`
  every 20 s (inside the 25 s window, so no sleep gap) for the duration of a
  battery stream, matching the official app; mains cameras never sleep and are
  skipped. Validated live on an A001513/L2 (renewals on the 20 s cadence). See
  the battery section of [`docs/CAMERAS.md`](docs/CAMERAS.md).

### Fixed
- **Keep-alive renew loop is single-instance and cleaned up on every exit path.**
  The renew task is battery-gated (mains cameras no longer schedule a throwaway
  no-op task); a re-view within the renew window cancels any still-running loop
  before starting a new one (no orphaned loops left POSTing `setKeepAliveTime`);
  the SDES/DTLS idle-release paths cancel it; and the `async_start_streaming`
  entry point starts it too, so a battery camera streamed via that path is
  renewed as well.

## [0.11.4]

### Changed
- **Lowered the `paho-mqtt` floor from `>=2.0` to `>=1.6.1`.** The MQTT client
  already ran on both paho generations - each `Client()` site falls back when
  `CallbackAPIVersion` is absent, and the callbacks accept a v1 `int` or a v2
  `ReasonCode` - so this only widens what can satisfy the dependency, useful
  where another package pins `paho-mqtt==1.6.1` (e.g. Home Assistant's
  custom-component test tooling). Validated live on 1.6.1: a real camera streams
  end-to-end. 2.x environments are unaffected (pip still resolves the highest).

### Fixed
- **Disconnect reason code is now truthful under paho 1.x.** The signaling MQTT
  client's `on_disconnect` used a fixed 5-arg (v2) signature, so paho 1.x's
  3-arg call landed the reason code in the wrong slot and logged it as `None`.
  It now reads the reason code from whichever position the installed paho passes.

## [0.11.3]

Hardening pass from a broad correctness + security review of the core modules.

### Security
- **MQTT broker password no longer logged.** `getServerUrlConfig`'s
  no-`mqttServerUrl` fallback logged the entire response body (which contains
  `mqttPassword`) at WARNING; it now logs only the non-sensitive key names,
  matching the redaction the adjacent debug log already used.
- **Token cache is written atomically at 0600.** The standalone CLI wrote the
  token file with umask-default perms before `chmod 0600` (a brief
  world-readable window) and truncated the existing file before serializing (a
  serialization failure destroyed the valid token). It now writes to a `0600`
  temp file and `os.replace`s it into place, so perms are never widened and the
  previous token survives any write failure.

### Fixed
- **Corrupt token cache no longer crashes the CLI.** `_make_client` now catches
  a bad/partial token file and falls back to username/password login instead of
  raising an uncaught `json.JSONDecodeError` at startup.
- **DTLS `async_snapshot` honors its bool contract.** Its open call was outside
  the try/except, so a busy-camera open raised out of a method documented to
  return `True`/`False`; it now returns `False` like the SDES branch.
- **SDES restart after an SRTP key change no longer produces a dead stream.**
  The ffmpeg-restart path now updates the shared process holder, so the bridge
  thread does not mistake the restarted ffmpeg for an exited one and starve it.
- **LAN attribute reads fail cleanly.** `async_get_attributes` raises
  `CameraLanError` (not an unguarded `IndexError`) when a camera logs in but
  never answers the attribute query, preserving the cloud-fallback contract.
- **Motion dedup evicts oldest, not arbitrary.** The `_motion_seen` memory
  bound is now insertion-ordered, so trimming keeps the most-recent uids and
  in-window events stay deduplicated.
- **Resource leaks on error paths closed.** Several terminal raises / loop exits
  now release what they held: the connect-per-stream MQTT session thread + its
  broker connection (DTLS media-declined and livePlay=0 refusals in both the
  DTLS and SDES open paths), and the cloud-playback TCP socket (login-failure
  returns and receive-loop exit now tear down via a shared cleanup).

### Changed
- Harmonized the persistent-MQTT `NO_MEDIA` soak figure between README and
  `docs/CAMERAS.md` (`~57% -> ~11-19%` across soaks).

## [0.11.2]

### Fixed
- **A token refresh could crash instead of persisting.** `login_info` is also
  used as the account-shared cache for the persistent-MQTT connection and
  its guarding `asyncio.Lock` (`_get_persistent_mqtt` - one connection per
  account, the default since 2026-06-17). Anything that serialized
  `login_info` directly - this library's own standalone CLI, or a consuming
  integration's config-entry storage - hit `TypeError: Object of type Lock
  is not JSON serializable` once that connection existed, silently failing
  to persist a freshly rotated token. Confirmed live: a standalone
  `aidot-go2rtc` run's token-refresh callback threw exactly this.
  `AidotClient.serializable_login_info()` is a new JSON-safe view (excludes
  the two runtime-only keys) that the CLI's own token cache now uses; any
  other caller persisting `login_info` should switch to it too.

## [0.11.1]

### Fixed
- **Keepalive retries no longer chase cloud-offline cameras.** When an open
  fails and the cloud has explicitly reported the device offline, the
  reconnect loops now hold - re-checking the online flag every 30 s
  (`AIDOT_OFFLINE_RECHECK_S`) and probing one real open only every 600 s
  (`AIDOT_OFFLINE_PROBE_S`) - instead of retrying on the normal backoff
  cadence. Each retry against a dead camera consumed an open-gate slot for
  the full 30 s signaling timeout; observed live (HA 2026.7.1), two unpowered
  A000088s cycling that way pushed a healthy camera's cold open past two
  minutes. Retries resume within one recheck of the device coming back
  online. First attempts are never delayed, and devices whose online state
  was never reported by the cloud are unaffected.

## [0.11.0]

### Fixed
- **Relay-only SDES (battery) cameras stream again.** These cameras (e.g.
  A001513, whose real LAN IP the cloud does not expose) answer with their ICE
  credentials after the initial STUN nomination window and send no connectivity
  probes of their own, so neither the in-window nor the probe-gated deferred
  `USE-CANDIDATE` send ever nominated their relay candidates - no SRTP media
  flowed and the serve failed with *"Could not find codec parameters (h264,
  none)"*. The ungated periodic `USE-CANDIDATE` re-sender now falls back to the
  late-parsed credentials, so relay-only cameras are nominated without needing a
  probe. Verified live on an A001513: 0/2 streaming before, 3/3 after. (#112)
- **`_mqtt_device_cmd` no longer reports success on a refused broker
  connection.** A failed MQTT connection now surfaces as a failure instead of a
  phantom success. Validated live: `setDevAttrReq` toggles return `True` only on
  a real seq-matched camera ACK. (#107)
- **Background stream tasks retrieve and log their exceptions** instead of
  producing *"exception was never retrieved"* warnings. (#107)

### Changed
- **The DTLS 1.0 downgrade is self-scoped to this library's sessions.** The
  OpenSSL minimum-version override for DTLS-1.0 camera firmware now applies only
  to peer connections whose certificate carries the library's tag, so other
  aiortc peer connections in the same process keep the DTLS 1.2 floor. Validated
  live on A000088 (DTLS 1.2) and A001513 (SDES + SCTP datachannel): both connect
  and stream, 0 DTLS errors. (#107)
- **A LAN login that cannot complete with the device's AES key marks the host
  ineligible** and falls back to cloud control (spoofed/broken hosts no longer
  wedge local control). (#107)

### Added
- **Opt-in TLS for `CloudPlaybackSession`** via `use_tls=` (default `False`,
  current plaintext behavior unchanged), with a warn-once when disabled. (#107)

## [0.10.3]

### Fixed
- **Installable under Home Assistant 2026.7 (PyAV 17).** HA 2026.7 pins `av==17`,
  but stock `aiortc` caps `av<17`, so `python-aidot-cameras[webrtc]` was
  unsatisfiable there - Home Assistant reported *"Requirements for aidot not
  found"* and the integration failed to load (confirmed on a live HA 2026.7.1
  box). `aiortc` is now **vendored** at `aidot/_vendor/aiortc` (byte-identical to
  aiortc 1.14.0) so its `av<17` packaging cap no longer gates installation, and
  the `[webrtc]` extra depends on aiortc's own runtime deps with the PyAV ceiling
  widened to `<18`. aiortc runs unchanged on av 17 (verified: import + H.264
  encode round-trip), so streaming behavior is unaffected. Validated under HA
  2026.7.1's exact `package_constraints.txt` (`av==17.0.1`): the previous release
  is *"unsatisfiable"*, this one installs and imports cleanly. Revert to the stock
  `aiortc` dependency once upstream widens the pin.

## [0.10.2]

### Changed
- **Repository re-aligned to a flat `aidot/` layout** (from `src/aidot/`) to match
  the upstream project's paths, and **downstream git ancestry with upstream
  (`AiDot-Development-Team/python-AiDot`) was established**, so future upstream
  changes can be merged directly (`git fetch upstream && git merge upstream/main`).

  Marker release only: **no functional or API change.** The published wheel ships
  the identical `aidot/` package (imports and behaviour are the same as 0.10.1);
  this release exists to record the maintenance/layout milestone in the changelog.

## [0.10.1]

### Fixed
- **Deadlock opening a stream on the SDES->DTLS fallback.** When a camera declared
  SDES but actually required DTLS, the fallback re-entered the *public*
  `async_open_webrtc_stream` while already holding the non-reentrant open-gate
  permit - hanging forever whenever the gate was saturated (two such cameras
  opening at once, or `AIDOT_MAX_CONCURRENT_OPENS=1`). It now calls the ungated
  impl under the permit it already holds.
- **DTLS fingerprint pinning failed open.** With `AIDOT_DTLS_PINNED_FP` set, the
  pin was silently skipped when the camera presented a real (non-empty)
  fingerprint - the check was gated on the empty-fingerprint workaround - and it
  accepted any certificate when the peer cert was missing or the digest raised.
  The pin is now enforced whenever it is set (independent of the workaround) and
  **fails closed**: a missing cert or a fingerprint error fails the handshake.
  Comparison is now colon/whitespace/case-insensitive. Unit tests added.
- **Secrets no longer written to logs.** The login response (access/refresh
  tokens), the userConfig body (MQTT password), and device-list bodies /
  per-device records (device `aesKey`/`password`) were logged on error or at
  DEBUG; they now emit only status codes / redacted identifiers.
- **`async_snapshot` no longer blocks the event loop.** It ran ffmpeg
  synchronously (and a no-timeout ffmpeg on the Pillow-missing path), freezing
  every camera/keepalive/MQTT drain for up to the timeout. It now uses an async
  subprocess with a timeout and offloads the blocking JPEG encode to an executor.

### Security / hardening
- Cap the LAN-control frame body size (an unbounded 32-bit length was a
  memory-exhaustion vector from a hostile/malfunctioning LAN peer).
- Sanitize the cloud-supplied `devid` before using it as the sprop cache
  filename (path-traversal hardening).
- Coerce cloud attribute values defensively so a malformed value can no longer
  crash the status-refresh path.
- Write credential/key files atomically at mode `0600` (no chmod-after-create
  window) and restrict the config directory to `0700`.

### CI
- Gate PyPI publishing on a green test run and run `twine check` before upload,
  so a red build can no longer publish.

## [0.10.0]

### Security
- **CSPRNG for media-keying material.** The SDES/DTLS pre-shared key carried over
  signaling is now generated using the `secrets` module instead of the
  predictable Mersenne-Twister `random`, removing a key-predictability weakness.
- **SDP-rewrite DoS guard.** The serve-port SDP rewrite now validates `m=audio`/
  `m=video` section shape before indexing, so a malformed/truncated SDP can no
  longer crash the rewrite.
- **Credential key separation.** `AIDOT_CRED_KEY_FILE` lets you store the Fernet
  key for encrypted credentials outside the config directory, so the key is no
  longer necessarily co-located with the ciphertext (a warning is emitted when it
  is). Honors `XDG_CONFIG_HOME`; applies to the default credentials path.

### Added
- **Opt-in transport hardening** (all default to prior behavior and emit a
  one-time warning when left permissive):
  - `AIDOT_DTLS_PINNED_FP` - pin the camera's DTLS `sha-256` fingerprint; a
    mismatching certificate fails the handshake instead of being accepted.
  - `AIDOT_PLAYBACK_TLS_VERIFY=1` - require full certificate + hostname
    verification on the TCP playback/live-stream TLS connection.
  - `AIDOT_ALLOW_LAN_SERVE` - acknowledge/silence the warning emitted when
    decrypted media is served on a non-loopback bind.
  - `AIDOT_SDES_HOLEPUNCH_HOST` - override the NAT hole-punch host used when the
    cloud supplies no TURN entry (set empty to disable the hardcoded fallback).
- **Supported-cameras documentation** - a model/transport/power table in
  `docs/CAMERAS.md` (and a short list in the README), covering A000088 (DTLS),
  A001513 (SDES, battery / "L2"), and A001064 (SDES, PTZ).

### Removed
- Dropped the write-only `_last_batch_response` attribute (a dead store with no
  readers).

## [0.9.3]

### Changed
- **The high-port ICE nomination fix is now unconditional.** The A000088/DTLS
  connect path forces USE-CANDIDATE onto the highest remote port (measured
  ~87% connect success versus ~10% without). This was previously gated behind a
  `AIDOT_DISABLE_HIGHPORT_FIX` debug escape hatch; the gate and its environment
  variable have been removed, since disabling the fix only ever degraded connect
  reliability. The override still self-scopes to tagged DTLS connections, so SDES
  cameras and non-camera devices are untouched.

### Documentation
- Decluttered the README environment-variable table down to the knobs most
  worth tuning. The finer-grained internal knobs (audio normalization,
  keyframe/PLI cadence, retry timing, SDES audio, idle release, the sprop cache
  path) now live under a dedicated "Advanced tuning environment variables"
  section in [`docs/CAMERAS.md`](docs/CAMERAS.md).

## [0.9.2]

### Fixed
- **Choppy DTLS camera audio under packet loss.** The DTLS A/V mux timestamped
  audio purely by accumulated decoded-sample count (`a_pts += fr.samples`) and
  discarded the PCMA RTP timestamp it had already captured. The video path locks
  to its 90 kHz RTP timestamps, but audio did not - so any lost audio packet made
  the lost time *vanish* and the remaining samples concatenate, compressing the
  audio timeline. Over a live stream this runs audio progressively ahead of the
  video and forces the player's jitter buffer to resync, heard as choppy audio.
  (A zero-loss lab capture sounded fine, which is why this hid behind earlier
  fixes.) The mux now anchors audio to its RTP clock and conceals a detected gap
  (>= 20 ms) with silence through the resampler - mirroring the video path - so
  audio stays time-locked and lost time becomes a brief honest silence instead of
  permanent A/V drift. Lossless streams are unaffected (the gap is zero, a no-op).
  An offline regression probe that drives the real mux with synthetic loss is at
  `scripts/audio_mux_probe.py`.

## [0.9.1]

Logging and packaging hygiene; no behavioural change to streaming.

### Fixed
- **Swallowed-exception debug logs now identify the camera.** Every
  `_LOGGER.debug("camera %s: swallowed exception", ...)` site across the camera
  modules was filling `%s` with the *function-name literal* instead of a device
  id, so logs read `camera stop: swallowed exception` and never said which
  camera. The 70 sites where a device id is in scope now log
  `camera <id>: swallowed exception in <func>` (via `getattr(self, "device_id",
  "?")` - these are except blocks, so they must never raise); the 35 sites with
  no device id in scope (the `SdesSession`/`WebRTCSession` classes carry none,
  plus module-level functions and non-`self` closures) drop the misleading
  `camera %s` framing and log `swallowed exception in <func>`.

### Changed
- **Core runtime dependencies now have conservative lower bounds**
  (`aiohttp>=3.9`, `cryptography>=42.0`, `pycryptodome>=3.20`, `dacite>=1.8`),
  so a fresh install can't resolve an ancient release. No upper caps - under
  Home Assistant, HA core pins `aiohttp`/`cryptography` itself and a cap would
  fight its resolver.

## [0.9.0]

Observability, connection-speed, and a large internal decomposition. Motivated
by diagnosing a buffering camera down to a marginal Wi-Fi link, then trimming
cold-start latency toward app-parity. All streaming changes were live-validated
on real DTLS and SDES cameras.

### Added
- **`WebRTCSession.get_stats()`** - a best-effort connection-health snapshot: the
  nominated ICE candidate pair (host/srflx/relay/prflx - the relay-vs-direct
  signal) plus inbound RTP packet loss / jitter. Fully guarded against
  aiortc/aioice internal drift.
- **`CameraStatus.wifi_rssi`** - parses the cloud `networkRssi` (dBm) into camera
  status, so a marginal camera link is visible without a packet capture.
- **`scripts/camera_diag.py`** - a maintained on-hardware probe: handshake time,
  time-to-first-frame, per-second decoded-fps timeline + gaps, nominated ICE
  path, RTP health, and Wi-Fi RSSI.

### Changed
- **DTLS fast-liveplay (default on).** Skips the up-to-2s `livePlayResp` wait on
  the DTLS open path (the official app never waits for it; it usually times out),
  while keeping the full ICE/TURN/DTLS handshake - so remote/relay viewing is
  unaffected, unlike the broader `fast_connect`. ~2s off a cold LAN open
  (12.8s->10.7s measured). Disable via `AIDOT_DTLS_FAST_LIVEPLAY=0` or per-camera
  `_dtls_fast_liveplay_opt`.
- **HTTP ICE config is cached** until just before its server-provided `ttl`
  (capped at 1h), saving the ~2s `iceConfig` fetch on a re-open after the warm
  session lapses. Honoring the explicit ttl guarantees no expired TURN
  credentials are reused.
- **Stall-triggered keyframe (PLI)** on the DTLS serve loop: a one-shot PLI when
  muxed frames stall (a dropped GOP on a jittery link), re-armed only when frames
  resume so a no-consumer freeze can't spam the camera. `AIDOT_STALL_PLI_S`.
- **Offline-device LAN errors downgraded to debug.** Connect-failed / read-status
  / unresponsive-keepalive messages on the light control channel are expected for
  an offline/powered-off/stale-IP device (the reconnect chain retries and
  availability is reflected in entity state), so they no longer log at
  ERROR/WARNING.

### Internal
- **`camera/client.py` decomposed 10,575 -> 3,646 lines (-65%).** The two
  ~3.5k-line stream-open state machines moved to mixin modules
  (`webrtc_open.py`, `sdes_open.py`) that `CameraMixin` inherits - behaviour-
  preserving (each method body byte-identical to the original), validated by
  ruff, the full suite, and live DTLS + SDES streams.
- **aioice compatibility guard** (`test_aioice_compat.py`) + an `aioice>=0.9,<0.12`
  pin: the high-port nomination patch and stream diagnostics read private aioice
  internals, so a breaking bump now fails loudly instead of silently degrading.

## [0.8.0]

Milestone release. The cloud TURN relay path is now empirically validated for a
genuinely-remote client, and the default-on persistent-MQTT and SDES-teardown
paths are hardened against the executor-thread leaks and silent command drops
found in a pre-release review.

### Fixed
- **Persistent-MQTT stream drain no longer leaks an executor thread.** The drain
  blocks an executor thread on `outgoing_q.get` until a `None` sentinel arrives.
  Cancelling the drain future (the previous teardown behaviour, 0.7.36) cannot
  interrupt that blocked thread, so a stream open cancelled mid-handshake - or a
  second open that replaced a prior one without an intervening
  `async_stop_streaming` - left the thread (and its handler on the shared
  connection) pinned forever, eventually exhausting the shared default
  `ThreadPoolExecutor`. Teardown and every new open now reap via
  `_reap_stream_drain`, which pushes the `outgoing_q` sentinel to release the
  thread before cancelling, and tracks the queue so a replacing open reaps the
  prior drain too.
- **Persistent-MQTT command/attribute requests fall back to a per-op connect.**
  When the persistent connection is momentarily down, `request()` returns an empty
  result with an error status; the command path previously treated that as a
  successful fire-and-forget send, silently dropping e.g. a PTZ or `setDevAttr`
  command. It now falls back to a fresh `_mqtt_session` connect (matching the
  `pm is None` path), so a transient outage degrades gracefully instead of losing
  the command or returning stale "no attributes".
- **`_request_sync` no longer raises on a concurrent `close()`.** It snapshots
  `self._client` under the lock and guards the publish, so a shutdown/reload
  nulling the client (or a paho publish error) returns an error tuple rather than
  letting an `AttributeError` escape `request()`.
- **Exactly one persistent connection per account under concurrency.**
  `_get_persistent_mqtt` now serializes get-or-create behind a per-account
  `asyncio.Lock`; the prior double-checked re-check could still let two concurrent
  first-callers each build a `_PersistentMqtt`, colliding on the single authorized
  client_id.
- **SDES ffmpeg teardown reaps the killed child and frees the stderr reader.** On
  the `kill()` path `SdesSession.stop()` now `wait()`s to reap the SIGKILL'd child
  (a raw `Popen` has no asyncio child-watcher, so it otherwise lingered as a zombie
  under reconnect churn), and on a stderr-read timeout it closes the pipe so the
  executor thread blocked in `stderr.read()` on a wedged ffmpeg is released instead
  of leaked.
- **Removed a duplicate `CONF_LOGIN_INFO` definition** in `const.py` (a dead
  `"login_info"` shadowed by `"loginInfo"`); no behaviour change - the effective
  value was always `"loginInfo"`, which the v1.1.3 login_info migration expects.

### Validated
- **Cloud TURN relay delivers media to a genuinely-remote client.** Verified from
  an off-site host on a different public IP: with only the relay candidate offered
  (host/srflx stripped), the camera delivered media through the cloud TURN relay
  (`nominated local=relay`), confirming the relay-default connection mode
  empirically rather than by app-parity inference alone.

## [0.7.36]

### Fixed
- **Orphaned persistent-MQTT stream drain is reaped on teardown.** When a stream
  open is cancelled before a `WebRTCSession` takes ownership of the persistent-MQTT
  drain (the session normally stops it via the `outgoing_q` sentinel), the drain
  would block on `outgoing_q.get` indefinitely with its handler still registered
  on the shared connection. It's now tracked and cancelled in
  `async_stop_streaming` (its `finally` removes the handler), so repeated
  cancel-during-open no longer accumulates drains/handlers. (#74)

## [0.7.35]

### Added
- **Per-camera served-audio gain (`start_keepalive(sdes_audio_gain_db=...)`).**
  The SDES served-audio gain (default `-8` dB) can now be set per camera by the
  caller, in addition to the `AIDOT_SDES_AUDIO_GAIN_DB` env - so a Home Assistant
  install (which can't set env vars) can expose it as an option. New
  `_resolve_sdes_audio_gain_db` resolver (opt wins over env; bad value falls back
  to the default). (#73)

## [0.7.34]

### Changed
- **SDES (battery) camera audio is now ON by default (`AIDOT_SDES_SERVE_AUDIO`).**
  Matching the official app, the SDES serve includes audio. A continuous
  `anullsrc` silence base is `amix`'d under the camera PCMA so the AAC encoder is
  fed from t=0 and the mpegts PMT writes promptly; any gaps are filled with
  silence, so audio from battery cameras streams smoothly. New
  `_resolve_sdes_serve_audio` resolver (per-camera `sdes_audio` opt wins over the
  `AIDOT_SDES_SERVE_AUDIO` env; falsy `{0,false,no,off}` disables). File recording
  (snapshots, diagnostics) is unaffected - always a plain `-c copy`. Soak-validated
  across the battery fleet (video + audio on every open). `AIDOT_SDES_AUDIO_GAIN_DB`
  (default `-8`) trims the hot mic. (#72)

## [0.7.33]

### Fixed
- **SDES teardown no longer hangs on a wedged ffmpeg.** `SdesSession.stop()` read
  ffmpeg's drained stderr with a blocking `proc.stderr.read()` on the event loop;
  if the killed ffmpeg hadn't fully exited (zombie / stuck in uninterruptible I/O
  - the no-media degradation case), the read never reached EOF and hung the whole
  teardown, wedging `async_cleanup` / `async_stop_streaming` / `close()`. It now
  runs in the executor under a 2 s timeout, so a wedged ffmpeg can't stall the
  close. (#71)
- **Cameras no longer hammer the light-protocol TCP:10000 login.** That control
  channel is lights-only - cameras use the separate `CameraLanClient` for local
  control and get their LAN IP from WebRTC signaling. When a discovered IP slipped
  the `_is_camera` gate, `async_login` would log in to a port the camera doesn't
  serve, fail with `login read status error 0 bytes read`, and re-fire every
  broadcast tick. Cameras are now excluded at `async_login` (the single chokepoint
  for the discovery and reconnect-chain paths), and `update_ip_address` is
  throttled to the same 30 s window the reconnect chain uses. Lights are
  unaffected. (#71)

## [0.7.32]

### Changed
- **SDES fast-liveplay is now ON by default (`AIDOT_SDES_FAST_LIVEPLAY`).** The
  official app never waits for/parses `livePlayResp` - it fires `livePlayReq` and
  goes straight to the WebRTC offer/ICE. We now match that by default (~4.5 s
  faster SDES cold start) instead of blocking on the echo/ack. Role-reversal
  models (`_NO_FAST_LIVEPLAY_MODELS`, e.g. A001064) remain hard-excluded for
  correctness. Disable via `AIDOT_SDES_FAST_LIVEPLAY` in `{0,false,no,off}` or
  `_sdes_fast_liveplay_opt=False`. With persistent-MQTT-by-default this brings the
  SDES signaling path to app-parity. (#70)

## [0.7.31]

### Fixed
- **Two-way talk now releases the camera speaker on teardown, so the next talk
  session isn't blocked.** Previously the DTLS `stop()` closed the PeerConnection
  without sending SPEAKERSTOP when talk was active (stall/error/`async_speak`
  paths), and even the clean path closed the transport immediately after
  SPEAKERSTOP without letting it flush - leaving the camera's speaker/talk channel
  bound to the dead session, so the app's (or HA's) next push-to-talk got `851`
  "mic occupied". Now: DTLS `stop()` sends SPEAKERSTOP(849), idles the track, and
  waits a short flush window before closing the PC whenever talk was active
  (idempotent); SDES `stop()` additionally settles after the bridge sends
  SPEAKERSTOP so the camera processes the release over the still-live SCTP before
  teardown. (#69)

## [0.7.30]

### Changed
- **Persistent MQTT connection reuse is now ON by default
  (`AIDOT_PERSISTENT_MQTT`).** This is exactly how the official app behaves - one
  persistent connection per login session for commands, attributes, and stream
  signaling - and the live soak validated it cuts SDES `NO_MEDIA` from ~57% to
  ~19% with no regression (battery cameras roughly doubled their media-delivery
  rate). It is also safer than connect-per-op, which can collide on the single
  authorized client_id. Disable with `AIDOT_PERSISTENT_MQTT` in `{0,false,no,off}`
  or per-camera `_persistent_mqtt_opt=False` (the explicit opt always wins). No
  behaviour change for callers that already set the flag. (#68)

## [0.7.29]

### Changed
- **Persistent MQTT now also carries the stream-open signaling
  (`AIDOT_PERSISTENT_MQTT`) - Phase 2.** When enabled, the WebRTC stream open no
  longer spins up its own connect-per-stream MQTT session; it subscribes and
  registers its handler on the SAME account-level persistent connection that
  commands/attributes use (the stream's `mqtt_cid` IS the authorized
  `mqttClientId`, so it is literally the same connection), drains its outgoing
  queue through it, and does NOT tear the connection down on stop - matching the
  app, which keeps one connection for everything. This removes the per-open
  connect churn that was rate-limiting the cloud account.
  **Soak-validated (live, 7-camera round-robin):** SDES `NO_MEDIA` dropped from
  **57% -> 11%** (n=63 -> n=28) and the connect RuntimeErrors went 6 -> ~0, with no
  per-camera regression - including the previously-worst battery camera going
  from ~15% to ~71% media delivery. The flag is still opt-in (default off);
  `_PersistentMqtt` gained `add_handler`/`remove_handler`/`publish`/`subscribe`
  for the long-lived stream consumer. (#67)

## [0.7.28]

### Added
- **Persistent MQTT connection reuse for commands + attributes
  (`AIDOT_PERSISTENT_MQTT`, opt-in, default off) - Phase 1.** Historically every
  device command (PTZ/settings) and every attribute fetch opened and tore down its
  own cloud MQTT WebSocket; the official app instead keeps ONE persistent
  connection per login session (LDSBaseMqttServiceImpl) and reuses it for
  everything. When enabled, the new `_PersistentMqtt` holds one account-level
  connection (the broker binds auth to the single authorized client_id, so there
  can only be one), subscribes once, replays subscriptions on reconnect, and routes
  `_mqtt_device_cmd` + `async_get_camera_attributes` through it - cutting the
  per-command and per-5-min-attribute-poll connect churn that can trip cloud
  rate-limiting across multiple cameras. The stream-open signaling path is
  unchanged (it uses per-session client_ids) and is a later phase. Connection is
  closed on `AidotClient.async_close`. Validated live: a real device reply
  (`lowPowerActiveStateResp`) collected through a single shared connection
  (`connects=1`); per-op fallback retained when off. (#66)

## [0.7.27]

### Added
- **Adaptive fast-with-fallback for SDES (`AIDOT_SDES_ADAPTIVE`, opt-in, default
  off).** When enabled, the SDES keepalive loop tries the fast path first (skip the
  livePlay waits + TURN relay pre-allocation, with a short 45 s open timeout / 40 s
  media grace) and, if that attempt delivers no media, falls back to the full,
  patient relay path for the rest of the loop. This makes a fast connect safe
  regardless of camera reachability: a LAN-direct camera gets the fast connect; a
  strict-NAT / non-LAN camera loses one fast attempt then connects via the relay. A
  **per-device cache** (`_fast_path_unavailable`) latches a camera that failed the
  fast path so later views skip straight to the full path - bounding the
  fast-timeout penalty to once per camera per session. Role-reversal models keep
  their `sdes_fast_liveplay` exclusion. Enable with `AIDOT_SDES_ADAPTIVE=1` or
  `start_keepalive(sdes_adaptive=True)`. **Default off pending real-world
  fast-failure-rate data** - a fast *failure* costs ~40 s (the grace) before
  fallback while success saves ~7 s, so the failure rate must be characterised on
  real fleets before this becomes a default. Live-validated on the dev-box LAN:
  fast success on mains A001064 (first-media 16.1 s) and battery A001513 (9.96 s)
  with 0 false fallbacks / 0 churn, and the fallback confirmed delivering media
  (11 s) when a fast attempt failed. (#65)

## [0.7.26]

### Added
- **`AIDOT_SDES_SKIP_TURN_PREALLOC` (experimental, opt-in, default off):** skips
  the blocking TURN relay pre-allocation on the SDES path for LAN-direct cameras.
  Before building the offer the SDES path does two synchronous RFC-5766 Allocate
  round-trips (audio + video) to the cloud TURN server so the offer can carry a
  relay address - but on a LAN the camera's host candidate wins and that relay is
  never used. Measured live, the pre-allocation costs ~2-3 s normally and **~4 s
  when the Allocate times out** (which it does from networks that can't reach the
  TURN server), all for `allocated=0`. Skipping it removes that dead wait. The
  cost is now always instrumented (`signaling-wait[...] sdes-turn-prealloc
  elapsed=...`), and `_fast_connect` is unchanged (still force-off for SDES) - this
  flag skips *only* the relay pre-allocation, leaving the SCTP-arming handshake
  intact. Validated live on A001513 (skip on: 9.8 MB over a 130 s hold, 0 SCTP
  churn, healthy heartbeats throughout). Per-camera `sdes_skip_turn` (via
  `start_keepalive`) or the env var; off by default pending a broader soak. (#64)

## [0.7.25]

### Fixed
- **livePlayResp was never matched, so its wait always timed out.** The handler
  matched the response on `devId`, but the camera's livePlayResp payload carries
  no `devId` - it echoes back our exact `peerid`. The wait therefore always ran
  to its full timeout (and the camera's reject `code` was never read). The match
  now keys on the echoed `peerid` (falling back to `devId`), so the wait returns
  the instant the response arrives (live: `elapsed=0ms arrived=True`).
- **Spurious aborts on transient/unknown livePlay codes.** With the response now
  actually parsed, the previously-dead reject path could fire on any non-OK code
  - including `-50019` ("not ready"), which battery cameras emit routinely and
  recover from via ICE. All three reject sites (one SDES, two DTLS) now fast-fail
  *only* on an unambiguous refusal (`livePlay=0`); other non-OK codes (incl.
  `-50019`) are logged as transient and the handshake proceeds. Validated live:
  A001513 SDES (1.67 MB) and A000088 DTLS (frames received) both stream. (#61)

## [0.7.24]

### Fixed
- **SDES fast-liveplay degraded the A001064 (role-reversal PTZ) camera and is now
  excluded from it.** That model's handshake has the camera echo our offer back
  as its own webrtcReq before doing ICE, so it must be armed *before* our
  webrtcReq - and the flag sends webrtcReq ~4.5 s earlier, which dropped its media
  reliability (a live A/B showed 2/2 media with the flag off vs 1/2 with it on;
  the flag's soak validation covered only the A001513 battery cameras). The flag
  now never applies to role-reversal models (`_NO_FAST_LIVEPLAY_MODELS`,
  currently `LK.IPC.A001064`) regardless of the option/env - they keep the full
  livePlay waits. A001513 cameras still get the ~4.5 s saving. (#60)

## [0.7.23]

### Changed
- **SDES fast-liveplay (`AIDOT_SDES_FAST_LIVEPLAY` / `sdes_fast_liveplay`) is now
  validated in soak** and relabelled from "experimental/unvalidated, may
  destabilise" to **validated (opt-in, default off)**. A 3-hour live soak - 15
  SDES opens across battery cameras, the flag engaging on every one, **0 churn /
  0 fail**, with the ~4.5 s signaling saving holding throughout - confirmed it
  doesn't break the handshake or cause near-term churn (it keeps the full
  ICE/TURN/SCTP handshake; only the always-timing-out echo/livePlayResp acks are
  shortened). **Kept off by default** pending broader multi-day use: per-open and
  near-term stability are proven, long-haul sustained stability is not yet.
  Docs/labels only - no behaviour change. (#59)

## [0.7.22]

### Fixed
- **The experimental SDES fast-liveplay flag (0.7.21) was dead code for SDES
  cameras** - its gate lived inside the DTLS-only `if not use_sdes:` block, so it
  never ran for the SDES cameras it targets (explaining the earlier "no effect").
  Moved the gate into the SDES open path where the SDES livePlay waits actually
  live, so it now engages.

### Changed (experimental)
- **`AIDOT_SDES_FAST_LIVEPLAY` now shortens the always-timing-out SDES signaling,
  not just the livePlayResp wait.** Instrumentation (see below) showed that for
  the SDES cameras measured, both the livePlayReq-echo wait (5 s) and the
  livePlayResp wait (1 s) **always time out** (echo/resp never arrive) yet
  streaming succeeds - ~6 s of dead padding. With the flag on, the echo wait is
  capped at 1.5 s and the livePlayResp wait is skipped: **~6 s -> ~1.5 s of
  signaling (a deterministic ~4.5 s saving)**, with the full ICE/TURN/SCTP
  handshake untouched. Still EXPERIMENTAL/off by default - stability over a real
  soak is unverified; enable to test and watch for SDES session churn.

### Added
- **`signaling-wait[<device>] <name> elapsed=<ms>` instrumentation** for the SDES
  (and DTLS) livePlay/iceConfig waits, so the actual cost of each wait is
  measurable from the logs (the `sdes_soak_monitor.py` validation tool reads
  these alongside the `cold-start[...]` markers). (#57)

## [0.7.21]

### Added (experimental)
- **`AIDOT_SDES_FAST_LIVEPLAY` / `start_keepalive(sdes_fast_liveplay=...)`** - an
  **experimental, unvalidated** opt-in that skips *only* the ~2 s `livePlayResp`
  blocking wait for SDES cameras, keeping the full ICE/TURN/SCTP handshake (the
  part whose skipping destabilises SDES - which is why full `fast_connect` stays
  forced off for SDES). Theory: shaves ~2 s off the SDES cold start without the
  SCTP churn that full fast-connect causes. **Off by default.** A clean synthetic
  A/B was not achievable (SDES cameras degrade on rapid reconnects and the
  available test cameras are battery / role-reversal), so this needs a real-world
  soak before any default change - **may destabilise SDES; enable at your own
  risk and watch for session churn.** (#55)

## [0.7.20]

### Fixed
- **Cold-start instrumentation now covers the SDES `webrtcReq`.** The SDES open
  has its own `webrtcReq` publish point that the 0.7.19 markers missed, so SDES
  cameras logged `first-media`/`serving` but not `webrtcReq`. Added
  `cold-start[<device>] webrtcReq (sdes) +<ms>` so the SDES cold-start timeline
  is complete.

## [0.7.19]

### Added
- **Cold-start instrumentation.** `_cold_phase()` logs greppable
  `cold-start[<device>] <phase> +<ms>` markers (webrtcReq -> first-media ->
  serving) on both serve paths, so a cold connect's timeline is measurable
  without a debugger. Best-effort: never raises, no-op when no open is in flight.
- **Warm-hold option.** `start_keepalive(stream_idle_s=...)` overrides
  `AIDOT_STREAM_IDLE_S` (default 120 s); `<= 0` keeps the warm WebRTC session
  forever so re-views are instant - intended for mains cameras (it holds a
  concurrent-stream slot + continuous decrypt for the camera's lifetime, so stay
  within `AIDOT_MAX_CONCURRENT_STREAMS`, default 3). Default behaviour unchanged.

### Changed
- **Denser SDES startup PLI burst** so the first decodable keyframe arrives
  sooner on a cold open: keyframe requests now ramp 0 / 1.5 / 3.5 / 6.5 s then
  the same 30 s safety PLI (was 3 PLIs at a flat 5 s -> first IDR up to ~10 s).
  Tunable/revertable via `AIDOT_SDES_PLI_GAPS`. (#52)

## [0.7.18]

### Fixed
- **Cold-start blank video: the first view of an idle camera (or the first view
  after an HA restart) could fail to load.** go2rtc pulls the library's local
  `ffmpeg -f mpegts -listen 1` socket before ffmpeg has bound it - ffmpeg only
  opens its `-listen` output after probing input, which needs the ~16-25 s WebRTC
  handshake to deliver the first frames. go2rtc hit `ECONNREFUSED`, retried for
  ~200 ms, then gave up, so the card stayed blank until a second attempt. The
  library now holds the public serve port for the whole session via a small relay
  (`_ServeRelay`) and proxies to ffmpeg on an internal port: an early pull
  connects and waits instead of being refused, and the public listener survives
  ffmpeg restarts (go2rtc reconnects). Wired into both serve paths (DTLS + SDES).
  Default on; disable with `AIDOT_SERVE_RELAY=0` or `start_keepalive(
  serve_relay=False)`. Falls back to serving ffmpeg directly on the public port
  if the relay bind fails, so a port clash never breaks streaming.
  Live-validated on an A001513 (SDES) camera. (#50, fixes #49)

## [0.7.17]

### Internal
- Consolidated reconnect pacing behind a single `ReconnectPacer` (in
  `camera/protocol.py`) wired into all three reconnect loops (SDES keepalive,
  JPEG streaming, DTLS serve), replacing per-loop attempt-counter bookkeeping
  with one escalate/reset policy. The open-fail and end-of-session delays are
  unchanged; this is a behavior-preserving refactor with unit coverage for the
  pacer's escalate/reset transitions.
- Deduplicated the cloud IPC POST path into `_async_post_ok()` and the owner-id
  fallback into `_owner_id()`, shared by the wake and `liveStreamParam` calls.
- Promoted the `liveStreamParam` gate to a `live_stream_param` keyword on
  `start_keepalive` (still falling back to `AIDOT_LIVESTREAM_PARAM`). (#47)

## [0.7.16]

### Documentation
- Documented the `AIDOT_LIVESTREAM_PARAM` environment variable in the README's
  environment-variable reference - the knob added in 0.7.15 to gate the
  `liveStreamParam` cloud pre-connect that provisions battery cameras (set `0` to
  disable). No code changes. (#45)

## [0.7.15]

### Fixed
- **Battery cameras (A001513/A001108/A001360, e.g. the L2 models) produced no live
  media.** They rejected every MQTT `livePlayReq` with code `-50019` ("not ready")
  and never ran ICE - even fresh-rebooted, app-closed, and uncontended - while
  mains cameras of the same model streamed fine. Root cause: the official app
  performs a cloud pre-connect the library skipped (`KVSPreConnectStrategy.
  fetchKvsParams` -> `POST /api/ipc/liveStream/liveStreamParam`) that provisions the
  live-stream session and brings the camera online before signaling. The library
  now makes that call for battery cameras at the start of the open path; the
  existing MQTT/SDES signaling then succeeds and decrypted RTP flows. Best-effort,
  gated on `is_battery_camera` (mains/DTLS unaffected), disable via
  `AIDOT_LIVESTREAM_PARAM=0`. (#43)

> Validated live on an A001513 battery camera: stream opens in ~16s and media flows
> for the full session; previously persistent `-50019` / zero media. 5 unit tests
> lock the request shape.

## [0.7.14]

### Changed
- **Jittered reconnect backoff** (`next_backoff` in `camera/protocol.py`): the SDES
  keepalive, JPEG streaming, and DTLS serve loops now use equal-jitter exponential
  backoff (with a hard floor at each loop's existing minimum) instead of a lockstep
  `delay *= 2`. Randomized spread stops a degraded camera - or a fleet reconnecting
  at once - from synchronizing into reconnect storms / cloud rate-limiting. The
  loops also escalate backoff only when a session opens but never delivers media
  (the camera-degradation case) and reset after a session that streamed; the
  decrypted-RTP liveness watchdog still drives *when* to restart. (#41)

> 7 new unit tests (`tests/test_backoff.py`). Validated live: all three DTLS
> cameras and a mains SDES camera re-establish through the rewired loops.

## [0.7.13]

### Fixed
- **SDES H.265 streaming recorded 0-byte video** (#39): SDES cameras stream H.264
  (pt=96) *or* H.265 (pt=97), varying per session, but the generated SDP listed
  both (`m=video ... 96 97`) - so ffmpeg bound its depacketizer to the first
  payload type (H.264) and silently dropped the camera's H.265 packets. The
  bridge now records the camera's actual video payload type on the first video
  RTP packet and narrows the ffmpeg SDP to that single codec before launch
  (falling back to the dual-codec SDP if no video is observed). This fixes the
  ffmpeg-fallback path for installs without go2rtc; go2rtc handles H.265 natively
  on the preferred path (0.7.12, #37).

> Validated live against a real SDES (A001513) camera: ~490 KB recorded on the
> first attempt with the camera answering H.265.

## [0.7.12]

### Added
- **Prefer-go2rtc serve with ffmpeg fallback** (`aidot/camera/go2rtc.py`): when a
  go2rtc server is reachable, the camera's local serve URL is registered as a
  go2rtc stream so go2rtc handles low-latency WebRTC delivery and native
  H.264/H.265 depacketization; when go2rtc is absent the existing ffmpeg serve
  (e.g. Home Assistant HLS) is used unchanged. `start_keepalive(go2rtc_url=...)`
  registers the stream, `stream_rtsp_url` prefers the go2rtc pull URL, and the
  stream is deregistered on stop. Best-effort throughout - go2rtc errors never
  break the fallback path. (#37)
- `scripts/go2rtc_serve.py`: dev harness that drives the go2rtc serve path
  without Home Assistant.

### Fixed
- **SDES streaming no-media on late ICE nomination**: a late USE-CANDIDATE now
  nominates both the audio *and* video sockets (previously only one), so video
  RTP reaches the bridge. Validated live (5.5 MB recording). (#36)

### Changed
- Finished decomposing the monolithic `camera/client.py` into focused modules
  (data models + TUTK session, playback/WebRTC sessions, SDES session,
  device-control setter mixin, stateless protocol helpers, SDP transforms).
  Behavior-preserving: all existing imports keep working via re-exports. (#29-#35)

> Validated live end-to-end through a real go2rtc server (camera -> library serve
> -> go2rtc -> ffprobe: H.264 1280x720 + AAC) in addition to the mocked unit suite
> (`tests/test_go2rtc.py`, 8 cases).

## [0.7.11]

### Changed
- Began splitting the monolithic `camera/client.py`: wire/protocol constants now
  live in `aidot/camera/constants.py` and are re-imported into `client.py`
  (behavior-preserving; all existing imports keep working).
- Renamed the worst cryptic private STUN/TURN helper closures for readability
  (`_mi_ta` -> `_stun_message_integrity`, `_br_a`/`_si_a` -> `_build_stun_attr`,
  `_rr_accept_cam_cert` -> `_accept_camera_cert`). No behavior change.

### Fixed
- `GETSTREAMCTRL_CMD` is re-exported from `aidot.camera.client` again (it is the
  public pair of `SETSTREAMCTRL_CMD`); the constants extraction had dropped it.
- Corrected a debug-log function-name label that the rename pass had rewritten.

### Added
- `scripts/smoke_stream.py`: manual on-hardware smoke test that logs in,
  enumerates cameras, and briefly streams them (DTLS + SDES paths), reporting
  frames/recorded bytes per camera.

### Internal
- Moved `cleanup-branches.sh` into `scripts/`.

> Validated live against real cameras (DTLS A000088 and SDES A001064) in addition
> to the mocked unit suite.

## [0.7.10]

### Added
- PEP 561 `py.typed` marker so consumers' type checkers use the library's hints.
- README "Environment variables" reference documenting every `AIDOT_*` knob.
- Non-blocking `mypy` and coverage reporting in CI.

### Changed
- `camera/client.py`: added diagnosable `debug(..., exc_info=True)` logging to 93
  previously-silent exception handlers; proactive ffmpeg-presence guards with
  actionable errors; `XDG_CONFIG_HOME` support for the sprop cache.
- `credentials.py` honors `XDG_CONFIG_HOME`; `discover.py` resolves network tools
  via `PATH` and degrades gracefully instead of raising.
- Translated remaining non-English source comments to English; added docstrings
  to the public `DeviceClient` / `AidotClient` / `Discover` APIs.
- Modernized tooling: ruff-based pre-commit (replacing a stale 2019 config) and
  `ruff check` in CI.

### Fixed
- Corrected the distribution name / repository URLs in the README install
  commands and project metadata.
