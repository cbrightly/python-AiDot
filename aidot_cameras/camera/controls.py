"""Camera device-control methods, split out of CameraMixin.

A behavior-preserving mixin holding the high-level control setters (lights,
siren, mic, LED, night-vision, PTZ, resolution, etc.). They issue commands via
the inherited async_set_device_attribute / async_trigger_device_action, so this
mixin must be combined into CameraMixin (it is not usable standalone).
"""

import logging
import struct

from typing import Optional

from .constants import _PTZ_DIR_CODES, _STREAM_QUALITY, SETSTREAMCTRL_CMD

_LOGGER = logging.getLogger(__name__)

#: How the floodlight behaves when the camera sees someone, by the name the
#: vendor app prints against each value. From the cloud device profile
#: (LK.IPC.A001513): ``lightBehavior`` is an enum with allowedValues
#: ``Constant=0, Flash=1``, default 0.
LIGHT_BEHAVIORS = {"constant": 0, "flash": 1}

#: How long the floodlight stays on after it triggers, in seconds. The camera
#: enumerates exactly these four (``LingerDuration``, default 30) -- it is not a
#: free range, and a value outside the set is accepted on the wire and ignored,
#: which would leave a control reporting a setting the camera never applied.
LIGHT_LINGER_DURATIONS = (20, 30, 40, 50)

#: The floodlight level the camera accepts (``Dimming``: min 10, max 100).
#: The floor is 10, not 0: 0 is out of range rather than "off", and off is
#: LightOnOff.
LIGHT_BRIGHTNESS_MIN = 10
LIGHT_BRIGHTNESS_MAX = 100

#: The camera's ack for SETSTREAMCTRL (800).
SETSTREAMCTRL_RESP_CMD = 801
#: Measured 0.01-0.03s; short so a control call never holds up a view.
_SETSTREAMCTRL_ACK_S = 1.5


class _CameraControlsMixin:
    """Device-control setters mixed into CameraMixin."""

    async def async_set_motion_detection(self, enabled: bool) -> bool:
        """Enable or disable the camera's motion detection."""
        # MotionDetection_Enable is read as getString() in IpcServiceImpl -> use str
        return await self.async_set_device_attribute(
            "MotionDetection_Enable", "1" if enabled else "0")

    async def async_set_floodlight(self, on: bool, brightness: int = 100) -> bool:
        """Turn the floodlight on/off (with optional 0-100 brightness)."""
        # Confirmed 2026-05-05: cameras with autoLightEnable=1 (A001064 PTZ, A000088) ignore
        # manual LightOnOff commands unless auto-light is disabled first.
        # Turning on: disable auto-light, set LightOnOff=1 (and optional Dimming).
        # Turning off: set LightOnOff=0 only (leave autoLightEnable as-is so the
        # camera can resume auto mode on its own schedule).
        if on:
            # Fire prereq without blocking - 1.5s is enough to catch most ACKs but
            # we don't need confirmation before sending LightOnOff.
            await self.async_set_device_attribute("autoLightEnable", 0, timeout=1.5)
        ok = await self.async_set_device_attribute("LightOnOff", 1 if on else 0)
        if ok and on and brightness != 100:
            await self.async_set_device_attribute(
                "Dimming", max(0, min(100, brightness)))
        return ok

    async def async_set_status_led(self, enabled: bool) -> bool:
        """Turn the camera's status LED on or off."""
        return await self.async_set_device_attribute("LedOnOff", 1 if enabled else 0)

    async def async_set_osd_timestamp(self, enabled: bool) -> bool:
        """Show or hide the timestamp overlay burned into the video (OSDEnable)."""
        return await self.async_set_device_attribute("OSDEnable", 1 if enabled else 0)

    async def async_set_auto_light(self, enabled: bool) -> bool:
        """Turn the light-up-when-someone-appears automation on or off.

        This is ``autoLightEnable``, which the vendor app labels "When Someone
        Appears" (or "When Someone Appears at Night" on some models -- that is
        which label the app prints for the model, not a separate setting).
        """
        return await self.async_set_device_attribute(
            "autoLightEnable", 1 if enabled else 0)

    async def async_set_light_behavior(self, behavior: str) -> bool:
        """Set how the light behaves when it triggers: "constant" or "flash".

        This looked for a while like an attribute the camera would not accept:
        the write acked and the value never moved, across both models, as int
        and as string, armed and disarmed. It was none of those. A battery
        camera was never given time to wake before the command arrived behind
        its own wake, and every one of those attempts went to a sleeping
        camera. Fixed in ``1.0.0rc18``; the write now lands on a sleeping
        camera, verified by read-back.

        Only the A001513 declares ``lightBehavior`` in its model profile. An
        A000088 carries a value for it in the cloud's property list and, asked
        directly over LAN, has no such attribute at all - so a control must be
        gated on the profile, not on a reported value.

        Refuses a name the camera does not offer rather than sending it: the
        attribute is an enum, and an out-of-range write is accepted silently.
        """
        try:
            value = LIGHT_BEHAVIORS[behavior]
        except KeyError:
            raise ValueError(
                f"unknown light behavior {behavior!r}; "
                f"expected one of {sorted(LIGHT_BEHAVIORS)}") from None
        return await self.async_set_device_attribute("lightBehavior", value)

    async def async_set_light_linger_duration(self, seconds: int) -> bool:
        """Set how long the light stays on after it triggers, in seconds."""
        if seconds not in LIGHT_LINGER_DURATIONS:
            raise ValueError(
                f"unsupported linger duration {seconds!r}; "
                f"the camera offers {list(LIGHT_LINGER_DURATIONS)}")
        return await self.async_set_device_attribute("LingerDuration", seconds)

    async def async_set_light_brightness(self, level: int) -> bool:
        """Set the floodlight level (10-100), clamped to what the camera takes.

        Separate from :meth:`async_set_floodlight`'s optional brightness, which
        is part of turning the light on by hand; this is the level the camera
        uses when its own automation fires.
        """
        return await self.async_set_device_attribute(
            "Dimming",
            max(LIGHT_BRIGHTNESS_MIN, min(LIGHT_BRIGHTNESS_MAX, int(level))))

    async def async_set_voice_prompts(self, enabled: bool) -> bool:
        """Enable or disable spoken prompts from the camera speaker (voiceEnable)."""
        return await self.async_set_device_attribute(
            "voiceEnable", 1 if enabled else 0)

    async def async_set_hdr(self, enabled: bool) -> bool:
        """Enable or disable HDR (HDRStatus)."""
        return await self.async_set_device_attribute("HDRStatus", 1 if enabled else 0)

    async def async_set_microphone(self, enabled: bool) -> bool:
        """Enable or disable the camera's microphone."""
        # micEnable: 1=on (default), 0=off
        return await self.async_set_device_attribute("micEnable", 1 if enabled else 0)

    async def async_set_speaker_volume(self, level: int) -> bool:
        """Set the camera's speaker volume (0-100, clamped)."""
        return await self.async_set_device_attribute(
            "SoundLevel", max(0, min(100, level)))

    async def async_set_siren(self, on: bool) -> bool:
        """Turn the camera's siren on or off."""
        # Siren uses devActionReq(action="playSound", in=[on,1,30])
        # in[0]=1/0, in[1]=type?, in[2]=duration seconds
        # No attr notification comes back - track state locally.
        result = await self.async_trigger_device_action(
            "playSound", [1 if on else 0, 1, 30])
        self.status.siren = on
        return result

    #: Sound-detection algorithms, in the order the camera reports them. The
    #: camera answers ``soundAlgorithmGet`` with a list of single-key dicts --
    #: ``[{"sound_enable": 0}, {"glass_Break": 0}, {"smoke_T3": 0}, ...]`` --
    #: so the key names come from the camera rather than from us. The vendor
    #: app's own strings name baby_cry and dog_bark alongside these.
    #: ``sound_enable`` is the master switch; the rest are individual detectors.
    SOUND_MASTER_KEY = "sound_enable"

    async def async_get_sound_detection(self) -> "Optional[dict]":
        """Which sound detectors are armed, as ``{key: bool}``.

        ``None`` means the camera did not answer -- unknown, NOT all-off. A
        model that does not implement this replies with a null ``out``, and
        reporting that as a set of disabled switches would invent a state the
        camera never claimed.
        """
        out = await self.async_query_device_action("soundAlgorithmGet")
        if not isinstance(out, list):
            return None
        flags: dict = {}
        for item in out:
            if isinstance(item, dict):
                for key, value in item.items():
                    flags[key] = bool(value)
        return flags or None

    async def async_set_sound_detection(self, key: str, enabled: bool) -> bool:
        """Arm or disarm one sound detector.

        Read-modify-write: the camera is asked for the current list and gets
        the same structure back with one flag changed. The alternative is
        inventing a payload schema for ``soundAlgorithmSet``, and the camera
        reports the shape it wants -- so echo it rather than guess it.
        """
        out = await self.async_query_device_action("soundAlgorithmGet")
        if not isinstance(out, list):
            _LOGGER.warning(
                "sound detection: %s did not report its algorithms; not writing",
                self.device_id)
            return False
        found = False
        payload = []
        for item in out:
            if isinstance(item, dict) and key in item:
                payload.append({key: 1 if enabled else 0})
                found = True
            else:
                payload.append(item)
        if not found:
            _LOGGER.warning("sound detection: %s does not report %r", self.device_id, key)
            return False
        return await self.async_trigger_device_action("soundAlgorithmSet", payload)

    #: Detection types the camera reports under ``getRoiHuman``.  Names come
    #: from the camera, not from us -- probed 2026-09-07 on an A000088 and an
    #: A001064, both of which answer with all five.  ``publicZone`` is in the
    #: same dict but is not a detection type; it is carried through untouched.
    DETECTION_TYPE_KEYS = ("humanDetect", "vehicleDetect", "packageDetect",
                           "petDetect")

    async def async_get_detection_types(self) -> "Optional[dict]":
        """Which detection types are armed, as ``{key: bool}``.

        ``None`` means the camera did not answer -- unknown, NOT all-off.  A
        battery A001513 answers nothing at all (measured: a null ``out`` for
        every one of these actions, because it is asleep), and rendering that
        as four switched-off detectors would claim a state it never reported.
        """
        out = await self.async_query_device_action("getRoiHuman")
        roi = (out or {}).get("roi") if isinstance(out, dict) else None
        if not isinstance(roi, list) or not roi or not isinstance(roi[0], dict):
            return None
        return {k: bool(v) for k, v in roi[0].items()}

    async def async_set_detection_type(self, key: str, enabled: bool) -> bool:
        """Arm or disarm one detection type.

        Read-modify-write against the camera's own dict, like
        ``async_set_sound_detection``.  Echoing the structure back matters more
        here than it does for sound: the same dict carries ``publicZone``, which
        is a real per-camera setting (0 on one model and 1 on another in the
        same probe), so rebuilding the payload from our own key list would
        silently reset a setting we do not model.
        """
        out = await self.async_query_device_action("getRoiHuman")
        roi = (out or {}).get("roi") if isinstance(out, dict) else None
        if not isinstance(roi, list) or not roi or not isinstance(roi[0], dict):
            _LOGGER.warning(
                "detection types: %s did not report its ROI; not writing",
                self.device_id)
            return False
        current = roi[0]
        if key not in current:
            _LOGGER.warning("detection types: %s does not report %r",
                            self.device_id, key)
            return False
        payload = dict(current)
        payload[key] = 1 if enabled else 0
        return await self.async_trigger_device_action(
            "setRoiHuman", {"roi": [payload]})

    #: The siren's automatic trigger.  ``autoAlarm`` is the master; the other
    #: two say what sets it off.  Probed 2026-09-07: NOT a mirror of anything
    #: else we expose -- on an A000088 ``motionDetection`` read 0 while the
    #: camera's own motion-detection setting read True, and on an A001064
    #: ``humanDetect`` read 0 while ``getRoiHuman``'s read 1.
    AUTO_ALARM_KEYS = ("autoAlarm", "motionDetection", "humanDetect")

    async def async_get_auto_alarm(self) -> "Optional[dict]":
        """Siren auto-trigger settings as ``{key: bool}``.

        ``None`` means the camera did not answer -- unknown, NOT all-off.
        Reporting an unanswered camera as three disarmed switches would claim a
        state it never gave, and this is the setting that decides whether a
        siren goes off in someone's house.
        """
        out = await self.async_query_device_action("getAutoAlarm")
        if not isinstance(out, list) or not out or not isinstance(out[0], dict):
            return None
        return {k: bool(v) for k, v in out[0].items()}

    async def async_set_auto_alarm(self, key: str, enabled: bool) -> bool:
        """Arm or disarm the siren's automatic trigger, or one of its causes.

        Read-modify-write against the camera's own object.  That matters more
        here than anywhere else: rebuilding the payload from our own key list
        could arm ``autoAlarm`` as a side effect of changing a trigger, which
        would make a camera start sounding a siren nobody asked it to.
        """
        out = await self.async_query_device_action("getAutoAlarm")
        if not isinstance(out, list) or not out or not isinstance(out[0], dict):
            _LOGGER.warning(
                "auto alarm: %s did not report its settings; not writing",
                self.device_id)
            return False
        current = out[0]
        if key not in current:
            _LOGGER.warning("auto alarm: %s does not report %r",
                            self.device_id, key)
            return False
        payload = dict(current)
        payload[key] = 1 if enabled else 0
        return await self.async_trigger_device_action("setAutoAlarm", [payload])

    async def async_get_wifi_info(self) -> "Optional[dict]":
        """``{"ssid": str, "rssi": int}`` for the camera's own WiFi link.

        The camera answers ``WifiBaseInfo`` with a positional list whose first
        two entries are the SSID and signal strength. Only those two are named
        here -- the third is an integer that looks like an encoded address, and
        naming a field we have not confirmed is how a guess becomes a fact.
        """
        out = await self.async_query_device_action("WifiBaseInfo")
        if not isinstance(out, list) or not out:
            return None
        info: dict = {"ssid": out[0] if isinstance(out[0], str) else None}
        if len(out) > 1 and isinstance(out[1], (int, float)):
            info["rssi"] = int(out[1])
        return info

    async def async_get_sd_card_info(self) -> "Optional[dict]":
        """``{"present": bool, "total": int, "used": int, "raw": list}``.

        ``SDcardBaseInfo`` answers positionally: ``[False, 0, 0, 0, 0]`` with no
        card, ``[True, 29838, 28848, 3, ...]`` on a nearly-full one.

        Only the first three fields are named. The fourth was almost called
        "free" -- but 29838 - 28848 is 990, not 3, so it is not a remainder;
        28848/29838 is 96.7%, which makes 3 look like a percentage. "Looks
        like" is not confirmation, so it stays unnamed in ``raw`` rather than
        shipping a field that reports 3 MB free on a 30 GB card.

        Units for ``total`` and ``used`` are unconfirmed too (MB is plausible
        at these magnitudes), so the numbers are passed through exactly as the
        camera reports them rather than converted.
        """
        out = await self.async_query_device_action("SDcardBaseInfo")
        if not isinstance(out, list) or not out:
            return None
        def _n(i):
            return int(out[i]) if len(out) > i and isinstance(out[i], (int, float)) else None
        return {"present": bool(out[0]), "total": _n(1), "used": _n(2),
                "raw": list(out)}

    async def async_reboot(self) -> bool:
        """Ask the camera to reboot. True means the request was SENT.

        The vendor app's camera settings page does exactly this -- its H5
        bundle calls ``devActionReq({action: "RebootFunc", in: []})`` -- and
        ``RebootFunc`` also appears in the native ``NewLivePresenter``. It is
        the same ``devActionReq`` transport the siren already uses.

        Two deliberate choices:

        * **No ack is awaited.** A reboot succeeds by taking the camera off the
          network, so a camera that reboots before answering would otherwise be
          reported as a failure. The app passes no timeout for this action
          either, unlike the reads beside it. So this reports "requested", and
          the caller must not read it as "rebooted".
        * **Refused when the cloud says the camera is offline.** The app only
          renders its reboot button when the device is reachable
          (``isCanUseStatus``), and a wake-then-reboot on a sleeping battery
          camera is not something to fire blind.

        The camera is gone for about a minute afterwards (the app's own wording
        is "The device Needs a minute to reboot"), during which a viewer sees a
        session that connects and delivers nothing.
        """
        if (not self.status.online) and getattr(self, "_cloud_online_explicit", False):
            _LOGGER.warning(
                "reboot refused for %s: the cloud reports it offline", self.device_id)
            return False
        _LOGGER.info("reboot requested for %s", self.device_id)
        return await self.async_trigger_device_action(
            "RebootFunc", [], expect_ack=False)

    async def async_set_night_vision(self, mode: str) -> bool:
        """mode: 'auto' (0), 'on' (1), 'off' (2)"""
        _modes = {"auto": 0, "on": 1, "off": 2}
        value = _modes.get(mode.lower())
        if value is None:
            raise ValueError(f"Invalid night vision mode: {mode!r}. Expected 'auto', 'on', or 'off'.")
        return await self.async_set_device_attribute("nightVisionMode", value)

    async def async_set_ptz_tracking(self, enabled: bool) -> bool:
        """Enable or disable PTZ motion auto-tracking."""
        return await self.async_set_device_attribute(
            "trackingMode", 1 if enabled else 0)

    async def async_set_motion_sensitivity(self, level: int) -> bool:
        """Set motion detection sensitivity.

        level: 1 (lowest) - 5 (highest).
        Attribute: MotionDetection_Sen (observed value '2' on A000088).
        """
        return await self.async_set_device_attribute(
            "MotionDetection_Sen", max(1, min(5, int(level))))

    async def async_set_ir_light(self, enabled: bool) -> bool:
        """Control the IR illumination LEDs independently of night-vision mode.

        Attribute: nightVisionIRLight (0=off, 1=on).
        Note: nightVisionMode still controls the IR cut filter / B&W switch.

        **This does not take on the A000088.** Measured 2026-08-14 by read-back
        over the local control channel on both A000088 units on the reference
        fleet: the write is acknowledged and the attribute keeps its previous
        value. That is ordinary for this firmware - eight of fourteen
        attributes probed the same day behaved the same way - and it is why the
        reference integration offers no IR-light switch. No model has been
        found where a read-back confirms it. The call is kept because the
        attribute is real and another model may honour it; do not assume a
        `True` return means the camera changed anything.
        """
        return await self.async_set_device_attribute(
            "nightVisionIRLight", 1 if enabled else 0)

    async def async_ptz_move(
        self,
        direction: str,
        speed: int = 4,
        preset: int = 0,
    ) -> bool:
        """Send a PTZ pan/tilt/zoom command.

        direction: "up"|"down"|"left"|"right"|"stop"|"goto"|
                   "zoom_in"|"zoom_out"
        speed:     0-255, default 4 (matches app default)
        preset:    preset slot for "goto" command

        Source: a.java d1() / f0.java A2() -> avSendIOCtrl(4097, 8B payload)
        Payload: [direction_code, speed, preset, 0, 0, 0, 0, 0]

        Direction codes (AVIOCTRLDEFs.java):
          STOP=0, UP=1, DOWN=2, LEFT=3, RIGHT=6
          LEFT_UP=4, LEFT_DOWN=5, RIGHT_UP=7, RIGHT_DOWN=8
          GOTO_POINT=12, SET_POINT=10, ZOOM_IN=23, ZOOM_OUT=24
        """
        code = _PTZ_DIR_CODES.get(direction.lower())
        if code is None:
            _LOGGER.error("async_ptz_move: unknown direction %r", direction)
            return False

        # A True return means the frame reached the channel, not that the camera
        # moved - there is no ack and no position feedback. That caveat stands,
        # but PTZ itself WORKS: measured 2026-08-15 on the reference A001064 at
        # speeds 4 and 200, mean frame difference 25.2 and 38.6 across a 5 s pan
        # against a no-command control of 2.6 on the same session and timings.
        #
        # Two earlier readings called it inert and both were instrument
        # failures: the camera-proxy still is cached (byte-identical across
        # presses) and short repeated go2rtc pulls return near-identical
        # keyframes. Compare frames from WITHIN one session recording, and
        # always run the no-command control - without it, "the picture changed"
        # and "twenty seconds passed" are the same measurement.
        payload = bytes([code, min(255, max(0, speed)), preset, 0, 0, 0, 0, 0])
        session = self._stream_session
        if session is None:
            _LOGGER.warning("async_ptz_move: no active stream session")
            return False
        ok = session._avio_cmd(4097, payload)
        _LOGGER.debug(
            "PTZ %s (code=%d speed=%d preset=%d) -> %s",
            direction, code, speed, preset, "sent" if ok else "no channel yet",
        )
        return ok

    async def async_ptz_stop(self) -> bool:
        """Send PTZ stop command (direction_code=0, speed=0)."""
        return await self.async_ptz_move("stop", speed=0)

    async def async_set_resolution(self, quality: str) -> bool:
        """Switch the live-stream resolution.

        quality: "hd" (AVIOCTRL_QUALITY_MAX) or "sd" (AVIOCTRL_QUALITY_MIDDLE),
        mirroring the official app's HD/SD toggle.  Rides the active stream
        session (SETSTREAMCTRL=800), so the camera must be streaming.

        The choice is REMEMBERED and re-sent whenever a session next starts.
        Without that it was simply dropped when nothing was streaming - and
        since a camera is idle far more often than not, the usual outcome of
        changing this was nothing at all, while the caller was told the setting
        had been applied. Nothing else re-sent it, so "it will apply on the next
        session" was not true of any code path.

        **On the A001064 this is acked and inert - it does not change the
        rate, on either codec.** Measured 2026-08-23 with the framing gap
        closed (1.0.0b27, so the AVIO header including the live-play dSeq is
        byte-identical to the app's), in-session with a control arm that waits
        the same gap and sends nothing: sd 0.885 against control 0.863, where
        a working SD is about 2:1. Re-measured the same night on the H265
        encode specifically - the codec the vendor app's working toggle rides -
        because every earlier measurement had landed on H264 sessions: hd on
        H265 scored 0.703 against controls at 0.743-0.776. Inert there too. The camera answers `801 payload=0000000000000000` every time. The
        vendor app's own SD tap DOES halve the rate on the same camera, so this
        is not a firmware that cannot do SD; we cannot trigger it. See
        docs/ROAD-TO-1.0.md item 2 for the full record, including the five
        other bitrate controls that turned out to be dead and the codec
        difference that is worth about the same 2:1.

        The call is kept because it is correct, it is what the app sends, and
        other models are not covered by that measurement. Callers should not
        rely on it changing the bitrate.

        Source: f0.java g3() -> X2(800, SetStreamCtrlReq.parseContent(0, quality)).
        Payload <IB3x> = channel(0) + quality byte + 3 reserved.
        The app has three settings, not two: Auto, SD and HD, which
        `NewLivePresenter.setDefaultResolution` maps from the persistent
        `props.StreamType` property to quality 16, 5 and 1. This library
        implements only hd=1 and sd=5; 16 (Auto) was swept and did nothing, and
        `StreamType` itself is acked-and-ignored on every write.
        """
        q = _STREAM_QUALITY.get(quality.lower())
        if q is None:
            _LOGGER.error("async_set_resolution: unknown quality %r", quality)
            return False
        self._desired_quality = quality.lower()
        payload = struct.pack("<IB3x", 0, q)
        session = self._stream_session
        if session is None:
            _LOGGER.info(
                "resolution %s remembered; the camera is not streaming, so it "
                "will be applied when a session next starts", quality)
            return True
        # Ask, and read what comes back.  The camera acks with 801 in
        # 0.01-0.19s and reports the new value through GETSTREAMCTRL afterwards
        # (where it implements 802), so the command is genuinely accepted - it
        # simply does not change the encode.
        #
        # Settled 2026-08-07 across both transports and every value the enum
        # defines, not just hd/sd: an A001064 was swept over all six
        # AVIOCTRL_QUALITY values, each followed by a session that sent nothing
        # to catch a setting that applies only to the NEXT session. Twelve
        # sessions, twelve times h264 1280x720, no dimension change in any of
        # them. Four of those values had never been sent to any camera here.
        # See docs/APP-PARITY-STATUS.md for the table.
        #
        # The RETURN value deliberately still means "the command went out". An
        # A001064 answers SPEAKERSTART but does not implement GETSTREAMCTRL at
        # all, so how much a given firmware answers is model-dependent, and
        # turning silence into a failure would break this call on exactly the
        # quieter cameras. Reading the reply is what we could not do before; it
        # makes a refusal visible instead of indistinguishable from success.
        reply = await session.async_avio_request(
            SETSTREAMCTRL_CMD, payload,
            response_cmd=SETSTREAMCTRL_RESP_CMD, timeout=_SETSTREAMCTRL_ACK_S,
        )
        if reply is None:
            _LOGGER.debug(
                "set resolution %s (quality=%d): sent, no ack within %.1fs",
                quality, q, _SETSTREAMCTRL_ACK_S,
            )
        else:
            _LOGGER.debug(
                "set resolution %s (quality=%d): camera acked %d payload=%s",
                quality, q, reply.command, reply.payload.hex() or "<empty>",
            )
        return True

    def _apply_pending_resolution(self) -> None:
        """Re-send the remembered resolution now that a session exists.

        Called when a stream session becomes active. Best-effort and silent on
        failure: a stream that is up matters more than a quality preference, so
        this must never be able to disturb it.
        """
        quality = getattr(self, "_desired_quality", None)
        if not quality:
            return
        q = _STREAM_QUALITY.get(quality)
        session = self._stream_session
        if q is None or session is None:
            return
        try:
            if session._avio_cmd(SETSTREAMCTRL_CMD, struct.pack("<IB3x", 0, q)):
                _LOGGER.debug("re-applied remembered resolution %s", quality)
        except Exception:
            _LOGGER.debug("could not re-apply resolution %s", quality, exc_info=True)
