"""Camera data models, split out of client.py (behavior-preserving).

CameraStatusData / CameraDeviceInformation extend the core DeviceStatusData /
DeviceInformation; VideoFrame is the decoded-frame container. Re-exported from
client.py so existing imports keep working.
"""

import json
import logging
from dataclasses import dataclass
from typing import Any, Optional

from ..const import (
    CONF_CCT,
    CONF_DIMMING,
    CONF_ON_OFF,
    CONF_PRODUCT,
    CONF_PROPERTIES,
    CONF_RGBW,
    CONF_SERVICE_MODULES,
)
from ..device_client import DeviceInformation, DeviceStatusData
from .constants import (
    _FRAME_TYPE_AUDIO,
    _FRAME_TYPE_B_FRAME,
    _FRAME_TYPE_I_FRAME,
    _FRAME_TYPE_P_FRAME,
)

_LOGGER = logging.getLogger(__name__)


def _as_int(v: Any) -> Optional[int]:
    """Coerce a cloud-supplied attr value to int, or None if not numeric.

    Cloud/device attributes are untrusted: a non-numeric value must be skipped,
    not raise ValueError/TypeError out of the status-refresh path.
    """
    try:
        return int(v)
    except (ValueError, TypeError):
        return None


def _as_bool(v: Any) -> Optional[bool]:
    """Coerce a 0/1 (int or numeric string) attr to bool, or None if not numeric."""
    i = _as_int(v)
    return None if i is None else bool(i)


def _card_present(attr: dict) -> Optional[bool]:
    """Is an SD card in the slot? None means nobody said.

    Three states, and the third is the point. Of seven cameras measured
    2026-08-12, one reported ``SDcardExistFlag: true``, two reported ``false``,
    and four carried neither key - including an A000088, the same model as all
    three that did report. So a missing key cannot mean "this model cannot say";
    it means we do not know, and anything that reads it as "no card" would tell
    someone with a working camera that their slot is empty.

    ``SDcardExistFlag`` wins where it exists. ``SDcardBaseInfo`` is the fallback
    and arrives as a STRING holding a JSON array - element 0 agreed with the
    flag on every camera carrying both. The other four positions are not
    decoded: ``30432`` is plausibly a 32 GB card's total MB and plausibly
    something else, and a guess does not belong in a public data model.
    """
    if "SDcardExistFlag" in attr:
        flag = _as_bool(attr.get("SDcardExistFlag"))
        if flag is not None:
            return flag

    raw = attr.get("SDcardBaseInfo")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return None
    if isinstance(raw, (list, tuple)) and raw:
        return _as_bool(raw[0])
    return None


class CameraStatusData(DeviceStatusData):
    """Core status plus camera fields; accepts both typed-model and dict updates."""

    # Restore None-as-unknown semantics: the core defaults (red/2700K/100)
    # would otherwise be pushed to consumers as real state before the first
    # getDevAttrReq reply arrives.
    rgdb: "int | None" = None
    rgbw: "tuple[int, int, int, int] | None" = None
    cct: "int | None" = None
    dimming: "int | None" = None

    # Camera-specific fields (None = unknown/not yet queried)
    motion_detection: Optional[bool] = None
    motion_sensitivity: Optional[int] = None  # MotionDetection_Sen 1-5
    status_led: Optional[bool] = None
    #: Timestamp/OSD overlay burned into the video (OSDEnable).
    osd_timestamp: Optional[bool] = None
    #: Floodlight automation (autoLightEnable). The vendor app labels this
    #: "When Someone Appears" -- it is the person-triggered light, not a
    #: generic schedule, and the three fields below are its settings.
    auto_light: Optional[bool] = None
    #: How the light behaves when it triggers: "constant" or "flash"
    #: (lightBehavior 0/1). An unmodelled number is carried through as itself.
    light_behavior: Optional[str] = None
    #: How long the light stays on after a trigger, in seconds (LingerDuration).
    light_linger_duration: Optional[int] = None
    #: Floodlight level 10-100 (Dimming). Kept apart from `dimming`, which is
    #: the light platform's brightness -- see _LIGHT_ONLY_ATTR_KEYS.
    light_brightness: Optional[int] = None
    #: Spoken prompts from the camera speaker (voiceEnable).
    voice_prompts: Optional[bool] = None
    #: HDR (HDRStatus).
    hdr: Optional[bool] = None
    microphone: Optional[bool] = None
    night_vision_mode: Optional[str] = None   # "auto" | "on" | "off"
    ir_light: Optional[bool] = None           # nightVisionIRLight 0/1
    floodlight: Optional[bool] = None
    ptz_tracking: Optional[bool] = None
    siren: bool = False
    speaker_volume: Optional[int] = None  # SoundLevel 0-100
    # Diagnostic / read-only camera fields
    battery_remaining: Optional[int] = None  # Battery_remaining 0-100 (%)
    occupancy: Optional[bool] = None          # Occupancy live presence
    sd_card_status: Optional[str] = None      # SDcardStatus
    # Tri-state: True in the slot, False slot empty, None nobody said. Reads
    # INVERTED on A000088 relative to sd_card_status ("0" with a card, "1"
    # without, 3/3) - which is why sd_card_status is not used for this and the
    # two are kept apart. That inversion has no corroboration off A000088.
    sd_card_present: Optional[bool] = None    # SDcardExistFlag/SDcardBaseInfo[0]
    wifi_rssi: Optional[int] = None           # networkRssi (dBm), cloud property

    def update(self, attr) -> None:
        if attr is None:
            return
        if not isinstance(attr, dict):
            # Typed DeviceAttr model from the core local-control receive path.
            # Guard: a malformed payload.attr (non-dict, non-model) must not
            # kill the caller's receive loop.
            if not hasattr(attr, "OnOff"):
                return
            super().update(attr)
            return
        # Dict path: camera attributes ONLY.  Light keys (OnOff/Dimming/RGBW/
        # CCT) are handled by the typed-model path in the core; the dict
        # feeders either strip them (update_from_camera_attributes) or have
        # already applied them via the model (receive_data raw-dict pass).
        # Camera attributes
        # Every conversion goes through _as_int/_as_bool so a malformed value
        # from the cloud (e.g. "on" where 0/1 is expected) is skipped rather than
        # raising out of update() and aborting the whole status refresh.
        if (b := _as_bool(attr.get("MotionDetection_Enable"))) is not None:
            self.motion_detection = b
        if (i := _as_int(attr.get("MotionDetection_Sen"))) is not None:
            self.motion_sensitivity = i
        if (b := _as_bool(attr.get("LedOnOff"))) is not None:
            self.status_led = b
        # Only on an actual reading, like every field here: attribute pushes
        # are partial, so a motion notif carrying none of these keys must not
        # clear what the last full poll established.
        if (b := _as_bool(attr.get("OSDEnable"))) is not None:
            self.osd_timestamp = b
        if (b := _as_bool(attr.get("autoLightEnable"))) is not None:
            self.auto_light = b
        if (v := attr.get("lightBehavior")) is not None:
            lb = _as_int(v)
            # Same shape as nightVisionMode: name the values we know and carry
            # anything else through, so a firmware that grows a third mode
            # cannot be reported as one of the two we do know.
            self.light_behavior = (
                {0: "constant", 1: "flash"}.get(lb, str(lb))
                if lb is not None else str(v))
        if (i := _as_int(attr.get("LingerDuration"))) is not None:
            self.light_linger_duration = i
        if (b := _as_bool(attr.get("voiceEnable"))) is not None:
            self.voice_prompts = b
        if (b := _as_bool(attr.get("HDRStatus"))) is not None:
            self.hdr = b
        if (b := _as_bool(attr.get("micEnable"))) is not None:
            self.microphone = b
        if (v := attr.get("nightVisionMode")) is not None:
            nv = _as_int(v)
            if nv is not None:
                self.night_vision_mode = {0: "auto", 1: "on", 2: "off"}.get(nv, str(nv))
            else:
                # Camera may send string "on"/"off"/"auto" instead of 0/1/2
                self.night_vision_mode = str(v)
        if (b := _as_bool(attr.get("nightVisionIRLight"))) is not None:
            self.ir_light = b
        if (b := _as_bool(attr.get("LightOnOff"))) is not None:
            self.floodlight = b
        if (b := _as_bool(attr.get("trackingMode"))) is not None:
            self.ptz_tracking = b
        if (i := _as_int(attr.get("SoundLevel"))) is not None:
            self.speaker_volume = i
        # Diagnostic / read-only
        if (i := _as_int(attr.get("Battery_remaining"))) is not None:
            self.battery_remaining = i
        if (b := _as_bool(attr.get("Occupancy"))) is not None:
            self.occupancy = b
        if (v := attr.get("SDcardStatus")) is not None:
            self.sd_card_status = str(v)
        # Only overwrite on an actual reading. Attribute pushes are partial - a
        # motion notif carries no card keys - so a silent update must leave what
        # the last full poll established alone.
        if (b := _card_present(attr)) is not None:
            self.sd_card_present = b
        if (i := _as_int(attr.get("networkRssi"))) is not None:
            self.wifi_rssi = i

    # Cloud "properties" keys that belong to lights, not cameras.  A camera's
    # image "Dimming" must not be read as a light brightness (and could TypeError
    # if non-numeric), so exclude the light-only keys when populating a camera.
    _LIGHT_ONLY_ATTR_KEYS = (CONF_ON_OFF, CONF_DIMMING, CONF_RGBW, CONF_CCT)

    def update_from_camera_attributes(self, attrs: dict) -> None:
        """Populate camera fields from a camera attribute / cloud-properties dict.

        Accepts either a setDevAttrNotif ``attr`` dict or a cloud device
        ``properties`` dict - both share the same camera attribute keys
        (Battery_remaining, Occupancy, SDcardStatus, MotionDetection_*, ...).
        """
        # Dimming is filtered out below because on a LIGHT it is the entity's
        # brightness, and a camera's must never be read as one. On a camera it
        # is nonetheless a real setting -- the floodlight's level, 10-100 in the
        # device profile, and what the app's Brightness page writes -- so read
        # it here into its own field rather than letting the filter lose it.
        if (i := _as_int(attrs.get(CONF_DIMMING))) is not None:
            self.light_brightness = i
        self.update({
            k: v for k, v in attrs.items()
            if k not in self._LIGHT_ONLY_ATTR_KEYS
        })


class CameraDeviceInformation(DeviceInformation):
    """Core device info plus camera fields parsed from the device dict."""

    # Per-device AES-128 key from the API (16-char ASCII).  Hypothesis: used
    # for TUTK IOCtrl encryption in LDS/SDES mode.  Confirmed structure-fit
    # (16B = AES-128).  Needs key from PTZ/L2 cameras to test against pcap.
    aes_key: str
    # Local device access password (TUTK viewPwd candidate)
    device_password: str
    # TUTK IOCtrl direction codes the camera advertises (e.g. [3,6] = left+right
    # for a pan-only camera, [1,2,3,6] = full PTZ).  Empty means unknown - callers
    # should treat unknown as "show all" for backward compatibility.
    ptz_directions: list

    def __init__(self, device: dict[str, Any]) -> None:
        super().__init__(device)
        # aesKey is a list in the API response; take first entry
        _aes = device.get("aesKey") or []
        self.aes_key = _aes[0] if isinstance(_aes, list) and _aes else (
            str(_aes) if _aes else "")
        self.device_password = device.get("password") or ""
        self.ptz_directions = []
        if CONF_PRODUCT in device and CONF_SERVICE_MODULES in device[CONF_PRODUCT]:
            for service in device[CONF_PRODUCT][CONF_SERVICE_MODULES]:
                for prop in service.get(CONF_PROPERTIES) or []:
                    if prop.get("code") == "ptzDirection":
                        raw = prop.get("allowedValues")
                        try:
                            codes = json.loads(raw) if isinstance(raw, str) else raw
                            if isinstance(codes, list):
                                self.ptz_directions = [int(c) for c in codes]
                        except Exception:
                            _LOGGER.debug("swallowed exception in %s", '__init__', exc_info=True)


@dataclass
class VideoFrame:
    # frame_type: 2=P-frame  3=B-frame  4=I-frame/keyframe  5=audio
    # audio_codec: 0=N/A  1=G.711A  (meaningful only when frame_type==5)
    # timestamp: server-side PTS in milliseconds
    # is_encrypted: True when sub-frame encryption byte was non-zero
    # data: raw H.264 NAL bytes (video) or G.711A bytes (audio)
    frame_type:   int
    audio_codec:  int
    timestamp:    int
    is_encrypted: bool
    data:         bytes

    @property
    def is_video(self) -> bool:
        return self.frame_type in (_FRAME_TYPE_P_FRAME,
                                   _FRAME_TYPE_B_FRAME,
                                   _FRAME_TYPE_I_FRAME)

    @property
    def is_keyframe(self) -> bool:
        return self.frame_type == _FRAME_TYPE_I_FRAME

    @property
    def is_audio(self) -> bool:
        return self.frame_type == _FRAME_TYPE_AUDIO
