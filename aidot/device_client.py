"""The aidot integration."""

import ctypes
import json
import logging
import random
import socket
import struct
import threading
import time
import asyncio
import zlib
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, List, Optional

from .aes_utils import aes_encrypt, aes_decrypt, aes_ecb_encrypt_str_key, aes_ecb_decrypt_str_key
from .const import (
    CONF_AES_KEY,
    CONF_ASCNUMBER,
    CONF_ATTR,
    CONF_CCT,
    CONF_HARDWARE_VERSION,
    CONF_ID,
    CONF_IDENTITY,
    CONF_MAC,
    CONF_MAXVALUE,
    CONF_MINVALUE,
    CONF_MODEL_ID,
    CONF_NAME,
    CONF_ON_OFF,
    CONF_DIMMING,
    CONF_PASSWORD,
    CONF_PAYLOAD,
    CONF_PRODUCT,
    CONF_PROPERTIES,
    CONF_RGBW,
    CONF_SERVICE_MODULES,
    CONF_ACK,
    CONF_CODE,
    Identity,
)

_LOGGER = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Camera / Leedarson smarthome API constants
# --------------------------------------------------------------------------- #

# AppKey from LDSAppOpenSDK CocoaPods docs (kLDSAppOpenSDKKey = "appa070")
_LEEDARSON_APP_KEY = "appa070"

# APP_ID sent in smarthome HTTP headers — value from MainActivity.java SharedPrefs
# (SharePreferenceUtils.setPrefString(this, "APP_ID", "1392315867093508098")).
_LEEDARSON_APP_ID = "1392315867093508098"

# Camera-specific backend; region prefix mirrors AidotClient._base_url pattern.
# e.g. "us" -> "https://us-smarthome.arnoo.com:443"
_SMARTHOME_URL_TEMPLATE = "https://{region}-smarthome.arnoo.com:443"

# --------------------------------------------------------------------------- #
# Playback TCP binary framing constants
#
# Wire layout (all big-endian) from RecordVideoEncoder.java, verified against
# INettyClientInitializer.java Netty params:
#   lengthFieldOffset=14, lengthFieldLength=4, lengthAdjustment=19
#
# version(H2) seq(i4) cmd(H2) subcmd(H2) cmdParam(i4)  <- 14 bytes
# payloadLen(i4)                                         <- offset 14
# timestamp(q8) context(i4) encodeType(b1) result(h2) reserve(i4)  <- 19 bytes
# <payload bytes>
# Total header = 37 bytes
# --------------------------------------------------------------------------- #

_HDR_FMT         = ">HiHHiiqibhi"
_HDR_SIZE        = struct.calcsize(_HDR_FMT)           # 37
_HDR_PREFIX_FMT  = ">HiHHii"
_HDR_PREFIX_SIZE = struct.calcsize(_HDR_PREFIX_FMT)    # 18
_HDR_SUFFIX_FMT  = ">qibhi"
_HDR_SUFFIX_SIZE = struct.calcsize(_HDR_SUFFIX_FMT)    # 19

assert _HDR_SIZE        == 37
assert _HDR_PREFIX_SIZE == 18
assert _HDR_SUFFIX_SIZE == 19

# Fixed values for all outbound request frames
_HDR_VERSION  = 256   # 0x0100
_HDR_CONTEXT  = 1005
_HDR_ENC_TYPE = 1
_HDR_RESULT   = 4
_HDR_RESERVE  = 2

# TCP command codes from AppCmd.java
_CMD_LOGIN_REQ  = 0x0101
_CMD_LOGIN_RES  = 0x0102
_CMD_HB_REQ     = 0x0105
_CMD_HB_RES     = 0x0106
_CMD_STREAM_REQ = 0x0107
_CMD_STREAM_RES = 0x0108
_CMD_SUBCMD     = 0x0001
_CMD_PARAM      = 0x00000002

# Video sub-frame header size from LDSPlayer.decodeStream():
# padding(2) frameType(1) audioCodec(1) timestamp(8) encType(1) payloadLen(4)
_SF_HDR_SIZE = 17

# Frame type values
_FRAME_TYPE_P_FRAME = 2
_FRAME_TYPE_B_FRAME = 3
_FRAME_TYPE_I_FRAME = 4   # keyframe
_FRAME_TYPE_AUDIO   = 5

_AUDIO_CODEC_G711A = 1

_PTZ_DIR_CODES: dict = {
    "stop": 0, "up": 1, "down": 2, "left": 3,
    "left_up": 4, "left_down": 5, "right": 6,
    "right_up": 7, "right_down": 8, "auto": 9,
    "set_point": 10, "clear_point": 11, "goto": 12,
    "zoom_in": 23, "zoom_out": 24,
}

# --------------------------------------------------------------------------- #
# Existing device-state classes (unchanged from original library)
# --------------------------------------------------------------------------- #

class DeviceStatusData:
    online: bool = False
    on: bool = False
    rgdb: int = None
    rgbw: tuple[int, int, int, int] = None
    cct: int = None
    dimming: int = None
    # Camera-specific fields (None = unknown/not yet queried)
    motion_detection: Optional[bool] = None
    motion_sensitivity: Optional[int] = None  # MotionDetection_Sen 1-5
    status_led: Optional[bool] = None
    microphone: Optional[bool] = None
    night_vision_mode: Optional[str] = None   # "auto" | "on" | "off"
    ir_light: Optional[bool] = None           # nightVisionIRLight 0/1
    floodlight: Optional[bool] = None
    ptz_tracking: Optional[bool] = None
    siren: bool = False
    speaker_volume: Optional[int] = None  # SoundLevel 0-100

    def update(self, attr: dict[str, Any]) -> None:
        if attr is None:
            return
        if attr.get(CONF_ON_OFF) is not None:
            self.on = attr.get(CONF_ON_OFF)
        if attr.get(CONF_DIMMING) is not None:
            self.dimming = int(attr.get(CONF_DIMMING) * 255 / 100)
        if attr.get(CONF_RGBW) is not None:
            self.rgdb = attr.get(CONF_RGBW)
            rgbw = ctypes.c_uint32(self.rgdb).value
            r = (rgbw >> 24) & 0xFF
            g = (rgbw >> 16) & 0xFF
            b = (rgbw >> 8) & 0xFF
            w = rgbw & 0xFF
            self.rgbw = (r, g, b, w)
        if attr.get(CONF_CCT) is not None:
            self.cct = attr.get(CONF_CCT)
        # Camera attributes
        if (v := attr.get("MotionDetection_Enable")) is not None:
            self.motion_detection = bool(int(v))
        if (v := attr.get("MotionDetection_Sen")) is not None:
            self.motion_sensitivity = int(v)
        if (v := attr.get("LedOnOff")) is not None:
            self.status_led = bool(int(v))
        if (v := attr.get("micEnable")) is not None:
            self.microphone = bool(int(v))
        if (v := attr.get("nightVisionMode")) is not None:
            try:
                nv = int(v)
                self.night_vision_mode = {0: "auto", 1: "on", 2: "off"}.get(nv, str(nv))
            except (ValueError, TypeError):
                # Camera may send string "on"/"off"/"auto" instead of 0/1/2
                self.night_vision_mode = str(v)
        if (v := attr.get("nightVisionIRLight")) is not None:
            self.ir_light = bool(int(v))
        if (v := attr.get("LightOnOff")) is not None:
            self.floodlight = bool(int(v))
        if (v := attr.get("trackingMode")) is not None:
            self.ptz_tracking = bool(int(v))
        if (v := attr.get("SoundLevel")) is not None:
            self.speaker_volume = int(v)

    def update_from_camera_attributes(self, attrs: dict) -> None:
        """Populate camera fields from async_get_camera_attributes() response."""
        self.update(attrs)


class DeviceInformation:
    enable_rgbw: bool = False
    enable_dimming: bool = True
    enable_cct: bool = False
    cct_min: int
    cct_max: int
    dev_id: str
    mac: str
    model_id: str
    name: str
    hw_version: str
    # Per-device AES-128 key from the API (16-char ASCII).  Hypothesis: used
    # for TUTK IOCtrl encryption in LDS/SDES mode.  Confirmed structure-fit
    # (16B = AES-128).  Needs key from PTZ/L2 cameras to test against pcap.
    aes_key: str
    # Local device access password (TUTK viewPwd candidate)
    device_password: str

    def __init__(self, device: dict[str, Any]) -> None:
        self.dev_id = device.get(CONF_ID)
        self.mac = device.get(CONF_MAC) if device.get(CONF_MAC) is not None else ""
        self.model_id = device.get(CONF_MODEL_ID)
        self.name = device.get(CONF_NAME)
        self.hw_version = device.get(CONF_HARDWARE_VERSION)
        # aesKey is a list in the API response; take first entry
        _aes = device.get("aesKey") or []
        self.aes_key = _aes[0] if isinstance(_aes, list) and _aes else (
            str(_aes) if _aes else "")
        self.device_password = device.get("password") or ""
        if CONF_PRODUCT in device and CONF_SERVICE_MODULES in device[CONF_PRODUCT]:
            for service in device[CONF_PRODUCT][CONF_SERVICE_MODULES]:
                if service[CONF_IDENTITY] == Identity.RGBW:
                    self.enable_rgbw = True
                    self.enable_cct = True
                elif service[CONF_IDENTITY] == Identity.CCT:
                    self.cct_min = int(service[CONF_PROPERTIES][0][CONF_MINVALUE])
                    self.cct_max = int(service[CONF_PROPERTIES][0][CONF_MAXVALUE])
                    self.enable_cct = True

# --------------------------------------------------------------------------- #
# Camera data types
# --------------------------------------------------------------------------- #

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

# --------------------------------------------------------------------------- #
# JPEG snapshot helper
# --------------------------------------------------------------------------- #

def _save_frame_as_jpeg(image_data: Any, output_path: str) -> bool:
    """Write a PIL Image or RGB numpy array to a JPEG file.

    image_data must already be fully decoded from any PyAV buffer before this
    is called (PIL Image and ndarray are both independent copies).
    """
    import os
    os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)

    # PIL Image path (fastest, no subprocess)
    if hasattr(image_data, "save"):
        try:
            image_data.save(output_path, "JPEG")
            return True
        except Exception as exc:
            _LOGGER.warning("async_snapshot: PIL save failed: %s", exc)
            return False

    # numpy ndarray path — try PIL then ffmpeg
    try:
        import numpy as _np
        if isinstance(image_data, _np.ndarray):
            try:
                from PIL import Image as _PILImage
                _PILImage.fromarray(image_data).save(output_path, "JPEG")
                return True
            except ImportError:
                pass
            # Pillow not available — pipe raw RGB to ffmpeg
            import subprocess as _sp
            h, w = image_data.shape[:2]
            r = _sp.run(
                [
                    "ffmpeg", "-y",
                    "-f", "rawvideo", "-pix_fmt", "rgb24",
                    "-s", f"{w}x{h}", "-i", "pipe:0",
                    "-vframes", "1", output_path,
                ],
                input=image_data.tobytes(),
                capture_output=True,
            )
            return r.returncode == 0
    except Exception as exc:
        _LOGGER.warning("async_snapshot: encode failed: %s", exc)

    return False


# --------------------------------------------------------------------------- #
# TCP binary framing helpers
# --------------------------------------------------------------------------- #

def _pack_frame(cmd: int, payload: bytes, sequence: Optional[int] = None) -> bytes:
    # Build one outbound wire frame: 37-byte header + payload.
    if sequence is None:
        sequence = random.randint(-(2 ** 31), 2 ** 31 - 1)
    ts = int(time.time() * 1000)
    header = struct.pack(
        _HDR_FMT,
        _HDR_VERSION,
        sequence,
        cmd,
        _CMD_SUBCMD,
        _CMD_PARAM,
        len(payload),
        ts,
        _HDR_CONTEXT,
        _HDR_ENC_TYPE,
        _HDR_RESULT,
        _HDR_RESERVE,
    )
    return header + payload


def _mqtt_timestamp() -> str:
    t = time.time()
    return time.strftime("%Y-%m-%d %H:%M:%S.", time.localtime(t)) + f"{int(t * 1000) % 1000:03d}"


async def _read_frame(reader: asyncio.StreamReader) -> tuple:
    # Read one complete framed response from the playback TCP server.
    # Returns (header_dict, payload_bytes).
    # header_dict keys: cmd, seq, result, timestamp.
    prefix_raw = await reader.readexactly(_HDR_PREFIX_SIZE)
    _version, seq, cmd, _subcmd, _cmd_param, payload_len = struct.unpack(
        _HDR_PREFIX_FMT, prefix_raw
    )
    if payload_len < 0 or payload_len > 4 * 1024 * 1024:
        raise ValueError(f"Implausible payloadLen={payload_len} in TCP frame")
    rest = await reader.readexactly(_HDR_SUFFIX_SIZE + payload_len)
    timestamp, _context, _enc_type, result, _reserve = struct.unpack(
        _HDR_SUFFIX_FMT, rest[:_HDR_SUFFIX_SIZE]
    )
    payload = rest[_HDR_SUFFIX_SIZE:]
    return {"cmd": cmd, "seq": seq, "result": result, "timestamp": timestamp}, payload


def _parse_video_payload(data: bytes) -> List[VideoFrame]:
    # Parse a STREAM_RES payload into VideoFrame objects.
    # Sub-frame layout (17-byte header, big-endian):
    #   padding(2) frameType(1) audioCodec(1) timestamp(8) encType(1) payloadLen(4)
    # Source: LDSPlayer.decodeStream() in the Leedarson Android SDK.
    frames: List[VideoFrame] = []
    offset = 0
    while len(data) - offset >= _SF_HDR_SIZE:
        frame_type    = data[offset + 2]
        audio_codec   = data[offset + 3]
        (timestamp,)  = struct.unpack_from(">q", data, offset + 4)
        enc_type      = data[offset + 12]
        (payload_len,) = struct.unpack_from(">i", data, offset + 13)
        if payload_len < 0:
            break
        end = offset + _SF_HDR_SIZE + payload_len
        if end > len(data):
            break
        if enc_type != 0:
            frames.append(VideoFrame(frame_type, audio_codec, timestamp, True, b""))
        else:
            frames.append(VideoFrame(
                frame_type, audio_codec, timestamp, False,
                data[offset + _SF_HDR_SIZE:end],
            ))
        offset = end
    return frames


def _build_stun_binding_success_response(
    *,
    transaction_id: bytes,
    mapped_ip: str,
    mapped_port: int,
    mi_password: str,
    magic_cookie: bytes = b"\x21\x12\xa4\x42",
) -> bytes:
    """Build STUN Binding Success with MESSAGE-INTEGRITY and FINGERPRINT.

    Some camera firmwares keep retransmitting ICE checks when responses lack a
    valid fingerprinted STUN envelope. This helper emits:
      XOR-MAPPED-ADDRESS + MESSAGE-INTEGRITY + FINGERPRINT
    """
    import hmac as _hmac, hashlib as _hashlib

    ip_parts = [int(x) for x in mapped_ip.split(".")]
    xip = bytes(a ^ b for a, b in zip(struct.pack("!4B", *ip_parts), magic_cookie))
    xport = (mapped_port ^ 0x2112) & 0xFFFF
    xma = b"\x00\x20\x00\x08\x00\x01" + struct.pack("!H", xport) + xip

    mi_attr_len = 24  # type(2)+len(2)+sha1(20)
    fp_attr_len = 8   # type(2)+len(2)+crc32(4)

    # Per RFC 5389/8445, MESSAGE-INTEGRITY is computed with length set to end
    # of MESSAGE-INTEGRITY (excluding any attributes that follow, e.g. FINGERPRINT).
    len_for_mi = len(xma) + mi_attr_len
    hdr_for_mi = b"\x01\x01" + struct.pack("!H", len_for_mi) + magic_cookie + transaction_id
    mi_val = _hmac.new(
        mi_password.encode(), hdr_for_mi + xma, _hashlib.sha1
    ).digest()
    mi_attr = b"\x00\x08\x00\x14" + mi_val

    # On-wire message length includes FINGERPRINT.
    len_with_fp = len_for_mi + fp_attr_len
    hdr_with_fp = b"\x01\x01" + struct.pack("!H", len_with_fp) + magic_cookie + transaction_id
    msg_wo_fp_attr = hdr_with_fp + xma + mi_attr
    fp_val = (zlib.crc32(msg_wo_fp_attr) ^ 0x5354554E) & 0xFFFFFFFF
    fp_attr = b"\x80\x28\x00\x04" + struct.pack("!I", fp_val)
    return msg_wo_fp_attr + fp_attr


def _compress_sdp_for_camera(sdp: str) -> str:
    """Selective SDP filter matching official Java client's g.b() behaviour.

    The Leedarson firmware (KVS-derived) parses ``wPayload.offer.sdp`` with
    ``encOffer=1`` expecting a compact SDP that includes only the lines its
    ICE/DTLS/codec stack needs.  Sending a full WebRTC-stack SDP (~5 KB+
    with extmap/rtcp-fb/ssrc/msid lines) frequently causes A001064-class
    cameras to drop the MQTT session immediately on receipt — the embedded
    MQTT buffer overflows.

    Keeps: v=, s=, m=, c=, a=group, a=msid-semantic, a=mid, direction
    (sendrecv/recvonly/sendonly), a=ice-ufrag, a=ice-pwd, a=ice-options,
    a=fingerprint, a=setup, a=crypto, a=ssrc cname (first per section),
    a=candidate (UDP only), a=rtpmap (PCMU/PCMA/AAC/opus only on audio,
    H264/H265/RTX-apt on video), a=fmtp profile-level-id, a=sctp-port.

    Drops: a=extmap, a=rtcp-fb, a=rtcp-mux, a=rtcp-rsize, a=msid, a=ssrc
    (non-cname), a=rtcp:9, redundant rtpmap entries.
    """
    out: list = []
    seen: dict = {}
    media_type = ""
    before_m = True

    def keep(ln: str, key: str = "") -> None:
        out.append(ln + "\r\n")
        if key:
            seen[key] = "1"

    for ln in sdp.splitlines():
        if ln.startswith("m="):
            before_m = False
            media_type = ln.split(" ")[0]
            keep(ln)
            continue
        if before_m:
            if (ln.startswith("v=") or ln.startswith("o=")
                    or ln.startswith("s=") or ln.startswith("t=")
                    or ln.startswith("a=group:")
                    or ln.startswith("a=msid-semantic")):
                keep(ln)
            continue
        if ln.startswith("c="):
            keep(ln)
            continue
        if ln.startswith("a=mid:"):
            keep(ln)
            continue
        if ln.startswith("a=ssrc") and "cname" in ln:
            if seen.get(f"ssrc-cname-{media_type}") is None:
                keep(ln, f"ssrc-cname-{media_type}")
            continue
        if any(d in ln for d in ("sendrecv", "recvonly", "sendonly")):
            keep(ln)
            continue
        for ak in ("ice-ufrag", "ice-pwd", "fingerprint", "setup",
                   "ice-options", "crypto"):
            if ak in ln:
                if seen.get(ak) is None:
                    keep(ln, ak)
                break
        else:
            if "candidate" in ln and " udp " in ln.lower():
                keep(ln)
                continue
            if media_type == "m=audio":
                if any(c in ln for c in ("opus", "PCMU", "PCMA", "AAC")):
                    keep(ln)
            elif media_type == "m=video":
                if "H264/90000" in ln and seen.get("H264/90000") is None:
                    keep(ln, "H264/90000")
                    try:
                        seen["H264/90000_pt"] = ln.split(":")[1].split(" ")[0]
                    except Exception:
                        pass
                elif "H265/90000" in ln and seen.get("H265/90000") is None:
                    keep(ln, "H265/90000")
                    try:
                        seen["H265/90000_pt"] = ln.split(":")[1].split(" ")[0]
                    except Exception:
                        pass
                elif "apt=" in ln:
                    try:
                        apt = ln.split("apt=")[1].strip()
                    except Exception:
                        apt = ""
                    if apt and apt in (
                        seen.get("H264/90000_pt", ""),
                        seen.get("H265/90000_pt", ""),
                    ):
                        keep(ln)
                elif "fmtp" in ln and "profile-level-id" in ln:
                    if seen.get("profile-level") is None:
                        keep(ln, "profile-level")
            elif media_type == "m=application":
                if "sctp-port" in ln:
                    keep(ln)
    return "".join(out)


# --------------------------------------------------------------------------- #
# CloudPlaybackSession
# --------------------------------------------------------------------------- #

class CloudPlaybackSession:
    # Manages a single cloud-playback TCP session for a Leedarson/AiDot camera.
    # Use DeviceClient.async_open_cloud_playback() to obtain an instance.

    def __init__(
        self,
        server_ip: str,
        server_port: int,
        heartbeat_interval: int,
        task_id: int,
        client_id: str,
        start_ts_s: int,
        on_frame: Callable[[VideoFrame], None],
    ) -> None:
        self._server_ip   = server_ip
        self._server_port = server_port
        self._hb_interval = heartbeat_interval
        self._task_id     = task_id
        self._client_id   = client_id
        self._start_ts    = start_ts_s
        self._on_frame    = on_frame
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._running  = False
        self._paused   = False
        self._hb_task: Optional[asyncio.Task] = None
        self._rx_task: Optional[asyncio.Task] = None

    async def _connect_and_login(self) -> bool:
        try:
            self._reader, self._writer = await asyncio.open_connection(
                self._server_ip, self._server_port
            )
        except OSError as exc:
            _LOGGER.error(
                "Cloud playback: TCP connect to %s:%d failed: %s",
                self._server_ip, self._server_port, exc,
            )
            return False

        login_body = json.dumps({
            "clientId":  self._client_id,
            "heartbeat": self._hb_interval,
            "taskId":    self._task_id,
        }).encode("utf-8")

        seq = random.randint(-(2 ** 31), 2 ** 31 - 1)
        self._writer.write(_pack_frame(_CMD_LOGIN_REQ, login_body, seq))
        await self._writer.drain()

        try:
            hdr, resp_payload = await asyncio.wait_for(
                _read_frame(self._reader), timeout=10.0
            )
        except asyncio.TimeoutError:
            _LOGGER.error("Cloud playback: login response timed out")
            return False
        except Exception as exc:
            _LOGGER.error("Cloud playback: login read error: %s", exc)
            return False

        if hdr["cmd"] != _CMD_LOGIN_RES:
            _LOGGER.error(
                "Cloud playback: unexpected login response cmd=0x%04x", hdr["cmd"]
            )
            return False

        try:
            body_obj = json.loads(resp_payload)
            if body_obj.get("code") != 200:
                _LOGGER.error(
                    "Cloud playback: login rejected code=%s body=%s",
                    body_obj.get("code"), body_obj,
                )
                return False
        except (json.JSONDecodeError, ValueError):
            pass  # some firmware sends no JSON body - treat as success

        _LOGGER.debug(
            "Cloud playback: login OK task=%d server=%s:%d",
            self._task_id, self._server_ip, self._server_port,
        )
        return True

    async def _request_stream_batch(self) -> None:
        if self._writer is None:
            return
        body = json.dumps({
            "begin":     self._start_ts,
            "type":      1,
            "framenums": 10,
            "speed":     1,
        }).encode("utf-8")
        self._writer.write(_pack_frame(_CMD_STREAM_REQ, body))
        await self._writer.drain()

    async def _heartbeat_loop(self) -> None:
        while self._running:
            await asyncio.sleep(self._hb_interval)
            if not self._running or self._writer is None:
                break
            try:
                self._writer.write(_pack_frame(_CMD_HB_REQ, b"{}"))
                await self._writer.drain()
            except Exception as exc:
                _LOGGER.warning("Cloud playback: heartbeat write failed: %s", exc)
                break

    async def _receive_loop(self) -> None:
        while self._running:
            if self._paused:
                await asyncio.sleep(0.2)
                continue
            try:
                hdr, payload = await asyncio.wait_for(
                    _read_frame(self._reader),
                    timeout=30.0,
                )
            except asyncio.TimeoutError:
                _LOGGER.warning("Cloud playback: receive timeout")
                break
            except asyncio.IncompleteReadError:
                if self._running:
                    _LOGGER.info("Cloud playback: server closed TCP connection")
                break
            except Exception as exc:
                if self._running:
                    _LOGGER.warning("Cloud playback: receive error: %s", exc)
                break

            if hdr["cmd"] == _CMD_HB_RES:
                continue

            if hdr["cmd"] != _CMD_STREAM_RES:
                _LOGGER.debug(
                    "Cloud playback: ignoring unexpected cmd=0x%04x", hdr["cmd"]
                )
                continue

            result = hdr["result"]
            if result == 200:
                for frame in _parse_video_payload(payload):
                    try:
                        self._on_frame(frame)
                    except Exception:
                        _LOGGER.exception("Cloud playback: exception in on_frame callback")
                if self._running and not self._paused:
                    await self._request_stream_batch()
            elif result == -15528:
                # End-of-stream sentinel from LDSOpenSDK.java receiveDataTask
                _LOGGER.info("Cloud playback: end of stream reached")
                break
            else:
                _LOGGER.warning("Cloud playback: unexpected stream result=%d", result)

    async def start(self) -> bool:
        self._running = True
        if not await self._connect_and_login():
            self._running = False
            return False
        await self._request_stream_batch()
        self._hb_task = asyncio.create_task(
            self._heartbeat_loop(), name="aidot-cloud-hb"
        )
        self._rx_task = asyncio.create_task(
            self._receive_loop(), name="aidot-cloud-rx"
        )
        return True

    async def pause(self) -> None:
        self._paused = True

    async def resume(self) -> None:
        self._paused = False
        if self._running and self._writer is not None:
            await self._request_stream_batch()

    async def stop(self) -> None:
        self._running = False
        self._paused  = False
        for task in (self._hb_task, self._rx_task):
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        self._hb_task = None
        self._rx_task = None
        if self._writer is not None:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
            self._writer = None
            self._reader = None

# --------------------------------------------------------------------------- #
# TutkStreamSession
#
# TUTK IOTC P2P live-stream session for Leedarson/AiDot cameras.
# Use DeviceClient.async_open_live_stream() to obtain an instance.
#
# Protocol source: classes.jar.decompiled.zip / TutkManager.java
#   IOTC_Connect_ByUID_Parallel(uid, sid) → nSID
#   avClientStart2(nSID, "admin", "admin123", ...) → avIndex
#   avSendIOCtrl(avIndex, 511, ...) → start video (IOTYPE_USER_IPCAM_START)
#   avRecvFrameData2(avIndex, ...) → frame data loop
#
# Requires: libIOTCAPIs.so + libAVAPIs.so from the TUTK SDK.
# Obtain them from the TUTK SDK distribution or an extracted AiDot APK.
# --------------------------------------------------------------------------- #

class TutkStreamSession:
    """TUTK IOTC P2P live-stream session."""

    _IOTYPE_INNER_SND_DATA_DELAY = 255   # TutkManager.java: sent before START
    _IOTYPE_USER_IPCAM_START     = 511   # AVIOCTRLDEFs: IOTYPE_USER_IPCAM_START
    _IOTYPE_USER_IPCAM_STOP      = 767   # AVIOCTRLDEFs: IOTYPE_USER_IPCAM_STOP
    _IOTYPE_USER_IPCAM_AUDIOSTART = 768  # AVIOCTRLDEFs: IOTYPE_USER_IPCAM_AUDIOSTART

    def __init__(
        self,
        uid: str,
        on_frame: Callable[["VideoFrame"], None],
        iotc_lib_path: str = "libIOTCAPIs.so",
        av_lib_path: str = "libAVAPIs.so",
    ) -> None:
        self._uid           = uid
        self._on_frame      = on_frame
        self._iotc_lib_path = iotc_lib_path
        self._av_lib_path   = av_lib_path
        self._thread: Optional[threading.Thread] = None
        self._stop_event    = threading.Event()
        self._sid           = -1
        self._av_index      = -1

    async def start(self) -> bool:
        """Load native libs, connect P2P, and start the frame-receive thread."""
        return await asyncio.get_event_loop().run_in_executor(
            None, self._start_sync)

    def _start_sync(self) -> bool:
        import ctypes

        try:
            iotc = ctypes.CDLL(self._iotc_lib_path)
            av   = ctypes.CDLL(self._av_lib_path)
        except OSError as exc:
            _LOGGER.error(
                "TutkStreamSession: cannot load TUTK native libraries "
                "(%s, %s): %s. "
                "Obtain them from the TUTK SDK or an extracted AiDot APK.",
                self._iotc_lib_path, self._av_lib_path, exc,
            )
            return False

        # --- Declare function signatures ------------------------------------ #
        iotc.IOTC_Initialize2.restype  = ctypes.c_int
        iotc.IOTC_Initialize2.argtypes = [ctypes.c_int]

        iotc.IOTC_Get_SessionID.restype  = ctypes.c_int
        iotc.IOTC_Get_SessionID.argtypes = []

        iotc.IOTC_Set_Max_Session_Number.restype  = None
        iotc.IOTC_Set_Max_Session_Number.argtypes = [ctypes.c_int]

        iotc.IOTC_Connect_ByUID_Parallel.restype  = ctypes.c_int
        iotc.IOTC_Connect_ByUID_Parallel.argtypes = [ctypes.c_char_p, ctypes.c_int]

        iotc.IOTC_Session_Close.restype  = None
        iotc.IOTC_Session_Close.argtypes = [ctypes.c_int]

        # TutkManager.java: AVAPIs.avInitialize(32)
        av.avInitialize.restype  = ctypes.c_int
        av.avInitialize.argtypes = [ctypes.c_int]

        av.avClientStart2.restype  = ctypes.c_int
        av.avClientStart2.argtypes = [
            ctypes.c_int,                        # nSID
            ctypes.c_char_p,                     # account
            ctypes.c_char_p,                     # password
            ctypes.c_int,                        # timeout_ms
            ctypes.POINTER(ctypes.c_int),        # srvType[] (out)
            ctypes.c_int,                        # reserved=0
            ctypes.POINTER(ctypes.c_int),        # nSend[] (out)
        ]

        av.avClientStop.restype  = ctypes.c_int
        av.avClientStop.argtypes = [ctypes.c_int]

        av.avSendIOCtrl.restype  = ctypes.c_int
        av.avSendIOCtrl.argtypes = [
            ctypes.c_int,    # nAVIndex
            ctypes.c_uint,   # nIOCtrlType
            ctypes.c_char_p, # cabIOCtrlData
            ctypes.c_int,    # nIOCtrlDataSize
        ]

        # FRAMEINFO_t — TUTK SDK v3.x layout (codec_id, flags, onlineNum,
        # frameSize, frameNo, timestamp). Adjust if your SDK version differs.
        class FrameInfo(ctypes.Structure):
            _fields_ = [
                ("codec_id",   ctypes.c_uint),
                ("flags",      ctypes.c_uint),
                ("onlineNum",  ctypes.c_uint),
                ("frameSize",  ctypes.c_uint),
                ("frameNo",    ctypes.c_uint),
                ("timestamp",  ctypes.c_uint),
            ]

        av.avRecvFrameData2.restype  = ctypes.c_int
        av.avRecvFrameData2.argtypes = [
            ctypes.c_int,                        # nAVIndex
            ctypes.c_char_p,                     # abFrameData
            ctypes.c_int,                        # nFrameDataMaxSize (by value)
            ctypes.POINTER(ctypes.c_int),        # pnActualFrameSize (out)
            ctypes.POINTER(ctypes.c_int),        # pnExpectedFrameSize (out)
            ctypes.c_char_p,                     # pFrameInfo (byte buffer)
            ctypes.c_int,                        # nFrameInfoBufSize (by value)
            ctypes.POINTER(ctypes.c_int),        # pnActualFrameInfoSize (out)
            ctypes.POINTER(ctypes.c_int),        # pnFrameIndex (out)
        ]

        # --- Initialize IOTC (idempotent) ----------------------------------- #
        # TutkManager.java: IOTC_Initialize2(0) then IOTC_Set_Max_Session_Number(10)
        # then avInitialize(32)
        ret = iotc.IOTC_Initialize2(0)
        if ret < 0:
            _LOGGER.debug("IOTC_Initialize2 returned %d (may already be initialized)", ret)
        else:
            iotc.IOTC_Set_Max_Session_Number(10)

        ret = av.avInitialize(32)
        if ret < 0:
            _LOGGER.debug("avInitialize returned %d (may already be initialized)", ret)

        # --- Connect P2P ---------------------------------------------------- #
        sid = iotc.IOTC_Get_SessionID()
        if sid < 0:
            _LOGGER.error("TUTK: IOTC_Get_SessionID failed: %d", sid)
            return False

        _LOGGER.debug("TUTK: connecting to uid=%s (sid=%d)", self._uid, sid)
        ret = iotc.IOTC_Connect_ByUID_Parallel(self._uid.encode(), sid)
        if ret < 0:
            _LOGGER.error(
                "TUTK: IOTC_Connect_ByUID_Parallel(%s) failed: %d",
                self._uid, ret,
            )
            return False
        self._sid = ret

        # --- Start AV client ------------------------------------------------ #
        # TutkManager.java: avClientStart2(nSID, account, pwd, 2000, srvType, 0, nSend)
        # Credentials: "admin" / "admin123" (hardcoded in TutkManager.java)
        srv_type = ctypes.c_int(0)
        n_send   = ctypes.c_int(0)
        av_index = av.avClientStart2(
            self._sid, b"admin", b"admin123", 2000,
            ctypes.byref(srv_type), 0, ctypes.byref(n_send))
        if av_index < 0:
            _LOGGER.error("TUTK: avClientStart2 failed: %d", av_index)
            iotc.IOTC_Session_Close(self._sid)
            self._sid = -1
            return False
        self._av_index = av_index

        # --- Send IOCtrl commands per TutkManager.java ---------------------- #
        # 1. IOTYPE_INNER_SND_DATA_DELAY (255) — 2-byte body
        av.avSendIOCtrl(self._av_index, self._IOTYPE_INNER_SND_DATA_DELAY,
                        (ctypes.c_uint8 * 2)(), 2)
        # 2. IOTYPE_USER_IPCAM_START (511) — 8-byte body (all zeros = default stream)
        av.avSendIOCtrl(self._av_index, self._IOTYPE_USER_IPCAM_START,
                        (ctypes.c_uint8 * 8)(), 8)
        # 3. IOTYPE_USER_IPCAM_AUDIOSTART (768) — 8-byte body
        av.avSendIOCtrl(self._av_index, self._IOTYPE_USER_IPCAM_AUDIOSTART,
                        (ctypes.c_uint8 * 8)(), 8)

        # --- Launch frame-receive thread ------------------------------------ #
        self._thread = threading.Thread(
            target=self._recv_loop,
            args=(av, iotc, FrameInfo),
            daemon=True,
            name=f"tutk-recv-{self._uid[:8]}",
        )
        self._thread.start()
        return True

    def _recv_loop(self, av, iotc, FrameInfo) -> None:
        import ctypes

        # avRecvFrameData2 signature (from AVAPIs.java / TUTK SDK):
        #   (nAVIndex, abFrameData, nFrameDataMaxSize,
        #    *pnActualFrameSize, *pnExpectedFrameSize,
        #    pFrameInfo, nFrameInfoBufSize,
        #    *pnActualFrameInfoSize, *pnFrameIndex)
        BUF_SIZE     = 131072   # 128 KB — matches TutkManager.VIDEO_BUF_SIZE (100000)
        frame_buf    = ctypes.create_string_buffer(BUF_SIZE)
        info_buf     = ctypes.create_string_buffer(ctypes.sizeof(FrameInfo))
        actual_sz    = ctypes.c_int(0)
        expected_sz  = ctypes.c_int(0)
        actual_info  = ctypes.c_int(0)
        frame_idx    = ctypes.c_int(0)

        _LOGGER.debug("TUTK: recv loop started (avIndex=%d)", self._av_index)

        while not self._stop_event.is_set():
            ret = av.avRecvFrameData2(
                self._av_index,
                frame_buf,
                BUF_SIZE,
                ctypes.byref(actual_sz),
                ctypes.byref(expected_sz),
                info_buf,
                ctypes.sizeof(FrameInfo),
                ctypes.byref(actual_info),
                ctypes.byref(frame_idx),
            )
            if ret == -20012:
                # AV_ER_DATA_NOREADY — no frame yet; brief sleep per TutkManager (2ms)
                time.sleep(0.002)
                continue
            if ret < 0:
                _LOGGER.error("TUTK: avRecvFrameData2 returned %d — stopping", ret)
                break

            raw      = bytes(frame_buf.raw[: actual_sz.value])
            fi       = FrameInfo.from_buffer_copy(info_buf)
            vf  = VideoFrame(
                frame_type   = fi.codec_id,
                audio_codec  = 0,
                timestamp    = fi.timestamp,
                is_encrypted = False,
                data         = raw,
            )
            try:
                self._on_frame(vf)
            except Exception as exc:
                _LOGGER.error("TUTK: on_frame callback raised: %s", exc)

        # Teardown
        if self._av_index >= 0:
            try:
                av.avClientStop(self._av_index)
            except Exception:
                pass
        if self._sid >= 0:
            try:
                iotc.IOTC_Session_Close(self._sid)
            except Exception:
                pass
        _LOGGER.debug("TUTK: recv loop exited")

    async def stop(self) -> None:
        """Signal the receive thread to stop and wait for it."""
        self._stop_event.set()
        if self._thread is not None:
            await asyncio.get_event_loop().run_in_executor(
                None, lambda: self._thread.join(timeout=5.0)
            )


# --------------------------------------------------------------------------- #
# LiveStreamSession
#
# Manages a single live-stream TCP session for a Leedarson/AiDot camera.
# Use DeviceClient.async_open_live_stream() to obtain an instance.
#
# Protocol source: iOS LDSXplayer startRealPlay → LDSTCPManager
#   connectHost:port:sessionId:aesKey:heartbeat:msg:cmd:subCmd:cmdParam:tls:
#
# Wire format: same 37-byte header + payload as CloudPlaybackSession, but:
#   - TLS socket (server cert not verified -- IoT device)
#   - AES-256/ECB/PKCS7 encrypts outbound payloads; decrypts inbound payloads
#   - LOGIN payload carries sessionId from the MQTT connectipc response
#   - STREAM_REQ starts the live video feed (no taskId needed)
# --------------------------------------------------------------------------- #

class LiveStreamSession:

    def __init__(
        self,
        server_ip: str,
        server_port: int,
        session_id: str,
        aes_key: str,
        heartbeat_interval: int,
        use_tls: bool,
        on_frame: Callable[["VideoFrame"], None],
    ) -> None:
        self._server_ip         = server_ip
        self._server_port       = int(server_port)
        self._session_id        = session_id
        self._aes_key           = aes_key
        self._heartbeat_secs    = max(1, int(heartbeat_interval))
        self._use_tls           = use_tls
        self._on_frame          = on_frame
        self._reader: Optional[asyncio.StreamReader]  = None
        self._writer: Optional[asyncio.StreamWriter]  = None
        self._task:   Optional[asyncio.Task]          = None
        self._closed  = False

    # -- Public interface ---------------------------------------------------- #

    async def start(self) -> bool:
        # Open the TLS (or plain) TCP connection and perform the login handshake.
        # Returns True on success, False on failure.
        import ssl

        try:
            if self._use_tls:
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode    = ssl.CERT_NONE
            else:
                ssl_ctx = None

            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self._server_ip, self._server_port, ssl=ssl_ctx
                ),
                timeout=10,
            )
        except Exception as exc:
            _LOGGER.error(
                "LiveStreamSession: TCP connect to %s:%d failed: %s",
                self._server_ip, self._server_port, exc,
            )
            return False

        # LOGIN -- carry sessionId as credential, AES-encrypt the JSON payload.
        try:
            login_body_raw = json.dumps({
                "sessionId": self._session_id,
                "clientId":  "live-stream",
            }).encode("utf-8")
            login_enc = aes_ecb_encrypt_str_key(login_body_raw, self._aes_key)
            self._writer.write(_pack_frame(_CMD_LOGIN_REQ, login_enc))
            await self._writer.drain()

            hdr, payload = await asyncio.wait_for(_read_frame(self._reader), timeout=10)
            if hdr["cmd"] != _CMD_LOGIN_RES:
                _LOGGER.error(
                    "LiveStreamSession: expected LOGIN_RES (0x%04x), got 0x%04x",
                    _CMD_LOGIN_RES, hdr["cmd"],
                )
                await self._cleanup()
                return False

            # Decrypt and log the login response (best-effort -- ignore on error)
            try:
                resp_plain = aes_ecb_decrypt_str_key(payload, self._aes_key)
                _LOGGER.debug("LiveStreamSession: LOGIN_RES: %s", resp_plain[:200])
            except Exception:
                _LOGGER.debug("LiveStreamSession: LOGIN_RES payload not AES-encrypted")

        except Exception as exc:
            _LOGGER.error("LiveStreamSession: login handshake failed: %s", exc)
            await self._cleanup()
            return False

        # STREAM_REQ -- request the live feed.
        # No taskId needed; the sessionId from MQTT already identifies the stream.
        try:
            stream_body_raw = json.dumps({"sessionId": self._session_id}).encode("utf-8")
            stream_enc = aes_ecb_encrypt_str_key(stream_body_raw, self._aes_key)
            self._writer.write(_pack_frame(_CMD_STREAM_REQ, stream_enc))
            await self._writer.drain()
        except Exception as exc:
            _LOGGER.error("LiveStreamSession: STREAM_REQ failed: %s", exc)
            await self._cleanup()
            return False

        # Start background receive/heartbeat task.
        self._task = asyncio.get_event_loop().create_task(self._receive_loop())
        return True

    async def stop(self) -> None:
        # Gracefully stop the session.
        self._closed = True
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        await self._cleanup()

    # -- Internals ----------------------------------------------------------- #

    async def _receive_loop(self) -> None:
        assert self._reader is not None
        assert self._writer is not None

        hb_interval = self._heartbeat_secs
        last_hb     = time.monotonic()

        try:
            while not self._closed:
                # Send heartbeat if due.
                if time.monotonic() - last_hb >= hb_interval:
                    try:
                        hb_enc = aes_ecb_encrypt_str_key(b"{}", self._aes_key)
                        self._writer.write(_pack_frame(_CMD_HB_REQ, hb_enc))
                        await self._writer.drain()
                        last_hb = time.monotonic()
                    except Exception as exc:
                        _LOGGER.warning("LiveStreamSession: heartbeat error: %s", exc)
                        break

                # Read next frame with a deadline matching the heartbeat interval.
                try:
                    hdr, payload = await asyncio.wait_for(
                        _read_frame(self._reader),
                        timeout=hb_interval * 2,
                    )
                except asyncio.TimeoutError:
                    _LOGGER.warning("LiveStreamSession: receive timeout -- reconnect?")
                    break

                if hdr["cmd"] == _CMD_HB_RES:
                    continue

                if hdr["cmd"] != _CMD_STREAM_RES:
                    _LOGGER.debug(
                        "LiveStreamSession: unexpected cmd=0x%04x", hdr["cmd"]
                    )
                    continue

                # End-of-stream sentinel (result == -15528 from LDSOpenSDK.java)
                if hdr.get("result") == -15528:
                    _LOGGER.info("LiveStreamSession: end-of-stream sentinel received")
                    break

                # AES-decrypt the payload, then parse video sub-frames.
                try:
                    plain = aes_ecb_decrypt_str_key(payload, self._aes_key)
                except Exception:
                    # Some servers send unencrypted frames; fall back gracefully.
                    plain = payload

                for frame in _parse_video_payload(plain):
                    try:
                        self._on_frame(frame)
                    except Exception as exc:
                        _LOGGER.warning(
                            "LiveStreamSession: on_frame callback raised: %s", exc
                        )

        except asyncio.CancelledError:
            pass
        except Exception as exc:
            if not self._closed:
                _LOGGER.error("LiveStreamSession: receive loop error: %s", exc)
        finally:
            await self._cleanup()

    async def _cleanup(self) -> None:
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
            self._writer = None
            self._reader = None


# --------------------------------------------------------------------------- #
# WebRTCSession
#
# Manages a live WebRTC stream opened by DeviceClient.async_open_webrtc_stream.
# Call await session.stop() to tear down the peer connection and MQTT session.
# --------------------------------------------------------------------------- #

class WebRTCSession:
    """Active WebRTC live-stream session for a liveType=2 AiDot camera.

    Obtain via ``await DeviceClient.async_open_webrtc_stream(...)``.
    Call ``await session.stop()`` when done.
    """

    def __init__(
        self,
        *,
        pc: Any,
        outgoing_q: Any,
        mqtt_fut: Any,
        recorder: Any,
        track_tasks: list,
        dc: Any = None,
    ) -> None:
        self._pc          = pc
        self._outgoing_q  = outgoing_q
        self._mqtt_fut    = mqtt_fut
        self._recorder    = recorder
        self._track_tasks = track_tasks
        self._dc          = dc  # RTCDataChannel for AVIO IOCtrl commands

    def _avio_cmd(self, cmd: int, payload: bytes = b"") -> bool:
        """Send an AVIO IOCtrl command via the DTLS SCTP DataChannel.

        Returns True if the command was dispatched, False if DC not open.
        """
        if self._dc is None:
            return False
        try:
            _seq = random.randint(0, 0x7FFFFFFF)
            _ts_ms = int(time.time() * 1000)
            _hdr = struct.pack("<IIqII4x", _seq, cmd, _ts_ms, len(payload), 0)
            self._dc.send(_hdr + payload)
            return True
        except Exception:
            return False

    async def stop(self) -> None:
        """Tear down the stream: close peer connection and MQTT session."""
        for task in self._track_tasks:
            task.cancel()
        if self._recorder is not None:
            try:
                await self._recorder.stop()
            except Exception:
                pass
        # Send None sentinel to stop the MQTT session in its thread
        self._outgoing_q.put_nowait(None)
        await self._pc.close()
        try:
            await asyncio.wait_for(self._mqtt_fut, timeout=5.0)
        except Exception:
            pass


class SdesSession:
    """Active SDES-SRTP stream session managed by an ffmpeg subprocess.

    Obtain via ``await DeviceClient.async_open_webrtc_stream(...)`` when the
    camera uses SDES-SRTP (``isDTLS == '0'``).
    Call ``await session.stop()`` when done.
    """

    def __init__(
        self,
        *,
        proc,
        sdp_path: str,
        outgoing_q,
        mqtt_fut,
        audio_sock=None,
        video_sock=None,
        cmd_chan=None,
    ) -> None:
        self._proc       = proc
        self._sdp_path   = sdp_path
        self._outgoing_q = outgoing_q
        self._mqtt_fut   = mqtt_fut
        self._audio_sock = audio_sock
        self._video_sock = video_sock
        # Mutable one-element list shared with the bridge thread.  Bridge sets
        # [0] to a callable(cmd, payload) once the SCTP channel is up.
        self._cmd_chan   = cmd_chan if cmd_chan is not None else [None]

    def _avio_cmd(self, cmd: int, payload: bytes = b"") -> bool:
        """Send an AVIO IOCtrl command via the encrypted SDES SCTP channel.

        Returns True if the command was dispatched, False if the channel is not
        yet established.
        """
        fn = self._cmd_chan[0]
        if fn is None:
            return False
        try:
            fn(cmd, payload)
            return True
        except Exception:
            return False

    @property
    def is_alive(self) -> bool:
        """True while ffmpeg is still running."""
        return self._proc.poll() is None

    async def wait_done(self) -> int:
        """Wait (non-blocking poll) until ffmpeg exits; return its exit code."""
        while self._proc.poll() is None:
            await asyncio.sleep(0.5)
        return self._proc.returncode

    async def stop(self) -> None:
        """Tear down the stream: terminate ffmpeg and stop MQTT."""
        self._proc.terminate()
        try:
            _stop_loop = asyncio.get_running_loop()
            await _stop_loop.run_in_executor(None, lambda: self._proc.wait(5))
        except Exception:
            self._proc.kill()
        stderr_bytes = b""
        try:
            stderr_bytes = self._proc.stderr.read()
        except Exception:
            pass
        if stderr_bytes:
            _LOGGER.warning("ffmpeg SDES stderr:\n%s", stderr_bytes.decode(errors="replace"))
        import os
        try:
            os.unlink(self._sdp_path)
        except Exception:
            pass
        for _sock in (self._audio_sock, self._video_sock):
            if _sock is not None:
                try:
                    _sock.close()
                except Exception:
                    pass
        self._outgoing_q.put_nowait(None)
        try:
            await asyncio.wait_for(self._mqtt_fut, timeout=5.0)
        except Exception:
            pass


def _make_talk_audio_track(pcm_provider: Callable[[], "Optional[bytes]"]):
    """Build an aiortc MediaStreamTrack that emits viewer→camera talk audio.

    Mirrors the official app (f0.java:695): a real audio track is present on the
    PeerConnection from the start, so the camera sees a genuine sender.  The
    track emits 20 ms (160-sample) frames of signed-16-bit PCM at 8 kHz mono;
    aiortc's RTCRtpSender encodes them to PCMA (PT=8) on the wire.

    ``pcm_provider`` is called once per 20 ms frame and returns either 320 bytes
    of s16le PCM (one frame) or ``None``/short data, in which case silence is
    emitted.  Emitting silence (rather than stopping) keeps the track "present
    but quiet" — the equivalent of the app's setEnabled(false) idle state.

    Returns ``None`` if the optional ``av``/``aiortc`` deps are unavailable.
    """
    try:
        import fractions
        import av
        from aiortc.mediastreams import MediaStreamTrack
    except ImportError:
        return None

    _RATE = 8000
    _SAMPLES = 160  # 20 ms @ 8 kHz
    _SILENCE = b"\x00" * (_SAMPLES * 2)

    class _TalkAudioTrack(MediaStreamTrack):
        kind = "audio"

        def __init__(self) -> None:
            super().__init__()
            self._timestamp = 0

        async def recv(self):
            # Pace to real time: one 20 ms frame per 20 ms.
            if self._timestamp:
                await asyncio.sleep(_SAMPLES / _RATE)
            try:
                pcm = pcm_provider()
            except Exception:
                pcm = None
            if not pcm or len(pcm) < _SAMPLES * 2:
                pcm = _SILENCE
            else:
                pcm = pcm[: _SAMPLES * 2]

            frame = av.AudioFrame(format="s16", layout="mono", samples=_SAMPLES)
            frame.planes[0].update(pcm)
            frame.sample_rate = _RATE
            frame.pts = self._timestamp
            frame.time_base = fractions.Fraction(1, _RATE)
            self._timestamp += _SAMPLES
            return frame

    return _TalkAudioTrack()


async def _webrtc_consume_video(track: Any, on_frame: Callable) -> None:
    """Receive video frames from an aiortc VideoStreamTrack and call on_frame."""
    while True:
        try:
            frame = await track.recv()
            try:
                on_frame(frame)
            except Exception:
                _LOGGER.debug("on_frame callback raised", exc_info=True)
        except Exception:
            break


# --------------------------------------------------------------------------- #
# MQTT helpers (playback provisioning + live-stream discovery)
#
# Uses paho-mqtt with WebSocket transport.  The synchronous paho loop runs in
# a thread-pool executor so it never blocks the asyncio event loop.
# Threading primitives (threading.Event, queue.Queue) replace the complex
# asyncio Future/call_soon_threadsafe bridge that had VERSION2 ReasonCode
# compatibility issues.
# --------------------------------------------------------------------------- #

def _mqtt_session_sync(
    mqtt_url: str,
    mqtt_user: str,
    mqtt_pwd: str,
    client_id: str,
    subscribe_topics: list,
    publish_items: list,
    duration: float,
    on_message=None,
    ws_path: str = "/mqtt",
    on_ready=None,
    outgoing_queue=None,
) -> tuple:
    """Synchronous paho MQTT session (runs in a thread executor).

    Returns (messages, status_dict) where:
      messages    = list of (topic, payload_str) tuples received
      status_dict = {"connected": bool, "rc": int, "rc_str": str,
                     "error": str|None, "log": [str, ...]}

    ws_path overrides the WebSocket endpoint path (default "/mqtt").
    Pass "" or "/" to try the root path.

    on_ready(status) — optional callback called after all subscribe/publish
    operations complete but before the receive loop starts.  If it blocks
    (e.g. waiting for user input) the paho background thread continues to
    buffer incoming messages.  The ``duration`` countdown starts only after
    on_ready returns, so use this hook to implement a "wait for ENTER before
    starting the capture window" pattern.
    """
    import paho.mqtt.client as _paho
    import ssl as _ssl
    import threading
    import queue as _queue
    from urllib.parse import urlparse

    parsed   = urlparse(mqtt_url)
    hostname = parsed.hostname or mqtt_url
    port     = parsed.port or (8443 if parsed.scheme in ("wss", "https") else 1883)
    tls      = parsed.scheme in ("wss", "https", "mqtts")
    # ws_path parameter takes priority; fall back to URL path then "/mqtt"
    path     = ws_path if ws_path is not None else (parsed.path or "/mqtt")
    if path == "":
        path = "/"

    msg_q   = _queue.Queue()
    conn_ev = threading.Event()
    status  = {"connected": False, "rc": None, "rc_str": "", "error": None, "log": []}

    # Build client — handle paho ≥2.0 (VERSION2) and <2.0
    try:
        client = _paho.Client(
            callback_api_version=_paho.CallbackAPIVersion.VERSION2,
            client_id=client_id,
            transport="websockets",
        )
    except AttributeError:
        client = _paho.Client(client_id=client_id, transport="websockets")

    client.ws_set_options(path=path)
    if mqtt_user:
        client.username_pw_set(mqtt_user, mqtt_pwd or "")
    if tls:
        ctx = _ssl.create_default_context()
        client.tls_set_context(ctx)

    def _on_connect(c, ud, flags, reason_code, props=None):
        # paho ≥2 passes ReasonCode; paho <2 passes int
        try:
            rc = int(reason_code)
        except (TypeError, ValueError):
            rc = getattr(reason_code, "value", -1)
        status["connected"] = (rc == 0)
        status["rc"]        = rc
        status["rc_str"]    = str(reason_code)
        conn_ev.set()

    def _on_message(c, ud, msg):
        payload = (msg.payload.decode("utf-8", errors="replace")
                   if isinstance(msg.payload, (bytes, bytearray))
                   else str(msg.payload))
        msg_q.put((msg.topic, payload))

    def _on_disconnect(c, ud, disconnect_flags=None, reason_code=None, props=None):
        # If _on_connect was never fired (WebSocket upgrade failed, auth refused
        # at TCP level, etc.) signal conn_ev now so the caller doesn't time out.
        if not conn_ev.is_set():
            status["connected"] = False
            status["rc_str"]    = f"disconnect-before-connect rc={reason_code}"
            conn_ev.set()
        msg_q.put(None)   # sentinel to unblock the receive loop

    def _on_log(c, ud, level, buf):
        if len(status["log"]) < 500:
            status["log"].append(buf)
        if "assword" not in buf:
            _LOGGER.debug("paho: %s", buf)

    client.on_connect    = _on_connect
    client.on_message    = _on_message
    client.on_disconnect = _on_disconnect
    client.on_log        = _on_log

    import time as _time

    try:
        client.connect(hostname, port, keepalive=60)
    except Exception as exc:
        status["error"] = str(exc)
        _LOGGER.warning("_mqtt_session: connect() raised: %s", exc)
        return [], status

    client.loop_start()

    if not conn_ev.wait(timeout=15):
        status["error"] = f"connect timeout to {hostname}:{port}"
        _LOGGER.warning("_mqtt_session: %s", status["error"])
        client.loop_stop()
        try:
            client.disconnect()
        except Exception:
            pass
        return [], status

    if not status["connected"]:
        _LOGGER.warning(
            "_mqtt_session: broker refused rc=%s (%s) for %s:%d",
            status["rc"], status["rc_str"], hostname, port,
        )
        client.loop_stop()
        try:
            client.disconnect()
        except Exception:
            pass
        return [], status

    _LOGGER.info("_mqtt_session: connected to %s:%d clientId=%s", hostname, port, client_id)

    for topic in subscribe_topics:
        client.subscribe(topic)
        _LOGGER.debug("_mqtt_session: subscribed %s", topic)

    for pub_topic, pub_payload in publish_items:
        client.publish(pub_topic, pub_payload)
        _LOGGER.debug("_mqtt_session: published %s", pub_topic)

    if on_ready:
        try:
            on_ready(status)
        except Exception:
            pass

    collected = []
    deadline  = _time.monotonic() + duration
    while True:
        remaining = deadline - _time.monotonic()
        if remaining <= 0:
            break
        try:
            item = msg_q.get(timeout=min(remaining, 0.1))
        except _queue.Empty:
            # Drain outgoing publish queue
            if outgoing_queue is not None:
                while True:
                    try:
                        out = outgoing_queue.get_nowait()
                    except _queue.Empty:
                        break
                    if out is None:   # stop sentinel
                        client.loop_stop()
                        try:
                            client.disconnect()
                        except Exception:
                            pass
                        return collected, status
                    pub_topic, pub_payload = out
                    client.publish(pub_topic, pub_payload)
                    _LOGGER.debug("_mqtt_session: published %s", pub_topic)
            continue
        if item is None:   # disconnect sentinel
            break
        collected.append(item)
        if on_message:
            try:
                on_message(*item)
            except Exception:
                pass

    client.loop_stop()
    try:
        client.disconnect()
    except Exception:
        pass
    return collected, status


async def _mqtt_session(
    mqtt_url: str,
    mqtt_user: str,
    mqtt_pwd: str,
    client_id: str,
    subscribe_topics: list,
    publish_items: list,
    duration: float,
    on_message=None,
    ws_path: str = "/mqtt",
    on_ready=None,
) -> list:
    """Async wrapper: runs _mqtt_session_sync in a thread executor.

    Returns list of (topic, payload_str) tuples.
    """
    messages, status = await _mqtt_session_with_status(
        mqtt_url, mqtt_user, mqtt_pwd, client_id,
        subscribe_topics, publish_items, duration, on_message, ws_path, on_ready,
    )
    if status.get("error"):
        _LOGGER.warning("_mqtt_session failed: %s", status["error"])
    return messages


async def _mqtt_session_with_status(
    mqtt_url: str,
    mqtt_user: str,
    mqtt_pwd: str,
    client_id: str,
    subscribe_topics: list,
    publish_items: list,
    duration: float,
    on_message=None,
    ws_path: str = "/mqtt",
    on_ready=None,
) -> tuple:
    """Like _mqtt_session but also returns the status dict for diagnostics."""
    import functools
    loop = asyncio.get_running_loop()
    fn = functools.partial(
        _mqtt_session_sync,
        mqtt_url, mqtt_user, mqtt_pwd, client_id,
        subscribe_topics, publish_items, duration, on_message, ws_path, on_ready,
    )
    return await loop.run_in_executor(None, fn)


async def _mqtt_get_playback_server_info(
    mqtt_url: str,
    mqtt_user: str,
    mqtt_pwd: str,
    device_id: str,
    client_id: str,
    timeout: float = 15.0,
) -> Optional[dict]:
    """Publish getPlaybackServerInfoReq and return the payload dict, or None.

    MQTT topics from IConstants.java / MqttManage.java:
      publish : iot/v1/s/{userId}/{service}/{method}
      subscribe: iot/v1/cb/{deviceId}/#
    Response arrives on iot/v1/c/{userId}/PlayBack/getPlaybackServerInfoResp
    (or on the device callback topic).
    """
    user_id   = mqtt_user or "0"
    seq       = str(random.randint(100000, 999999))
    pub_topic = f"iot/v1/s/{user_id}/PlayBack/getPlaybackServerInfoReq"
    payload   = json.dumps({
        "method":  "getPlaybackServerInfoReq",
        "service": "PlayBack",
        "devId":   device_id,
        "srcAddr": f"0.{user_id}",
        "seq":     seq,
        "tst":     int(time.time() * 1000),
        "payload": {},
    })

    result_holder: list = []

    def _check(topic, raw):
        try:
            body   = json.loads(raw)
            method = body.get("method", "")
            if "PlaybackServerInfo" not in method and "getPlaybackServer" not in method:
                return
            pl = body.get("payload") or body.get("data") or {}
            if pl.get("serverIP") or pl.get("serverIp"):
                pl["serverIP"] = pl.get("serverIP") or pl.get("serverIp")
                result_holder.append(pl)
        except Exception:
            pass

    await _mqtt_session(
        mqtt_url, mqtt_user, mqtt_pwd, client_id,
        subscribe_topics=[
            f"iot/v1/cb/{device_id}/#",
            f"iot/v1/c/{user_id}/#",
        ],
        publish_items=[(pub_topic, payload)],
        duration=timeout,
        on_message=_check,
    )
    return result_holder[0] if result_holder else None


async def _mqtt_listen(
    mqtt_url: str,
    mqtt_user: str,
    mqtt_pwd: str,
    client_id: str,
    device_id: str,
    duration: float = 60.0,
    on_message=None,
) -> list:
    """Subscribe to all device/user MQTT topics and collect messages for *duration* seconds.

    Returns a list of (topic, payload_str) tuples.
    *on_message(topic, payload_str)* is called for each message as it arrives.
    """
    user_id = mqtt_user or "0"
    return await _mqtt_session(
        mqtt_url, mqtt_user, mqtt_pwd, client_id,
        subscribe_topics=[
            f"iot/v1/cb/{device_id}/#",
            f"iot/v1/c/{user_id}/#",
            f"lds/v1/cb/{device_id}/#",
            f"lds/v1/c/{user_id}/#",
            f"iot/v1/s/{user_id}/#",
        ],
        publish_items=[],
        duration=duration,
        on_message=on_message,
    )


# --------------------------------------------------------------------------- #
# DeviceClient
# --------------------------------------------------------------------------- #

class DeviceClient(object):
    status: DeviceStatusData
    info: DeviceInformation
    _login_uuid = 0
    _connect_and_login: bool = False
    _connecting: bool = False
    _simpleVersion: str = ""
    _ip_address: str = None
    device_id: str
    _is_close: bool = False
    _status_fresh_cb: Any = None

    @property
    def connect_and_login(self) -> bool:
        return self._connect_and_login

    @property
    def connecting(self) -> bool:
        return self._connecting

    # Camera models that report ``enableSdes: '1'`` but whose SDES-SRTP
    # implementation is non-functional on the wire.  Forced to the DTLS path.
    #
    # Models for which we should NOT include an SCTP data channel in the
    # WebRTC offer.  Most KVS-WebRTC firmware (LK.IPC.A000088, .A001513) sends
    # SCTP control messages over DTLS application_data after handshake; if the
    # client never set up an SCTP transport, the camera retransmits, then
    # tears DTLS down with close_notify after ~22 s — observed via byte-tap.
    # A001064 is the exception: across runs it answers our datachannel offer
    # with (a) no m=application section, (b) a different kind, or (c) extra
    # video sections — all of which break setRemoteDescription.  Keep it
    # data-channel-less; it's parked on the SDES/TUTK side anyway.
    _NO_DATACHANNEL_MODELS: frozenset = frozenset({"LK.IPC.A001064"})

    @property
    def _offer_should_include_datachannel(self) -> bool:
        model = getattr(getattr(self, "info", None), "model_id", None)
        return model not in self._NO_DATACHANNEL_MODELS

    @property
    def is_sdes_camera(self) -> bool:
        """True when ``properties.enableSdes == '1'`` in the device API response."""
        props = getattr(self, "_raw_device", {}).get("properties") or {}
        return str(props.get("enableSdes", "0")) == "1"

    @property
    def is_battery_camera(self) -> bool:
        """True for battery/low-power models (A001513, A001108, A001360).
        Source: IpcServiceImpl.java B() — powerType=2 for these models.
        """
        model = getattr(getattr(self, "info", None), "model_id", None) or ""
        return any(m in model for m in ("A001513", "A001108", "A001360"))

    def __init__(self, device: dict[str, Any], user_info: dict[str, Any]) -> None:
        self.ping_count = 0
        self.status = DeviceStatusData()
        self.info = DeviceInformation(device)
        self.user_id = user_info.get(CONF_ID)

        # Store full user_info for camera API calls
        self._user_info: dict[str, Any] = user_info

        # Region written to login_info by AidotClient.async_post_login()
        self._region: str = user_info.get("region", "us")

        # Cache slot for MQTT broker URL, fetched lazily on first playback call
        self._mqtt_url: Optional[str] = None

        # Cache slot for Leedarson smarthome auth (mqttUser, mqttPassword, userId)
        # Fetched lazily via _async_get_smarthome_auth()
        self._smarthome_auth: Optional[dict] = None

        # Raw device dict retained for transport-type detection (isDTLS field)
        self._raw_device: dict = device

        self.password = device.get(CONF_PASSWORD)
        self.device_id = device.get(CONF_ID)

        # Full list of device IDs for this account.  Used when calling
        # batchGetDeviceUserInfo so the server returns data for this device
        # (sending only one ID may yield an empty response).  Populated by
        # AidotClient after the full device list is fetched; falls back to
        # just this device's ID so standalone DeviceClient usage still works.
        self._all_device_ids: list = [self.device_id]

        if CONF_AES_KEY in device:
            key_string = device[CONF_AES_KEY][0]
            if key_string is not None:
                self.aes_key = bytearray(16)
                key_bytes = key_string.encode()
                self.aes_key[: len(key_bytes)] = key_bytes
        self._simpleVersion = device.get("simpleVersion")
        # Pre-populate _ip_address from the device-list entry if it contains
        # an IP field.  Covers cameras (e.g. LK.IPC.A001064) whose
        # batchGetDeviceUserInfo response returns no IP and whose firmware
        # does not push setDevAttrNotif promptly after user/connect.
        _dev_ip_init = (
            device.get("localIp") or device.get("ipAddress")
            or device.get("ip") or device.get("localIPAddress")
            or device.get("wlanIp") or device.get("wifiIp")
            or device.get("lanIp") or device.get("addr")
            or (device.get("properties") or {}).get("ipAddress")
            or (device.get("properties") or {}).get("ip")
        )
        if _dev_ip_init:
            # Guard against ASCII-encoded IPs: the AiDot cloud sometimes stores
            # a LAN IP as raw ASCII bytes (e.g. "192." → octets 49,57,50,46 →
            # "49.57.50.46").  Detect this by checking whether every octet falls
            # in the printable-ASCII range AND decodes to digit/dot characters.
            _ip_str = str(_dev_ip_init)
            try:
                _parts = [int(p) for p in _ip_str.split('.')]
                _decoded = "".join(chr(p) for p in _parts)
                _ascii_encoded = (
                    len(_parts) == 4
                    and all(32 <= p <= 126 for p in _parts)
                    and all(chr(p) in '0123456789.' for p in _parts)
                    and any(_decoded.startswith(pfx)
                            for pfx in ("192.", "10.", "172.", "169.", "127."))
                )
            except Exception:
                _ascii_encoded = False
            if _ascii_encoded:
                _LOGGER.warning(
                    "DeviceClient %s: ignoring ASCII-encoded IP %r from device dict "
                    "(cloud stored IP bytes as ASCII chars; real IP unknown)",
                    device.get("id") or device.get("devId"), _ip_str,
                )
            else:
                self._ip_address = _ip_str

        # Persistent background streaming state
        self.latest_jpeg: Optional[bytes] = None
        self._streaming_active: bool = False
        self._stream_session: Optional[Any] = None
        self._stream_task: Optional["asyncio.Task[None]"] = None
        self._last_frame_time: float = 0.0
        self._keepalive_rtsp_url: Optional[str] = None  # RTSP push URL for go2rtc

    # -- Camera helpers ------------------------------------------------------ #

    @property
    def _smarthome_base(self) -> str:
        return _SMARTHOME_URL_TEMPLATE.format(region=self._region)

    def _leedarson_headers(self) -> dict:
        # Headers from OkHttp interceptor (b.java): token, appId, terminal auto-injected.
        # NOTE: "owner" is intentionally omitted — the recording/playback endpoints
        # return 560073 "Share head error" when owner is present; token alone identifies
        # the user on us-smarthome.arnoo.com.  Add owner only if a specific endpoint
        # requires it (none currently do).
        token = (
            self._user_info.get("accessToken")
            or self._user_info.get("access_token")
            or ""
        )
        return {
            "terminal":        "app",
            "token":           token,
            "appId":           _LEEDARSON_APP_ID,
            "active-language": "en_US",
            "Content-Type":    "application/json",
        }

    async def _async_get_mqtt_url(self) -> Optional[str]:
        # Fetch and cache the WSS MQTT broker URL (and MQTT credentials) from
        # getServerUrlConfig.  The full response is stored in self._smarthome_auth
        # so mqttUser / mqttPassword are captured in the same call.
        if self._mqtt_url:
            return self._mqtt_url

        import aiohttp

        headers = {k: v for k, v in self._leedarson_headers().items()
                   if k != "Content-Type"}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self._smarthome_base}/commonController/getServerUrlConfig",
                    headers=headers,
                    params={"version": "1.0.1", "clientId": f"app-{self.user_id}"},
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    body = await resp.json(content_type=None)

            data = body.get("data") or {}
            _LOGGER.debug("getServerUrlConfig: mqtt=%s ip=%s", data.get("mqttServerUrl"), data.get("ip"))

            mqtt_host = data.get("mqttServerUrl") or ""
            if not mqtt_host:
                # Fall back to the regional MQTT broker URL known to work from
                # the AiDot web client: wss://{region}-mqtt.arnoo.com:8443/mqtt
                _LOGGER.warning(
                    "getServerUrlConfig returned no mqttServerUrl; "
                    "using regional fallback. body=%s", body
                )
                mqtt_host = f"wss://{self._region}-mqtt.arnoo.com:8443/mqtt"

            self._mqtt_url = (
                mqtt_host
                if mqtt_host.startswith(("wss://", "ws://"))
                else f"wss://{mqtt_host}"
            )

            # Capture mqttUser + mqttPassword from this same response if present.
            # iOS SDK binary strings confirm these fields cluster with mqttServerUrl.
            if not self._smarthome_auth:
                self._smarthome_auth = {
                    "mqttUrl":      self._mqtt_url,
                    "mqttUser":     (data.get("mqttUser") or data.get("userId")
                                     or str(self.user_id)),
                    "mqttPassword": (data.get("mqttPassword") or data.get("mqqtPwd")
                                     or ""),
                    "raw":          data,
                }
                _LOGGER.debug(
                    "getServerUrlConfig cached: url=%s user=%s hasPwd=%s",
                    self._mqtt_url,
                    self._smarthome_auth["mqttUser"],
                    bool(self._smarthome_auth["mqttPassword"]),
                )

            # Always forward the broker-observed public IP into _smarthome_auth.raw
            # so _open_sdes_stream can build srflx candidates for WAN cameras.
            # When Strategy 1 auth (mqttPassword in login_info) fires first it sets
            # raw={"source": ...} with no "ip" key; without this patch _public_ip
            # stays None, no srflx candidate is advertised, and cameras on WAN
            # (or a different subnet) can never reach our reservation sockets.
            _raw_ref = (self._smarthome_auth or {}).get("raw")
            if data.get("ip") and isinstance(_raw_ref, dict) and "ip" not in _raw_ref:
                _raw_ref["ip"] = data["ip"]

            return self._mqtt_url

        except Exception as exc:
            _LOGGER.error("_async_get_mqtt_url failed: %s", exc)
            return None

    async def _async_get_smarthome_auth(self) -> Optional[dict]:
        """Fetch MQTT credentials (mqttUser + mqttPassword) for the Arnoo broker.

        Strategy order — stops at first success:
          0. Already cached
          1. mqttPassword already in AiDot login_info (from _async_fetch_user_config)
          2. GET /user/getUser  <- documented SDK step (reqUserAuthInfoWithCallback)
             Returns LDSAuthInfo {userId, mqttUser, mqttPassword, ...}
          3. getServerUrlConfig response side-effect (if MQTT URL not yet fetched)
          4. accessToken as MQTT password (Arnoo broker fallback)
        """
        if self._smarthome_auth and self._smarthome_auth.get("mqttPassword"):
            return self._smarthome_auth

        import aiohttp

        # Smarthome userId — 'id' in AiDot login_info is the Leedarson userId
        _mqtt_id = (
            self._user_info.get("id")
            or self._user_info.get("userId")
            or str(self.user_id)
        )

        # --- Strategy 1: mqttPassword already in AiDot login_info ---
        # _async_fetch_user_config() stores it under "mqttPassword" or "mqttPwd".
        for key in ("mqttPassword", "mqttPwd"):
            val = self._user_info.get(key)
            if val:
                self._smarthome_auth = {
                    "mqttUser":     _mqtt_id,
                    "mqttPassword": val,
                    "userId":       _mqtt_id,
                    "raw":          {"source": f"login_info.{key}"},
                }
                return self._smarthome_auth

        # --- Strategy 2: GET /user/getUser  (reqUserAuthInfoWithCallback in SDK) ---
        # CocoaPods README documents the 3-step auth flow:
        #   1. loginWithUserName -> accessToken
        #   2. setHeader (set token on SDK)
        #   3. reqUserAuthInfoWithCallback -> LDSAuthInfo {mqttUser, mqttPassword}
        token = (
            self._user_info.get("accessToken")
            or self._user_info.get("access_token")
            or ""
        )
        if token:
            headers = self._leedarson_headers()
            try:
                async with aiohttp.ClientSession() as _s2:
                    async with _s2.post(
                        f"{self._smarthome_base}/user/getUser",
                        headers=headers,
                        json={"desc": _mqtt_id},
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as resp:
                        body = await resp.json(content_type=None)

                code = body.get("code")
                data = body.get("data") or {}
                _LOGGER.debug(
                    "_async_get_smarthome_auth /user/getUser -> code=%s  data_keys=%s",
                    code, list(data.keys()) if isinstance(data, dict) else data,
                )
                if isinstance(data, dict):
                    auth = data.get("authInfo") or data
                    mqtt_user = (
                        auth.get("mqttUser")
                        or auth.get("userId")
                        or auth.get("associatedAccount")
                        or _mqtt_id
                    )
                    mqtt_pwd = (
                        auth.get("mqttPassword")
                        or auth.get("mqqtPwd")
                        or auth.get("mqttPwd")
                        or ""
                    )
                    if mqtt_pwd:
                        self._smarthome_auth = {
                            "mqttUser":     mqtt_user,
                            "mqttPassword": mqtt_pwd,
                            "userId":       auth.get("userId") or mqtt_user,
                            "raw":          auth,
                        }
                        _LOGGER.debug(
                            "_async_get_smarthome_auth OK via /user/getUser: mqttUser=%s",
                            mqtt_user,
                        )
                        return self._smarthome_auth
            except Exception as exc:
                _LOGGER.debug("_async_get_smarthome_auth /user/getUser exc: %s", exc)

        # --- Strategy 3: getServerUrlConfig ---
        if not self._mqtt_url:
            await self._async_get_mqtt_url()
        if self._smarthome_auth and self._smarthome_auth.get("mqttPassword"):
            _LOGGER.warning("_async_get_smarthome_auth: mqttPassword from getServerUrlConfig")
            return self._smarthome_auth

        # --- Strategy 4: accessToken as MQTT password (common Arnoo pattern) ---
        # The Arnoo broker accepts (userId, accessToken) as credentials when the
        # /user/getUser call fails.  Always available after AiDot login.
        access_token = (
            self._user_info.get("accessToken")
            or self._user_info.get("access_token")
            or ""
        )
        if access_token:
            _LOGGER.warning(
                "_async_get_smarthome_auth: /user/getUser gave no mqttPassword; "
                "falling back to userId+accessToken for MQTT."
            )
            self._smarthome_auth = {
                "mqttUser":     _mqtt_id,
                "mqttPassword": access_token,
                "userId":       _mqtt_id,
                "raw":          {"source": "accessToken_fallback"},
            }
            return self._smarthome_auth

        _LOGGER.error(
            "_async_get_smarthome_auth: all strategies failed. login_info_keys=%s",
            list(self._user_info.keys()),
        )
        return None

    # -- Camera public methods ----------------------------------------------- #

    @property
    def _aidot_v21_base(self) -> str:
        return f"https://prod-{self._region}-api.arnoo.com/v21"

    @property
    def _aidot_v32_base(self) -> str:
        return f"https://prod-{self._region}-api.arnoo.com/v32/api/ipc"

    def _aidot_headers(self) -> dict:
        # Auth headers for the AiDot platform API (prod-{region}-api.arnoo.com).
        # Matches AidotClient.async_session_get(): CONF_APP_ID="Appid", APP_ID,
        # CONF_TOKEN="Token", CONF_TERMINAL="Terminal" (see login_const.py/const.py).
        token = (self._user_info.get("accessToken")
                 or self._user_info.get("access_token") or "")
        return {
            "Appid":        "1383974540041977857",
            "Token":        token,
            "Terminal":     "app",
            "Content-Type": "application/json",
        }

    async def async_get_device_user_info(
        self,
        all_device_ids: Optional[List[str]] = None,
    ) -> Optional[dict]:
        """Fetch per-device user info from the AiDot v21 API.

        POST /v21/devices/batchGetDeviceUserInfo
        Returns the raw data dict for this device, or None on failure.
        This is the same call the AiDot widget/app makes; the response includes
        the TUTK p2pId and any per-device streaming credentials.

        Args:
            all_device_ids: All device IDs to include in the batch request.
                The app sends all device IDs in a single call (~260 bytes for
                7 devices). Sending only one ID may cause the server to return
                an empty result. Pass the full list from the account's device
                listing if available.
        """
        import aiohttp
        ids = all_device_ids or [self.device_id]
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self._aidot_v21_base}/devices/batchGetDeviceUserInfo",
                    json={"deviceIds": ids},
                    headers=self._aidot_headers(),
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    body = await resp.json(content_type=None)
                    status = resp.status

            # Store the raw response so callers can inspect it for diagnostics.
            self._last_batch_response = body

            # Server may return a bare JSON array OR {"data": [...]} / {"data": {}}
            if isinstance(body, list):
                data = body
                _LOGGER.debug("batchGetDeviceUserInfo bare-list response for %s: %d items",
                              self.device_id, len(data))
            elif isinstance(body, dict):
                data = body.get("data") or {}
                if data:
                    _LOGGER.debug("batchGetDeviceUserInfo response for %s (status=%d): %s",
                                  self.device_id, status, body)
                else:
                    _LOGGER.warning(
                        "batchGetDeviceUserInfo no data for %s (status=%d): %s",
                        self.device_id, status, body,
                    )
            else:
                data = {}

            # Find the entry for this device
            if isinstance(data, dict):
                item = data.get(self.device_id) or next(iter(data.values()), None)
                return item
            if isinstance(data, list):
                for item in data:
                    # Server may use "deviceId", "devId", or "id" as the device
                    # identifier field.  Try all variants so that the correct
                    # camera's entry is returned even when the field name differs
                    # from the most-common "deviceId".  Without this, the code
                    # falls back to data[0] (the first camera in the batch),
                    # producing the wrong numeric userId and broken MQTT topics.
                    if isinstance(item, dict) and (
                        item.get("deviceId") == self.device_id
                        or item.get("devId") == self.device_id
                        or item.get("id") == self.device_id
                    ):
                        _LOGGER.debug(
                            "batchGetDeviceUserInfo matched device %s: keys=%s",
                            self.device_id, sorted(item.keys()),
                        )
                        return item
                # No exact match found — log which device IDs were present so
                # the caller can diagnose why the lookup failed.  Falling back
                # to data[0] will return the wrong camera's userId, which
                # produces incorrect MQTT subscription topics and prevents
                # getIceConfigResp (TURN credentials) from being received.
                _found_ids = [
                    item.get("deviceId") or item.get("devId") or item.get("id")
                    for item in data[:10] if isinstance(item, dict)
                ]
                _LOGGER.warning(
                    "batchGetDeviceUserInfo: no item matched device_id=%r"
                    " — falling back to data[0].  Device IDs in response: %s"
                    "  (wrong userId will cause broken MQTT topics and missing"
                    " TURN credentials)",
                    self.device_id, _found_ids,
                )
                return data[0] if data else None
        except Exception as exc:
            _LOGGER.error("async_get_device_user_info failed for %s: %s",
                          self.device_id, exc)
        return None

    async def async_get_p2p_uid(self) -> Optional[str]:
        """Fetch the TUTK P2P UID for this camera.

        Tries two sources in order:
          1. POST /v21/devices/batchGetDeviceUserInfo  (AiDot platform API)
          2. POST /deviceController/getP2pId           (Leedarson smarthome API)
        """
        import aiohttp

        # --- Source 1: AiDot v21 batchGetDeviceUserInfo ---
        try:
            dev_info = await self.async_get_device_user_info()
            if isinstance(dev_info, dict):
                uid = (dev_info.get("p2pId")
                       or dev_info.get("uid")
                       or dev_info.get("tutk_uid")
                       or dev_info.get("tutkUid"))
                if uid:
                    _LOGGER.debug("async_get_p2p_uid: got UID from batchGetDeviceUserInfo: %s", uid)
                    return str(uid)
        except Exception as exc:
            _LOGGER.debug("async_get_p2p_uid: batchGetDeviceUserInfo failed: %s", exc)

        # --- Source 2: Leedarson smarthome /deviceController/getP2pId ---
        headers = {k: v for k, v in self._leedarson_headers().items()
                   if k != "Content-Type"}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self._smarthome_base}/deviceController/getP2pId",
                    data={"deviceId": self.device_id},
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    body = await resp.json(content_type=None)

            uid = body.get("data") or body.get("uid")
            if uid:
                _LOGGER.debug("async_get_p2p_uid: got UID from getP2pId: %s", uid)
                return str(uid)
            _LOGGER.debug("async_get_p2p_uid: getP2pId returned no UID for %s. body=%s",
                          self.device_id, body)
        except Exception as exc:
            _LOGGER.debug("async_get_p2p_uid: smarthome call failed for %s: %s",
                          self.device_id, exc)

        # --- Source 3: AiDot v32 IPC device detail ---
        # Android app's NewLiveFragment.w5() parses a JSON string from the device
        # object to obtain the TUTK UID. The v32 IPC endpoint may return it directly.
        # Known paths from iOS HTTP traffic: /v32/api/ipc/devices/{id}
        for path in (
            f"/devices/{self.device_id}",
            f"/devices/{self.device_id}/info",
            f"/devices/{self.device_id}/detail",
        ):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        f"{self._aidot_v32_base}{path}",
                        headers=self._aidot_headers(),
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as resp:
                        body = await resp.json(content_type=None)

                data = body.get("data") or body if isinstance(body, dict) else {}
                uid = (data.get("p2pId") or data.get("tutkUid")
                       or data.get("tutk_uid") or data.get("uid")
                       or data.get("iotcUid") or data.get("p2pUID"))
                if uid:
                    _LOGGER.debug("async_get_p2p_uid: got UID from v32%s: %s", path, uid)
                    return str(uid)
                _LOGGER.debug("async_get_p2p_uid: v32%s returned no UID for %s. body=%s",
                              path, self.device_id, body)
                # If we got a 200-level response (not 404/405), don't try other paths
                break
            except Exception as exc:
                _LOGGER.debug("async_get_p2p_uid: v32%s failed for %s: %s",
                              path, self.device_id, exc)

        _LOGGER.warning(
            "async_get_p2p_uid: all three sources returned empty UID for %s",
            self.device_id,
        )
        return None

    # ------------------------------------------------------------------ #
    # Phase 2: device controls via MQTT setDevAttrReq                     #
    # ------------------------------------------------------------------ #

    async def _mqtt_device_cmd(
        self,
        pub_topic: str,
        payload_str: str,
        *,
        timeout: float = 8.0,
        ack_keyword: str = "setDevAttr",
    ) -> bool:
        """Connect MQTT, optionally wake battery camera, publish command, wait for ack.

        All setDevAttrReq callers in the APK (b6.java, LiveCameraView, etc.)
        are in live-view screens where the camera is already awake and MQTT-
        connected.  For battery cameras we send lowPowerActiveStateReq first so
        the camera wakes and processes our command.
        """
        import json as _json

        smarthome_auth = await self._async_get_smarthome_auth()
        mqtt_user = (smarthome_auth or {}).get("mqttUser") or str(self.user_id)
        mqtt_pwd  = (smarthome_auth or {}).get("mqttPassword") or ""
        client_id = (self._user_info.get("mqttClientId") or f"app-{mqtt_user}")
        user_id   = self.user_id

        mqtt_url = await self._async_get_mqtt_url()
        if not mqtt_url:
            _LOGGER.error("_mqtt_device_cmd: no MQTT URL for %s", self.device_id)
            return False

        device_id = self.device_id
        sub_topics = [
            f"iot/v1/c/{user_id}/#",
            f"iot/v1/cb/{user_id}/#",
            f"iot/v1/cb/{device_id}/#",
            f"iot/v1/c/{device_id}/#",
        ]

        # Wake battery cameras before sending the control command.
        # Battery cameras (batteryMode=2) sleep between sessions and disconnect
        # from MQTT.  Without the wake call they miss our setDevAttrReq.
        # Payload from DeviceWakeUpRepos.java — no srcAddr/seq/tst.
        publish_items: list = []
        if self.is_battery_camera:
            _wake_payload = _json.dumps({
                "method":  "lowPowerActiveStateReq",
                "service": "IPC",
                "devId":   device_id,
                "userId":  str(user_id),
                "payload": {"devId": device_id, "status": "wakeup"},
            })
            _wake_topic = f"iot/v1/s/{user_id}/IPCAM/lowPowerActiveStateReq"
            publish_items.append((_wake_topic, _wake_payload))
        publish_items.append((pub_topic, payload_str))

        messages = await _mqtt_session(
            mqtt_url, mqtt_user, mqtt_pwd, client_id,
            subscribe_topics=sub_topics,
            publish_items=publish_items,
            duration=timeout,
        )

        for topic, raw in messages:
            if ack_keyword and ack_keyword not in topic:
                continue
            try:
                msg = _json.loads(raw)
            except Exception:
                continue
            code = (msg.get("ack") or {}).get("code") or msg.get("code")
            if code == 200:
                _LOGGER.debug("device cmd ack 200: topic=%s", topic)
                return True
            # Some firmware ACKs with code in payload.payload
            inner = msg.get("payload") or {}
            if isinstance(inner, dict) and inner.get("code") == 200:
                _LOGGER.debug("device cmd ack 200 (inner): topic=%s", topic)
                return True

        # Fire-and-forget fallback: if we published successfully and got ANY
        # broker delivery confirmation (no MQTT error), treat as success.
        # The official app uses a delivery callback, not a device response.
        if messages is not None:
            _LOGGER.debug(
                "device cmd: sent (no explicit 200-ack on %s, %d msgs total) "
                "— treating as sent-ok (official app is fire-and-forget)",
                device_id, len(messages),
            )
            return True

        return False

    async def async_set_device_attribute(
        self,
        attr: str,
        value,
        *,
        timeout: float = 8.0,
    ) -> bool:
        """Set one camera attribute via MQTT setDevAttrReq.

        Exact format from b6.java (NewLivePresenter.j0()):
          Topic:   iot/v1/c/{deviceId}/device/setDevAttrReq
          Payload: {"id": deviceId, "method": "setDevAttrReq",
                    "service": "device", "seq": "<generated>",
                    "payload": {"attr": {key: value}}}

        LDSBaseMqttServiceImpl auto-injects seq in the official app;
        we add it ourselves.  onlyPubAck=false means camera sends
        setDevAttrResp matched by seq.  _mqtt_device_cmd sends a
        lowPowerActiveStateReq wake signal before this command.
        """
        import json as _json
        import random as _random

        device_id = self.device_id
        user_id   = self.user_id
        # camera's local password (from device API dict 'password' field)
        cam_pwd   = getattr(getattr(self, "info", None), "device_password", "") or ""
        seq = f"ap{_random.randint(1000000, 9999999)}"
        # Web app JS (app-beautified.js:26551) includes userId + password in payload;
        # b6.java does not — camera accepts both, but web format is more complete.
        inner: dict = {"devId": device_id, "attr": {attr: value}}
        if user_id:
            inner["userId"] = str(user_id)
        if cam_pwd:
            inner["password"] = cam_pwd
        payload = _json.dumps({
            "id":      device_id,
            "method":  "setDevAttrReq",
            "service": "device",
            "seq":     seq,
            "payload": inner,
        })
        pub_topic = f"iot/v1/c/{device_id}/device/setDevAttrReq"
        _LOGGER.info("setDevAttrReq: %s=%s → %s  seq=%s", attr, value, device_id, seq)
        return await self._mqtt_device_cmd(
            pub_topic, payload, timeout=timeout, ack_keyword="setDevAttr")

    async def async_trigger_device_action(
        self,
        action: str,
        params,
        *,
        timeout: float = 4.0,
    ) -> bool:
        """Send a devActionReq (e.g. siren/alarm trigger).

        Correct format from decompiled APK (b6.java h0()):
          Topic:   iot/v1/s/{userId}/device/devActionReq
          Payload: {"method": "devActionReq", "service": "device",
                    "payload": {"devId": deviceId, "action": action, "in": params}}
        """
        import json as _json

        user_id   = self.user_id
        device_id = self.device_id

        payload = _json.dumps({
            "method":  "devActionReq",
            "service": "device",
            "payload": {
                "devId":  device_id,
                "action": action,
                "in":     params,
            },
        })
        pub_topic = f"iot/v1/s/{user_id}/device/devActionReq"
        _LOGGER.info("devActionReq: %s %s → %s", action, params, device_id)
        return await self._mqtt_device_cmd(
            pub_topic, payload, timeout=timeout, ack_keyword="devAction")

    # Convenience wrappers — confirmed attribute names/types from APK source

    async def async_set_motion_detection(self, enabled: bool) -> bool:
        # MotionDetection_Enable is read as getString() in IpcServiceImpl → use str
        return await self.async_set_device_attribute(
            "MotionDetection_Enable", "1" if enabled else "0")

    async def async_set_floodlight(self, on: bool, brightness: int = 100) -> bool:
        # Confirmed 2026-05-05: cameras with autoLightEnable=1 (PTZ, Deck) ignore
        # manual LightOnOff commands unless auto-light is disabled first.
        # Turning on: disable auto-light, set LightOnOff=1 (and optional Dimming).
        # Turning off: set LightOnOff=0 only (leave autoLightEnable as-is so the
        # camera can resume auto mode on its own schedule).
        if on:
            # Fire prereq without blocking — 1.5s is enough to catch most ACKs but
            # we don't need confirmation before sending LightOnOff.
            await self.async_set_device_attribute("autoLightEnable", 0, timeout=1.5)
        ok = await self.async_set_device_attribute("LightOnOff", 1 if on else 0)
        if ok and on and brightness != 100:
            await self.async_set_device_attribute(
                "Dimming", max(0, min(100, brightness)))
        return ok

    async def async_set_status_led(self, enabled: bool) -> bool:
        return await self.async_set_device_attribute("LedOnOff", 1 if enabled else 0)

    async def async_set_microphone(self, enabled: bool) -> bool:
        # micEnable: 1=on (default), 0=off
        return await self.async_set_device_attribute("micEnable", 1 if enabled else 0)

    async def async_set_speaker_volume(self, level: int) -> bool:
        return await self.async_set_device_attribute(
            "SoundLevel", max(0, min(100, level)))

    async def async_set_siren(self, on: bool) -> bool:
        # Siren uses devActionReq(action="playSound", in=[on,1,30])
        # in[0]=1/0, in[1]=type?, in[2]=duration seconds
        # No attr notification comes back — track state locally.
        result = await self.async_trigger_device_action(
            "playSound", [1 if on else 0, 1, 30])
        self.status.siren = on
        return result

    async def async_set_night_vision(self, mode: str) -> bool:
        """mode: 'auto' (0), 'on' (1), 'off' (2)"""
        _modes = {"auto": 0, "on": 1, "off": 2}
        value = _modes.get(mode.lower())
        if value is None:
            raise ValueError(f"Invalid night vision mode: {mode!r}. Expected 'auto', 'on', or 'off'.")
        return await self.async_set_device_attribute("nightVisionMode", value)

    async def async_set_ptz_tracking(self, enabled: bool) -> bool:
        return await self.async_set_device_attribute(
            "trackingMode", 1 if enabled else 0)

    async def async_set_motion_sensitivity(self, level: int) -> bool:
        """Set motion detection sensitivity.

        level: 1 (lowest) – 5 (highest).
        Attribute: MotionDetection_Sen (observed value '2' on A000088).
        """
        return await self.async_set_device_attribute(
            "MotionDetection_Sen", max(1, min(5, int(level))))

    async def async_set_ir_light(self, enabled: bool) -> bool:
        """Control the IR illumination LEDs independently of night-vision mode.

        Attribute: nightVisionIRLight (0=off, 1=on).
        Note: nightVisionMode still controls the IR cut filter / B&W switch.
        """
        return await self.async_set_device_attribute(
            "nightVisionIRLight", 1 if enabled else 0)

    async def async_get_camera_attributes(
        self,
        *,
        timeout: float = 8.0,
    ) -> Optional[dict]:
        """Read camera attributes by announcing user presence and waiting for setDevAttrNotif.

        Mirrors the official app flow (l.java + IpcServiceImpl.java):
          1. Subscribe iot/v1/c/{userId}/# and iot/v1/cb/{deviceId}/#
          2. Publish iot/v1/cb/{userId}/user/connect  (triggers camera to push state)
          3. For battery cameras: publish lowPowerActiveStateReq to wake from deep sleep
          4. Wait for camera-pushed setDevAttrNotif

        Returns the ``attr`` dict on success, else None.
        """
        import json as _json
        import time as _time

        smarthome_auth = await self._async_get_smarthome_auth()
        mqtt_user = (smarthome_auth or {}).get("mqttUser") or str(self.user_id)
        mqtt_pwd  = (smarthome_auth or {}).get("mqttPassword") or ""
        client_id = (self._user_info.get("mqttClientId") or f"app-{mqtt_user}")
        user_id   = self.user_id
        device_id = self.device_id

        mqtt_url = await self._async_get_mqtt_url()
        if not mqtt_url:
            _LOGGER.error("async_get_camera_attributes: no MQTT URL for %s", device_id)
            return None

        sub_topics = [
            f"iot/v1/c/{user_id}/#",
            f"iot/v1/cb/{user_id}/#",
            f"iot/v1/cb/{device_id}/#",
            f"iot/v1/c/{device_id}/#",
        ]

        # Announce user presence — triggers online cameras to push setDevAttrNotif.
        # Exact format from l.java P():
        #   topic:   iot/v1/cb/{userId}/user/connect
        #   payload: {service:"user", method:"connect", srcAddr:"0.{userId}",
        #             payload:{timestamp:"yyyy-MM-dd HH:mm:ss.SSS"}}
        _ts = _time.strftime("%Y-%m-%d %H:%M:%S.") + f"{int(_time.time() * 1000) % 1000:03d}"
        _connect_topic   = f"iot/v1/cb/{user_id}/user/connect"
        _connect_payload = _json.dumps({
            "service": "user",
            "method":  "connect",
            "srcAddr": f"0.{user_id}",
            "payload": {"timestamp": _ts},
        })

        publish_items = [(_connect_topic, _connect_payload)]

        # For battery cameras (lowPowerActiveState): send wake signal so the camera
        # exits deep sleep and responds.  Payload from DeviceWakeUpRepos.java —
        # keys are method/devId/userId/service/payload; no srcAddr/seq/tst.
        if self.is_battery_camera:
            _wake_topic   = f"iot/v1/s/{user_id}/IPCAM/lowPowerActiveStateReq"
            _wake_payload = _json.dumps({
                "method":  "lowPowerActiveStateReq",
                "service": "IPC",
                "devId":   device_id,
                "userId":  str(user_id),
                "payload": {"devId": device_id, "status": "wakeup"},
            })
            publish_items.append((_wake_topic, _wake_payload))

        messages = await _mqtt_session(
            mqtt_url, mqtt_user, mqtt_pwd, client_id,
            subscribe_topics=sub_topics,
            publish_items=publish_items,
            duration=timeout,
        )

        for topic, raw in messages:
            if "setDevAttrNotif" not in topic:
                continue
            try:
                msg = _json.loads(raw)
            except Exception:
                continue
            inner = msg.get("payload") or msg
            attr = inner.get("attr") if isinstance(inner, dict) else None
            if attr and isinstance(attr, dict):
                _LOGGER.debug(
                    "async_get_camera_attributes %s: %s", device_id, attr
                )
                return attr

        _LOGGER.debug(
            "async_get_camera_attributes: no attr response from %s (got %d msgs)",
            device_id, len(messages),
        )
        return None

    async def async_get_cloud_recordings(
        self,
        start_ts: int,
        end_ts: int,
        *,
        page: int = 1,
        page_size: int = 10,
    ) -> List[dict]:
        """List cloud-recorded event clips for this camera.

        start_ts / end_ts: Unix timestamps in milliseconds.
        page: 1-indexed page number (the server uses 1-based pagination).
        Returns list of dicts from the server (each has eventUuid, eventDesc, picUrl, etc.).

        Uses /api/ipc/playback/eventRecordingList (confirmed from EventListRepos.java).
        Body format from EventListRequestParamsBean: deviceIds (list), recordSta, recordEnd,
        eventCodes (list), areaIds (list), pageNum, pageSize.
        """
        import aiohttp

        await self._async_get_smarthome_auth()
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self._smarthome_base}/api/ipc/playback/eventRecordingList",
                    json={
                        "deviceIds":  [self.device_id],
                        "eventCodes": [],
                        "areaIds":    [],
                        "pageNum":    page,
                        "pageSize":   page_size,
                        "recordSta":  start_ts,
                        "recordEnd":  end_ts,
                    },
                    headers=self._leedarson_headers(),
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    body = await resp.json(content_type=None)

            _LOGGER.debug("eventRecordingList raw response for %s: %s", self.device_id, body)
            if body.get("code") != 200:
                _LOGGER.warning(
                    "eventRecordingList code=%s msg=%s for %s",
                    body.get("code"), body.get("desc") or body.get("msg"), self.device_id,
                )
                return []

            data = body.get("data") or {}
            items = data.get("list") or []
            _LOGGER.info(
                "eventRecordingList for %s: total=%s returned=%d",
                self.device_id, data.get("total"), len(items),
            )
            return items

        except Exception as exc:
            _LOGGER.error(
                "async_get_cloud_recordings failed for %s: %s", self.device_id, exc
            )
            return []

    async def async_get_event_video_url(self, event_uuid: str) -> Optional[str]:
        """Return a direct playback URL (MP4 or M3U8) for a specific recording.

        event_uuid: the eventUuid field from an async_get_cloud_recordings() item.
        Returns the first video URL from getEventVideoUrl, or None on error.

        From CloudPlaybackFragment.java / EventListRepos.java:
          POST /api/ipc/playback/getEventVideoUrl
          body: {deviceId, eventList: [{eventUuid}]}
          response: data.eventUrlList[0].videoUrlList[0].url
          type 1 = MP4, type 2 = M3U8
        """
        import aiohttp

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self._smarthome_base}/api/ipc/playback/getEventVideoUrl",
                    json={
                        "deviceId":  self.device_id,
                        "eventList": [{"eventUuid": event_uuid}],
                    },
                    headers=self._leedarson_headers(),
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    body = await resp.json(content_type=None)

            if body.get("code") != 200:
                _LOGGER.warning(
                    "getEventVideoUrl code=%s for %s uuid=%s: %s",
                    body.get("code"), self.device_id, event_uuid, body,
                )
                return None

            event_url_list = ((body.get("data") or {}).get("eventUrlList") or [])
            if not event_url_list:
                return None
            video_url_list = (event_url_list[0] or {}).get("videoUrlList") or []
            if not video_url_list:
                return None
            return video_url_list[0].get("url") or None

        except Exception as exc:
            _LOGGER.error(
                "async_get_event_video_url failed for %s uuid=%s: %s",
                self.device_id, event_uuid, exc,
            )
            return None

    async def async_get_latest_thumbnail(self) -> Optional[str]:
        """Return the URL of the most recent event/motion thumbnail for this camera.

        Uses /api/ipc/playback/eventRecordingList (pageNum=1, pageSize=1) and extracts
        the picUrl CDN field from the first result.  This endpoint works without an
        "owner" header (unlike the videoController paths which return 560073 with owner).

        Returns the CDN URL string, or None if no events exist.
        """
        import aiohttp, time

        await self._async_get_smarthome_auth()
        end_ts = int(time.time() * 1000)
        start_ts = end_ts - 30 * 86_400_000  # look back 30 days

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self._smarthome_base}/api/ipc/playback/eventRecordingList",
                    json={
                        "deviceIds":  [self.device_id],
                        "eventCodes": [],
                        "areaIds":    [],
                        "pageNum":    1,
                        "pageSize":   1,
                        "recordSta":  start_ts,
                        "recordEnd":  end_ts,
                    },
                    headers=self._leedarson_headers(),
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    body = await resp.json(content_type=None)

            _LOGGER.debug("thumbnail eventRecordingList for %s: %s", self.device_id, body)
            if body.get("code") != 200:
                _LOGGER.debug(
                    "async_get_latest_thumbnail: code=%s for %s (no cloud plan or no events)",
                    body.get("code"), self.device_id,
                )
                return None

            items = ((body.get("data") or {}).get("list") or [])
            if not items:
                _LOGGER.debug("No event photos available for %s", self.device_id)
                return None

            url = items[0].get("picUrl")
            _LOGGER.debug("Latest thumbnail for %s: %s", self.device_id, url)
            return url or None

        except Exception as exc:
            _LOGGER.error(
                "async_get_latest_thumbnail failed for %s: %s", self.device_id, exc
            )
            return None

    async def async_snapshot(
        self,
        output_path: str,
        timeout: float = 30.0,
        status_callback: Optional[Callable[[str], None]] = None,
    ) -> bool:
        """Capture a JPEG still from the camera's live WebRTC stream.

        DTLS cameras (A000088): waits for the first keyframe via on_frame callback.
        SDES cameras (A001064/A001513): streams ~5s to a temp TS file, then extracts
        one JPEG with ffmpeg (on_frame is never called for SDES).

        Args:
            output_path: Destination file path (e.g. ``/tmp/snap.jpg``).
            timeout:     Seconds to wait for the first frame / stream start.
            status_callback: Optional callback for connection status messages.

        Returns:
            True if the snapshot was saved successfully, False otherwise.
        """
        import asyncio as _asyncio

        # ── SDES path: stream briefly to a temp TS file, extract one JPEG ──── #
        if self.is_sdes_camera:
            import os as _os
            import subprocess as _sp
            import tempfile as _tf

            with _tf.NamedTemporaryFile(suffix=".ts", delete=False) as _tmpf:
                _tmp_ts = _tmpf.name
            try:
                # SDES cameras require a full SCTP/DCEP handshake before streaming.
                # The bridge thread (STUN+SCTP+DCEP) takes 25-35s; LIVING is sent
                # only after DCEP_OPEN + 300ms.  PLI forces an IDR every 5s once
                # streaming starts, so 10s of recording is always enough for a still.
                # Battery cameras (A001513) can take up to 17s to wake and send their
                # SDP answer — use a 45s cap so answer_fut does not expire first.
                _sdes_snap_seconds = 10
                _session = await self.async_open_webrtc_stream(
                    on_frame=lambda _f: None,
                    output_path=_tmp_ts,
                    max_seconds=_sdes_snap_seconds,
                    timeout=timeout,
                    status_callback=status_callback,
                    _sdes_answer_timeout=45.0,
                )
                try:
                    await _asyncio.wait_for(
                        _session.wait_done(),
                        timeout=_sdes_snap_seconds + 80,
                    )
                except (_asyncio.TimeoutError, _asyncio.CancelledError):
                    pass
                finally:
                    await _session.stop()

                if _os.path.getsize(_tmp_ts) == 0:
                    _LOGGER.warning(
                        "async_snapshot SDES: stream produced no data for %s",
                        self.device_id,
                    )
                    return False

                _ffmpeg_snap = _sp.run(
                    ["ffmpeg", "-y", "-i", _tmp_ts,
                     "-frames:v", "1", "-f", "image2", output_path],
                    capture_output=True, timeout=15,
                )
                if _ffmpeg_snap.returncode == 0 and _os.path.exists(output_path):
                    return True
                _LOGGER.warning(
                    "async_snapshot SDES: ffmpeg frame extract failed for %s: %s",
                    self.device_id,
                    _ffmpeg_snap.stderr.decode(errors="replace")[-200:],
                )
                return False
            except Exception as _snap_exc:
                _LOGGER.error(
                    "async_snapshot SDES failed for %s: %s", self.device_id, _snap_exc)
                return False
            finally:
                try:
                    _os.unlink(_tmp_ts)
                except Exception:
                    pass

        # ── DTLS path: on_frame callback delivers frames from aiortc ─────── #
        frame_event = _asyncio.Event()
        captured: list = [None]  # stores PIL Image or ndarray once decoded

        def _on_frame(frame) -> None:
            if frame_event.is_set():
                return
            # Skip non-keyframes to avoid reference-frame artifacts on first delivery.
            if not getattr(frame, "key_frame", True):
                return
            # Decode the frame NOW while PyAV's decoder buffer is still valid.
            try:
                captured[0] = frame.to_image()          # PIL Image
            except Exception:
                try:
                    captured[0] = frame.to_ndarray(format="rgb24")  # numpy
                except Exception:
                    return
            frame_event.set()

        session = await self.async_open_webrtc_stream(
            on_frame=_on_frame,
            timeout=timeout,
            status_callback=status_callback,
        )
        try:
            try:
                await _asyncio.wait_for(frame_event.wait(), timeout=timeout)
            except _asyncio.TimeoutError:
                _LOGGER.warning(
                    "async_snapshot: no keyframe received within %.0fs for %s",
                    timeout, self.device_id,
                )
                return False
        finally:
            await session.stop()

        if captured[0] is None:
            return False
        return _save_frame_as_jpeg(captured[0], output_path)

    async def async_start_streaming(self) -> None:
        """Start a persistent background WebRTC stream that updates latest_jpeg.

        DTLS cameras (A000088): frames delivered via on_frame callback, latest_jpeg updated.
        SDES cameras (A001064/A001513): on_frame not available (ffmpeg writes TS directly),
        so latest_jpeg stays None. HA camera entity falls back to cloud thumbnail in that case.
        Safe to call multiple times — does nothing if already running.
        """
        if self.is_sdes_camera:
            _LOGGER.debug(
                "SDES camera %s: latest_jpeg not updated by streaming"
                " (HA will use cloud thumbnail fallback)",
                self.device_id,
            )
            return
        if self._stream_task is not None and not self._stream_task.done():
            return
        self._streaming_active = True
        self._stream_task = asyncio.ensure_future(self._streaming_loop())

    async def async_stop_streaming(self) -> None:
        """Stop the persistent background WebRTC stream."""
        self._streaming_active = False
        session, self._stream_session = self._stream_session, None
        if session is not None:
            try:
                await session.stop()
            except Exception:
                pass
        task, self._stream_task = self._stream_task, None
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

    async def start_keepalive(self, rtsp_push_url: Optional[str] = None) -> None:
        """Start a persistent stream that keeps the camera session alive.

        For SDES cameras (A001064/A001513): opens an indefinite ffmpeg stream and
        optionally pushes it to an RTSP server (e.g. go2rtc at rtsp://127.0.0.1:8554).
        This avoids the 25-70s cold-start SCTP handshake on every viewer connection.

        For DTLS cameras (A000088): delegates to async_start_streaming() which drives
        the existing on_frame keepalive loop (latest_jpeg is updated continuously).

        Safe to call multiple times — does nothing if already running.
        """
        if self._stream_task is not None and not self._stream_task.done():
            return
        self._keepalive_rtsp_url = rtsp_push_url
        self._streaming_active = True
        if self.is_sdes_camera:
            self._stream_task = asyncio.ensure_future(self._sdes_keepalive_loop())
        else:
            self._stream_task = asyncio.ensure_future(self._streaming_loop())

    @property
    def stream_rtsp_url(self) -> Optional[str]:
        """RTSP pull URL for the live keepalive stream, or None if not running.

        When keepalive is active with an RTSP push URL of the form
        ``rtsp://HOST:PORT/NAME``, go2rtc makes the stream available at the same
        address for HA's stream integration to pull.
        """
        if self._streaming_active and self._keepalive_rtsp_url:
            return self._keepalive_rtsp_url
        return None

    async def _sdes_keepalive_loop(self) -> None:
        """Background task: keep SDES stream alive; push to go2rtc via RTSP."""
        _MIN_DELAY = 10.0
        _MAX_DELAY = 300.0
        _retry_delay = _MIN_DELAY

        while self._streaming_active:
            try:
                session = await self.async_open_webrtc_stream(
                    rtsp_push_url=self._keepalive_rtsp_url,
                    timeout=120.0,
                )
            except asyncio.CancelledError:
                return
            except Exception as exc:
                _LOGGER.warning(
                    "SDES keepalive: stream open failed for %s (retry in %.0fs): %s",
                    self.device_id, _retry_delay, exc,
                )
                try:
                    await asyncio.sleep(_retry_delay)
                except asyncio.CancelledError:
                    return
                _retry_delay = min(_retry_delay * 2, _MAX_DELAY)
                continue

            _retry_delay = _MIN_DELAY  # reset on success
            self._stream_session = session
            try:
                await session.wait_done()
            except asyncio.CancelledError:
                self._stream_session = None
                await session.stop()
                return
            finally:
                self._stream_session = None

            try:
                await session.stop()
            except Exception:
                pass

            if self._streaming_active:
                try:
                    await asyncio.sleep(_MIN_DELAY)
                except asyncio.CancelledError:
                    return

    async def _streaming_loop(self) -> None:
        """Background task: open WebRTC stream and update latest_jpeg; reconnect on drop."""
        import io as _io

        _WATCHDOG = 30.0
        _MIN_DELAY = 5.0
        _MAX_DELAY = 300.0
        _retry_delay = _MIN_DELAY

        def _on_frame(frame) -> None:
            # Accept keyframes always; accept P-frames only after first keyframe.
            if not getattr(frame, "key_frame", True) and self.latest_jpeg is not None:
                return
            try:
                pil_img = frame.to_image()
            except Exception:
                try:
                    from PIL import Image as _PILImage
                    pil_img = _PILImage.fromarray(frame.to_ndarray(format="rgb24"))
                except Exception:
                    return
            try:
                buf = _io.BytesIO()
                pil_img.save(buf, "JPEG")
                self.latest_jpeg = buf.getvalue()
                self._last_frame_time = asyncio.get_event_loop().time()
            except Exception as enc_exc:
                _LOGGER.debug("Streaming encode failed for %s: %s", self.device_id, enc_exc)

        while self._streaming_active:
            try:
                session = await self.async_open_webrtc_stream(on_frame=_on_frame)
            except asyncio.CancelledError:
                return
            except Exception as exc:
                _LOGGER.warning(
                    "Stream open failed for %s (retry in %.0fs): %s",
                    self.device_id, _retry_delay, exc,
                )
                try:
                    await asyncio.sleep(_retry_delay)
                except asyncio.CancelledError:
                    return
                _retry_delay = min(_retry_delay * 2, _MAX_DELAY)
                continue

            _retry_delay = _MIN_DELAY  # reset on success
            self._stream_session = session
            try:
                while self._streaming_active:
                    await asyncio.sleep(5.0)
                    elapsed = asyncio.get_event_loop().time() - self._last_frame_time
                    if self._last_frame_time > 0 and elapsed > _WATCHDOG:
                        _LOGGER.warning(
                            "No frames from %s in %.0fs — restarting stream",
                            self.device_id, elapsed,
                        )
                        break
            except asyncio.CancelledError:
                self._stream_session = None
                await session.stop()
                return
            finally:
                self._stream_session = None

            try:
                await session.stop()
            except Exception:
                pass

            if self._streaming_active:
                try:
                    await asyncio.sleep(_MIN_DELAY)
                except asyncio.CancelledError:
                    return

    # ── PTZ physical pan/tilt (A001064) ─────────────────────────────────── #
    # Uses IOCtrl cmd=4097 (IOTYPE_USER_IPCAM_PTZ_COMMAND) — NOT MQTT.
    # DTLS path: sent via WebRTC DataChannel. SDES path: sent via encrypted
    # SCTP cmd_chan. Requires an active stream session (_stream_session).

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

        Source: a.java d1() / f0.java A2() → avSendIOCtrl(4097, 8B payload)
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

        payload = bytes([code, min(255, max(0, speed)), preset, 0, 0, 0, 0, 0])
        session = self._stream_session
        if session is None:
            _LOGGER.warning("async_ptz_move: no active stream session")
            return False
        ok = session._avio_cmd(4097, payload)
        _LOGGER.debug(
            "PTZ %s (code=%d speed=%d preset=%d) → %s",
            direction, code, speed, preset, "sent" if ok else "no channel yet",
        )
        return ok

    async def async_ptz_stop(self) -> bool:
        """Send PTZ stop command (direction_code=0, speed=0)."""
        return await self.async_ptz_move("stop", speed=0)

    async def async_open_cloud_playback(
        self,
        start_ts: int,
        end_ts: int,
        on_frame: Callable[[VideoFrame], None],
    ) -> Optional[CloudPlaybackSession]:
        # Open a cloud-playback session and begin streaming VideoFrame objects.
        # start_ts / end_ts: Unix timestamps in milliseconds.
        # on_frame: called in the asyncio event loop for each decoded frame.
        # Returns a running CloudPlaybackSession, or None if handshake fails.
        #
        # Three-step handshake from LDSOpenSDK.playCloudRecord():
        #   1. MQTT getPlaybackServerInfoReq -> serverIP, serverPort, heartbeat
        #   2. HTTP POST playRecord          -> taskId
        #   3. TCP binary login + stream
        import aiohttp

        # Fetch MQTT credentials from the Leedarson smarthome /user/login endpoint.
        # The AiDot platform login does NOT return mqttUser/mqttPassword.
        smarthome_auth = await self._async_get_smarthome_auth()
        mqtt_user = (smarthome_auth or {}).get("mqttUser") or str(self.user_id)
        mqtt_pwd  = (smarthome_auth or {}).get("mqttPassword") or ""
        client_id = (self._user_info.get("mqttClientId") or f"app-{mqtt_user}")

        # Step 1 - MQTT
        mqtt_url = await self._async_get_mqtt_url()
        if not mqtt_url:
            _LOGGER.error(
                "async_open_cloud_playback: cannot determine MQTT URL for %s",
                self.device_id,
            )
            return None

        _LOGGER.debug("Cloud playback step 1: MQTT for %s", self.device_id)
        srv_info = await _mqtt_get_playback_server_info(
            mqtt_url, mqtt_user, mqtt_pwd, self.device_id, client_id,
        )
        if not srv_info:
            _LOGGER.error(
                "async_open_cloud_playback: MQTT response empty for %s",
                self.device_id,
            )
            return None

        server_ip   = srv_info.get("serverIP")
        server_port = srv_info.get("serverPort")
        heartbeat   = int(srv_info.get("heartbeat") or 15)

        if not server_ip or not server_port:
            _LOGGER.error(
                "async_open_cloud_playback: incomplete server info for %s: %s",
                self.device_id, srv_info,
            )
            return None

        # Step 2 - HTTP playRecord
        _LOGGER.debug("Cloud playback step 2: HTTP playRecord for %s", self.device_id)
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self._smarthome_base}"
                    "/api/ipc/playbackController/playRecord",
                    json={
                        "deviceId":      self.device_id,
                        "recordStaTime": start_ts,
                        "recordEndTime": end_ts,
                    },
                    headers=self._leedarson_headers(),
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    play_body = await resp.json(content_type=None)

            if play_body.get("code") != 200:
                _LOGGER.error(
                    "playRecord returned code=%s for %s: %s",
                    play_body.get("code"), self.device_id, play_body,
                )
                return None

            task_id = (play_body.get("data") or {}).get("taskId")
            if task_id is None:
                _LOGGER.error(
                    "playRecord: no taskId in response for %s: %s",
                    self.device_id, play_body,
                )
                return None

        except Exception as exc:
            _LOGGER.error(
                "async_open_cloud_playback: playRecord failed for %s: %s",
                self.device_id, exc,
            )
            return None

        # Step 3 - TCP
        _LOGGER.debug(
            "Cloud playback step 3: TCP to %s:%d task=%d heartbeat=%ds",
            server_ip, server_port, task_id, heartbeat,
        )
        pb_session = CloudPlaybackSession(
            server_ip=server_ip,
            server_port=int(server_port),
            heartbeat_interval=heartbeat,
            task_id=int(task_id),
            client_id=str(self.user_id),
            start_ts_s=start_ts // 1000,
            on_frame=on_frame,
        )
        if not await pb_session.start():
            return None

        _LOGGER.info(
            "Cloud playback session open for %s task=%d start=%d",
            self.device_id, task_id, start_ts // 1000,
        )
        return pb_session

    async def async_open_live_stream(
        self,
        on_frame: Callable[[VideoFrame], None],
        timeout: float = 60.0,
    ) -> Optional[TutkStreamSession]:
        # Open a TUTK IOTC P2P live-stream session.
        # on_frame: called from the receive thread for each decoded VideoFrame.
        # Returns a running TutkStreamSession, or None on failure.
        #
        # Protocol: TUTK IOTC P2P (confirmed from classes.jar.decompiled.zip).
        #   p2pId (TUTK UID) ← POST /v21/devices/batchGetDeviceUserInfo
        #   IOTC_Connect_ByUID_Parallel(uid) → nSID
        #   avClientStart2(nSID, "admin", "admin123") → avIndex
        #   avSendIOCtrl(avIndex, 511, ...) → start video stream
        #   avRecvFrameData2(avIndex, ...) → frame loop
        #
        # Requires libIOTCAPIs.so + libAVAPIs.so from the TUTK SDK.

        uid = await self.async_get_p2p_uid()
        if not uid:
            props = getattr(self, "_raw_device", {}).get("properties") or {}
            is_webrtc = (str(props.get("enableSdes", "0")) == "1"
                         or str(props.get("liveType", "0")) == "2")
            if is_webrtc:
                _LOGGER.error(
                    "async_open_live_stream: p2pId not available for %s — "
                    "this camera uses WebRTC streaming (enableSdes=%s, liveType=%s); "
                    "use async_open_webrtc_stream() for live video.",
                    self.device_id,
                    props.get("enableSdes", "0"),
                    props.get("liveType", "0"),
                )
            else:
                _LOGGER.error(
                    "async_open_live_stream: p2pId not available for %s. "
                    "Ensure batchGetDeviceUserInfo returns data (check auth/request "
                    "format) or that the smarthome getP2pId endpoint is reachable.",
                    self.device_id,
                )
            return None

        _LOGGER.debug(
            "async_open_live_stream: TUTK P2P uid=%s for %s", uid, self.device_id)
        session = TutkStreamSession(uid=uid, on_frame=on_frame)
        try:
            ok = await asyncio.wait_for(session.start(), timeout=timeout)
        except asyncio.TimeoutError:
            _LOGGER.error(
                "async_open_live_stream: TUTK connect timed out after %.0fs for %s",
                timeout, self.device_id,
            )
            return None
        if not ok:
            return None

        _LOGGER.info(
            "TUTK live stream session open for %s (uid=%s)",
            self.device_id, uid,
        )
        return session

    async def async_get_ice_config(self, device_id: str) -> Optional[dict]:
        """Fetch STUN/TURN ICE server credentials for a liveType=2 camera.

        Publishes ``IPC/getIceConfigReq`` via MQTT and waits up to 5 s for the
        ``IPC/getIceConfigResp`` reply.  The response contains per-device and
        per-user TURN credentials for the Arnoo TURN cluster.

        Returns a dict with keys ``app`` (list of user-side ICE server entries)
        and ``dev`` (list of device-side ICE server entries), each entry having
        the shape::

            {"id": str, "token": int, "ttl": int,
             "uris": [...], "dnsUris": [...]}

        Returns ``None`` if the MQTT session fails or no response arrives.
        A fallback ICE config (public STUN only, no TURN credentials) can be
        constructed by the caller if ``None`` is returned.
        """
        smarthome_auth = await self._async_get_smarthome_auth()
        mqtt_user = (smarthome_auth or {}).get("mqttUser") or str(self.user_id)
        mqtt_pwd  = (smarthome_auth or {}).get("mqttPassword") or ""
        user_id   = str(self.user_id)
        # Use the server-assigned authorised clientId — the broker rejects
        # random or made-up prefixes with rc=4.
        diag_cid  = (
            self._user_info.get("mqttClientId") or
            f"app-{mqtt_user}"
        )
        mqtt_url  = await self._async_get_mqtt_url()
        if not mqtt_url:
            _LOGGER.warning("async_get_ice_config: no MQTT URL available")
            return None

        seq     = f"ap{random.randint(1000000, 9999999)}"
        result: dict = {}

        payload = json.dumps({
            "method":  "getIceConfigReq",
            "service": "IPC",
            "srcAddr": f"0.{user_id}",
            "seq":     seq,
            "tst":     int(time.time() * 1000),
            "payload": {"deviceId": device_id, "userId": user_id},
        })

        def _capture(topic: str, raw: str) -> None:
            # Accept any message on the user callback topic that looks like
            # an ICE config response.
            if "iceconfig" in topic.lower() or "getice" in topic.lower():
                try:
                    msg = json.loads(raw)
                    inner = (msg.get("payload") or msg.get("data") or msg)
                    if isinstance(inner, dict) and ("app" in inner or "dev" in inner):
                        result["data"] = inner
                    elif isinstance(inner, dict) and "data" not in result:
                        result["data"] = inner
                except Exception:
                    result["data"] = raw

        await _mqtt_session(
            mqtt_url, mqtt_user, mqtt_pwd, diag_cid,
            subscribe_topics=[f"iot/v1/c/{user_id}/#"],
            publish_items=[(f"iot/v1/s/{user_id}/IPC/getIceConfigReq", payload)],
            duration=5.0,
            on_message=_capture,
        )

        if "data" not in result:
            _LOGGER.warning(
                "async_get_ice_config: no getIceConfigResp received for device %s; "
                "the device may not support MQTT ICE config (try after opening app live view)",
                device_id,
            )
        return result.get("data")

    async def async_get_ice_config_http(self) -> Optional[dict]:
        """Fetch ICE config via HTTP (primary path used by official app).

        Calls ``/v29/api/webrtc/iceConfig?forceRefresh=0`` using the same
        Appid/Token headers used by all other AiDot platform API calls.
        Returns a dict with ``app`` / ``dev`` keys on success, or ``None``.
        """
        import aiohttp

        token = (
            self._user_info.get("accessToken")
            or self._user_info.get("access_token")
        )

        if not self._region or not token:
            _LOGGER.warning(
                "async_get_ice_config_http: missing region or access token"
            )
            return None

        url = (
            f"https://prod-{self._region}-api.arnoo.com"
            f"/v29/api/webrtc/iceConfig?forceRefresh=0"
        )

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    headers=self._aidot_headers(),
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status != 200:
                        _LOGGER.warning(
                            "async_get_ice_config_http: HTTP %s from %s",
                            resp.status, url,
                        )
                        return None
                    return await resp.json(content_type=None)
        except Exception as exc:
            _LOGGER.warning("async_get_ice_config_http failed: %s", exc)
            return None

    @staticmethod
    def generate_webrtc_peer_id(
        live_type: int = 2, stream_id: int = 0, *, sdes: bool = False
    ) -> str:
        """Generate a peerId for a WebRTC connection.

        Format observed in iOS app telemetry:
        ``{32-hex-session}_{6-hex-random}_{liveType}_{streamId}_{version}``

        The trailing version digit encodes the signalling transport:
        ``1`` for SDES-SRTP cameras, ``2`` for DTLS-SRTP cameras.
        iOS app telemetry (2025-03-23) confirms: LK.IPC.A001513 (SDES,
        ``enableSdes: "1"``) uses ``_1`` and responds; LK.IPC.A000088 /
        LK.IPC.A001064 (DTLS, ``enableSdes: "0"``) use ``_2`` and respond.
        SDES cameras appear to silently discard webrtcReq with ``_2``.
        """
        import os
        session = os.urandom(16).hex()          # 32 hex chars
        rand6   = os.urandom(3).hex()           # 6 hex chars
        version = 1 if sdes else 2
        return f"{session}_{rand6}_{live_type}_{stream_id}_{version}"

    async def async_open_webrtc_stream(
        self,
        on_frame: Optional[Callable[["VideoFrame"], None]] = None,
        *,
        stream_id: int = 0,
        timeout: float = 30.0,
        output_path: Optional[str] = None,
        max_seconds: Optional[float] = None,
        status_callback: Optional[Callable[[str], None]] = None,
        force_sdes: Optional[bool] = None,
        _skip_ice_config: bool = False,
        _ice_config: "Optional[dict]" = None,
        _sdes_answer_timeout: Optional[float] = None,
        rtsp_push_url: Optional[str] = None,
        talk_pcm_provider: "Optional[Callable[[], Optional[bytes]]]" = None,
    ) -> "WebRTCSession":
        """Open a liveType=2 WebRTC stream via MQTT signaling.

        Performs the full WebRTC handshake over MQTT, then delivers decoded
        video frames to ``on_frame`` (and/or records to ``output_path``).

        Supports both DTLS-SRTP cameras (aiortc path, peerid suffix ``_2``)
        and SDES-SRTP cameras (ffmpeg path, peerid suffix ``_1``).  The
        transport is auto-detected from ``self.is_sdes_camera`` unless
        overridden by ``force_sdes``.

        Protocol (confirmed from live MQTT capture, 2025-03 / 2026-03):
          1. Subscribe ``iot/v1/c/{userId}/#`` on the authorised MQTT clientId
          2. Publish to ``iot/v1/s/{userId}/IPC/getIceConfigReq`` (server-side wake)
             → wait 2 s for broker session init
          3. Publish to ``iot/v1/s/{userId}/IPC/livePlayReq`` (camera-side arm)
             → wait 0.5 s for camera WebRTC subsystem to arm
          4. Create peer connection (aiortc or SDES SDP), add recvonly tracks
          5. Generate SDP offer → publish to ``iot/v1/s/{userId}/IPC/webrtcReq``
          6. Receive ``IPC/webrtcResp`` on ``iot/v1/c/{userId}/#`` → set remote description
          7. Exchange ICE candidates on ``iot/v1/s/{userId}/IPC/iceCandidateReq``
          8. Receive media tracks → call ``on_frame`` for each VideoFrame

        Topic routing: ALL IPC publish messages (getIceConfigReq, livePlayReq,
        webrtcReq, iceCandidateReq) go to ``iot/v1/s/{userId}/IPC/...``.
        The broker routes to the specific camera using the ``devId`` field in
        the JSON payload, NOT based on the MQTT topic path.  Confirmed from
        iOS app telemetry (2025-03-23): explicit publish logs show userId in
        the topic for iceCandidateReq and livePlayReq.

        Parameters
        ----------
        on_frame : callable or None
            Called with each ``av.VideoFrame`` from the camera (DTLS path only).
        stream_id : int
            Stream index: 0 = main stream, 1 = sub-stream.
        timeout : float
            Seconds to wait for ICE connection before raising RuntimeError.
        output_path : str or None
            Record the stream to this file (e.g. ``/tmp/live.ts``) via
            aiortc MediaRecorder (DTLS) or ffmpeg (SDES).  Supports any
            container ffmpeg can write; ``.ts`` is streamable via vlc/ffplay.
        max_seconds : float or None
            Stop recording after this many seconds (SDES path: passed as
            ``-t`` to ffmpeg so it exits cleanly).  For DTLS, the caller is
            responsible for calling ``session.stop()`` after the desired
            duration; max_seconds is ignored on the DTLS path.
        force_sdes : bool or None
            Override transport auto-detection.  ``True`` → SDES path,
            ``False`` → DTLS path, ``None`` → auto (uses ``is_sdes_camera``).

        Returns
        -------
        WebRTCSession or SdesSession
            Call ``await session.stop()`` to close the stream.

        Raises
        ------
        ImportError
            If ``aiortc`` is not installed (DTLS path only).
            (``pip install python-aidot[webrtc]``).
        RuntimeError
            If the MQTT connection fails or ICE does not complete within
            ``timeout`` seconds.
        """
        import queue as _q_mod

        use_sdes = force_sdes if force_sdes is not None else self.is_sdes_camera

        if not use_sdes:
            try:
                from aiortc import RTCPeerConnection, RTCSessionDescription
                from aiortc.sdp import candidate_from_sdp
            except ImportError:
                raise ImportError(
                    "aiortc is required for WebRTC streaming. "
                    "Install with: pip install python-aidot[webrtc]"
                )

            # Allow DTLS 1.0 client hellos.  L2_162 (A001513) and likely other
            # KVS-derived camera firmware sends DTLS 1.0 ClientHello (0xfeff).
            # OpenSSL 3.x disables DTLS 1.0 by default, so aiortc's SSL context
            # aborts the handshake immediately ("Unexpected EOF") without
            # responding.  Monkey-patch RTCCertificate._create_ssl_context to
            # set the min protocol version to DTLS 1.0.  Safe: A000088 cameras
            # that negotiate DTLS 1.2 still get DTLS 1.2; this only widens
            # the floor.
            try:
                from aiortc.rtcdtlstransport import RTCCertificate as _AidotRTCCert
                if not getattr(_AidotRTCCert, "_aidot_dtls10_patched", False):
                    _orig_create_ctx = _AidotRTCCert._create_ssl_context
                    _DTLS1_VERSION = 0xFEFF  # not exposed in pyOpenSSL; raw OpenSSL constant
                    def _aidot_create_ssl_context(self, srtp_profiles):
                        _ctx = _orig_create_ctx(self, srtp_profiles)
                        try:
                            _ctx.set_min_proto_version(_DTLS1_VERSION)
                        except Exception as _e:
                            _LOGGER.warning(
                                "DTLS 1.0 enable failed: %s", _e
                            )
                        return _ctx
                    _AidotRTCCert._create_ssl_context = _aidot_create_ssl_context
                    _AidotRTCCert._aidot_dtls10_patched = True
                    _LOGGER.debug("aiortc DTLS min version lowered to 1.0")
            except Exception as _patch_exc:
                _LOGGER.warning(
                    "DTLS 1.0 patch could not be applied: %s", _patch_exc
                )

        # ------------------------------------------------------------------ #
        # Credentials + MQTT setup
        # ------------------------------------------------------------------ #
        smarthome_auth = await self._async_get_smarthome_auth()
        mqtt_user = (smarthome_auth or {}).get("mqttUser") or str(self.user_id)
        mqtt_pwd  = (smarthome_auth or {}).get("mqttPassword") or ""
        user_id   = str(self.user_id)
        mqtt_cid  = (
            self._user_info.get("mqttClientId") or
            (self._user_info.get("_userConfigRaw") or {}).get("mqtt", {}).get("clientId") or
            f"app-{mqtt_user}"
        )
        # terminalIndex is the session prefix of mqtt_cid (e.g. "1i1h3m" from "1i1h3m-{userId}").
        # The camera validates srcAddr against active MQTT sessions; "0.{userId}" matches nothing.
        mqtt_url = await self._async_get_mqtt_url()
        if not mqtt_url:
            raise RuntimeError("async_open_webrtc_stream: no MQTT URL available")

        # Fetch camera's registered numeric userId.  Used for:
        # 1. Additional MQTT subscriptions (cameras may route webrtcResp by numeric ID)
        # 2. Injecting "userId" into the IPC message envelope so camera firmware can
        #    validate the caller (LK.IPC.A001064 silently ignores offers without it).
        # Run batchGetDeviceUserInfo and HTTP ICE config fetch concurrently —
        # both are independent HTTP calls; sequencing them wastes up to ~10 s.
        _fetch_http_ice = not _skip_ice_config and _ice_config is None
        if _fetch_http_ice:
            _cam_user_info, _http_ice_config = await asyncio.gather(
                self.async_get_device_user_info(all_device_ids=self._all_device_ids or None),
                self.async_get_ice_config_http(),
            )
        else:
            _cam_user_info = await self.async_get_device_user_info(
                all_device_ids=self._all_device_ids or None
            )
            _http_ice_config = None
        _numeric_uid_raw = (_cam_user_info or {}).get("userId")
        if _numeric_uid_raw is not None:
            try:
                _numeric_uid_raw = int(_numeric_uid_raw)
            except (TypeError, ValueError):
                _LOGGER.warning(
                    "async_open_webrtc_stream: unexpected userId type %r — skipping injection",
                    _numeric_uid_raw,
                )
                _numeric_uid_raw = None
        numeric_user_id = str(_numeric_uid_raw) if _numeric_uid_raw is not None else None
        if numeric_user_id is None:
            _LOGGER.warning(
                "async_open_webrtc_stream: no numeric userId from batchGetDeviceUserInfo"
                " for %s — user_info_keys=%s.  Camera firmware may reject WebRTC offers"
                " without a matching userId, and getIceConfigResp may not be routed to"
                " us (TURN credentials unavailable, ICE will likely fail over segmented"
                " networks).",
                self.device_id,
                sorted((_cam_user_info or {}).keys()),
            )

        # Also extract the camera's local IP address from batchGetDeviceUserInfo if present.
        # Used to pre-seed cam_ip_q in the role-reversal ICE wait loop as a fallback when
        # setDevAttrNotif doesn't arrive or uses an unexpected IP field name.
        # Final fallback: self._ip_address populated by LAN broadcast discovery
        # (update_ip_address / Discover.send_broadcast) — covers ICE-lite cameras such as
        # LK.IPC.A001064 whose batchGetDeviceUserInfo response contains no IP field.
        _cam_local_ip: str | None = (
            (_cam_user_info or {}).get("localIp")
            or (_cam_user_info or {}).get("ipAddress")
            or (_cam_user_info or {}).get("ip")
            or (_cam_user_info or {}).get("localIPAddress")
            or self._ip_address
            or ((self._raw_device or {}).get("properties") or {}).get("ipAddress")
            or ((self._raw_device or {}).get("properties") or {}).get("ip")
        ) or None
        if not _cam_local_ip:
            _LOGGER.warning(
                "async_open_webrtc_stream: camera IP unknown for %s"
                " — no IP field in batchGetDeviceUserInfo, device properties,"
                " or LAN-discovered IP."
                " Synthetic ICE candidates cannot be injected; ICE will fail for"
                " ICE-lite cameras (e.g. LK.IPC.A001064).  user_info_keys=%s"
                "  raw_device_keys=%s",
                self.device_id,
                sorted((_cam_user_info or {}).keys()),
                sorted((self._raw_device or {}).keys()),
            )

        # Extract the camera's userUuid from batchGetDeviceUserInfo.
        # Some camera firmware (e.g. LK.IPC.A001064) publishes its real
        # webrtcResp/webrtcReq to MQTT topics keyed by the camera's own
        # userUuid rather than the app user's UUID.  If we don't subscribe
        # to those topics, the camera's answer (with its actual ICE candidates)
        # is silently dropped and we fall into the broken echo-only path.
        _cam_user_uuid: str | None = ((_cam_user_info or {}).get("userUuid") or None)
        _LOGGER.debug(
            "batchGetDeviceUserInfo: device=%s  userId=%s  userUuid=%s",
            self.device_id, _numeric_uid_raw, _cam_user_uuid,
        )

        # Respect isDTLS='0': those cameras cannot do DTLS, so falling back
        # after an SDES timeout would only hang the stream (~30 s with zero
        # frames).  For cameras where isDTLS is absent or non-zero, allow DTLS
        # fallback in case enableSdes='1' was incorrectly provisioned.
        # LK.IPC.A001064 (enableSdes='1') echoes our MQTT messages but does
        # not send STUN or SRTP — the echo-reversal DTLS fallback path at the
        # end of _open_sdes_stream handles this without launching ffmpeg.
        _cam_props = (self._raw_device or {}).get("properties") or {}
        _dtls_fallback_ok = str(_cam_props.get("isDTLS", "1")) != "0"

        device_id = self.device_id
        peer_id   = self.generate_webrtc_peer_id(
            live_type=2, stream_id=stream_id, sdes=use_sdes
        )
        loop      = asyncio.get_running_loop()

        # Broad wildcard subscriptions — the camera's full namespace is not
        # documented, and narrowing to specific service paths (IPC/IPCAM/device)
        # missed camera wake signals on other paths.  The # wildcard ensures we
        # receive all messages regardless of what service prefix the camera uses.
        sub_topics = [
            f"iot/v1/c/{user_id}/#",
            f"iot/v1/cb/{user_id}/#",
            f"iot/v1/cb/{device_id}/#",
            f"iot/v1/c/{device_id}/#",
            f"lds/v1/c/{user_id}/#",
            f"lds/v1/cb/{device_id}/#",
        ]
        # Some firmware routes responses on topics keyed by the camera's numeric
        # userId rather than the account UUID.
        if numeric_user_id and numeric_user_id != user_id:
            sub_topics += [
                f"iot/v1/c/{numeric_user_id}/#",
                f"iot/v1/cb/{numeric_user_id}/#",
                f"lds/v1/c/{numeric_user_id}/#",
            ]
        # Some firmware routes webrtcResp on topics keyed by the camera's own
        # userUuid from batchGetDeviceUserInfo instead of the app user UUID.
        _known_ids = {user_id, device_id, numeric_user_id or ""}
        if _cam_user_uuid and _cam_user_uuid not in _known_ids:
            sub_topics += [
                f"iot/v1/c/{_cam_user_uuid}/#",
                f"iot/v1/cb/{_cam_user_uuid}/#",
                f"lds/v1/c/{_cam_user_uuid}/#",
            ]
            _LOGGER.debug(
                "webrtc: adding camera userUuid subscriptions for %s (uuid=%s)",
                self.device_id, _cam_user_uuid,
            )
        # iOS app telemetry (2025-03-23) confirms ALL IPC publish topics use
        # the userId path.  The broker routes to the specific camera using the
        # ``devId`` field inside the JSON payload, NOT the MQTT topic path.
        webrtc_req_topic = f"iot/v1/s/{user_id}/IPC/webrtcReq"
        ice_cand_topic   = f"iot/v1/s/{user_id}/IPC/iceCandidateReq"
        live_play_topic  = f"iot/v1/s/{user_id}/IPC/livePlayReq"

        # ------------------------------------------------------------------ #
        # MQTT ↔ asyncio bridge
        # ------------------------------------------------------------------ #
        outgoing_q:       _q_mod.Queue    = _q_mod.Queue()
        answer_fut:        asyncio.Future = loop.create_future()
        second_answer_fut: asyncio.Future = loop.create_future()   # captures discarded broker-echo camera's real webrtcResp
        camera_offer_fut:     asyncio.Future = loop.create_future()  # set when camera sends webrtcReq (role-reversal)
        webrtc_req_echo_fut:  asyncio.Future = loop.create_future()  # set when broker echoes our own webrtcReq back (is_echo=True)
        ice_config_fut:    asyncio.Future = loop.create_future()  # TURN credentials from getIceConfigResp
        ice_q:            asyncio.Queue   = asyncio.Queue()
        cam_ip_q:         asyncio.Queue   = asyncio.Queue()  # camera IP from setDevAttrNotif
        camera_ready_ev:  asyncio.Event   = asyncio.Event()  # set when camera is on MQTT
        liveplay_echo_ev: asyncio.Event   = asyncio.Event()  # set when livePlayReq echo arrives
        liveplay_resp_fut: asyncio.Future = loop.create_future()  # set on livePlayResp
        camera_reconnect_ev: asyncio.Event = asyncio.Event() # set when camera sends device/connect
        # Mutable flag: set True when setDevAttrNotif delivers sptPreconn:1.
        # Confirmed 2026-05-02: both A000088 Deck and A001064 PTZ report
        # sptPreconn:1.  AVIO LIVING (SESSION_MODE_REQ=5376) must be sent
        # via the data channel to trigger streaming in PreCon cameras.
        _spt_preconn: list = [False]

        # Gate: block asyncio until MQTT is connected + subscribed
        import threading as _threading
        _mqtt_ready_ev     = _threading.Event()
        _mqtt_conn_status: dict = {}

        def _status(msg: str) -> None:
            """Fire status_callback and log.  Callback is the primary output
            channel; logging is DEBUG so log files capture detail without INFO
            flood when the callback is not routing to a logger."""
            if status_callback:
                status_callback(msg)
                _LOGGER.debug("webrtc: %s", msg)
            else:
                _LOGGER.info("webrtc: %s", msg)

        if _numeric_uid_raw is not None and numeric_user_id != user_id:
            _LOGGER.debug("webrtc: numeric userId for payload injection: %s", _numeric_uid_raw)

        # ------------------------------------------------------------------ #
        # HTTP-first ICE config pre-fetch (matches official app behaviour)
        # ------------------------------------------------------------------ #
        # HTTP ICE config was fetched concurrently with batchGetDeviceUserInfo
        # above (parallel gather).  Just log the outcome here.
        if _fetch_http_ice:
            if _http_ice_config:
                _status("ICE config fetched via HTTP (primary path, parallel fetch)")
            else:
                _status("HTTP ICE config unavailable — will use MQTT path")

        def _on_mqtt_ready(st: dict) -> None:
            _mqtt_conn_status.update(st)
            _mqtt_ready_ev.set()

        def _extract_cam_ip(method_name: str, inner: dict, msg: dict) -> None:
            _cam_ip = (inner.get("ipAddress") or inner.get("ip")
                       or inner.get("localIp") or inner.get("localIPAddress")
                       or inner.get("wlanIp") or inner.get("wlanIPAddress")
                       or inner.get("deviceIp") or inner.get("localAddr")
                       or msg.get("ipAddress") or msg.get("ip")
                       or msg.get("localIp") or msg.get("localIPAddress"))
            if _cam_ip:
                loop.call_soon_threadsafe(cam_ip_q.put_nowait, _cam_ip)
                loop.call_soon_threadsafe(
                    lambda ip=_cam_ip: _status(f"{method_name}: camera IP = {ip}")
                )
            else:
                _LOGGER.warning(
                    "%s: no IP address field found; inner_keys=%s  msg_keys=%s",
                    method_name, list(inner.keys()), [k for k in msg if k != "payload"],
                )

        def _on_mqtt_message(topic: str, payload_str: str) -> None:
            _LOGGER.debug("webrtc rx  topic=%s  %.400s", topic, payload_str)
            try:
                msg = json.loads(payload_str)
            except Exception:
                loop.call_soon_threadsafe(
                    lambda t=topic, p=payload_str: _status(
                        f"camera raw (non-JSON)  topic={t}  data={p[:200]!r}"
                    )
                )
                return
            method = msg.get("method") or ""
            inner  = msg.get("payload") or {}
            # Fire camera_ready_ev the moment the camera appears on MQTT — either via its
            # explicit wake-ACK (lowPowerActiveStateResp), any message on the device channel,
            # OR any message on the user channel whose payload identifies our device.
            # LK.IPC.A001064 (and similar) responds on the user channel (iot/v1/c/{userId}/…)
            # rather than the device channel, so the old topic-prefix check never fired —
            # causing the 17-second getIceConfigReq timeout overhead every session.
            if (method == "lowPowerActiveStateResp"
                    or topic.startswith(f"iot/v1/c/{device_id}/")
                    or topic.startswith(f"lds/v1/cb/{device_id}/")
                    or inner.get("devId") == device_id
                    or msg.get("devId") == device_id):
                loop.call_soon_threadsafe(camera_ready_ev.set)
            # livePlayResp: explicit camera ack/nack for start-play command.
            if method == "livePlayResp" and inner.get("devId") == device_id:
                if not liveplay_resp_fut.done():
                    loop.call_soon_threadsafe(liveplay_resp_fut.set_result, inner)
            # livePlayReq echo: broker/camera confirmed delivery of our livePlayReq.
            # Signal _open_sdes_stream to proceed with webrtcReq.
            if method == "livePlayReq" and inner.get("devId") == device_id:
                loop.call_soon_threadsafe(liveplay_echo_ev.set)
            if method == "webrtcResp":
                resp_pid = inner.get("peerid")
                answer   = inner.get("offer") or inner.get("answer") or {}
                if not answer.get("sdp"):
                    return  # empty / incomplete response — ignore
                if resp_pid == peer_id:
                    pass  # exact peerid match — accept (fast path)
                elif (inner.get("devId") == device_id
                        and inner.get("dstAddr") == user_id):
                    # Camera replied with its own stable session peerid rather than
                    # echoing back our peerid.  Accept only if BOTH devId and dstAddr
                    # match — dstAddr alone matches every message to our account.
                    loop.call_soon_threadsafe(
                        lambda rp=resp_pid: _status(
                            f"webrtcResp accepted (camera peerid) —"
                            f" got {rp!r}"
                            f" expected ...{peer_id[-12:]}"
                        )
                    )
                else:
                    loop.call_soon_threadsafe(
                        lambda rp=resp_pid: _status(
                            f"webrtcResp IGNORED — peerid/devId/dstAddr mismatch:"
                            f" got {rp!r}"
                        )
                    )
                    return
                if not answer_fut.done():
                    loop.call_soon_threadsafe(answer_fut.set_result, answer)
                else:
                    # Second webrtcResp — likely the camera's real answer (the first
                    # was the broker echo of our own webrtcResp).  Capture and log it.
                    _LOGGER.debug(
                        "SDES: second webrtcResp received (answer_fut already set)"
                        " — camera real answer SDP (len=%d)",
                        len(answer.get("sdp", "")),
                    )
                    if not second_answer_fut.done():
                        loop.call_soon_threadsafe(second_answer_fut.set_result, answer)
            elif method == "iceCandidateReq":
                resp_pid = inner.get("peerid")
                if (resp_pid != peer_id
                        and inner.get("devId") != device_id
                        and inner.get("dstAddr") != user_id):
                    return   # high-volume; suppress status noise for foreign ICE
                cand = inner.get("candidate") or {}
                if cand.get("candidate"):
                    loop.call_soon_threadsafe(ice_q.put_nowait, cand)
            elif method == "webrtcReq":
                # Camera acting as WebRTC offerer (role reversal observed on
                # LK.IPC.A001064).  Set camera_offer_fut so the DTLS path can
                # respond with a proper webrtcResp answer.
                resp_pid   = inner.get("peerid")
                cam_offer  = inner.get("offer") or {}
                src_addr   = inner.get("srcAddr") or msg.get("srcAddr") or ""
                own_prefix = f"0.{user_id}"
                is_echo    = src_addr.startswith(own_prefix) or src_addr == own_prefix
                if is_echo:
                    # Broker echoes our own webrtcReq back with our srcAddr.
                    # Signal the SDES path so it can send webrtcResp to the camera.
                    if not webrtc_req_echo_fut.done():
                        loop.call_soon_threadsafe(
                            webrtc_req_echo_fut.set_result, cam_offer
                        )
                elif (cam_offer.get("sdp")
                        and (resp_pid == peer_id
                             or inner.get("devId") == device_id
                             or inner.get("dstAddr") == user_id)):
                    if not camera_offer_fut.done():
                        loop.call_soon_threadsafe(
                            camera_offer_fut.set_result, cam_offer
                        )
                # Extract IceServerList from the camera's webrtcReq and seed
                # ice_config_fut so RTCPeerConnection can use TURN servers.
                # Only process when not an echo — we sent those servers ourselves.
                if not is_echo:
                    _req_ice_list = inner.get("IceServerList") or []
                    if _req_ice_list and not ice_config_fut.done():
                        loop.call_soon_threadsafe(
                            ice_config_fut.set_result,
                            {"IceServerList": _req_ice_list},
                        )
                loop.call_soon_threadsafe(
                    lambda m=method, t=topic: _status(
                        f"camera replied  method={m!r}  endpoint={t.rsplit('/', 1)[-1]}"
                    )
                )
            elif method == "setDevAttrNotif":
                # Camera broadcasts its real LAN IP shortly after ICE starts.
                # Capture it so the role-reversal path can inject synthetic
                # remote candidates (camera-IP + echoed ports) to give aiortc
                # a concrete target for STUN probes when the camera is ICE-lite
                # and won't send its own binding requests.
                _extract_cam_ip("setDevAttrNotif", inner, msg)
                # Also capture sptPreconn (PreCon / PreConnect support flag).
                # Confirmed 2026-05-02: both A001064 PTZ and A000088 Deck have
                # sptPreconn:1.  Per BaseKVSCameraView.k():805-815, the official
                # client sends AVIO LIVING (SESSION_MODE_REQ=5376) via the data
                # channel only when isSupportPreCon() is true.  Set the flag
                # here so the DC on("open") callback can send LIVING.
                _spt = inner.get("attr", {}).get("sptPreconn", 0)
                if _spt:
                    loop.call_soon_threadsafe(
                        lambda: _spt_preconn.__setitem__(0, True)
                    )
            elif method == "getDevAttrResp":
                # Defensive: some camera firmware pushes getDevAttrResp rather
                # than setDevAttrNotif.  Extract the LAN IP if present.
                _extract_cam_ip("getDevAttrResp", inner, msg)
            elif method == "getIceConfigResp":
                # Capture TURN server credentials so aiortc can use them.
                # getIceConfigResp arrives before RTCPeerConnection is created,
                # so we store it in ice_config_fut and consumed later when
                # building the RTCPeerConnection configuration.
                #
                # Accept any non-empty response regardless of key names —
                # the actual structure is normalised in the extraction code
                # below.  Previously this block silently dropped responses
                # whose payload didn't have top-level "app"/"dev" keys,
                # which prevented TURN credentials from reaching aiortc.
                _ice_inner = inner if isinstance(inner, dict) else {}
                if not _ice_inner and isinstance(msg.get("data"), dict):
                    _ice_inner = msg["data"]
                # Accept anything that looks like ICE config data.
                _has_known_keys = ("app" in _ice_inner or "dev" in _ice_inner
                                   or "iceServers" in _ice_inner
                                   or "turnServers" in _ice_inner)
                if not _has_known_keys and _ice_inner:
                    # Log the actual structure so we can learn the format.
                    _LOGGER.warning(
                        "getIceConfigResp: unexpected structure (no app/dev/iceServers)"
                        " — storing raw for extraction attempt.  keys=%s",
                        list(_ice_inner.keys())[:20],
                    )
                if _ice_inner and not ice_config_fut.done():
                    loop.call_soon_threadsafe(ice_config_fut.set_result, _ice_inner)
                    # getIceConfigResp arriving means the broker session is
                    # active and TURN credentials are available.  Wake the
                    # camera_ready_ev so we don't burn the full 12-second
                    # timeout when the server responds promptly.
                    loop.call_soon_threadsafe(camera_ready_ev.set)
                elif not _ice_inner and not ice_config_fut.done():
                    # No usable payload — store the whole message as fallback.
                    _LOGGER.warning(
                        "getIceConfigResp: empty inner payload; storing full msg."
                        " msg_keys=%s", list(msg.keys())
                    )
                    if msg and not ice_config_fut.done():
                        loop.call_soon_threadsafe(ice_config_fut.set_result, msg)
            elif method == "connect":
                # Camera re-connected (quickConn cycle after WebRTC signaling).
                # Signal the ICE wait loop so it can re-send webrtcResp + ICE
                # candidates — the camera may have reset its WebRTC session state
                # and needs fresh signaling to continue ICE connectivity checks.
                if inner.get("devId") == device_id:
                    loop.call_soon_threadsafe(camera_reconnect_ev.set)
                loop.call_soon_threadsafe(
                    lambda m=method, t=topic: _status(
                        f"camera replied  method={m!r}  endpoint={t.rsplit('/', 1)[-1]}"
                    )
                )
            else:
                loop.call_soon_threadsafe(
                    lambda m=method, t=topic: _status(
                        f"camera replied  method={m!r}  endpoint={t.rsplit('/', 1)[-1]}"
                    )
                )

        # Run MQTT in a thread executor (very long duration; stopped via
        # outgoing_q sentinel when the caller calls WebRTCSession.stop()).
        mqtt_fut = loop.run_in_executor(
            None,
            lambda: _mqtt_session_sync(
                mqtt_url, mqtt_user, mqtt_pwd, mqtt_cid,
                sub_topics, [], 3600.0, _on_mqtt_message,
                "/mqtt", _on_mqtt_ready, outgoing_q,
            ),
        )

        # Wait for MQTT to be connected and subscribed before proceeding.
        # threading.Event.wait(timeout) returns True if set, False on timeout.
        mqtt_ok = await loop.run_in_executor(
            None, lambda: _mqtt_ready_ev.wait(timeout=15.0)
        )
        if not mqtt_ok or not _mqtt_conn_status.get("connected"):
            outgoing_q.put_nowait(None)   # stop MQTT thread
            _err = (
                _mqtt_conn_status.get("error")
                or _mqtt_conn_status.get("rc_str")
                or f"rc={_mqtt_conn_status.get('rc')}"
            )
            raise RuntimeError(
                f"async_open_webrtc_stream: MQTT connection failed: {_err}"
            )
        _status(f"MQTT connected (clientId={mqtt_cid})")

        # ------------------------------------------------------------------ #
        # Announce user presence (l.java P()) so the camera pushes its current
        # state via setDevAttrNotif.  The setDevAttrNotif handler enqueues
        # the camera's LAN IP into cam_ip_q so the ICE wait loop can
        # synthesise a host candidate for direct LAN probing.
        # Replaces the invented getDevAttrReq which does not exist in the APK.
        # ------------------------------------------------------------------ #
        outgoing_q.put_nowait((
            f"iot/v1/cb/{user_id}/user/connect",
            json.dumps({
                "service": "user",
                "method":  "connect",
                "srcAddr": f"0.{user_id}",
                "payload": {"timestamp": _mqtt_timestamp()},
            }),
        ))

        # ------------------------------------------------------------------ #
        # Send getIceConfigReq first — this warms up the broker-side WebRTC
        # session and registers the camera routing so the subsequent webrtcReq
        # is forwarded to the device.  iOS app telemetry confirms getIceConfigReq
        # is always sent before webrtcReq.  Without this step the broker echoes
        # webrtcReq back to us but never routes it to the camera.
        #
        # Skipped on SDES→DTLS fallback retries (_skip_ice_config=True): the
        # camera is already awake from the SDES attempt so the wake phase is
        # unnecessary; skipping saves up to 17 s of timeout overhead.
        # ------------------------------------------------------------------ #
        # Build getIceConfigReq payload unconditionally — used in both the
        # normal wake-wait path and the DTLS-fallback no-wait path below.
        _ice_req_payload = json.dumps({
            "method":  "getIceConfigReq",
            "service": "IPC",
            "devId":   device_id,
            "srcAddr": f"0.{user_id}",
            "seq":     f"ap{random.randint(1000000, 9999999)}",
            "tst":     int(time.time() * 1000),
            **( {"userId": _numeric_uid_raw} if _numeric_uid_raw is not None else {} ),
            "payload": {"devId": device_id, "userId": user_id},
        })

        if _skip_ice_config:
            camera_ready_ev.set()  # camera already awake; skip wake handshake
            _status("Skipping getIceConfigReq wake wait (DTLS fallback — camera already awake)")
            # Still send getIceConfigReq so TURN credentials can be gathered
            # asynchronously.  The server may respond now that the camera already
            # has an active MQTT session from the preceding SDES attempt.
            outgoing_q.put_nowait(
                (f"iot/v1/s/{user_id}/IPC/getIceConfigReq", _ice_req_payload)
            )
            # Seed ice_config_fut from pre-loaded config (caller-supplied or
            # HTTP pre-fetch) so RTCPeerConnection picks up TURN servers.
            _effective_ice = _ice_config or _http_ice_config
            if _effective_ice is not None and not ice_config_fut.done():
                loop.call_soon_threadsafe(ice_config_fut.set_result, _effective_ice)
        else:
            # Seed ice_config_fut from HTTP pre-fetch if available, so TURN
            # credentials are ready before the camera even wakes.
            _effective_ice = _ice_config or _http_ice_config
            if _effective_ice is not None and not ice_config_fut.done():
                loop.call_soon_threadsafe(ice_config_fut.set_result, _effective_ice)

            # Wake the camera via two parallel channels (n.java DeviceWakeUpRepos k()+l()):
            #   1. MQTT lowPowerActiveStateReq — reaches cameras already on MQTT
            #   2. HTTP lowPowerActiveState    — cloud push for deep-sleep cameras
            # Both are fire-and-forget; getIceConfigReq below confirms wakeup.
            # Payload from n.java l() — publishes extendsObj directly (no outer wrapper).
            _wake_mqtt_payload = json.dumps({
                "method":  "lowPowerActiveStateReq",
                "devId":   device_id,
                "userId":  user_id,
                "service": "IPC",
                "payload": {
                    "devId":  device_id,
                    "status": "wakeup",
                },
            })
            outgoing_q.put_nowait((
                f"iot/v1/s/{user_id}/IPCAM/lowPowerActiveStateReq",
                _wake_mqtt_payload,
            ))

            async def _http_wake() -> None:
                try:
                    import aiohttp as _aiohttp_w
                    async with _aiohttp_w.ClientSession() as _ws:
                        async with _ws.post(
                            f"{self._aidot_v32_base}/devices/{device_id}"
                            "/lowPowerActiveState",
                            json={"deviceId": device_id, "status": "wakeup"},
                            headers=self._aidot_headers(),
                            timeout=_aiohttp_w.ClientTimeout(total=8),
                        ) as _wr:
                            _LOGGER.debug(
                                "lowPowerActiveState HTTP %d for %s",
                                _wr.status, device_id,
                            )
                except Exception as _we:
                    _LOGGER.debug(
                        "lowPowerActiveState HTTP failed for %s: %s", device_id, _we
                    )

            async def _http_keepalive() -> None:
                # setKeepAliveTime keeps the camera in active state for 25 s
                # after wake (n.java:224 — keepAliveTime=25, not 20).
                # Without this call the camera's built-in timer may return it
                # to sleep before SCTP + LIVING completes (~10–15 s).
                try:
                    import aiohttp as _aiohttp_k
                    async with _aiohttp_k.ClientSession() as _ks:
                        async with _ks.post(
                            f"{self._aidot_v32_base}/devices/{device_id}"
                            "/setKeepAliveTime",
                            json={"keepAliveTime": 25},
                            headers=self._aidot_headers(),
                            timeout=_aiohttp_k.ClientTimeout(total=8),
                        ) as _kr:
                            _LOGGER.debug(
                                "setKeepAliveTime HTTP %d for %s",
                                _kr.status, device_id,
                            )
                except Exception as _ke:
                    _LOGGER.debug(
                        "setKeepAliveTime HTTP failed for %s: %s", device_id, _ke
                    )

            asyncio.ensure_future(_http_wake())
            asyncio.ensure_future(_http_keepalive())

            outgoing_q.put_nowait(
                (f"iot/v1/s/{user_id}/IPC/getIceConfigReq", _ice_req_payload)
            )
            _status("getIceConfigReq sent — waiting for camera to wake (up to 12s)")
            try:
                await asyncio.wait_for(camera_ready_ev.wait(), timeout=12.0)
                _status("Camera awake — got MQTT signal")
            except asyncio.TimeoutError:
                # First 12s window elapsed without a camera MQTT signal.
                # Resend both the wake signal and ICE config req, then give
                # a shorter 5s window before proceeding regardless — cameras
                # either wake quickly or take >24s, so the extra wait rarely
                # catches the slow case but always costs time for the fast one.
                _status("Camera wake timeout — retrying ...")
                outgoing_q.put_nowait((
                    f"iot/v1/s/{user_id}/IPCAM/lowPowerActiveStateReq",
                    _wake_mqtt_payload,
                ))
                outgoing_q.put_nowait(
                    (f"iot/v1/s/{user_id}/IPC/getIceConfigReq", _ice_req_payload)
                )
                asyncio.ensure_future(_http_wake())
                try:
                    await asyncio.wait_for(camera_ready_ev.wait(), timeout=5.0)
                    _status("Camera awake — got MQTT signal (after retry)")
                except asyncio.TimeoutError:
                    _status("Camera not responding — proceeding anyway")
                    if use_sdes:
                        _status(
                            "Note: getIceConfigReq timed out for claimed-SDES camera"
                            " — will fall back to DTLS if SDES handshake fails"
                        )

        # ------------------------------------------------------------------ #
        # powerType / p2pCache — source: IpcServiceImpl.java:B()
        # B() returns 2 for battery/low-power models (A001513, A001108, A001360)
        # and 1 for everything else.  p2pCache is the camera's prop value
        # (all tested cameras report p2pCache=2).  Both fields appear in
        # livePlayReq, webrtcReq, and the SDES webrtcReq.
        _live_model_id = getattr(getattr(self, "info", None), "model_id", None) or ""
        _live_power_type = "2" if any(
            m in _live_model_id for m in ("A001513", "A001108", "A001360")
        ) else "1"
        _live_p2p_cache = "2"  # All cameras report p2pCache:2 in device attrs

        # ------------------------------------------------------------------ #
        # Send livePlayReq BEFORE the SDP offer.  iOS app telemetry confirms
        # this message is always sent first to arm the camera's WebRTC
        # subsystem; the camera silently ignores webrtcReq without it.
        # ------------------------------------------------------------------ #
        _live_req_payload = json.dumps({
            "method":  "livePlayReq",
            "service": "IPC",
            "devId":   device_id,
            "srcAddr": f"0.{user_id}",
            "seq":     f"ap{random.randint(1000000, 9999999)}",
            "tst":     int(time.time() * 1000),
            **( {"userId": _numeric_uid_raw} if _numeric_uid_raw is not None else {} ),
            "payload": {
                "peerid":  peer_id,
                "devId":   device_id,
                # Decompiled reference app (tyrus/o.java) sets payload.dstAddr
                # to the target deviceId for livePlayReq.
                "dstAddr": device_id,
                # App payload compatibility fields (see LiveRequestParamsBean /
                # LivePlayPaylodBean in decompiled app).
                "livePlay": 1,
                "powerType": _live_power_type,
                "p2pCache": _live_p2p_cache,
                "dseq": 0,
            },
        })
        if not use_sdes:
            # SDES path sends its own livePlayReq inside _open_sdes_stream;
            # only send here for the DTLS path to avoid a duplicate.
            outgoing_q.put_nowait((live_play_topic, _live_req_payload))
            _status(f"livePlayReq sent  peerid={peer_id}")
            # Wait for the broker to echo livePlayReq back (confirms delivery).
            # Proceed as soon as the echo arrives; fall through after 0.5 s.
            try:
                await asyncio.wait_for(liveplay_echo_ev.wait(), timeout=0.5)
            except asyncio.TimeoutError:
                pass
            # livePlayResp carries camera-side accept/reject.  If the camera
            # rejects start-play, continuing to SDP/ICE causes large STUN churn
            # but no media.  Fail fast with the concrete code.
            try:
                _lp_resp = await asyncio.wait_for(
                    asyncio.shield(liveplay_resp_fut), timeout=2.0
                )
                _lp_code = int(_lp_resp.get("code", 200))
                _lp_on = int(_lp_resp.get("livePlay", 1))
                if _lp_code not in (0, 200) or _lp_on == 0:
                    raise RuntimeError(
                        f"livePlay rejected by camera (code={_lp_code}, livePlay={_lp_on})"
                    )
            except asyncio.TimeoutError:
                pass
            # Short extra wait for getIceConfigResp — the server may only respond
            # once a live camera session is active (i.e. after livePlayReq).
            # Waiting here ensures TURN credentials arrive before RTCPeerConnection
            # is created.  The 3-second window is long enough for typical Arnoo
            # broker round-trips without adding noticeable latency to fast paths.
            if not ice_config_fut.done():
                try:
                    await asyncio.wait_for(asyncio.shield(ice_config_fut), timeout=3.0)
                    _status("getIceConfigResp received (post-livePlayReq)")
                except asyncio.TimeoutError:
                    pass  # proceed without TURN; synthetic candidates are fallback

        # ------------------------------------------------------------------ #
        # Branch: SDES-SRTP cameras use ffmpeg; DTLS cameras use aiortc
        # ------------------------------------------------------------------ #
        if use_sdes:
            try:
                return await self._open_sdes_stream(
                    peer_id=peer_id,
                    user_id=user_id,
                    device_id=device_id,
                    outgoing_q=outgoing_q,
                    answer_fut=answer_fut,
                    camera_offer_fut=camera_offer_fut,
                    webrtc_req_echo_fut=webrtc_req_echo_fut,
                    loop=loop,
                    timeout=timeout,
                    output_path=output_path,
                    max_seconds=max_seconds,
                    _status=_status,
                    mqtt_fut=mqtt_fut,
                    liveplay_echo_ev=liveplay_echo_ev,
                    liveplay_resp_fut=liveplay_resp_fut,
                    numeric_uid_raw=_numeric_uid_raw,
                    dtls_fallback_ok=_dtls_fallback_ok,
                    second_answer_fut=second_answer_fut,
                    ice_config=(
                        ice_config_fut.result() if ice_config_fut.done()
                        else _http_ice_config
                    ),
                    camera_reconnect_ev=camera_reconnect_ev,
                    sdes_answer_timeout=_sdes_answer_timeout,
                    rtsp_push_url=rtsp_push_url,
                )
            except DeviceClient._SdesNoAnswerError:
                # Camera reported enableSdes='1' but did not respond to our SDES
                # offer.  iOS telemetry shows models such as LK.IPC.A001064 can
                # have an incorrectly set enableSdes property while actually
                # requiring DTLS (peerid suffix _2).  The MQTT session was already
                # told to close (None sentinel sent to outgoing_q inside
                # _open_sdes_stream); wait for the thread to finish before opening
                # a new MQTT connection with the same clientId.
                _status(
                    "SDES handshake failed — camera may be DTLS despite"
                    " enableSdes='1'.  Retrying with DTLS (aiortc) ..."
                )
                try:
                    await asyncio.wait_for(mqtt_fut, timeout=5.0)
                except Exception:
                    pass   # MQTT thread exit errors don't affect the retry
                return await self.async_open_webrtc_stream(
                    on_frame,
                    stream_id=stream_id,
                    timeout=timeout,
                    output_path=output_path,
                    status_callback=status_callback,
                    force_sdes=False,
                    _skip_ice_config=True,
                    _ice_config=(
                        ice_config_fut.result() if ice_config_fut.done() else None
                    ),
                )

        # ------------------------------------------------------------------ #
        # aiortc peer connection (DTLS-SRTP path)
        # ------------------------------------------------------------------ #
        import logging as _logging_dtls
        _logging_dtls.getLogger("aioice").setLevel(_logging_dtls.DEBUG)
        from aiortc import RTCConfiguration, RTCIceServer

        def _sanitize_ice_uris(uris):
            """Remove ?transport= from stun: URIs — invalid per RFC 7064."""
            result = []
            for u in uris:
                if isinstance(u, str) and u.startswith("stun:") and "?" in u:
                    u = u.split("?")[0]
                result.append(u)
            return result

        _ice_servers = [RTCIceServer(urls=["stun:stun.l.google.com:19302"])]
        if ice_config_fut.done():
            try:
                _ice_data = ice_config_fut.result()
                # Normalise multiple possible response shapes:
                #   Arnoo format:   {app: [{uris, id, token}, ...], dev: [...]}
                #   Standard W3C:  {iceServers: [{urls, username, credential}, ...]}
                #   Nested:        {data: {app: [...], ...}} or {data: {iceServers: [...]}}
                #   Wrapped:       {payload: {app: [...], ...}} or {code, data: {...}}
                def _unwrap(d):
                    """Recursively unwrap common envelope keys to reach the list."""
                    if not isinstance(d, dict):
                        return d
                    for _k in ("data", "payload", "result"):
                        if _k in d and isinstance(d[_k], dict):
                            inner = d[_k]
                            if any(k in inner for k in
                                   ("app", "dev", "iceServers", "turnServers")):
                                return inner
                            # one more level
                            unwrapped = _unwrap(inner)
                            if unwrapped is not inner:
                                return unwrapped
                    return d
                _ice_data = _unwrap(_ice_data)

                # Arnoo app/dev lists: [{uris/Uris/dnsUris, id/Username, token/Password}, ...]
                # app = user-level TURN entries; dev = per-device TURN entries.
                # The camera needs its device-specific credential (dev entry, Username=deviceId)
                # to allocate a TURN relay when direct / srflx connectivity is unavailable.
                # Both sections must be extracted and included in the webrtcReq IceServerList
                # so the camera receives those credentials and can initiate ICE via TURN.
                for _sect in ("app", "dev"):
                    for _entry in (_ice_data.get(_sect) or []):
                        _uris = _sanitize_ice_uris(
                            _entry.get("uris") or _entry.get("Uris")
                            or _entry.get("dnsUris") or []
                        )
                        _uid  = str(_entry.get("id") or _entry.get("Username")
                                    or _entry.get("username") or "")
                        _cred = str(_entry.get("token") or _entry.get("Password")
                                    or _entry.get("credential") or "")
                        if _uris:
                            _ice_servers.append(
                                RTCIceServer(urls=_uris, username=_uid, credential=_cred)
                            )
                # Standard W3C / plain iceServers list
                for _entry in (_ice_data.get("iceServers")
                               or _ice_data.get("turnServers") or []):
                    _uris = (_entry.get("urls") or _entry.get("uris")
                             or _entry.get("dnsUris") or [])
                    if isinstance(_uris, str):
                        _uris = [_uris]
                    _uris = _sanitize_ice_uris(_uris)
                    _uid  = str(_entry.get("username") or _entry.get("id") or "")
                    _cred = str(_entry.get("credential") or _entry.get("token") or "")
                    if _uris:
                        _ice_servers.append(
                            RTCIceServer(urls=_uris, username=_uid, credential=_cred)
                        )
                # Camera IceServerList format (from webrtcReq echo):
                # [{Uris: ['stun:...', 'turn:...'], id: '...', token: '...'}]
                # Uses capital 'Uris' key and may carry TURN credentials.
                for _entry in (_ice_data.get("IceServerList") or []):
                    _uris = (_entry.get("Uris") or _entry.get("uris")
                             or _entry.get("dnsUris") or [])
                    if isinstance(_uris, str):
                        _uris = [_uris]
                    _uris = _sanitize_ice_uris(_uris)
                    _uid  = str(_entry.get("id") or _entry.get("username")
                               or _entry.get("Username") or "")
                    _cred = str(_entry.get("token") or _entry.get("credential")
                                or _entry.get("Password") or "")
                    if _uris:
                        _ice_servers.append(
                            RTCIceServer(urls=_uris, username=_uid, credential=_cred)
                        )
                _has_turn_in_resp = any(
                    any(u.startswith(("turn:", "turns:"))
                        for u in (srv.urls if isinstance(srv.urls, list) else [srv.urls]))
                    for srv in _ice_servers[1:]
                )
                if len(_ice_servers) > 1:
                    _status(
                        f"ICE config from getIceConfigResp"
                        f" ({'TURN' if _has_turn_in_resp else 'STUN-only'}):"
                        f" {[s.urls for s in _ice_servers[1:]]}"
                    )
                else:
                    _LOGGER.warning(
                        "getIceConfigResp received but no ICE servers extracted."
                        " ice_data keys=%s", list(_ice_data.keys())[:20]
                    )
            except Exception as _ice_exc:
                _LOGGER.warning(
                    "Failed to parse getIceConfigResp ICE config: %s", _ice_exc
                )
                _has_turn_in_resp = False
        else:
            _has_turn_in_resp = False
        # Always ensure a TURN relay is available.  getIceConfigResp often returns
        # only STUN (e.g. when ice_config_fut is seeded from the camera's webrtcReq
        # echo which carries only Google STUN).  Without relay, ICE fails for cameras
        # that are on a different network segment or behind strict NAT.  The Arnoo
        # TURN server (confirmed from browser webrtc_internals — ALL candidates are
        # relay type) accepts connections without explicit per-session credentials.
        _arnoo_stun = "stun:3.230.182.123:3478"
        _arnoo_turn = "turn:3.230.182.123:5349"
        if not _has_turn_in_resp:
            _ice_servers.append(RTCIceServer(urls=[_arnoo_stun, _arnoo_turn]))
        # Log the final ICE server configuration.
        _stun_url = (_ice_servers[0].urls[0]
                     if _ice_servers and _ice_servers[0].urls
                     else "none")
        _turn_entries = [s.urls for s in _ice_servers[1:]]
        _status(
            f"ICE servers: STUN={_stun_url}"
            f"  relay×{len(_turn_entries)}: {_turn_entries}"
        )
        pc = RTCPeerConnection(
            configuration=RTCConfiguration(iceServers=_ice_servers)
        )
        # Audio: sendrecv WITHOUT a real audio sender.  Empirical findings
        # from 2026-04-26 testing (commits aa341a1b, aeaea893):
        #
        #   recvonly             → camera tears down at ~22s after SCTP up
        #                          (REMOTE-initiated DTLS Alert)
        #   sendrecv, no track   → camera patient-waits indefinitely
        #                          (no remote tear-down within test window)
        #   sendrecv + silent
        #     PCMA RTP track     → camera tears down at ~24s after SCTP up
        #                          (REMOTE-initiated DTLS Alert)
        #
        # Sendrecv flips a "viewer is a real client" gate in the camera's
        # KVS-WebRTC firmware (verified against reference offer in
        # research/webrtc_internals_dump.json:5433 which also uses sendrecv).
        # But actually emitting audio RTP from our side regresses the
        # camera — the firmware appears to dislike receiving viewer audio
        # in some way (possibly: codec mismatch, SSRC routing bug, or
        # firmware bug processing inbound audio).  Camera answer keeps
        # sendrecv on its mid:0 audio (line 327 of test log) so it's not
        # a direction-mismatch issue at the SDP layer.
        #
        # No sender tracks — camera is sendonly (a=sendonly in its answer SDP).
        # sendrecv on audio prevents direction-mismatch errors in the answer.
        #
        # Two-way audio (talk): when a talk_pcm_provider is supplied we attach a
        # real PCMA sender track from the start, mirroring the official app
        # (f0.java:695 createAudioTrack + addTrack, enabled only during talk).
        # The track emits silence until the provider returns PCM, so the camera
        # sees a genuine, continuously-present sender — the APK keeps the track
        # present the whole session, so track presence is NOT the ~24s-teardown
        # cause.  Audio is enabled on the wire by also sending AVIO SPEAKERSTART
        # (848) once the DataChannel opens (see _send_avio_speaker below).
        _talk_track = None
        if talk_pcm_provider is not None:
            _talk_track = _make_talk_audio_track(talk_pcm_provider)
        if _talk_track is not None:
            pc.addTrack(_talk_track)                        # mid:0  audio sender (PCMA talk)
            _status("talk: attached PCMA sender track (two-way audio enabled)")
        else:
            pc.addTransceiver("audio", direction="sendrecv")  # mid:0  audio (no sender track)
        pc.addTransceiver("video", direction="recvonly")   # mid:1  H264 video
        # Wire capture (2026-05-02) of an official iOS Aidot session against
        # A000088 showed the camera answers with FOUR BUNDLE'd m-sections:
        #   mid:0  audio      sendrecv  PCMA/8000
        #   mid:1  H264 video sendonly  PT 127 + RTX 124
        #   mid:2  H265 video sendonly  PT 98  + RTX 99   ← separate section!
        #   mid:3  datachannel sctp-port:5000
        # Our old 3-section offer (audio/video/DC at mids 0/1/2) caused the
        # camera's H265 answer on mid:2 to collide with our DC declaration
        # (application ≠ video), so the answer-rebuild stubbed it as DC and
        # discarded H265 entirely.  The camera never got confirmation that
        # video negotiation succeeded and sent nothing on mid:1 either.
        # H265 mid:2 is INJECTED as a synthetic SDP text section via
        # _inject_h265_section() in the offer pipeline — NO aiortc transceiver
        # is created for it.  This is intentional: aiortc does not have H265
        # in its codec registry and raises OperationError on any stub we give
        # it for a H265 transceiver.  The camera sees a proper 4-section offer
        # (audio/H264/H265/DC) from the sent SDP; aiortc only manages the
        # 3 sections it knows about (audio mid:0 / H264 mid:1 / DC mid:2).
        # Before calling setRemoteDescription, the answer is stripped of the
        # H265 stub and DC is renumbered from mid:3 → mid:2.
        # SCTP data channel — KVS firmware ALWAYS opens SCTP regardless of
        # whether m=application is in the negotiated answer.  Decoded the
        # post-handshake 0x17 records as SCTP INIT chunks (srcPort=5000
        # dstPort=5000 verifTag=0 chunkType=0x01).  Camera retransmits INIT
        # at ~6s intervals and tears DTLS down with close_notify after ~22s
        # if it never receives INIT-ACK.  Adding the data channel here
        # creates an SCTP endpoint on our side that answers the INIT.
        # Without the H265 transceiver, DC stays at mid:2 in aiortc's eyes.
        # Skipped only for A001064 (see _NO_DATACHANNEL_MODELS).
        # Helper: build the 36-byte AVIO LIVING TUTK frame and send via dc.
        # Extracted so it can be invoked from either dc.on("open") (we created
        # the channel) or pc.on("datachannel") (camera initiated DCEP).
        def _send_avio_living(_dc_ref, _label_for_log: str) -> None:
            try:
                _seq = random.randint(0, 0x7fffffff)
                _ts_ms = int(time.time() * 1000)
                _payload = struct.pack("<IB3x", 0, 1)  # channel=0, mode=LIVING
                _hdr = struct.pack(
                    "<IIqII4x",
                    _seq, 5376, _ts_ms, len(_payload), 0,
                )
                _frame = _hdr + _payload
                _dc_ref.send(_frame)
                _status(
                    f"DC[{_label_for_log}] OPEN → sent AVIO LIVING (5376)"
                    f" {len(_frame)}B seq=0x{_seq:08x}"
                )
            except Exception as _dc_send_exc:
                _status(
                    f"DC[{_label_for_log}] LIVING send failed: {_dc_send_exc}"
                )

        def _send_avio_heartbeat(_dc_ref) -> None:
            # CMD_AVIO_CTRL_HEARTHEAT_REQ = 5156 (AVIOCTRLDEFs.java:119).
            # Official app sends this every 10 s (f0.java:2991 timer period
            # 10000 ms) to prevent the camera's 22-second watchdog from
            # tearing down the DTLS session.  Empty payload, header only.
            try:
                _seq = random.randint(0, 0x7fffffff)
                _ts_ms = int(time.time() * 1000)
                _hdr = struct.pack("<IIqII4x", _seq, 5156, _ts_ms, 0, 0)
                _dc_ref.send(_hdr)
            except Exception:
                pass

        def _send_avio_audiostart(_dc_ref) -> None:
            # IOTYPE_USER_IPCAM_AUDIOSTART = 768 (AVIOCTRLDEFs.java:154).
            # The camera negotiates audio as sendrecv.  aiortc's RTCRtpSender
            # sends RTCP SR with packet_count=0 (no track), which tells the
            # camera we said sendrecv but are sending nothing.  After ~25 s
            # the camera interprets this as "viewer not receiving audio" and
            # stops its own audio RTP stream, even though DTLS/video continue.
            # Sending AUDIOSTART explicitly tells the camera to keep audio
            # streaming regardless of our send state.  8-byte payload of zeros
            # matches the TUTK IOTC path usage in a.java:1126.
            try:
                _seq = random.randint(0, 0x7fffffff)
                _ts_ms = int(time.time() * 1000)
                _payload = b'\x00' * 8
                _hdr = struct.pack("<IIqII4x", _seq, 768, _ts_ms, len(_payload), 0)
                _dc_ref.send(_hdr + _payload)
            except Exception:
                pass

        def _send_avio_speaker(_dc_ref, start: bool) -> None:
            # IOTYPE_USER_IPCAM_SPEAKERSTART = 848 / SPEAKERSTOP = 849
            # (AVIOCTRLDEFs.java:268-271).  The official app sends SPEAKERSTART
            # when talk begins (f0.java:1500, startTalk m2()) to open the
            # camera's speaker, and SPEAKERSTOP to close it.  Payload is
            # SMsgAVIoctrlAVStream.parseContent(0) = 8 bytes, channel=0 LE.
            try:
                _cmd = 848 if start else 849
                _seq = random.randint(0, 0x7fffffff)
                _ts_ms = int(time.time() * 1000)
                _payload = b'\x00' * 8  # channel=0
                _hdr = struct.pack("<IIqII4x", _seq, _cmd, _ts_ms, len(_payload), 0)
                _dc_ref.send(_hdr + _payload)
                _status(f"talk: sent AVIO SPEAKER{'START' if start else 'STOP'}"
                        f" ({_cmd})")
            except Exception as _spk_exc:
                _status(f"talk: SPEAKER{'START' if start else 'STOP'} failed:"
                        f" {_spk_exc}")

        # Camera-initiated DCEP path: KVS firmware on A000088 doesn't include
        # m=application in its answer SDP, suggesting the data channel may
        # actually be opened by the camera (master), not the viewer.  Hook
        # pc.on("datachannel") so we receive whatever channel arrives.
        @pc.on("datachannel")
        def _on_remote_datachannel(channel) -> None:
            _status(
                f"pc.on(datachannel) FIRED — label={channel.label!r}"
                f" id={channel.id} state={channel.readyState}"
            )

            @channel.on("open")
            def _on_remote_dc_open() -> None:
                _status(f"DC[remote:{channel.label}] OPEN (camera-initiated)")

            @channel.on("message")
            def _on_remote_dc_message(message) -> None:
                try:
                    if isinstance(message, (bytes, bytearray)):
                        _status(
                            f"DC[remote:{channel.label}] RX {len(message)}B"
                            f" hex={bytes(message)[:32].hex()}"
                        )
                    else:
                        _status(f"DC[remote:{channel.label}] RX text {message!r}")
                except Exception:
                    pass

        track_tasks: list = []
        _kvs_dc = None
        if self._offer_should_include_datachannel:
            # Match the official client's label exactly: f0.java:2923 uses
            # "data-channel-of-" + this.h, where this.h is the peer_id we
            # already generate (deviceId_random_count_0_streamID).  Camera
            # firmware likely pattern-matches this label.
            _dc_label = f"data-channel-of-{peer_id}"
            # Pre-negotiated channel (negotiated=True, id=1): skip DCEP
            # entirely.  Tested default (DCEP) createDataChannel on
            # 2026-04-25 — DTLS regression: aiortc allocates a second
            # ICE/DTLS transport for the DCEP-mode datachannel that doesn't
            # survive the answer-rebuild BUNDLE rewrite, and `__connect()`
            # raises InvalidStateError("RTCIceTransport is closed") before
            # DTLS handshake can complete.  Pre-negotiated mode rides on the
            # bundled transport, so DTLS comes up.  AVIO LIVING send below is
            # disabled separately to test whether the camera tolerates its
            # absence (per BaseKVSCameraView.k():805-815, the official client
            # only sends LIVING for PreCon cameras).
            _kvs_dc = pc.createDataChannel(_dc_label, negotiated=True, id=0)
            _status(
                f"offer: including SCTP datachannel label={_dc_label!r}"
                f" (pre-negotiated; KVS opens SCTP regardless)"
            )

            # AVIO LIVING (E_CMD_AVIO_CTRL_SESSION_MODE_REQ=5376) is sent
            # unconditionally when DC opens.  2026-05-03 testing confirmed:
            # A000088 cameras (Deck + Bedroom M3 Pro) connect via DTLS,
            # SCTP comes up, DC opens at t+1-2s — but camera tears down at
            # t+22s if LIVING is not sent.  This is the PreCon watchdog:
            # without LIVING the camera gives up waiting for a viewer.
            # Previously LIVING was gated on setDevAttrNotif(sptPreconn:1),
            # but setDevAttrNotif only arrives during quickConn reset cycles
            # (now eliminated) — so the flag never gets set.
            # Per BaseKVSCameraView.k():805-815, non-PreCon cameras ignore
            # LIVING; sending it unconditionally is safe.

            @_kvs_dc.on("open")
            def _on_kvs_dc_open() -> None:
                async def _dcep_open_then_living() -> None:
                    # The official KVS Android client uses DCEP
                    # (createDataChannel with default Init), so the camera
                    # registers stream 0 only after receiving DATA_CHANNEL_OPEN
                    # (PPID=50, RFC 8832 §5.1).  Our pre-negotiated DC skips
                    # DCEP, so AVIO LIVING (PPID=51) arrives on an unregistered
                    # stream and is silently discarded at the application layer
                    # (SCTP SACK confirms transport delivery, but no response).
                    # Send DATA_CHANNEL_OPEN first so the camera registers
                    # stream 0, then send AVIO LIVING.
                    try:
                        _label_bytes = _dc_label.encode("utf-8")
                        _dc_open_msg = struct.pack(
                            "!BBHLHH",
                            0x03, 0x00,          # OPEN, DATA_CHANNEL_RELIABLE
                            0, 0,                # priority, reliability_param
                            len(_label_bytes), 0,  # label_len, proto_len
                        ) + _label_bytes
                        await _kvs_dc.transport._send(0, 50, _dc_open_msg)
                        _status(
                            f"DC[{_dc_label}] sent DATA_CHANNEL_OPEN"
                            f" (PPID=50) {len(_dc_open_msg)}B"
                        )
                        # Yield to event loop so DATA_CHANNEL_OPEN is
                        # transmitted and camera can register stream 0.
                        await asyncio.sleep(0.3)
                    except Exception as _dc_open_exc:
                        _status(
                            f"DC[{_dc_label}] DATA_CHANNEL_OPEN failed:"
                            f" {_dc_open_exc}"
                        )
                    _send_avio_living(_kvs_dc, _dc_label + " (PreCon)")
                    _send_avio_audiostart(_kvs_dc)
                    # Talk mode: open the camera speaker so it plays our audio.
                    if talk_pcm_provider is not None:
                        _send_avio_speaker(_kvs_dc, True)

                    # Periodic keepalive loop:
                    # - HEARTBEAT (5156) every 10 s: prevents camera's ~22 s
                    #   DTLS watchdog (f0.java:2991).
                    # - AUDIOSTART (768) every 10 s: prevents camera's ~25 s
                    #   audio watchdog.  Camera negotiates audio as sendrecv;
                    #   aiortc's sender emits RTCP SR with packet_count=0, which
                    #   the camera reads as "viewer not sending audio → stop
                    #   sending audio".  Periodic AUDIOSTART keeps audio alive.
                    async def _heartbeat_loop() -> None:
                        try:
                            while True:
                                await asyncio.sleep(10.0)
                                _send_avio_heartbeat(_kvs_dc)
                                _send_avio_audiostart(_kvs_dc)
                        except asyncio.CancelledError:
                            pass
                    _hb_task = asyncio.ensure_future(_heartbeat_loop())
                    track_tasks.append(_hb_task)

                asyncio.ensure_future(_dcep_open_then_living())

            @_kvs_dc.on("message")
            def _on_kvs_dc_message(message) -> None:
                try:
                    if isinstance(message, (bytes, bytearray)):
                        _status(
                            f"DC[{_dc_label}] RX {len(message)}B"
                            f" hex={bytes(message)[:32].hex()}"
                        )
                    else:
                        _status(f"DC[{_dc_label}] RX text {message!r}")
                except Exception:
                    pass

            # Periodic readyState diagnostic — last run had no "DC OPEN"
            # log line, so we want to see whether readyState ever transitions
            # away from "connecting" or stays stuck.  Polls for 30s then stops.
            async def _poll_dc_state():
                _last = None
                for _ in range(30):
                    try:
                        _cur = _kvs_dc.readyState
                    except Exception:
                        _cur = "<error>"
                    if _cur != _last:
                        _status(f"DC[{_dc_label}] readyState: {_last} → {_cur}")
                        _last = _cur
                    if _cur in ("open", "closed"):
                        break
                    await asyncio.sleep(1.0)

            track_tasks.append(asyncio.ensure_future(_poll_dc_state()))
        else:
            _status("offer: SCTP datachannel skipped (model in _NO_DATACHANNEL_MODELS)")

        @pc.on("track")
        def _on_track(track) -> None:
            if track.kind == "audio":
                _status(f"audio track: id={track.id} kind={track.kind}")
                # The audio transceiver is sendrecv (no actual sender track).
                # aiortc's RTCRtpSender fires RTCP SR every ~1 s with
                # packet_count=0.  Camera firmware interprets 25 s of
                # zero-packet SR as "viewer not transmitting audio → stop
                # sending audio to them."  We patch the sender's _send_rtcp
                # to a no-op so no SR reaches the camera.
                #
                # In talk mode we attach a REAL PCMA sender, so its RTCP SR
                # carries genuine packet counts — skip the suppression so the
                # camera sees a properly-transmitting viewer.
                async def _suppress_audio_sender_rtcp() -> None:
                    # Patch _send_rtcp on the sender instance to a no-op so
                    # the RTCP SR loop keeps running (no BYE sent) but every
                    # SR with packet_count=0 is silently discarded.
                    # Cancelling the task instead would trigger a RTCP BYE,
                    # signalling "sender done" to the camera — worse outcome.
                    await asyncio.sleep(1.5)  # wait for sender to start
                    for _t in pc.getTransceivers():
                        if _t.kind == "audio":
                            async def _noop_rtcp(_pkts, **_kw):
                                pass
                            _t.sender._send_rtcp = _noop_rtcp
                            _status(
                                "audio sender: _send_rtcp patched → no-op"
                                " (suppresses 0-packet SR audio watchdog)"
                            )
                            break
                if talk_pcm_provider is None:
                    asyncio.ensure_future(_suppress_audio_sender_rtcp())
                # Drain decoded audio frames so the queue doesn't grow unbounded.
                async def _drain_audio() -> None:
                    try:
                        while True:
                            await track.recv()
                    except Exception:
                        pass
                t = asyncio.ensure_future(_drain_audio())
                track_tasks.append(t)
            elif track.kind == "video":
                # Request an IDR keyframe immediately via RTCP PLI so we start
                # decoding from a complete frame.  Without this, if the camera's
                # first IDR arrived before our SRTP path was ready (seq gap at
                # the start), H264 decoding silently drops every subsequent
                # delta frame and we receive zero decoded frames.
                async def _request_keyframe() -> None:
                    # aiortc 1.14 changed _send_rtcp_pli(media_ssrc) to require
                    # the remote SSRC.  The SSRC is only known once RTP starts
                    # arriving, so poll getSynchronizationSources() briefly and
                    # send PLI for each discovered source.
                    for _attempt in range(10):  # up to ~5s
                        await asyncio.sleep(0.5)
                        try:
                            _recv = next(
                                (r for r in pc.getReceivers() if r.track is track),
                                None,
                            )
                            if _recv is None:
                                continue
                            _ssrcs = [
                                s.source
                                for s in _recv.getSynchronizationSources()
                            ]
                            if not _ssrcs:
                                continue
                            for _ssrc in _ssrcs:
                                await _recv._send_rtcp_pli(_ssrc)
                            _status(
                                f"video track: sent RTCP PLI (keyframe request)"
                                f" ssrc={_ssrcs}"
                            )
                            return
                        except Exception as _pli_exc:
                            _LOGGER.debug("RTCP PLI attempt failed: %s", _pli_exc)
                    _LOGGER.debug("RTCP PLI: no SSRC discovered within 5s")
                asyncio.ensure_future(_request_keyframe())
                if on_frame is not None:
                    t = asyncio.ensure_future(_webrtc_consume_video(track, on_frame))
                    track_tasks.append(t)

        recorder = None
        if output_path:
            try:
                from aiortc.contrib.media import MediaRecorder
                recorder = MediaRecorder(output_path)

                _video_recorded = [False]

                @pc.on("track")
                def _on_track_rec(track) -> None:
                    if track.kind == "video":
                        if not _video_recorded[0]:
                            recorder.addTrack(track)
                            _video_recorded[0] = True
                    else:
                        recorder.addTrack(track)
            except Exception as exc:
                _LOGGER.warning(
                    "async_open_webrtc_stream: MediaRecorder not available: %s", exc
                )

        # ------------------------------------------------------------------ #
        # Create SDP offer and publish webrtcReq
        # ------------------------------------------------------------------ #
        offer = await pc.createOffer()
        await pc.setLocalDescription(offer)
        _LOGGER.debug(
            "webrtc: SDP offer (first 500 chars):\n%s",
            pc.localDescription.sdp[:500],
        )

        def _sdp_transport(sdp: str, kind: str) -> str:
            for line in sdp.splitlines():
                if line.startswith(f"m={kind} "):
                    parts = line.split()
                    return parts[2] if len(parts) > 2 else "?"
            return "absent"

        _sdp = pc.localDescription.sdp
        _status(
            f"SDP offer  m=video={_sdp_transport(_sdp, 'video')}"
            f"  m=audio={_sdp_transport(_sdp, 'audio')}"
        )
        _mlines = [ln for ln in _sdp.splitlines() if ln.startswith("m=")]
        _status("SDP m-sections (%d): %s" % (len(_mlines), " | ".join(_mlines)))

        def _seq() -> str:
            return f"ap{random.randint(1000000, 9999999)}"

        def _upgrade_sctp(sdp: str) -> str:
            """Convert aiortc pre-RFC-8841 SCTP section to RFC 8841 format.

            aiortc generates the legacy format:
                m=application PORT DTLS/SCTP 5000
                a=sctpmap:5000 webrtc-datachannel 65535
                a=max-message-size:65536

            RFC 8841 (and cameras / modern browsers) expect:
                m=application 9 UDP/DTLS/SCTP webrtc-datachannel
                a=sctp-port:5000
                a=max-message-size:65536   ← required by RFC 8841 §4.3.1
            """
            import re as _re
            out = []
            for line in _re.split(r'\r?\n', sdp):
                if _re.match(r'^m=application \d+ DTLS/SCTP \d+$', line):
                    out.append('m=application 9 UDP/DTLS/SCTP webrtc-datachannel')
                elif line.startswith('a=sctpmap:'):
                    out.append('a=sctp-port:5000')
                else:
                    out.append(line)   # includes a=max-message-size (keep as-is)
            return '\r\n'.join(out)

        def _inject_h265_section(sdp: str) -> str:
            """Inject a synthetic H265 m-section between H264 and DC.

            aiortc has no H265 codec support; creating a second video transceiver
            for H265 causes setRemoteDescription to fail with OperationError
            regardless of what stub we provide in the answer.  Instead:
            - aiortc manages 3 sections: audio(mid:0), H264(mid:1), DC(mid:2)
            - This function INSERTS a synthetic H265 text section as mid:2 and
              renumbers the DC section from mid:2 → mid:3 in the SENT offer.
            - The camera sees the expected 4-section BUNDLE layout.
            - Before setRemoteDescription, the answer is stripped back to 3 aiortc
              sections via _aiortc_answer() (H265 dropped, DC mid:3 → mid:2).

            PTs are chosen free of any already-used PT in the SDP.
            """
            import re as _re

            _used_pts: set = set()
            for _ln in _re.split(r'\r?\n', sdp):
                _mm = _re.match(r'^m=\S+ \d+ \S+ (.+)$', _ln)
                if _mm:
                    for _pt in _mm.group(1).split():
                        try:
                            _used_pts.add(int(_pt))
                        except ValueError:
                            pass
                _rm = _re.match(r'^a=rtpmap:(\d+) ', _ln)
                if _rm:
                    _used_pts.add(int(_rm.group(1)))
            _free = [pt for pt in range(96, 128) if pt not in _used_pts]
            _h265_pt = _free[0]
            _h265_rtx_pt = _free[1] if len(_free) > 1 else _free[0] + 1

            # Parse SDP into header (pre-first-m=) + per-section blocks.
            lines = _re.split(r'\r?\n', sdp)
            header: list[str] = []
            sections: list[list[str]] = []
            _in_header = True
            _cur_sec: list[str] = []
            for ln in lines:
                if _in_header and ln.startswith('m='):
                    _in_header = False
                if _in_header:
                    header.append(ln)
                elif ln.startswith('m='):
                    if _cur_sec:
                        sections.append(_cur_sec)
                    _cur_sec = [ln]
                else:
                    _cur_sec.append(ln)
            if _cur_sec:
                sections.append(_cur_sec)

            # Find mid:1 (H264) section to clone transport attrs for H265.
            _h264_sec = next((s for s in sections if any('a=mid:1' == l.rstrip() for l in s)), None)
            _ufrag = _pwd = _fp = _setup = ''
            if _h264_sec:
                for _l in _h264_sec:
                    if _l.startswith('a=ice-ufrag:'): _ufrag = _l
                    elif _l.startswith('a=ice-pwd:'): _pwd = _l
                    elif _l.startswith('a=fingerprint:'): _fp = _l
                    elif _l.startswith('a=setup:'): _setup = _l

            # Build the synthetic H265 m-section (mid:2).
            _video_port = _h264_sec[0].split()[1] if _h264_sec else '9'
            _h265_sec: list[str] = [
                f'm=video {_video_port} UDP/TLS/RTP/SAVPF {_h265_pt} {_h265_rtx_pt}',
                'c=IN IP4 0.0.0.0',
            ]
            for _x in (_ufrag, _pwd, _fp, _setup):
                if _x:
                    _h265_sec.append(_x)
            _h265_sec.extend([
                'a=mid:2',
                'a=recvonly',
                'a=rtcp-mux',
                f'a=rtpmap:{_h265_pt} H265/90000',
                f'a=fmtp:{_h265_pt} level-id=180;profile-id=1;tier-flag=0;tx-mode=SRST',
                f'a=rtcp-fb:{_h265_pt} nack',
                f'a=rtcp-fb:{_h265_pt} goog-remb',
                f'a=rtcp-fb:{_h265_pt} transport-cc',
                f'a=rtpmap:{_h265_rtx_pt} rtx/90000',
                f'a=fmtp:{_h265_rtx_pt} apt={_h265_pt}',
            ])

            # Renumber DC section: mid:2 → mid:3.
            new_sections: list[list[str]] = []
            for sec in sections:
                if any('a=mid:2' == l.rstrip() for l in sec) and sec[0].startswith('m=application'):
                    new_sections.append([l.replace('a=mid:2', 'a=mid:3') if l.rstrip() == 'a=mid:2' else l for l in sec])
                else:
                    new_sections.append(sec)

            # Insert H265 section between H264 (mid:1) and DC (now mid:3).
            result_secs: list[list[str]] = []
            for sec in new_sections:
                result_secs.append(sec)
                if any('a=mid:1' == l.rstrip() for l in sec):
                    result_secs.append(_h265_sec)

            # Update a=group:BUNDLE in header.
            new_header = []
            for hl in header:
                if hl.startswith('a=group:BUNDLE '):
                    mids = hl[len('a=group:BUNDLE '):].split()
                    # Replace mid:2 with mid:2 mid:3 (H265 + DC)
                    new_mids: list[str] = []
                    for m in mids:
                        if m == '2':
                            new_mids.extend(['2', '3'])  # H265 then DC
                        else:
                            new_mids.append(m)
                    new_header.append('a=group:BUNDLE ' + ' '.join(new_mids))
                else:
                    new_header.append(hl)

            all_lines = new_header[:]
            for sec in result_secs:
                all_lines.extend(sec)
            return '\r\n'.join(all_lines)

        def _normalize_bundle_ice_credentials(sdp: str) -> str:
            """Unify all m-section ICE credentials to match the BUNDLE master (mid:0).

            RFC 8843 §7.1.3 requires all bundled m-sections to carry the same
            ice-ufrag and ice-pwd.  aiortc generates a separate ICETransport per
            transceiver, giving each a unique credential pair.  Cameras that
            validate this requirement silently reject offers with mismatched
            credentials.  We overwrite every m-section's credentials with those
            of the first m-section (the BUNDLE master, mid:0).

            This is safe because: after BUNDLE negotiation succeeds, aiortc uses
            only mid:0's ICETransport for all media; the camera's ICE checks go
            exclusively to mid:0, whose credentials remain unchanged.
            """
            import re as _re
            lines = _re.split(r'\r?\n', sdp)
            master_ufrag: str | None = None
            master_pwd:   str | None = None
            in_msection = False
            for ln in lines:
                if ln.startswith('m='):
                    in_msection = True
                if in_msection:
                    if ln.startswith('a=ice-ufrag:') and master_ufrag is None:
                        master_ufrag = ln
                    if ln.startswith('a=ice-pwd:') and master_pwd is None:
                        master_pwd = ln
                if master_ufrag and master_pwd:
                    break
            if not (master_ufrag and master_pwd):
                return sdp   # no ICE credentials found; leave SDP unchanged
            result = []
            for ln in lines:
                if ln.startswith('a=ice-ufrag:'):
                    result.append(master_ufrag)
                elif ln.startswith('a=ice-pwd:'):
                    result.append(master_pwd)
                else:
                    result.append(ln)
            return '\r\n'.join(result)

        def _reorder_m_section_ice_attrs(sdp: str) -> str:
            """Move transport attrs (ice-ufrag/pwd, fingerprint, setup) before candidates.

            aiortc places a=ice-ufrag, a=ice-pwd, a=fingerprint, and a=setup at
            the END of each m-section, after all a=candidate lines.  Camera
            firmware parsers (and Chrome/libwebrtc) expect these transport
            attributes to appear BEFORE the first a=candidate line.  A linear
            parser that encounters candidates before seeing ice-ufrag/pwd cannot
            validate them and silently rejects the offer — producing no webrtcResp.

            This function moves those four lines to immediately before the first
            a=candidate: in every m-section that contains candidates.  All other
            attribute ordering is preserved; no content is added or removed.
            """
            import re as _re
            _TRANSPORT = ('a=ice-ufrag:', 'a=ice-pwd:', 'a=fingerprint:', 'a=setup:')
            lines = _re.split(r'\r?\n', sdp)
            sections: list[list[str]] = []
            current: list[str] = []
            for ln in lines:
                if ln.startswith('m=') and current:
                    sections.append(current)
                    current = [ln]
                else:
                    current.append(ln)
            if current:
                sections.append(current)
            result: list[str] = []
            for sec in sections:
                first_cand = next(
                    (i for i, ln in enumerate(sec) if ln.startswith('a=candidate:')),
                    None,
                )
                if first_cand is None:
                    result.extend(sec)
                    continue
                # Collect transport lines that appear at-or-after first candidate
                transport_after: list[str] = []
                kept: list[str] = []
                for ln in sec[first_cand:]:
                    if any(ln.startswith(p) for p in _TRANSPORT):
                        transport_after.append(ln)
                    else:
                        kept.append(ln)
                result.extend(sec[:first_cand])
                result.extend(transport_after)
                result.extend(kept)
            return '\r\n'.join(result)

        def _filter_sdp_candidates(sdp: str) -> str:
            """Remove ICE candidates that are unreachable from remote cameras.

            Strips Docker-bridge (172.17.x), CGNAT/Tailscale (100.x.x.x), and
            all IPv6 addresses from the SDP.  These addresses are only reachable
            within the local host or VPN and waste ICE checking time; they also
            cause ICE-lite cameras to echo them back verbatim as their own
            candidates, polluting the remote candidate list.

            LAN (192.168.x / 10.x / 172.16-31 non-Docker), srflx, and TURN
            relay candidates are kept — they represent paths a remote camera
            can actually use.
            """
            import re as _re
            out = []
            for line in _re.split(r'\r?\n', sdp):
                if line.startswith('a=candidate:'):
                    # Skip Docker bridge 172.17.x
                    if _re.search(r'\b172\.17\.', line):
                        continue
                    # Skip CGNAT / Tailscale 100.x.x.x
                    if _re.search(r'\b100\.\d+\.\d+\.\d+\b', line):
                        continue
                    # Skip IPv6 candidates (any colon-containing IP field)
                    # Format: "a=candidate:... IP6-addr port ..."
                    parts = line.split()
                    # parts[4] is the IP address in standard candidate line
                    if len(parts) > 4 and ':' in parts[4]:
                        continue
                out.append(line)
            return '\r\n'.join(out)

        def _strip_datachannel(sdp: str) -> str:
            """Remove the m=application (datachannel) section from the SDP offer.

            Camera firmware (e.g. LK.IPC.A001064) does not support WebRTC data
            channels and silently discards offers that include an m=application
            section.  aiortc adds this section automatically; stripping it gives
            the camera a clean 2-m-line offer (audio + video) that it can parse.

            Also removes the datachannel mid from the BUNDLE group so the SDP
            remains well-formed.
            """
            import re as _re_dc
            lines = _re_dc.split(r'\r?\n', sdp)
            # Find the start of m=application section
            _dc_start = None
            for _i, _ln in enumerate(lines):
                if _ln.startswith('m=application'):
                    _dc_start = _i
                    break
            if _dc_start is None:
                return sdp  # no datachannel section — nothing to strip
            # The section ends at the next m= line (or EOF)
            _dc_end = len(lines)
            for _i in range(_dc_start + 1, len(lines)):
                if lines[_i].startswith('m='):
                    _dc_end = _i
                    break
            # Extract the mid of the datachannel section so we can remove it
            # from a=group:BUNDLE
            _dc_mid = None
            for _ln in lines[_dc_start:_dc_end]:
                if _ln.startswith('a=mid:'):
                    _dc_mid = _ln[len('a=mid:'):]
                    break
            # Remove the datachannel section
            out_lines = lines[:_dc_start] + lines[_dc_end:]
            # Update a=group:BUNDLE to remove the datachannel mid
            if _dc_mid is not None:
                for _i, _ln in enumerate(out_lines):
                    if _ln.startswith('a=group:BUNDLE'):
                        mids = _ln[len('a=group:BUNDLE'):].split()
                        mids = [m for m in mids if m != _dc_mid]
                        out_lines[_i] = 'a=group:BUNDLE' + (' ' + ' '.join(mids) if mids else '')
                        break
            return '\r\n'.join(out_lines)

        def _dedup_bundle_candidates(sdp: str) -> str:
            """Remove a=candidate lines from non-BUNDLE-master m-sections.

            In a BUNDLE-d offer all m-sections share one ICE transport.
            Candidates only need to appear in the first m-section (mid:0,
            the BUNDLE master); listing them in mid:1 and mid:2 as well
            bloats the SDP by ~800-1200 bytes and can push the total
            webrtcReq MQTT payload over the camera's receive-buffer limit
            (~9-10 KB for A000088), causing a quickConn reset.  Stripping
            duplicate candidates from non-master sections is safe because
            the camera uses a single ICE transport for all BUNDLE'd media.
            """
            import re as _re_dc2
            lines = _re_dc2.split(r'\r?\n', sdp)
            sections: list[list[str]] = []
            current: list[str] = []
            for ln in lines:
                if ln.startswith('m=') and current:
                    sections.append(current)
                    current = [ln]
                else:
                    current.append(ln)
            if current:
                sections.append(current)
            result: list[str] = []
            for i, sec in enumerate(sections):
                if i == 0:
                    result.extend(sec)   # keep all in BUNDLE master (first m-section)
                else:
                    result.extend(ln for ln in sec if not ln.startswith('a=candidate:'))
            return '\r\n'.join(result)

        _offer_sdp = _dedup_bundle_candidates(
            _filter_sdp_candidates(
                _reorder_m_section_ice_attrs(
                    _normalize_bundle_ice_credentials(
                        _upgrade_sctp(pc.localDescription.sdp)
                    )
                )
            )
        )
        # Strip a=fingerprint:sha-384 and sha-512 lines.  aiortc emits all three
        # algorithm fingerprints; the camera's KVS-derived DTLS validator picks
        # one and fails when it doesn't match (closes the handshake with
        # "Unexpected EOF" after we send our certificate).  Browser WebRTC sends
        # sha-256 only — verified from a recorded successful session on the
        # same A001513 camera.  Keep only sha-256 to mirror that behaviour.
        import re as _fp_strip_re
        _offer_sdp = _fp_strip_re.sub(
            r'(?m)^a=fingerprint:sha-(?:384|512)[^\r\n]*\r?\n', '', _offer_sdp
        )
        _patched_mlines = [ln for ln in _offer_sdp.splitlines() if ln.startswith("m=")]
        _status("Offer m-sections (patched): %s" % " | ".join(_patched_mlines))
        # Build IceServerList from available _ice_servers for inclusion in
        # webrtcReq.  The browser always sends IceServerList; without it some
        # camera firmware (e.g. LK.IPC.A001064) does not activate its ICE
        # agent and never sends STUN probes, causing ICE to time out.
        # Deduplicate by URI tuple — getIceConfigResp commonly returns the
        # same TURN server 8x (one entry per relay slot).  Sending all 8
        # bloats the webrtcReq payload past A001064's MQTT receive buffer.
        _ice_server_list: list = []
        _seen_uris: set = set()
        for _srv in _ice_servers:
            _uris = _srv.urls if isinstance(_srv.urls, list) else [_srv.urls]
            _key = tuple(_uris)
            if _key in _seen_uris:
                continue
            _seen_uris.add(_key)
            _entry: dict = {"Uris": _uris}
            if getattr(_srv, "username", None):
                _entry["Username"] = _srv.username
            if getattr(_srv, "credential", None):
                _entry["Password"] = _srv.credential
            _ice_server_list.append(_entry)

        import random as _rnd_psk_dtls
        _psk_charset_dtls = "123456789abcdef"
        _psk_dtls = "".join(
            _psk_charset_dtls[_rnd_psk_dtls.randint(0, len(_psk_charset_dtls) - 1)]
            for _ in range(64)
        )

        # Compress SDP for wPayload.offer.sdp.  encOffer=1 in the official
        # client signals "compact SDP" — the camera's parser only consumes
        # the lines kept by _compress_sdp_for_camera.  Sending the full
        # aiortc-generated SDP (~5 KB+ of extmap/rtcp-fb/ssrc/msid) overflows
        # A001064's MQTT receive buffer and the camera quickConn-resets the
        # broker session before processing the request.
        _compressed_offer_sdp = _compress_sdp_for_camera(_offer_sdp)

        webrtc_req_payload = json.dumps({
            "method":  "webrtcReq",
            "service": "IPC",
            "devId":   device_id,
            "srcAddr": f"0.{user_id}",
            "seq":     _seq(),
            "tst":     int(time.time() * 1000),
            **( {"userId": _numeric_uid_raw} if _numeric_uid_raw is not None else {} ),
            "payload": {
                # Browser-style nested fields — newer firmware (e.g. A001064)
                # parses payload.wPayload.peerid / payload.wPayload.offer and
                # requires IceServerList to activate its ICE agent.
                # HAR captures from the official AiDot web app confirm this is
                # the canonical format; flat fields are kept for older firmware.
                # wPayload.offer.sdp must carry the FULL SDP (not the
                # compressed form): the camera's compressed-answer codepath
                # appears to skip its fingerprint-fill step when fed a
                # compressed offer, returning a malformed
                # `a=fingerprint:sha-256 ` line with empty value that
                # aiortc then rejects with "not enough values to unpack".
                # The legacy flat payload.offer.sdp gets the COMPRESSED SDP
                # so the total request still fits under the camera's MQTT
                # receive buffer (~10 KB threshold; we want < ~7-8 KB).
                "wPayload": {
                    "peerid": peer_id,
                    "sts":    int(time.time() * 1000),
                    "psk":    _psk_dtls,
                    "offer":  {"type": pc.localDescription.type,
                                "sdp":  _offer_sdp},
                },
                "IceServerList": _ice_server_list,
                # Legacy flat fields — older firmware parses payload.peerid directly.
                "peerid":  peer_id,
                "devId":   device_id,
                "offer":   {"type": pc.localDescription.type,
                             "sdp":  _compressed_offer_sdp},
                "trackId": 0,
                # Decompiled reference app (tyrus/o.java) sets dstAddr=deviceId
                # for webrtcReq.
                "dstAddr": device_id,
                "liveMqtt": 1,
                "encOffer": 1,
                # powerType/p2pCache: per docs/official_camera_network_calls.md
                # §5.2, both fields are present on every webrtcReq.  Defaults
                # used here match the fallback behaviour in the decompiled
                # reference app when IPC device info is unavailable.
                "powerType": _live_power_type,
                "p2pCache": _live_p2p_cache,
            },
        })
        outgoing_q.put_nowait((webrtc_req_topic, webrtc_req_payload))
        _status(f"webrtcReq sent  peerid={peer_id}"
                f"  IceServerList×{len(_ice_server_list)}"
                f"  payload={len(webrtc_req_payload)}B")

        # Re-announce user presence now that the camera is confirmed awake
        # (it responded to livePlayReq).  The first user/connect was sent at
        # MQTT-setup time; this second send gives ICE-lite cameras a better
        # chance of pushing setDevAttrNotif with their LAN IP before the ICE
        # wait loop starts.  Replaces the invented getDevAttrReq.
        if not _cam_local_ip:
            outgoing_q.put_nowait((
                f"iot/v1/cb/{user_id}/user/connect",
                json.dumps({
                    "service": "user",
                    "method":  "connect",
                    "srcAddr": f"0.{user_id}",
                    "payload": {"timestamp": _mqtt_timestamp()},
                }),
            ))

        # Store ICE candidates for reconnect re-send (camera may quickConn-reset
        # during the signaling wait and need a fresh offer + candidates).
        _dtls_ice_payloads: list = []  # list of (topic, json_str)

        # Forward our own ICE candidates to the camera via MQTT
        @pc.on("icecandidate")
        def _on_local_ice(candidate) -> None:
            # Diag: aiortc gathers candidates during setLocalDescription and
            # may never fire this event (vanilla-ICE behavior).  Log unconditionally
            # so the next run tells us whether we can rely on this hook or must
            # do the manual local-SDP candidate extraction (see post-SRD block).
            _status(f"icecandidate event fired: {candidate!r}")
            if candidate is None:
                return
            # Skip candidates that remote cameras cannot use.
            # Docker-bridge (172.17.x), CGNAT/Tailscale (100.x.x.x), and
            # IPv6 addresses are unreachable from cameras on the internet or
            # a different LAN segment.  Sending them wastes ICE checking time
            # and can cause ICE-lite cameras to echo them back as their own
            # candidates, polluting the remote candidate list.
            import re as _re
            _cand_ip = getattr(candidate, "ip", "") or ""
            if _re.match(r'^172\.17\.', _cand_ip):
                return  # Docker bridge — skip
            if _re.match(r'^100\.', _cand_ip):
                return  # CGNAT / Tailscale — skip
            if ':' in _cand_ip:
                return  # IPv6 — skip
            cand_str = (
                f"candidate:{candidate.foundation} {candidate.component} "
                f"{candidate.protocol} {candidate.priority} {candidate.ip} "
                f"{candidate.port} typ {candidate.type}"
            )
            if getattr(candidate, "relatedAddress", None):
                cand_str += (
                    f" raddr {candidate.relatedAddress}"
                    f" rport {candidate.relatedPort}"
                )
            # Include sdpMid/sdpMLineIndex so the camera can map the candidate
            # to the correct m-section.  A001064 and similar firmware needs these
            # fields; without them the camera may silently ignore the candidates.
            _cand_obj: dict = {"candidate": cand_str}
            _c_mid     = getattr(candidate, "sdpMid",        None)
            _c_mid_idx = getattr(candidate, "sdpMLineIndex",  None)
            if _c_mid is not None:
                _cand_obj["sdpMid"] = _c_mid
            if _c_mid_idx is not None:
                _cand_obj["sdpMLineIndex"] = _c_mid_idx
            payload = json.dumps({
                "method":  "iceCandidateReq",
                "service": "IPC",
                "devId":   device_id,
                "srcAddr": f"0.{user_id}",
                "seq":     _seq(),
                "tst":     int(time.time() * 1000),
                **( {"userId": _numeric_uid_raw} if _numeric_uid_raw is not None else {} ),
                "payload": {
                    # dstAddr routes the candidate to the target device (device ID,
                    # not user ID).  HAR captures from the official AiDot web app
                    # confirm payload.dstAddr = deviceId on every iceCandidateReq.
                    "dstAddr": device_id,
                    # wPayload is the browser-style nested format required by
                    # newer firmware (e.g. LK.IPC.A001064) that parses
                    # payload.wPayload.candidate rather than payload.candidate.
                    "wPayload": {
                        "peerid":    peer_id,
                        "candidate": _cand_obj,
                    },
                    # Keep flat fields for older firmware that reads payload.peerid /
                    # payload.candidate directly.
                    "peerid":    peer_id,
                    "devId":     device_id,
                    "candidate": _cand_obj,
                },
            })
            outgoing_q.put_nowait((ice_cand_topic, payload))
            _dtls_ice_payloads.append((ice_cand_topic, payload))

        # Wait for EITHER webrtcResp (normal) OR webrtcReq from camera (role reversal).
        # Some firmware (e.g. LK.IPC.A001064) responds to our offer by sending back
        # its own webrtcReq (counter-offer) instead of a webrtcResp answer.
        #
        # Also include webrtc_req_echo_fut: for "echo-only" cameras (e.g.
        # LK.IPC.A001064) the broker echo of our webrtcReq is the camera's ONLY
        # signal — no separate webrtcResp or non-echo webrtcReq ever arrives.
        # If only the echo fires we do a brief secondary wait; if still no real
        # response we synthesise camera_offer_fut from the echo SDP so the
        # existing role-reversal path can proceed (it already handles mirrored
        # ICE credentials — see comment below at "Observed behaviour").
        #
        # Note: _patch_answer_mid2_for_aiortc is no longer needed.  With 3-section
        # SDP the camera's answer mid:1=H264 video and mid:2=datachannel — aiortc
        # accepts both without patching.
        # Initial signaling wait: poll so we can also notice a quickConn reset
        # that arrives BEFORE any of the three signaling futures fire.  Some
        # firmware (LK.IPC.A001064 with isDTLS=0/enableSdes=1) drops the MQTT
        # session immediately on receiving our DTLS webrtcReq — neither echoes
        # it back nor sends a webrtcResp — and only re-subscribes ~3 s later.
        # Without re-publishing webrtcReq + ICE candidates after the reconnect,
        # the camera silently ignores the original request and we time out.
        _init_done: set = set()
        _init_pending: set = {answer_fut, camera_offer_fut, webrtc_req_echo_fut}
        _init_deadline = asyncio.get_event_loop().time() + timeout
        _init_reconnect_resends = 0
        while asyncio.get_event_loop().time() < _init_deadline:
            _init_remaining = _init_deadline - asyncio.get_event_loop().time()
            _init_done, _init_pending = await asyncio.wait(
                _init_pending,
                timeout=min(1.0, max(0.01, _init_remaining)),
                return_when=asyncio.FIRST_COMPLETED,
            )
            if _init_done:
                break
            if (camera_reconnect_ev.is_set()
                    and _init_reconnect_resends < 2):
                camera_reconnect_ev.clear()
                _init_reconnect_resends += 1
                _status(
                    f"camera quickConn-reset before signaling reply"
                    f" (resend {_init_reconnect_resends})"
                    " — re-sending DTLS webrtcReq + ICE candidates"
                )
                await asyncio.sleep(1.5)   # let camera re-subscribe to MQTT
                outgoing_q.put_nowait((webrtc_req_topic, webrtc_req_payload))
                for _di_p in _dtls_ice_payloads:
                    outgoing_q.put_nowait(_di_p)
        _rr_done, _rr_pending = _init_done, _init_pending

        # Echo-reversal path: echo arrived but no proper response yet.
        # Poll up to 20 s for a real webrtcResp; handle camera quickConn resets
        # by re-sending webrtcReq + ICE candidates so the camera gets a fresh offer.
        # LK.IPC.A001064: SDES path (run before us) poisons its session; camera
        # resets (quickConn=1) on receiving our DTLS webrtcReq, then comes back
        # clean after ~3-5 s.  Re-sending the offer after reconnect gets the
        # camera to respond with its real DTLS answer in ~242 ms.
        _rr_echo_only = False  # True only for cameras that echo but never send a real webrtcResp
        if (webrtc_req_echo_fut in _rr_done
                and answer_fut not in _rr_done
                and camera_offer_fut not in _rr_done):
            _status("webrtcReq echo received — waiting for camera webrtcResp...")
            _rr_secondary_limit = 20.0
            _rr_secondary_deadline = asyncio.get_event_loop().time() + _rr_secondary_limit
            _rr_done2: set = set()
            _rr_pending2 = _rr_pending   # {answer_fut, camera_offer_fut}
            _rr_reconnect_resends = 0
            while asyncio.get_event_loop().time() < _rr_secondary_deadline:
                _remaining = _rr_secondary_deadline - asyncio.get_event_loop().time()
                _rr_done2, _rr_pending2 = await asyncio.wait(
                    _rr_pending2,
                    timeout=min(1.0, max(0.01, _remaining)),
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if _rr_done2:
                    break   # Real response arrived
                # Camera quickConn reset: came back clean, needs a fresh offer.
                if (camera_reconnect_ev.is_set()
                        and _rr_reconnect_resends < 2):
                    camera_reconnect_ev.clear()
                    _rr_reconnect_resends += 1
                    _status(
                        f"camera reconnected during webrtcResp wait"
                        f" (resend {_rr_reconnect_resends})"
                        " — re-sending webrtcReq + ICE candidates"
                    )
                    await asyncio.sleep(1.5)   # let camera re-subscribe
                    outgoing_q.put_nowait((webrtc_req_topic, webrtc_req_payload))
                    for _di_p in _dtls_ice_payloads:
                        outgoing_q.put_nowait(_di_p)
            if _rr_done2:
                # Real response arrived — proceed normally
                _rr_done, _rr_pending = _rr_done2, _rr_pending2
            else:
                # No real webrtcResp in 20 s.  Camera (e.g. LK.IPC.A001064) is
                # likely still in its prior SDES session (SDES webrtcReq was sent
                # before us; camera waits ~25-30 s for a webrtcResp that never
                # comes).  Re-send DTLS webrtcReq now and wait another 20 s;
                # once the SDES session clears the camera answers in ~242 ms.
                _status(
                    "echo-reversal: no real webrtcResp after 20 s"
                    " — re-sending DTLS webrtcReq (camera clearing SDES session)"
                )
                outgoing_q.put_nowait((webrtc_req_topic, webrtc_req_payload))
                for _di_p in _dtls_ice_payloads:
                    outgoing_q.put_nowait(_di_p)

                _rr_ext_limit    = 20.0
                _rr_ext_deadline = asyncio.get_event_loop().time() + _rr_ext_limit
                _rr_done3: set   = set()
                _rr_reconnect_ext = 0
                while asyncio.get_event_loop().time() < _rr_ext_deadline:
                    _ext_rem = _rr_ext_deadline - asyncio.get_event_loop().time()
                    _rr_done3, _rr_pending2 = await asyncio.wait(
                        _rr_pending2,
                        timeout=min(1.0, max(0.01, _ext_rem)),
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    if _rr_done3:
                        break
                    if (camera_reconnect_ev.is_set()
                            and _rr_reconnect_ext < 2):
                        camera_reconnect_ev.clear()
                        _rr_reconnect_ext += 1
                        _status(
                            f"camera reconnected (extended wait, resend {_rr_reconnect_ext})"
                            " — re-sending DTLS webrtcReq"
                        )
                        await asyncio.sleep(1.5)
                        outgoing_q.put_nowait((webrtc_req_topic, webrtc_req_payload))
                        for _di_p in _dtls_ice_payloads:
                            outgoing_q.put_nowait(_di_p)

                if _rr_done3:
                    # Camera finally answered — proceed via normal path
                    _rr_done, _rr_pending = _rr_done3, _rr_pending2
                else:
                    # Still no response after ~40 s total.  Last-resort role-reversal.
                    _rr_echo_only = True
                    _status(
                        "echo-reversal: no real webrtcResp after extended wait"
                        " — role-reversal as last resort"
                    )
                    camera_offer_fut.set_result(webrtc_req_echo_fut.result())
                    _rr_done    = {camera_offer_fut}
                    _rr_pending = _rr_pending2

        for _f in _rr_pending:
            _f.cancel()

        if not _rr_done:
            _status(f"no webrtcResp in {timeout}s")
            outgoing_q.put_nowait(None)
            await pc.close()
            raise RuntimeError(
                f"async_open_webrtc_stream: no webrtcResp received within {timeout}s"
            )

        # Ports from camera counter-offer for synthetic candidate injection.
        # Populated in the role-reversal path below; consumed in the ICE wait loop.
        _rr_cam_ports: list = []  # list of (sdpMid, sdpMLineIndex, port)

        # Stored webrtcResp + ICE candidate payloads for reconnect re-send.
        # Set in the role-reversal block; consumed in the ICE wait loop when the
        # camera sends device/connect (quickConn reconnect) during ICE checking.
        _rr_webrtc_resp_topic:   str  = ""
        _rr_webrtc_resp_payload: str  = ""
        _rr_ice_payloads:        list = []  # list of (topic, json_str) tuples

        if camera_offer_fut in _rr_done and answer_fut not in _rr_done:
            # ---- ROLE REVERSAL path (e.g. LK.IPC.A001064) ---------------------- #
            # Camera sent webrtcReq (its offer) instead of webrtcResp.
            # Protocol: we send webrtcResp (our answer to the camera's counter-offer),
            # then the camera sends its real second webrtcResp (captured in
            # second_answer_fut, ignored here — ICE timing).
            # We call setRemoteDescription NOW using a synthetic answer built from
            # pc.localDescription.sdp (for correct codec PTs) but patched with the
            # camera's own ICE credentials from the counter-offer (so aioice can
            # authenticate the camera's incoming STUN binding requests).
            _status(
                "camera sent webrtcReq (role reversal) — answering and sending webrtcResp"
            )
            # ---- Fingerprint bypass for echo-reversal --------------------------- #
            # The camera echoes our fingerprint in its SDP.  When the camera
            # (DTLS active/client) presents its own self-signed certificate during
            # the handshake, aiortc's _validate_peer_identity would compare the
            # camera's cert digest against our echoed fingerprint → always fails,
            # leaving the DTLS transport in State.FAILED and producing 0 frames.
            #
            # Patch each DTLS transport to overwrite the stored fingerprint with
            # the camera's actual certificate digest so verification always succeeds.
            # This must be applied before the DTLS handshake starts (i.e. before
            # ICE connects), but does NOT require setRemoteDescription first.
            import types as _types
            try:
                from aiortc.rtcdtlstransport import (
                    RTCDtlsFingerprint as _RRFp,
                    certificate_digest as _rr_cert_fp,
                )

                def _rr_accept_cam_cert(self, remote_params):
                    """Accept camera's actual DTLS cert (echo-reversal fingerprint fix)."""
                    try:
                        _cam_cert = self._ssl.get_peer_certificate(
                            as_cryptography=True
                        )
                        if _cam_cert is not None:
                            _real_fp = _rr_cert_fp(_cam_cert, "sha-256")
                            remote_params.fingerprints[:] = [
                                _RRFp(algorithm="sha-256", value=_real_fp)
                            ]
                    except Exception:
                        pass  # cert retrieval failed; skip verification

                for _rr_tc in pc.getTransceivers():
                    _rr_tc.receiver.transport._validate_peer_identity = (
                        _types.MethodType(
                            _rr_accept_cam_cert, _rr_tc.receiver.transport
                        )
                    )
                _status(
                    "role-reversal fingerprint bypass applied"
                    f" ({len(pc.getTransceivers())} transceivers)"
                )
            except Exception as _rr_fp_exc:
                _status(
                    f"role-reversal fingerprint bypass skipped: {_rr_fp_exc}"
                )
            # ---- Early setRemoteDescription from camera's counter-offer ---------- #
            # The camera starts STUN probing as soon as it receives our webrtcResp +
            # iceCandidateReq.  If we wait for second_answer_fut (up to 8 s) before
            # calling setRemoteDescription, the camera's initial binding checks may
            # expire before aiortc's ICE agent starts — leaving ICE stuck in
            # "checking" indefinitely.  Instead, call setRemoteDescription NOW with
            # a synthetic answer (built from our local offer but with the camera's
            # ICE credentials injected).  aiortc enters ICE "checking" immediately;
            # when the camera's STUN probes arrive after iceCandidateReq, aioice
            # creates peer-reflexive candidates and ICE connects.
            import re as _rr_re
            # Extract camera's ICE credentials from its counter-offer.
            # Observed behaviour for LK.IPC.A001064: the camera echoes our ICE
            # credentials exactly (ufrag/pwd are identical in both the counter-offer
            # and the real second answer).  The substitution below is therefore a
            # no-op in practice for this model, but is kept for correctness in case
            # a future firmware version uses its own credentials.  Without the
            # substitution, any camera that does generate different credentials would
            # cause every STUN probe to fail auth → ICE stuck checking.
            _cam_counter_sdp = (camera_offer_fut.result() or {}).get("sdp", "")
            _cam_ice_ufrag: str | None = None
            _cam_ice_pwd:   str | None = None
            _rr_cm_idx = -1
            for _rr_cln in _cam_counter_sdp.splitlines():
                if _rr_cln.startswith("a=ice-ufrag:") and _cam_ice_ufrag is None:
                    _cam_ice_ufrag = _rr_cln.strip()
                if _rr_cln.startswith("a=ice-pwd:") and _cam_ice_pwd is None:
                    _cam_ice_pwd = _rr_cln.strip()
                # Collect ports from the camera counter-offer m-lines for later
                # synthetic candidate injection (cam-IP + echoed port).
                if _rr_cln.startswith("m="):
                    _rr_cm_idx += 1
                    _rr_pm = _rr_re.match(r'm=\S+ (\d+)', _rr_cln)
                    if _rr_pm:
                        _rr_cp = int(_rr_pm.group(1))
                        if _rr_cp != 0 and _rr_cm_idx <= 1:
                            _rr_cam_ports.append((str(_rr_cm_idx), _rr_cm_idx, _rr_cp))
            # Use pc.localDescription.sdp (the unpatched aiortc offer) as the
            # synthetic answer base so the codec list matches aiortc's internal state
            # (VP8/H264 PT=97-102 for all m-sections, no PT=103=H265).
            _rr_synth_sdp = pc.localDescription.sdp
            _rr_synth_sdp = _normalize_bundle_ice_credentials(_rr_synth_sdp)
            # Strip our own local ICE candidates — they are useless as "remote"
            # candidates for the answer.  aioice will discover peer-reflexive
            # candidates when the camera probes after iceCandidateReq.
            _rr_synth_sdp = _rr_re.sub(
                r'a=candidate:[^\r\n]*\r?\n', '', _rr_synth_sdp
            )
            _rr_synth_sdp = (
                _rr_synth_sdp
                .replace('a=end-of-candidates\r\n', '')
                .replace('a=end-of-candidates\n', '')
            )
            # Strip local SSRC lines — they belong to our own transceivers and must
            # not appear as remote sender SSRCs.  Removing them lets aiortc accept
            # incoming RTP from the camera regardless of its actual SSRC.
            _rr_synth_sdp = _rr_re.sub(r'a=ssrc(?:-group)?:[^\r\n]*\r?\n', '', _rr_synth_sdp)
            # Replace our local ICE credentials with the camera's so aioice
            # authenticates the camera's STUN probes correctly.
            if _cam_ice_ufrag:
                _rr_synth_sdp = _rr_re.sub(
                    r'a=ice-ufrag:[^\r\n]*', _cam_ice_ufrag, _rr_synth_sdp
                )
            if _cam_ice_pwd:
                _rr_synth_sdp = _rr_re.sub(
                    r'a=ice-pwd:[^\r\n]*', _cam_ice_pwd, _rr_synth_sdp
                )
            # Camera sends media to us → its answer direction is sendonly.
            _rr_synth_sdp = _rr_synth_sdp.replace('a=recvonly\r\n', 'a=sendonly\r\n')
            # DTLS setup role depends on whether the camera is echo-only or real-reversal.
            # Echo-only (e.g. LK.IPC.A001064): camera never sends its own webrtcResp, so
            # we cannot know its DTLS preference.  We declare setup:passive in our
            # webrtcResp, making the camera DTLS active/ICE-controlling.  The camera then
            # allocates a TURN relay and sends iceCandidateReq → ICE connects via relay.
            # Tell aiortc the remote is DTLS active so aiortc becomes passive/server.
            # RFC 5763: remote=active → local=passive (server).
            #
            # Real role-reversal (camera sent setup:passive in its second webrtcResp):
            # we send setup:active so we are DTLS client and initiate the ClientHello.
            # Tell aiortc the remote is passive so aiortc becomes active/client.
            # RFC 5763: remote=passive → local=active (client).
            _rr_synth_sdp = _rr_synth_sdp.replace(
                'a=setup:actpass\r\n',
                'a=setup:active\r\n' if _rr_echo_only else 'a=setup:passive\r\n'
            )
            try:
                await pc.setRemoteDescription(
                    RTCSessionDescription(sdp=_rr_synth_sdp, type="answer")
                )
                _status(
                    "role-reversal: setRemoteDescription from counter-offer"
                    " — ICE now checking"
                )
            except Exception as _rr_srd_exc:
                _status(
                    f"role-reversal: early setRemoteDescription failed:"
                    f" {_rr_srd_exc}"
                )
                outgoing_q.put_nowait(None)
                await pc.close()
                raise RuntimeError(
                    f"async_open_webrtc_stream: setRemoteDescription failed:"
                    f" {_rr_srd_exc}"
                ) from _rr_srd_exc
            # Pre-seed cam_ip_q with camera IP from user info (fallback if setDevAttrNotif
            # doesn't arrive).  Must be done after _rr_cam_ports is populated and after
            # setRemoteDescription so aiortc is in ICE "checking" state when the ICE wait
            # loop picks up the candidate and calls addIceCandidate.
            #
            # IMPORTANT: Skip for echo-only cameras.  In echo-only mode the camera's
            # "counter-offer" is our own echoed webrtcReq, so _rr_cam_ports contains our
            # aiortc-allocated ports (e.g. 60705/47324), not the camera's listening ports.
            # Injecting synthetic host candidates as {camera_IP}:{our_port} sends STUN
            # probes to an address the camera never listens on, consuming the full ICE
            # timeout with no hope of success.  Instead rely on:
            #   1. Arnoo TURN relay (already appended to _ice_servers when no TURN in
            #      getIceConfigResp) — lets the camera reach us via relay.
            #   2. second_answer_fut candidates (processed in ICE wait loop below) if the
            #      camera sends a real webrtcResp after receiving our webrtcResp.
            if _cam_local_ip and _rr_cam_ports and cam_ip_q.empty() and not _rr_echo_only:
                cam_ip_q.put_nowait(_cam_local_ip)
                _status(f"pre-seeded cam_ip_q from user-info IP: {_cam_local_ip}")
            elif _rr_echo_only and _rr_cam_ports:
                _status(
                    f"echo-only: skipping cam_ip_q pre-seed"
                    f" (echo ports are ours: {[p for _, _, p in _rr_cam_ports]})"
                    f" — relying on TURN relay and second_answer_fut candidates"
                )

            # Send webrtcResp so the camera knows our DTLS fingerprint and ICE params.
            # setup value is role-dependent (see comment above the synth-SDP replace):
            #   echo-only  → setup:passive (we are DTLS server; camera is DTLS client/
            #                               ICE-controlling; camera allocates relay and
            #                               sends iceCandidateReq → ICE via TURN relay)
            #   real-reversal → setup:active (we initiate DTLS ClientHello after ICE)
            # aiortc generates SDPs with \r\n so a simple replace is safe here.
            _rr_setup_val = "passive" if _rr_echo_only else "active"
            _rr_answer_sdp = _normalize_bundle_ice_credentials(
                pc.localDescription.sdp.replace(
                    "a=setup:actpass\r\n", f"a=setup:{_rr_setup_val}\r\n"
                )
            )
            _webrtc_resp_topic   = f"iot/v1/s/{user_id}/IPC/webrtcResp"
            _webrtc_resp_payload = json.dumps({
                "method":  "webrtcResp",
                "service": "IPC",
                "devId":   device_id,
                "srcAddr": f"0.{user_id}",
                "seq":     _seq(),
                "tst":     int(time.time() * 1000),
                **( {"userId": _numeric_uid_raw} if _numeric_uid_raw is not None else {} ),
                "payload": {
                    "peerid":  peer_id,
                    "devId":   device_id,
                    "answer":  {"type": "answer", "sdp": _rr_answer_sdp},
                    "trackId": 0,
                    "dstAddr": device_id,
                    # wPayload mirrors the webrtcReq format.  Newer firmware
                    # (e.g. LK.IPC.A001064) parses wPayload.answer.sdp to
                    # extract our ICE credentials and candidates; without this
                    # the camera cannot form valid STUN binding requests and
                    # never initiates ICE connectivity checks → ICE closed.
                    "wPayload": {
                        "peerid": peer_id,
                        "answer": {"type": "answer", "sdp": _rr_answer_sdp},
                    },
                },
            })
            outgoing_q.put_nowait((_webrtc_resp_topic, _webrtc_resp_payload))
            # Save for potential reconnect re-send in the ICE wait loop.
            _rr_webrtc_resp_topic   = _webrtc_resp_topic
            _rr_webrtc_resp_payload = _webrtc_resp_payload
            _status(f"webrtcResp sent (role-reversal answer, setup={_rr_setup_val})")

            # Re-announce ALL our gathered ICE candidates (host + srflx/prflx) after
            # sending webrtcResp.  The @pc.on("icecandidate") callbacks fired during
            # ICE gathering (possibly before the camera's MQTT session was ready to
            # process them).  We resend here to ensure the camera sees every candidate
            # at the right time so it can initiate STUN checks against us.
            #
            # Key fix: the previous version only sent the first private-LAN host
            # candidate (e.g. 192.168.1.175), which is unreachable from a remote
            # camera.  We now send ALL gathered candidates including server-reflexive
            # ones (e.g. 72.84.199.230 public IP) so a remote camera can reach us
            # even when NAT traversal without TURN is possible.
            _rr_local_sdp  = pc.localDescription.sdp
            _rr_ice_topic  = f"iot/v1/s/{user_id}/IPC/iceCandidateReq"
            _rr_cand_count = 0
            _rr_cur_midx   = -1
            for _rr_ln in _rr_re.split(r'\r?\n', _rr_local_sdp):
                if _rr_ln.startswith('m='):
                    _rr_cur_midx += 1
                    if _rr_cur_midx > 1:   # only mid:0 audio, mid:1 video (skip mid:2 datachannel)
                        break
                elif _rr_ln.startswith('a=candidate:') and _rr_cur_midx >= 0:
                    # Skip loopback candidates (unreachable from any remote peer).
                    _rr_cip_m = _rr_re.search(
                        r'a=candidate:\S+ \d+ \w+ \d+ (\S+)', _rr_ln
                    )
                    if _rr_cip_m:
                        _rr_cip = _rr_cip_m.group(1)
                        if _rr_cip.startswith('127.') or _rr_cip == '::1':
                            continue
                    # Convert SDP attribute form (a=candidate:...) to MQTT form
                    # (candidate:...) — the leading "a=" is an SDP-layer decoration.
                    _rr_cand_str = 'candidate:' + _rr_ln.split('a=candidate:', 1)[-1]
                    _rr_cand_obj = {
                        "candidate":     _rr_cand_str,
                        "sdpMid":        str(_rr_cur_midx),
                        "sdpMLineIndex": _rr_cur_midx,
                    }
                    _rr_ice_json = json.dumps({
                        "method":  "iceCandidateReq",
                        "service": "IPC",
                        "devId":   device_id,
                        "srcAddr": f"0.{user_id}",
                        "seq":     _seq(),
                        "tst":     int(time.time() * 1000),
                        **( {"userId": _numeric_uid_raw} if _numeric_uid_raw is not None else {} ),
                        "payload": {
                            "dstAddr": device_id,
                            "wPayload": {
                                "peerid":    peer_id,
                                "candidate": _rr_cand_obj,
                            },
                            "peerid":    peer_id,
                            "devId":     device_id,
                            "candidate": _rr_cand_obj,
                        },
                    })
                    outgoing_q.put_nowait((_rr_ice_topic, _rr_ice_json))
                    _rr_ice_payloads.append((_rr_ice_topic, _rr_ice_json))
                    _rr_cand_count += 1
            _status(
                f"iceCandidateReq sent (role-reversal, post-webrtcResp,"
                f" {_rr_cand_count} candidates)"
            )

        else:
            # ---- NORMAL path: camera sent webrtcResp ---------------------------- #
            answer   = answer_fut.result()
            _ans_sdp = answer["sdp"]
            _ans_mlines = [ln for ln in _ans_sdp.splitlines() if ln.startswith("m=")]
            _status(
                f"webrtcResp received — m=video={_sdp_transport(_ans_sdp, 'video')}"
                f"  m=audio={_sdp_transport(_ans_sdp, 'audio')}"
            )
            _status("Answer m-sections (%d): %s" % (len(_ans_mlines), " | ".join(_ans_mlines)))
            # Log negotiated direction per m-section so we can see whether
            # camera renegotiated audio sendrecv→sendonly (or kept sendrecv).
            # Also expose ssrc/msid lines — useful when diagnosing why media
            # doesn't flow even though signaling completes.
            try:
                _ans_dirs = []
                _cur_mid = None
                for _ln in _ans_sdp.splitlines():
                    if _ln.startswith("m="):
                        _cur_mid = _ln.split()[0][2:]  # "audio", "video", "application"
                    elif _ln.startswith("a=mid:"):
                        _cur_mid = f"{_cur_mid}/mid={_ln[6:]}"
                    elif _ln in ("a=sendrecv", "a=sendonly", "a=recvonly", "a=inactive"):
                        _ans_dirs.append(f"{_cur_mid}={_ln[2:]}")
                _status(f"Answer m-section directions: {_ans_dirs}")
            except Exception as _ans_dir_exc:
                _status(f"Answer m-section direction log failed: {_ans_dir_exc}")

            # ---- Fingerprint placeholder + bypass -------------------------------- #
            # A001064 (and family) returns answer SDP with empty
            # ``a=fingerprint:sha-256 `` lines (template not filled in by the
            # camera's compressed-answer codepath; behaviour is identical
            # whether we send a compressed or uncompressed offer in
            # wPayload).  aiortc's SDP parser then fails at the empty value
            # with "not enough values to unpack".  Substitute a placeholder
            # 32-byte zero fingerprint so the parse succeeds, then patch
            # _validate_peer_identity on each DTLS transport so the actual
            # camera certificate is accepted at handshake time (same pattern
            # used in the role-reversal branch above).  This is safe because
            # the MQTT signaling channel is already authenticated; cert
            # pinning here would add no extra security.
            import re as _fp_re
            _ZERO_FP = ":".join(["00"] * 32)
            _ans_sdp_patched, _fp_subs = _fp_re.subn(
                r'(?m)^(a=fingerprint:sha-256)\s*$',
                rf'\1 {_ZERO_FP}',
                _ans_sdp,
            )
            if _fp_subs:
                _status(
                    f"answer SDP: filled in {_fp_subs} empty"
                    " a=fingerprint:sha-256 line(s) with placeholder"
                )
                _ans_sdp = _ans_sdp_patched

            # ---- Rebuild answer m-sections to match offer's mid+kind ------------ #
            # A001064 firmware violates RFC 3264 §6 in three observed ways:
            #   1. Drops rejected m-sections entirely instead of port=0.
            #   2. Replaces a rejected section with a different KIND (e.g.
            #      datachannel → second video for H265).
            #   3. Adds m-sections for kinds we never offered (e.g. extra
            #      H265 video at mid:2 when offer was audio+video only).
            # aiortc enforces strict count + kind match.  Rebuild the answer
            # by walking the offer's mid order: for each offer mid take the
            # answer's matching same-kind section if present, otherwise
            # synthesise a rejected (port=0) stub.  Answer mids not in the
            # offer are dropped.  Result has exactly the same mid order +
            # kind sequence as the offer.
            # Use _offer_sdp (the sent offer with injected H265 mid:2 + DC mid:3)
            # to drive the rebuild, NOT pc.localDescription.sdp which only has
            # 3 sections (audio/H264/DC at mids 0/1/2 without H265).  This gives
            # _offer_mids=['0','1','2','3'] matching the camera's 4-section answer.
            _offer_mids: list = []
            _offer_kinds: dict = {}
            _cur_kind: str = ""
            for _ln in _offer_sdp.splitlines():
                if _ln.startswith("m="):
                    _cur_kind = _ln.split(" ", 1)[0][2:]   # audio/video/application
                elif _ln.startswith("a=mid:"):
                    _mid = _ln[len("a=mid:"):].strip()
                    _offer_mids.append(_mid)
                    _offer_kinds[_mid] = _cur_kind

            # Split answer into header (pre-first-m=) + per-section blocks.
            # Each section block runs from its m= line through the line
            # before the next m= (or end-of-SDP).
            def _first_attr(_sdp: str, _attr: str) -> str:
                for _ln2 in _sdp.splitlines():
                    if _ln2.startswith(_attr):
                        return _ln2
                return ""
            _ice_ufrag_ln = _first_attr(_ans_sdp, "a=ice-ufrag:")
            _ice_pwd_ln   = _first_attr(_ans_sdp, "a=ice-pwd:")
            _fp_ln        = _first_attr(_ans_sdp, "a=fingerprint:")
            _setup_ln     = _first_attr(_ans_sdp, "a=setup:")

            _ans_lines = _ans_sdp.splitlines()
            _ans_sections: dict = {}      # mid → list[str] of section's lines
            _ans_header: list = []
            _cur_block: list = []
            _cur_mid: str = ""
            _cur_block_kind: str = ""
            _seen_first_m = False
            def _flush():
                if _cur_block and _cur_mid:
                    _ans_sections[_cur_mid] = (_cur_block_kind, list(_cur_block))
            for _ln in _ans_lines:
                if _ln.startswith("m="):
                    _flush()
                    _seen_first_m = True
                    _cur_block = [_ln]
                    _cur_mid = ""
                    _cur_block_kind = _ln.split(" ", 1)[0][2:]
                elif not _seen_first_m:
                    _ans_header.append(_ln)
                else:
                    _cur_block.append(_ln)
                    if _ln.startswith("a=mid:"):
                        _cur_mid = _ln[len("a=mid:"):].strip()
            _flush()

            def _stub(_m: str, _kind: str) -> list:
                if _kind == "application":
                    # Synthesize a VALID m=application section so aiortc's SCTP
                    # transport can start.  Camera (KVS firmware) answers mid:2
                    # with m=video H265 instead of m=application but always
                    # opens SCTP on port 5000 regardless.  Without these attrs
                    # aiortc crashes in serialize_packet (port=None).
                    # port=9 per RFC 8842 = "use sctp-port".
                    _hdr = "m=application 9 UDP/DTLS/SCTP webrtc-datachannel"
                    _block = [_hdr, "c=IN IP4 0.0.0.0", f"a=mid:{_m}"]
                    for _x in (_ice_ufrag_ln, _ice_pwd_ln, _fp_ln, _setup_ln):
                        if _x:
                            _block.append(_x)
                    _block.append("a=sctp-port:5000")
                    _block.append("a=max-message-size:262144")
                    return _block
                if _kind == "audio":
                    _hdr = "m=audio 0 UDP/TLS/RTP/SAVPF 0"
                else:
                    # PT=0 (PCMU/audio) in a video stub causes aiortc to fail
                    # "Failed to set remote video description send parameters"
                    # because PT=0 is not in aiortc's video codec registry.
                    # PT=97 is always in aiortc's video codec list (VP8 or H264
                    # variant) and satisfies codec lookup for a rejected section.
                    _hdr = "m=video 0 UDP/TLS/RTP/SAVPF 97"
                _block = [_hdr, "c=IN IP4 0.0.0.0", f"a=mid:{_m}"]
                for _x in (_ice_ufrag_ln, _ice_pwd_ln, _fp_ln, _setup_ln):
                    if _x:
                        _block.append(_x)
                # aiortc's __validate_description requires a=rtcp-mux in every
                # m-section that appears in the answer when the offer had it.
                # Our offer always includes a=rtcp-mux; stub sections must echo
                # it or setRemoteDescription raises "RTCP mux is not enabled".
                _block.append("a=rtcp-mux")
                _block.append("a=inactive")
                return _block

            # PTs we assigned to H265 in _replace_mid2_codecs_with_h265.
            # If the camera answers a video section using only these PTs,
            # aiortc fails with "Failed to set remote video description send
            # parameters" because H265 is not in its codec registry.  Stub
            # those sections so aiortc sees port=0/inactive for H265 — we
            # still benefit from the camera negotiating H265 (it proves the
            # 4-section BUNDLE is aligned) but we only decode H264 and audio.
            _h265_offer_pts: set = set()  # H265 no longer offered; camera won't answer H265 PTs

            _rebuilt: list = list(_ans_header)
            _kept_count = 0
            _stub_count = 0
            _dropped_mids: list = []
            _rejected_mids: set = set()  # mids whose stub has port=0 (excluded from BUNDLE)
            for _m in _offer_mids:
                _expected_kind = _offer_kinds[_m]
                _ans_kind, _ans_block = _ans_sections.get(_m, ("", []))
                # Force-stub H265 sections: detect by camera's answer m-line
                # using only our H265 PTs (103/104).
                _ans_h265 = False
                if _ans_block and _ans_kind == "video":
                    for _al in _ans_block:
                        if _al.startswith("m="):
                            _pts = set(_al.split()[3:])
                            if _pts and _pts.issubset(_h265_offer_pts):
                                _ans_h265 = True
                            break
                if _ans_h265:
                    _s = _stub(_m, _expected_kind)
                    _rebuilt.extend(_s)
                    _stub_count += 1
                    if _s and _s[0].split()[1] == '0':
                        _rejected_mids.add(_m)
                elif _ans_block and _ans_kind == _expected_kind:
                    _rebuilt.extend(_ans_block)
                    _kept_count += 1
                else:
                    _s = _stub(_m, _expected_kind)
                    _rebuilt.extend(_s)
                    _stub_count += 1
                    if _s and _s[0].split()[1] == '0':
                        _rejected_mids.add(_m)
            for _ans_mid in _ans_sections:
                if _ans_mid not in _offer_kinds:
                    _dropped_mids.append(_ans_mid)

            if _stub_count or _dropped_mids:
                _status(
                    f"answer SDP rebuilt: kept={_kept_count}"
                    f" stubbed={_stub_count} dropped={_dropped_mids}"
                    f" (offer mids={_offer_mids})"
                    + (f" rejected_from_bundle={sorted(_rejected_mids)}" if _rejected_mids else "")
                )

            # Fix a=group:BUNDLE: use offer mid order but exclude port=0 (rejected)
            # stubs.  RFC 8843 prohibits rejected m-sections in BUNDLE; aiortc
            # raises "Failed to set remote video description send parameters"
            # when a port=0 section is in the BUNDLE group.
            _bundle_mids = [m for m in _offer_mids if m not in _rejected_mids]
            _rebuilt2: list = []
            _bundle_replaced = False
            for _ln in _rebuilt:
                if _ln.startswith("a=group:BUNDLE") and not _bundle_replaced:
                    _rebuilt2.append("a=group:BUNDLE " + " ".join(_bundle_mids))
                    _bundle_replaced = True
                else:
                    _rebuilt2.append(_ln)
            _ans_sdp = "\r\n".join(_rebuilt2) + "\r\n"

            # Apply DTLS cert bypass — always, whenever we patched
            # fingerprints (camera's empty-fingerprint quirk applies on
            # every webrtcResp from this firmware family).
            if _fp_subs:
                import types as _np_types
                try:
                    from aiortc.rtcdtlstransport import (
                        RTCDtlsFingerprint as _NPFp,
                        certificate_digest as _np_cert_fp,
                    )

                    def _np_accept_cam_cert(self, remote_params):
                        try:
                            _cam_cert = self._ssl.get_peer_certificate(
                                as_cryptography=True
                            )
                            if _cam_cert is not None:
                                _real_fp = _np_cert_fp(_cam_cert, "sha-256")
                                remote_params.fingerprints[:] = [
                                    _NPFp(algorithm="sha-256", value=_real_fp)
                                ]
                        except Exception:
                            pass

                    # Diag: log PC/ICE state at patch-application time so we
                    # can see whether DTLS handshake has *already* started by
                    # the time we install the bypass (some aiortc versions
                    # kick off DTLS during setRemoteDescription itself).
                    _status(
                        "fingerprint bypass: pre-patch"
                        f" pc.connectionState={pc.connectionState}"
                        f" pc.iceConnectionState={pc.iceConnectionState}"
                    )
                    for _np_idx, _np_tc in enumerate(pc.getTransceivers()):
                        _np_dtls = _np_tc.receiver.transport
                        _np_ice = _np_dtls.transport
                        _np_pre_vpi = getattr(
                            getattr(
                                _np_dtls, "_validate_peer_identity", None
                            ),
                            "__qualname__",
                            "missing",
                        )
                        _status(
                            f"  patch[{_np_idx}] id(dtls)={id(_np_dtls)}"
                            f" id(ice)={id(_np_ice)}"
                            f" dtls.state={getattr(_np_dtls, 'state', '?')}"
                            f" ice.state={getattr(_np_ice, 'state', '?')}"
                            f" pre.vpi={_np_pre_vpi}"
                        )
                        _np_dtls._validate_peer_identity = (
                            _np_types.MethodType(_np_accept_cam_cert, _np_dtls)
                        )
                        _np_post_vpi = getattr(
                            getattr(
                                _np_dtls, "_validate_peer_identity", None
                            ),
                            "__qualname__",
                            "missing",
                        )
                        _status(f"  patch[{_np_idx}] post.vpi={_np_post_vpi}")
                    _status(
                        "fingerprint bypass applied"
                        f" ({len(pc.getTransceivers())} transceivers)"
                    )
                except Exception as _np_fp_exc:
                    _status(f"fingerprint bypass skipped: {_np_fp_exc}")

            # Strip H265 from the answer before giving to aiortc.  aiortc manages
            # only 3 sections (audio/H264/DC at mids 0/1/2); any H265 stub causes
            # OperationError regardless of PT or direction.  The _inject_h265_section
            # pipeline added H265 as mid:2 and shifted DC to mid:3 in the SENT offer.
            # Here we reverse that for aiortc: drop mid:2 (H265 stub, port=0) and
            # rename mid:3 (DC) → mid:2 so aiortc sees the 3 sections it knows.
            import re as _re_h265_strip
            def _aiortc_answer(sdp: str) -> str:
                """Produce a 3-section answer SDP for aiortc (audio/H264/DC).

                aiortc has 3 transceivers: audio(mid:0), H264(mid:1), DC(mid:2).
                The full rebuild may have fewer sections (camera only answered
                audio+H264; H265 was stubbed/rejected from BUNDLE; DC was stripped
                from the sent offer).  This function:
                  1. Strips any H265 stubs (port=0 video).
                  2. Renames DC mid:3 → mid:2 if present (legacy path).
                  3. If no DC section exists, synthesises one using the camera's
                     ICE credentials so aiortc can bring up the SCTP transport.
                  4. Ensures a=group:BUNDLE includes mids 0, 1, 2.
                """
                _lines2 = _re_h265_strip.split(r'\r?\n', sdp)
                _secs2, _cur2 = [], []
                for _l2 in _lines2:
                    if _l2.startswith('m=') and _cur2:
                        _secs2.append(_cur2); _cur2 = [_l2]
                    else:
                        _cur2.append(_l2)
                if _cur2: _secs2.append(_cur2)
                _out2: list[str] = []
                _has_dc = False
                for _sec2 in _secs2:
                    if _sec2 and _sec2[0].startswith('m=video') and _sec2[0].split()[1] == '0':
                        continue  # strip H265 stub
                    if _sec2 and _sec2[0].startswith('m=application'):
                        _has_dc = True
                    # Rename DC mid:3 → mid:2 (if DC present from 4-section rebuild)
                    _out2.extend('a=mid:2' if _l2.rstrip() == 'a=mid:3' else _l2 for _l2 in _sec2)
                if not _has_dc:
                    # Synthesise DC stub for aiortc's DC transceiver (mid:2).
                    # Use camera's ICE credentials so the SCTP handshake succeeds.
                    _dc_stub = [
                        'm=application 9 UDP/DTLS/SCTP webrtc-datachannel',
                        'c=IN IP4 0.0.0.0',
                        'a=mid:2',
                    ]
                    for _x2 in (_ice_ufrag_ln, _ice_pwd_ln, _fp_ln, _setup_ln):
                        if _x2: _dc_stub.append(_x2)
                    _dc_stub.extend(['a=sctp-port:5000', 'a=max-message-size:262144'])
                    _out2.extend(_dc_stub)
                sdp2 = '\r\n'.join(_out2)
                # Ensure BUNDLE includes 0, 1, 2.
                if 'a=group:BUNDLE' in sdp2:
                    sdp2 = _re_h265_strip.sub(
                        r'a=group:BUNDLE [0-9 ]+',
                        'a=group:BUNDLE 0 1 2',
                        sdp2, count=1,
                    )
                return sdp2

            _aiortc_sdp = _aiortc_answer(_ans_sdp)

            try:
                await pc.setRemoteDescription(
                    RTCSessionDescription(
                        sdp=_aiortc_sdp,
                        type=answer.get("type", "answer"),
                    )
                )
                # Diag: per-transceiver DTLS/ICE state immediately after
                # setRemoteDescription returns.  If dtls.state already !=
                # "new" here, aiortc has kicked off DTLS handshake on the
                # setRemoteDescription call itself — meaning our patch
                # (applied above) ran before, but any handshake that
                # already failed earlier wouldn't show that here either.
                try:
                    for _srd_idx, _srd_tc in enumerate(
                        pc.getTransceivers()
                    ):
                        _srd_dtls = _srd_tc.receiver.transport
                        _srd_ice = _srd_dtls.transport
                        _srd_vpi = getattr(
                            getattr(
                                _srd_dtls, "_validate_peer_identity", None
                            ),
                            "__qualname__",
                            "missing",
                        )
                        # Log id() of dtls/ice transports per transceiver:
                        # if BUNDLE merged correctly, all transceivers share
                        # the SAME RTCDtlsTransport + RTCIceTransport
                        # objects.  Different ids ⇒ BUNDLE failed and aiortc
                        # is running parallel transports — RTP would arrive
                        # on whichever transport's DTLS is up but the
                        # decoder receivers may be bound to the other one.
                        _srd_kind = getattr(
                            getattr(_srd_tc, "receiver", None),
                            "_kind",
                            getattr(_srd_tc, "kind", "?"),
                        )
                        _srd_mid = getattr(_srd_tc, "mid", "?")
                        _status(
                            f"  post-SRD[{_srd_idx}]"
                            f" mid={_srd_mid} kind={_srd_kind}"
                            f" dtls.id=0x{id(_srd_dtls):x}"
                            f" ice.id=0x{id(_srd_ice):x}"
                            f" dtls.state={getattr(_srd_dtls, 'state', '?')}"
                            f" ice.state={getattr(_srd_ice, 'state', '?')}"
                            f" vpi={_srd_vpi}"
                        )
                except Exception as _srd_diag_exc:
                    _status(f"  post-SRD diag failed: {_srd_diag_exc}")

                # --- Manual iceCandidateReq trickle (DTLS path) ----------- #
                # The official Android app sends iceCandidateReq for every local
                # ICE candidate AFTER receiving webrtcResp.  The camera waits
                # for this trickle, and tears down the DTLS session if it never
                # arrives — even when the same candidates are present in the
                # SDP offer's a=candidate lines.  aiortc gathers candidates
                # synchronously during setLocalDescription so the @pc.on(
                # "icecandidate") hook above never fires (vanilla-ICE);
                # parse pc.localDescription.sdp directly and publish each.
                try:
                    import re as _re_lc
                    _lsdp = (
                        pc.localDescription.sdp if pc.localDescription
                        else ""
                    )
                    _cur_mid: str | None = None
                    _cur_idx: int = -1
                    _sent_n = 0
                    for _ln in _lsdp.splitlines():
                        if _ln.startswith("m="):
                            _cur_idx += 1
                            _cur_mid = None
                            continue
                        _mid_m = _re_lc.match(r'^a=mid:(\S+)', _ln)
                        if _mid_m:
                            _cur_mid = _mid_m.group(1)
                            continue
                        _cand_m = _re_lc.match(r'^a=candidate:(.+)$', _ln)
                        if not _cand_m or _cur_mid is None:
                            continue
                        _cand_str = "candidate:" + _cand_m.group(1).strip()
                        # Skip Docker bridge / CGNAT / IPv6 — same filters as
                        # the dead @pc.on("icecandidate") handler above.
                        _cand_ip_m = _re_lc.search(
                            r'\s(\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)\s\d+\s+typ\s',
                            _cand_str,
                        )
                        _cand_ip = _cand_ip_m.group(1) if _cand_ip_m else ""
                        if (_cand_ip.startswith("172.17.")
                                or _cand_ip.startswith("100.")
                                or ':' in _cand_ip):
                            continue
                        _cand_obj = {
                            "candidate":     _cand_str,
                            "sdpMid":        _cur_mid,
                            "sdpMLineIndex": _cur_idx,
                        }
                        _ic_payload = json.dumps({
                            "method":  "iceCandidateReq",
                            "service": "IPC",
                            "devId":   device_id,
                            "srcAddr": f"0.{user_id}",
                            "seq":     _seq(),
                            "tst":     int(time.time() * 1000),
                            **( {"userId": _numeric_uid_raw}
                                if _numeric_uid_raw is not None else {} ),
                            "payload": {
                                "dstAddr": device_id,
                                "wPayload": {
                                    "peerid":    peer_id,
                                    "candidate": _cand_obj,
                                },
                                "peerid":    peer_id,
                                "devId":     device_id,
                                "candidate": _cand_obj,
                            },
                        })
                        outgoing_q.put_nowait((ice_cand_topic, _ic_payload))
                        _sent_n += 1
                    _status(
                        f"iceCandidateReq trickle (post-SRD): {_sent_n} candidate(s)"
                        f" sent from local SDP"
                    )
                except Exception as _trickle_exc:
                    _status(f"  manual iceCandidateReq trickle failed: {_trickle_exc}")
            except Exception as exc:
                # Dump full SDP and traceback so we can pinpoint where aiortc
                # is choking (the {exc} message alone — e.g. "not enough
                # values to unpack" — does not identify the offending line).
                import traceback as _tb_dtls
                _LOGGER.warning(
                    "setRemoteDescription failed: %s\n--- camera answer SDP ---\n%s\n--- traceback ---\n%s",
                    exc, _ans_sdp, _tb_dtls.format_exc(),
                )
                _status(f"setRemoteDescription failed: {exc}")
                outgoing_q.put_nowait(None)
                await pc.close()
                raise RuntimeError(
                    f"async_open_webrtc_stream: setRemoteDescription failed: {exc}"
                ) from exc

            # --- Inbound-datagram byte-tap (diagnostic) -------------------- #
            # Discriminates between "camera is silent until close_notify" vs
            # "camera is sending SRTP / DTLS / STUN we're failing to handle".
            # First byte tells the story:
            #   0x00-0x03 = STUN  (binding req/resp, consent, etc.)
            #   0x14-0x17 = DTLS records (0x15 = alert, e.g. close_notify)
            #   0x80-0xBF = RTP/RTCP/SRTP/SRTCP
            # Wrap each protocol's datagram_received on the live aioice
            # Connection.  Includes monotonic timestamp so we can correlate
            # against aiortc's untimestamped DEBUG transitions.
            try:
                import time as _bt_time
                _bt_start = _bt_time.monotonic()
                _ice_xport = pc.getTransceivers()[0].receiver.transport.transport
                _aio_conn  = getattr(_ice_xport, "_connection", None)
                _bt_protos = (
                    list(getattr(_aio_conn, "_protocols", []) or [])
                    if _aio_conn is not None else []
                )

                def _make_bt_tap(_orig_dr, _label):
                    def _tap(data, addr):
                        _dt = _bt_time.monotonic() - _bt_start
                        try:
                            _h8 = data[:8].hex() if data else ""
                        except Exception:
                            _h8 = "?"
                        try:
                            _status(
                                f"RX {_label} t+{_dt:.3f}s {len(data)}B"
                                f" from={addr} hex={_h8}"
                            )
                        except Exception:
                            pass
                        return _orig_dr(data, addr)
                    return _tap

                for _bp_idx, _bp in enumerate(_bt_protos):
                    _orig = _bp.datagram_received
                    _bp.datagram_received = _make_bt_tap(_orig, f"p{_bp_idx}")
                _status(
                    f"byte-tap installed on {len(_bt_protos)} aioice protocol(s)"
                )
            except Exception as _bt_install_exc:
                _status(f"byte-tap install failed: {_bt_install_exc}")

            # --- DTLS-decrypted-data tap (Path B diagnostic) -------------- #
            # Camera sends DTLS application_data (0x17) records post-handshake
            # that we don't understand.  aiortc decrypts them via OpenSSL then
            # routes plaintext to RTCDtlsTransport._data_receiver._handle_data.
            # We attach a logging shim so the next log shows the actual decrypted
            # payload (first ~64 bytes hex) — this discriminates between SCTP
            # INIT chunks (KVS firmware always opens SCTP) and proprietary
            # Leedarson control messages.
            try:
                import time as _ddt_time

                class _LoggingDataReceiver:
                    def __init__(self, _wrap, _t0):
                        self._wrap = _wrap
                        self._t0 = _t0
                        self._n = 0

                    async def _handle_data(self, data: bytes) -> None:
                        self._n += 1
                        _dt = _ddt_time.monotonic() - self._t0
                        try:
                            _hex = data[:64].hex() if data else ""
                            # SCTP common header parse (RFC 4960 §3.1):
                            # bytes 0-1 = source port, 2-3 = dest port,
                            # 4-7 = verification tag, 8-11 = checksum.
                            # If this is SCTP, you'll see plausible port
                            # numbers (often 5000) and a non-zero verif tag.
                            _hint = ""
                            if len(data) >= 12:
                                _sp = int.from_bytes(data[0:2], "big")
                                _dp = int.from_bytes(data[2:4], "big")
                                _vt = int.from_bytes(data[4:8], "big")
                                _hint = (
                                    f"  if-sctp: srcPort={_sp} dstPort={_dp}"
                                    f" verifTag=0x{_vt:08x}"
                                )
                            _status(
                                f"DTLS-app-data #{self._n} t+{_dt:.3f}s"
                                f" {len(data)}B hex={_hex}{_hint}"
                            )
                        except Exception:
                            pass
                        if self._wrap is not None:
                            try:
                                await self._wrap._handle_data(data)
                            except Exception as _wrap_exc:
                                _status(
                                    f"  wrapped data_receiver raised: {_wrap_exc}"
                                )

                _ddt_t0 = _bt_start  # share start time with byte-tap
                _ddt_n = 0

                # Wrap-on-call: don't pre-install — would steal the slot from
                # aiortc's SCTP and trigger AssertionError(_data_receiver is
                # None) when SCTP later tries to register.  Instead, monkey-
                # patch _register_data_receiver so when SCTP registers, we
                # transparently wrap it in our shim.  Camera's INIT then
                # reaches SCTP unchanged → SCTP sends INIT-ACK → handshake
                # completes; we still log every plaintext payload.
                def _make_wrapped_register(_dtls_inst, _t0):
                    _orig_reg = _dtls_inst._register_data_receiver

                    def _wrapped_register(receiver):
                        _shim = _LoggingDataReceiver(receiver, _t0)
                        _orig_reg(_shim)
                        try:
                            _status(
                                f"DTLS data-receiver registered: wrapping"
                                f" {type(receiver).__name__}"
                                f" → _LoggingDataReceiver"
                            )
                        except Exception:
                            pass

                    return _wrapped_register

                for _ddt_idx, _ddt_tc in enumerate(pc.getTransceivers()):
                    _ddt_dtls = _ddt_tc.receiver.transport
                    _ddt_existing = getattr(_ddt_dtls, "_data_receiver", None)
                    if _ddt_existing is not None:
                        # SCTP already registered before we got here — chain-
                        # wrap by replacing its receiver with our shim.
                        _ddt_dtls._data_receiver = _LoggingDataReceiver(
                            _ddt_existing, _ddt_t0
                        )
                    else:
                        _ddt_dtls._register_data_receiver = _make_wrapped_register(
                            _ddt_dtls, _ddt_t0
                        )
                    _ddt_n += 1
                _status(
                    f"DTLS data-receiver tap installed on {_ddt_n} transceiver(s)"
                    f" (wrap-on-call; preserves aiortc SCTP registration)"
                )
            except Exception as _ddt_install_exc:
                _status(f"DTLS data-receiver tap install failed: {_ddt_install_exc}")

            # Extract ICE candidates embedded in the SDP answer body.
            # The AiDot camera includes its host candidate as a=candidate: lines
            # inside the answer SDP.  The browser WebRTC API processes these
            # automatically; aiortc requires explicit addIceCandidate() calls.
            # Track m-section index / mid so we can set sdpMid+sdpMLineIndex.
            import re as _re
            _sdp_cand_midx = -1
            _sdp_cand_smid = "0"
            for _sdp_ans_ln in _re.split(r'\r?\n', _ans_sdp):
                if _sdp_ans_ln.startswith('m='):
                    _sdp_cand_midx += 1
                    _sdp_cand_smid = str(_sdp_cand_midx)
                elif _sdp_ans_ln.startswith('a=mid:'):
                    _sdp_cand_smid = _sdp_ans_ln[len('a=mid:'):].strip()
                elif _sdp_ans_ln.startswith('a=candidate:'):
                    _sdp_cand_line = _re.sub(
                        r'\s+generation\s+\d+.*$',
                        '',
                        _sdp_ans_ln[len('a=candidate:'):].strip(),
                    )
                    try:
                        _sdp_ice = candidate_from_sdp(_sdp_cand_line)
                        _sdp_ice.sdpMid = _sdp_cand_smid
                        _sdp_ice.sdpMLineIndex = max(_sdp_cand_midx, 0)
                        await pc.addIceCandidate(_sdp_ice)
                        _status(f"addIceCandidate (answer SDP): {_sdp_cand_line[:80]}")
                    except Exception as _sdp_exc:
                        _LOGGER.debug(
                            "addIceCandidate (answer SDP) error: %s", _sdp_exc
                        )

        # ------------------------------------------------------------------ #
        # Apply remote ICE candidates + wait for ICE connection
        # ------------------------------------------------------------------ #
        connected_ev = asyncio.Event()

        @pc.on("connectionstatechange")
        async def _on_conn_state() -> None:
            _status(f"WebRTC connectionState → {pc.connectionState}")
            if pc.connectionState == "failed":
                # Dump per-transceiver DTLS + ICE state so we can see which
                # transport actually failed and why.  aiortc transitions
                # connectionState to "failed" on the first transport that
                # enters either dtlsTransport.state = "failed" or
                # iceTransport.state = "failed".
                try:
                    for _i, _tc in enumerate(pc.getTransceivers()):
                        _dtls = _tc.receiver.transport
                        _ice  = _dtls.transport
                        _status(
                            f"  transceiver[{_i}] kind={_tc.receiver.track.kind if _tc.receiver.track else '?'}"
                            f"  dtls.state={getattr(_dtls, 'state', '?')}"
                            f"  ice.state={getattr(_ice, 'state', '?')}"
                            f"  ice.role={getattr(getattr(_ice, '_connection', None), 'role', '?')}"
                        )
                except Exception as _diag_exc:
                    _status(f"  transceiver state dump failed: {_diag_exc}")
            if pc.connectionState in ("connected", "completed"):
                connected_ev.set()
            elif pc.connectionState in ("failed", "closed"):
                connected_ev.set()   # unblock the wait; session will detect failure

        @pc.on("iceconnectionstatechange")
        async def _on_ice_state() -> None:
            _status(f"ICE connectionState → {pc.iceConnectionState}")

        @pc.on("icegatheringstatechange")
        async def _on_ice_gather() -> None:
            _LOGGER.info("webrtc: ICE gatheringState → %s", pc.iceGatheringState)

        deadline = time.monotonic() + timeout
        _last_ice_log = time.monotonic()
        _userconnect_midloop_sent = False  # guard: re-send user/connect once at half-timeout
        _second_ans_processed = False  # guard: process second_answer_fut candidates once
        _reconnect_resent_count = 0   # counter: re-send webrtcResp+ICE on each reconnect (max 3)
        while not connected_ev.is_set() and time.monotonic() < deadline:
            # Drain incoming ICE candidates from the camera
            while True:
                try:
                    cand_dict = ice_q.get_nowait()
                except asyncio.QueueEmpty:
                    break
                cand_line = cand_dict.get("candidate", "")
                if cand_line.startswith("candidate:"):
                    cand_line = cand_line[len("candidate:"):]
                # Strip non-standard trailing extensions (generation, network-cost)
                # that aioice's candidate_from_sdp cannot parse.
                import re as _re
                cand_line = _re.sub(r'\s+generation\s+\d+.*$', '', cand_line).strip()
                try:
                    ice_cand = candidate_from_sdp(cand_line)
                    _smid_val = cand_dict.get("sdpMid")
                    _smidx_val = cand_dict.get("sdpMLineIndex")
                    ice_cand.sdpMid = (
                        str(_smid_val) if _smid_val is not None else
                        (str(_smidx_val) if _smidx_val is not None else "0")
                    )
                    ice_cand.sdpMLineIndex = _smidx_val
                    await pc.addIceCandidate(ice_cand)
                    _status(f"addIceCandidate: {cand_line[:80]}")
                except Exception as exc:
                    _LOGGER.debug(
                        "async_open_webrtc_stream: addIceCandidate error: %s", exc
                    )
            # Drain camera-IP queue (setDevAttrNotif) and inject synthetic candidates.
            # When a role-reversal camera (e.g. LK.IPC.A001064) is ICE-lite it will
            # not send STUN binding requests on its own; it only responds to ours.
            # With no remote candidates in the synthetic answer, aiortc has nothing
            # to probe.  When setDevAttrNotif delivers the camera's real LAN IP we
            # synthesize host candidates using that IP + the ports the camera echoed
            # in its counter-offer, giving aiortc concrete targets to STUN-probe.
            while True:
                try:
                    _cam_ip_addr = cam_ip_q.get_nowait()
                except asyncio.QueueEmpty:
                    break
                if _rr_cam_ports:
                    for _c_smid, _c_smidx, _c_port in _rr_cam_ports:
                        _synth_cand_line = (
                            f"1 1 udp 2130706431 {_cam_ip_addr} {_c_port} typ host"
                        )
                        try:
                            _synth_ice = candidate_from_sdp(_synth_cand_line)
                            _synth_ice.sdpMid = _c_smid
                            _synth_ice.sdpMLineIndex = _c_smidx
                            await pc.addIceCandidate(_synth_ice)
                            _status(
                                f"addIceCandidate (cam-IP synth):"
                                f" {_cam_ip_addr}:{_c_port}  mid:{_c_smid}"
                            )
                        except Exception as _synth_exc:
                            _LOGGER.debug(
                                "addIceCandidate (cam-IP synth) error: %s", _synth_exc
                            )
            # Process camera's real second webrtcResp SDP for ICE candidates.
            # For LK.IPC.A001064 (role-reversal), the camera's counter-offer echoes
            # our SDP (so _rr_cam_ports has OUR ports, not camera's).  The camera's
            # real second webrtcResp (captured in second_answer_fut) typically
            # contains the camera's actual a=candidate: host lines with its real
            # ICE port.  Without this, aiortc probes wrong ports forever and ICE
            # times out.
            if not _second_ans_processed and second_answer_fut.done():
                _second_ans_processed = True
                try:
                    _sa_result = second_answer_fut.result()
                    _sa_sdp = (_sa_result or {}).get("sdp", "")
                    if _sa_sdp:
                        import re as _re3
                        _sa_midx = -1
                        _sa_smid = "0"
                        for _sa_ln in _re3.split(r'\r?\n', _sa_sdp):
                            if _sa_ln.startswith('m='):
                                _sa_midx += 1
                                _sa_smid = str(_sa_midx)
                            elif _sa_ln.startswith('a=candidate:'):
                                _sa_cand = _sa_ln[len('a=candidate:'):]
                                _sa_cand = _re3.sub(
                                    r'\s+generation\s+\d+.*$', '', _sa_cand
                                ).strip()
                                try:
                                    _sa_ice = candidate_from_sdp(_sa_cand)
                                    _sa_ice.sdpMid = _sa_smid
                                    _sa_ice.sdpMLineIndex = max(_sa_midx, 0)
                                    await pc.addIceCandidate(_sa_ice)
                                    _status(
                                        f"addIceCandidate (2nd-answer SDP):"
                                        f" {_sa_cand[:80]}"
                                    )
                                except Exception as _sa_ce:
                                    _LOGGER.debug(
                                        "addIceCandidate (2nd-answer SDP) error: %s",
                                        _sa_ce,
                                    )
                    else:
                        _status("second_answer_fut resolved but SDP is empty")
                except Exception as _sa_exc:
                    _LOGGER.debug("second_answer_fut result() error: %s", _sa_exc)
            # Periodic ICE state heartbeat so we know the loop is alive.
            if time.monotonic() - _last_ice_log >= 5.0:
                _status(
                    f"ICE wait  connState={pc.connectionState}"
                    f"  iceState={pc.iceConnectionState}"
                    f"  remaining={deadline - time.monotonic():.0f}s"
                )
                _last_ice_log = time.monotonic()
            # Mid-loop user/connect retry: if no camera IP yet and ~half of the
            # ICE timeout has elapsed, re-announce user presence so the camera
            # pushes setDevAttrNotif again.  Replaces the invented getDevAttrReq.
            _remaining = deadline - time.monotonic()
            if (not _userconnect_midloop_sent
                    and cam_ip_q.empty()
                    and _remaining > 0
                    and _remaining <= timeout / 2.0):
                outgoing_q.put_nowait((
                    f"iot/v1/cb/{user_id}/user/connect",
                    json.dumps({
                        "service": "user",
                        "method":  "connect",
                        "srcAddr": f"0.{user_id}",
                        "payload": {"timestamp": _mqtt_timestamp()},
                    }),
                ))
                _userconnect_midloop_sent = True
                _status("user/connect re-sent (mid-loop, waiting for camera IP)")
            # Re-send webrtcResp + ICE candidates if camera reconnected during ICE.
            # LK.IPC.A001064 performs a quickConn MQTT reconnect after receiving
            # our webrtcResp; the reconnect resets its ICE agent so it no longer
            # has our ICE credentials or candidates.  We must re-send webrtcResp
            # first (to restore credentials/fingerprint) then ICE candidates.
            # ICE candidates alone are not sufficient — without webrtcResp the
            # camera has no credentials to validate STUN, so it never probes us.
            # Guard: only for echo-only role-reversal cameras (_rr_ice_payloads
            # is empty for all other paths) and at most 3 times per session.
            if (camera_reconnect_ev.is_set()
                    and _reconnect_resent_count < 3
                    and _rr_ice_payloads):
                _reconnect_resent_count += 1
                camera_reconnect_ev.clear()
                _status(
                    f"camera reconnected during ICE (retry {_reconnect_resent_count})"
                    " — re-sending webrtcResp + ICE candidates"
                )
                await asyncio.sleep(1.5)  # let camera re-subscribe before re-send
                if _rr_webrtc_resp_topic and _rr_webrtc_resp_payload:
                    outgoing_q.put_nowait((_rr_webrtc_resp_topic, _rr_webrtc_resp_payload))
                for _rr_ice_p in _rr_ice_payloads:
                    outgoing_q.put_nowait(_rr_ice_p)
            await asyncio.sleep(0.1)

        if pc.connectionState not in ("connected", "completed"):
            outgoing_q.put_nowait(None)
            await pc.close()
            raise RuntimeError(
                f"async_open_webrtc_stream: ICE connection not established "
                f"(connState={pc.connectionState}"
                f"  iceState={pc.iceConnectionState}) within {timeout}s"
            )

        if recorder:
            await recorder.start()

        _LOGGER.info(
            "WebRTC stream open for %s (peerid=%s)", device_id, peer_id
        )
        return WebRTCSession(
            pc=pc,
            outgoing_q=outgoing_q,
            mqtt_fut=mqtt_fut,
            recorder=recorder,
            track_tasks=track_tasks,
            dc=_kvs_dc,
        )

    # Keep old name as alias
    async_open_kvs_stream = async_open_webrtc_stream

    # ------------------------------------------------------------------ #
    # SDES-SRTP streaming path (cameras with isDTLS == '0')
    # ------------------------------------------------------------------ #

    class _SdesNoAnswerError(Exception):
        """Raised by _open_sdes_stream when no webrtcResp arrives and
        DTLS fallback is permitted (isDTLS != '0').

        Signals async_open_webrtc_stream to retry with the DTLS path for
        cameras that report ``enableSdes: '1'`` but actually require DTLS.
        Cameras with ``isDTLS: '0'`` are excluded from this path; they
        instead continue with ffmpeg and collect the SRTP stream directly.
        """

    async def _open_sdes_stream(
        self,
        *,
        peer_id: str,
        user_id: str,
        device_id: str,
        outgoing_q,
        answer_fut,
        camera_offer_fut,
        webrtc_req_echo_fut=None,
        loop,
        timeout: float,
        output_path: Optional[str],
        max_seconds: Optional[float] = None,
        _status=None,
        mqtt_fut=None,
        liveplay_echo_ev=None,
        liveplay_resp_fut=None,
        numeric_uid_raw: Optional[str] = None,
        dtls_fallback_ok: bool = True,
        second_answer_fut=None,
        ice_config: "Optional[dict]" = None,
        camera_reconnect_ev=None,
        sdes_answer_timeout: Optional[float] = None,
        rtsp_push_url: Optional[str] = None,
    ) -> "SdesSession":
        """SDES-SRTP streaming path using a hand-crafted SDP offer and ffmpeg.

        SDES cameras negotiate SRTP keys inline in the SDP (``a=crypto:`` lines)
        rather than via a DTLS handshake.  aiortc does not support SDES-SRTP, so
        this path sends a manually constructed SDP offer, waits for the camera's
        SDP answer, writes it to a temp file, and launches ffmpeg to receive and
        record the SRTP stream.
        """
        import base64
        import os
        import subprocess
        import tempfile
        import json

        user_id = user_id or str(self.user_id)

        # Models confirmed (2026-05-02) to send TUTK-framed data instead of
        # standard SRTP: camera announces an ASCII-printable fake SDES key and
        # sends packets with byte0=0xC8 (TUTK audio SFrame header) and an SSRC
        # that differs from the one advertised in the SDP.  For these models:
        # (a) ffmpeg SDP uses plain RTP/AVP (no SRTP decryption attempt), and
        # (b) the bridge thread detects TUTK SFrame headers (0xC8=audio,
        #     0xC9=video), strips the 12-byte TUTK header, synthesizes a
        #     standard RTP header from the TUTK timestamp+SSRC fields, and
        #     forwards the reassembled plain-RTP packet to ffmpeg.
        _model_id = getattr(getattr(self, "info", None), "model_id", None) or ""
        _use_plain_rtp = _model_id in {"LK.IPC.A001064", "LK.IPC.A001513"}
        # powerType/p2pCache — IpcServiceImpl.java:B() returns 2 for battery
        # models (A001513, A001108, A001360); 1 for wired.  All tested cameras
        # report p2pCache=2 in their setDevAttrNotif device attributes.
        _live_power_type = "2" if any(
            m in _model_id for m in ("A001513", "A001108", "A001360")
        ) else "1"
        _live_p2p_cache = "2"

        webrtc_req_topic = f"iot/v1/s/{user_id}/IPC/webrtcReq"

        def _seq() -> str:
            import random
            return f"ap{random.randint(1000000, 9999999)}"

        # --- Allocate UDP ports and determine local IP ---------------------- #
        import socket as _socket

        _audio_sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        _audio_sock.bind(("0.0.0.0", 0))
        audio_port = _audio_sock.getsockname()[1]

        _video_sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        _video_sock.bind(("0.0.0.0", 0))
        video_port = _video_sock.getsockname()[1]

        # Use the outbound interface toward 8.8.8.8 to find our local IP.
        # connect() on a UDP socket does not send any packet.
        with _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM) as _s:
            _s.connect(("8.8.8.8", 80))
            local_ip = _s.getsockname()[0]

        # Determine server-reflexive (public) IP from cached getServerUrlConfig.
        # The Arnoo broker records our outbound IP in the "ip" field; this is the
        # same address that aiortc discovers via STUN and exposes as srflx
        # candidates.  Adding it to the SDES offer lets cameras that cannot route
        # to our LAN IP (WAN cameras, different subnet) send STUN probes to our
        # public address, which the router NATs to our reservation sockets.
        _public_ip: Optional[str] = None
        try:
            _raw_srv = (self._smarthome_auth or {}).get("raw") or {}
            _cand_pub = str(_raw_srv.get("ip") or "").strip()
            if _cand_pub and _cand_pub != local_ip:
                # Accept any valid IPv4 that differs from our LAN address.
                _p = _cand_pub.split(".")
                if len(_p) == 4 and all(x.isdigit() and 0 <= int(x) <= 255 for x in _p):
                    _public_ip = _cand_pub
        except Exception:
            pass

        # Build TURN server list for _sdes_ice_server_list from ice_config if
        # available.  The camera's ICE agent uses these to gather its own relay
        # candidates; a relay path is the last resort when direct and srflx
        # connectivity both fail (e.g. symmetric NAT or strict firewall).
        _sdes_turn_entries: list = []
        try:
            if ice_config:
                # Unwrap common envelope shapes (mirrors DTLS path normalisation).
                _ic = ice_config
                for _k in ("data", "payload", "result"):
                    if isinstance(_ic, dict) and _k in _ic and isinstance(_ic[_k], dict):
                        _ic = _ic[_k]
                        break
                # Arnoo format: {app: [{uris, id, token}], dev: [...]}
                for _sect in ("app", "dev"):
                    for _entry in (_ic.get(_sect) or []):
                        _uris = _entry.get("uris") or _entry.get("Uris") or []
                        _user = (_entry.get("id") or _entry.get("Username")
                                 or _entry.get("username") or "")
                        _cred = (_entry.get("token") or _entry.get("Password")
                                 or _entry.get("password") or "")
                        if any("turn:" in str(u) for u in _uris):
                            _sdes_turn_entries.append({
                                "Uris":     _uris,
                                "Username": _user,
                                "Password": str(_cred),
                            })
                # W3C format: {iceServers: [{urls, username, credential}]}
                for _entry in (_ic.get("iceServers") or []):
                    _uris = _entry.get("urls") or _entry.get("uris") or []
                    if isinstance(_uris, str):
                        _uris = [_uris]
                    if any("turn:" in str(u) for u in _uris):
                        _sdes_turn_entries.append({
                            "Uris":     _uris,
                            "Username": _entry.get("username") or "",
                            "Password": _entry.get("credential") or "",
                        })
        except Exception:
            pass

        # --- TURN relay allocation helper ------------------------------------ #
        # Defined BEFORE the offer so relay IP/port can be embedded in the
        # offer's c= and m= lines.  Pure-SDES cameras (no ICE) read the OFFER's
        # c= address and stream SRTP there directly — if we put the relay address
        # in the offer, the camera's SRTP reaches us through port-restricted NAT.
        _relay_addrs: dict = {}  # sock → (relay_ip, relay_port, realm, nonce, t_host, t_port, key)

        def _turn_allocate_udp(_ta_sock, _ta_host, _ta_port, _ta_user, _ta_pass):
            """RFC 5766 TURN relay allocation with long-term credential auth.
            Returns (relay_ip, relay_port, realm, nonce) or None on failure."""
            import hashlib as _ha, hmac as _hm, struct as _st_ta, select as _sl_ta, time as _tm_ta

            _MAGIC_TA = b'\x21\x12\xa4\x42'

            def _a(_t, _v):
                _p = (-len(_v)) % 4
                return _st_ta.pack('!HH', _t, len(_v)) + _v + b'\x00' * _p

            def _mi_ta(_k, _m):
                # Patch Length to include the MI attribute (4 hdr + 20 digest = 24)
                _patched = _m[:2] + _st_ta.pack('!H', len(_m) - 20 + 24) + _m[4:]
                return _hm.new(_k, _patched, _ha.sha1).digest()

            # Step 1: unauthenticated Allocate → get REALM and NONCE from 401
            _tid1 = os.urandom(12)
            _b1 = _a(0x0019, b'\x11\x00\x00\x00')  # REQUESTED-TRANSPORT = UDP(17), RFC 5766 §14.7 protocol in MSB
            _r1 = b'\x00\x03' + _st_ta.pack('!H', len(_b1)) + _MAGIC_TA + _tid1 + _b1
            try:
                _ta_sock.sendto(_r1, (_ta_host, _ta_port))
            except Exception:
                return None
            # Loop until we get a response whose TID matches our request (discard
            # stale packets from previous exchanges that may linger in the buffer).
            _rsp1 = None
            _dl1 = _tm_ta.time() + 2.0
            while _tm_ta.time() < _dl1:
                _rem = _dl1 - _tm_ta.time()
                _rs1, _, _ = _sl_ta.select([_ta_sock], [], [], min(_rem, 0.5))
                if not _rs1:
                    continue
                try:
                    _cand1, _ = _ta_sock.recvfrom(2048)
                except OSError:
                    break
                if len(_cand1) >= 20 and _cand1[8:20] == _tid1:
                    _rsp1 = _cand1
                    break
            if _rsp1 is None:
                return None
            _realm_ta = _nonce_ta = b''
            _o = 20
            while _o + 4 <= len(_rsp1):
                _at, _al = _st_ta.unpack_from('!HH', _rsp1, _o)
                _av = _rsp1[_o + 4:_o + 4 + _al]
                _o += 4 + _al + (-_al % 4)
                if _at == 0x0014:
                    _realm_ta = _av
                elif _at == 0x0015:
                    _nonce_ta = _av
            if not _realm_ta or not _nonce_ta:
                _LOGGER.debug("TURN alloc step1: no realm/nonce in response type=%s",
                              _rsp1[:2].hex())
                return None
            _LOGGER.debug("TURN alloc step1 challenge: realm=%r nonce_len=%d",
                          _realm_ta.decode(errors='replace'), len(_nonce_ta))

            # Step 2: authenticated Allocate
            _tid2 = os.urandom(12)
            _key_ta = _ha.md5(_ta_user + b':' + _realm_ta + b':' + _ta_pass).digest()
            _b2 = (
                _a(0x0006, _ta_user)                  # USERNAME
                + _a(0x0014, _realm_ta)               # REALM
                + _a(0x0015, _nonce_ta)               # NONCE
                + _a(0x0019, b'\x11\x00\x00\x00')     # REQUESTED-TRANSPORT = UDP, RFC 5766 §14.7 protocol in MSB
            )
            _h2 = b'\x00\x03' + _st_ta.pack('!H', len(_b2) + 24) + _MAGIC_TA + _tid2
            _b2 += _a(0x0008, _mi_ta(_key_ta, _h2 + _b2))  # MESSAGE-INTEGRITY
            _r2 = b'\x00\x03' + _st_ta.pack('!H', len(_b2)) + _MAGIC_TA + _tid2 + _b2
            try:
                _ta_sock.sendto(_r2, (_ta_host, _ta_port))
            except Exception:
                return None
            # Same TID-matching loop — if step 1's 401 was still in the buffer,
            # a bare recvfrom would consume it and report failure on a good alloc.
            _rsp2 = None
            _dl2 = _tm_ta.time() + 2.0
            while _tm_ta.time() < _dl2:
                _rem = _dl2 - _tm_ta.time()
                _rs2, _, _ = _sl_ta.select([_ta_sock], [], [], min(_rem, 0.5))
                if not _rs2:
                    continue
                try:
                    _cand2, _ = _ta_sock.recvfrom(2048)
                except OSError:
                    break
                if len(_cand2) >= 20 and _cand2[8:20] == _tid2:
                    _rsp2 = _cand2
                    break
            if _rsp2 is None:
                return None
            if _rsp2[:2] != b'\x01\x03':  # Allocate Success = 0x0103
                # Parse ERROR-CODE (0x0009) for diagnostics
                _ec2 = 0
                _o_ec = 20
                while _o_ec + 4 <= len(_rsp2):
                    _at_ec, _al_ec = _st_ta.unpack_from('!HH', _rsp2, _o_ec)
                    _av_ec = _rsp2[_o_ec + 4:_o_ec + 4 + _al_ec]
                    _o_ec += 4 + _al_ec + (-_al_ec % 4)
                    if _at_ec == 0x0009 and _al_ec >= 4:
                        _ec2 = (_av_ec[2] & 0x07) * 100 + _av_ec[3]
                _LOGGER.debug(
                    "TURN alloc step2 error_code=%d realm=%r response_type=%s",
                    _ec2, _realm_ta.decode(errors='replace'), _rsp2[:2].hex(),
                )
                return None

            # Parse XOR-RELAYED-ADDRESS (0x0016)
            _o = 20
            while _o + 4 <= len(_rsp2):
                _at, _al = _st_ta.unpack_from('!HH', _rsp2, _o)
                _av = _rsp2[_o + 4:_o + 4 + _al]
                _o += 4 + _al + (-_al % 4)
                if _at == 0x0016 and _al >= 8:  # XOR-RELAYED-ADDRESS
                    _xp = _st_ta.unpack_from('!H', _av, 2)[0] ^ 0x2112
                    _xb = bytes(a ^ b for a, b in zip(_av[4:8], _MAGIC_TA))
                    _r_ip_ta = '.'.join(str(b) for b in _xb)
                    # Do NOT pre-create permissions for our own srflx IP or
                    # TURN server IP. That can cause TURN self-loop Data
                    # Indications and massive STUN echo storms.
                    return _r_ip_ta, _xp, _realm_ta, _nonce_ta
            return None

        # --- Early TURN relay allocation (before offer build) --------------- #
        # Allocate relay now so offer c= and m= carry relay IP/port.
        # Camera reads offer's c= to know where to send SRTP — relay address
        # here means SRTP reaches us even through port-restricted / hairpin NAT.
        if _sdes_turn_entries:
            try:
                import re as _re_pre, hashlib as _hlk_pre
                _our_te_pre = next(
                    (e for e in _sdes_turn_entries if e.get("Username") == user_id),
                    _sdes_turn_entries[0],
                )
                _t_uri_pre = next(
                    (str(u) for u in (_our_te_pre.get("Uris") or []) if "turn:" in str(u)),
                    ""
                )
                _tm_pre = _re_pre.search(r'turns?:([^:?]+)(?::(\d+))?', _t_uri_pre)
                if _tm_pre:
                    _t_host_pre = _tm_pre.group(1)
                    _t_port_pre = int(_tm_pre.group(2) or 5349)
                    _t_user_pre = (_our_te_pre.get("Username") or "").encode()
                    _t_pass_pre = str(_our_te_pre.get("Password") or "").encode()
                    for _pre_sock, _pre_name in ((_audio_sock, "audio"), (_video_sock, "video")):
                        _pre_res = _turn_allocate_udp(
                            _pre_sock, _t_host_pre, _t_port_pre, _t_user_pre, _t_pass_pre,
                        )
                        if _pre_res:
                            _r_ip_pre, _r_port_pre, _r_realm_pre, _r_nonce_pre = _pre_res
                            _r_key_pre = _hlk_pre.md5(
                                _t_user_pre + b':' + _r_realm_pre + b':' + _t_pass_pre
                            ).digest()
                            _relay_addrs[_pre_sock] = (
                                _r_ip_pre, _r_port_pre, _r_realm_pre, _r_nonce_pre,
                                _t_host_pre, _t_port_pre, _r_key_pre,
                            )
                            _status(
                                f"TURN relay pre-allocated (offer): {_pre_name}"
                                f" → {_r_ip_pre}:{_r_port_pre}"
                            )
            except Exception as _pre_exc:
                _LOGGER.warning("TURN pre-allocation error: %s", _pre_exc)

        # --- DTLS certificate for m=application probe ----------------------- #
        # PreCon cameras (sptPreconn=1) need SESSION_MODE_REQ via SCTP datachannel.
        # Include m=application in offer so camera answers with its own DataChannel
        # section.  Use cryptography (already a dependency) — no aiortc needed.
        _dc_probe_fp = ""
        try:
            from cryptography import x509 as _cx509
            from cryptography.x509.oid import NameOID as _CNOID
            from cryptography.hazmat.primitives import hashes as _ch, serialization as _cser
            from cryptography.hazmat.primitives.asymmetric import ec as _cec
            from cryptography.hazmat.backends import default_backend as _cbd
            import datetime as _dt_dc, hashlib as _hs_dc
            _dc_key = _cec.generate_private_key(_cec.SECP256R1(), _cbd())
            _dc_name = _cx509.Name([_cx509.NameAttribute(_CNOID.COMMON_NAME, "aidot-dc")])
            _dc_cert = (
                _cx509.CertificateBuilder()
                .subject_name(_dc_name).issuer_name(_dc_name)
                .public_key(_dc_key.public_key())
                .serial_number(_cx509.random_serial_number())
                .not_valid_before(_dt_dc.datetime.utcnow())
                .not_valid_after(_dt_dc.datetime.utcnow() + _dt_dc.timedelta(days=365))
                .sign(_dc_key, _ch.SHA256(), _cbd())
            )
            _dc_der = _dc_cert.public_bytes(_cser.Encoding.DER)
            _dc_hex = _hs_dc.sha256(_dc_der).hexdigest().upper()
            _dc_probe_fp = "sha-256 " + ":".join(
                _dc_hex[i:i+2] for i in range(0, len(_dc_hex), 2)
            )
        except Exception as _cert_exc:
            _LOGGER.debug("DC probe: cert generation failed: %s", _cert_exc)

        # --- Generate PSK before SDP (must precede SDP building) ------------- #
        # PSK is injected into SDP as a=psk: and into wPayload.psk.
        import random as _rnd_psk_early
        _psk_charset_req = "123456789abcdef"
        _psk_value_req = "".join(
            _psk_charset_req[_rnd_psk_early.randint(0, len(_psk_charset_req) - 1)]
            for _ in range(64)
        )

        # --- Build SDES SDP offer ------------------------------------------ #
        # AES_CM_128_HMAC_SHA1_80: 16-byte key + 14-byte salt = 30 bytes.
        srtp_key_audio = base64.b64encode(os.urandom(30)).decode()
        srtp_key_video = base64.b64encode(os.urandom(30)).decode()
        # Log SDES key material at DEBUG only — this is SRTP keying material and
        # should not appear in production-level logs.  Re-enable at debug when
        # verifying the AES counter derivation formula after Frida observation.
        _LOGGER.debug(
            "sdes: offer key=%s salt=%s psk=%s",
            base64.b64decode(srtp_key_audio)[:16].hex(),
            base64.b64decode(srtp_key_audio)[16:].hex(),
            _psk_value_req,
        )
        ts = int(time.time())
        # SDES-SRTP cameras use SIP-era plain SDP (RFC 3264 + RFC 3711).
        # Use RTP/SAVPF (RFC 4585) — Leedarson firmware expects the feedback
        # profile and silently ignores offers with plain RTP/SAVP.
        # Include per-m-section ICE credentials and a host candidate so that
        # newer PTZ firmware (e.g. LK.IPC.A001064) that requires ICE for
        # address discovery will respond.  Older cameras that don't understand
        # ICE ignore those attributes and use the port in the m= line directly.
        import secrets as _secrets
        _ufrag_a = _secrets.token_urlsafe(4)[:4]
        _pwd_a   = _secrets.token_urlsafe(24)[:22]
        _ufrag_v = _secrets.token_urlsafe(4)[:4]
        _pwd_v   = _secrets.token_urlsafe(24)[:22]
        # Use srflx (public) IP and direct port in c= and m= for the offer too,
        # for consistency with the answer.  TURN relay requires CreatePermission
        # for the camera's public IP which is unknown; relay in c= causes TURN to
        # drop every camera packet.  Relay is still in a=candidate: for ICE.
        # For LAN cameras (_public_ip is None) fall back to local_ip directly.
        _offer_audio_ip   = _public_ip or local_ip
        _offer_audio_port = audio_port
        _offer_video_ip   = _public_ip or local_ip
        _offer_video_port = video_port
        _bundle_hdr_line = (
            "a=group:BUNDLE 0 1 2\r\n" if _dc_probe_fp else "a=group:BUNDLE 0 1\r\n"
        )
        sdes_offer_sdp = (
            "v=0\r\n"
            f"o=- {ts} {ts} IN IP4 {local_ip}\r\n"
            "s=-\r\n"
            f"t=0 0\r\n{_bundle_hdr_line}"
            # audio m-section
            # a=crypto MUST precede ICE attributes (RFC 4568 §9.1) so that
            # linear-parsing camera firmware recognises this as an SDES offer
            # rather than a pure-ICE offer and does not discard the key.
            f"m=audio {_offer_audio_port} RTP/SAVPF 0 8\r\n"
            f"c=IN IP4 {_offer_audio_ip}\r\n"
            "a=recvonly\r\n"
            "a=mid:0\r\n"
            f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{srtp_key_audio}\r\n"
            "a=rtpmap:0 PCMU/8000\r\n"
            "a=rtpmap:8 PCMA/8000\r\n"
            # a=rtcp-mux: multiplexes RTCP onto the RTP port so the camera does
            # not send RTCP to audio_port+1 (which is never bound), and so that
            # ffmpeg does not try to open a separate RTCP socket.
            "a=rtcp-mux\r\n"
            # PSK is sent in wPayload only — real app does NOT inject a=psk: into
            # the SDP body (confirmed from logcat ground truth 2026-05-22).
            f"a=ice-ufrag:{_ufrag_a}\r\n"
            f"a=ice-pwd:{_pwd_a}\r\n"
            f"a=candidate:1 1 udp 2130706431 {local_ip} {audio_port} typ host\r\n"
            + (
                f"a=candidate:2 1 udp 1694498815 {_public_ip} {audio_port}"
                f" typ srflx raddr {local_ip} rport {audio_port}\r\n"
                if _public_ip else ""
            )
            + (
                f"a=candidate:3 1 udp 16777215 {_relay_addrs[_audio_sock][0]}"
                f" {_relay_addrs[_audio_sock][1]}"
                f" typ relay raddr {local_ip} rport {audio_port}\r\n"
                if _audio_sock in _relay_addrs else ""
            )
            # video m-section
            + f"m=video {_offer_video_port} RTP/SAVPF 96 97\r\n"
            f"c=IN IP4 {_offer_video_ip}\r\n"
            "a=recvonly\r\n"
            "a=mid:1\r\n"
            f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{srtp_key_video}\r\n"
            "a=rtpmap:96 H264/90000\r\n"
            "a=fmtp:96 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f\r\n"
            "a=rtpmap:97 H265/90000\r\n"
            "a=fmtp:97 level-id=93\r\n"
            "a=rtcp-mux\r\n"
            f"a=ice-ufrag:{_ufrag_v}\r\n"
            f"a=ice-pwd:{_pwd_v}\r\n"
            f"a=candidate:1 1 udp 2130706431 {local_ip} {video_port} typ host\r\n"
            + (
                f"a=candidate:2 1 udp 1694498815 {_public_ip} {video_port}"
                f" typ srflx raddr {local_ip} rport {video_port}\r\n"
                if _public_ip else ""
            )
            + (
                f"a=candidate:3 1 udp 16777215 {_relay_addrs[_video_sock][0]}"
                f" {_relay_addrs[_video_sock][1]}"
                f" typ relay raddr {local_ip} rport {video_port}\r\n"
                if _video_sock in _relay_addrs else ""
            )
            # m=application SCTP DataChannel section for SDES cameras.
            # Ground truth from real Leedarson app logcat (2026-05-22):
            #   m=application 9 SCTP webrtc-datachannel
            #   a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{key}
            # That is ALL — no a=setup, no a=sctp-port, no fingerprint.
            # Using UDP/DTLS/SCTP or a=setup:active triggers the SCTP deadlock;
            # plain SCTP lets the camera handle role negotiation internally.
            # The a=crypto line is required: GetSctpSdesKey0/1 in the camera
            # firmware parse inline: from this attribute to derive the AES key.
            + (
                "m=application 9 SCTP webrtc-datachannel\r\n"
                "c=IN IP4 0.0.0.0\r\n"
                "a=mid:2\r\n"
                f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{srtp_key_audio}\r\n"
                if _dc_probe_fp else ""
            )
        )

        _relay_str = (
            f"  relay-audio={_relay_addrs[_audio_sock][0]}:{_relay_addrs[_audio_sock][1]}"
            if _audio_sock in _relay_addrs else ""
        )
        _status(
            f"SDP offer (SDES)  local={local_ip}"
            + (f"  srflx={_public_ip}" if _public_ip else "")
            + f"  audio={audio_port}  video={video_port}"
            + _relay_str
        )

        # Send livePlayReq before the SDP offer to arm the camera's stream.
        import random as _random
        _live_req_sdes = json.dumps({
            "method":  "livePlayReq",
            "service": "IPC",
            "devId":   device_id,
            "srcAddr": f"0.{user_id}",
            "seq":     f"ap{_random.randint(1000000, 9999999)}",
            "tst":     int(time.time() * 1000),
            **( {"userId": numeric_uid_raw} if numeric_uid_raw is not None else {} ),
            "payload": {
                "peerid":  peer_id,
                "devId":   device_id,
                # Decompiled reference app (tyrus/o.java) sets payload.dstAddr
                # to the target deviceId for livePlayReq.
                "dstAddr": device_id,
                # App payload compatibility fields (decompiled live-play model).
                "livePlay": 1,
                "powerType": _live_power_type,
                "p2pCache": _live_p2p_cache,
                "dseq": 0,
            },
        })
        _live_play_topic_sdes = f"iot/v1/s/{user_id}/IPC/livePlayReq"
        outgoing_q.put_nowait((_live_play_topic_sdes, _live_req_sdes))
        _status(f"livePlayReq sent (SDES)  peerid={peer_id}")
        import asyncio as _asyncio
        # Wait for the livePlayReq echo from the broker/camera before sending
        # webrtcReq.  The echo confirms the MQTT pipeline to this device is live
        # and the broker session is registered.  Fall through after 5 s if it
        # never arrives (same safety as the old fixed 0.5 s sleep, but adaptive).
        try:
            await _asyncio.wait_for(liveplay_echo_ev.wait(), timeout=5.0)
            _status("livePlayReq echo received — sending webrtcReq, ICE, then launching ffmpeg")
        except _asyncio.TimeoutError:
            _status("no livePlayReq echo in 5s — sending webrtcReq, ICE, then launching ffmpeg anyway")
        # If camera provided explicit livePlayResp failure, abort before SDP/ICE.
        try:
            _lp_resp_sdes = await _asyncio.wait_for(
                _asyncio.shield(liveplay_resp_fut), timeout=1.0
            )
            _lp_code_sdes = int(_lp_resp_sdes.get("code", 200))
            _lp_on_sdes = int(_lp_resp_sdes.get("livePlay", 1))
            if _lp_code_sdes not in (0, 200) or _lp_on_sdes == 0:
                raise RuntimeError(
                    f"livePlay rejected by camera (code={_lp_code_sdes}, livePlay={_lp_on_sdes})"
                )
        except _asyncio.TimeoutError:
            pass

        # --- Build local-receiver SDP for ffmpeg ----------------------------- #
        # Built BEFORE sending webrtcReq so ffmpeg is already listening on the
        # reserved ports when the camera starts streaming.  Launching ffmpeg
        # after webrtcReq means the first seconds of SRTP data land in the
        # Python reservation sockets (or trigger ICMP port-unreachable after
        # they are closed), causing 0-frame output.
        # ffmpeg_sdp uses only audio_port/video_port and srtp_key_* — all known
        # from the allocation step above; the camera's webrtcResp is not needed.
        # c=IN IP4 0.0.0.0 tells ffmpeg to bind locally (listen mode).
        # Use RTP/SAVP (plain SRTP, RFC 3711) rather than RTP/SAVPF for the
        # ffmpeg receiver SDP.  ffmpeg's SDP demuxer does not recognise the
        # SAVPF feedback profile (RFC 4585) as a valid SRTP profile and fails
        # with "Could not find codec parameters" when SAVPF is used.  The
        # camera-facing offer SDP still uses RTP/SAVPF as required by the
        # firmware; only this local file (read by ffmpeg) needs SAVP.
        ffmpeg_sdp = (
            "v=0\r\n"
            f"o=- {ts} {ts} IN IP4 0.0.0.0\r\n"
            "s=aidot-sdes-rx\r\n"
            "t=0 0\r\n"
            f"m=audio {audio_port} RTP/SAVP 0 8\r\n"
            "c=IN IP4 0.0.0.0\r\n"
            f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{srtp_key_audio}\r\n"
            "a=rtpmap:0 PCMU/8000\r\n"
            "a=rtpmap:8 PCMA/8000\r\n"
            # a=rtcp-mux prevents ffmpeg from trying to bind audio_port+1 for
            # RTCP (a separate socket that is never needed here).
            "a=rtcp-mux\r\n"
            f"m=video {video_port} RTP/SAVP 96 97\r\n"
            "c=IN IP4 0.0.0.0\r\n"
            f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{srtp_key_video}\r\n"
            "a=rtpmap:96 H264/90000\r\n"
            "a=fmtp:96 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f\r\n"
            "a=rtpmap:97 H265/90000\r\n"
            "a=fmtp:97 level-id=93\r\n"
            "a=rtcp-mux\r\n"
        )

        sdp_fd, sdp_path = tempfile.mkstemp(suffix=".sdp", prefix="aidot_sdes_")
        with os.fdopen(sdp_fd, "w") as f:
            f.write(ffmpeg_sdp)

        # --- Send webrtcReq BEFORE releasing reservation sockets ------------- #
        # ICE cameras (e.g. LK.IPC.A001064) send STUN binding requests to our
        # ICE candidates immediately after receiving webrtcReq.  We must respond
        # from the reservation sockets (which own those ports) BEFORE handing
        # the ports to ffmpeg.  Non-ICE cameras start streaming SRTP straight
        # away; any early SRTP packets landing on the reservation sockets are
        # discarded, but the camera keeps streaming once ffmpeg is bound.
        # IceServerList for SDES path.  Always include STUN so the camera's ICE
        # agent can gather its own srflx candidate.  Append any TURN entries from
        # ice_config so the camera can allocate a relay and probe our srflx/host
        # candidates when direct connectivity fails (e.g. symmetric NAT).
        _sdes_ice_server_list = [{"Uris": ["stun:stun.l.google.com:19302"]}]
        _sdes_ice_server_list.extend(_sdes_turn_entries)
        # _psk_value_req was generated before the SDP offer (see above).
        # Reused here in webrtcReq and webrtcResp for consistency.
        def _compress_sdp_req(_sdp: str) -> str:
            """g.b() equivalent — selective SDP filter for wPayload."""
            _out: list = []
            _seen: dict = {}
            _media_type = ""
            _before_m = True

            def _k(_ln: str, _key: str = "") -> None:
                _out.append(_ln + "\r\n")
                if _key:
                    _seen[_key] = "1"

            for _ln in _sdp.splitlines():
                if _ln.startswith("m="):
                    _before_m = False
                    _media_type = _ln.split(" ")[0]
                    _k(_ln)
                    continue
                if _before_m:
                    if _ln.startswith("s="):
                        _k(_ln)
                    continue
                if _ln.startswith("a=ssrc") and "cname" in _ln:
                    _k(_ln)
                    continue
                if any(_d in _ln for _d in ("sendrecv", "recvonly", "sendonly")):
                    _k(_ln)
                    continue
                for _ak in ("ice-ufrag", "ice-pwd", "fingerprint", "setup",
                            "ice-options", "crypto", "psk"):
                    if _ak in _ln:
                        if _seen.get(_ak) is None:
                            _k(_ln, _ak)
                        break
                else:
                    if "candidate" in _ln and " udp " in _ln.lower():
                        _k(_ln)
                        continue
                    if _media_type == "m=audio":
                        if any(_c in _ln for _c in ("opus", "PCMU", "PCMA", "AAC")):
                            _k(_ln)
                    elif _media_type == "m=video":
                        if "H264/90000" in _ln and _seen.get("H264/90000") is None:
                            _k(_ln, "H264/90000")
                            try:
                                _seen["H264/90000_pt"] = _ln.split(":")[1].split(" ")[0]
                            except Exception:
                                pass
                        elif "H265/90000" in _ln and _seen.get("H265/90000") is None:
                            _k(_ln, "H265/90000")
                            try:
                                _seen["H265/90000_pt"] = _ln.split(":")[1].split(" ")[0]
                            except Exception:
                                pass
                        elif "apt=" in _ln:
                            try:
                                _apt = _ln.split("apt=")[1].strip()
                            except Exception:
                                _apt = ""
                            if _apt and _apt in (
                                _seen.get("H264/90000_pt", ""),
                                _seen.get("H265/90000_pt", ""),
                            ):
                                _k(_ln)
                        elif "fmtp" in _ln and "profile-level-id" in _ln:
                            if _seen.get("profile-level") is None:
                                _k(_ln, "profile-level")
                    elif _media_type == "m=application":
                        if "sctp-port" in _ln:
                            _k(_ln)
            return "".join(_out)

        _compressed_sdp_req = _compress_sdp_req(sdes_offer_sdp)
        _webrtc_req_sdes_payload = json.dumps({
            "method":  "webrtcReq",
            "service": "IPC",
            "devId":   device_id,
            "srcAddr": f"0.{user_id}",
            "seq":     _seq(),
            "tst":     int(time.time() * 1000),
            **( {"userId": numeric_uid_raw} if numeric_uid_raw is not None else {} ),
            "payload": {
                # Legacy flat fields — older firmware parses payload.peerid directly.
                "peerid":  peer_id,
                "devId":   device_id,
                "offer":   {"type": "offer", "sdp": sdes_offer_sdp},
                "trackId": 0,
                # Decompiled reference app (tyrus/o.java) sets dstAddr=deviceId
                # for webrtcReq.
                "dstAddr": device_id,
                "encOffer": 1,
                "liveMqtt": 1,
                # wPayload: newer firmware parses wPayload for ICE credentials
                # and PSK.  Fields match reference app o.java (signaling/tyrus).
                "wPayload": {
                    "peerid": peer_id,
                    "sts":    int(time.time() * 1000),
                    "psk":    _psk_value_req,
                    "offer":  {"type": "offer", "sdp": _compressed_sdp_req},
                },
                "IceServerList": _sdes_ice_server_list,
            },
        })
        outgoing_q.put_nowait((webrtc_req_topic, _webrtc_req_sdes_payload))
        _status(f"webrtcReq sent (SDES)  peerid={peer_id}")

        # --- Acknowledge camera's webrtcReq echo with webrtcResp ------------- #
        # LK.IPC.A001064 echoes our offer back as webrtcReq before doing ICE.
        # It will not start streaming until it receives a webrtcResp from us.
        # Check for the echo within 2 s so the webrtcResp is sent while our
        # reservation sockets are still open (camera's ICE may arrive next).
        #
        # NOTE: webrtc_req_echo_fut (not camera_offer_fut) is the correct future
        # here.  camera_offer_fut is only set for non-echo (role-reversal) messages
        # where is_echo=False.  The broker echo carries our own srcAddr prefix so
        # is_echo=True, which is exactly what webrtc_req_echo_fut signals.
        _echo_fut = webrtc_req_echo_fut if webrtc_req_echo_fut is not None else camera_offer_fut
        _cam_echo_received = False
        _webrtc_resp_sdes_topic: "Optional[str]" = None
        _webrtc_resp_sdes: "Optional[str]" = None
        _sdes_webrtcresp_sent = False   # True once we actually publish the SDES webrtcResp
        try:
            await _asyncio.wait_for(
                _asyncio.shield(_echo_fut), timeout=2.0
            )
            _cam_echo_received = True
            _status("camera webrtcReq echo received — building webrtcResp")
            # Seed _sdes_turn_entries from the echo's IceServerList if the HTTP
            # ice_config fetch returned nothing (empty list).  The echo carries
            # our userId TURN credentials — extract them so the hole-punch and
            # any future relay allocation use the correct server/port.
            if not _sdes_turn_entries:
                try:
                    _echo_payload = _echo_fut.result() if (_echo_fut is not None and _echo_fut.done()) else {}
                    for _e in (_echo_payload.get("IceServerList") or []):
                        _e_uris = _e.get("Uris") or []
                        if any("turn:" in str(u) for u in _e_uris):
                            _sdes_turn_entries.append({
                                "Uris":     _e_uris,
                                "Username": _e.get("Username") or "",
                                "Password": str(_e.get("Password") or ""),
                            })
                except Exception:
                    pass
            # Allocate TURN relay if not already done before offer build.
            # When ice_config provided TURN entries, pre-allocation already ran
            # and _relay_addrs is populated — skip to avoid double-allocation.
            if not _relay_addrs:
                try:
                    import re as _re_relay_e, hashlib as _hlk_e
                    _our_te = next(
                        (e for e in _sdes_turn_entries if e.get("Username") == user_id),
                        _sdes_turn_entries[0] if _sdes_turn_entries else None,
                    )
                    if _our_te:
                        _t_uri_e = next(
                            (str(u) for u in (_our_te.get("Uris") or [])
                             if "turn:" in str(u)), ""
                        )
                        _tm_e = _re_relay_e.search(
                            r'turns?:([^:?]+)(?::(\d+))?', _t_uri_e
                        )
                        if _tm_e:
                            _t_host_e = _tm_e.group(1)
                            _t_port_e = int(_tm_e.group(2) or 5349)
                            _t_user_e = (_our_te.get("Username") or "").encode()
                            _t_pass_e = str(_our_te.get("Password") or "").encode()
                            for _alloc_sock_e in (_audio_sock, _video_sock):
                                _alloc_res_e = _turn_allocate_udp(
                                    _alloc_sock_e, _t_host_e, _t_port_e,
                                    _t_user_e, _t_pass_e,
                                )
                                if _alloc_res_e:
                                    _r_ip_e, _r_port_e, _r_realm_e, _r_nonce_e = _alloc_res_e
                                    _r_key_e = _hlk_e.md5(
                                        _t_user_e + b':' + _r_realm_e + b':' + _t_pass_e
                                    ).digest()
                                    _relay_addrs[_alloc_sock_e] = (
                                        _r_ip_e, _r_port_e, _r_realm_e, _r_nonce_e,
                                        _t_host_e, _t_port_e, _r_key_e,
                                    )
                                    _status(
                                        f"TURN relay allocated (echo fallback): "
                                        f"{'audio' if _alloc_sock_e is _audio_sock else 'video'}"
                                        f" → {_r_ip_e}:{_r_port_e}"
                                    )
                except Exception as _relay_early_exc:
                    _LOGGER.warning(
                        "TURN relay allocation error: %s", _relay_early_exc
                    )
            # Answer SDP c= and m= use the TURN relay address when available so
            # the camera sends SRTP to our relay port.  The TURN server then
            # wraps each SRTP packet in a Data Indication and delivers it to
            # audio_sock / video_sock; the bridge thread strips the wrapper and
            # forwards the inner SRTP to ffmpeg's loopback ports.
            # For cameras on the same LAN or when relay allocation failed, fall
            # back to the srflx (public) or local IP.
            _audio_relay = _relay_addrs.get(_audio_sock)
            _video_relay = _relay_addrs.get(_video_sock)
            _ans_audio_ip   = _audio_relay[0] if _audio_relay else (_public_ip or local_ip)
            _ans_audio_port = _audio_relay[1] if _audio_relay else audio_port
            _ans_video_ip   = _video_relay[0] if _video_relay else (_public_ip or local_ip)
            _ans_video_port = _video_relay[1] if _video_relay else video_port
            _relay_answer_sdp = (
                "v=0\r\n"
                f"o=- {ts} {ts} IN IP4 {local_ip}\r\n"
                "s=-\r\n"
                "t=0 0\r\n"
                f"m=audio {_ans_audio_port} RTP/SAVPF 0 8\r\n"
                f"c=IN IP4 {_ans_audio_ip}\r\n"
                "a=sendonly\r\n"
                "a=mid:0\r\n"
                f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{srtp_key_audio}\r\n"
                "a=rtpmap:0 PCMU/8000\r\n"
                "a=rtpmap:8 PCMA/8000\r\n"
                "a=rtcp-mux\r\n"
                f"a=ice-ufrag:{_ufrag_a}\r\n"
                f"a=ice-pwd:{_pwd_a}\r\n"
                f"a=candidate:1 1 udp 2130706431 {local_ip} {audio_port} typ host\r\n"
                + (
                    f"a=candidate:2 1 udp 1694498815 {_public_ip} {audio_port}"
                    f" typ srflx raddr {local_ip} rport {audio_port}\r\n"
                    if _public_ip else ""
                )
                + (
                    f"a=candidate:3 1 udp 16777215 {_relay_addrs[_audio_sock][0]}"
                    f" {_relay_addrs[_audio_sock][1]}"
                    f" typ relay raddr {local_ip} rport {audio_port}\r\n"
                    if _audio_sock in _relay_addrs else ""
                )
                + f"m=video {_ans_video_port} RTP/SAVPF 96 97\r\n"
                f"c=IN IP4 {_ans_video_ip}\r\n"
                "a=sendonly\r\n"
                "a=mid:1\r\n"
                f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{srtp_key_video}\r\n"
                "a=rtpmap:96 H264/90000\r\n"
                "a=fmtp:96 level-asymmetry-allowed=1;packetization-mode=1;"
                "profile-level-id=42e01f\r\n"
                "a=rtpmap:97 H265/90000\r\n"
                "a=fmtp:97 level-id=93\r\n"
                "a=rtcp-mux\r\n"
                f"a=ice-ufrag:{_ufrag_v}\r\n"
                f"a=ice-pwd:{_pwd_v}\r\n"
                f"a=candidate:1 1 udp 2130706431 {local_ip} {video_port} typ host\r\n"
                + (
                    f"a=candidate:2 1 udp 1694498815 {_public_ip} {video_port}"
                    f" typ srflx raddr {local_ip} rport {video_port}\r\n"
                    if _public_ip else ""
                )
                + (
                    f"a=candidate:3 1 udp 16777215 {_relay_addrs[_video_sock][0]}"
                    f" {_relay_addrs[_video_sock][1]}"
                    f" typ relay raddr {local_ip} rport {video_port}\r\n"
                    if _video_sock in _relay_addrs else ""
                )
            )
            _compressed_sdp_ans = _compress_sdp_req(_relay_answer_sdp)

            _webrtc_resp_sdes_topic = f"iot/v1/s/{user_id}/IPC/webrtcResp"
            _webrtc_resp_sdes = json.dumps({
                "method":  "webrtcResp",
                "service": "IPC",
                "devId":   device_id,
                "srcAddr": f"0.{user_id}",
                "seq":     _seq(),
                "tst":     int(time.time() * 1000),
                **( {"userId": numeric_uid_raw} if numeric_uid_raw is not None else {} ),
                "payload": {
                    "peerid":  peer_id,
                    "devId":   device_id,
                    "answer":  {"type": "answer", "sdp": _relay_answer_sdp},
                    "trackId": 0,
                    "dstAddr": device_id,
                    "encOffer": 1,
                    "liveMqtt": 1,
                    # wPayload: newer firmware (e.g. LK.IPC.A001064) parses
                    # wPayload to extract ICE credentials and PSK.  Fields match
                    # reference app o.java (signaling/tyrus).
                    "wPayload": {
                        "peerid": peer_id,
                        "sts":    int(time.time() * 1000),
                        "psk":    _psk_value_req,
                        "answer": {"type": "answer", "sdp": _compressed_sdp_ans},
                    },
                },
            })
            # Send SDES webrtcResp: camera will send SRTP to our public IP/port
            # (srflx), which routes through NAT directly to our socket.
            outgoing_q.put_nowait((_webrtc_resp_sdes_topic, _webrtc_resp_sdes))
            _sdes_webrtcresp_sent = True
            _ans_via = "relay" if (_audio_relay or _video_relay) else "srflx"
            _status(
                f"webrtcResp sent (SDES, {_ans_via} answer:"
                f" audio={_ans_audio_ip}:{_ans_audio_port}"
                f" video={_ans_video_ip}:{_ans_video_port})"
            )
        except _asyncio.TimeoutError:
            pass  # no echo — camera uses a different signalling variant; proceed

        # --- Announce our ICE candidates via MQTT (iceCandidateReq) ----------- #
        # The iOS app always sends iceCandidateReq after webrtcReq/webrtcResp.
        # ICE-capable cameras (e.g. LK.IPC.A001064) wait for this trickle-ICE
        # message before initiating STUN connectivity checks, even when the same
        # candidates are already present in the SDP a=candidate lines.  Without
        # this step the camera sits idle and never sends STUN — resulting in 0
        # frames.  Non-ICE cameras (e.g. LK.IPC.A001513) ignore iceCandidateReq
        # and begin streaming immediately from the SDP exchange, so sending these
        # messages is safe for all camera models.
        _ice_cand_topic_sdes = f"iot/v1/s/{user_id}/IPC/iceCandidateReq"

        def _send_sdes_ice_cand(cand_str: str, mid: str) -> None:
            """Publish a single trickle-ICE candidate via MQTT."""
            _cand_obj = {
                "candidate":     cand_str,
                "sdpMid":        mid,
                "sdpMLineIndex": int(mid),
            }
            _msg = json.dumps({
                "method":  "iceCandidateReq",
                "service": "IPC",
                "devId":   device_id,
                "srcAddr": f"0.{user_id}",
                "seq":     _seq(),
                "tst":     int(time.time() * 1000),
                **( {"userId": numeric_uid_raw} if numeric_uid_raw is not None else {} ),
                "payload": {
                    # dstAddr routes to the camera device, not the user account.
                    # HAR captures confirm payload.dstAddr = deviceId on every
                    # iceCandidateReq; using user_id causes silent drops by firmware.
                    "dstAddr": device_id,
                    # wPayload is the nested format required by newer firmware
                    # (e.g. LK.IPC.A001064) that parses wPayload.candidate instead
                    # of the flat payload.candidate field.
                    "wPayload": {
                        "peerid":    peer_id,
                        "candidate": _cand_obj,
                    },
                    # Flat legacy fields retained for older firmware compatibility.
                    "peerid":    peer_id,
                    "devId":     device_id,
                    "candidate": _cand_obj,
                },
            })
            outgoing_q.put_nowait((_ice_cand_topic_sdes, _msg))

        # --- TURN relay allocation: fallback for cameras that skip the echo path #
        # Early allocation was done inside the echo handler above.  This block
        # handles cameras that did not produce an echo (non-echo-reversal path)
        # so _relay_addrs is still empty at this point.
        if not _relay_addrs:
            try:
                import re as _re_relay, hashlib as _hlk
                _our_turn_entry = None
                for _te in _sdes_turn_entries:
                    if _te.get("Username") == user_id:
                        _our_turn_entry = _te
                        break
                if _our_turn_entry is None and _sdes_turn_entries:
                    _our_turn_entry = _sdes_turn_entries[0]
                if _our_turn_entry:
                    _t_uri_r = next(
                        (str(u) for u in (_our_turn_entry.get("Uris") or [])
                         if "turn:" in str(u)),
                        ""
                    )
                    _tm_r = _re_relay.search(r'turns?:([^:?]+)(?::(\d+))?', _t_uri_r)
                    if _tm_r:
                        _t_host_r = _tm_r.group(1)
                        _t_port_r = int(_tm_r.group(2) or 5349)
                        _t_user_r = (_our_turn_entry.get("Username") or "").encode()
                        _t_pass_r = str(_our_turn_entry.get("Password") or "").encode()
                        for _alloc_sock in (_audio_sock, _video_sock):
                            _alloc_res = _turn_allocate_udp(
                                _alloc_sock, _t_host_r, _t_port_r,
                                _t_user_r, _t_pass_r,
                            )
                            if _alloc_res:
                                _r_ip, _r_port, _r_realm, _r_nonce = _alloc_res
                                _r_key = _hlk.md5(
                                    _t_user_r + b':' + _r_realm + b':' + _t_pass_r
                                ).digest()
                                _relay_addrs[_alloc_sock] = (
                                    _r_ip, _r_port, _r_realm, _r_nonce,
                                    _t_host_r, _t_port_r, _r_key,
                                )
                                _status(
                                    f"TURN relay allocated: "
                                    f"{'audio' if _alloc_sock is _audio_sock else 'video'}"
                                    f" → {_r_ip}:{_r_port}"
                                )
                            else:
                                _LOGGER.warning(
                                    "TURN allocation failed for %s socket",
                                    "audio" if _alloc_sock is _audio_sock else "video",
                                )
            except Exception as _relay_exc:
                _LOGGER.warning("TURN relay allocation error: %s", _relay_exc)

        for _ice_mid, _ice_port in (("0", audio_port), ("1", video_port)):
            # Host candidate (LAN IP)
            _send_sdes_ice_cand(
                f"candidate:1 1 udp 2130706431 {local_ip} {_ice_port} typ host",
                _ice_mid,
            )
            # srflx candidate (public IP) — announced separately so the camera
            # triggers a new ICE check to our public address even if it already
            # processed the SDP host candidate.
            if _public_ip:
                _send_sdes_ice_cand(
                    f"candidate:2 1 udp 1694498815 {_public_ip} {_ice_port}"
                    f" typ srflx raddr {local_ip} rport {_ice_port}",
                    _ice_mid,
                )
            # relay candidate — advertised so the camera can probe us via TURN
            # when direct and srflx paths are blocked (port-restricted NAT).
            _relay_sock = _audio_sock if _ice_mid == "0" else _video_sock
            if _relay_sock in _relay_addrs:
                _ri = _relay_addrs[_relay_sock]
                _send_sdes_ice_cand(
                    f"candidate:3 1 udp 16777215 {_ri[0]} {_ri[1]}"
                    f" typ relay raddr {local_ip} rport {_ice_port}",
                    _ice_mid,
                )
        _status(
            f"iceCandidateReq sent  audio={audio_port}  video={video_port}"
            + (f"  srflx={_public_ip}" if _public_ip else "")
            + (f"  relay={_relay_addrs[_audio_sock][0]}"
               if _audio_sock in _relay_addrs else "")
        )

        # --- NAT hole-punch: create outbound UDP mapping before STUN window --- #
        # Without a prior outbound packet from each socket, most home-router NATs
        # have no mapping for those ports and silently drop the inbound STUN
        # binding requests from the camera.  Sending a minimal STUN binding-
        # request packet to an external host forces the router to create a NAT
        # entry so the camera's probes are forwarded to our sockets.
        _hp_host = "3.230.182.123"   # fallback: Arnoo TURN server
        _hp_port = 3478
        try:
            if _sdes_turn_entries:
                import re as _re_hp
                # Find the first TURN URI in the entry (not just Uris[0], which
                # may be a stun: URI that the regex won't match).
                _hp_uri = next(
                    (str(u) for u in (_sdes_turn_entries[0].get("Uris") or [])
                     if "turn:" in str(u)),
                    ""
                )
                _m_hp = _re_hp.search(r'turns?:([^:?]+)(?::(\d+))?', _hp_uri)
                if _m_hp:
                    _hp_host = _m_hp.group(1)
                    _hp_port = int(_m_hp.group(2) or 3478)
        except Exception:
            pass
        _hp_stun = b'\x00\x01\x00\x00\x21\x12\xa4\x42' + os.urandom(12)
        for _hp_sock in (_audio_sock, _video_sock):
            try:
                _hp_sock.sendto(_hp_stun, (_hp_host, _hp_port))
            except Exception:
                pass
        # Punch to TURN allocation port (5349) as well so port-restricted NAT
        # allows traffic from either TURN port (3478 STUN or 5349 allocation).
        _hp_port2 = 5349
        if _hp_port != _hp_port2:
            for _hp_sock in (_audio_sock, _video_sock):
                try:
                    _hp_sock.sendto(_hp_stun, (_hp_host, _hp_port2))
                except Exception:
                    pass
        _status(
            f"NAT hole-punch: sent from audio={audio_port}"
            f" video={video_port} → {_hp_host}:{_hp_port}"
            + (f" and :{_hp_port2}" if _hp_port != _hp_port2 else "")
        )

        def _is_self_peer_ip(_ip: "Optional[str]") -> bool:
            if not _ip:
                return False
            if _ip in {"127.0.0.1", "0.0.0.0", local_ip}:
                return True
            if _public_ip and _ip == _public_ip:
                return True
            return False

        _selfloop_drop_count = 0
        _bridge_selfloop_drop_count = 0
        _prefer_direct_stun = {_audio_sock: False, _video_sock: False}

        # --- ICE STUN responder (runs while reservation sockets are still open) #
        # Two-phase window:
        #   Normal (no echo-reversal): exit after 0.5 s idle, max 2.5 s total.
        #   Echo-reversal, SDES confirmed (webrtcResp sent): up to 20 s for ICE.
        #   Echo-reversal, dtls_fallback_ok (webrtcResp suppressed): 5 s max —
        #     camera won't stream without webrtcResp so no STUN/SRTP will arrive;
        #     exit quickly so the DTLS fallback starts sooner.
        #   SRTP early exit: if a non-STUN packet arrives (SRTP), ICE is done —
        #     close sockets immediately so ffmpeg can bind.
        import struct as _struct, select as _select
        _STUN_MAGIC = b'\x21\x12\xa4\x42'
        _stun_count = 0
        _stun_seen = False
        _srtp_detected = False
        _stun_window_pkt_count = 0
        _turn_only_pkt_count = 0
        _camera_side_pkt_count = 0
        if not _cam_echo_received:
            _stun_max = 2.5
        elif _sdes_webrtcresp_sent:
            _stun_max = 20.0   # webrtcResp sent — camera may do ICE; give it time
        else:
            _stun_max = 5.0    # webrtcResp suppressed — no STUN expected; exit fast
        _idle_limit = 1.5      # exit after ICE silence once first STUN seen
        _pre_stun_idle = 0.5   # exit early if no packet at all (non-ICE camera)
        _stun_deadline = time.monotonic() + _stun_max
        _last_pkt_t = time.monotonic()
        for _rsock in (_audio_sock, _video_sock):
            try:
                _rsock.setblocking(False)
            except Exception:
                pass
        while time.monotonic() < _stun_deadline:
            # Idle-exit: threshold depends on whether we've seen any STUN yet
            idle = time.monotonic() - _last_pkt_t
            if _stun_seen:
                if idle > _idle_limit:
                    break   # ICE done (silence after STUN) — ffmpeg will pick up SRTP
            elif not _cam_echo_received and idle > _pre_stun_idle:
                break       # no STUN at all — non-ICE camera, skip window
            try:
                _rlist, _, _ = _select.select(
                    [_audio_sock, _video_sock], [], [], 0.1
                )
            except Exception:
                break
            for _sock in _rlist:
                _last_pkt_t = time.monotonic()
                try:
                    _pkt, _src = _sock.recvfrom(2048)
                except OSError:
                    continue
                _stun_window_pkt_count += 1
                if _stun_window_pkt_count <= 3 or _stun_window_pkt_count % 50 == 0:
                    _LOGGER.debug(
                        "STUN window: %d bytes from %s:%d, first4=%s (pkt#%d)",
                        len(_pkt), _src[0], _src[1], _pkt[:4].hex(),
                        _stun_window_pkt_count,
                    )
                # Track packets that are only TURN server control responses
                # (Allocate/permission challenge/success), which do not indicate
                # that the camera actually started ICE checks.
                if _src[0] == _hp_host:
                    _turn_only_pkt_count += 1
                else:
                    _camera_side_pkt_count += 1
                # --- TURN Data Indication (type 0x0017): strip wrapper --------- #
                # Camera ICE probes routed via TURN arrive as Data Indications from
                # 3.230.182.123:5349 (the control channel, already NAT-mapped).
                # Strip the TURN envelope to get the inner STUN Binding Request so
                # we can respond correctly via a TURN Send Indication.
                _turn_peer_ip_sw: "Optional[str]" = None
                _turn_peer_port_sw: "Optional[int]" = None
                if (len(_pkt) >= 20
                        and _pkt[:2] == b'\x00\x17'
                        and _pkt[4:8] == _STUN_MAGIC):
                    _sw_off = 20
                    _sw_inner = None
                    while _sw_off + 4 <= len(_pkt):
                        _sw_at, _sw_al = _struct.unpack_from('!HH', _pkt, _sw_off)
                        _sw_av = _pkt[_sw_off + 4:_sw_off + 4 + _sw_al]
                        _sw_off += 4 + _sw_al + (-_sw_al % 4)
                        if _sw_at == 0x0012 and _sw_al >= 8:  # XOR-PEER-ADDRESS
                            _sw_xp = _struct.unpack_from('!H', _sw_av, 2)[0] ^ 0x2112
                            _sw_xb = bytes(
                                a ^ b for a, b in zip(_sw_av[4:8], _STUN_MAGIC)
                            )
                            _turn_peer_ip_sw = '.'.join(str(b) for b in _sw_xb)
                            _turn_peer_port_sw = _sw_xp
                        elif _sw_at == 0x0013:  # DATA
                            _sw_inner = _sw_av
                    if _sw_inner:
                        _pkt = _sw_inner  # process inner payload
                    # TURN Data Indication with XOR-PEER-ADDRESS means the
                    # camera (or its relay) is actively talking to us.
                    if _turn_peer_ip_sw:
                        _camera_side_pkt_count += 1

                if (len(_pkt) >= 20 and _pkt[4:8] == _STUN_MAGIC):
                    # STUN packet — only Binding Requests (0x0001) indicate that
                    # ICE is active.  Error/Success responses (e.g. hole-punch
                    # replies) must NOT set _stun_seen or they'd trigger the 1.5s
                    # idle-exit prematurely, before camera probes arrive.
                    if _pkt[:2] == b'\x00\x01':
                        # Binding Request — reply with Binding Success Response
                        _stun_seen = True
                        if _turn_peer_ip_sw is None and _src[0] != _hp_host:
                            _prefer_direct_stun[_sock] = True
                        _tid = _pkt[8:20]
                        try:
                            # Use TURN peer address for XOR-MAPPED-ADDRESS when
                            # request arrived via TURN Data Indication.
                            _resp_src_ip = _turn_peer_ip_sw or _src[0]
                            _resp_src_port = _turn_peer_port_sw or _src[1]
                            _resp = _build_stun_binding_success_response(
                                transaction_id=_tid,
                                mapped_ip=_resp_src_ip,
                                mapped_port=_resp_src_port,
                                mi_password=(
                                    _pwd_a if _sock is _audio_sock else _pwd_v
                                ),
                                magic_cookie=_STUN_MAGIC,
                            )
                            if _turn_peer_ip_sw and _prefer_direct_stun.get(_sock, False):
                                pass
                            elif (_turn_peer_ip_sw and _sock in _relay_addrs
                                    and not _is_self_peer_ip(_turn_peer_ip_sw)):
                                # Arrived via TURN — respond via Send Indication
                                _ri_sw = _relay_addrs[_sock]
                                _t_host_sw, _t_port_sw = _ri_sw[4], _ri_sw[5]
                                _si_pip = bytes(
                                    int(x) for x in _turn_peer_ip_sw.split('.')
                                )
                                _si_xip = bytes(
                                    a ^ b for a, b in zip(_si_pip, _STUN_MAGIC)
                                )
                                _si_xport = (_turn_peer_port_sw ^ 0x2112) & 0xFFFF
                                _si_xpa = (b'\x00\x01'
                                           + _struct.pack('!H', _si_xport)
                                           + _si_xip)

                                def _si_a(_t, _v):
                                    _p = (-len(_v)) % 4
                                    return (_struct.pack('!HH', _t, len(_v))
                                            + _v + b'\x00' * _p)

                                _si_body = _si_a(0x0012, _si_xpa) + _si_a(0x0013, _resp)
                                _send_ind = (b'\x00\x16'
                                             + _struct.pack('!H', len(_si_body))
                                             + _STUN_MAGIC + os.urandom(12)
                                             + _si_body)
                                _sock.sendto(_send_ind, (_t_host_sw, _t_port_sw))
                            elif _turn_peer_ip_sw and _is_self_peer_ip(_turn_peer_ip_sw):
                                # Self-loop Data Indication (peer == our own
                                # local/srflx address). Responding via TURN
                                # creates an endless STUN echo loop and no media.
                                # Drop it and wait for real camera checks.
                                _selfloop_drop_count += 1
                                if _selfloop_drop_count <= 5 or _selfloop_drop_count % 50 == 0:
                                    _LOGGER.debug(
                                        "STUN window: drop TURN self-loop peer %s:%s"
                                        " (count=%d)",
                                        _turn_peer_ip_sw, _turn_peer_port_sw,
                                        _selfloop_drop_count,
                                    )
                            else:
                                _sock.sendto(_resp, _src)
                            _stun_count += 1
                        except Exception:
                            pass
                else:
                    # Non-STUN packet = SRTP arriving — ICE is done, hand off to ffmpeg now
                    _srtp_detected = True
                    break   # inner per-socket loop
            if _srtp_detected:
                break       # outer while loop
        for _rsock in (_audio_sock, _video_sock):
            try:
                _rsock.setblocking(True)
            except Exception:
                pass
        if _stun_count:
            _status(f"ICE: responded to {_stun_count} STUN binding request(s)")
        elif not _srtp_detected:
            if _stun_window_pkt_count and _turn_only_pkt_count == _stun_window_pkt_count:
                _status(
                    "ICE: no camera probes seen in STUN window"
                    f" (received {_stun_window_pkt_count} TURN-server control packet(s) only)"
                )
            else:
                _status(
                    "ICE: 0 camera STUN binding requests in window"
                    f" (total packets={_stun_window_pkt_count})"
                )
        if _srtp_detected:
            _status("SRTP detected — exiting STUN window, handing off to ffmpeg")

        # --- Reconnect retry: camera may quickConn during synchronous STUN window #
        # LK.IPC.A001064 performs an MQTT disconnect+reconnect (quickConn) after
        # receiving WebRTC signaling.  The synchronous select() loop above blocks
        # asyncio entirely, so camera_reconnect_ev.set() is queued but not
        # processed until asyncio.sleep(0) runs.  After flushing the queue, check
        # for the reconnect and re-send webrtcResp + ICE candidates so the camera
        # can restart its ICE agent.  Allow up to 2 retries.
        _sdes_retries = 0
        while (_cam_echo_received
               and _stun_count == 0
               and not _srtp_detected
               and camera_reconnect_ev is not None
               and _sdes_retries < 2):
            await asyncio.sleep(0)   # flush queued callbacks (reconnect_ev.set())
            if not camera_reconnect_ev.is_set():
                break
            camera_reconnect_ev.clear()
            _sdes_retries += 1
            _status(
                f"camera reconnected during SDES ICE window (retry {_sdes_retries})"
                " — re-sending webrtcResp + ICE candidates"
            )
            await asyncio.sleep(0.3)   # let camera re-subscribe before re-send
            if _webrtc_resp_sdes is not None and _sdes_webrtcresp_sent:
                # Only re-send webrtcResp if we sent it originally (isDTLS='0').
                # For dtls_fallback_ok cameras the SDES session was intentionally
                # suppressed — do not retroactively start one on reconnect.
                outgoing_q.put_nowait((_webrtc_resp_sdes_topic, _webrtc_resp_sdes))
            for _ice_mid_r, _ice_port_r in (("0", audio_port), ("1", video_port)):
                _send_sdes_ice_cand(
                    f"candidate:1 1 udp 2130706431 {local_ip} {_ice_port_r}"
                    " typ host",
                    _ice_mid_r,
                )
                if _public_ip:
                    _send_sdes_ice_cand(
                        f"candidate:2 1 udp 1694498815 {_public_ip} {_ice_port_r}"
                        f" typ srflx raddr {local_ip} rport {_ice_port_r}",
                        _ice_mid_r,
                    )
                _relay_sock_r = _audio_sock if _ice_mid_r == "0" else _video_sock
                if _relay_sock_r in _relay_addrs:
                    _ri_r = _relay_addrs[_relay_sock_r]
                    _send_sdes_ice_cand(
                        f"candidate:3 1 udp 16777215 {_ri_r[0]} {_ri_r[1]}"
                        f" typ relay raddr {local_ip} rport {_ice_port_r}",
                        _ice_mid_r,
                    )
            # Refresh NAT mapping so router allows new inbound STUN from camera
            for _hp_sock_r in (_audio_sock, _video_sock):
                try:
                    _hp_sock_r.sendto(_hp_stun, (_hp_host, _hp_port))
                except Exception:
                    pass
            # Retry STUN window (8 s)
            _stun_deadline = time.monotonic() + 8.0
            _last_pkt_t = time.monotonic()
            _stun_seen = False
            while time.monotonic() < _stun_deadline:
                if _stun_seen and time.monotonic() - _last_pkt_t > _idle_limit:
                    break
                try:
                    _rlist_r, _, _ = _select.select(
                        [_audio_sock, _video_sock], [], [], 0.1
                    )
                except Exception:
                    break
                for _sk_r in _rlist_r:
                    _last_pkt_t = time.monotonic()
                    try:
                        _pkt_r, _src_r = _sk_r.recvfrom(2048)
                    except OSError:
                        continue
                    if (len(_pkt_r) >= 20
                            and _pkt_r[4:8] == _STUN_MAGIC):
                        if _pkt_r[:2] != b'\x00\x01':
                            continue   # not a Binding Request; don't trigger idle-exit
                        _stun_seen = True
                        _tid_r = _pkt_r[8:20]
                        try:
                            _resp_r = _build_stun_binding_success_response(
                                transaction_id=_tid_r,
                                mapped_ip=_src_r[0],
                                mapped_port=_src_r[1],
                                mi_password=(
                                    _pwd_a if _sk_r is _audio_sock else _pwd_v
                                ),
                                magic_cookie=_STUN_MAGIC,
                            )
                            _sk_r.sendto(_resp_r, _src_r)
                            _stun_count += 1
                        except Exception:
                            pass
                    else:
                        _srtp_detected = True
                        break
                if _srtp_detected:
                    break
            if _stun_count:
                _status(
                    f"ICE retry {_sdes_retries}:"
                    f" responded to {_stun_count} STUN binding request(s)"
                )
            if _srtp_detected:
                _status(
                    f"SRTP detected in retry {_sdes_retries}"
                    " — exiting STUN window, handing off to ffmpeg"
                )

        # --- Harvest camera's webrtcResp answer (may have arrived during STUN window) --- #
        # The asyncio event loop was blocked by the synchronous STUN loop.  Any
        # call_soon_threadsafe(answer_fut.set_result, …) from the MQTT thread is
        # queued but hasn't fired yet.  One asyncio cycle resolves it.
        await asyncio.sleep(0)
        _pre_launch_answer_sdp: str = ""
        _our_tx_srtp_key_audio = srtp_key_audio  # our TX key; set early in case answer absent
        _cam_key_audio: str = ""   # camera's answer key; set in SDP parse block below
        _cam_key_video: str = ""   # camera's video SRTP key; set in SDP parse block below
        _dc_answer_has_app: bool = False  # set True if camera echoes m=application; init here so bridge closure never sees NameError on late-wake path
        _sctp: dict = {              # initialized here for the same reason — bridge closure
            'state': 'CLOSED', 'local_tag': 0, 'peer_tag': 0,
            'local_tsn': 0, 'stream_seq': 0,
        }
        if answer_fut.done():
            try:
                _pre_ans = answer_fut.result()
                _pre_launch_answer_sdp = (_pre_ans or {}).get("sdp", "")
            except Exception:
                pass
        if _pre_launch_answer_sdp:
            _LOGGER.debug(
                "_open_sdes_stream: camera webrtcResp answer SDP (len=%d)",
                len(_pre_launch_answer_sdp),
            )
            import re as _re

            def _sdes_key_from_sdp(sdp, media):
                """Return the inline key from the first a=crypto line in the named m-section."""
                in_sec = False
                for ln in sdp.splitlines():
                    if ln.startswith(f"m={media}"):
                        in_sec = True
                    elif ln.startswith("m=") and in_sec:
                        break
                    elif in_sec and ln.startswith("a=crypto:"):
                        _m = _re.search(r"inline:([A-Za-z0-9+/=]+)", ln)
                        if _m:
                            return _m.group(1)
                return ""

            # Probe result: did camera echo back m=application?
            if _dc_probe_fp:
                _dc_ans_lines, _in_dc_sec = [], False
                for _aln in _pre_launch_answer_sdp.splitlines():
                    if _aln.startswith("m=application"):
                        _in_dc_sec = True
                    elif _aln.startswith("m=") and _in_dc_sec:
                        break
                    if _in_dc_sec:
                        _dc_ans_lines.append(_aln)
                if _dc_ans_lines:
                    _status(
                        "DC probe ACCEPTED: camera answered m=application"
                        f" ({len(_dc_ans_lines)} lines):\n"
                        + "\n".join(_dc_ans_lines)
                    )
                else:
                    _status(
                        "DC probe REJECTED: camera did not include m=application"
                        " in its answer — BUNDLE+DTLS unsupported on this firmware"
                    )

            # SCTP DataChannel for SDES cameras.
            # Source analysis (f0.java g2()) confirmed SESSION_MODE_REQ (5376)
            # must be sent via DataChannel.send(), NOT raw TUTK 0xC8 UDP.
            # Camera uses plain SCTP over UDP (same ICE port), no DTLS.
            # We are the SCTP client (proactive INIT), camera is server.
            _dc_answer_has_app = "m=application" in _pre_launch_answer_sdp
            _sctp = {
                'state': 'CLOSED',    # INIT_SENT → COOKIE_ECHOED → ESTABLISHED → DONE
                'local_tag': 0,       # our verification tag (sent in INIT)
                'peer_tag': 0,        # camera's verification tag (from INIT-ACK)
                'local_tsn': 0,       # our TSN counter
                'stream_seq': 0,      # stream sequence number
            }

            _cam_key_audio = _sdes_key_from_sdp(_pre_launch_answer_sdp, "audio")
            _cam_key_video = _sdes_key_from_sdp(_pre_launch_answer_sdp, "video")
            if _cam_key_audio and _cam_key_audio != srtp_key_audio:
                _status("Using camera's audio SRTP key from answer (was our offer key)")
                srtp_key_audio = _cam_key_audio
            if _cam_key_video and _cam_key_video != srtp_key_video:
                _status("Using camera's video SRTP key from answer (was our offer key)")
                srtp_key_video = _cam_key_video
            # Rewrite SDP file on disk with the (potentially updated) keys.
            # TUTK cameras (A001064/A001513) probe with TUTK 0xC8 frames then
            # switch to SRTP after the stream trigger.  Use SAVPF + crypto so
            # ffmpeg can decrypt real SRTP.  Synthesized fake-RTP probe packets
            # are plain and will fail SRTP auth (ffmpeg skips them); real SRTP
            # audio/video will decode correctly.
            _ts = int(time.time())
            if _use_plain_rtp:
                # RTP/AVP (no crypto) because we decrypt SDES ourselves and
                # forward plain RTP to ffmpeg; ffmpeg must not expect SRTP auth.
                _updated_sdp = (
                    "v=0\r\n"
                    f"o=- {_ts} {_ts} IN IP4 0.0.0.0\r\n"
                    "s=aidot-tutk-rx\r\n"
                    "t=0 0\r\n"
                    f"m=audio {audio_port} RTP/AVP 0 8\r\n"
                    "c=IN IP4 0.0.0.0\r\n"
                    "a=rtpmap:0 PCMU/8000\r\n"
                    "a=rtpmap:8 PCMA/8000\r\n"
                    "a=rtcp-mux\r\n"
                    f"m=video {video_port} RTP/AVP 96 97 98\r\n"
                    "c=IN IP4 0.0.0.0\r\n"
                    "a=rtpmap:96 H264/90000\r\n"
                    "a=fmtp:96 level-asymmetry-allowed=1;packetization-mode=1;"
                    "profile-level-id=42e01f\r\n"
                    "a=rtpmap:97 H265/90000\r\n"
                    "a=fmtp:97 level-id=93\r\n"
                    "a=rtpmap:98 H265/90000\r\n"
                    "a=fmtp:98 level-id=93\r\n"
                    "a=rtcp-mux\r\n"
                )
            else:
                _updated_sdp = (
                    "v=0\r\n"
                    f"o=- {_ts} {_ts} IN IP4 0.0.0.0\r\n"
                    "s=aidot-sdes-rx\r\n"
                    "t=0 0\r\n"
                    f"m=audio {audio_port} RTP/SAVPF 0 8\r\n"
                    "c=IN IP4 0.0.0.0\r\n"
                    f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{srtp_key_audio}\r\n"
                    "a=rtpmap:0 PCMU/8000\r\n"
                    "a=rtpmap:8 PCMA/8000\r\n"
                    "a=rtcp-mux\r\n"
                    f"m=video {video_port} RTP/SAVPF 96 97\r\n"
                    "c=IN IP4 0.0.0.0\r\n"
                    f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{srtp_key_video}\r\n"
                    "a=rtpmap:96 H264/90000\r\n"
                    "a=fmtp:96 level-asymmetry-allowed=1;packetization-mode=1;"
                    "profile-level-id=42e01f\r\n"
                    "a=rtpmap:97 H265/90000\r\n"
                    "a=fmtp:97 level-id=93\r\n"
                    "a=rtcp-mux\r\n"
                )
            try:
                with open(sdp_path, "w") as _sdp_f:
                    _sdp_f.write(_updated_sdp)
            except Exception as _sdp_exc:
                _LOGGER.warning("_open_sdes_stream: could not rewrite SDP: %s", _sdp_exc)

        # --- SCTP helper functions (always defined — even when answer arrives late) --- #
        def _crc32c_fn(data):
            crc = 0xFFFFFFFF
            for b in data:
                crc ^= b
                for _ in range(8):
                    crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
            return crc ^ 0xFFFFFFFF

        def _sctp_pkt(vtag, *chunks):
            import struct as _st_sc
            base = _st_sc.pack('!HHII', 5000, 5000, vtag, 0) + b''.join(chunks)
            crc = _crc32c_fn(base)
            return base[:8] + _st_sc.pack('<I', crc) + base[12:]  # camera usrsctp uses LE CRC32c

        def _sctp_chunk(ctype, flags, data):
            import struct as _st_sc
            n = 4 + len(data)
            raw = _st_sc.pack('!BBH', ctype, flags, n) + data
            return raw + b'\x00' * ((-len(raw)) % 4)

        def _sctp_init():
            import struct as _st_sc, random as _r_sc
            if _sctp['local_tag'] == 0:
                _sctp['local_tag'] = _r_sc.randint(1, 0xFFFFFFFF)
                _sctp['local_tsn'] = _r_sc.randint(1, 0xFFFFFFFF)
            body = _st_sc.pack('!IIHHI', _sctp['local_tag'],
                               131072, 1024, 2048, _sctp['local_tsn'])
            return _sctp_pkt(0, _sctp_chunk(0x01, 0, body))

        def _sctp_parse_init_ack(pkt):
            import struct as _st_sc
            pos = 12
            while pos + 4 <= len(pkt):
                ctype, _, clen = _st_sc.unpack_from('!BBH', pkt, pos)
                if clen < 4:
                    break
                cdata = pkt[pos + 4:pos + clen]
                if ctype == 0x02 and len(cdata) >= 16:
                    peer_tag = _st_sc.unpack_from('!I', cdata)[0]
                    peer_tsn = _st_sc.unpack_from('!I', cdata, 12)[0]
                    _sctp['peer_tag'] = peer_tag
                    _sctp['local_tsn'] = peer_tsn
                    pp = 16
                    while pp + 4 <= len(cdata):
                        ptype, plen = _st_sc.unpack_from('!HH', cdata, pp)
                        if plen < 4:
                            break
                        if ptype == 7:  # State Cookie
                            return cdata[pp + 4:pp + plen]
                        pp += max(4, (plen + 3) & ~3)
                pos += max(4, (clen + 3) & ~3)
            return None

        def _sctp_parse_init(pkt):
            import struct as _st_sc
            pos = 12
            while pos + 4 <= len(pkt):
                ctype, _, clen = _st_sc.unpack_from('!BBH', pkt, pos)
                if clen < 4:
                    break
                cdata = pkt[pos + 4:pos + clen]
                if ctype == 0x01 and len(cdata) >= 16:
                    peer_tag = _st_sc.unpack_from('!I', cdata)[0]
                    peer_tsn = _st_sc.unpack_from('!I', cdata, 12)[0]
                    _sctp['peer_tag'] = peer_tag
                    _sctp['peer_tsn'] = peer_tsn
                    return peer_tag
                pos += max(4, (clen + 3) & ~3)
            return None

        def _sctp_init_ack_pkt():
            import struct as _st_sc, random as _r_sc
            # RFC 4960 §5.2.1: reuse local_tag/tsn from our INIT in simultaneous open
            if _sctp['local_tag'] == 0:
                _sctp['local_tag'] = _r_sc.randint(1, 0xFFFFFFFF)
                _sctp['local_tsn'] = _r_sc.randint(1, 0xFFFFFFFF)
            cookie = _st_sc.pack('!II', _sctp['local_tag'], _sctp['peer_tag'])
            cookie_param = _st_sc.pack('!HH', 7, 4 + len(cookie)) + cookie
            body = (_st_sc.pack('!IIHHI', _sctp['local_tag'],
                                131072, 1024, 2048, _sctp['local_tsn'])
                    + cookie_param)
            return _sctp_pkt(_sctp['peer_tag'], _sctp_chunk(0x02, 0, body))

        def _sctp_cookie_echo(cookie):
            return _sctp_pkt(_sctp['peer_tag'], _sctp_chunk(0x0A, 0, cookie))

        def _sctp_data(ppid, payload):
            import struct as _st_sc
            tsn = _sctp['local_tsn']
            _sctp['local_tsn'] = (tsn + 1) & 0xFFFFFFFF
            seq = _sctp['stream_seq']
            _sctp['stream_seq'] = (seq + 1) & 0xFFFF
            body = _st_sc.pack('!IHHI', tsn, 0, seq, ppid) + payload
            return _sctp_chunk(0x00, 0x03, body)

        def _dcep_open_msg():
            import struct as _st_sc
            label = b'data'
            return (_st_sc.pack('!BBHIHH', 0x03, 0x00, 256, 0, len(label), 0)
                    + label)

        def _session_mode_req_msg():
            import struct as _st_sc, random as _r_sc, time as _t_sc
            seq = _r_sc.randint(0, 0x7FFFFFFF)
            ts  = int(_t_sc.time() * 1000)
            return (_st_sc.pack('<IIqII4x', seq, 5376, ts, 8, 0)
                    + _st_sc.pack('<IB3x', 0, 1))

        def _sctp_send_living(sock, addr):
            dcep   = _sctp_data(50, _dcep_open_msg())
            living = _sctp_data(53, _session_mode_req_msg())
            sock.sendto(_sctp_pkt(_sctp['peer_tag'], dcep), addr)
            sock.sendto(_sctp_pkt(_sctp['peer_tag'], living), addr)
            _sctp['state'] = 'DONE'
            _status("SDES DC: sent DATA_CHANNEL_OPEN + SESSION_MODE_REQ(5376) via SCTP")

        # --- ICE controlling: send STUN Binding Requests with USE-CANDIDATE --- #
        # The camera is a full-ICE controlled agent (RFC 8445).  It sends STUN
        # binding requests to our candidates (verified above), but it will NOT
        # send SRTP until the controlling agent (us) nominates an ICE pair by
        # sending a binding request with the USE-CANDIDATE attribute (0x0025).
        # Without this, the camera stays in ICE "Checking" state indefinitely
        # (hence the continuous duplicate STUN probe log lines) and never streams.
        import re as _re_ice

        # Parse camera's ICE credentials and UDP candidates from its answer SDP.
        _cam_ice_ufrag: str = ""
        _cam_ice_pwd:   str = ""
        _cam_ice_cands: list = []   # list of (ip, port) tuples

        _cam_ice_host: tuple = ()    # (ip, port) of typ host candidate for SCTP
        if _pre_launch_answer_sdp:
            for _ice_ln in _pre_launch_answer_sdp.splitlines():
                if _ice_ln.startswith("a=ice-ufrag:") and not _cam_ice_ufrag:
                    _cam_ice_ufrag = _ice_ln[len("a=ice-ufrag:"):].strip()
                elif _ice_ln.startswith("a=ice-pwd:") and not _cam_ice_pwd:
                    _cam_ice_pwd = _ice_ln[len("a=ice-pwd:"):].strip()
                elif _ice_ln.startswith("a=candidate:"):
                    _cand_m = _re_ice.match(
                        r"a=candidate:\S+ \d+ udp \d+ ([\d.]+) (\d+) typ (\w+)",
                        _ice_ln,
                    )
                    if _cand_m:
                        _cip, _cport = _cand_m.group(1), int(_cand_m.group(2))
                        _ctyp = _cand_m.group(3)
                        _cam_ice_cands.append((_cip, _cport))
                        if _ctyp == "host" and not _cam_ice_host:
                            _cam_ice_host = (_cip, _cport)

        def _send_use_candidate(sock, our_ufrag, our_pwd, cam_ufrag, cam_pwd, cam_addr):
            """Send a STUN Binding Request with ICE-CONTROLLING + USE-CANDIDATE."""
            import struct as _st_uc, os as _os_uc, hmac as _hm_uc, hashlib as _hs_uc
            _MAGIC_UC = b'\x21\x12\xa4\x42'
            _tid_uc = _os_uc.urandom(12)
            _user = f"{cam_ufrag}:{our_ufrag}".encode()
            _user_a = (
                _st_uc.pack('!HH', 0x0006, len(_user))
                + _user + b'\x00' * ((-len(_user)) % 4)
            )
            _tiebreaker = int.from_bytes(_os_uc.urandom(8), 'big')
            _ctrl_a = _st_uc.pack('!HHQ', 0x802a, 8, _tiebreaker)  # ICE-CONTROLLING
            _prio_a = _st_uc.pack('!HHI', 0x0024, 4, 1845493759)   # PRIORITY (prflx)
            _uc_a   = _st_uc.pack('!HH',  0x0025, 0)               # USE-CANDIDATE
            _attrs  = _user_a + _ctrl_a + _prio_a + _uc_a
            _mi_len = len(_attrs) + 24
            _mi_in  = _st_uc.pack('!HH', 0x0001, _mi_len) + _MAGIC_UC + _tid_uc + _attrs
            _mi     = _hm_uc.new(cam_pwd.encode(), _mi_in, _hs_uc.sha1).digest()
            _mi_a   = _st_uc.pack('!HH', 0x0008, 20) + _mi
            _total  = len(_attrs) + len(_mi_a)
            # FINGERPRINT (RFC 5389 §15.5): CRC32 XOR 0x5354554E, after MI.
            # KVS SDK silently drops binding requests without a valid FINGERPRINT.
            # MI is computed with length=_total (end-of-MI); FINGERPRINT uses
            # length=_total+8.  The camera strips FINGERPRINT before verifying MI,
            # so the MI value is unchanged.
            import zlib as _zl_uc
            _fp_total = _total + 8
            _req_for_fp = (
                _st_uc.pack('!HH', 0x0001, _fp_total)
                + _MAGIC_UC + _tid_uc + _attrs + _mi_a
            )
            _fp_val = (_zl_uc.crc32(_req_for_fp) & 0xFFFFFFFF) ^ 0x5354554E
            _fp_a   = _st_uc.pack('!HHI', 0x8028, 4, _fp_val)
            _req    = _req_for_fp + _fp_a
            try:
                sock.sendto(_req, cam_addr)
            except Exception:
                pass

        if _cam_ice_ufrag and _cam_ice_pwd and _cam_ice_cands:
            for _c_ip, _c_port in _cam_ice_cands:
                _send_use_candidate(
                    _audio_sock, _ufrag_a, _pwd_a,
                    _cam_ice_ufrag, _cam_ice_pwd, (_c_ip, _c_port),
                )
                _send_use_candidate(
                    _video_sock, _ufrag_v, _pwd_v,
                    _cam_ice_ufrag, _cam_ice_pwd, (_c_ip, _c_port),
                )
            _status(
                f"ICE controlling: sent USE-CANDIDATE to"
                f" {len(_cam_ice_cands)} camera candidate(s)"
                f" ({_cam_ice_cands[0][0]}:{_cam_ice_cands[0][1]})"
            )
            # SCTP client: INIT will be sent from the bridge thread on BindingSucc.
        else:
            _status(
                "ICE controlling: no camera ICE credentials in answer"
                " (pre-answer or relay-only path)"
            )

        # --- Bridge thread: keep reservation sockets open for ICE + SRTP ----- #
        # The camera's ICE agent sends STUN Binding Requests to audio_port and
        # video_port AFTER this point.  If we close those sockets and let ffmpeg
        # bind them, ffmpeg cannot respond to STUN → ICE fails → camera never
        # sends SRTP → 0-byte output file.
        #
        # Fix: allocate fresh loopback ports for ffmpeg, rewrite the SDP to point
        # at those ports, and keep the original sockets alive in a bridge thread
        # that:
        #   • responds to STUN Binding Requests on the original sockets
        #   • forwards all non-STUN packets (SRTP) to ffmpeg's loopback ports
        # When the session ends, SdesSession.stop() closes the original sockets,
        # which causes the bridge thread's select() to raise and it exits cleanly.
        import threading as _threading_br, socket as _socket_br

        def _alloc_lo_port():
            _s = _socket_br.socket(_socket_br.AF_INET, _socket_br.SOCK_DGRAM)
            try:
                _s.bind(('127.0.0.1', 0))
                return _s.getsockname()[1]
            finally:
                _s.close()

        _lo_audio_port = _alloc_lo_port()
        _lo_video_port = _alloc_lo_port()

        # Rewrite SDP to point ffmpeg at the loopback ports.
        # TUTK cameras use plain RTP/AVP (no SRTP): the bridge synthesizes
        # standard RTP packets from TUTK SFrames and forwards without crypto.
        _ts_br = int(time.time())
        if _use_plain_rtp:
            _br_sdp = (
                "v=0\r\n"
                f"o=- {_ts_br} {_ts_br} IN IP4 0.0.0.0\r\n"
                "s=aidot-tutk-rx\r\n"
                "t=0 0\r\n"
                f"m=audio {_lo_audio_port} RTP/AVP 0 8\r\n"
                "c=IN IP4 127.0.0.1\r\n"
                "a=rtpmap:0 PCMU/8000\r\n"
                "a=rtpmap:8 PCMA/8000\r\n"
                "a=rtcp-mux\r\n"
                f"m=video {_lo_video_port} RTP/AVP 96 97\r\n"
                "c=IN IP4 127.0.0.1\r\n"
                "a=rtpmap:96 H264/90000\r\n"
                "a=fmtp:96 level-asymmetry-allowed=1;packetization-mode=1;"
                "profile-level-id=42e01f\r\n"
                "a=rtpmap:97 H265/90000\r\n"
                "a=fmtp:97 level-id=93\r\n"
                "a=rtcp-mux\r\n"
            )
        else:
            _br_sdp = (
                "v=0\r\n"
                f"o=- {_ts_br} {_ts_br} IN IP4 0.0.0.0\r\n"
                "s=aidot-sdes-rx\r\n"
                "t=0 0\r\n"
                f"m=audio {_lo_audio_port} RTP/SAVP 0 8\r\n"
                "c=IN IP4 127.0.0.1\r\n"
                f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{srtp_key_audio}\r\n"
                "a=rtpmap:0 PCMU/8000\r\n"
                "a=rtpmap:8 PCMA/8000\r\n"
                "a=rtcp-mux\r\n"
                f"m=video {_lo_video_port} RTP/SAVP 96 97\r\n"
                "c=IN IP4 127.0.0.1\r\n"
                f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{srtp_key_video}\r\n"
                "a=rtpmap:96 H264/90000\r\n"
                "a=fmtp:96 level-asymmetry-allowed=1;packetization-mode=1;"
                "profile-level-id=42e01f\r\n"
                "a=rtpmap:97 H265/90000\r\n"
                "a=fmtp:97 level-id=93\r\n"
                "a=rtcp-mux\r\n"
            )
        try:
            with open(sdp_path, "w") as _br_sdp_f:
                _br_sdp_f.write(_br_sdp)
        except Exception as _br_sdp_exc:
            _LOGGER.warning("bridge: could not rewrite SDP: %s", _br_sdp_exc)

        # Shared channel: bridge thread sets [0] to a persistent send function
        # once the SCTP DataChannel is established.  SdesSession reads it via
        # _cmd_chan[0] to dispatch PTZ / IOCtrl commands from the main thread.
        _cmd_chan: list = [None]
        # Proc holder: set to the ffmpeg Popen object after launch so the
        # bridge thread can poll for exit without a NameError race.
        _proc_holder: list = [None]

        def _bridge_fn():
            nonlocal _br_first_di_logged, _br_first_srtp_logged, _br_first_req_dumped
            nonlocal _br_first_audio_logged, _br_first_video_logged, _avio_living_sent
            _STUN_MAGIC_BR = b'\x21\x12\xa4\x42'
            import struct as _st_br, select as _sel_br, time as _time_br
            _br_prefer_direct_stun = {_audio_sock: False, _video_sock: False}
            _br_last_uc = 0.0
            _br_stun_resp_count = 0
            _tutk_trigger_sent = False
            _last_trigger_ts    = 0.0     # time of last AVIO LIVING send
            _trigger_bs         = None    # socket used for trigger
            _trigger_bsrc       = None    # camera addr for trigger
            _sdes_probe_received = False  # True after first 0xC8 probe from camera
            _last_hb_ts         = 0.0     # time of last AVIO HEARTBEAT send
            _lo_a = _socket_br.socket(_socket_br.AF_INET, _socket_br.SOCK_DGRAM)
            _lo_v = _socket_br.socket(_socket_br.AF_INET, _socket_br.SOCK_DGRAM)
            try:
                while True:
                    try:
                        _rl, _, _ = _sel_br.select(
                            [_audio_sock, _video_sock], [], [], 0.5
                        )
                    except Exception:
                        break
                    # Stop the bridge when ffmpeg exits (normal end or crash).
                    _br_proc = _proc_holder[0]
                    if _br_proc is not None:
                        _br_rc = _br_proc.poll()
                        if _br_rc is not None:
                            if _br_rc != 0:
                                import logging as _log_br
                                _log_br.getLogger(__name__).warning(
                                    "SDES bridge: ffmpeg exited with code %d"
                                    " — stream ended", _br_rc
                                )
                            break

                    # AVIO HEARTBEAT (cmd=5156) + AUDIOSTART (cmd=768) every 10s
                    # after first probe received. Mirrors the DTLS keepalive path:
                    # heartbeat keeps the session alive; AUDIOSTART explicitly enables
                    # the audio/video stream (confirmed needed on A000088 DTLS cameras).
                    if (_sdes_probe_received
                            and _trigger_bs is not None
                            and _time_br.time() - _last_hb_ts >= 10.0):
                        import struct as _st_hb, random as _r_hb
                        _hb_ts  = int(_time_br.time() * 1000)
                        try:
                            from Crypto.Cipher import AES as _AES_hb
                            from Crypto.Util.Padding import pad as _pad_hb
                            _hb_k  = _our_tx_srtp_key_audio[:16].encode('ascii')
                            _hb_iv = (_cam_key_audio or _our_tx_srtp_key_audio)[:16].encode('ascii')
                        except Exception:
                            _hb_k = _hb_iv = None

                        def _sdes_send_cmd(_cmd, _extra=b''):
                            _seq = _r_hb.randint(0, 0x7FFFFFFF)
                            _pl = _st_hb.pack('<IIqII4x', _seq, _cmd, _hb_ts,
                                              len(_extra), 0) + _extra
                            _enc = None
                            if _hb_k:
                                try:
                                    _enc = _AES_hb.new(
                                        _hb_k, _AES_hb.MODE_CBC, _hb_iv,
                                    ).encrypt(_pad_hb(_pl, 16))
                                except Exception:
                                    pass
                            for _p in [_enc, _pl]:
                                if _p is None:
                                    continue
                                _sz = len(_p)
                                try:
                                    _trigger_bs.sendto(
                                        bytes([0xC8, 0x00, _sz >> 8, _sz & 0xFF]) + _p,
                                        _trigger_bsrc,
                                    )
                                except Exception:
                                    pass

                        _sdes_send_cmd(5156)             # HEARTBEAT: data_len=0
                        _sdes_send_cmd(768, b'\x00'*8)  # AUDIOSTART: 8B zero payload
                        _last_hb_ts = _time_br.time()
                        _status(
                            f"SDES: sent HEARTBEAT+AUDIOSTART"
                            f" → {_trigger_bsrc[0]}:{_trigger_bsrc[1]}"
                        )

                    # RTCP PLI (Picture Loss Indication) — forces camera to
                    # resend IDR + VPS/SPS/PPS so ffmpeg gets codec params
                    # within the analyzeduration window even if the initial
                    # parameter sets arrived before ffmpeg was listening.
                    # Fire every 5 s while video SSRC is known; triggered
                    # immediately (ts=0) on first video packet arrival.
                    if (hasattr(_bridge_fn, '_cam_video_ssrc')
                            and hasattr(_bridge_fn, '_cam_srtp_sock')
                            and _time_br.time() - getattr(
                                _bridge_fn, '_last_pli_ts', 0.0) >= 5.0):
                        import base64 as _b64_pli
                        _pli_sender_ssrc = 0xAB12CD34
                        _pli_media_ssrc  = _bridge_fn._cam_video_ssrc
                        _pli_raw = _st_br.pack(
                            '!BBHII',
                            0x81, 206, 2,
                            _pli_sender_ssrc,
                            _pli_media_ssrc,
                        )
                        _pli_sent = False
                        try:
                            import pylibsrtp as _plsrtp_pli
                            if not hasattr(_bridge_fn, '_pli_tx_sess'):
                                _pli_key_b64 = (
                                    _our_tx_srtp_key_audio
                                    or srtp_key_audio
                                )
                                _pli_pol = _plsrtp_pli.Policy(
                                    key=_b64_pli.b64decode(_pli_key_b64),
                                    ssrc_type=_plsrtp_pli.Policy.SSRC_SPECIFIC,
                                    ssrc_value=_pli_sender_ssrc,
                                    srtp_profile=(
                                        _plsrtp_pli.Policy
                                        .SRTP_PROFILE_AES128_CM_SHA1_80),
                                )
                                _pli_pol.allow_repeat_tx = True
                                _bridge_fn._pli_tx_sess = _plsrtp_pli.Session(
                                    policy=_pli_pol)
                            _bridge_fn._cam_srtp_sock.sendto(
                                _bridge_fn._pli_tx_sess.protect_rtcp(_pli_raw),
                                _bridge_fn._cam_srtp_src,
                            )
                            _pli_sent = True
                        except Exception:
                            pass
                        if not _pli_sent:
                            try:
                                _bridge_fn._cam_srtp_sock.sendto(
                                    _pli_raw, _bridge_fn._cam_srtp_src)
                            except Exception:
                                pass
                        _bridge_fn._last_pli_ts = _time_br.time()
                        _pli_n = getattr(_bridge_fn, '_pli_count', 0) + 1
                        _bridge_fn._pli_count = _pli_n
                        if _pli_n <= 3:
                            _status(
                                f"SDES: sent RTCP PLI #{_pli_n}"
                                f" → SSRC=0x{_pli_media_ssrc:08x}"
                                f" ({'SRTCP' if _pli_sent else 'plain'})"
                            )

                    # DCEP_WAIT → send LIVING 300ms after DCEP_OPEN.
                    # Camera needs time to register stream 0 before LIVING arrives.
                    if (_sctp.get('state') == 'DCEP_WAIT'
                            and _time_br.time() - _sctp.get('dcep_sent_ts', 0.0) >= 0.3):
                        _dw_sock = _sctp.get('dcep_sock')
                        _dw_src  = _sctp.get('dcep_src')
                        if _dw_sock and _dw_src:
                            try:
                                _lv_dw = _sctp_data(53, _session_mode_req_msg())
                                _dw_sock.sendto(_enc_c8_sctp(_sctp_pkt(_sctp['peer_tag'], _lv_dw)), _dw_src)  # noqa: F821
                                _sctp['state'] = 'DONE'
                                _sdes_probe_received = True
                                _last_hb_ts = _time_br.time()
                                _status(
                                    f"SDES DC: DCEP_WAIT → LIVING(5376)"
                                    f" TSN={_sctp['local_tsn']-1}"
                                    f" (300ms after DCEP_OPEN)"
                                )
                                # Build persistent command sender for PTZ/IOCtrl.
                                # Captures stable session state; computes timestamp
                                # fresh on every call so commands are not stale.
                                import struct as _st_pcmd, random as _r_pcmd
                                try:
                                    from Crypto.Cipher import AES as _AES_pcmd
                                    from Crypto.Util.Padding import pad as _pad_pcmd
                                    _pcmd_k  = _our_tx_srtp_key_audio[:16].encode('ascii')
                                    _pcmd_iv = (_cam_key_audio or _our_tx_srtp_key_audio)[:16].encode('ascii')
                                except Exception:
                                    _AES_pcmd = _pad_pcmd = _pcmd_k = _pcmd_iv = None

                                def _persistent_sdes_cmd(_cmd, _extra=b''):
                                    _seq = _r_pcmd.randint(0, 0x7FFFFFFF)
                                    _ts  = int(_time_br.time() * 1000)
                                    _pl  = _st_pcmd.pack('<IIqII4x', _seq, _cmd, _ts, len(_extra), 0) + _extra
                                    _enc = None
                                    if _pcmd_k and _AES_pcmd:
                                        try:
                                            _enc = _AES_pcmd.new(
                                                _pcmd_k, _AES_pcmd.MODE_CBC, _pcmd_iv
                                            ).encrypt(_pad_pcmd(_pl, 16))
                                        except Exception:
                                            pass
                                    for _p in [_enc, _pl]:
                                        if _p is None:
                                            continue
                                        _sz = len(_p)
                                        try:
                                            _trigger_bs.sendto(
                                                bytes([0xC8, 0x00, _sz >> 8, _sz & 0xFF]) + _p,
                                                _trigger_bsrc,
                                            )
                                        except Exception:
                                            pass

                                _cmd_chan[0] = _persistent_sdes_cmd
                            except Exception as _dw_e:
                                _status(f"SDES DC: DCEP_WAIT LIVING err: {_dw_e}")

                    # Periodic retrigger: resend AVIO LIVING every 2s until probe
                    # received (camera acknowledged our trigger).
                    if (_avio_living_sent
                            and not _sdes_probe_received
                            and _trigger_bs is not None
                            and _time_br.time() - _last_trigger_ts >= 2.0):
                        import struct as _st_re2, random as _r_re2
                        _re_ts  = int(_time_br.time() * 1000)
                        _re_seq  = _r_re2.randint(0, 0x7FFFFFFF)
                        _re_plain = (
                            _st_re2.pack('<IIqII4x', _re_seq, 5376, _re_ts, 28, 0)
                            + _st_re2.pack('<IIIIIII', 0, 0, 1, 0, 0, 0, 0)
                        )  # 56B
                        _re_enc = None
                        try:
                            from Crypto.Cipher import AES as _AES_re2
                            from Crypto.Util.Padding import pad as _pad_re2
                            _re_key = _our_tx_srtp_key_audio[:16].encode('ascii')
                            _re_iv  = (_cam_key_audio or _our_tx_srtp_key_audio)[:16].encode('ascii')
                            _re_enc = _AES_re2.new(
                                _re_key, _AES_re2.MODE_CBC, _re_iv
                            ).encrypt(_pad_re2(_re_plain, 16))
                        except Exception:
                            pass
                        for _rp in [_re_enc, _re_plain]:
                            if _rp is None:
                                continue
                            _rsz = len(_rp)
                            try:
                                _trigger_bs.sendto(
                                    bytes([0xC8, 0x00, _rsz >> 8, _rsz & 0xFF]) + _rp,
                                    _trigger_bsrc,
                                )
                            except Exception:
                                pass
                        _last_trigger_ts = _time_br.time()

                    for _bs in _rl:
                        try:
                            _bpkt, _bsrc = _bs.recvfrom(4096)
                        except OSError:
                            continue
                        # --- TURN Data Indication: strip wrapper before dispatch --- #
                        # Camera SRTP and late ICE probes may arrive wrapped in
                        # TURN Data Indications (type 0x0017) on the TURN control
                        # channel (3.230.182.123:5349).  Strip to get the inner
                        # payload, record the peer address for response routing.
                        _br_turn_peer_ip = None
                        _br_turn_peer_port = None
                        if (len(_bpkt) >= 20
                                and _bpkt[:2] == b'\x00\x17'
                                and _bpkt[4:8] == _STUN_MAGIC_BR):
                            if not _br_first_di_logged:
                                _br_first_di_logged = True
                                _status(
                                    f"bridge: first Data Indication from"
                                    f" {_bsrc[0]}:{_bsrc[1]}"
                                )
                            _br_off = 20
                            _br_inner = None
                            while _br_off + 4 <= len(_bpkt):
                                _br_at, _br_al = _st_br.unpack_from(
                                    '!HH', _bpkt, _br_off)
                                _br_av = _bpkt[_br_off + 4:_br_off + 4 + _br_al]
                                _br_off += 4 + _br_al + (-_br_al % 4)
                                if _br_at == 0x0012 and _br_al >= 8:  # XOR-PEER-ADDRESS
                                    _br_xp = (_st_br.unpack_from(
                                        '!H', _br_av, 2)[0] ^ 0x2112)
                                    _br_xb = bytes(
                                        a ^ b for a, b in zip(
                                            _br_av[4:8], _STUN_MAGIC_BR)
                                    )
                                    _br_turn_peer_ip = '.'.join(
                                        str(b) for b in _br_xb)
                                    _br_turn_peer_port = _br_xp
                                elif _br_at == 0x0013:  # DATA
                                    _br_inner = _br_av
                            if _br_inner:
                                _bpkt = _br_inner

                        if (len(_bpkt) >= 20
                                and _bpkt[4:8] == _STUN_MAGIC_BR
                                and _bpkt[:2] == b'\x00\x01'):
                            # STUN Binding Request — send Binding Success Response
                            if not _br_first_req_dumped:
                                _br_first_req_dumped = True
                                _attrs = []
                                _o = 20
                                while _o + 4 <= len(_bpkt):
                                    _at, _al = _st_br.unpack_from('!HH', _bpkt, _o)
                                    _attrs.append(f"0x{_at:04x}/{_al}")
                                    _o += 4 + _al + (-_al % 4)
                                _status(
                                    f"bridge: first BindingReq from"
                                    f" {_bsrc[0]}:{_bsrc[1]}"
                                    f" attrs=[{', '.join(_attrs)}]"
                                )
                            try:
                                if _br_turn_peer_ip is None and _bsrc[0] != _hp_host:
                                    _br_prefer_direct_stun[_bs] = True
                                _btid = _bpkt[8:20]
                                # Use TURN peer address when arrived via relay
                                _bresp_ip = _br_turn_peer_ip or _bsrc[0]
                                _bresp_port = _br_turn_peer_port or _bsrc[1]
                                _bresp = _build_stun_binding_success_response(
                                    transaction_id=_btid,
                                    mapped_ip=_bresp_ip,
                                    mapped_port=_bresp_port,
                                    mi_password=(
                                        _pwd_a if _bs is _audio_sock else _pwd_v
                                    ),
                                    magic_cookie=_STUN_MAGIC_BR,
                                )
                                if _br_turn_peer_ip and _br_prefer_direct_stun.get(_bs, False):
                                    pass
                                elif (_br_turn_peer_ip and _bs in _relay_addrs
                                        and not _is_self_peer_ip(_br_turn_peer_ip)):
                                    # Arrived via TURN — respond via Send Indication
                                    _bri = _relay_addrs[_bs]
                                    _br_t_host, _br_t_port = _bri[4], _bri[5]
                                    _br_pip = bytes(
                                        int(x) for x in _br_turn_peer_ip.split('.')
                                    )
                                    _br_xip2 = bytes(
                                        a ^ b for a, b in zip(
                                            _br_pip, _STUN_MAGIC_BR)
                                    )
                                    _br_xport2 = (
                                        _br_turn_peer_port ^ 0x2112) & 0xFFFF
                                    _br_xpa = (b'\x00\x01'
                                               + _st_br.pack('!H', _br_xport2)
                                               + _br_xip2)

                                    def _br_a(_t, _v):
                                        _p = (-len(_v)) % 4
                                        return (_st_br.pack('!HH', _t, len(_v))
                                                + _v + b'\x00' * _p)

                                    _br_si_body = (
                                        _br_a(0x0012, _br_xpa)
                                        + _br_a(0x0013, _bresp)
                                    )
                                    _br_send_ind = (
                                        b'\x00\x16'
                                        + _st_br.pack('!H', len(_br_si_body))
                                        + _STUN_MAGIC_BR + os.urandom(12)
                                        + _br_si_body
                                    )
                                    _bs.sendto(_br_send_ind, (_br_t_host, _br_t_port))
                                elif _br_turn_peer_ip and _is_self_peer_ip(_br_turn_peer_ip):
                                    _bridge_selfloop_drop_count += 1
                                    if (_bridge_selfloop_drop_count <= 5
                                            or _bridge_selfloop_drop_count % 50 == 0):
                                        _LOGGER.debug(
                                            "bridge: drop TURN self-loop STUN peer %s:%d"
                                            " (count=%d)",
                                            _br_turn_peer_ip, _br_turn_peer_port,
                                            _bridge_selfloop_drop_count,
                                        )
                                else:
                                    _bs.sendto(_bresp, _bsrc)
                                    _br_stun_resp_count += 1
                                # Late USE-CANDIDATE: send when answer arrived
                                # after bridge started (empty at setup time).
                                if not _bridge_uc_info["sent"] and _bridge_uc_info["ufrag"]:
                                    _bridge_uc_info["sent"] = True
                                    _br_uc_ufrag = _ufrag_a if _bs is _audio_sock else _ufrag_v
                                    _br_uc_pwd   = _pwd_a   if _bs is _audio_sock else _pwd_v
                                    for _br_ci, _br_cp in _bridge_uc_info["cands"]:
                                        try:
                                            _send_use_candidate(
                                                _bs, _br_uc_ufrag, _br_uc_pwd,
                                                _bridge_uc_info["ufrag"],
                                                _bridge_uc_info["pwd"],
                                                (_br_ci, _br_cp),
                                            )
                                        except Exception:
                                            pass
                                    _status(
                                        f"bridge: late USE-CANDIDATE sent to"
                                        f" {len(_bridge_uc_info['cands'])} camera candidate(s)"
                                        " (answer arrived after bridge started)"
                                    )
                            except Exception:
                                pass
                        elif len(_bpkt) >= 20 and _bpkt[4:8] == _STUN_MAGIC_BR:
                            # STUN BindingSuccess (0x0101) from camera: ICE complete.
                            # Send AES-128-CBC encrypted SESSION_MODE_REQ (AVIO LIVING).
                            #
                            # Confirmed via Ghidra static analysis of arm64
                            # libjingle_peerconnection_so.so (usrsctp_transport.cc):
                            #   - FUN_0098a9b0 (EncryptPayload): AES-128-CBC, PKCS#7 padding
                            #   - Key:  base64_decode(our_sdes_inline_key)[:16]
                            #   - IV:   base64_decode(our_sdes_inline_key)[16:30] + \x00\x00
                            #   - Packet: [0xC8][0x00][len_hi][len_lo][ciphertext]
                            #     (4-byte header, NOT the 12-byte TUTK SFrame with ts/SSRC)
                            if (_use_plain_rtp and not _tutk_trigger_sent
                                    and _bpkt[:2] == b'\x01\x01'):
                                _tutk_trigger_sent = True
                                import struct as _st_tk
                                import random as _rand_tk
                                _ts_ms = int(_time_br.time() * 1000)
                                _tk_seq = _rand_tk.randint(0, 0x7FFFFFFF)
                                _avio_plain = (
                                    _st_tk.pack('<IIqII4x', _tk_seq, 5376, _ts_ms, 28, 0)
                                    + _st_tk.pack('<IIIIIII', 0, 0, 1, 0, 0, 0, 0)
                                )  # 28B AVIO header + 28B AVStream = 56B

                                # AES-128-CBC: key=our_inline[:16] ASCII, IV=cam_inline[:16] ASCII.
                                # Confirmed by Frida v8.23 (2026-05-28): first 16 raw chars of
                                # each party's a=crypto: inline string, not base64-decoded.
                                _trigger_enc = None
                                try:
                                    from Crypto.Cipher import AES as _AES_tk
                                    from Crypto.Util.Padding import pad as _pad_tk
                                    _aes_key = _our_tx_srtp_key_audio[:16].encode('ascii')
                                    _aes_iv  = (_cam_key_audio or _our_tx_srtp_key_audio)[:16].encode('ascii')
                                    _padded  = _pad_tk(_avio_plain, 16)  # PKCS#7 → 64B
                                    _trigger_enc = _AES_tk.new(
                                        _aes_key, _AES_tk.MODE_CBC, _aes_iv
                                    ).encrypt(_padded)
                                except Exception:
                                    pass  # no pycryptodome

                                # Packet: [0xC8][0x00][ciphertext_len_BE_2B][ciphertext]
                                for _payload, _label in [
                                    (_trigger_enc, "AES-128-CBC"),
                                    (_avio_plain,  "plaintext"),
                                ]:
                                    if _payload is None:
                                        continue
                                    _sz = len(_payload)
                                    _pkt = bytes([0xC8, 0x00, _sz >> 8, _sz & 0xFF]) + _payload
                                    try:
                                        _bs.sendto(_pkt, _bsrc)
                                        _status(
                                            f"SDES: sent trigger ({_label})"
                                            f" len={_sz}"
                                            f" → {_bsrc[0]}:{_bsrc[1]}"
                                        )
                                    except Exception:
                                        pass
                                _avio_living_sent = True
                                _last_trigger_ts = _time_br.time()
                                _trigger_bs   = _bs
                                _trigger_bsrc = _bsrc

                                # Camera is SCTP initiator (a=setup:active).
                                # Be pure SCTP server: wait for camera's INIT,
                                # reply INIT-ACK, wait for COOKIE-ECHO, then send data.
                                if _dc_answer_has_app:
                                    _status(
                                        "SDES DC: m=application present"
                                        " — waiting for camera SCTP INIT"
                                        f" key={_our_tx_srtp_key_audio[:8]}"
                                        f" iv={_cam_key_audio[:8] if _cam_key_audio else '(none)'}"
                                    )
                        else:
                            # Non-STUN packet — demux by first byte.
                            if _avio_living_sent and len(_bpkt) >= 4:
                                _nsl_cnt = getattr(
                                    _bridge_fn, '_non_stun_logged', 0)
                                if _nsl_cnt < 5:
                                    _LOGGER.debug(
                                        "bridge non-STUN %dB from %s:%d"
                                        " first4=%s",
                                        len(_bpkt),
                                        _bsrc[0], _bsrc[1],
                                        _bpkt[:4].hex(),
                                    )
                                    _bridge_fn._non_stun_logged = (
                                        _nsl_cnt + 1)
                            # Plain SCTP over UDP: srcPort=dstPort=5000 (0x1388).
                            # Camera is a=setup:active (SCTP client — initiates INIT).
                            # We are SCTP server: wait for camera's INIT, reply INIT-ACK,
                            # then complete: COOKIE-ECHO → COOKIE-ACK →
                            # DATA_CHANNEL_OPEN + SESSION_MODE_REQ(5376).
                            # Check for any SCTP-like packet: first 4 bytes are
                            # srcPort(2B) + dstPort(2B) in SCTP common header.
                            # Standard SCTP uses port 5000 (0x1388) but log ALL
                            # candidates to catch non-standard port usage.
                            _possible_sctp = (
                                len(_bpkt) >= 12
                                and _bpkt[4:8] == b'\x00\x00\x00\x00'  # vtag=0 means INIT
                                and _bpkt[12] in (0x01, 0x02, 0x0A, 0x0B, 0x06)
                            ) or (
                                len(_bpkt) >= 12
                                and _bpkt[:2] == b'\x13\x88'
                                and _bpkt[2:4] == b'\x13\x88'
                            )
                            if _possible_sctp:
                                st = _sctp['state']
                                _chunk_type = _bpkt[12] if len(_bpkt) > 12 else 0xFF
                                _status(
                                    f"SDES DC: plain SCTP {len(_bpkt)}B"
                                    f" from {_bsrc[0]}:{_bsrc[1]}"
                                    f" state={st}"
                                    f" chunk=0x{_chunk_type:02x}"
                                    f" [{_bpkt[:16].hex()}]"
                                )
                                # Secondary C: camera may be SCTP client (a=setup:active
                                # means camera initiates). If state is CLOSED and we see
                                # an INIT chunk (type=0x01), respond with INIT-ACK.
                                if st == 'CLOSED' and _chunk_type == 0x01:
                                    peer_tag = _sctp_parse_init(_bpkt)
                                    if peer_tag:
                                        _sctp['state'] = 'COOKIE_ECHOED'
                                        try:
                                            _ack_pkt = _sctp_init_ack_pkt()
                                            _bs.sendto(_ack_pkt, _bsrc)
                                            _status(
                                                f"SDES DC: camera sent SCTP INIT"
                                                f" (peer_tag=0x{peer_tag:08x})"
                                                f" — sent INIT-ACK"
                                            )
                                        except Exception as _iae:
                                            _status(f"SCTP INIT-ACK failed: {_iae}")
                                elif st in ('INIT_SENT', 'COOKIE_WAIT'):
                                    cookie = _sctp_parse_init_ack(_bpkt)
                                    if cookie:
                                        _sctp['state'] = 'COOKIE_ECHOED'
                                        try:
                                            _bs.sendto(_sctp_cookie_echo(cookie), _bsrc)
                                            _status(
                                                f"SDES DC: plain INIT-ACK"
                                                f" (cookie {len(cookie)}B)"
                                                f" → sent COOKIE-ECHO"
                                            )
                                        except Exception as _sce:
                                            _status(f"SCTP COOKIE-ECHO failed: {_sce}")
                                    else:
                                        _status("SDES DC: plain SCTP pkt in INIT_SENT/COOKIE_WAIT"
                                                " — parse_init_ack found no cookie")
                                elif st == 'COOKIE_ECHOED':
                                    # Any SCTP packet (COOKIE-ACK = type 0x0B) signals
                                    # SCTP is established.
                                    _sctp['state'] = 'ESTABLISHED'
                                    _status("SDES DC: SCTP COOKIE-ACK — DataChannel OPEN")
                                    try:
                                        _sctp_send_living(_bs, _bsrc)
                                    except Exception as _sle:
                                        _LOGGER.warning("SDES DC: send living failed: %s",
                                                        _sle)
                                elif st == 'DONE':
                                    pass  # ignore further SCTP (SACKs etc.)
                                continue
                            # Log DTLS packets (first byte 0x14-0x17) if they arrive.
                            # Camera is a=setup:active (DTLS client) — if it sends
                            # DTLS ClientHello, we'd see 0x16 here.
                            if len(_bpkt) >= 4 and 0x14 <= _bpkt[0] <= 0x17:
                                _status(
                                    f"bridge: DTLS record {len(_bpkt)}B"
                                    f" from {_bsrc[0]}:{_bsrc[1]}"
                                    f" ct=0x{_bpkt[0]:02x}"
                                    f" ver={_bpkt[1:3].hex()}"
                                )
                            #
                            # Raw hex dump of all 0xC8/0xC9 packets (first 10) to verify
                            # packet format and AES key/IV derivation.
                            if (len(_bpkt) >= 1
                                    and _bpkt[0] not in (0xC8, 0xC9)
                                    and not (len(_bpkt) >= 4 and 0x14 <= _bpkt[0] <= 0x17)
                                    and _sctp.get('state') == 'DONE'):
                                if not hasattr(_bridge_fn, '_non_c8_after_done'):
                                    _bridge_fn._non_c8_after_done = 0
                                _bridge_fn._non_c8_after_done += 1
                                if _bridge_fn._non_c8_after_done <= 5:
                                    _status(
                                        f"bridge: non-0xC8 after DONE:"
                                        f" {len(_bpkt)}B byte0=0x{_bpkt[0]:02x}"
                                        f" {_bpkt[:24].hex()}"
                                    )
                            if len(_bpkt) >= 1 and _bpkt[0] in (0xC8, 0xC9):
                                if not hasattr(_bridge_fn, '_c8_raw_count'):
                                    _bridge_fn._c8_raw_count = 0
                                _bridge_fn._c8_raw_count += 1
                                if _bridge_fn._c8_raw_count <= 10:
                                    _sdes_k = _our_tx_srtp_key_audio[:16]
                                    _sdes_v = (_cam_key_audio or _our_tx_srtp_key_audio)[:16]
                                    _status(
                                        f"bridge: RAW 0x{_bpkt[0]:02x} {len(_bpkt)}B"
                                        f" #{_bridge_fn._c8_raw_count}"
                                        f" sdes_key={_sdes_k}"
                                        f" sdes_iv={_sdes_v}"
                                        f" [{_bpkt.hex()}]"
                                    )
                            # TUTK SFrame detection (A001064 / _use_plain_rtp):
                            # The camera sends TUTK-framed data instead of SRTP.
                            # Wire-capture analysis (2026-05-02) confirmed:
                            #   byte0=0xC8 → TUTK audio SFrame
                            #   byte0=0xC9 → TUTK video SFrame (expected)
                            # TUTK SFrame header (12 bytes):
                            #   [0]   type   (0xC8=audio, 0xC9=video)
                            #   [1]   channel/flags
                            #   [2-3] payload_size (big-endian; = packet_len - 4)
                            #   [4-7] timestamp (big-endian, camera clock)
                            #   [8-11] SSRC (big-endian; confirmed matches actual pkt ssrc)
                            # Strip TUTK header and synthesize a standard RTP/2 packet
                            # so ffmpeg (configured with RTP/AVP, no SRTP) can decode.
                            if _use_plain_rtp and len(_bpkt) >= 12 and _bpkt[0] in (0xC8, 0xC9):
                                _tk_type  = _bpkt[0]
                                _tk_ts    = int.from_bytes(_bpkt[4:8],  'big')
                                _tk_ssrc  = int.from_bytes(_bpkt[8:12], 'big')
                                _tk_audio = (_tk_type == 0xC8)
                                _tk_pt    = 8 if _tk_audio else 96   # PCMA or H264
                                _tk_payload = _bpkt[12:]
                                # Mark probe received; start heartbeat timer
                                if not _sdes_probe_received:
                                    _sdes_probe_received = True
                                    _last_hb_ts = _time_br.time()  # HB fires in 10s
                                if not hasattr(_bridge_fn, '_tutk_seq'):
                                    _bridge_fn._tutk_seq_a = 0
                                    _bridge_fn._tutk_seq_v = 0
                                if _tk_audio:
                                    _bridge_fn._tutk_seq_a = (_bridge_fn._tutk_seq_a + 1) & 0xFFFF
                                    _tk_seq = _bridge_fn._tutk_seq_a
                                    _btgt, _lo_target, _kind = _lo_audio_port, _lo_a, "audio"
                                else:
                                    _bridge_fn._tutk_seq_v = (_bridge_fn._tutk_seq_v + 1) & 0xFFFF
                                    _tk_seq = _bridge_fn._tutk_seq_v
                                    _btgt, _lo_target, _kind = _lo_video_port, _lo_v, "video"
                                # Synthesize 12-byte RTP header (V=2, no padding/ext/csrc)
                                _rtp_hdr = _st_br.pack('!BBHII',
                                    0x80,       # V=2 P=0 X=0 CC=0
                                    _tk_pt,     # M=0 PT
                                    _tk_seq,
                                    _tk_ts,
                                    _tk_ssrc,
                                )
                                _bpkt = _rtp_hdr + _tk_payload
                                if not hasattr(_bridge_fn, '_tutk_count'):
                                    _bridge_fn._tutk_count = 0
                                    _bridge_fn._tutk_first_ts = _time_br.time()
                                _bridge_fn._tutk_count += 1
                                _elapsed = _time_br.time() - _bridge_fn._tutk_first_ts
                                # Decrypt audio probe: SRTP AES-CM (RFC 3711).
                                # AES-128-CBC: key=our_inline[:16], IV=cam_inline[:16].
                                # Frida v8.23 (2026-05-28) confirmed: both encrypt and
                                # decrypt use first 16 ASCII chars of the respective
                                # a=crypto: inline strings, NOT base64-decoded content.
                                # Ciphertext starts at byte 4 (after 0xC8 header).
                                _pd_plain = None
                                if _tk_audio and _cam_key_audio:
                                    try:
                                        from Crypto.Cipher import AES as _AES_pd
                                        from Crypto.Util.Padding import unpad as _unpad_pd
                                        _pd_key = _our_tx_srtp_key_audio[:16].encode('ascii')
                                        _pd_iv  = _cam_key_audio[:16].encode('ascii')
                                        _pd_ct  = _bpkt[4:]  # full ciphertext after 4B header
                                        if len(_pd_ct) % 16 == 0 and len(_pd_ct) >= 16:
                                            _pd_plain = _unpad_pd(
                                                _AES_pd.new(_pd_key, _AES_pd.MODE_CBC, _pd_iv
                                                            ).decrypt(_pd_ct), 16)
                                    except ImportError:
                                        pass
                                    except Exception as _pde:
                                        _status(f"bridge: SDES decrypt error: {_pde}")
                                # Log for first 5 and every 10th frame
                                if _bridge_fn._tutk_count <= 5 or _bridge_fn._tutk_count % 10 == 0:
                                    _status(
                                        f"bridge: TUTK {_kind} SFrame"
                                        f" type=0x{_tk_type:02x} ssrc={_tk_ssrc}"
                                        f" ts={_tk_ts} payload={len(_tk_payload)}B"
                                        f" #{_bridge_fn._tutk_count} (+{_elapsed:.1f}s)"
                                    )
                                    if _bridge_fn._tutk_count <= 5:
                                        _status(
                                            f"bridge: TUTK raw"
                                            f" type=0x{_tk_type:02x}"
                                            f" ts={_tk_ts} ssrc=0x{_tk_ssrc:08x}"
                                            f" payload_all={_tk_payload.hex()}"
                                        )
                                        if _pd_plain is not None:
                                            _status(
                                                f"bridge: TUTK decrypt → "
                                                f" plain_all={_pd_plain.hex()}"
                                            )
                                # ── Encrypted SCTP state machine (SDES path) ──
                                # Camera sends SCTP handshake (INIT, COOKIE-ECHO, DATA)
                                # wrapped in 0xC8 AES-128-CBC frames. Handle before
                                # forwarding to ffmpeg.
                                if (_pd_plain is not None
                                        and len(_pd_plain) >= 16
                                        and _pd_plain[:4] == b'\x13\x88\x13\x88'):
                                    _pd_ct8 = _pd_plain[12] if len(_pd_plain) > 12 else 0xFF

                                    def _enc_c8_sctp(_raw):
                                        from Crypto.Cipher import AES as _ae
                                        from Crypto.Util.Padding import pad as _pa
                                        _k = _our_tx_srtp_key_audio[:16].encode('ascii')
                                        _v = _cam_key_audio[:16].encode('ascii')
                                        _e = _ae.new(_k, _ae.MODE_CBC, _v).encrypt(_pa(_raw, 16))
                                        return bytes([0xC8, 0x00, len(_e) >> 8, len(_e) & 0xFF]) + _e

                                    _sct = _sctp['state']
                                    if _pd_ct8 == 0x01 and _sct in ('CLOSED', 'INIT_SENT', 'COOKIE_WAIT'):
                                        # Camera SCTP INIT (or retransmit) → send encrypted INIT-ACK.
                                        # Handle retransmits in COOKIE_WAIT: re-send INIT-ACK
                                        # (our first may have been lost).
                                        _sc_p = _sctp_parse_init(_pd_plain)
                                        if _sc_p:
                                            try:
                                                _iak_plain = _sctp_init_ack_pkt()
                                                _iak_bytes = _enc_c8_sctp(_iak_plain)
                                                _bs.sendto(_iak_bytes, _bsrc)
                                                _sctp['state'] = 'COOKIE_WAIT'
                                                _status(
                                                    f"SDES DC: INIT(peer=0x{_sc_p:08x})"
                                                    f" → INIT-ACK {len(_iak_bytes)}B"
                                                    f" to {_bsrc[0]}:{_bsrc[1]}"
                                                    f" plain={_iak_plain.hex()}"
                                                )
                                            except Exception as _sce8:
                                                _status(f"SDES DC: enc INIT-ACK err: {_sce8}")
                                    elif _pd_ct8 == 0x02 and _sct in ('INIT_SENT', 'COOKIE_WAIT'):
                                        # Camera SCTP INIT-ACK → send encrypted COOKIE-ECHO
                                        _sc_ck = _sctp_parse_init_ack(_pd_plain)
                                        if _sc_ck:
                                            try:
                                                _bs.sendto(_enc_c8_sctp(_sctp_cookie_echo(_sc_ck)), _bsrc)
                                                _sctp['state'] = 'COOKIE_ECHOED'
                                                _status(
                                                    f"SDES DC: enc INIT-ACK"
                                                    f" (cookie {len(_sc_ck)}B)"
                                                    f" → sent enc COOKIE-ECHO"
                                                )
                                            except Exception as _sce8:
                                                _status(f"SDES DC: enc COOKIE-ECHO err: {_sce8}")
                                    elif _pd_ct8 == 0x0A and _sct in ('COOKIE_WAIT', 'COOKIE_ECHOED'):
                                        # Camera COOKIE-ECHO → send COOKIE-ACK + DCEP_OPEN,
                                        # then wait 300ms before sending LIVING (PPID=53).
                                        # Without DCEP_OPEN (PPID=50), LIVING arrives on an
                                        # unregistered stream and is silently discarded by the
                                        # camera's SCTP application layer (SACK confirms transport
                                        # delivery, but no audio/video results). The DTLS path
                                        # (lines ~4589-4617) does exactly this sleep — required.
                                        try:
                                            _cak8 = _sctp_pkt(_sctp['peer_tag'], _sctp_chunk(0x0B, 0, b''))
                                            _bs.sendto(_enc_c8_sctp(_cak8), _bsrc)
                                            _dc8 = _sctp_data(50, _dcep_open_msg())
                                            _bs.sendto(_enc_c8_sctp(_sctp_pkt(_sctp['peer_tag'], _dc8)), _bsrc)
                                            _sctp['state'] = 'DCEP_WAIT'
                                            _sctp['dcep_sent_ts'] = _time_br.time()
                                            _sctp['dcep_sock'] = _bs
                                            _sctp['dcep_src'] = _bsrc
                                            _status(
                                                "SDES DC: COOKIE-ECHO"
                                                " → COOKIE-ACK + DCEP_OPEN(50),"
                                                " waiting 300ms before LIVING"
                                            )
                                        except Exception as _sce8:
                                            _status(f"SDES DC: enc COOKIE-ACK err: {_sce8}")
                                    elif _pd_ct8 == 0x0B and _sct == 'COOKIE_ECHOED':
                                        # Camera COOKIE-ACK → send encrypted LIVING only
                                        try:
                                            _lv8 = _sctp_data(53, _session_mode_req_msg())
                                            _bs.sendto(_enc_c8_sctp(_sctp_pkt(_sctp['peer_tag'], _lv8)), _bsrc)
                                            _sctp['state'] = 'DONE'
                                            _sdes_probe_received = True
                                            _last_hb_ts = _time_br.time()
                                            _status("SDES DC: enc COOKIE-ACK → sent enc LIVING")
                                        except Exception as _sce8:
                                            _status(f"SDES DC: enc LIVING err: {_sce8}")
                                    elif _pd_ct8 == 0x00 and _sct == 'DONE':
                                        # SCTP DATA from camera
                                        _sc_pay = _pd_plain[28:] if len(_pd_plain) > 28 else b''
                                        _sc_ppid = (int.from_bytes(_pd_plain[24:28], 'big')
                                                    if len(_pd_plain) >= 28 else 0)
                                        _sc_cmd = (int.from_bytes(_sc_pay[4:8], 'little')
                                                   if len(_sc_pay) >= 8 else 0)
                                        _status(
                                            f"SDES DC: enc DATA ppid={_sc_ppid}"
                                            f" cmd={_sc_cmd} {len(_sc_pay)}B"
                                            f" {_sc_pay[:32].hex()}"
                                        )
                                    else:
                                        # Log SACK (0x03) with cumulative TSN ack for diagnostics
                                        if _pd_ct8 == 0x03 and len(_pd_plain) >= 20:
                                            _cum_tsn = int.from_bytes(_pd_plain[16:20], 'big')
                                            _status(
                                                f"SDES DC: SACK cum_tsn={_cum_tsn:#010x}"
                                                f" state={_sct}"
                                            )
                                        else:
                                            _status(
                                                f"SDES DC: enc SCTP ct=0x{_pd_ct8:02x}"
                                                f" state={_sct} {len(_pd_plain)}B"
                                            )
                                    continue  # SCTP never forwarded to ffmpeg
                                # Send RTCP RR to camera to acknowledge audio receipt.
                                if _tk_audio:
                                    _rr_our_ssrc = 0xAB12CD34
                                    _rr_pkt = _st_br.pack(
                                        '!BBHIIIIIII',
                                        0x81, 201, 7,
                                        _rr_our_ssrc,
                                        _tk_ssrc,
                                        0,
                                        _bridge_fn._tutk_count,
                                        0, 0, 0,
                                    )
                                    _rtcp_sent = False
                                    try:
                                        import pylibsrtp as _plsrtp_rr
                                        import base64 as _b64_rr
                                        _rr_key = _b64_rr.b64decode(
                                            _cam_key_audio or _our_tx_srtp_key_audio)
                                        _rr_pol = _plsrtp_rr.Policy(
                                            key=_rr_key,
                                            ssrc_type=_plsrtp_rr.Policy.SSRC_SPECIFIC,
                                            ssrc_value=_rr_our_ssrc,
                                            srtp_profile=_plsrtp_rr.Policy.SRTP_PROFILE_AES128_CM_SHA1_80,
                                        )
                                        _rr_pol.allow_repeat_tx = True
                                        _rr_sess = _plsrtp_rr.Session(policy=_rr_pol)
                                        _bs.sendto(_rr_sess.protect_rtcp(_rr_pkt), _bsrc)
                                        _rtcp_sent = True
                                    except Exception:
                                        pass
                                    if not _rtcp_sent:
                                        try:
                                            _bs.sendto(_rr_pkt, _bsrc)
                                        except Exception:
                                            pass
                                    if _bridge_fn._tutk_count == 1:
                                        _status(
                                            f"SDES: sent RTCP RR to camera"
                                            f" (SSRC=0x{_tk_ssrc:08x})"
                                        )
                                # Forward decrypted PCMA audio to ffmpeg loopback.
                                # AVIO control frames (SESSION_MODE_RESP=5377, etc.) are
                                # identified by cmd field and skipped; raw PCMA bytes are sent.
                                if _tk_audio and _pd_plain is not None:
                                    _fwd_cmd = (int.from_bytes(_pd_plain[4:8], 'little')
                                                if len(_pd_plain) >= 8 else 0)
                                    _avio_cmds = {5376, 5377, 5156, 5157, 768, 769, 511}
                                    if _fwd_cmd not in _avio_cmds:
                                        try:
                                            _lo_a.sendto(
                                                _rtp_hdr + _pd_plain,
                                                ('127.0.0.1', _lo_audio_port),
                                            )
                                            if not _br_first_audio_logged:
                                                _br_first_audio_logged = True
                                                _status(
                                                    f"bridge: first SDES audio → ffmpeg"
                                                    f" loopback:{_lo_audio_port}"
                                                    f" ({len(_pd_plain)}B PCMA)"
                                                )
                                        except Exception:
                                            pass
                                continue

                            # Standard SRTP/SRTCP demux by RTP payload type.
                            # Camera answers BUNDLE (a=group:BUNDLE 0 1) so all media
                            # arrives on _audio_sock.  Routing by source socket would
                            # send video RTP to ffmpeg's audio loopback.  RFC 5761:
                            #   - RTP byte[1] = M(1) | PT(7); PT in 0..127
                            #   - RTCP byte[1] = PT(8); PT in 200..204
                            # SRTP/SRTCP keeps the header in clear, so we can read PT
                            # before decryption.  Audio PTs: 0 (PCMU), 8 (PCMA).
                            # Video PTs: 96 (H264), 97 (H265).
                            if not hasattr(_bridge_fn, '_srtp_switch_logged'):
                                _bridge_fn._srtp_switch_logged = True
                                _LOGGER.info(
                                    "bridge: SRTP/non-TUTK pkt %dB from %s:%d"
                                    " first4=%s (PT=%d) — camera switched to SRTP",
                                    len(_bpkt), _bsrc[0], _bsrc[1],
                                    _bpkt[:4].hex(),
                                    (_bpkt[1] & 0x7F) if len(_bpkt) > 1 else -1,
                                )
                            _pt_byte = _bpkt[1] if len(_bpkt) > 1 else 0
                            if 200 <= _pt_byte <= 204:
                                # SRTCP from camera.  For _use_plain_rtp cameras
                                # the ffmpeg SDP uses RTP/AVP (no crypto).  If we
                                # forward encrypted SRTCP, ffmpeg reads the
                                # encrypted NTP/RTP sender-info bytes as garbage
                                # and uses them to rebase its internal clock,
                                # producing wildly wrong DTS (≈ Unix epoch µs).
                                # Drop encrypted SRTCP entirely; ffmpeg works fine
                                # without RTCP SR — it uses only RTP timestamps.
                                if _use_plain_rtp:
                                    continue
                                # For SDES cameras (non-plain-rtp) ffmpeg uses
                                # SAVP and handles SRTCP itself — forward as-is.
                                try:
                                    _lo_a.sendto(_bpkt, ('127.0.0.1', _lo_audio_port))
                                except Exception:
                                    pass
                                try:
                                    _lo_v.sendto(_bpkt, ('127.0.0.1', _lo_video_port))
                                except Exception:
                                    pass
                                continue
                            _pt = _pt_byte & 0x7F
                            if _pt in (96, 97, 98):
                                _btgt, _lo_target, _kind = (
                                    _lo_video_port, _lo_v, "video"
                                )
                            elif _pt in (0, 8):
                                _btgt, _lo_target, _kind = (
                                    _lo_audio_port, _lo_a, "audio"
                                )
                            else:
                                # Unknown PT — fall back to source-socket routing.
                                if _bs is _audio_sock:
                                    _btgt, _lo_target, _kind = (
                                        _lo_audio_port, _lo_a, "audio"
                                    )
                                else:
                                    _btgt, _lo_target, _kind = (
                                        _lo_video_port, _lo_v, "video"
                                    )
                            if not _br_first_srtp_logged:
                                _br_first_srtp_logged = True
                                # Hex-dump first 24 bytes + parsed RTP header
                                # so we can verify byte 0 is 0x80 (real RTP v2),
                                # PT, sequence, timestamp, and SSRC against the
                                # camera's announced ssrc:5075/5073.
                                _hex24 = _bpkt[:24].hex()
                                _b0 = _bpkt[0] if len(_bpkt) > 0 else 0
                                if len(_bpkt) >= 12:
                                    _seq16, _ts32, _ssrc32 = _st_br.unpack_from(
                                        '!HII', _bpkt, 2
                                    )
                                else:
                                    _seq16 = _ts32 = _ssrc32 = 0
                                _status(
                                    f"bridge: first SRTP from"
                                    f" {_bsrc[0]}:{_bsrc[1]} pt={_pt}"
                                    f" → {_kind} loopback:{_btgt}"
                                    f"  byte0=0x{_b0:02x} byte1=0x{_pt_byte:02x}"
                                    f" seq={_seq16} ts={_ts32}"
                                    f" ssrc={_ssrc32}"
                                    f" len={len(_bpkt)}"
                                    f" hex24={_hex24}"
                                )
                            if _kind == "audio" and not _br_first_audio_logged:
                                _br_first_audio_logged = True
                                _status(f"bridge: first audio RTP pt={_pt}")
                            elif _kind == "video" and not _br_first_video_logged:
                                _br_first_video_logged = True
                                _status(f"bridge: first video RTP pt={_pt}")
                                # Capture camera video SSRC for RTCP PLI.
                                if len(_bpkt) >= 12:
                                    _bridge_fn._cam_video_ssrc = _st_br.unpack_from(
                                        '!I', _bpkt, 8)[0]
                                _bridge_fn._cam_srtp_src  = _bsrc
                                _bridge_fn._cam_srtp_sock = _bs
                                # Schedule immediate PLI so IDR+SPS arrives in
                                # the analyzeduration window.
                                _bridge_fn._last_pli_ts = 0.0
                            # For TUTK cameras (_use_plain_rtp) the ffmpeg SDP uses
                            # RTP/AVP (no crypto). After LIVING the camera switches
                            # from TUTK SFrames to standard SRTP, so we decrypt here
                            # before forwarding plain RTP to ffmpeg.
                            _fwd_pkt = _bpkt
                            if _use_plain_rtp:
                                if not hasattr(_bridge_fn, '_srtp_rx_sess'):
                                    _bridge_fn._srtp_rx_sess = None
                                    _rx_inline = _cam_key_audio or srtp_key_audio
                                    if _rx_inline:
                                        try:
                                            import pylibsrtp as _plsrtp_rx
                                            import base64 as _b64_srx
                                            _rx_pol = _plsrtp_rx.Policy(
                                                key=_b64_srx.b64decode(_rx_inline),
                                                ssrc_type=_plsrtp_rx.Policy.SSRC_ANY_INBOUND,
                                                srtp_profile=_plsrtp_rx.Policy.SRTP_PROFILE_AES128_CM_SHA1_80,
                                            )
                                            _rx_pol.allow_repeat_tx = True
                                            _bridge_fn._srtp_rx_sess = _plsrtp_rx.Session(
                                                policy=_rx_pol
                                            )
                                            _status("bridge: SRTP RX session ready (cam→us)")
                                        except Exception as _srx_e:
                                            _status(f"bridge: SRTP RX init failed: {_srx_e}")
                                if _bridge_fn._srtp_rx_sess is not None:
                                    try:
                                        _fwd_pkt = _bridge_fn._srtp_rx_sess.unprotect(_bpkt)
                                    except Exception as _srx_dec_e:
                                        _ec = getattr(
                                            _bridge_fn, '_decrypt_err_n', 0)
                                        if _ec < 8:
                                            _bridge_fn._decrypt_err_n = _ec + 1
                                            _seq_d = (int.from_bytes(
                                                _bpkt[2:4], 'big')
                                                if len(_bpkt) >= 4 else -1)
                                            _ssrc_d = (int.from_bytes(
                                                _bpkt[8:12], 'big')
                                                if len(_bpkt) >= 12 else 0)
                                            _status(
                                                f"bridge: SRTP decrypt err:"
                                                f" {_srx_dec_e}"
                                                f" seq={_seq_d}"
                                                f" ssrc=0x{_ssrc_d:08x}"
                                                f" pt={_pt}"
                                            )
                            # Rebase RTP timestamps to start near 0.  Camera picks a
                            # random starting timestamp (RFC 3550 §5.1); the 90 kHz
                            # video clock can be near 2^32 and wraps, producing huge
                            # or negative DTS values that the MPEG-TS muxer drops.
                            # Subtracting the first-seen timestamp per-stream gives
                            # ffmpeg a monotonically increasing sequence from 0.
                            if (_use_plain_rtp
                                    and len(_fwd_pkt) >= 8
                                    and _fwd_pkt[0] == 0x80):
                                _rtp_raw_ts = _st_br.unpack_from('!I', _fwd_pkt, 4)[0]
                                _ts_base_attr = (
                                    '_rtp_ts_base_video' if _kind == 'video'
                                    else '_rtp_ts_base_audio'
                                )
                                if not hasattr(_bridge_fn, _ts_base_attr):
                                    setattr(_bridge_fn, _ts_base_attr, _rtp_raw_ts)
                                _rtp_base = getattr(_bridge_fn, _ts_base_attr)
                                _rtp_norm = (_rtp_raw_ts - _rtp_base) & 0xFFFFFFFF
                                _fwd_pkt = (_fwd_pkt[:4]
                                            + _st_br.pack('!I', _rtp_norm)
                                            + _fwd_pkt[8:])
                            try:
                                _lo_target.sendto(
                                    _fwd_pkt, ('127.0.0.1', _btgt)
                                )
                            except Exception:
                                pass
                    # Periodic ICE controlling check: re-send USE-CANDIDATE every 2.5 s.
                    # Keeps the camera in ICE "Completed" state and satisfies consent
                    # refresh (RFC 7675).  Also handles the case where the initial
                    # USE-CANDIDATE (sent right after the STUN window) was lost.
                    _br_now = _time_br.monotonic()
                    if _cam_ice_cands and (_br_now - _br_last_uc) >= 2.5:
                        _br_last_uc = _br_now
                        for _c_ip, _c_port in _cam_ice_cands:
                            _send_use_candidate(
                                _audio_sock, _ufrag_a, _pwd_a,
                                _cam_ice_ufrag, _cam_ice_pwd, (_c_ip, _c_port),
                            )
                            _send_use_candidate(
                                _video_sock, _ufrag_v, _pwd_v,
                                _cam_ice_ufrag, _cam_ice_pwd, (_c_ip, _c_port),
                            )
            finally:
                try:
                    _lo_a.close()
                except Exception:
                    pass
                try:
                    _lo_v.close()
                except Exception:
                    pass

        _br_first_di_logged = False
        _br_first_srtp_logged = False
        _br_first_req_dumped = False
        _br_first_audio_logged = False
        _br_first_video_logged = False
        _avio_living_sent = False

        # Shared mutable container so the bridge can send USE-CANDIDATE even
        # when the camera's SDP answer arrives after the bridge starts (late-
        # wakeup path where _cam_ice_ufrag/pwd/cands are still empty at setup).
        # Written by the main coroutine, read by the bridge thread.  Safe in
        # CPython: dict key assignment and simple attribute writes are atomic
        # under the GIL.
        _bridge_uc_info: dict = {
            "ufrag":   _cam_ice_ufrag,
            "pwd":     _cam_ice_pwd,
            "cands":   list(_cam_ice_cands),
            "sent":    bool(_cam_ice_cands),  # True if already sent at setup
        }

        _bridge_thread = _threading_br.Thread(
            target=_bridge_fn, daemon=True, name="sdes-bridge"
        )
        _bridge_thread.start()
        _status(
            f"bridge thread started — camera sockets audio={audio_port}"
            f" video={video_port} → ffmpeg loopback {_lo_audio_port}/{_lo_video_port}"
        )

        # --- DTLS fallback: echo-reversal camera did not do ICE or SRTP ----- #
        # LK.IPC.A001064 echoes our webrtcReq offer and webrtcResp answer back
        # over MQTT but then never initiates STUN connectivity checks or sends
        # any SRTP packets.  The camera appears to require DTLS (peerid _2)
        # despite reporting enableSdes='1' in its device properties.
        # Detect this by checking: echo-reversal received (_cam_echo_received)
        # AND no STUN in the ICE window AND no early SRTP.
        # _cam_echo_received=True only for cameras that mirror our webrtcReq
        # (e.g. A001064); non-echo SDES cameras (e.g. A001513) always have it
        # False and are never affected by this block.
        # NOTE: isDTLS='0' (dtls_fallback_ok=False) does NOT mean the camera
        # cannot do DTLS — webrtc_internals_dump confirms LK.IPC.A001064 uses
        # DTLS (UDP/TLS/RTP/SAVPF) when given a proper DTLS offer.  The
        # property means SDES is available, not that DTLS is absent.
        if (_cam_echo_received
                and _stun_count == 0
                and _camera_side_pkt_count == 0
                and not _srtp_detected
                and dtls_fallback_ok):
            _status(
                "echo-reversal camera: no STUN or SRTP received in ICE window"
                " — camera likely requires DTLS; falling back"
            )
            # Stop bridge thread by closing its sockets before we raise.
            for _rsock in (_audio_sock, _video_sock):
                try:
                    _rsock.close()
                except Exception:
                    pass
            try:
                os.unlink(sdp_path)
            except Exception:
                pass
            outgoing_q.put_nowait(None)   # stop MQTT thread
            raise DeviceClient._SdesNoAnswerError()
        elif (_cam_echo_received
              and _stun_count == 0
              and _camera_side_pkt_count == 0
              and not _srtp_detected
              and not dtls_fallback_ok):
            _status(
                "echo-reversal camera: no STUN or SRTP received in ICE window"
                " — DTLS fallback disabled by camera flags; continuing SDES path"
            )

        if rtsp_push_url:
            # Push decrypted stream to an RTSP server (e.g. go2rtc at port 8554).
            # -rtsp_transport tcp avoids UDP fragmentation on loopback.
            dest_args = [
                "-c", "copy",
                "-f", "rtsp", "-rtsp_transport", "tcp",
                rtsp_push_url,
            ]
        elif output_path:
            # Ensure the output directory exists before ffmpeg tries to open the
            # file.  ffmpeg fails with "No such file or directory" if the parent
            # directory is missing.
            out_dir = os.path.dirname(output_path)
            if out_dir:
                os.makedirs(out_dir, exist_ok=True)
            dest_args = ["-c", "copy", output_path]
        else:
            # -c copy /dev/null fails: "Unable to find a suitable output format
            # for '/dev/null'".  Use the null muxer instead so ffmpeg stays
            # alive and receives the SRTP stream without writing anything.
            dest_args = ["-f", "null", "/dev/null"]
        # Output-side duration limit: -t N stops ffmpeg after N seconds of
        # encoded output.  The bridge thread detects ffmpeg exit via proc.poll()
        # and stops forwarding + sending keepalives automatically.
        _time_args = ["-t", str(int(max_seconds))] if max_seconds else []
        cmd = [
            "ffmpeg", "-y",
            "-loglevel", "warning",
            "-protocol_whitelist", "file,rtp,udp,srtp",
            # 2 s analyzeduration: the camera sends SPS+PPS+IDR in the very
            # first burst (seq=0,1,2...).  15 s consumed nearly all packets
            # during analysis, leaving only 1s of output in a 30s test.
            # PLI forces a new IDR every 5 s, so parameters always re-arrive.
            "-fflags", "+nobuffer+genpts",
            "-analyzeduration", "2000000",
            "-probesize", "500000",
            "-i", sdp_path,
            *_time_args,
            *dest_args,
        ]
        _LOGGER.info("SDES ffmpeg cmd: %s", " ".join(cmd))
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            _proc_holder[0] = proc
        except FileNotFoundError:
            # ffmpeg is not installed — clean up and surface a clear error.
            for _rsock in (_audio_sock, _video_sock):
                try:
                    _rsock.close()
                except Exception:
                    pass
            try:
                os.unlink(sdp_path)
            except Exception:
                pass
            outgoing_q.put_nowait(None)   # stop MQTT thread
            raise RuntimeError(
                "ffmpeg not found — install ffmpeg to stream SDES-SRTP cameras.\n"
                "  Ubuntu/Debian:  sudo apt install ffmpeg\n"
                "  macOS (Homebrew): brew install ffmpeg\n"
                "  Windows:         https://ffmpeg.org/download.html"
            )

        # Wait until ffmpeg has actually bound the UDP ports before sending
        # webrtcReq.  Popen() returns as soon as the process is created;
        # ffmpeg needs additional time to parse the SDP and call bind().
        # If we send webrtcReq before ffmpeg is listening, the camera's first
        # SRTP packets hit closed ports, the OS sends ICMP port-unreachable,
        # and the camera stops streaming — producing 0 frames.
        def _udp_port_bound(port: int) -> bool:
            """True if a UDP socket is currently bound to `port` on 127.0.0.1.

            Uses try-bind: if we can bind the port it's free; if EADDRINUSE
            it's taken — i.e. ffmpeg is listening.  Works on macOS and Linux
            without /proc/net/udp.
            """
            try:
                _s_pb = _socket_br.socket(
                    _socket_br.AF_INET, _socket_br.SOCK_DGRAM)
                try:
                    _s_pb.bind(('127.0.0.1', port))
                    return False   # bound cleanly → port was free
                except OSError:
                    return True    # EADDRINUSE → ffmpeg is listening
                finally:
                    _s_pb.close()
            except Exception:
                return False

        _t0 = time.monotonic()
        _bind_deadline = _t0 + 3.0
        _bound = False
        while time.monotonic() < _bind_deadline:
            if _udp_port_bound(_lo_audio_port) and _udp_port_bound(_lo_video_port):
                _bound = True
                break
            await asyncio.sleep(0.05)

        _bind_ms = int((time.monotonic() - _t0) * 1000)
        if _bound:
            _status(
                f"SDES ffmpeg ready — loopback audio={_lo_audio_port}"
                f" video={_lo_video_port} bound in {_bind_ms} ms  (pid={proc.pid})"
            )
        else:
            # /proc/net/udp unavailable or ffmpeg very slow — use fixed delay
            _status(
                f"ffmpeg port bind not confirmed after {_bind_ms} ms"
                " — sleeping 1.5 s as fallback"
            )
            await asyncio.sleep(1.5)

        # --- Wait for SDP answer -------------------------------------------- #
        # Wait for the camera's SDP answer.  True SDES cameras (e.g.
        # LK.IPC.A001513) send webrtcResp within a few seconds.  If no
        # answer arrives the camera is not operating in SDES mode — most
        # likely it has enableSdes='1' set incorrectly and actually requires
        # DTLS.  In that case abort the ffmpeg process and raise
        # _SdesNoAnswerError so the caller retries with the DTLS path.
        # Battery SDES cameras (A001513 etc.) take up to ~15s to wake from
        # deep sleep — they answer webrtcReq well after the bridge starts.
        # Cameras with DTLS fallback keep 8s so the fallback fires quickly.
        _sdes_answer_timeout = (
            sdes_answer_timeout if sdes_answer_timeout is not None
            else min(timeout, 8.0 if dtls_fallback_ok else 20.0)
        )
        try:
            answer = await asyncio.wait_for(answer_fut, timeout=_sdes_answer_timeout)
            _ans_sdp = answer.get("sdp", "")
            _ans_mlines = [ln for ln in _ans_sdp.splitlines() if ln.startswith("m=")]
            _status(
                "webrtcResp received (SDES) — answer m-sections (%d): %s"
                % (len(_ans_mlines), " | ".join(_ans_mlines))
            )
            # If the answer arrived late (after bridge started without ICE creds),
            # parse the camera's ICE credentials now and populate _bridge_uc_info
            # so the bridge can send USE-CANDIDATE on the next camera BindingReq.
            if not _bridge_uc_info["sent"] and not _bridge_uc_info["ufrag"] and _ans_sdp:
                import re as _re_late_ice
                _late_ufrag = _late_pwd = ""
                _late_cands: list = []
                for _al in _ans_sdp.splitlines():
                    if _al.startswith("a=ice-ufrag:") and not _late_ufrag:
                        _late_ufrag = _al[len("a=ice-ufrag:"):].strip()
                    elif _al.startswith("a=ice-pwd:") and not _late_pwd:
                        _late_pwd = _al[len("a=ice-pwd:"):].strip()
                    elif _al.startswith("a=candidate:"):
                        _cm = _re_late_ice.match(
                            r"a=candidate:\S+ \d+ udp \d+ ([\d.]+) (\d+) typ",
                            _al,
                        )
                        if _cm:
                            _late_cands.append(
                                (_cm.group(1), int(_cm.group(2))))
                if _late_ufrag and _late_pwd and _late_cands:
                    _bridge_uc_info["ufrag"]  = _late_ufrag
                    _bridge_uc_info["pwd"]    = _late_pwd
                    _bridge_uc_info["cands"]  = _late_cands
                    # Update _dc_answer_has_app and _cam_key_audio so the bridge's
                    # SCTP path activates for late-wake cameras.
                    if "m=application" in _ans_sdp:
                        _dc_answer_has_app = True
                    if not _cam_key_audio and _ans_sdp:
                        import re as _re_lk
                        _lk_in = False
                        for _lk_ln in _ans_sdp.splitlines():
                            if _lk_ln.startswith("m=audio"):
                                _lk_in = True
                            elif _lk_ln.startswith("m=") and _lk_in:
                                break
                            elif _lk_in and _lk_ln.startswith("a=crypto:"):
                                _lk_m = _re_lk.search(r"inline:([A-Za-z0-9+/=]+)", _lk_ln)
                                if _lk_m:
                                    _cam_key_audio = _lk_m.group(1)
                                    break
                    _status(
                        f"late ICE creds parsed — bridge will send USE-CANDIDATE"
                        f" to {len(_late_cands)} candidate(s)"
                        + (" [m=application present]" if _dc_answer_has_app else "")
                        + (f" [cam_key set: {_cam_key_audio[:8]}...]" if _cam_key_audio else "")
                    )
            # For echo-reversal cameras (A001064) the first answer_fut was set by
            # the broker echo of our own webrtcResp.  Wait briefly for the camera's
            # real second webrtcResp, which may carry a different SRTP key.
            if second_answer_fut is not None and _cam_echo_received and not second_answer_fut.done():
                try:
                    _second_ans = await asyncio.wait_for(
                        asyncio.shield(second_answer_fut), timeout=5.0
                    )
                except asyncio.TimeoutError:
                    _second_ans = None
            elif second_answer_fut is not None and second_answer_fut.done():
                try:
                    _second_ans = second_answer_fut.result()
                except Exception:
                    _second_ans = None
            else:
                _second_ans = None

            if _second_ans:
                _second_sdp = _second_ans.get("sdp", "")
                if _second_sdp:
                    _status("camera real webrtcResp — extracting SRTP keys")
                    import re as _re2

                    def _extract_key(sdp, media):
                        _in_sec = False
                        for _ln in sdp.splitlines():
                            if _ln.startswith(f"m={media}"):
                                _in_sec = True
                            elif _ln.startswith("m=") and _in_sec:
                                break
                            elif _in_sec and _ln.startswith("a=crypto:"):
                                _km = _re2.search(r"inline:([A-Za-z0-9+/=]+)", _ln)
                                if _km:
                                    return _km.group(1)
                        return ""

                    _real_key_audio = _extract_key(_second_sdp, "audio")
                    _real_key_video = _extract_key(_second_sdp, "video")
                    _keys_changed = False
                    if _real_key_audio and _real_key_audio != srtp_key_audio:
                        _status("camera audio SRTP key differs from offer — restarting ffmpeg")
                        srtp_key_audio = _real_key_audio
                        _keys_changed = True
                    if _real_key_video and _real_key_video != srtp_key_video:
                        _status("camera video SRTP key differs from offer — restarting ffmpeg")
                        srtp_key_video = _real_key_video
                        _keys_changed = True
                    if _keys_changed:
                        proc.terminate()
                        try:
                            proc.wait(timeout=2)
                        except Exception:
                            proc.kill()
                        _ts2 = int(time.time())
                        _new_sdp = (
                            "v=0\r\n"
                            f"o=- {_ts2} {_ts2} IN IP4 0.0.0.0\r\n"
                            "s=aidot-sdes-rx\r\n"
                            "t=0 0\r\n"
                            f"m=audio {_lo_audio_port} RTP/SAVP 0 8\r\n"
                            "c=IN IP4 127.0.0.1\r\n"
                            f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{srtp_key_audio}\r\n"
                            "a=rtpmap:0 PCMU/8000\r\n"
                            "a=rtpmap:8 PCMA/8000\r\n"
                            "a=rtcp-mux\r\n"
                            f"m=video {_lo_video_port} RTP/SAVP 96 97\r\n"
                            "c=IN IP4 127.0.0.1\r\n"
                            f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{srtp_key_video}\r\n"
                            "a=rtpmap:96 H264/90000\r\n"
                            "a=fmtp:96 level-asymmetry-allowed=1;packetization-mode=1;"
                            "profile-level-id=42e01f\r\n"
                            "a=rtpmap:97 H265/90000\r\n"
                            "a=fmtp:97 level-id=93\r\n"
                            "a=rtcp-mux\r\n"
                        )
                        try:
                            with open(sdp_path, "w") as _f2:
                                _f2.write(_new_sdp)
                        except Exception as _sdp_exc2:
                            _LOGGER.warning("could not rewrite SDP for restart: %s", _sdp_exc2)
                        proc = subprocess.Popen(
                            cmd,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE,
                        )
                        _status("ffmpeg restarted with camera's SRTP keys")
        except asyncio.TimeoutError:
            if _cam_echo_received:
                # We already sent webrtcResp in response to the camera's echo.
                # The camera should now be streaming; keep ffmpeg running.
                _status(
                    f"no second webrtcResp in {_sdes_answer_timeout:.0f}s"
                    " — camera acknowledged; continuing with ffmpeg"
                )
            elif dtls_fallback_ok:
                # Camera likely requires DTLS despite enableSdes='1'.  Kill
                # ffmpeg and signal the caller to retry with the DTLS path.
                _status(
                    f"no webrtcResp in {_sdes_answer_timeout:.0f}s"
                    " — SDES handshake failed; aborting ffmpeg and falling back to DTLS"
                )
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except Exception:
                    proc.kill()
                for _rsock in (_audio_sock, _video_sock):
                    try:
                        _rsock.close()
                    except Exception:
                        pass
                try:
                    os.unlink(sdp_path)
                except Exception:
                    pass
                outgoing_q.put_nowait(None)   # signal MQTT thread to exit
                raise DeviceClient._SdesNoAnswerError()
            else:
                # isDTLS='0': this camera cannot do DTLS so falling back is
                # pointless.  Some SDES cameras (e.g. LK.IPC.A001064) start
                # streaming SRTP directly to our ports without sending a
                # webrtcResp SDP answer.  Keep ffmpeg running — it already
                # has the SRTP key it needs from the offered SDP, and the
                # camera's RTP should start arriving momentarily.
                _status(
                    f"no webrtcResp in {_sdes_answer_timeout:.0f}s"
                    " — isDTLS=0: DTLS fallback not available;"
                    " continuing with ffmpeg (camera may stream without SDP answer)"
                )
                # Battery cameras often answer after the 20s timeout (they take
                # 15-25s to wake).  The answer arrives as a second webrtcResp
                # (answer_fut was cancelled, so MQTT handler sets second_answer_fut).
                # Spawn a background task to pick it up and inject ICE credentials
                # into _bridge_uc_info so the bridge can send USE-CANDIDATE.
                if second_answer_fut is not None:
                    import re as _re_sa
                    async def _late_second_answer_task():
                        nonlocal _dc_answer_has_app
                        try:
                            _la = await asyncio.wait_for(
                                asyncio.shield(second_answer_fut), timeout=30.0
                            )
                            _la_sdp = (_la or {}).get("sdp", "") if _la else ""
                            if (_la_sdp
                                    and not _bridge_uc_info["sent"]
                                    and not _bridge_uc_info["ufrag"]):
                                _la_ufrag = _la_pwd = ""
                                _la_cands: list = []
                                for _ll in _la_sdp.splitlines():
                                    if _ll.startswith("a=ice-ufrag:") and not _la_ufrag:
                                        _la_ufrag = _ll[len("a=ice-ufrag:"):].strip()
                                    elif _ll.startswith("a=ice-pwd:") and not _la_pwd:
                                        _la_pwd = _ll[len("a=ice-pwd:"):].strip()
                                    elif _ll.startswith("a=candidate:"):
                                        _cm2 = _re_sa.match(
                                            r"a=candidate:\S+ \d+ udp \d+ ([\d.]+) (\d+) typ",
                                            _ll,
                                        )
                                        if _cm2:
                                            _la_cands.append(
                                                (_cm2.group(1), int(_cm2.group(2))))
                                if _la_ufrag and _la_pwd and _la_cands:
                                    _bridge_uc_info["ufrag"]  = _la_ufrag
                                    _bridge_uc_info["pwd"]    = _la_pwd
                                    _bridge_uc_info["cands"]  = _la_cands
                                    if "m=application" in _la_sdp:
                                        _dc_answer_has_app = True
                                    _status(
                                        f"late second_answer_fut: ICE creds parsed"
                                        f" ({len(_la_cands)} candidate(s))"
                                        + (" [m=app]" if _dc_answer_has_app else "")
                                    )
                        except Exception:
                            pass
                    asyncio.ensure_future(_late_second_answer_task())

        return SdesSession(
            proc=proc,
            sdp_path=sdp_path,
            outgoing_q=outgoing_q,
            mqtt_fut=mqtt_fut,
            audio_sock=_audio_sock,   # bridge thread keeps these open; stop() closes them
            video_sock=_video_sock,
            cmd_chan=_cmd_chan,
        )

    # -- Existing methods (unchanged) ---------------------------------------- #

    async def connect(self, ip_address) -> None:
        _LOGGER.info(f"connect device : {ip_address}")
        self.reader = self.writer = None
        self._connecting = True
        try:
            self.reader, self.writer = await asyncio.open_connection(ip_address, 10000)
            sock: socket.socket = self.writer.get_extra_info("socket")
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.seq_num = 1
            await self.login()
            self._connect_and_login = True
        except Exception:
            self._connect_and_login = False
        finally:
            self._connecting = False

    def update_ip_address(self, ip: str) -> None:
        if ip is None:
            return
        self._ip_address = ip
        if self._connecting is not True and self._connect_and_login is not True:
            asyncio.get_running_loop().create_task(self.async_login())

    async def async_login(self) -> None:
        if self._ip_address is None:
            return
        if self._connecting is not True and self._connect_and_login is not True:
            await self.connect(self._ip_address)

    def get_send_packet(self, message, msgtype):
        magic = struct.pack(">H", 0x1EED)
        _msgtype = struct.pack(">h", msgtype)
        if self.aes_key is not None:
            send_data = aes_encrypt(message, self.aes_key)
        else:
            send_data = message
        bodysize = struct.pack(">i", len(send_data))
        packet = magic + _msgtype + bodysize + send_data
        return packet

    async def login(self) -> None:
        login_seq = str(int(time.time() * 1000) + self._login_uuid)[-9:]
        self._login_uuid += 1
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
        message = {
            "service": "device",
            "method": "loginReq",
            "seq": login_seq,
            "srcAddr": self.user_id,
            "deviceId": self.device_id,
            "payload": {
                "userId": self.user_id,
                "password": self.password,
                "timestamp": timestamp,
                "ascNumber": 1,
            },
        }
        try:
            self.writer.write(self.get_send_packet(json.dumps(message).encode(), 1))
            await self.writer.drain()
            data = await self.reader.read(1024)
        except (BrokenPipeError, ConnectionResetError) as e:
            _LOGGER.error(f"{self.device_id} login read status error {e}")
        except Exception as e:
            _LOGGER.error(f"recv data error {e}")

        data_len = len(data)
        if data_len <= 0:
            return

        try:
            magic, msgtype, bodysize = struct.unpack(">HHI", data[:8])
            encrypted_data = data[8:]
            if self.aes_key is not None:
                decrypted_data = aes_decrypt(encrypted_data, self.aes_key)
            else:
                decrypted_data = encrypted_data
            json_data = json.loads(decrypted_data)
            code = json_data[CONF_ACK][CONF_CODE]
            if code != 200:
                _LOGGER.error(f"{self.device_id} login error, code: {code}")
                await self.reset()
                return
            self.ascNumber = json_data[CONF_PAYLOAD][CONF_ASCNUMBER]
            self.ascNumber += 1
            self.status.online = True
            asyncio.get_running_loop().create_task(self.reveive_data())
            _LOGGER.info(f"connect device success: {self._ip_address}")
            await self.send_action({}, "getDevAttrReq")
        except Exception as e:
            _LOGGER.error(f"connect device error : {e}")
            return

    async def reveive_data(self) -> None:
        while True:
            try:
                data = await self.reader.read(1024)
            except (BrokenPipeError, ConnectionResetError) as e:
                _LOGGER.error(f"{self.device_id} read status error {e}")
                await self.reset()
                self.status.online = False
                return
            except Exception as e:
                _LOGGER.error(f"recv data error {e}")
                return
            data_len = len(data)
            if data_len <= 0:
                _LOGGER.error("recv data error len, exit socket")
                await self.reset()
                self.status.online = False
                return
            try:
                magic, msgtype, bodysize = struct.unpack(">HHI", data[:8])
                decrypted_data = aes_decrypt(data[8:], self.aes_key)
                json_data = json.loads(decrypted_data)
            except Exception as e:
                _LOGGER.error(f"recv json error : {e}")
                continue
            if "service" in json_data:
                if "test" == json_data["service"]:
                    self.ping_count = 0
                    continue
            payload = json_data.get(CONF_PAYLOAD)
            if payload is not None:
                self.ascNumber = payload.get(CONF_ASCNUMBER)
                self.status.update(payload.get(CONF_ATTR))
                if self._status_fresh_cb:
                    self._status_fresh_cb(self.status)

    def set_status_fresh_cb(self, callback) -> None:
        self._status_fresh_cb = callback

    async def read_status(self) -> DeviceStatusData:
        return self.status

    async def ping_task(self) -> None:
        while True:
            if self._is_close:
                return
            await asyncio.sleep(5)
            await self.send_ping_action()
            await asyncio.sleep(5)

    async def send_dev_attr(self, dev_attr) -> None:
        if not self._connect_and_login:
            raise ConnectionError('Device offline')
        await self.send_action(dev_attr, "setDevAttrReq")

    async def async_turn_off(self) -> None:
        await self.send_dev_attr({CONF_ON_OFF: 0})

    async def async_turn_on(self) -> None:
        await self.send_dev_attr({CONF_ON_OFF: 1})

    async def async_set_brightness(self, brightness: int) -> None:
        final_dimming = int(brightness * 100 / 255)
        await self.send_dev_attr({CONF_DIMMING: final_dimming})

    async def async_set_rgbw(self, rgbw: tuple[int, int, int, int]) -> None:
        final_rgbw = (rgbw[0] << 24) | (rgbw[1] << 16) | (rgbw[2] << 8) | rgbw[3]
        await self.send_dev_attr({CONF_RGBW: ctypes.c_int32(final_rgbw).value})

    async def async_set_cct(self, cct: int) -> None:
        await self.send_dev_attr({CONF_CCT: cct})

    async def send_action(self, attr, method) -> None:
        current_timestamp_milliseconds = int(time.time() * 1000)
        self.seq_num += 1
        seq = "ha93" + str(self.seq_num).zfill(5)
        if not self.status.on and CONF_ON_OFF not in attr:
            self.status.on = True
            attr[CONF_ON_OFF] = 1
        if self._simpleVersion is not None:
            action = {
                "method": method,
                "service": "device",
                "clientId": "ha-" + self.user_id,
                "srcAddr": "0." + self.user_id,
                "seq": "" + seq,
                "payload": {
                    "devId": self.device_id,
                    "parentId": self.device_id,
                    "userId": self.user_id,
                    "password": self.password,
                    "attr": attr,
                    "channel": "tcp",
                    "ascNumber": self.ascNumber,
                },
                "tst": current_timestamp_milliseconds,
                "deviceId": self.device_id,
            }
        else:
            action = {
                "method": method,
                "service": "device",
                "seq": "" + seq,
                "srcAddr": "0." + self.user_id,
                "payload": {
                    "attr": attr,
                    "ascNumber": self.ascNumber,
                },
                "tst": current_timestamp_milliseconds,
                "deviceId": self.device_id,
            }
        try:
            self.writer.write(self.get_send_packet(json.dumps(action).encode(), 1))
            await self.writer.drain()
        except (BrokenPipeError, ConnectionResetError) as e:
            _LOGGER.error(f"{self.device_id} send action error {e}")
            await self.reset()
        except Exception as e:
            _LOGGER.error(f"{self.device_id} send action error {e}")

    async def send_ping_action(self) -> int:
        ping = {
            "service": "test",
            "method": "pingreq",
            "seq": "123456",
            "srcAddr": "x.xxxxxxx",
            CONF_PAYLOAD: {},
        }
        try:
            if self.ping_count >= 2:
                _LOGGER.error(
                    f"Last ping did not return within 20 seconds. device id:{self.device_id}"
                )
                await self.reset()
                return -1
            if self._connect_and_login is False:
                return -1
            self.writer.write(self.get_send_packet(json.dumps(ping).encode(), 2))
            await self.writer.drain()
            self.ping_count += 1
            return 1
        except Exception as e:
            _LOGGER.error(f"{self.device_id} ping error {e}")
            await self.reset()
            return -1

    async def reset(self) -> None:
        try:
            if self.writer:
                self.writer.close()
                await self.writer.wait_closed()
        except Exception as e:
            _LOGGER.error(f"{self.device_id} writer close error {e}")
        self._connect_and_login = False
        self.status.online = False
        self.ping_count = 0

    async def close(self) -> None:
        self._is_close = True
        await self.async_stop_streaming()
        await self.reset()
        _LOGGER.info(f"{self.device_id} connect close by user")
