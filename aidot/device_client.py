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
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, List, Optional

from .aes_utils import aes_encrypt, aes_decrypt
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

    def __init__(self, device: dict[str, Any]) -> None:
        self.dev_id = device.get(CONF_ID)
        self.mac = device.get(CONF_MAC) if device.get(CONF_MAC) is not None else ""
        self.model_id = device.get(CONF_MODEL_ID)
        self.name = device.get(CONF_NAME)
        self.hw_version = device.get(CONF_HARDWARE_VERSION)
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

# --------------------------------------------------------------------------- #
# AES helpers (live stream)
#
# Source: AESUtils.java in Leedarson Android SDK.
# Algorithm: AES/ECB/PKCS7Padding, key zero-padded to 32 bytes.
# --------------------------------------------------------------------------- #

def _aes_pad_key(key_str: str) -> bytes:
    # Replicate AESUtils.get32Key(): take UTF-8 bytes of key, zero-pad to 32.
    raw = key_str.encode("utf-8")
    return raw[:32].ljust(32, b"\x00")


def _aes_ecb_decrypt(key_str: str, data: bytes) -> bytes:
    # AES-256/ECB/PKCS7 decrypt. Used to decrypt live-stream TCP frame payloads.
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding as sym_padding
    except ImportError as exc:
        raise ImportError(
            "The 'cryptography' package is required for live-stream decryption. "
            "Install it with:  pip install cryptography"
        ) from exc
    key = _aes_pad_key(key_str)
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    dec = cipher.decryptor()
    padded = dec.update(data) + dec.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def _aes_ecb_encrypt(key_str: str, data: bytes) -> bytes:
    # AES-256/ECB/PKCS7 encrypt. Used to encrypt outbound live-stream payloads.
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding as sym_padding
    except ImportError as exc:
        raise ImportError(
            "The 'cryptography' package is required for live-stream encryption. "
            "Install it with:  pip install cryptography"
        ) from exc
    key = _aes_pad_key(key_str)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    enc = cipher.encryptor()
    return enc.update(padded) + enc.finalize()




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
                is_key_frame = bool(fi.flags & 0x1),
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
            login_enc = _aes_ecb_encrypt(self._aes_key, login_body_raw)
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
                resp_plain = _aes_ecb_decrypt(self._aes_key, payload)
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
            stream_enc = _aes_ecb_encrypt(self._aes_key, stream_body_raw)
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
                        hb_enc = _aes_ecb_encrypt(self._aes_key, b"{}")
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
                    plain = _aes_ecb_decrypt(self._aes_key, payload)
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
    ) -> None:
        self._pc          = pc
        self._outgoing_q  = outgoing_q
        self._mqtt_fut    = mqtt_fut
        self._recorder    = recorder
        self._track_tasks = track_tasks

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
    ) -> None:
        self._proc       = proc
        self._sdp_path   = sdp_path
        self._outgoing_q = outgoing_q
        self._mqtt_fut   = mqtt_fut
        self._audio_sock = audio_sock
        self._video_sock = video_sock

    async def stop(self) -> None:
        """Tear down the stream: terminate ffmpeg and stop MQTT."""
        self._proc.terminate()
        try:
            self._proc.wait(timeout=5)
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


async def _webrtc_consume_video(track: Any, on_frame: Callable) -> None:
    """Receive video frames from an aiortc VideoStreamTrack and call on_frame."""
    while True:
        try:
            frame = await track.recv()
            try:
                on_frame(frame)
            except Exception:
                pass
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
        ctx.check_hostname = False
        ctx.verify_mode    = _ssl.CERT_NONE
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
        status["log"].append(buf)
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
    import functools
    loop = asyncio.get_running_loop()
    fn = functools.partial(
        _mqtt_session_sync,
        mqtt_url, mqtt_user, mqtt_pwd, client_id,
        subscribe_topics, publish_items, duration, on_message, ws_path, on_ready,
    )
    messages, status = await loop.run_in_executor(None, fn)
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

    @property
    def is_sdes_camera(self) -> bool:
        """True if the camera uses SDES-SRTP rather than DTLS-SRTP.

        Determined by ``properties.enableSdes`` in the device API response:
        ``'1'`` → SDES explicitly enabled → SDES path.
        anything else → DTLS-SRTP path (default).

        ``isDTLS: '0'`` is NOT used here — iOS app session captures confirm
        that cameras with ``isDTLS: '0'`` (e.g. LK.IPC.A000088) still respond
        with a full DTLS fingerprint answer.  ``enableSdes: '0'`` (the default)
        means SDES is disabled, so those cameras must use DTLS.
        """
        props = getattr(self, "_raw_device", {}).get("properties") or {}
        return str(props.get("enableSdes", "0")) == "1"

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
        # does not respond to getDevAttrReq with a setDevAttrNotif.
        _dev_ip_init = (
            device.get("localIp") or device.get("ipAddress")
            or device.get("ip") or device.get("localIPAddress")
            or device.get("wlanIp") or device.get("wifiIp")
            or device.get("lanIp") or device.get("addr")
            or (device.get("properties") or {}).get("ipAddress")
            or (device.get("properties") or {}).get("ip")
        )
        if _dev_ip_init:
            self._ip_address = _dev_ip_init

    # -- Camera helpers ------------------------------------------------------ #

    @property
    def _smarthome_base(self) -> str:
        return _SMARTHOME_URL_TEMPLATE.format(region=self._region)

    def _leedarson_headers(self) -> dict:
        # HTTP headers required by the Leedarson smarthome API.
        # Mirrors header construction in LDSOpenSDK.java.
        token = (
            self._user_info.get("accessToken")
            or self._user_info.get("access_token")
            or ""
        )
        return {
            "terminal":        "thirdPlatFormUser",
            "active-language": "en_US",
            "access-token":    token,
            "token":           token,
            "appKey":          _LEEDARSON_APP_KEY,
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
            _LOGGER.warning("getServerUrlConfig full response data keys=%s  body=%s", list(data.keys()), body)

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
                    "Server config cached: url=%s mqttUser=%s hasPwd=%s  all_keys=%s",
                    self._mqtt_url,
                    self._smarthome_auth["mqttUser"],
                    bool(self._smarthome_auth["mqttPassword"]),
                    list(data.keys()),
                )
                _LOGGER.warning("getServerUrlConfig data=%s", data)

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
          1. mqttPassword already in AiDot login_info (unlikely but cheap to check)
          2. GET /user/getUser  <- THE DOCUMENTED STEP 3 from LDSAppOpenSDK CocoaPods README
             The SDK calls reqUserAuthInfoWithCallback which hits /user/getUser?desc=...
             and returns LDSAuthInfo {userId, mqttUser, mqttPassword, ...}
          3. getServerUrlConfig response (fallback — may not include mqtt creds)
          4. POST /user/login form-encoded with multiple appId/pwd variants (last resort)
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
        for key in ("mqttPassword", "mqqtPwd", "mqttPwd", "mqtt_pwd",
                    "mqttPass", "mqtttoken", "mqttToken", "MQTTPassword"):
            val = self._user_info.get(key)
            if val:
                _LOGGER.warning("_async_get_smarthome_auth: found %r in login_info", key)
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
            for desc_val in (_mqtt_id, "", None):
                body_data = {"desc": desc_val} if desc_val is not None else {}
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.post(
                            f"{self._smarthome_base}/user/getUser",
                            headers=headers,
                            json=body_data,
                            timeout=aiohttp.ClientTimeout(total=10),
                        ) as resp:
                            body = await resp.json(content_type=None)

                    code = body.get("code")
                    data = body.get("data") or {}
                    _LOGGER.debug(
                        "_async_get_smarthome_auth POST /user/getUser desc=%r -> "
                        "code=%s  data_keys=%s",
                        desc_val, code,
                        list(data.keys()) if isinstance(data, dict) else data,
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
                            _LOGGER.warning(
                                "_async_get_smarthome_auth OK via /user/getUser: "
                                "mqttUser=%s desc=%r", mqtt_user, desc_val,
                            )
                            return self._smarthome_auth

                    if code not in (200, 0, None):
                        break  # hard error, don't retry other desc values

                except Exception as exc:
                    _LOGGER.debug("_async_get_smarthome_auth /user/getUser exc: %s", exc)
                    print(f"    [getUser] EXCEPTION: {exc}")
                    break

        # --- Strategy 3: getServerUrlConfig ---
        if not self._mqtt_url:
            await self._async_get_mqtt_url()
        if self._smarthome_auth and self._smarthome_auth.get("mqttPassword"):
            _LOGGER.warning("_async_get_smarthome_auth: mqttPassword from getServerUrlConfig")
            return self._smarthome_auth

        # --- Strategy 4: POST /user/login (form-encoded, multiple appId+pwd variants) ---
        import hashlib

        username = (
            self._user_info.get("username")
            or self._user_info.get("userName")
            or ""
        )
        password = (
            self._user_info.get("password")
            or self._user_info.get("passWord")
            or ""
        )
        if not username or not password:
            _LOGGER.error(
                "_async_get_smarthome_auth: username/password missing — cannot try /user/login"
            )
            return None

        rsa_pwd: Optional[str] = None
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import padding as _apad
            from cryptography.hazmat.backends import default_backend
            import base64 as _b64
            _PUBLIC_KEY_PEM = (
                b"-----BEGIN PUBLIC KEY-----\n"
                b"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCtQAnPCi8ksPnS1Du6z96PsKfN\n"
                b"p2Gp/f/bHwlrAdplbX3p7/TnGpnbJGkLq8uRxf6cw+vOthTsZjkPCF7CatRvRnTj\n"
                b"c9fcy7yE0oXa5TloYyXD6GkxgftBbN/movkJJGQCc7gFavuYoAdTRBOyQoXBtm0m\n"
                b"kXMSjXOldI/290b9BQIDAQAB\n"
                b"-----END PUBLIC KEY-----"
            )
            pub_key = serialization.load_pem_public_key(
                _PUBLIC_KEY_PEM, backend=default_backend()
            )
            rsa_pwd = _b64.b64encode(
                pub_key.encrypt(password.encode("utf-8"), _apad.PKCS1v15())
            ).decode("utf-8")
        except Exception as exc:
            _LOGGER.debug("RSA encrypt unavailable: %s", exc)

        md5_pwd = hashlib.md5(password.encode("utf-8")).hexdigest().upper()
        _AIDOT_APP_ID = "1383974540041977857"
        pwd_variants = []
        if rsa_pwd:
            pwd_variants.append(("rsa", rsa_pwd))
        pwd_variants.append(("plain", password))
        pwd_variants.append(("md5", md5_pwd))

        login_headers = {
            "terminal":        "thirdPlatFormUser",
            "active-language": "en_US",
            "appKey":          _LEEDARSON_APP_KEY,
        }
        # smarthome tenantId (integer 11 from /user/getUser) is different from
        # the AiDot platform tid ("0001IF").  Passing the AiDot tid causes a
        # server-side NumberFormatException (500).  Use the smarthome tenantId
        # if we fetched it; otherwise omit the field entirely.
        _smarthome_tenant_id = str(
            self._smarthome_auth.get("tenantId", "")
            if self._smarthome_auth else ""
        )
        _phone_id = (
            self._user_info.get("terminalIndex")
            or self._user_info.get("phoneId")
            or ""
        )
        last_body: dict = {}
        # The Android SDK uses Retrofit @QueryMap on POST (/deviceController/getP2pId etc.)
        # which appends params as URL query string, NOT as form body.  Try both styles:
        #   "qs"   = params= (URL query string)   <-- Retrofit @QueryMap pattern
        #   "form" = data=   (x-www-form-urlencoded body)
        #   "json" = json=   (application/json body)
        _login_styles = [
            ("qs",   lambda d: {"params": d}),
            ("form", lambda d: {"data":   d}),
            ("json", lambda d: {"json":   d}),
        ]
        async with aiohttp.ClientSession() as session:
            for app_id in (_LEEDARSON_APP_KEY, _AIDOT_APP_ID):
                for pwd_type, pwd_val in pwd_variants:
                    base_data = {
                        "userName":     username,
                        "passWord":     pwd_val,
                        "os":           "ios",
                        "terminalMark": "app",
                        "appId":        app_id,
                        "phoneId":      _phone_id,
                        "locationId":   self._region or "us",
                    }
                    if _smarthome_tenant_id:
                        base_data["tenantId"] = _smarthome_tenant_id
                    for style, make_kw in _login_styles:
                        try:
                            async with session.post(
                                f"{self._smarthome_base}/user/login",
                                headers=login_headers,
                                timeout=aiohttp.ClientTimeout(total=10),
                                **make_kw(base_data),
                            ) as resp:
                                last_body = await resp.json(content_type=None)

                            code = last_body.get("code")
                            _LOGGER.warning(
                                "_async_get_smarthome_auth /user/login style=%s appId=%s pwd=%s "
                                "-> code=%s: %s",
                                style, app_id, pwd_type, code, last_body.get("desc"),
                            )
                            print(f"    [/user/login] style={style} appId={app_id} pwd={pwd_type} "
                                  f"tenantId={_smarthome_tenant_id!r} -> code={code} "
                                  f"desc={last_body.get('desc')!r}")
                            if code not in (200, 0):
                                continue

                            data = last_body.get("data") or {}
                            if isinstance(data, str):
                                import json as _json
                                try:
                                    data = _json.loads(data)
                                except Exception:
                                    data = {}

                            auth = (data.get("authInfo") if isinstance(data, dict) else None) or data
                            mqtt_user = (
                                (auth.get("mqttUser")             if isinstance(auth, dict) else None)
                                or (auth.get("userId")            if isinstance(auth, dict) else None)
                                or (auth.get("associatedAccount") if isinstance(auth, dict) else None)
                                or _mqtt_id
                            )
                            mqtt_pwd = (
                                (auth.get("mqttPassword") if isinstance(auth, dict) else None)
                                or (auth.get("mqqtPwd")   if isinstance(auth, dict) else None)
                                or (auth.get("mqttPwd")   if isinstance(auth, dict) else None)
                                or ""
                            )
                            if mqtt_pwd:
                                self._smarthome_auth = {
                                    "mqttUser":     mqtt_user,
                                    "mqttPassword": mqtt_pwd,
                                    "userId":       (auth.get("userId") if isinstance(auth, dict) else None) or mqtt_user,
                                    "raw":          auth,
                                }
                                _LOGGER.warning(
                                    "_async_get_smarthome_auth OK via /user/login: "
                                    "mqttUser=%s style=%s appId=%s pwd=%s",
                                    mqtt_user, style, app_id, pwd_type,
                                )
                                return self._smarthome_auth

                            _LOGGER.warning(
                                "_async_get_smarthome_auth /user/login code=200 but no "
                                "mqttPassword. data_keys=%s  auth_keys=%s",
                                list(data.keys()) if isinstance(data, dict) else data,
                                list(auth.keys()) if isinstance(auth, dict) else auth,
                            )

                        except Exception as exc:
                            _LOGGER.debug(
                                "_async_get_smarthome_auth /user/login style=%s appId=%s pwd=%s: %s",
                                style, app_id, pwd_type, exc,
                            )
                            continue

        # --- Strategy 5: accessToken as MQTT password (common Arnoo pattern) ---
        # The Arnoo broker frequently accepts (userId, accessToken) as credentials.
        # This is always available and is the first candidate --diag-mqtt tries.
        # Use it as a guaranteed non-empty fallback rather than returning None.
        access_token = (
            self._user_info.get("accessToken")
            or self._user_info.get("access_token")
            or ""
        )
        if access_token:
            _LOGGER.warning(
                "_async_get_smarthome_auth: all HTTP strategies failed; "
                "falling back to userId+accessToken for MQTT (common Arnoo pattern). "
                "last_body=%s", last_body,
            )
            self._smarthome_auth = {
                "mqttUser":     _mqtt_id,
                "mqttPassword": access_token,
                "userId":       _mqtt_id,
                "raw":          {"source": "accessToken_fallback"},
            }
            return self._smarthome_auth

        _LOGGER.error(
            "_async_get_smarthome_auth: all strategies failed (no accessToken either). "
            "last_body=%s  login_info_keys=%s",
            last_body,
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
                return data.get(self.device_id) or next(iter(data.values()), None)
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

    async def async_get_cloud_recordings(
        self,
        start_ts: int,
        end_ts: int,
        *,
        page: int = 1,
        page_size: int = 100,
    ) -> List[dict]:
        # List cloud-recorded time slots for this camera.
        # start_ts / end_ts: Unix timestamps in milliseconds.
        # Returns list of {"sta": <ms>, "end": <ms>} dicts.
        # POST /api/ipc/playbackController/getRecordTimeSlot
        import aiohttp

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self._smarthome_base}"
                    "/api/ipc/playbackController/getRecordTimeSlot",
                    json={
                        "deviceId":      self.device_id,
                        "recordStaTime": start_ts,
                        "recordEndTime": end_ts,
                        "pageNum":       page,
                        "pageSize":      page_size,
                        "timeout":       20_000,
                    },
                    headers=self._leedarson_headers(),
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    body = await resp.json(content_type=None)

            if body.get("code") != 200:
                _LOGGER.warning(
                    "getRecordTimeSlot returned code=%s for %s",
                    body.get("code"), self.device_id,
                )
                return []

            items = (body.get("data") or {}).get("list") or []
            return [{"sta": int(it["sta"]), "end": int(it["end"])} for it in items]

        except Exception as exc:
            _LOGGER.error(
                "async_get_cloud_recordings failed for %s: %s", self.device_id, exc
            )
            return []

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

        terminal_idx = self._user_info.get("terminalIndex") or diag_cid.split("-")[0]
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
        status_callback: Optional[Callable[[str], None]] = None,
        force_sdes: Optional[bool] = None,
        _skip_ice_config: bool = False,
        _ice_config: "Optional[dict]" = None,
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
        terminal_idx = (
            mqtt_cid.split('-')[0]
            if '-' in mqtt_cid
            else (self._user_info.get("terminalIndex") or "0")
        )
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

        sub_topics       = [
            f"iot/v1/c/{user_id}/#",
            f"iot/v1/cb/{user_id}/#",    # catch webrtcResp on user cb channel
            f"iot/v1/cb/{device_id}/#",
            f"iot/v1/c/{device_id}/#",   # catch webrtcResp routed to device channel
            f"lds/v1/c/{user_id}/#",     # Leedarson firmware: webrtcResp on user channel
            f"lds/v1/cb/{device_id}/#",  # Leedarson firmware: webrtcResp on device cb channel
        ]
        # Some camera firmware (e.g. LK.IPC.A001064) routes webrtcResp using the
        # camera's internally registered numeric userId rather than the account UUID.
        # Subscribe to those topics so we receive the answer regardless of which ID
        # the camera firmware uses for routing.
        if numeric_user_id and numeric_user_id != user_id:
            sub_topics += [
                f"iot/v1/c/{numeric_user_id}/#",
                f"iot/v1/cb/{numeric_user_id}/#",
                f"lds/v1/c/{numeric_user_id}/#",
            ]
        # Subscribe to topics keyed by the camera's userUuid (from batchGetDeviceUserInfo).
        # Certain firmware versions route webrtcResp / webrtcReq on topics containing the
        # camera's own UUID rather than the app user's UUID.  Without this subscription we
        # only see broker echoes of our own messages; the camera's real answer (carrying its
        # actual ICE candidates) is silently dropped, forcing the broken echo-only ICE path.
        _known_ids = {user_id, device_id, numeric_user_id or ""}
        if _cam_user_uuid and _cam_user_uuid not in _known_ids:
            sub_topics += [
                f"iot/v1/c/{_cam_user_uuid}/#",
                f"iot/v1/cb/{_cam_user_uuid}/#",
                f"lds/v1/c/{_cam_user_uuid}/#",
            ]
            _LOGGER.info(
                "async_open_webrtc_stream: subscribing to camera userUuid topics"
                " for %s (userUuid=%s)",
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
        camera_reconnect_ev: asyncio.Event = asyncio.Event() # set when camera sends device/connect

        # Gate: block asyncio until MQTT is connected + subscribed
        import threading as _threading
        _mqtt_ready_ev     = _threading.Event()
        _mqtt_conn_status: dict = {}

        def _status(msg: str) -> None:
            """Fire status_callback (if provided) and log at INFO level."""
            if status_callback:
                status_callback(msg)
            _LOGGER.info("webrtc: %s", msg)

        if _numeric_uid_raw is not None and numeric_user_id != user_id:
            _status(f"Numeric userId for payload injection: {_numeric_uid_raw}")

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

        def _on_mqtt_message(topic: str, payload_str: str) -> None:
            _LOGGER.info("webrtc rx  topic=%s  %.400s", topic, payload_str)
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
                    _LOGGER.warning(
                        "SDES: second webrtcResp received (answer_fut already set)"
                        " — camera real answer SDP:\n%s",
                        answer.get("sdp", "<empty>"),
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
                    lambda m=method, p=inner, t=topic: _status(
                        f"camera replied  topic={t}  method={m!r}  payload={p!r}"
                    )
                )
            elif method == "setDevAttrNotif":
                # Camera broadcasts its real LAN IP shortly after ICE starts.
                # Capture it so the role-reversal path can inject synthetic
                # remote candidates (camera-IP + echoed ports) to give aiortc
                # a concrete target for STUN probes when the camera is ICE-lite
                # and won't send its own binding requests.
                # Check multiple field name variants — firmware differs across models.
                _cam_ip = (inner.get("ipAddress") or inner.get("ip")
                           or inner.get("localIp") or inner.get("localIPAddress")
                           or inner.get("wlanIp") or inner.get("wlanIPAddress")
                           or inner.get("deviceIp") or inner.get("localAddr")
                           or msg.get("ipAddress") or msg.get("ip")
                           or msg.get("localIp") or msg.get("localIPAddress"))
                if _cam_ip:
                    loop.call_soon_threadsafe(cam_ip_q.put_nowait, _cam_ip)
                    loop.call_soon_threadsafe(
                        lambda ip=_cam_ip: _status(
                            f"setDevAttrNotif: camera IP = {ip}"
                        )
                    )
                else:
                    _LOGGER.warning(
                        "setDevAttrNotif: no IP address field found;"
                        " inner_keys=%s  msg_keys=%s",
                        list(inner.keys()),
                        [k for k in msg if k != "payload"],
                    )
            elif method == "getDevAttrResp":
                # Some camera firmware replies to getDevAttrReq with
                # getDevAttrResp rather than the push notification
                # setDevAttrNotif.  Run the same IP-extraction logic.
                _cam_ip = (inner.get("ipAddress") or inner.get("ip")
                           or inner.get("localIp") or inner.get("localIPAddress")
                           or inner.get("wlanIp") or inner.get("wlanIPAddress")
                           or inner.get("deviceIp") or inner.get("localAddr")
                           or msg.get("ipAddress") or msg.get("ip")
                           or msg.get("localIp") or msg.get("localIPAddress"))
                if _cam_ip:
                    loop.call_soon_threadsafe(cam_ip_q.put_nowait, _cam_ip)
                    loop.call_soon_threadsafe(
                        lambda ip=_cam_ip: _status(
                            f"getDevAttrResp: camera IP = {ip}"
                        )
                    )
                else:
                    _LOGGER.warning(
                        "getDevAttrResp: no IP address field found;"
                        " inner_keys=%s  msg_keys=%s",
                        list(inner.keys()),
                        [k for k in msg if k != "payload"],
                    )
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
                    lambda m=method, p=inner, t=topic: _status(
                        f"camera replied  topic={t}  method={m!r}  payload={p!r}"
                    )
                )
            else:
                loop.call_soon_threadsafe(
                    lambda m=method, p=inner, t=topic: _status(
                        f"camera replied  topic={t}  method={m!r}  payload={p!r}"
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
        # Send getDevAttrReq to prompt the camera to report its LAN IP via
        # setDevAttrNotif.  Required for ICE-lite cameras (e.g. LK.IPC.A001064)
        # whose IP is absent from batchGetDeviceUserInfo and who do not send
        # setDevAttrNotif spontaneously.  The setDevAttrNotif handler (below)
        # enqueues the IP into cam_ip_q; the ICE wait loop converts it to a
        # synthetic host candidate so aiortc can STUN-probe the camera.
        # Sent unconditionally (both initial and DTLS-fallback sessions) because
        # each session creates a new MQTT connection and a new cam_ip_q.
        # ------------------------------------------------------------------ #
        _dev_attr_req_payload = json.dumps({
            "method":  "getDevAttrReq",
            "service": "IPC",
            "devId":   device_id,
            "srcAddr": f"0.{user_id}",
            "seq":     f"ap{random.randint(1000000, 9999999)}",
            "tst":     int(time.time() * 1000),
            **( {"userId": _numeric_uid_raw} if _numeric_uid_raw is not None else {} ),
            "payload": {"devId": device_id},
        })
        outgoing_q.put_nowait(
            (f"iot/v1/s/{user_id}/IPC/getDevAttrReq", _dev_attr_req_payload)
        )

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
            outgoing_q.put_nowait(
                (f"iot/v1/s/{user_id}/IPC/getIceConfigReq", _ice_req_payload)
            )
            _status("getIceConfigReq sent — waiting for camera to wake (up to 12s)")
            try:
                await asyncio.wait_for(camera_ready_ev.wait(), timeout=12.0)
                _status("Camera awake — got MQTT signal")
            except asyncio.TimeoutError:
                # First attempt timed out — camera may be awake but the broker session
                # may not be registered yet.  Retry getIceConfigReq to re-trigger
                # broker routing registration before proceeding.
                _status("Camera wake timeout — retrying getIceConfigReq ...")
                outgoing_q.put_nowait(
                    (f"iot/v1/s/{user_id}/IPC/getIceConfigReq", _ice_req_payload)
                )
                try:
                    await asyncio.wait_for(camera_ready_ev.wait(), timeout=5.0)
                    _status("Camera awake — got MQTT signal (after retry)")
                except asyncio.TimeoutError:
                    _status("Camera wake timeout after retry — proceeding anyway")
                    if use_sdes:
                        _status(
                            "Note: getIceConfigReq timed out for claimed-SDES camera"
                            " — will fall back to DTLS if SDES handshake fails"
                        )

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
                "dstAddr": user_id,
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
                    _status=_status,
                    mqtt_fut=mqtt_fut,
                    liveplay_echo_ev=liveplay_echo_ev,
                    numeric_uid_raw=_numeric_uid_raw,
                    dtls_fallback_ok=_dtls_fallback_ok,
                    second_answer_fut=second_answer_fut,
                    ice_config=(
                        ice_config_fut.result() if ice_config_fut.done()
                        else _http_ice_config
                    ),
                    camera_reconnect_ev=camera_reconnect_ev,
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
        pc.addTransceiver("audio", direction="recvonly")   # mid:0  audio
        pc.addTransceiver("video", direction="recvonly")   # mid:1  video (H264; H265 injected below)
        pc.createDataChannel("data")                        # mid:2  SCTP datachannel
        # HAR capture of the official AiDot web app confirms cameras answer with a
        # 3-section SDP: audio (PCMA) + video (H264 PT 103) + application/SCTP.
        # H265 is advertised alongside H264 in the single video m-section (mid:1),
        # matching Chrome's behaviour.  A separate H265 m-section is wrong and causes
        # aiortc's setRemoteDescription to misalign sections (datachannel answer mapped
        # to our H265 video transceiver), breaking ICE/DTLS/media.

        track_tasks: list = []

        @pc.on("track")
        def _on_track(track) -> None:
            if track.kind == "video" and on_frame is not None:
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

        def _inject_h265_into_mid1(sdp: str) -> str:
            """Append H265 codec lines to mid:1 (the single video m-section).

            The AiDot web app (Chrome) puts ALL video codecs — VP8, VP9, H264, and
            H265 — into a single m=video section (mid:1).  Cameras with liveType=2
            require H265 to appear in that section before they will respond with
            webrtcResp.  aiortc cannot offer H265 natively, so this function injects
            the necessary lines after the existing codec list.

            H265 is assigned a dynamically chosen PT that does not collide with any
            already-used PT in the SDP (RFC 8843 §9.2 requires globally unique PTs
            across all BUNDLE m-sections).  Standard aiortc offers use PT 96–102 for
            audio/video variants, so the selection reliably lands on PT 103 or higher.
            """
            import re as _re

            # Collect all PTs already declared anywhere in the SDP.
            _used_pts: set = set()
            for _ln in _re.split(r'\r?\n', sdp):
                _mm = _re.match(r'^m=\S+ \d+ \S+ (.+)$', _ln)
                if _mm:
                    for _pt in _mm.group(1).split():
                        try:
                            _used_pts.add(int(_pt))
                        except ValueError:
                            pass  # "webrtc-datachannel" and similar
                _rm = _re.match(r'^a=rtpmap:(\d+) ', _ln)
                if _rm:
                    _used_pts.add(int(_rm.group(1)))
            _h265_pt = next(pt for pt in range(96, 128) if pt not in _used_pts)

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
                if not any(a.rstrip() == 'a=mid:1' for a in sec):
                    result.extend(sec)
                    continue
                # This is mid:1 (video) — add H265 PT to m-line and append codec attrs.
                new_sec: list[str] = []
                for ln in sec:
                    if ln.startswith('m=video '):
                        # Append the H265 PT to the codec list on the m-line.
                        new_sec.append(ln.rstrip() + f' {_h265_pt}')
                    else:
                        new_sec.append(ln)
                # Insert H265 codec lines after the last existing codec attribute.
                # Find the last rtpmap/fmtp/rtcp-fb line and insert after it.
                last_codec_idx = -1
                for i, ln in enumerate(new_sec):
                    if (ln.startswith('a=rtpmap:') or
                            ln.startswith('a=fmtp:') or
                            ln.startswith('a=rtcp-fb:')):
                        last_codec_idx = i
                h265_lines = [
                    f'a=rtpmap:{_h265_pt} H265/90000',
                    f'a=fmtp:{_h265_pt} level-id=180;profile-id=1;tier-flag=0;tx-mode=SRST',
                    f'a=rtcp-fb:{_h265_pt} nack',
                    f'a=rtcp-fb:{_h265_pt} goog-remb',
                    f'a=rtcp-fb:{_h265_pt} transport-cc',
                ]
                if last_codec_idx >= 0:
                    new_sec[last_codec_idx + 1:last_codec_idx + 1] = h265_lines
                else:
                    new_sec.extend(h265_lines)
                result.extend(new_sec)
            return '\r\n'.join(result)

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

        _offer_sdp = _strip_datachannel(
            _filter_sdp_candidates(
                _reorder_m_section_ice_attrs(
                    _normalize_bundle_ice_credentials(
                        _inject_h265_into_mid1(_upgrade_sctp(pc.localDescription.sdp))
                    )
                )
            )
        )
        _patched_mlines = [ln for ln in _offer_sdp.splitlines() if ln.startswith("m=")]
        _status("Offer m-sections (patched): %s" % " | ".join(_patched_mlines))

        # Build IceServerList from available _ice_servers for inclusion in
        # webrtcReq.  The browser always sends IceServerList; without it some
        # camera firmware (e.g. LK.IPC.A001064) does not activate its ICE
        # agent and never sends STUN probes, causing ICE to time out.
        _ice_server_list = []
        for _srv in _ice_servers:
            _uris = _srv.urls if isinstance(_srv.urls, list) else [_srv.urls]
            _entry: dict = {"Uris": _uris}
            if getattr(_srv, "username", None):
                _entry["Username"] = _srv.username
            if getattr(_srv, "credential", None):
                _entry["Password"] = _srv.credential
            _ice_server_list.append(_entry)

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
                "wPayload": {
                    "peerid": peer_id,
                    "offer":  {"type": pc.localDescription.type,
                                "sdp":  _offer_sdp},
                },
                "IceServerList": _ice_server_list,
                # Legacy flat fields — older firmware parses payload.peerid directly.
                "peerid":  peer_id,
                "devId":   device_id,
                "offer":   {"type": pc.localDescription.type,
                             "sdp":  _offer_sdp},
                "trackId": 0,
                # dstAddr matches the SDES webrtcReq format (user_id).  The broker
                # uses the MQTT topic path (iot/v1/s/{userId}/IPC/webrtcReq) for
                # camera routing, not this field; but camera firmware may use it to
                # route the webrtcResp — wrong value causes response to be silently
                # discarded or routed to the wrong endpoint.
                "dstAddr": user_id,
            },
        })
        outgoing_q.put_nowait((webrtc_req_topic, webrtc_req_payload))
        _status(f"webrtcReq sent  peerid={peer_id}"
                f"  IceServerList×{len(_ice_server_list)}")

        # Re-send getDevAttrReq now that the camera is confirmed awake
        # (it responded to livePlayReq).  The first getDevAttrReq was sent
        # at MQTT-setup time when the camera may have been sleeping; this
        # second attempt gives ICE-lite cameras (e.g. LK.IPC.A001064) a
        # better chance of returning setDevAttrNotif/getDevAttrResp with
        # their LAN IP before the ICE wait loop starts.
        if not _cam_local_ip:
            outgoing_q.put_nowait((
                f"iot/v1/s/{user_id}/IPC/getDevAttrReq",
                json.dumps({
                    "method":  "getDevAttrReq",
                    "service": "IPC",
                    "devId":   device_id,
                    "srcAddr": f"0.{user_id}",
                    "seq":     _seq(),
                    "tst":     int(time.time() * 1000),
                    **( {"userId": _numeric_uid_raw} if _numeric_uid_raw is not None else {} ),
                    "payload": {"devId": device_id},
                })
            ))

        # Forward our own ICE candidates to the camera via MQTT
        @pc.on("icecandidate")
        def _on_local_ice(candidate) -> None:
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
        _rr_done, _rr_pending = await asyncio.wait(
            {answer_fut, camera_offer_fut, webrtc_req_echo_fut},
            timeout=timeout,
            return_when=asyncio.FIRST_COMPLETED,
        )

        # Echo-reversal path: echo arrived but no proper response yet.
        # Give the camera a brief secondary window to send its real reply.
        _rr_echo_only = False  # True only for cameras that echo but never send a real webrtcResp
        if (webrtc_req_echo_fut in _rr_done
                and answer_fut not in _rr_done
                and camera_offer_fut not in _rr_done):
            _status("webrtcReq echo received — waiting briefly for camera webrtcResp...")
            _rr_done2, _rr_pending2 = await asyncio.wait(
                _rr_pending,   # {answer_fut, camera_offer_fut}
                timeout=3.0,   # 3 s is generous; real responses arrive in <1 s with userUuid fix
                return_when=asyncio.FIRST_COMPLETED,
            )
            if _rr_done2:
                # Real response arrived — proceed normally
                _rr_done, _rr_pending = _rr_done2, _rr_pending2
            else:
                # Echo-only camera (e.g. LK.IPC.A001064): use echo SDP as
                # the camera's counter-offer so the role-reversal path fires.
                _rr_echo_only = True
                _status(
                    "echo-reversal: no real webrtcResp after echo"
                    " — using echo SDP as camera offer (role-reversal)"
                )
                camera_offer_fut.set_result(webrtc_req_echo_fut.result())
                _rr_done    = {camera_offer_fut}
                _rr_pending = _rr_pending2   # answer_fut cancelled below; camera_offer_fut cancel is no-op

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

            try:
                await pc.setRemoteDescription(
                    RTCSessionDescription(
                        sdp=_ans_sdp,
                        type=answer.get("type", "answer"),
                    )
                )
            except Exception as exc:
                _status(f"setRemoteDescription failed: {exc}")
                outgoing_q.put_nowait(None)
                await pc.close()
                raise RuntimeError(
                    f"async_open_webrtc_stream: setRemoteDescription failed: {exc}"
                ) from exc

            # Extract ICE candidates embedded in the SDP answer body.
            # The AiDot camera includes its host candidate as a=candidate: lines
            # inside the answer SDP.  The browser WebRTC API processes these
            # automatically; aiortc requires explicit addIceCandidate() calls.
            import re as _re
            for _m_sdp_cand in _re.finditer(
                r'(?m)^a=candidate:(.+)$', _ans_sdp
            ):
                _sdp_cand_line = _re.sub(
                    r'\s+generation\s+\d+.*$',
                    '',
                    _m_sdp_cand.group(1).strip(),
                )
                try:
                    await pc.addIceCandidate(candidate_from_sdp(_sdp_cand_line))
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
        _devattr_midloop_sent = False  # guard: send getDevAttrReq once at half-timeout
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
            # Mid-loop getDevAttrReq retry: if no camera IP yet and ~half of the
            # ICE timeout has elapsed, send getDevAttrReq again.  The camera may
            # have been slow to wake up or the first requests may have been lost.
            _remaining = deadline - time.monotonic()
            if (not _devattr_midloop_sent
                    and cam_ip_q.empty()
                    and _remaining > 0
                    and _remaining <= timeout / 2.0):
                outgoing_q.put_nowait((
                    f"iot/v1/s/{user_id}/IPC/getDevAttrReq",
                    json.dumps({
                        "method":  "getDevAttrReq",
                        "service": "IPC",
                        "devId":   device_id,
                        "srcAddr": f"0.{user_id}",
                        "seq":     _seq(),
                        "tst":     int(time.time() * 1000),
                        **( {"userId": _numeric_uid_raw}
                            if _numeric_uid_raw is not None else {} ),
                        "payload": {"devId": device_id},
                    })
                ))
                _devattr_midloop_sent = True
                _status("getDevAttrReq re-sent (mid-loop, waiting for camera IP)")
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
        _status,
        mqtt_fut,
        liveplay_echo_ev,
        numeric_uid_raw=None,
        dtls_fallback_ok: bool = True,
        second_answer_fut=None,
        ice_config: "Optional[dict]" = None,
        camera_reconnect_ev=None,
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

        # --- Build SDES SDP offer ------------------------------------------ #
        # AES_CM_128_HMAC_SHA1_80: 16-byte key + 14-byte salt = 30 bytes.
        srtp_key_audio = base64.b64encode(os.urandom(30)).decode()
        srtp_key_video = base64.b64encode(os.urandom(30)).decode()
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
        sdes_offer_sdp = (
            "v=0\r\n"
            f"o=- {ts} {ts} IN IP4 {local_ip}\r\n"
            "s=-\r\n"
            "t=0 0\r\n"
            # audio m-section
            # a=crypto MUST precede ICE attributes (RFC 4568 §9.1) so that
            # linear-parsing camera firmware recognises this as an SDES offer
            # rather than a pure-ICE offer and does not discard the key.
            f"m=audio {audio_port} RTP/SAVPF 0 8\r\n"
            f"c=IN IP4 {_public_ip or local_ip}\r\n"
            "a=recvonly\r\n"
            "a=mid:0\r\n"
            f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{srtp_key_audio}\r\n"
            "a=rtpmap:0 PCMU/8000\r\n"
            "a=rtpmap:8 PCMA/8000\r\n"
            # a=rtcp-mux: multiplexes RTCP onto the RTP port so the camera does
            # not send RTCP to audio_port+1 (which is never bound), and so that
            # ffmpeg does not try to open a separate RTCP socket.
            "a=rtcp-mux\r\n"
            f"a=ice-ufrag:{_ufrag_a}\r\n"
            f"a=ice-pwd:{_pwd_a}\r\n"
            f"a=candidate:1 1 udp 2130706431 {local_ip} {audio_port} typ host\r\n"
            # srflx (server-reflexive / public IP) candidate — allows cameras
            # on WAN or a different subnet to probe us at our outward-facing IP.
            # Priority 1694498815 = standard ICE srflx priority for UDP+IPv4.
            + (
                f"a=candidate:2 1 udp 1694498815 {_public_ip} {audio_port}"
                f" typ srflx raddr {local_ip} rport {audio_port}\r\n"
                if _public_ip else ""
            )
            # video m-section
            + f"m=video {video_port} RTP/SAVPF 96 97\r\n"
            f"c=IN IP4 {_public_ip or local_ip}\r\n"
            "a=recvonly\r\n"
            "a=mid:1\r\n"
            f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{srtp_key_video}\r\n"
            "a=rtpmap:96 H264/90000\r\n"
            "a=fmtp:96 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f\r\n"
            "a=rtpmap:97 H265/90000\r\n"
            # a=fmtp:97: Leedarson firmware echoes back exactly the fmtp it
            # received; without this line it may reject PT 97 or downgrade to
            # H264 only.
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
        )

        _status(
            f"SDP offer (SDES)  local={local_ip}"
            + (f"  srflx={_public_ip}" if _public_ip else "")
            + f"  audio={audio_port}  video={video_port}"
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
                "dstAddr": user_id,
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
        # Pre-generate PSK and compressed SDP for webrtcReq; the same PSK is
        # reused in webrtcResp so the camera sees a consistent value.
        import random as _rnd_psk_req
        _psk_charset_req = "123456789abcdef"
        _psk_value_req = "".join(
            _psk_charset_req[_rnd_psk_req.randint(0, len(_psk_charset_req) - 1)]
            for _ in range(64)
        )

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
                            "ice-options", "crypto"):
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
                "dstAddr": user_id,
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

        # --- TURN relay allocation helper ------------------------------------ #
        # Defined here so the echo handler below can call it before sending
        # webrtcResp.  Pure-SDES cameras read c= from our answer SDP and stream
        # SRTP directly there — putting the relay IP in the answer is the only
        # way camera traffic reaches us through port-restricted NAT.
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
                    # CreatePermission: tell TURN server which peer source IP(s)
                    # to accept SRTP from and forward as Data Indications.
                    # Primary: camera's public IP (_public_ip, e.g. 72.84.199.230)
                    # — this is the source IP the TURN server sees when the camera
                    # sends SRTP to our relay (both camera and client behind same NAT).
                    # Fallback to _ta_host (TURN server IP) if _public_ip unavailable.
                    # Also send a second permission for _ta_host (belt-and-suspenders
                    # in case camera routes via its own TURN allocation on same server).
                    def _send_create_perm(_perm_ip_str):
                        _pxip = bytes(
                            a ^ b for a, b in zip(
                                bytes(int(x) for x in _perm_ip_str.split('.')),
                                _MAGIC_TA,
                            )
                        )
                        _pxpa = b'\x00\x01' + _st_ta.pack('!H', 0x2112) + _pxip
                        _pbp = (
                            _a(0x0006, _ta_user)
                            + _a(0x0014, _realm_ta)
                            + _a(0x0015, _nonce_ta)
                            + _a(0x0012, _pxpa)
                        )
                        _ptp = os.urandom(12)
                        _php = (b'\x00\x08' + _st_ta.pack('!H', len(_pbp) + 24)
                                + _MAGIC_TA + _ptp)
                        _pbp += _a(0x0008, _mi_ta(_key_ta, _php + _pbp))
                        _pcp = (b'\x00\x08' + _st_ta.pack('!H', len(_pbp))
                                + _MAGIC_TA + _ptp + _pbp)
                        _LOGGER.debug(
                            "TURN CreatePermission for peer %s", _perm_ip_str)
                        try:
                            _ta_sock.sendto(_pcp, (_ta_host, _ta_port))
                        except Exception:
                            pass

                    _perm_ip_primary = _public_ip if _public_ip else _ta_host
                    _send_create_perm(_perm_ip_primary)
                    if _ta_host != _perm_ip_primary:
                        _send_create_perm(_ta_host)
                    return _r_ip_ta, _xp, _realm_ta, _nonce_ta
            return None

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
        try:
            await _asyncio.wait_for(
                _asyncio.shield(_echo_fut), timeout=2.0
            )
            _cam_echo_received = True
            _status("camera webrtcReq echo received — sending webrtcResp to trigger streaming")
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
            # Allocate TURN relay before sending webrtcResp so the relay IP/port
            # can go into the answer SDP's c= and m= lines.  Pure-SDES cameras
            # (no ICE) read our answer's c= and stream SRTP directly there —
            # if we put the relay address here the camera can reach us even
            # through port-restricted NAT.
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
                                    f"TURN relay allocated (early): "
                                    f"{'audio' if _alloc_sock_e is _audio_sock else 'video'}"
                                    f" → {_r_ip_e}:{_r_port_e}"
                                )
            except Exception as _relay_early_exc:
                _LOGGER.warning(
                    "TURN early relay allocation error: %s", _relay_early_exc
                )
            # Build relay-aware answer SDP: relay IP/port in c= and m= so camera
            # sends SRTP to our relay.  Falls back to public/local IP if allocation
            # failed (same behaviour as before this change).
            _audio_relay_e = _relay_addrs.get(_audio_sock)
            _video_relay_e = _relay_addrs.get(_video_sock)
            _ans_audio_ip   = _audio_relay_e[0] if _audio_relay_e else (_public_ip or local_ip)
            _ans_audio_port = _audio_relay_e[1] if _audio_relay_e else audio_port
            _ans_video_ip   = _video_relay_e[0] if _video_relay_e else (_public_ip or local_ip)
            _ans_video_port = _video_relay_e[1] if _video_relay_e else video_port
            _relay_answer_sdp = (
                "v=0\r\n"
                f"o=- {ts} {ts} IN IP4 {local_ip}\r\n"
                "s=-\r\n"
                "t=0 0\r\n"
                f"m=audio {_ans_audio_port} RTP/SAVPF 0 8\r\n"
                f"c=IN IP4 {_ans_audio_ip}\r\n"
                "a=recvonly\r\n"
                "a=mid:0\r\n"
                f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{srtp_key_audio}\r\n"
                "a=rtpmap:0 PCMU/8000\r\n"
                "a=rtpmap:8 PCMA/8000\r\n"
                "a=rtcp-mux\r\n"
                f"m=video {_ans_video_port} RTP/SAVPF 96 97\r\n"
                f"c=IN IP4 {_ans_video_ip}\r\n"
                "a=recvonly\r\n"
                "a=mid:1\r\n"
                f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{srtp_key_video}\r\n"
                "a=rtpmap:96 H264/90000\r\n"
                "a=fmtp:96 level-asymmetry-allowed=1;packetization-mode=1;"
                "profile-level-id=42e01f\r\n"
                "a=rtpmap:97 H265/90000\r\n"
                "a=fmtp:97 level-id=93\r\n"
                "a=rtcp-mux\r\n"
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
            outgoing_q.put_nowait((_webrtc_resp_sdes_topic, _webrtc_resp_sdes))
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

        # --- ICE STUN responder (runs while reservation sockets are still open) #
        # Two-phase window:
        #   Normal (no echo-reversal): exit after 0.5 s idle, max 2.5 s total.
        #   Echo-reversal (A001064):   wait up to 8 s for ICE to start, then
        #     exit 1.5 s after the last STUN packet (ICE silence = done).
        #   SRTP early exit: if a non-STUN packet arrives (SRTP), ICE is done —
        #     close sockets immediately so ffmpeg can bind.
        import struct as _struct, select as _select
        _STUN_MAGIC = b'\x21\x12\xa4\x42'
        _stun_count = 0
        _stun_seen = False
        _srtp_detected = False
        _stun_max = 20.0 if _cam_echo_received else 2.5
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
                _LOGGER.debug(
                    "STUN window: %d bytes from %s:%d, first4=%s",
                    len(_pkt), _src[0], _src[1], _pkt[:4].hex()
                )
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

                if (len(_pkt) >= 20 and _pkt[4:8] == _STUN_MAGIC):
                    # STUN packet — only Binding Requests (0x0001) indicate that
                    # ICE is active.  Error/Success responses (e.g. hole-punch
                    # replies) must NOT set _stun_seen or they'd trigger the 1.5s
                    # idle-exit prematurely, before camera probes arrive.
                    if _pkt[:2] == b'\x00\x01':
                        # Binding Request — reply with Binding Success Response
                        _stun_seen = True
                        _tid = _pkt[8:20]
                        try:
                            # Use TURN peer address for XOR-MAPPED-ADDRESS when
                            # request arrived via TURN Data Indication.
                            _resp_src_ip = _turn_peer_ip_sw or _src[0]
                            _resp_src_port = _turn_peer_port_sw or _src[1]
                            _ip_parts = [int(x) for x in _resp_src_ip.split('.')]
                            _xip = bytes(
                                a ^ b for a, b in zip(
                                    _struct.pack('!4B', *_ip_parts), _STUN_MAGIC
                                )
                            )
                            _xport = (_resp_src_port ^ 0x2112) & 0xFFFF
                            _xma = (b'\x00\x20\x00\x08\x00\x01'
                                    + _struct.pack('!H', _xport) + _xip)
                            _resp = (b'\x01\x01'
                                     + _struct.pack('!H', len(_xma))
                                     + _STUN_MAGIC + _tid + _xma)
                            if _turn_peer_ip_sw and _sock in _relay_addrs:
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
            _status("ICE: 0 packets received in STUN window (NAT may be blocking camera probes)")
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
            if _webrtc_resp_sdes is not None:
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
                            _ip_r = [int(x) for x in _src_r[0].split('.')]
                            _xip_r = bytes(
                                a ^ b for a, b in zip(
                                    _struct.pack('!4B', *_ip_r), _STUN_MAGIC
                                )
                            )
                            _xport_r = (_src_r[1] ^ 0x2112) & 0xFFFF
                            _xma_r = (b'\x00\x20\x00\x08\x00\x01'
                                      + _struct.pack('!H', _xport_r) + _xip_r)
                            _resp_r = (b'\x01\x01'
                                       + _struct.pack('!H', len(_xma_r))
                                       + _STUN_MAGIC + _tid_r + _xma_r)
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
        if answer_fut.done():
            try:
                _pre_ans = answer_fut.result()
                _pre_launch_answer_sdp = (_pre_ans or {}).get("sdp", "")
            except Exception:
                pass
        if _pre_launch_answer_sdp:
            _LOGGER.warning(
                "_open_sdes_stream: camera webrtcResp answer SDP:\n%s",
                _pre_launch_answer_sdp,
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

            _cam_key_audio = _sdes_key_from_sdp(_pre_launch_answer_sdp, "audio")
            _cam_key_video = _sdes_key_from_sdp(_pre_launch_answer_sdp, "video")
            if _cam_key_audio and _cam_key_audio != srtp_key_audio:
                _status("Using camera's audio SRTP key from answer (was our offer key)")
                srtp_key_audio = _cam_key_audio
            if _cam_key_video and _cam_key_video != srtp_key_video:
                _status("Using camera's video SRTP key from answer (was our offer key)")
                srtp_key_video = _cam_key_video
            # Rewrite SDP file on disk with the (potentially updated) keys.
            _ts = int(time.time())
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
        _ts_br = int(time.time())
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

        def _bridge_fn():
            nonlocal _br_first_di_logged, _br_first_srtp_logged
            _STUN_MAGIC_BR = b'\x21\x12\xa4\x42'
            import struct as _st_br, select as _sel_br
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
                            try:
                                _btid = _bpkt[8:20]
                                # Use TURN peer address when arrived via relay
                                _bresp_ip = _br_turn_peer_ip or _bsrc[0]
                                _bresp_port = _br_turn_peer_port or _bsrc[1]
                                _bip = [int(x) for x in _bresp_ip.split('.')]
                                _bxip = bytes(
                                    a ^ b for a, b in zip(
                                        _st_br.pack('!4B', *_bip), _STUN_MAGIC_BR
                                    )
                                )
                                _bxport = (_bresp_port ^ 0x2112) & 0xFFFF
                                _bxma = (b'\x00\x20\x00\x08\x00\x01'
                                         + _st_br.pack('!H', _bxport) + _bxip)
                                _bresp = (b'\x01\x01'
                                          + _st_br.pack('!H', len(_bxma))
                                          + _STUN_MAGIC_BR + _btid + _bxma)
                                if _br_turn_peer_ip and _bs in _relay_addrs:
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
                                    _LOGGER.debug(
                                        "bridge: STUN resp via TURN → %s:%d",
                                        _br_turn_peer_ip, _br_turn_peer_port,
                                    )
                                else:
                                    _bs.sendto(_bresp, _bsrc)
                                    _LOGGER.debug(
                                        "bridge: STUN resp → %s:%d",
                                        _bsrc[0], _bsrc[1],
                                    )
                            except Exception:
                                pass
                        elif len(_bpkt) >= 20 and _bpkt[4:8] == _STUN_MAGIC_BR:
                            pass  # other STUN (keepalives etc.) — ignore
                        else:
                            # Non-STUN packet — forward SRTP to ffmpeg loopback port
                            _btgt = (
                                _lo_audio_port if _bs is _audio_sock
                                else _lo_video_port
                            )
                            if not _br_first_srtp_logged:
                                _br_first_srtp_logged = True
                                _status(
                                    f"bridge: first SRTP from"
                                    f" {_bsrc[0]}:{_bsrc[1]}"
                                    f" → loopback:{_btgt}"
                                )
                            try:
                                (_lo_a if _bs is _audio_sock else _lo_v).sendto(
                                    _bpkt, ('127.0.0.1', _btgt)
                                )
                            except Exception:
                                pass
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
                and not _srtp_detected
                and not _relay_addrs):
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

        if output_path:
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
        cmd = [
            "ffmpeg", "-y",
            "-loglevel", "warning",
            "-protocol_whitelist", "file,rtp,udp,srtp",
            # Give ffmpeg up to 100 s to detect codec parameters from the
            # incoming SRTP stream.  Without this, ffmpeg uses 0 µs and fails
            # with "Could not find codec parameters" if the first packets
            # arrive before the format is fully probed.
            "-analyzeduration", "100000000",
            "-probesize", "10000000",
            "-i", sdp_path,
            *dest_args,
        ]
        _LOGGER.info("SDES ffmpeg cmd: %s", " ".join(cmd))
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
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
            """True if any UDP socket is currently bound to `port`."""
            port_hex = f"{port:04X}"
            for _proc_file in ("/proc/net/udp", "/proc/net/udp6"):
                try:
                    with open(_proc_file) as _pf:
                        for _ln in _pf:
                            _parts = _ln.split()
                            if len(_parts) >= 2 and ":" in _parts[1]:
                                if _parts[1].split(":")[1] == port_hex:
                                    return True
                except OSError:
                    pass
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
        _sdes_answer_timeout = min(timeout, 8.0)
        try:
            answer = await asyncio.wait_for(answer_fut, timeout=_sdes_answer_timeout)
            _ans_sdp = answer.get("sdp", "")
            _ans_mlines = [ln for ln in _ans_sdp.splitlines() if ln.startswith("m=")]
            _status(
                "webrtcResp received (SDES) — answer m-sections (%d): %s"
                % (len(_ans_mlines), " | ".join(_ans_mlines))
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

        return SdesSession(
            proc=proc,
            sdp_path=sdp_path,
            outgoing_q=outgoing_q,
            mqtt_fut=mqtt_fut,
            audio_sock=_audio_sock,   # bridge thread keeps these open; stop() closes them
            video_sock=_video_sock,
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
        await self.reset()
        _LOGGER.info(f"{self.device_id} connect close by user")
