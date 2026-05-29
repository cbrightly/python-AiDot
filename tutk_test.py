#!/usr/bin/env python3
"""
tutk_test.py — TUTK IOTC direct-connection test for SDES cameras + PTZ control.

Requires Linux ARM64 glibc .so files from developer.tutk.com
(NOT the Android Bionic .so files from the APK — those fail with glibc errors).

SETUP ON PI:
  # Replace research/so_files/ with Linux SDK .so files, then:
  cd /path/to/python-AiDot
  export LD_LIBRARY_PATH="$(pwd)/research/so_files:$LD_LIBRARY_PATH"

USAGE:
  # Step 1: Find camera UID via LAN search (no UID needed):
  python3 tutk_test.py --scan

  # Step 2: Connect and get session info:
  python3 tutk_test.py --connect --uid <UID> --password aU6xW4SPug3b

  # Step 3: Full stream trigger:
  python3 tutk_test.py --stream --uid <UID> --password aU6xW4SPug3b

  # PTZ control (once connected):
  python3 tutk_test.py --ptz up   --uid <UID> --password aU6xW4SPug3b
  python3 tutk_test.py --ptz down --uid <UID> --password aU6xW4SPug3b
  python3 tutk_test.py --ptz left --uid <UID> --password aU6xW4SPug3b
  python3 tutk_test.py --ptz right --uid <UID> --password aU6xW4SPug3b
  python3 tutk_test.py --ptz stop  --uid <UID> --password aU6xW4SPug3b
  python3 tutk_test.py --ptz goto --preset 1 --uid <UID> --password aU6xW4SPug3b

CAMERA PASSWORDS (from --p2p output, 'password' field):
  PTZ  (192.168.1.217): aU6xW4SPug3b
  Deck (192.168.1.245): myt4zXL771SJ
  Bedroom M3 Pro:       XPJC7hkSGK0n

PTZ SOURCE: a.java d1() → avSendIOCtrl(avIdx, 4097, 8B, 8)
  Byte 0: direction (UP=1, DOWN=2, LEFT=3, RIGHT=6, STOP=0, GOTO_POINT=12)
  Byte 1: speed (default 4)
  Byte 2: preset point number (for GOTO_POINT)
  Bytes 3-7: zeros
"""

import argparse
import ctypes
import ctypes.util
import logging
import os
import signal
import socket
import struct
import sys
import time

logging.basicConfig(level=logging.DEBUG, format='%(levelname)s %(message)s')
log = logging.getLogger('tutk')

# TUTK internally uses alarm() for timeouts; on Linux unhandled SIGALRM
# kills the process.  Ignore it — we use our own timeouts via select/sleep.
signal.signal(signal.SIGALRM, signal.SIG_IGN)

# TUTK SDK license key (from a.java:320 in decompiled APK)
TUTK_LICENSE_KEY = (
    "AQAAABmfpqk4S/+3DUHJAi+gq9pcU1dBRLeM4Ys1o0V+JtWm9CLbN6k/"
    "QQHRfsHgwHLzkvBwGWBtade2pJqeXb/YatJDIFCuwlRcJ4At6UH8ac47hpq7t8w"
    "sH3v8XME2Y38yPCeO5/opHKuPVeH8OtUsa9xThMsZE2ZcSKkYUp5X1ZxGat4y4H"
    "xDSFFQVbfxtTp2+D36mTGd92azF8TA4pghsWgb"
)

# Default .so directory (relative to this file)
DEFAULT_LIB_DIR = os.path.join(os.path.dirname(__file__), "research", "so_files")

# AVIO command types (from official AVIOCTRLDEFs.java)
IOTYPE_INNER_SND_DATA_DELAY            = 255
IOTYPE_USER_IPCAM_CONNECTION_CHECK_REQ = 496
IOTYPE_USER_IPCAM_START                = 511
IOTYPE_USER_IPCAM_AUDIOSTART           = 768
E_CMD_AVIO_CTRL_SESSION_MODE_REQ       = 5376  # Leedarson LDS custom

# Error codes
IOTC_ER_NoERROR            = 0
IOTC_ER_TIMEOUT            = -13
IOTC_ER_UNKNOWN_DEVICE     = -15
IOTC_ER_DEVICE_IS_SLEEP    = -64
IOTC_ER_DEVICE_OFFLINE     = -90
TUTK_ER_INVALID_LICENSE    = -1004
AV_ER_WRONG_VIEWACCorPWD   = -20009


# ── ctypes structures ─────────────────────────────────────────────────────── #

class st_LanSearchInfo(ctypes.Structure):
    """TUTK LAN search result — returned by IOTC_Lan_Search2."""
    _fields_ = [
        ("UID",  ctypes.c_char * 21),   # device UID (null-terminated)
        ("IP",   ctypes.c_char * 17),   # device IP
        ("port", ctypes.c_uint),        # IOTC port (0 if default)
    ]

class St_AVClientStartInConfig(ctypes.Structure):
    # Layout from wyzecam (mrlt8/docker-wyze-bridge) — proven against real TUTK cameras.
    # cb = sizeof(struct); session_id is a struct field, NOT a separate argument.
    # avClientStartEx(byref(in_cfg), byref(out_cfg)) — 2 args only.
    _fields_ = [
        ("cb",                 ctypes.c_uint32),   # must be set to sizeof(this struct)
        ("iotc_session_id",    ctypes.c_uint32),
        ("iotc_channel_id",    ctypes.c_uint8),
        ("timeout_sec",        ctypes.c_uint32),
        ("account_or_identity", ctypes.c_char_p),
        ("password_or_token",  ctypes.c_char_p),
        ("resend",             ctypes.c_int32),    # 1 = enable retransmission
        ("security_mode",      ctypes.c_uint32),   # 0=clear, 1=DTLS/SDES
        ("auth_type",          ctypes.c_uint32),
        ("sync_recv_data",     ctypes.c_int32),
    ]

class St_AVClientStartOutConfig(ctypes.Structure):
    _fields_ = [
        ("cb",               ctypes.c_uint32),   # sizeof(this struct)
        ("server_type",      ctypes.c_uint32),
        ("resend",           ctypes.c_int32),
        ("two_way_streaming", ctypes.c_int32),
        ("sync_recv_data",   ctypes.c_int32),
        ("security_mode",    ctypes.c_uint32),
    ]

class St_FrameInfo(ctypes.Structure):
    # 60-byte frame header returned by avRecvFrameData2 (wyzecam FrameInfoStruct).
    # codec_id: 96=H264, 97=H265, 138=G711A(PCMA), 140=AAC
    _fields_ = [
        ("codec_id",      ctypes.c_uint16),
        ("is_keyframe",   ctypes.c_uint8),
        ("cam_index",     ctypes.c_uint8),
        ("online_num",    ctypes.c_uint8),
        ("framerate",     ctypes.c_uint8),
        ("frame_size",    ctypes.c_uint8),
        ("bitrate",       ctypes.c_uint8),
        ("timestamp_ms",  ctypes.c_uint32),
        ("timestamp",     ctypes.c_uint32),
        ("frame_len",     ctypes.c_uint32),
        ("frame_no",      ctypes.c_uint32),
        ("ac_mac_addr",   ctypes.c_char * 12),
        ("n_play_token",  ctypes.c_int32),
    ]

class St_SInfoEx(ctypes.Structure):
    """Session info — UID field reveals remote device's TUTK UID."""
    _fields_ = [
        ("size",          ctypes.c_int),
        ("UID",           ctypes.c_byte * 21),
        ("RemoteIP",      ctypes.c_byte * 17),
        ("RemotePort",    ctypes.c_int),
        ("CorD",          ctypes.c_byte),
        ("Mode",          ctypes.c_byte),
        ("TX_count",      ctypes.c_int),
        ("RX_count",      ctypes.c_int),
        ("IOTCVersion",   ctypes.c_int),
        ("VID",           ctypes.c_int),
        ("PID",           ctypes.c_int),
        ("GID",           ctypes.c_int),
        ("isSecure",      ctypes.c_byte),
        ("LocalNatType",  ctypes.c_byte),
        ("RemoteNatType", ctypes.c_byte),
        ("RelayType",     ctypes.c_byte),
        ("NetState",      ctypes.c_int),
        ("RemoteWANIP",   ctypes.c_byte * 17),
        ("RemoteWANPort", ctypes.c_int),
        ("isNebula",      ctypes.c_byte),
        ("isUseAuthkey",  ctypes.c_byte),
    ]


# ── Library loader ────────────────────────────────────────────────────────── #

class TUTKLib:
    """Wraps libTUTKGlobalAPIs.so + libIOTCAPIs.so + libAVAPIs.so."""

    def __init__(self, lib_dir: str = DEFAULT_LIB_DIR):
        self.lib_dir = lib_dir
        self._global = None   # libTUTKGlobalAPIs.so
        self._iotc   = None   # libIOTCAPIs.so
        self._av     = None   # libAVAPIs.so
        self._load()

    def _p(self, name):
        path = os.path.join(self.lib_dir, name)
        if not os.path.exists(path):
            raise FileNotFoundError(f"{name} not found in {self.lib_dir}")
        return path

    def _load(self):
        GLOBAL = ctypes.RTLD_GLOBAL

        # libTUTKGlobalAPIs.so is optional — not present in GitHub SDK builds.
        # If absent, TUTK_SDK_Set_License_Key may be in libIOTCAPIs or skippable.
        try:
            log.info("Loading libTUTKGlobalAPIs.so ...")
            self._global = ctypes.CDLL(self._p("libTUTKGlobalAPIs.so"), mode=GLOBAL)
        except Exception as e:
            log.warning("libTUTKGlobalAPIs.so not found (%s) — license key step skipped", e)
            self._global = None

        # Pre-load bionic compat shim with RTLD_GLOBAL so its __errno() symbol
        # is visible when libIOTCAPIs_linux.so (Bionic-linked) is opened.
        # This replaces the need for LD_PRELOAD=libbionic_compat.so.
        _compat = self._p("libbionic_compat.so")
        if os.path.exists(_compat):
            try:
                ctypes.CDLL(_compat, mode=GLOBAL)
                log.info("Loaded libbionic_compat.so (Bionic→glibc __errno bridge)")
            except Exception as _ce:
                log.warning("libbionic_compat.so load failed: %s", _ce)
                log.warning("  Recompile: gcc -shared -fPIC -o libbionic_compat.so bionic_compat.c")

        log.info("Loading TUTK libraries ...")
        # libIOTCAPIs_ALL.so (from docker-wyze-bridge) is a single Linux glibc
        # ARM64 library that bundles both IOTC and AV APIs — preferred over the
        # separate Android Bionic .so files from the GitHub SDK.
        _all_path = os.path.join(self.lib_dir, "libIOTCAPIs_ALL.so")
        if os.path.exists(_all_path):
            try:
                _all = ctypes.CDLL(_all_path, mode=GLOBAL)
                self._iotc = _all
                self._av   = _all   # both APIs in one library
                log.info("  Loaded libIOTCAPIs_ALL.so (IOTC + AV combined, Linux glibc)")
            except Exception as e:
                log.warning("libIOTCAPIs_ALL.so failed: %s", e)

        # Fallback: separate IOTC + AV libraries (Android Bionic or Linux builds)
        if self._iotc is None:
            for name in ("libIOTC.so", "libIOTCAPIs_linux.so", "libIOTCAPIs.so"):
                try:
                    self._iotc = ctypes.CDLL(self._p(name), mode=GLOBAL)
                    log.info("  Loaded %s (IOTC only)", name)
                    if name == "libIOTCAPIs_linux.so":
                        _std = os.path.join(self.lib_dir, "libIOTCAPIs.so")
                        if not os.path.lexists(_std):
                            try:
                                os.symlink("libIOTCAPIs_linux.so", _std)
                            except Exception:
                                pass
                    break
                except Exception as e:
                    log.debug("  %s failed: %s", name, e)
            else:
                raise FileNotFoundError("No IOTC library found in " + self.lib_dir)

        if self._av is None:
            _old_ldp = os.environ.get('LD_LIBRARY_PATH', '')
            os.environ['LD_LIBRARY_PATH'] = (
                self.lib_dir + (':' + _old_ldp if _old_ldp else ''))
            try:
                self._av = ctypes.CDLL(self._p("libAVAPIs.so"), mode=GLOBAL)
                log.info("  Loaded libAVAPIs.so")
            except Exception as e:
                log.warning("libAVAPIs.so failed: %s — stream-start unavailable", e)

        self._setup_sigs()

    def _setup_sigs(self):
        # Optional: license key (in libTUTKGlobalAPIs or libIOTCAPIs depending on SDK build)
        for src in ([self._global] if self._global else []) + [self._iotc]:
            try:
                src.TUTK_SDK_Set_License_Key.restype  = ctypes.c_int
                src.TUTK_SDK_Set_License_Key.argtypes = [ctypes.c_char_p]
                self._license_lib = src
                break
            except Exception:
                pass
        else:
            self._license_lib = None
            log.warning("TUTK_SDK_Set_License_Key not found — proceeding without license")

        i = self._iotc
        i.IOTC_Initialize2.restype  = ctypes.c_int
        i.IOTC_Initialize2.argtypes = [ctypes.c_int]

        # Version: this SDK uses IOTC_Get_Version(int[3]), not IOTC_Get_Version_String
        try:
            i.IOTC_Get_Version_String.restype  = ctypes.c_char_p
            i.IOTC_Get_Version_String.argtypes = []
            self._has_version_string = True
        except Exception:
            self._has_version_string = False
        try:
            i.IOTC_Get_Version.restype  = None
            i.IOTC_Get_Version.argtypes = [ctypes.POINTER(ctypes.c_uint * 3)]
        except Exception:
            pass

        i.IOTC_Setup_Session_Alive_Timeout.restype  = None
        i.IOTC_Setup_Session_Alive_Timeout.argtypes = [ctypes.c_int]

        i.IOTC_Set_LanSearchPort.restype  = ctypes.c_int
        i.IOTC_Set_LanSearchPort.argtypes = [ctypes.c_int]

        # LAN search — finds devices without needing a UID!
        i.IOTC_Lan_Search2.restype  = ctypes.c_int
        i.IOTC_Lan_Search2.argtypes = [
            ctypes.POINTER(st_LanSearchInfo),  # result array
            ctypes.c_int,                       # max results
            ctypes.c_int,                       # wait time (ms)
        ]

        # Newer async search API
        i.IOTC_Search_Device_Start.restype  = ctypes.c_int
        i.IOTC_Search_Device_Start.argtypes = [ctypes.c_int]  # timeout ms

        i.IOTC_Search_Device_Stop.restype  = None
        i.IOTC_Search_Device_Stop.argtypes = []

        i.IOTC_Search_Device_Result.restype  = ctypes.c_int
        i.IOTC_Search_Device_Result.argtypes = [
            ctypes.POINTER(st_LanSearchInfo),
            ctypes.c_int,
        ]

        i.IOTC_Get_SessionID.restype  = ctypes.c_int
        i.IOTC_Get_SessionID.argtypes = []

        i.IOTC_Connect_ByUID_Parallel.restype  = ctypes.c_int
        i.IOTC_Connect_ByUID_Parallel.argtypes = [ctypes.c_char_p, ctypes.c_int]

        # Direct IP connection — bypasses P2P UID and cloud entirely.
        # Canonical TUTK IOTC_Connect_UDP signature: (ip, port) → session_id
        # Does NOT take a pre-allocated session_id (unlike Connect_ByUID_Parallel).
        try:
            i.IOTC_Connect_UDP.restype  = ctypes.c_int
            i.IOTC_Connect_UDP.argtypes = [ctypes.c_char_p, ctypes.c_ushort]
        except Exception:
            pass

        i.IOTC_Session_Check_Ex.restype  = ctypes.c_int
        i.IOTC_Session_Check_Ex.argtypes = [ctypes.c_int,
                                             ctypes.POINTER(St_SInfoEx)]
        i.IOTC_Session_Close.restype  = None
        i.IOTC_Session_Close.argtypes = [ctypes.c_int]

        i.IOTC_Connect_Stop.restype  = None
        i.IOTC_Connect_Stop.argtypes = []

        i.IOTC_WakeUp_WakeDevice.restype  = ctypes.c_int
        i.IOTC_WakeUp_WakeDevice.argtypes = [ctypes.c_char_p]

        i.IOTC_DeInitialize.restype  = ctypes.c_int
        i.IOTC_DeInitialize.argtypes = []

        if self._av:
            av = self._av
            av.avInitialize.restype  = ctypes.c_int
            av.avInitialize.argtypes = [ctypes.c_int]

            # avClientStartEx(in_config*, out_config*) — 2 args only.
            # session_id goes in in_config.iotc_session_id, not as a separate arg.
            av.avClientStartEx.restype  = ctypes.c_int
            av.avClientStartEx.argtypes = [
                ctypes.POINTER(St_AVClientStartInConfig),
                ctypes.POINTER(St_AVClientStartOutConfig),
            ]

            # avRecvFrameData2: 9 args (frame_info_actual_len is arg 8)
            av.avRecvFrameData2.restype  = ctypes.c_int
            av.avRecvFrameData2.argtypes = [
                ctypes.c_int,                      # av_chan_id
                ctypes.c_char_p,                   # frame_data_buf
                ctypes.c_int,                      # frame_data_max_len
                ctypes.POINTER(ctypes.c_int),      # frame_data_actual_len
                ctypes.POINTER(ctypes.c_int),      # frame_data_expected_len
                ctypes.POINTER(St_FrameInfo),      # frame_info
                ctypes.c_int,                      # frame_info_max_len
                ctypes.POINTER(ctypes.c_int),      # frame_info_actual_len
                ctypes.POINTER(ctypes.c_int),      # frame_index
            ]

            av.avSendIOCtrl.restype  = ctypes.c_int
            av.avSendIOCtrl.argtypes = [ctypes.c_int, ctypes.c_uint,
                                         ctypes.c_char_p, ctypes.c_int]

            av.avRecvIOCtrl.restype  = ctypes.c_int
            av.avRecvIOCtrl.argtypes = [ctypes.c_int,
                                         ctypes.POINTER(ctypes.c_int),
                                         ctypes.c_char_p, ctypes.c_int,
                                         ctypes.c_int]

            av.avClientStop.restype  = None
            av.avClientStop.argtypes = [ctypes.c_int]

            av.avClientExit.restype  = None
            av.avClientExit.argtypes = [ctypes.c_int, ctypes.c_int]

            av.avDeInitialize.restype  = ctypes.c_int
            av.avDeInitialize.argtypes = []

    # ── High-level API ──────────────────────────────────────────────────── #

    def init(self) -> bool:
        # Print version (handle both API variants)
        try:
            if self._has_version_string:
                ver = self._iotc.IOTC_Get_Version_String()
                log.info("TUTK version: %s", ver.decode() if ver else "?")
            else:
                arr = (ctypes.c_uint * 3)(0, 0, 0)
                self._iotc.IOTC_Get_Version(ctypes.byref(arr))
                log.info("TUTK version: %d.%d.%d", arr[0], arr[1], arr[2])
        except Exception as e:
            log.debug("Version query failed: %s", e)

        # Set license key if available (may be absent in GitHub SDK builds)
        if self._license_lib is not None:
            ret = self._license_lib.TUTK_SDK_Set_License_Key(TUTK_LICENSE_KEY.encode())
            log.info("TUTK_SDK_Set_License_Key → %d (%s)", ret,
                     "OK" if ret == 0 else ("INVALID KEY" if ret == TUTK_ER_INVALID_LICENSE else "ERR"))
            # Don't abort on license failure — some SDK builds ignore it
            if ret == TUTK_ER_INVALID_LICENSE:
                log.warning("License key rejected — continuing anyway (may work for LAN search)")
        else:
            log.info("Skipping license key (not exported by this SDK build)")

        ret = self._iotc.IOTC_Initialize2(0)
        log.info("IOTC_Initialize2 → %d", ret)
        if ret < 0 and ret != -3:  # -3 = already initialized (OK)
            log.error("IOTC_Initialize2 failed: %d", ret)
            return False

        try:
            self._iotc.IOTC_Setup_Session_Alive_Timeout(15)
        except Exception:
            pass
        try:
            self._iotc.IOTC_Set_LanSearchPort(2002)
        except Exception:
            pass

        if self._av:
            try:
                ret = self._av.avInitialize(32)
                log.info("avInitialize → %d", ret)
            except Exception as e:
                log.warning("avInitialize failed: %s", e)

        return True

    def deinit(self):
        if self._av:
            self._av.avDeInitialize()
        self._iotc.IOTC_DeInitialize()

    def lan_search(self, max_results: int = 20, wait_ms: int = 5000):
        """Search for TUTK devices on LAN using multiple ports.
        Tries IOTC_Set_LanSearchPort with Aidot-known ports before searching."""
        # Aidot/Leedarson cameras known to use 6666 (discovery) and 10000 (streaming)
        # alongside standard TUTK port 2002.
        for port in (6666, 10000, 2002):
            try:
                self._iotc.IOTC_Set_LanSearchPort(port)
                log.debug("IOTC_Set_LanSearchPort(%d)", port)
            except Exception:
                pass
        results = (st_LanSearchInfo * max_results)()
        log.info("IOTC_Lan_Search2: scanning LAN for %dms ...", wait_ms)
        n = self._iotc.IOTC_Lan_Search2(results, max_results, wait_ms)
        log.info("IOTC_Lan_Search2 → %d device(s) found", n)
        found = []
        for i in range(max(0, n)):
            r = results[i]
            uid = r.UID.decode('ascii', errors='replace').rstrip('\x00')
            ip  = r.IP.decode('ascii',  errors='replace').rstrip('\x00')
            found.append((uid, ip, r.port))
            log.info("  [%d] UID=%r IP=%s port=%d", i, uid, ip, r.port)
        return found

    def lan_search_async(self, wait_ms: int = 5000, max_results: int = 20):
        """Alternative async LAN search API."""
        log.info("IOTC_Search_Device_Start (%dms) ...", wait_ms)
        ret = self._iotc.IOTC_Search_Device_Start(wait_ms)
        log.info("IOTC_Search_Device_Start → %d", ret)
        if ret < 0:
            log.warning("IOTC_Search_Device_Start not supported (code %d) — skipping", ret)
            return []
        time.sleep(wait_ms / 1000.0)
        results = (st_LanSearchInfo * max_results)()
        n = self._iotc.IOTC_Search_Device_Result(results, max_results)
        self._iotc.IOTC_Search_Device_Stop()
        log.info("IOTC_Search_Device_Result → %d", n)
        found = []
        for i in range(max(0, n)):
            r = results[i]
            uid = r.UID.decode('ascii', errors='replace').rstrip('\x00')
            ip  = r.IP.decode('ascii',  errors='replace').rstrip('\x00')
            found.append((uid, ip, r.port))
            log.info("  [%d] UID=%r IP=%s port=%d", i, uid, ip, r.port)
        return found

    def connect_udp(self, ip: str, port: int = 2002) -> int:
        """Attempt direct IP:port connect via IOTC_Connect_UDP.

        Canonical TUTK signature: IOTC_Connect_UDP(ip, port) → session_id
        faulthandler is enabled in main() so a SIGSEGV crash will print a
        traceback to stderr before dying.
        """
        if not hasattr(self._iotc, 'IOTC_Connect_UDP'):
            log.error("IOTC_Connect_UDP not exported by this SDK build")
            return -1
        import threading as _thr
        _result = [None]
        def _connect():
            _result[0] = self._iotc.IOTC_Connect_UDP(ip.encode(), port)
        _t = _thr.Thread(target=_connect, daemon=True, name="iotc-connect")
        log.info("IOTC_Connect_UDP(%s, %d) — faulthandler active; crash → traceback in log",
                 ip, port)
        _t.start()
        _t.join(timeout=5.0)
        if _result[0] is None:
            log.warning("*** IOTC_Connect_UDP TIMED OUT (5s) ***"
                        " — camera ICE port %d does not accept TUTK IOTC", port)
            return -11
        ret = _result[0]
        if ret >= 0:
            log.info("  IOTC_Connect_UDP SUCCESS: session_id=%d", ret)
        else:
            log.warning("  IOTC_Connect_UDP FAILED code=%d", ret)
        return ret

    def connect(self, uid: str, timeout: int = 15) -> int:
        """Connect by UID. Returns session_id >= 0 or error code < 0."""
        sid = self._iotc.IOTC_Get_SessionID()
        if sid < 0:
            log.error("IOTC_Get_SessionID failed: %d", sid)
            return sid
        log.info("Connecting to UID=%r (session_id=%d) ...", uid, sid)
        ret = self._iotc.IOTC_Connect_ByUID_Parallel(uid.encode(), sid)
        if ret >= 0:
            log.info("Connected: session_id=%d", ret)
            info = St_SInfoEx()
            self._iotc.IOTC_Session_Check_Ex(ret, ctypes.byref(info))
            remote_uid = bytes(info.UID).rstrip(b'\x00').decode('ascii', 'replace')
            remote_ip  = bytes(info.RemoteIP).rstrip(b'\x00').decode('ascii', 'replace')
            log.info("  Remote UID=%r IP=%s port=%d mode=%d",
                     remote_uid, remote_ip, info.RemotePort, info.Mode)
        else:
            err = {IOTC_ER_TIMEOUT: "timeout",
                   IOTC_ER_UNKNOWN_DEVICE: "unknown UID",
                   IOTC_ER_DEVICE_IS_SLEEP: "device sleeping",
                   IOTC_ER_DEVICE_OFFLINE: "device offline"}
            log.error("Connect failed: %d (%s)", ret, err.get(ret, "unknown"))
        return ret

    def av_connect(self, sid: int, account: str = "admin",
                   password: str = "admin123", timeout: int = 10) -> int:
        """Open AV channel on an established IOTC session.

        Layout from wyzecam (proven against real TUTK cameras):
        - cb = sizeof(struct) must be set
        - iotc_session_id goes inside the struct
        - avClientStartEx takes only 2 args (pointers to in/out config)
        Returns av_index >= 0 on success or negative error code.
        """
        in_c  = St_AVClientStartInConfig()
        out_c = St_AVClientStartOutConfig()
        in_c.cb                 = ctypes.sizeof(St_AVClientStartInConfig)
        in_c.iotc_session_id    = sid
        in_c.iotc_channel_id    = 0
        in_c.timeout_sec        = timeout
        in_c.account_or_identity = account.encode()
        in_c.password_or_token  = password.encode()
        in_c.resend             = 1
        in_c.security_mode      = 0
        in_c.auth_type          = 0
        in_c.sync_recv_data     = 0
        out_c.cb = ctypes.sizeof(St_AVClientStartOutConfig)
        ret = self._av.avClientStartEx(ctypes.byref(in_c), ctypes.byref(out_c))
        log.info("avClientStartEx(sid=%d) → av_index=%d  server_type=%d  sec=%d",
                 sid, ret, out_c.server_type, out_c.security_mode)
        return ret

    def start_stream(self, av_idx: int) -> bool:
        """Send full stream-start sequence from a.java N1() + Leedarson SESSION_MODE_REQ."""
        import random

        # 1. Pre-flight data delay (255)
        ret = self._av.avSendIOCtrl(av_idx, IOTYPE_INNER_SND_DATA_DELAY, b'\x00'*2, 2)
        log.info("avSendIOCtrl(DATA_DELAY 255) → %d", ret)
        if ret < 0: return False

        # 2. Connection check (496) — 16-byte device identifier
        ident = b'\x00' * 16
        ret = self._av.avSendIOCtrl(av_idx, IOTYPE_USER_IPCAM_CONNECTION_CHECK_REQ, ident, 16)
        log.info("avSendIOCtrl(CONNECTION_CHECK 496) → %d", ret)

        # 3. Stream start (511) — 24 bytes: zeros[8] + ident[16]
        payload_511 = b'\x00'*8 + ident
        ret = self._av.avSendIOCtrl(av_idx, IOTYPE_USER_IPCAM_START, payload_511, 24)
        log.info("avSendIOCtrl(IPCAM_START 511) → %d", ret)
        if ret < 0: return False

        # 4. Audio start (768)
        ret = self._av.avSendIOCtrl(av_idx, IOTYPE_USER_IPCAM_AUDIOSTART, b'\x00'*8, 8)
        log.info("avSendIOCtrl(AUDIOSTART 768) → %d", ret)

        # 5. Leedarson SESSION_MODE_REQ (5376) — AVIO header + body
        seq = random.randint(0, 0x7FFFFFFF)
        ts  = int(time.time() * 1000)
        avio = struct.pack('<IIqII4x', seq, 5376, ts, 8, 0)  # 28B header
        avio += struct.pack('<IB3x', 0, 1)                    # 8B body: channel=0, mode=LIVING
        ret = self._av.avSendIOCtrl(av_idx, E_CMD_AVIO_CTRL_SESSION_MODE_REQ, avio, len(avio))
        log.info("avSendIOCtrl(SESSION_MODE_REQ 5376) → %d", ret)

        return True

    def recv_responses(self, av_idx: int, count: int = 5, timeout_ms: int = 3000):
        buf = ctypes.create_string_buffer(1024)
        ptype = ctypes.c_int(0)
        log.info("Listening for IOCtrl responses (%dx %dms timeout)...", count, timeout_ms)
        for _ in range(count):
            ret = self._av.avRecvIOCtrl(av_idx, ctypes.byref(ptype),
                                         buf, 1024, timeout_ms)
            if ret >= 0:
                log.info("  IOCtrl type=%d size=%d: %s",
                         ptype.value, ret, buf.raw[:ret].hex())
            else:
                log.info("  avRecvIOCtrl → %d (timeout/done)", ret)
                break

    def ptz_move(self, av_idx: int, direction: str, speed: int = 4,
                 preset: int = 0) -> bool:
        """Send PTZ pan/tilt/zoom command via avSendIOCtrl(4097).

        Source: a.java d1() → avSendIOCtrl(avIdx, 4097, SMsgAVIoctrlPtzCmd, 8)
        AVIOCTRLDEFs: PTZ_UP=1 DOWN=2 LEFT=3 RIGHT=6 STOP=0 GOTO_POINT=12

        8-byte payload: [control, speed, point, limit, aux, channel, 0, 0]
        """
        IOTYPE_USER_IPCAM_PTZ_COMMAND = 4097
        dir_map = {
            "up": 1, "down": 2, "left": 3, "right": 6,
            "stop": 0, "goto": 12, "set_point": 10,
            "zoom_in": 23, "zoom_out": 24,
        }
        ctrl = dir_map.get(direction.lower())
        if ctrl is None:
            log.error("Unknown PTZ direction: %r (valid: %s)", direction, list(dir_map))
            return False
        payload = bytes([ctrl, speed, preset, 0, 0, 0, 0, 0])
        ret = self._av.avSendIOCtrl(av_idx, IOTYPE_USER_IPCAM_PTZ_COMMAND, payload, 8)
        log.info("PTZ %s (ctrl=%d speed=%d preset=%d) → avSendIOCtrl(4097) = %d",
                 direction, ctrl, speed, preset, ret)
        return ret >= 0


# ── CLI ───────────────────────────────────────────────────────────────────── #

def main():
    ap = argparse.ArgumentParser(description="TUTK IOTC camera direct-connect test + PTZ")
    ap.add_argument("--lib-dir",    default=DEFAULT_LIB_DIR)

    ap.add_argument("--camera-ip",  default="192.168.1.217")
    ap.add_argument("--uid",        default=None, help="Camera TUTK UID")
    # Web app JS (app-beautified.js:22312,72787) hardcodes admin/admin123 for ALL cameras.
    # The per-device 'password' field (aU6xW4SPug3b etc.) is for HTTP/setDevAttrReq only.
    ap.add_argument("--password",   default="admin123")
    ap.add_argument("--account",    default="")
    ap.add_argument("--connect-udp", action="store_true",
                    help="Connect directly by IP (no UID needed) — tries port 2002 then common TUTK ports")
    ap.add_argument("--udp-port",   type=int, default=0,
                    help="Specific UDP port for --connect-udp (0 = try all common ports)")
    ap.add_argument("--wait-port",  action="store_true",
                    help="Wait for /tmp/aidot-camera-port file written by test_camera.py bridge, "
                         "then connect to that IP:port automatically (no --udp-port needed)")
    ap.add_argument("--ptz",        default=None,
                    metavar="DIR", help="PTZ direction: up/down/left/right/stop/goto/zoom_in/zoom_out")
    ap.add_argument("--preset",     type=int, default=0, help="Preset point for --ptz goto")
    ap.add_argument("--ptz-speed",  type=int, default=4, help="PTZ speed (default 4)")
    ap.add_argument("--scan",       action="store_true", help="LAN search for cameras")
    ap.add_argument("--connect",    action="store_true", help="Connect by UID")
    ap.add_argument("--stream",     action="store_true", help="Connect + trigger stream")
    ap.add_argument("--scan-wait",  type=int, default=5000, help="LAN scan wait ms")
    args = ap.parse_args()

    # Enable faulthandler so C-level crashes (SIGSEGV) produce a stack trace
    # in stderr before killing the process — shows which TUTK call crashed.
    import faulthandler as _fh
    _fh.enable()

    # glibc caches LD_LIBRARY_PATH at process startup; os.environ changes made
    # inside Python don't affect subsequent dlopen() calls. Re-exec once with the
    # lib_dir in LD_LIBRARY_PATH so libAVAPIs.so can find libIOTCAPIs.so there.
    _abs_lib = os.path.abspath(args.lib_dir)
    _ldp = os.environ.get('LD_LIBRARY_PATH', '')
    if _abs_lib not in _ldp.split(':'):
        os.environ['LD_LIBRARY_PATH'] = _abs_lib + (':' + _ldp if _ldp else '')
        log.info("Re-execing with LD_LIBRARY_PATH=%s", os.environ['LD_LIBRARY_PATH'])
        os.execv(sys.executable, [sys.executable] + sys.argv)
        # unreachable — new process starts here with correct linker search path

    lib = TUTKLib(args.lib_dir)
    if not lib.init():
        print("❌ TUTK init failed")
        sys.exit(1)

    try:
        # LAN scan — only required when we need a UID (not for --connect-udp/--wait-port)
        need_uid = ((args.connect or args.stream or args.ptz)
                    and not args.connect_udp and not args.wait_port)
        if args.scan or (need_uid and not args.uid):
            print(f"\n🔍 LAN search (wait {args.scan_wait}ms)...")
            found = lib.lan_search(wait_ms=args.scan_wait)
            if not found:
                print("   Trying async search API...")
                found = lib.lan_search_async(wait_ms=args.scan_wait)
            if found:
                for uid, ip, port in found:
                    print(f"  ✅ Found: UID={uid!r}  IP={ip}  port={port}")
                if not args.uid:
                    args.uid = found[0][0]
                    print(f"  → Using UID={args.uid!r}")
            else:
                print("  ❌ No devices found on LAN")
                if need_uid and not args.uid:
                    sys.exit(1)
                # --connect-udp doesn't need a UID; continue regardless

        need_av = args.connect or args.stream or args.ptz or args.connect_udp or args.wait_port
        if not need_av:
            return

        # --wait-port: block until test_camera.py writes the camera ICE address
        if args.wait_port:
            _port_file = "/tmp/aidot-camera-port"
            import os as _os_wp
            # Remove stale file from a previous session
            try:
                _os_wp.remove(_port_file)
            except FileNotFoundError:
                pass
            print(f"Waiting for {_port_file} (start test_camera.py -w now) ...")
            while not _os_wp.path.exists(_port_file):
                time.sleep(0.25)
            with open(_port_file) as _pf:
                _cam_addr = _pf.read().strip()
            args.camera_ip, _wp = _cam_addr.split(":")
            args.udp_port = int(_wp)
            args.connect_udp = True
            print(f"  Got camera address: {args.camera_ip}:{args.udp_port}")

        # Connect — by UID or by direct UDP IP
        if args.connect_udp:
            # Try common TUTK ports in order; stop on first success
            ports = [args.udp_port] if args.udp_port else [6666, 10000, 2002, 6668, 9000, 10240]
            sid = -1
            for port in ports:
                sid = lib.connect_udp(args.camera_ip, port)
                if sid >= 0:
                    print(f"✅ IOTC session via UDP {args.camera_ip}:{port}: sid={sid}")
                    break
                print(f"  UDP:{port} → {sid}")
            if sid < 0:
                print(f"❌ connect_udp failed on all ports: {sid}")
                sys.exit(1)
        else:
            sid = lib.connect(args.uid, timeout=15)
            if sid < 0:
                print(f"❌ Connect failed: {sid}")
                sys.exit(1)
        print(f"✅ IOTC session: {sid}")

        if not lib._av:
            print("⚠️  libAVAPIs.so not loaded — AV operations unavailable")
            lib._iotc.IOTC_Session_Close(sid)
            return

        # AV auth
        av_idx = lib.av_connect(sid)
        if av_idx < 0:
            print(f"❌ AV auth failed: {av_idx}")
            lib._iotc.IOTC_Session_Close(sid)
            sys.exit(1)
        print(f"✅ AV authenticated: av_index={av_idx}")

        # PTZ move
        if args.ptz:
            ok = lib.ptz_move(av_idx, args.ptz,
                              speed=args.ptz_speed, preset=args.preset)
            print(f"{'✅' if ok else '❌'} PTZ {args.ptz}")

        # Stream
        elif args.stream:
            if lib.start_stream(av_idx):
                print("✅ Stream start commands sent")
                lib.recv_responses(av_idx, count=5, timeout_ms=3000)

        lib._av.avClientStop(av_idx)
        lib._av.avClientExit(sid, av_idx)
        lib._iotc.IOTC_Session_Close(sid)

    finally:
        lib.deinit()


if __name__ == "__main__":
    main()
