#!/usr/bin/env python3
"""
test_camera.py - Exercise the camera additions to python-aidot.

Usage:
  cd /path/to/python-aidot

  # One-time: save credentials to a file (chmod 600) so they aren't on the CLI:
  python3 test_camera.py --save-credentials ~/.config/aidot/credentials.json \
                         --username you@email.com --password yourpass

  # Subsequent runs — auto-loads ~/.config/aidot/credentials.json if it exists:
  python3 test_camera.py --webrtc --device DEVICE_ID

  # Or point explicitly at any credentials file:
  python3 test_camera.py --credentials /path/to/creds.json --webrtc

  # Plain username/password flags still work and override any credentials file:
  python3 test_camera.py --username you@email.com --password yourpass [--country US]

  # Run on a specific camera only (device UID from the device list printed above):
  python3 test_camera.py --device DEVICE_ID --webrtc

Optional flags:
  -d, --device DEVICE_ID  Only run tests for this camera's AiDot device UID
  -p, --p2p               Show device fields and probe the TUTK P2P UID endpoint
      --list-recordings   List recordings from the past 24 hours
      --play              Play back the first available recording
      --diag-mqtt         Verbose MQTT diagnostics: broker info, raw messages,
                          batchGetDeviceUserInfo dump
      --diag-live         Sniff MQTT signalling — open the AiDot app live view
                          while this runs so the WebRTC traffic is captured
  -w, --webrtc            Open a liveType=2 WebRTC stream (requires aiortc for
                          DTLS cameras; SDES cameras use ffmpeg directly):
                            pip install python-aidot[webrtc]
  -o, --webrtc-output PATH
                          Record the stream to PATH.

                          Recommended formats:
                            /tmp/cam.ts      MPEG-TS — streamable while recording
                            /tmp/cam.mkv     Matroska — full playback after stop
                            pipe:1           Raw mux to stdout (pipe into ffmpeg)

                          Playback / re-broadcast options (MPEG-TS recommended):

                            ffmpeg (re-stream to RTSP via MediaMTX / go2rtc):
                              ffmpeg -re -i /tmp/cam.ts -c copy \
                                -f rtsp rtsp://localhost:8554/cam

                            go2rtc (add to go2rtc.yaml, then open in any RTSP client):
                              streams:
                                cam: ffmpeg:/tmp/cam.ts#video=copy#audio=copy

                            VLC (direct live playback):
                              vlc /tmp/cam.ts
                              vlc rtsp://localhost:8554/cam   # after go2rtc/MediaMTX

  --webrtc-protocol {sdes|dtls|auto}
                          Force streaming protocol (default: auto, selects from
                          camera model: A000088→dtls, A001513/A001064→sdes)
  -n, --webrtc-seconds N  Seconds to stream during --webrtc (default: 300)
  -s, --set-attr KEY=VAL  Set a camera attribute via MQTT (may be repeated)
  -S, --snap PATH         Capture a live JPEG snapshot from the WebRTC stream
  -t, --thumbnail PATH    Save latest event photo to PATH
  -u, --username EMAIL    AiDot account email
  -P, --password PASS     AiDot account password
  -c, --credentials PATH  JSON credentials file (see --save-credentials)
      --save-credentials PATH  Save credentials to file and exit
  -L, --log-file PATH     Write all output to PATH as well as stdout
  -v, --verbose           Extra detail: ICE config URIs, paho logs
"""

import argparse
import asyncio
import json
import os
import stat
import sys
import time

import aiohttp


class _Tee:
    """Write to both the real stdout and a log file simultaneously.

    Installed as sys.stdout when --log-file is given so that all print()
    calls go to both the terminal and the file with no code changes at
    call sites.
    """
    def __init__(self, path: str) -> None:
        self._file   = open(path, "w", encoding="utf-8", buffering=1)
        self._stdout = sys.__stdout__

    def write(self, s: str) -> None:
        self._stdout.write(s)
        self._file.write(s)

    def flush(self) -> None:
        self._stdout.flush()
        self._file.flush()

    def fileno(self) -> int:          # needed by some logging handlers
        return self._stdout.fileno()

    def close(self) -> None:
        self._file.close()

    isatty = lambda self: False       # noqa: E731

# Run from the python-aidot repo root so the local aidot package is found.
sys.path.insert(0, ".")

try:
    from aidot.client import AidotClient
    from aidot.device_client import VideoFrame
except ImportError as e:
    print(f"ERROR: Could not import aidot. Run this script from the python-aidot directory.\n  {e}")
    sys.exit(1)

# --------------------------------------------------------------------------- #
# LAN probe
# --------------------------------------------------------------------------- #

async def _lan_probe(dc, cam_name: str, verbose: bool = False) -> None:
    """Probe a camera's LAN TCP:10000 control interface.

    Tries to complete the loginReq handshake with several AES key candidates,
    then issues getDevAttrReq if login succeeds.  Results show whether the
    camera accepts local TCP control (bypassing MQTT for attribute commands).
    """
    import socket
    import struct

    from aidot.aes_utils import aes_encrypt, aes_decrypt

    BROADCAST_KEY_STR = "T54uednca587"

    def _make_key_32(s: str) -> bytearray:
        k = bytearray(32)
        b = s.encode()
        k[:len(b)] = b
        return k

    def _make_key_16(s: str) -> bytearray:
        k = bytearray(16)
        b = s.encode()
        k[:len(b)] = b
        return k

    def _make_packet(obj: dict, aes_key) -> bytes:
        body = json.dumps(obj).encode()
        if aes_key is not None:
            body = aes_encrypt(body, aes_key)
        return struct.pack(">HHI", 0x1EED, 1, len(body)) + body

    def _parse_packet(data: bytes, aes_key) -> dict | None:
        if len(data) < 8:
            return None
        magic, _msgtype, bodysize = struct.unpack(">HHI", data[:8])
        if magic != 0x1EED:
            return None
        body = data[8:8 + bodysize]
        if aes_key is not None:
            try:
                body = aes_decrypt(body, aes_key).encode()
            except Exception:
                return None
        try:
            return json.loads(body)
        except Exception:
            return {"_raw": body[:300].decode(errors="replace")}

    cam_ip = dc._ip_address
    print(f"\n[LAN PROBE] {cam_name}  ip={cam_ip or 'unknown'}")

    # ── UDP:6666 broadcast (using existing Discover) ─────────────────────── #
    # The Discover class already ran a broadcast earlier; here we just note
    # whether this camera responded (its IP was pre-populated if it did).
    if cam_ip:
        print(f"  [UDP:6666] Camera known at {cam_ip} "
              f"({'from LAN discovery' if dc._ip_address else 'from cloud API'})")
    else:
        print("  [UDP:6666] Camera IP unknown — TCP:10000 probe skipped")
        print("             (run without --device to trigger LAN broadcast first)")
        return

    # ── TCP:10000 probe ───────────────────────────────────────────────────── #
    print(f"  [TCP:10000] Connecting to {cam_ip}:10000 ...")
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(cam_ip, 10000), timeout=5.0
        )
    except asyncio.TimeoutError:
        print("  [TCP:10000] connect timeout — port not open on this camera")
        return
    except ConnectionRefusedError:
        print("  [TCP:10000] connection refused — port not open on this camera")
        return
    except OSError as e:
        print(f"  [TCP:10000] connect failed: {e}")
        return

    print(f"  [TCP:10000] Connected.")

    # Try several AES key candidates in priority order:
    #   1. Per-device aesKey (16-byte AES-128) — used by lights, may exist for cameras
    #   2. Broadcast discovery key "T54uednca587" as AES-256 (padded to 32 bytes)
    #   3. Broadcast discovery key as AES-128 (first 16 bytes)
    #   4. No encryption (plain JSON)
    dev_aes_key = getattr(dc, "aes_key", None)  # bytearray(16) or None
    key_candidates = []
    if dev_aes_key is not None:
        key_candidates.append(("per-device aesKey (AES-128)", dev_aes_key))
    key_candidates.append(("broadcast key AES-256", _make_key_32(BROADCAST_KEY_STR)))
    key_candidates.append(("broadcast key AES-128", _make_key_16(BROADCAST_KEY_STR)))
    key_candidates.append(("no encryption", None))

    login_seq = str(int(time.time() * 1000))[-9:]
    login_msg = {
        "protocolVer": "2.0.0",
        "service": "device",
        "method": "loginReq",
        "seq": login_seq,
        "srcAddr": f"0.{dc.user_id}",
        "deviceId": dc.device_id,
        "tst": int(time.time() * 1000),
        "payload": {
            "userId": str(dc.user_id),
            "password": dc.password or "",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "ascNumber": 1,
        },
    }

    working_key = None
    for key_label, aes_key in key_candidates:
        try:
            writer.write(_make_packet(login_msg, aes_key))
            await writer.drain()
        except Exception as e:
            print(f"    send failed with {key_label}: {e}")
            continue

        try:
            raw = await asyncio.wait_for(reader.read(4096), timeout=4.0)
        except asyncio.TimeoutError:
            print(f"    {key_label}: no response (timeout)")
            continue
        except Exception as e:
            print(f"    {key_label}: read error: {e}")
            continue

        resp = _parse_packet(raw, aes_key)
        if resp is None:
            if verbose:
                print(f"    {key_label}: response not parseable with this key "
                      f"({len(raw)}B: {raw[:40].hex()})")
            continue

        ack  = resp.get("ack") or {}
        code = ack.get("code") if isinstance(ack, dict) else None
        print(f"    {key_label}: loginResp code={code}  "
              f"{json.dumps(resp, separators=(',', ':'))[:200]}")

        if code == 200:
            working_key = aes_key
            working_label = key_label
            break

    if working_key is None and code != 200:
        # Try once more: maybe camera doesn't check credentials and just sends
        # back a response we can parse with a different key.
        for _k_label, _k in key_candidates:
            resp2 = _parse_packet(raw, _k) if "raw" in dir() else None
            if resp2 and resp2.get("ack", {}).get("code") == 200:
                working_key = _k
                working_label = _k_label
                break

    if working_key is None:
        print(f"\n  Result: login failed on all key candidates.")
        print(f"          Camera may not support TCP:10000 control,")
        print(f"          or requires different credentials.")
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return

    print(f"\n  LOGIN SUCCESS with {working_label}")
    print(f"  → TCP:10000 LAN control is SUPPORTED on this camera.")
    print(f"  → Attribute reads/writes can bypass MQTT.")

    # ── Send getDevAttrReq ────────────────────────────────────────────────── #
    asc = (resp.get("payload") or {}).get("ascNumber", 1) if resp else 1
    attr_msg = {
        "protocolVer": "2.0.0",
        "service": "device",
        "method": "getDevAttrReq",
        "seq": str(int(time.time() * 1000))[-9:],
        "srcAddr": f"0.{dc.user_id}",
        "deviceId": dc.device_id,
        "tst": int(time.time() * 1000),
        "payload": {
            "devId": dc.device_id,
            "ascNumber": asc + 1,
        },
    }
    try:
        writer.write(_make_packet(attr_msg, working_key))
        await writer.drain()
        raw2 = await asyncio.wait_for(reader.read(8192), timeout=5.0)
        resp2 = _parse_packet(raw2, working_key)
        if resp2:
            attrs = (resp2.get("payload") or {}).get("attr", {})
            if attrs:
                print(f"\n  Camera attributes (via TCP:10000):")
                for k, v in sorted(attrs.items()):
                    print(f"    {k} = {v!r}")
            else:
                print(f"\n  getDevAttrResp (no attr field): {json.dumps(resp2, indent=2)[:600]}")
        else:
            print(f"  getDevAttrResp: unparseable ({len(raw2)}B): {raw2[:80].hex()}")
    except asyncio.TimeoutError:
        print("  getDevAttrResp: timeout (5s) — no attribute push yet")
    except Exception as e:
        print(f"  getDevAttrReq error: {e}")

    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def ms_to_str(ts_ms: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts_ms / 1000))


def find_cameras(devices: list) -> list:
    # Heuristic: cameras have a productId or modelId containing "CAM" or "IPC",
    # or a serviceModule identity that starts with "control.camera".
    cameras = []
    for dev in devices:
        product = dev.get("product") or {}
        modules = product.get("serviceModules") or []
        identities = [m.get("identity", "") for m in modules]
        model = (dev.get("modelId") or "").upper()
        if (any("camera" in i.lower() or "ipc" in i.lower() for i in identities)
                or "CAM" in model or "IPC" in model):
            cameras.append(dev)
    return cameras


def on_frame(frame: VideoFrame) -> None:
    kind = ("KEYFRAME" if frame.is_keyframe
            else "P/B-frame" if frame.is_video
            else "audio" if frame.is_audio
            else f"type={frame.frame_type}")
    enc  = " [encrypted]" if frame.is_encrypted else ""
    size = len(frame.data)
    ts   = (ms_to_str(frame.timestamp) if frame.timestamp > 1_000_000_000_000
            else f"ts={frame.timestamp}")
    print(f"  frame  {kind:<10}  {size:>6} bytes  {ts}{enc}")


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

async def run(args: argparse.Namespace) -> None:
    import sys as _sys
    import logging as _logging
    _log_fmt = "%(name)s %(levelname)s: %(message)s"
    _vv = getattr(args, "very_verbose", False)
    if _vv:
        args.verbose = True   # --vv implies --verbose
        _logging.basicConfig(level=_logging.DEBUG, format=_log_fmt, stream=_sys.stdout)
        # --vv: enable aioice/TURN trace so STUN/TURN packet flow is visible
        for _noisy in ("paho",):
            _logging.getLogger(_noisy).setLevel(_logging.WARNING)
    elif args.verbose:
        _logging.basicConfig(level=_logging.DEBUG, format=_log_fmt, stream=_sys.stdout)
        # --verbose: suppress pure packet-level noise from third-party libs
        for _noisy in ("aiortc", "aioice", "aioice.ice", "paho"):
            _logging.getLogger(_noisy).setLevel(_logging.WARNING)
        _logging.getLogger("aiortc.rtcdtlstransport").setLevel(_logging.DEBUG)
    else:
        _logging.basicConfig(level=_logging.WARNING, format=_log_fmt, stream=_sys.stdout)
    async with aiohttp.ClientSession() as http_session:
        client = AidotClient(
            session=http_session,
            country_code=args.country,
            username=args.username,
            password=args.password,
        )

        # Login (now calls /users/login with MD5 password + fetches MQTT pwd via /commons/userConfig)
        print(f"\n[1] Logging in as {args.username} ...")
        try:
            info = await client.async_post_login()
            user_id = info.get("id") or info.get("userId") or "?"
            has_mqtt_pwd = bool(info.get("mqttPassword"))
            print(f"    OK  userId={user_id}  region={client._region}  "
                  f"mqttPassword={'present' if has_mqtt_pwd else 'MISSING'}")
            if not has_mqtt_pwd:
                raw_cfg = info.get("_userConfigRaw") or {}
                print(f"    [userConfig raw keys]: {list(raw_cfg.keys())}")
                print(f"    [userConfig raw body]: {raw_cfg}")
        except Exception as e:
            print(f"    FAILED: {e}")
            return

        # Get all devices
        print("\n[2] Fetching device list ...")
        try:
            result  = await client.async_get_all_device()
            devices = result.get("device_list") or []
            print(f"    {len(devices)} device(s) found")
        except Exception as e:
            print(f"    FAILED: {e}")
            return

        if not devices:
            print("    No devices on account — nothing to test.")
            return

        # Identify cameras
        cameras = find_cameras(devices)
        if not cameras:
            print("\n    No camera devices detected (checked modelId and serviceModules).")
            print("    All devices:")
            for d in devices:
                print(f"      {d.get('id')}  model={d.get('modelId')}  name={d.get('name')}")
            print("\n    You can still test P2P/playback by passing a specific device ID")
            print("    via --device if you know which one is a camera.")
            return

        print(f"    {len(cameras)} camera(s) detected:")
        for cam in cameras:
            print(f"      {cam.get('id')}  model={cam.get('modelId')}  name={cam.get('name')}")

        # Collect all camera IDs upfront for batch API calls.
        # The app sends all device IDs in a single batchGetDeviceUserInfo request
        # (~260 bytes for 7 devices); sending only one may return an empty result.
        # Must be built from the unfiltered list before --device narrows it down.
        _all_camera_ids = [c.get("id") for c in cameras if c.get("id")]

        if args.device:
            # Accept both UUID (exact) and display name (case-insensitive partial).
            _query = args.device.strip()
            _by_id   = [c for c in cameras if c.get("id") == _query]
            _by_name = [c for c in cameras if _query.lower() in (c.get("name") or "").lower()]
            cameras  = _by_id or _by_name
            if not cameras:
                print(f"    --device {_query!r} not found (checked UUID and name)")
                return
            print(f"    Filtered to: {', '.join(c.get('name', c.get('id')) for c in cameras)}")

        # Brief LAN broadcast discovery so ICE-lite cameras (e.g. LK.IPC.A001064)
        # get their local IP populated in dc._ip_address before the WebRTC session.
        # Without this, batchGetDeviceUserInfo returns no IP field for these cameras
        # and synthetic ICE candidates cannot be injected — ICE fails after 30 s.
        _disc_ips: dict = {}
        try:
            from aidot.discover import Discover as _Discover
            print("\n[LAN] Discovering cameras on local network ...")
            _disc = _Discover(client.login_info, None)
            await _disc.send_broadcast()
            await asyncio.sleep(3.0)
            await _disc.send_broadcast()   # second broadcast for cameras that miss the first
            await asyncio.sleep(3.0)
            _disc.close()
            for _cam in cameras:
                _disc_ip = _disc.discovered_device.get(_cam.get("id"))
                if _disc_ip:
                    _disc_ips[_cam.get("id")] = _disc_ip
                    print(f"    LAN discovery: {_cam.get('name')} → {_disc_ip}")
            if not _disc_ips:
                print("    No cameras responded to LAN broadcast (may be remote/offline)")
        except Exception as _disc_exc:
            print(f"    LAN discovery skipped: {_disc_exc}")

        # Run selected tests
        for cam in cameras:
            dc = client.get_device_client(cam)
            # Ensure batchGetDeviceUserInfo uses all device IDs (server may
            # return empty results if only a single device ID is sent).
            dc._all_device_ids = _all_camera_ids
            # Apply LAN-discovered IP so async_open_webrtc_stream can inject
            # synthetic ICE candidates for ICE-lite cameras.
            if cam.get("id") in _disc_ips:
                dc._ip_address = _disc_ips[cam.get("id")]
            print(f"\n{'='*60}")
            print(f"Camera: {cam.get('name')}  ({cam.get('id')})")
            print(f"{'='*60}")

            # LAN probe
            if args.lan_probe:
                await _lan_probe(dc, cam.get("name", cam.get("id", "?")),
                                 verbose=args.verbose)

            # P2P UID
            if args.p2p or not (args.list_recordings or args.play or
                                args.diag_mqtt or args.diag_live or args.webrtc
                                or args.lan_probe or args.set_attrs
                                or args.thumbnail or args.snap):
                print("\n[P2P] Camera device fields:")
                for k, v in cam.items():
                    if k != "product":
                        print(f"    {k} = {v!r}")

                base = dc._smarthome_base
                headers_no_ct = {k: v for k, v in dc._leedarson_headers().items()
                                 if k != "Content-Type"}

                print(f"\n[P2P] Trying P2P UID requests against {base}")

                candidates = [
                    ("deviceId (form)", "form", {"deviceId": cam.get("id")}),
                    ("deviceSn (form)", "form", {"deviceSn": cam.get("sn") or cam.get("deviceSn") or cam.get("serialNumber")}),
                    ("deviceId (json)", "json", {"deviceId": cam.get("id")}),
                    ("mac (form)",      "form", {"mac":      cam.get("mac")}),
                ]

                for label, enc, body in candidates:
                    val = list(body.values())[0]
                    if not val:
                        print(f"    {label:<25} skipped (field not present)")
                        continue
                    try:
                        async with aiohttp.ClientSession() as _s:
                            kw = {"headers": headers_no_ct, "timeout": aiohttp.ClientTimeout(total=10)}
                            if enc == "json":
                                kw["json"] = body
                            else:
                                kw["data"] = body
                            async with _s.post(f"{base}/deviceController/getP2pId", **kw) as _r:
                                _resp = await _r.json(content_type=None)
                        uid_val = _resp.get("data") or _resp.get("uid")
                        marker = "  *** UID FOUND ***" if uid_val else ""
                        print(f"    {label:<25} -> {_resp}{marker}")
                    except Exception as _e:
                        print(f"    {label:<25} -> ERROR: {_e}")

            # Cloud recordings
            if args.list_recordings or args.play:
                now_ms   = int(time.time() * 1000)
                day_ms   = 24 * 60 * 60 * 1000
                start_ms = now_ms - day_ms

                print(f"\n[REC] Listing recordings from last 24 h ...")
                clips = await dc.async_get_cloud_recordings(start_ms, now_ms)
                if not clips:
                    print("    No recordings found in that window.")
                else:
                    print(f"    {len(clips)} clip(s):")
                    for i, c in enumerate(clips):
                        dur = (c["end"] - c["sta"]) // 1000
                        print(f"      [{i}]  {ms_to_str(c['sta'])}  ->  "
                              f"{ms_to_str(c['end'])}  ({dur}s)")

                # Playback
                if args.play and clips:
                    clip = clips[0]
                    print(f"\n[PLAY] Opening playback for clip [0] "
                          f"({ms_to_str(clip['sta'])} -> {ms_to_str(clip['end'])}) ...")
                    print("    (Ctrl+C to stop early)")

                    session = await dc.async_open_cloud_playback(
                        clip["sta"], clip["end"], on_frame
                    )
                    if session is None:
                        print("    FAILED to open playback session.")
                    else:
                        print(f"    Session open — streaming for {args.play_seconds}s ...")
                        try:
                            await asyncio.sleep(args.play_seconds)
                        except asyncio.CancelledError:
                            pass
                        finally:
                            await session.stop()
                        print("    Session stopped.")

            if args.diag_mqtt:
                # --------------------------------------------------------------- #
                # MQTT diagnostics: print broker URL, connection status, and
                # ALL raw messages received so we can see what the broker delivers.
                # --------------------------------------------------------------- #
                print(f"\n[DIAG] All raw device fields for {cam.get('name')}:")
                for _dk, _dv in cam.items():
                    print(f"    {_dk} = {_dv!r}")

                # Dump ALL user_info keys
                print(f"\n[DIAG] All user_info keys ({len(dc._user_info)} total):")
                SENSITIVE = ("token", "password", "pwd", "secret")
                for k, v in sorted(dc._user_info.items()):
                    if any(x in k.lower() for x in SENSITIVE):
                        print(f"    {k!r}: <redacted len={len(str(v))}>")
                    else:
                        print(f"    {k!r}: {v!r}")

                _lid = dc._user_info

                # --- batchGetDeviceUserInfo probe (AiDot v21 API) ---
                # Send all camera IDs in one batch (mirrors app behaviour ~260B body).
                import json as _dui_json
                print(f"\n[DIAG] Fetching batchGetDeviceUserInfo "
                      f"(batch of {len(_all_camera_ids)} device(s)) ...")
                _dev_user_info = await dc.async_get_device_user_info(
                    all_device_ids=_all_camera_ids)
                _raw_batch = getattr(dc, '_last_batch_response', None)
                if _dev_user_info:
                    _p2p = (_dev_user_info.get("p2pId") or _dev_user_info.get("uid")
                            or _dev_user_info.get("tutk_uid"))
                    print(f"    batchGetDeviceUserInfo data for {cam.get('id')}:")
                    print(f"    {_dui_json.dumps(_dev_user_info, indent=6, default=str)}")
                    if not _p2p:
                        print(f"    (no p2pId — TUTK P2P not supported by this camera)")
                else:
                    print(f"    batchGetDeviceUserInfo: call failed for {cam.get('id')}")
                    print(f"    raw server response: {_raw_batch}")

                # --- P2P UID probe ---
                print(f"\n[DIAG] Fetching P2P UID for {cam.get('id')} ...")
                _p2p_uid = await dc.async_get_p2p_uid()
                if _p2p_uid:
                    print(f"    P2P UID: {_p2p_uid!r}  (TUTK/LiveAndPlayBack path available)")
                else:
                    print(f"    P2P UID: None  (P2P not available; relay path needed)")

            if args.diag_live:
                # ----------------------------------------------------------- #
                # MQTT live-stream sniffer + HTTP provisioning probe
                # ----------------------------------------------------------- #
                import json as _dlj
                from aidot.device_client import _mqtt_session_with_status

                print(f"\n[DIAG-LIVE] Live-stream provisioning probe for {cam.get('name')} ...")

                # Fetch MQTT credentials
                _sm_auth = await dc._async_get_smarthome_auth()
                _mqtt_user = (_sm_auth or {}).get("mqttUser") or str(dc.user_id)
                _mqtt_pwd  = (_sm_auth or {}).get("mqttPassword") or ""
                # Use the EXACT authorised clientId from the server config.
                # The broker requires the server-assigned {terminalIndex}-{userId}
                # format; random or made-up prefixes are rejected with rc=4.
                _mqtt_cid  = (dc._user_info.get("mqttClientId") or
                              (dc._user_info.get("_userConfigRaw") or {}).get("mqtt", {}).get("clientId") or
                              f"app-{_mqtt_user}")
                _mqtt_url  = await dc._async_get_mqtt_url()

                print(f"    MQTT broker   : {_mqtt_url}")
                print(f"    MQTT user     : {_mqtt_user}")
                print(f"    MQTT clientId : {_mqtt_cid}")
                print(f"    MQTT pwd      : {'<present>' if _mqtt_pwd else '<MISSING>'}")

                # Print any streaming-related keys from getServerUrlConfig response.
                _raw_cfg = (dc._smarthome_auth or {}).get("raw") or {}
                if _raw_cfg and set(_raw_cfg.keys()) != {"source"}:
                    _stream_keys = {k: v for k, v in _raw_cfg.items()
                                    if any(x in k.lower() for x in
                                           ("live", "stream", "rtsp", "webrtc", "kvs",
                                            "signal", "media", "play", "video", "ipc"))}
                    if _stream_keys:
                        print(f"    getServerUrlConfig streaming keys: {_stream_keys}")
                    elif args.verbose:
                        print(f"    getServerUrlConfig keys: {sorted(_raw_cfg.keys())}")

                # ICE config (HTTP — no MQTT session needed)
                print(f"\n[DIAG-LIVE] Fetching ICE server config (STUN/TURN credentials) ...")
                _ice_cfg = await dc.async_get_ice_config(cam.get("id"))
                if _ice_cfg:
                    _app_entries = _ice_cfg.get("app") or []
                    _dev_entries = _ice_cfg.get("dev") or []
                    _cam_dev = next((e for e in _dev_entries if e.get("id") == cam.get("id")), None)
                    print(f"    ICE config received — "
                          f"{len(_app_entries)} app entr{'y' if len(_app_entries)==1 else 'ies'}, "
                          f"{len(_dev_entries)} device entr{'y' if len(_dev_entries)==1 else 'ies'}")
                    if _cam_dev:
                        _uris = _cam_dev.get("uris") or []
                        print(f"    This camera: token={_cam_dev.get('token','?')}  "
                              f"ttl={_cam_dev.get('ttl','?')}  uris={_uris}")
                    if args.verbose:
                        for _e in _app_entries:
                            print(f"      app  id={_e.get('id','?')}  token={_e.get('token','?')}  ttl={_e.get('ttl','?')}")
                            for _u in (_e.get("uris") or []):
                                print(f"           uri: {_u}")
                        for _e in _dev_entries:
                            _marker = "  *** this camera ***" if _e.get("id") == cam.get("id") else ""
                            print(f"      dev  id={_e.get('id','?')}  token={_e.get('token','?')}{_marker}")
                            for _u in (_e.get("uris") or []):
                                print(f"           uri: {_u}")
                else:
                    print(f"    (no ICE config received — sniff may capture it if app is active)")

                # Passive MQTT sniff — single persistent session using the
                # authorised clientId.  The on_ready hook waits for ENTER so the
                # 60-second capture window starts exactly when the user says, while
                # the broker connection (and any early messages) are preserved.
                _sniff_secs = args.diag_live_seconds
                _live_topics = [
                    f"iot/v1/cb/{cam.get('id')}/#",
                    f"iot/v1/c/{_mqtt_user}/#",
                    f"lds/v1/cb/{cam.get('id')}/#",
                    f"lds/v1/c/{_mqtt_user}/#",
                ]

                _seen = []
                def _on_msg(topic, payload):
                    _seen.append((topic, payload))
                    try:
                        _p = _dlj.loads(payload)
                        _pstr = _dlj.dumps(_p, indent=6, default=str)
                    except Exception:
                        _p = None
                        _pstr = repr(payload[:500])
                    print(f"  MQTT  topic={topic}")
                    print(f"        {_pstr}")
                    # For webrtcReq/webrtcResp: highlight SDP transport line
                    _method = _p.get("method") if isinstance(_p, dict) else None
                    if _method in ("webrtcReq", "webrtcResp"):
                        _inner = (_p.get("payload") or {})
                        _sdp   = ((_inner.get("offer") or _inner.get("answer") or {})).get("sdp", "")
                        _pid   = _inner.get("peerid", "?")
                        _vtrans = next(
                            (ln.split()[2] for ln in _sdp.splitlines()
                             if ln.startswith("m=video ") and len(ln.split()) > 2),
                            "absent",
                        )
                        print(f"        *** {_method}: peerid={_pid}")
                        print(f"        *** SDP m=video transport: {_vtrans}")

                def _on_ready(st):
                    """Called from the MQTT thread after subscription.
                    Blocks on stdin so the capture window starts after ENTER.
                    """
                    if not st.get("connected"):
                        err = st.get("error") or st.get("rc_str") or f"rc={st.get('rc')}"
                        print(f"\n[DIAG-LIVE] MQTT connection FAILED: {err}")
                        if args.verbose:
                            for _ll in st.get("log", [])[-10:]:
                                print(f"  paho: {_ll}")
                        return
                    print(f"\n[DIAG-LIVE] MQTT connected (clientId={_mqtt_cid})")
                    print()
                    print(f"    STEP 1: Open the AiDot app on your phone")
                    print(f"    STEP 2: Navigate to the live view for '{cam.get('name')}'")
                    print(f"    STEP 3: Press ENTER below AFTER the live view is open")
                    print()
                    # Write prompt to stderr so it appears on the terminal even
                    # when stdout is redirected to a file (--log-file).
                    sys.stderr.write(
                        f"    >>> Press ENTER to start the {_sniff_secs}s capture window ... "
                    )
                    sys.stderr.flush()
                    sys.stdin.readline()
                    print(f"    Capture started — keep the live view open for {_sniff_secs}s ...")
                    print()

                print(f"\n[DIAG-LIVE] Connecting to MQTT broker for {_sniff_secs}s sniff ...")
                _sniff_msgs, _sniff_status = await _mqtt_session_with_status(
                    _mqtt_url, _mqtt_user, _mqtt_pwd, _mqtt_cid,
                    _live_topics, [], float(_sniff_secs), _on_msg,
                    ws_path="/mqtt", on_ready=_on_ready,
                )
                if _sniff_status.get("connected"):
                    print(f"\n    Sniff complete. {len(_seen)} message(s) captured.")
                else:
                    _err = _sniff_status.get("error") or _sniff_status.get("rc_str") or f"rc={_sniff_status.get('rc')}"
                    print(f"\n    MQTT connection failed: {_err}")
                    if args.verbose:
                        for _logline in _sniff_status.get("log", [])[-10:]:
                            print(f"      paho: {_logline}")

            if args.webrtc:
                # ----------------------------------------------------------- #
                # WebRTC live stream via MQTT signaling + aiortc (DTLS cameras)
                # or ffmpeg SRTP receiver (SDES cameras, isDTLS == '0').
                #
                # Capture to MPEG-TS (streamable while recording):
                #   python3 test_camera.py ... --webrtc --webrtc-output /tmp/cam.ts
                #
                # Re-broadcast as RTSP with ffmpeg → MediaMTX / go2rtc:
                #   ffmpeg -re -i /tmp/cam.ts -c copy -f rtsp rtsp://localhost:8554/cam
                #
                # go2rtc pull (go2rtc.yaml):
                #   streams:
                #     cam: ffmpeg:/tmp/cam.ts#video=copy#audio=copy
                #
                # VLC direct:
                #   vlc /tmp/cam.ts
                #   vlc rtsp://localhost:8554/cam   # after go2rtc / MediaMTX
                # ----------------------------------------------------------- #
                # Check for aiortc (required for DTLS cameras; SDES cameras use ffmpeg).
                # Print a note but do NOT skip — SDES cameras work without aiortc.
                try:
                    import aiortc as _aiortc_check  # noqa: F401
                    _has_aiortc = True
                except ImportError:
                    _has_aiortc = False

                if not _has_aiortc:
                    print(f"\n[WEBRTC] Note: aiortc not installed "
                          f"(needed for DTLS cameras; SDES cameras use ffmpeg).")
                    print(f"    pip install aiortc")

                # Auto-name output file when -w is used without -o.
                _cam_name   = cam.get("name") or cam.get("id", "cam")
                _safe_name  = "".join(c if c.isalnum() or c in "-_" else "_" for c in _cam_name)
                import datetime as _dt
                _ts_str     = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
                _out_path   = args.webrtc_output or f"/tmp/cam-{_safe_name}-{_ts_str}.ts"

                # Resolve protocol: auto → use camera's is_sdes_camera property.
                _proto = args.webrtc_protocol  # "auto" | "sdes" | "dtls"
                _force_sdes: bool | None
                if _proto == "sdes":
                    _force_sdes = True
                elif _proto == "dtls":
                    _force_sdes = False
                else:
                    _force_sdes = None  # library auto-detects from model/properties

                print(f"\n[WEBRTC] {_cam_name}")
                print(f"    Output : {_out_path}")
                print(f"    Protocol: {'auto' if _force_sdes is None else ('SDES' if _force_sdes else 'DTLS')}"
                      f"  |  Duration: {args.webrtc_seconds}s  |  Timeout: {args.webrtc_timeout}s")

                _wrtc_frames = [0]
                def _wrtc_on_frame(frame) -> None:
                    _wrtc_frames[0] += 1
                    if _wrtc_frames[0] % 30 == 1:
                        print(f"    frame #{_wrtc_frames[0]}"
                              f"  {getattr(frame, 'width', '?')}x{getattr(frame, 'height', '?')}")

                # Three verbosity tiers for status messages from the WebRTC stack:
                #   (no flag) → key connection milestones only
                #   --verbose → + session-level events (ICE/DTLS state, DataChannel,
                #                 SDP details, MQTT signaling, TURN allocation)
                #   --vv      → + per-packet traces (RX p0, DTLS-app-data, DC RX, ...)
                _STATUS_ALWAYS = (
                    "mqtt connected", "camera awake", "wake timeout", "already awake",
                    "sdp offer", "webrtcresp received", "ice controlling",
                    "ice connectionstate", "webrtc connectionstate",
                    "bridge thread started", "ffmpeg ready", "ffmpeg cmd",
                    "first srtp", "first audio rtp", "first video rtp",
                    "webrtc stream open",
                    "session stopped", "failed", "error", "note:",
                )
                # Per-packet traces that should only appear at --vv
                _STATUS_PACKETS = (
                    "rx p0 t+", "dtls-app-data", " dc[", " rx ", "stun window",
                )
                def _wrtc_status(msg: str) -> None:
                    msg_l = msg.lower()
                    is_always  = any(kw in msg_l for kw in _STATUS_ALWAYS)
                    is_packet  = any(kw in msg_l for kw in _STATUS_PACKETS)
                    _vv_mode   = getattr(args, "very_verbose", False)
                    if is_always:
                        print(f"    {msg}")
                    elif _vv_mode:
                        print(f"    {msg}")      # --vv: show everything
                    elif args.verbose and not is_packet:
                        print(f"    {msg}")      # --verbose: session-level, no packets

                try:
                    _wrtc_session = await dc.async_open_webrtc_stream(
                        on_frame=_wrtc_on_frame,
                        output_path=_out_path,
                        max_seconds=args.webrtc_seconds,
                        timeout=args.webrtc_timeout,
                        status_callback=_wrtc_status,
                        force_sdes=_force_sdes,
                    )
                    print(f"    WebRTC connected — streaming for {args.webrtc_seconds}s"
                          f"  (Ctrl+C to stop early)")
                    try:
                        # For SDES cameras ffmpeg exits when -t expires; wait_done()
                        # returns as soon as it does.  For DTLS cameras (no wait_done)
                        # fall back to sleeping for the full duration.
                        _wait_fn = getattr(_wrtc_session, "wait_done", None)
                        if _wait_fn is not None:
                            await asyncio.wait_for(
                                _wait_fn(),
                                timeout=args.webrtc_seconds + 10,
                            )
                        else:
                            await asyncio.sleep(args.webrtc_seconds)
                    except (asyncio.CancelledError, asyncio.TimeoutError):
                        pass
                    finally:
                        await _wrtc_session.stop()
                    print(f"    Done. {_wrtc_frames[0]} frame(s)  →  {_out_path}")
                except ImportError as _ie:
                    print(f"    ERROR: {_ie}")
                except RuntimeError as _re:
                    print(f"    FAILED: {_re}")
                except Exception as _exc:
                    print(f"    UNEXPECTED ERROR [{type(_exc).__name__}]: {_exc}")

            # ---------------------------------------------------------- #
            # Latest event thumbnail: --thumbnail PATH                    #
            # ---------------------------------------------------------- #
            if args.thumbnail:
                print(f"\n[THUMBNAIL] Fetching latest event photo for"
                      f" {cam.get('name', cam.get('id', '?'))} ...")
                try:
                    url = await dc.async_get_latest_thumbnail()
                    if url:
                        print(f"    URL: {url}")
                        async with aiohttp.ClientSession() as _sess:
                            async with _sess.get(url, timeout=aiohttp.ClientTimeout(total=30)) as _r:
                                img_bytes = await _r.read()
                        out = args.thumbnail
                        with open(out, "wb") as _f:
                            _f.write(img_bytes)
                        print(f"    Saved {len(img_bytes):,} bytes → {out}")
                    else:
                        print("    No event photos available (no cloud plan or no recent events)")
                except Exception as _te:
                    print(f"    ERROR: {_te}")

            # ---------------------------------------------------------- #
            # Live snapshot: --snap PATH                                   #
            # ---------------------------------------------------------- #
            if args.snap:
                _snap_name = cam.get("name", cam.get("id", "?"))
                print(f"\n[SNAP] Capturing live snapshot from {_snap_name} ...")
                def _snap_status(msg: str) -> None:
                    msg_l = msg.lower()
                    if any(kw in msg_l for kw in (
                        "webrtc stream open", "ice connectionstate", "dtls",
                        "failed", "error", "timeout",
                    )):
                        print(f"    {msg}")
                try:
                    ok = await dc.async_snapshot(
                        args.snap,
                        timeout=args.webrtc_timeout,
                        status_callback=_snap_status,
                    )
                    if ok:
                        print(f"    Saved → {args.snap}")
                    else:
                        print("    FAILED: no keyframe received within timeout")
                except Exception as _se:
                    print(f"    ERROR: {_se}")

            # ---------------------------------------------------------- #
            # Device controls: --set-attr KEY=VALUE                       #
            # ---------------------------------------------------------- #
            if args.set_attrs:
                print(f"\n[SET-ATTR] Setting attributes on {cam.get('name', cam.get('id', '?'))} ...")
                for kv in args.set_attrs:
                    if "=" not in kv:
                        print(f"    SKIP: {kv!r}  (expected KEY=VALUE format)")
                        continue
                    attr_key, _, attr_val = kv.partition("=")
                    attr_key = attr_key.strip()
                    attr_val_raw = attr_val.strip()
                    # Auto-coerce numeric strings to int so the payload is typed correctly
                    # (most attrs use int 0/1; MotionDetection_Enable uses str "0"/"1")
                    try:
                        attr_val_typed = int(attr_val_raw)
                    except ValueError:
                        attr_val_typed = attr_val_raw
                    print(f"    {attr_key} = {attr_val_typed!r} ...", end="  ", flush=True)
                    try:
                        ok = await dc.async_set_device_attribute(attr_key, attr_val_typed)
                        print("✓ acked" if ok else "? no ack (check camera logs)")
                    except Exception as _e:
                        print(f"ERROR: {_e}")


from aidot.credentials import (
    load_credentials, save_credentials,
    _DEFAULT_CREDS_FILE as _DEFAULT_CREDS_PATH,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Test camera additions to python-aidot",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("-u", "--username", default=None,
                        help="AiDot account email (can also be stored in a credentials file)")
    parser.add_argument("-P", "--password", default=None,
                        help="AiDot account password (can also be stored in a credentials file)")
    parser.add_argument("--country", default=None, help="Country code (default: US)")
    parser.add_argument("-c", "--credentials", metavar="PATH", default=None,
                        help="JSON credentials file produced by --save-credentials. "
                             f"Auto-loaded from {_DEFAULT_CREDS_PATH} if it exists and "
                             "--username/--password are not given.")
    parser.add_argument("--save-credentials", action="store_true", default=False,
                        help="Encrypt and save --username/--password/--country to "
                             "~/.config/aidot/credentials.enc and exit. Works on any platform "
                             "without OS keychain dependencies.")
    parser.add_argument("-p", "--p2p", action="store_true",
                        help="Show device fields and probe the P2P UID endpoint "
                             "(also the default when no other action flag is given)")
    parser.add_argument("--list-recordings", action="store_true",
                        help="List cloud recordings from the past 24 hours")
    parser.add_argument("--play", action="store_true",
                        help="Play back the first available recording")
    parser.add_argument("--play-seconds", type=int, default=15,
                        help="How many seconds to stream during --play (default: 15)")
    parser.add_argument("--diag-mqtt", action="store_true",
                        help="Verbose MQTT diagnostics: broker info, raw messages, "
                             "batchGetDeviceUserInfo dump, P2P UID probe")
    parser.add_argument("--diag-live", action="store_true",
                        help="Probe live-stream provisioning API and sniff MQTT for "
                             "--diag-live-seconds seconds (open app live view during sniff)")
    parser.add_argument("--diag-live-seconds", type=int, default=60,
                        help="How many seconds to sniff MQTT during --diag-live (default: 60)")
    parser.add_argument("-d", "--device", metavar="NAME_OR_ID",
                        help="Camera to use — accepts UUID or display name "
                             "(case-insensitive, partial match). E.g. -d Deck")
    parser.add_argument("-L", "--log-file", metavar="PATH",
                        help="Write all output to PATH in addition to stdout "
                             "(prompt still appears on terminal even when stdout is redirected)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Session-level detail: ICE/DTLS state, DataChannel events, "
                             "SDP sections, MQTT exchanges (no per-packet traces)")
    parser.add_argument("--vv", "--very-verbose", dest="very_verbose",
                        action="store_true",
                        help="Packet-level traces: every RX packet, DTLS records, "
                             "SCTP frames, aioice/TURN debug (implies --verbose)")
    parser.add_argument("-w", "--webrtc", action="store_true",
                        help="Stream live video via WebRTC (auto-selects DTLS or SDES "
                             "based on camera model; requires aiortc for DTLS cameras)")
    parser.add_argument("-o", "--webrtc-output", metavar="PATH",
                        help="Record to PATH (e.g. /tmp/cam.ts). Omit to auto-name "
                             "as /tmp/cam-{name}-{timestamp}.ts. Use .ts for live "
                             "playback or RTSP re-broadcast via ffmpeg+go2rtc.")
    parser.add_argument("-n", "--webrtc-seconds", type=int, default=300,
                        help="Stream duration in seconds (default: 300). "
                             "The camera session is kept alive with periodic AVIO "
                             "heartbeats for the full duration.")
    parser.add_argument("--webrtc-timeout", type=float, default=30.0,
                        help="Seconds to wait for WebRTC ICE connection (default: 30)")
    parser.add_argument("--webrtc-protocol", metavar="{sdes|dtls|auto}",
                        default="auto",
                        help="Force streaming protocol. 'auto' (default) selects based "
                             "on camera model (A000088→dtls, A001513/A001064→sdes)")
    parser.add_argument("--lan-probe", action="store_true",
                        help="Probe LAN control interface (TCP:10000) on each camera. "
                             "Tests loginReq handshake with several AES key candidates "
                             "and dumps camera attributes if login succeeds. "
                             "Requires camera IP (from LAN broadcast discovery or cloud API).")
    parser.add_argument("-s", "--set-attr", metavar="KEY=VALUE", action="append",
                        default=[], dest="set_attrs",
                        help="Set a camera attribute via MQTT setDevAttrReq. "
                             "May be repeated. Examples:\n"
                             "  -s MotionDetection_Enable=1\n"
                             "  -s LightOnOff=1\n"
                             "  -s Dimming=80\n"
                             "  -s sirenRing=1\n"
                             "  -s nightVisionMode=0\n"
                             "  -s LedOnOff=0")
    parser.add_argument("-t", "--thumbnail", metavar="PATH",
                        help="Fetch the latest event photo from the cloud and save it to PATH "
                             "(e.g. /tmp/snap.jpg). Requires an active cloud plan with events.")
    parser.add_argument("-S", "--snap", metavar="PATH",
                        help="Capture a live JPEG snapshot from the camera's WebRTC stream "
                             "and save to PATH (e.g. /tmp/snap.jpg). Works offline; "
                             "requires Pillow or ffmpeg.")

    args = parser.parse_args()

    # --save-credentials: encrypt credentials to file and exit
    if args.save_credentials:
        if not args.username or not args.password:
            parser.error("--save-credentials requires --username and --password")
        path = save_credentials(
            args.username,
            args.password,
            args.country or "US",
            args.credentials,
        )
        print(f"Credentials saved to {path}")
        return

    # Credential resolution order:
    #   1. Explicit --username/--password on the command line (highest priority)
    #   2. AIDOT_USERNAME / AIDOT_PASSWORD env vars (via load_credentials)
    #   3. Encrypted credentials file (default or --credentials path)
    #   4. Legacy plain JSON credentials file (auto-migrated to encrypted)
    if not (args.username and args.password):
        try:
            creds = load_credentials(args.credentials)
        except Exception as exc:
            parser.error(
                f"Could not load credentials: {exc}\n"
                "  Provide --username/--password, set AIDOT_USERNAME/AIDOT_PASSWORD, "
                "or run --save-credentials."
            )
        args.username = args.username or creds["username"]
        args.password = args.password or creds["password"]
        if args.country is None:
            args.country = creds.get("country", "US")

    if args.country is None:
        args.country = "US"

    # --webrtc-output or --webrtc-protocol imply --webrtc.
    if not args.webrtc and (args.webrtc_output or args.webrtc_protocol != "auto"):
        args.webrtc = True

    # Default: show device info when no action flag is given.
    if not any([args.p2p, args.list_recordings, args.play,
                args.diag_mqtt, args.diag_live, args.webrtc, args.set_attrs,
                args.thumbnail, args.snap, args.lan_probe]):
        args.p2p = True

    _tee = None
    if args.log_file:
        _tee = _Tee(args.log_file)
        sys.stdout = _tee

    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\nInterrupted.")
    finally:
        if _tee:
            sys.stdout = sys.__stdout__
            _tee.close()


if __name__ == "__main__":
    main()
