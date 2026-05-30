#!/usr/bin/env python3
"""
beta_test.py — AiDot camera beta readiness test suite.

Exercises every connected camera across all six capability areas:
cloud APIs, MQTT attribute reads, device controls, WebRTC streaming,
cloud recording playback, and LAN control probe.

Results are printed to stdout and written to a timestamped log file.
Stream output files are saved to /tmp/ for manual playback in VLC.

Usage:
    python3 beta_test.py                         # all cameras, all tests
    python3 beta_test.py -d Deck                 # one camera (partial name)
    python3 beta_test.py --no-stream             # skip WebRTC (fast, ~2 min)
    python3 beta_test.py --no-controls           # skip attribute writes
    python3 beta_test.py --stream-seconds 20     # longer stream (default 10)
    python3 beta_test.py -L /tmp/beta.log        # write log + JSON to file
"""

import argparse
import asyncio
import datetime
import json
import os
import struct
import sys
import time
from dataclasses import asdict, dataclass
from typing import Optional

import aiohttp

sys.path.insert(0, ".")
try:
    from aidot.client import AidotClient
    from aidot.device_client import DeviceClient
except ImportError as e:
    print(f"ERROR: Cannot import aidot — run from the repo root.\n  {e}")
    sys.exit(1)

try:
    from aidot.credentials import load_credentials as _load_credentials
except ImportError:
    _load_credentials = None
_TS = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")


# ── Result tracking ─────────────────────────────────────────────────────────── #

@dataclass
class Result:
    camera: str   # "" for infrastructure tests
    test: str
    status: str   # PASS | FAIL | SKIP | WARN
    detail: str
    elapsed: float


_results: list[Result] = []
_stream_files: list[tuple[str, str]] = []   # (camera_name, file_path)


def _record(camera: str, test: str, status: str, detail: str, elapsed: float) -> None:
    _results.append(Result(camera, test, status, detail, elapsed))
    sym = {"PASS": "✓", "FAIL": "✗", "SKIP": "~", "WARN": "!"}[status]
    indent = "  " if camera else ""
    print(f"{indent}{sym}  {test:<48} {detail}  ({elapsed:.1f}s)")


async def _t(camera: str, name: str, coro, timeout: float = 30) -> str:
    """Run a test coroutine, record the result, return the status string."""
    t0 = time.monotonic()
    try:
        status, detail = await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError:
        status, detail = "FAIL", f"timeout after {timeout:.0f}s"
    except Exception as exc:
        status, detail = "FAIL", f"{type(exc).__name__}: {str(exc)[:120]}"
    _record(camera, name, status, detail, time.monotonic() - t0)
    return status


# ── Infrastructure tests ────────────────────────────────────────────────────── #

async def _test_login(client: AidotClient):
    info = await client.async_post_login()
    uid = info.get("id") or info.get("userId") or "?"
    if not info.get("mqttPassword"):
        return "WARN", f"userId={uid} — mqttPassword missing (MQTT controls will fail)"
    return "PASS", f"userId={uid}  region={client._region}  mqttPassword=present"


async def _test_device_list(client: AidotClient):
    result = await client.async_get_all_device()
    devices = result.get("device_list") or []
    if not devices:
        return "FAIL", "no devices returned"
    models = ", ".join(sorted({d.get("modelId", "?") for d in devices}))
    return "PASS", f"{len(devices)} device(s)  models: {models}"


async def _test_lan_discovery(client: AidotClient, cameras: list):
    from aidot.discover import Discover as _Discover
    disc = _Discover(client.login_info, None)
    await disc.send_broadcast()
    await asyncio.sleep(2.5)
    await disc.send_broadcast()
    await asyncio.sleep(2.5)
    disc.close()
    found = {}
    for cam in cameras:
        ip = disc.discovered_device.get(cam.get("id"))
        if ip:
            found[cam["id"]] = ip
    detail = f"{len(found)}/{len(cameras)} cameras on LAN"
    for cam in cameras:
        if cam["id"] in found:
            detail += f"  {cam.get('name','?')}={found[cam['id']]}"
    return ("PASS" if found else "WARN"), detail, found


# ── Per-camera tests — Cloud APIs ───────────────────────────────────────────── #

async def _test_user_info(dc: DeviceClient, all_ids: list):
    info = await dc.async_get_device_user_info(all_device_ids=all_ids)
    if not info:
        return "FAIL", "no data (server returned empty for this device)"
    uid = info.get("userId") or info.get("userUuid") or "?"
    ip  = info.get("ip") or info.get("ipAddress") or "not provided"
    return "PASS", f"userId={uid}  ip={ip}"


async def _test_thumbnail(dc: DeviceClient, http: aiohttp.ClientSession):
    url = await dc.async_get_latest_thumbnail()
    if not url:
        return "SKIP", "no event photos (no cloud plan or no recent events)"
    async with http.get(url, timeout=aiohttp.ClientTimeout(total=15)) as r:
        data = await r.read()
    if r.status != 200 or not data:
        return "FAIL", f"HTTP {r.status}  {len(data)} bytes"
    return "PASS", f"{len(data):,} bytes  {r.content_type}"


async def _test_recordings(dc: DeviceClient):
    now_ms = int(time.time() * 1000)
    clips = await dc.async_get_cloud_recordings(now_ms - 86_400_000, now_ms)
    if clips is None:
        return "FAIL", "API call failed"
    if not clips:
        return "SKIP", "no recordings in past 24 h (no cloud plan or quiet period)"
    # eventRecordingList returns "begin"/"end" timestamps in milliseconds
    t0 = time.strftime("%H:%M", time.localtime((clips[0].get("begin") or clips[0].get("eventTime", 0)) / 1000))
    t1 = time.strftime("%H:%M", time.localtime((clips[-1].get("begin") or clips[-1].get("eventTime", 0)) / 1000))
    return "PASS", f"{len(clips)} clip(s)  {t0} → {t1}"


# ── Per-camera tests — MQTT reads ───────────────────────────────────────────── #

async def _test_attributes(dc: DeviceClient):
    attrs = await dc.async_get_camera_attributes(timeout=10.0)
    if attrs is None:
        return "FAIL", "no response — MQTT timeout or camera offline"
    if not isinstance(attrs, dict) or not attrs:
        return "WARN", "response was empty"
    sample = list(attrs.keys())[:6]
    return "PASS", f"{len(attrs)} attrs  e.g. {sample}"


# ── Per-camera tests — Controls ─────────────────────────────────────────────── #

async def _toggle(dc, label, set_fn_true, set_fn_false):
    """Toggle a control on then off; return (status, detail)."""
    ok_on  = await asyncio.wait_for(set_fn_true(),  timeout=12)
    await asyncio.sleep(0.4)
    ok_off = await asyncio.wait_for(set_fn_false(), timeout=12)
    if ok_on and ok_off:
        return "PASS", "on→ack  off→ack"
    parts = (["on: no ack"] if not ok_on else []) + (["off: no ack"] if not ok_off else [])
    return "WARN", "  ".join(parts)


async def _test_motion_detection(dc: DeviceClient):
    return await _toggle(dc, "motion_detection",
                         lambda: dc.async_set_motion_detection(True),
                         lambda: dc.async_set_motion_detection(False))


async def _test_status_led(dc: DeviceClient):
    return await _toggle(dc, "status_led",
                         lambda: dc.async_set_status_led(True),
                         lambda: dc.async_set_status_led(False))


async def _test_microphone(dc: DeviceClient):
    return await _toggle(dc, "microphone",
                         lambda: dc.async_set_microphone(True),
                         lambda: dc.async_set_microphone(False))


async def _test_night_vision(dc: DeviceClient):
    # on → auto (two confirmed modes)
    ok_on   = await asyncio.wait_for(dc.async_set_night_vision("on"),   timeout=12)
    await asyncio.sleep(0.4)
    ok_auto = await asyncio.wait_for(dc.async_set_night_vision("auto"), timeout=12)
    if ok_on and ok_auto:
        return "PASS", "on→ack  auto→ack"
    parts = (["on: no ack"] if not ok_on else []) + (["auto: no ack"] if not ok_auto else [])
    return "WARN", "  ".join(parts)


async def _test_motion_sensitivity(dc: DeviceClient):
    # Set to 3 (middle); we don't know/restore the original value but 3 is safe.
    ok = await asyncio.wait_for(dc.async_set_motion_sensitivity(3), timeout=12)
    return ("PASS", "sensitivity=3 → ack") if ok else ("WARN", "no ack")


async def _test_ir_light(dc: DeviceClient):
    return await _toggle(dc, "ir_light",
                         lambda: dc.async_set_ir_light(True),
                         lambda: dc.async_set_ir_light(False))


async def _test_ptz_tracking(dc: DeviceClient):
    return await _toggle(dc, "ptz_tracking",
                         lambda: dc.async_set_ptz_tracking(True),
                         lambda: dc.async_set_ptz_tracking(False))


async def _test_floodlight(dc: DeviceClient):
    return await _toggle(dc, "floodlight",
                         lambda: dc.async_set_floodlight(True),
                         lambda: dc.async_set_floodlight(False))


# ── Per-camera tests — Streaming ────────────────────────────────────────────── #

async def _test_stream(dc: DeviceClient, cam_name: str, secs: int, ptz: bool):
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in cam_name)
    out_path  = f"/tmp/beta-{safe_name}-{_TS}.ts"

    video_frames = [0]
    audio_frames = [0]
    ptz_detail   = [None]

    def on_frame(f):
        if getattr(f, "is_video", False):
            video_frames[0] += 1
        elif getattr(f, "is_audio", False):
            audio_frames[0] += 1

    # A000088 (DTLS) cameras intermittently fail ICE/DTLS (~50%/attempt — the
    # camera's ICE-lite exposes two candidate pairs and aioice may bind DTLS to
    # the wrong port).  Each attempt is independent, so retry as the CLI/HA paths
    # do (test_camera.py --webrtc-retries), giving a clean validation signal.
    session = None
    _last_exc = None
    for _attempt in range(3):
        try:
            session = await asyncio.wait_for(
                dc.async_open_webrtc_stream(
                    on_frame=on_frame,
                    output_path=out_path,
                    max_seconds=secs,
                    timeout=30,
                    status_callback=lambda _: None,
                ),
                timeout=35,
            )
            break
        except Exception as exc:
            _last_exc = exc
            if _attempt < 2:
                await asyncio.sleep(2.0)
    if session is None:
        raise _last_exc if _last_exc else RuntimeError("stream open failed")

    # Wait for stream to produce frames before PTZ
    await asyncio.sleep(min(secs, 4))

    if ptz and video_frames[0] > 0:
        try:
            await dc.async_ptz_move("up",    speed=4); await asyncio.sleep(1.2)
            await dc.async_ptz_stop();                 await asyncio.sleep(0.3)
            await dc.async_ptz_move("right", speed=4); await asyncio.sleep(1.2)
            await dc.async_ptz_stop()
            ptz_detail[0] = "PTZ up+right+stop ok"
        except Exception as exc:
            ptz_detail[0] = f"PTZ failed: {exc}"

    wait_fn = getattr(session, "wait_done", None)
    # SDES cameras complete an SCTP/DCEP handshake inside the bridge thread AFTER
    # the session is returned.  That handshake can take 20-35 s on a busy LAN.
    # Give wait_done enough headroom: secs (output) + 50 s (SCTP + analysis).
    _wait_budget = secs + 50
    try:
        if wait_fn:
            await asyncio.wait_for(wait_fn(), timeout=_wait_budget)
        else:
            await asyncio.sleep(max(0, secs - 4))
    except (asyncio.TimeoutError, asyncio.CancelledError):
        pass
    finally:
        await session.stop()

    file_size = os.path.getsize(out_path) if os.path.exists(out_path) else 0

    # SDES cameras write directly to ffmpeg — on_frame callback is never called, so
    # video_frames[0] stays 0.  Use file_size as primary indicator.
    if file_size > 0:
        status = "PASS"
        frame_info = (f"{video_frames[0]} video + {audio_frames[0]} audio frames  "
                      if video_frames[0] > 0 else "")
        detail = f"{frame_info}file={file_size//1024:,} KB → {out_path}"
        _stream_files.append((cam_name, out_path))
    elif video_frames[0] >= 5:
        status = "WARN"
        detail = f"{video_frames[0]} video + {audio_frames[0]} audio frames but output file is empty"
    else:
        status = "FAIL"
        detail = f"only {video_frames[0]} video frames in {secs}s (stream didn't start?)"

    if ptz_detail[0]:
        detail += f"  [{ptz_detail[0]}]"
    return status, detail


async def _test_snapshot(dc: DeviceClient, cam_name: str):
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in cam_name)
    path = f"/tmp/beta-snap-{safe}-{_TS}.jpg"
    ok   = await asyncio.wait_for(dc.async_snapshot(path, timeout=45), timeout=145)
    if ok and os.path.exists(path):
        size = os.path.getsize(path)
        return "PASS", f"{size:,} bytes → {path}"
    return "FAIL", "no keyframe captured within timeout"


# ── Per-camera tests — Cloud playback ──────────────────────────────────────── #

async def _test_playback(dc: DeviceClient):
    """Verify cloud playback URL via getEventVideoUrl (HTTP-only, no MQTT/TCP)."""
    now_ms = int(time.time() * 1000)
    clips  = await dc.async_get_cloud_recordings(now_ms - 7 * 86_400_000, now_ms)
    if not clips:
        return "SKIP", "no recordings in last 7 days"

    clip = clips[0]
    event_uuid = clip.get("eventUuid")
    if not event_uuid:
        return "SKIP", f"no eventUuid in recording item (keys: {sorted(clip.keys())})"

    url = await dc.async_get_event_video_url(event_uuid)
    if not url:
        return "FAIL", "getEventVideoUrl returned no URL"

    # Confirm the URL looks like a CDN video link
    is_mp4  = ".mp4" in url.lower()
    is_m3u8 = ".m3u8" in url.lower()
    kind    = "mp4" if is_mp4 else ("m3u8" if is_m3u8 else "url")
    sta_ms  = clip.get("begin") or clip.get("eventTime") or 0
    dur_s   = ((clip.get("end") or (sta_ms + 30_000)) - sta_ms) // 1000
    return "PASS", f"{kind} {dur_s}s clip → {url[:80]}…" if len(url) > 80 else f"{kind} {dur_s}s clip → {url}"


# ── Per-camera tests — LAN probe ────────────────────────────────────────────── #

async def _test_lan_probe(dc: DeviceClient):
    from aidot.aes_utils import aes_ecb_encrypt_str_key, aes_ecb_decrypt_str_key

    cam_ip = dc._ip_address
    if not cam_ip:
        return "SKIP", "no LAN IP (camera not found by UDP discovery)"

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(cam_ip, 10000), timeout=5
        )
    except asyncio.TimeoutError:
        return "SKIP", f"{cam_ip}:10000 — connect timeout (port not open)"
    except ConnectionRefusedError:
        return "SKIP", f"{cam_ip}:10000 — connection refused"
    except OSError as e:
        return "FAIL", f"connect error: {e}"

    import json as _json

    def _pkt(obj, key):
        body = _json.dumps(obj).encode()
        if key is not None:
            body = aes_ecb_encrypt_str_key(body, key) if isinstance(key, str) else __import__("aidot.aes_utils", fromlist=["aes_encrypt"]).aes_encrypt(body, key)
        import struct as _s
        return _s.pack(">HHI", 0x1EED, 1, len(body)) + body

    def _parse(data, key):
        if len(data) < 8:
            return None
        import struct as _s
        magic, _, blen = _s.unpack(">HHI", data[:8])
        if magic != 0x1EED:
            return None
        body = data[8:8 + blen]
        if key is not None:
            try:
                body = (aes_ecb_decrypt_str_key(body, key).encode()
                        if isinstance(key, str) else body)
            except Exception:
                return None
        try:
            return _json.loads(body)
        except Exception:
            return None

    login_msg = {
        "protocolVer": "2.0.0", "service": "device", "method": "loginReq",
        "seq": str(int(time.time() * 1000))[-9:],
        "srcAddr": f"0.{dc.user_id}", "deviceId": dc.device_id,
        "tst": int(time.time() * 1000),
        "payload": {
            "userId": str(dc.user_id), "password": dc.password or "",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"), "ascNumber": 1,
        },
    }

    # Try key candidates: per-device aesKey (str), then broadcast key, then no enc
    candidates = []
    if getattr(dc, "aes_key", None):
        candidates.append(("aesKey(device)", dc.aes_key))
    candidates.append(("aesKey(broadcast)", "T54uednca587"))
    candidates.append(("no-enc", None))

    result_status, result_detail = "FAIL", "all key candidates rejected"
    for label, key in candidates:
        try:
            writer.write(_pkt(login_msg, key))
            await writer.drain()
            raw = await asyncio.wait_for(reader.read(4096), timeout=4)
        except asyncio.TimeoutError:
            continue
        except Exception:
            break
        resp = _parse(raw, key)
        if resp:
            code = (resp.get("ack") or {}).get("code")
            if code == 200:
                result_status, result_detail = "PASS", f"TCP:10000 login ok with {label}"
            else:
                result_status = "WARN"
                result_detail = f"connected, loginReq code={code} with {label}"
            break

    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    return result_status, result_detail


# ── Helpers ─────────────────────────────────────────────────────────────────── #

def _find_cameras(devices: list) -> list:
    out = []
    for dev in devices:
        product    = dev.get("product") or {}
        modules    = product.get("serviceModules") or []
        identities = [m.get("identity", "") for m in modules]
        model      = (dev.get("modelId") or "").upper()
        if (any("camera" in i.lower() or "ipc" in i.lower() for i in identities)
                or "CAM" in model or "IPC" in model):
            out.append(dev)
    return out


def _is_ptz(cam: dict) -> bool:
    return "A001064" in (cam.get("modelId") or "").upper()


def _proto(dc: DeviceClient) -> str:
    return "SDES" if dc.is_sdes_camera else "DTLS"


# ── Main ─────────────────────────────────────────────────────────────────────── #

async def run(args: argparse.Namespace) -> None:
    print("\n" + "=" * 66)
    print("  AiDot Camera Beta Test Suite  —  " + _TS)
    print("=" * 66)

    async with aiohttp.ClientSession() as http:
        client = AidotClient(
            session=http,
            country_code=args.country,
            username=args.username,
            password=args.password,
        )

        # ── Phase 1: Infrastructure ──────────────────────────────────────── #
        print("\n── Infrastructure ──────────────────────────────────────────────")

        status = await _t("", "Login", _test_login(client), timeout=20)
        if status == "FAIL":
            print("  Cannot continue without login."); return

        status = await _t("", "Device list", _test_device_list(client), timeout=20)
        if status == "FAIL":
            return

        all_devices = (await client.async_get_all_device()).get("device_list") or []
        cameras     = _find_cameras(all_devices)
        all_cam_ids = [c["id"] for c in cameras if c.get("id")]
        # batchGetDeviceUserInfo requires all account device IDs (not just cameras)
        # — the server returns empty when only camera IDs are sent.
        all_device_ids = [d["id"] for d in all_devices if d.get("id")]

        if not cameras:
            print("  No cameras detected."); return

        if args.device:
            q = args.device.strip().lower()
            cameras = ([c for c in cameras if c.get("id") == args.device]
                       or [c for c in cameras if q in (c.get("name") or "").lower()])
            if not cameras:
                print(f"  --device {args.device!r} not found."); return

        disc_ips: dict = {}
        t0 = time.monotonic()
        try:
            status, detail, disc_ips = await asyncio.wait_for(
                _test_lan_discovery(client, cameras), timeout=14
            )
        except asyncio.TimeoutError:
            status, detail = "WARN", "discovery timeout"
        except Exception as e:
            status, detail = "WARN", f"discovery error: {e}"
        _record("", "LAN discovery", status, detail, time.monotonic() - t0)

        # ── Phase 2: Per-camera ──────────────────────────────────────────── #
        for cam in cameras:
            name  = cam.get("name") or cam.get("id", "?")
            model = cam.get("modelId") or "?"
            dc    = client.get_device_client(cam)
            dc._all_device_ids = all_device_ids
            if cam.get("id") in disc_ips:
                dc._ip_address = disc_ips[cam["id"]]

            print(f"\n── {name}  [{model}  {_proto(dc)}]"
                  + ("  PTZ" if _is_ptz(cam) else "")
                  + " ──────────────────────────────────")

            # A: Cloud APIs
            print("  Cloud APIs")
            await _t(name, "  batchGetDeviceUserInfo",
                     _test_user_info(dc, all_device_ids), timeout=20)
            await _t(name, "  Thumbnail",
                     _test_thumbnail(dc, http), timeout=20)
            await _t(name, "  Cloud recordings",
                     _test_recordings(dc), timeout=20)

            # B: MQTT attribute read
            print("  MQTT")
            await _t(name, "  Camera attributes",
                     _test_attributes(dc), timeout=20)

            # C: Controls
            if not args.no_controls:
                print("  Controls")
                if not args.nighttime:
                    await _t(name, "  Motion detection",
                             _test_motion_detection(dc), timeout=30)
                await _t(name, "  Status LED",
                         _test_status_led(dc), timeout=30)
                await _t(name, "  Microphone",
                         _test_microphone(dc), timeout=30)
                if not args.nighttime:
                    await _t(name, "  Night vision (on→auto)",
                             _test_night_vision(dc), timeout=30)
                await _t(name, "  Motion sensitivity (→3)",
                         _test_motion_sensitivity(dc), timeout=20)
                if not args.nighttime:
                    await _t(name, "  IR light",
                             _test_ir_light(dc), timeout=30)
                await _t(name, "  PTZ tracking",
                         _test_ptz_tracking(dc), timeout=30)
                if not args.nighttime:
                    await _t(name, "  Floodlight",
                             _test_floodlight(dc), timeout=30)

            # D: Streaming
            if not args.no_stream:
                print("  Streaming")
                is_dtls = not dc.is_sdes_camera
                stream_ok = True
                if is_dtls:
                    try:
                        import aiortc  # noqa: F401
                    except ImportError:
                        _record(name, "  WebRTC stream (DTLS)", "SKIP",
                                "aiortc not installed — pip install aiortc", 0)
                        _record(name, "  Snapshot", "SKIP",
                                "requires aiortc for DTLS cameras", 0)
                        stream_ok = False

                if stream_ok:
                    await _t(name, f"  WebRTC stream ({_proto(dc)})",
                             _test_stream(dc, name, args.stream_seconds, _is_ptz(cam)),
                             timeout=args.stream_seconds + 110)
                    await _t(name, "  Snapshot",
                             _test_snapshot(dc, name), timeout=160)

            # E: Cloud playback (only if we found recordings)
            rec_results = [r for r in _results
                           if r.camera == name and r.test.strip() == "Cloud recordings"
                           and r.status == "PASS"]
            if rec_results:
                print("  Cloud playback")
                await _t(name, "  Recording playback (5s)",
                         _test_playback(dc), timeout=40)

            # F: LAN probe
            print("  LAN")
            await _t(name, "  TCP:10000 LAN probe",
                     _test_lan_probe(dc), timeout=15)

    # ── Phase 3: Summary ─────────────────────────────────────────────────── #
    print("\n" + "=" * 66)
    print("  RESULTS SUMMARY")
    print("=" * 66)

    infra   = [r for r in _results if not r.camera]
    by_cam  = {}
    for r in _results:
        if r.camera:
            by_cam.setdefault(r.camera, []).append(r)

    infra_ok = all(r.status in ("PASS", "SKIP", "WARN") for r in infra)
    print(f"\n  Infrastructure : {'OK' if infra_ok else 'ISSUES'}")

    cam_pass = cam_warn = cam_fail = 0
    for cam_name, rlist in by_cam.items():
        fails = [r for r in rlist if r.status == "FAIL"]
        warns = [r for r in rlist if r.status == "WARN"]
        if fails:
            cam_fail += 1; flag = "✗ FAIL"
        elif warns:
            cam_warn += 1; flag = "! WARN"
        else:
            cam_pass += 1; flag = "✓ PASS"
        print(f"  {flag}  {cam_name}")
        for f in fails:
            print(f"       FAIL: {f.test.strip()} — {f.detail}")
        for w in warns:
            print(f"       WARN: {w.test.strip()} — {w.detail}")

    total = cam_pass + cam_warn + cam_fail
    print(f"\n  Cameras : {cam_pass}/{total} all-pass  "
          f"{cam_warn} warn  {cam_fail} fail")
    tally = {s: sum(1 for r in _results if r.status == s)
             for s in ("PASS", "FAIL", "SKIP", "WARN")}
    print(f"  Tests   : {sum(tally.values())} total  "
          + "  ".join(f"{v} {k}" for k, v in tally.items()))

    if _stream_files:
        print("\n  Stream output files (open in VLC for manual review):")
        for cam_name, path in _stream_files:
            size = os.path.getsize(path) // 1024 if os.path.exists(path) else 0
            print(f"    {cam_name:<30}  {size:,} KB  →  {path}")
            print(f"    vlc {path}")

    print()


# ── CLI ─────────────────────────────────────────────────────────────────────── #

def main() -> None:
    parser = argparse.ArgumentParser(
        description="AiDot camera beta readiness test suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("-u", "--username",  default=None)
    parser.add_argument("-P", "--password",  default=None)
    parser.add_argument("--country",         default=None)
    parser.add_argument("-c", "--credentials", metavar="PATH", default=None,
                        help="Path prefix for encrypted credentials "
                             "(default: ~/.config/aidot/credentials)")
    parser.add_argument("-d", "--device",    metavar="NAME_OR_ID", default=None,
                        help="Test only this camera (partial name match)")
    parser.add_argument("--no-stream",   action="store_true",
                        help="Skip WebRTC streaming tests (~2 min faster)")
    parser.add_argument("--no-controls", action="store_true",
                        help="Skip device control write tests (read-only mode)")
    parser.add_argument("--nighttime", action="store_true",
                        help="Skip visually/audibly disruptive controls: "
                             "floodlight, IR light, night vision, motion detection")
    parser.add_argument("--stream-seconds", type=int, default=10,
                        help="WebRTC stream duration per camera (default: 10)")
    parser.add_argument("-L", "--log-file", metavar="PATH",
                        help="Write full output + JSON results to PATH")
    args = parser.parse_args()

    if not (args.username and args.password):
        if _load_credentials is None:
            parser.error("aidot.credentials not available — provide --username/--password")
        try:
            creds = _load_credentials(args.credentials)
        except Exception as exc:
            parser.error(
                f"Could not load credentials: {exc}\n"
                "  Set AIDOT_USERNAME/AIDOT_PASSWORD env vars or run "
                "test_camera.py --save-credentials."
            )
        args.username = args.username or creds["username"]
        args.password = args.password or creds["password"]
        if args.country is None:
            args.country = creds.get("country", "US")
    if args.country is None:
        args.country = "US"

    log_fh = None
    if args.log_file:
        log_fh = open(args.log_file, "w", encoding="utf-8", buffering=1)
        real_stdout = sys.stdout

        class _Tee:
            def write(self, s): real_stdout.write(s); log_fh.write(s)
            def flush(self):    real_stdout.flush();  log_fh.flush()
            def fileno(self):   return real_stdout.fileno()
            isatty = lambda self: False

        sys.stdout = _Tee()

    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\nInterrupted.")
    finally:
        if log_fh:
            log_fh.write("\n\n=== JSON RESULTS ===\n")
            log_fh.write(json.dumps([asdict(r) for r in _results], indent=2))
            log_fh.write("\n")
            sys.stdout = real_stdout
            log_fh.close()
            print(f"Log + JSON written to {args.log_file}")


if __name__ == "__main__":
    main()
