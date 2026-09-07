"""Camera / WebRTC / SDES extensions, layered additively over the core DeviceClient."""

import json
import logging
from urllib.parse import urlparse
import os
import random
import time
import asyncio
import warnings
from typing import TYPE_CHECKING, Any, Callable, List, Optional, Union

if TYPE_CHECKING:  # annotation only; keeps av off the import path
    from av import VideoFrame as AvVideoFrame

from ..exceptions import AidotCameraBusy, AidotCameraNoMedia, AidotCameraNotReady
from ..const import APP_ID as _AIDOT_APP_ID
from ..const import (
    LOGIN_INFO_MQTT_PASSWORD_KEYS,
    LOGIN_INFO_PERSISTENT_MQTT_KEY,
    LOGIN_INFO_PERSISTENT_MQTT_LOCK_KEY,
)

# Wire/protocol constants live in constants.py; re-imported here so all
# in-module references (and any external importers) keep resolving.
from .constants import (
    _LEEDARSON_APP_ID,
    _LIVE_PLAY_NOT_READY,
    _SMARTHOME_URL_TEMPLATE,  # noqa: F401 - re-exported for back-compat; reads go through smarthome_base()
    GETSTREAMCTRL_CMD,  # noqa: F401 - re-exported for back-compat (public pair; unused in-module)
    SDES_SPEAKERSTART_DELAY,  # noqa: F401 - used by the sdes_open mixin; kept re-exported
    aidot_api_base,
    smarthome_base,
)
from .constants import (  # noqa: F401 - re-exported for device_client / back-compat
    TALK_PCM_FRAME_BYTES,
    TALK_PCM_RATE,
)
from .models import (  # re-exported: data models split into models.py
    CameraDeviceInformation,
    CameraStatusData,
    VideoFrame,
    _as_int,
)
from .tutk import TutkStreamSession  # re-exported (split into tutk.py)
from .playback import (  # re-exported (split into playback.py)
    CloudPlaybackSession,
    LiveStreamSession,  # noqa: F401 - back-compat re-export (unused in-module)
)
from .webrtc import WebRTCSession  # re-exported (split into webrtc.py)
from .sdes import SdesSession  # re-exported (split into sdes.py); also the SDES return type
from .controls import _CameraControlsMixin
from .sd_listing import _CameraSdMixin
from .webrtc_open import _WebRTCOpenMixin
from .sdes_open import (
    _SdesOpenMixin,
    _sdes_max_session_s,
    _session_cap_reached,
)
from .protocol import (  # noqa: F401 - used here and/or by the webrtc_open mixin; kept re-exported for back-compat
    _mqtt_timestamp,
    ReconnectPacer,
    _build_stun_binding_success_response,
    _terminal_webrtc_ack,
    _install_highport_nomination_patch,
    _compress_sdp_for_camera,
    _make_talk_audio_track,
    _webrtc_consume_video,
    _write_text_file,
    _make_sdp_tempfile,
    _terminate_proc,
    _extract_param_sets_from_rtp,
    _build_sprop,
    _load_sprop,
    _save_sprop,
    _inject_sprop,
    _sdes_serve_port,
    sdes_ice_teardown,
    _serve_host,
    _warn_lan_serve,
    _ServeRelay,
    _rewrite_serve_port,
    _grab_free_port,
    _tcp_table_has_established_on_port,
    _idle_release_due,
    _DirectTsServer,
    _direct_serve_enabled,
    _serve_port,
    _dtls_av_mux_run,
    _h264_has_keyframe,
    _mqtt_session_sync,
    _mqtt_session,
    _mqtt_session_with_status,
    _mqtt_get_playback_server_info,
    _ip_looks_ascii_garbled,
    _normalize_bundle_ice_credentials,
    _reorder_m_section_ice_attrs,
    _filter_sdp_candidates,
    _dedup_bundle_candidates,
    _upgrade_sctp,
    _sdp_transport,
)
from .protocol import (  # noqa: F401 - re-exported for device_client / back-compat
    _CAMERA_ALARM_TYPES,
    _WEBRTC_TERMINAL_ACK_CODES,
    _highport_nomination_decision,
    _parse_alarm_event,
)

_LOGGER = logging.getLogger(__name__)

# Offline keepalive pause (see CameraMixin._backoff_or_offline_pause): while the
# cloud explicitly reports a device offline, failed-open retries re-check the
# flag every RECHECK seconds and only probe a real open every PROBE seconds,
# instead of consuming an open-gate slot on the normal reconnect cadence.
_OFFLINE_RECHECK_S = float(os.environ.get("AIDOT_OFFLINE_RECHECK_S", "30"))
_OFFLINE_PROBE_S = float(os.environ.get("AIDOT_OFFLINE_PROBE_S", "600"))

# DTLS serve loop slow-probe: an idle-but-cloud-online camera (asleep, wedged
# firmware, ...) never trips the offline pause above (the cloud keeps reporting
# it reachable), so its failed opens would otherwise retry FOREVER at the
# pacer's 300s cap - burning a 30s open timeout every attempt and dripping a
# WARNING each time (see _open_fail_logger).  After
# AIDOT_DTLS_SLOW_PROBE_THRESHOLD consecutive open failures (keyed on the
# ReconnectPacer's attempt count - see _in_slow_probe / _probe_interval below -
# NOT the cloud-offline flag, which this case never sets), the loop widens its
# retry interval to AIDOT_DTLS_SLOW_PROBE_INTERVAL_S and downgrades the
# per-attempt WARNING to a periodic INFO summary (_should_log_slow_probe).
# Resets the instant an open succeeds, via the same ReconnectPacer.reset() the
# loop already calls on success (attempt -> 0, so _in_slow_probe is false again
# with no separate state to clear).
_SLOW_PROBE_THRESHOLD = int(os.environ.get("AIDOT_DTLS_SLOW_PROBE_THRESHOLD", "5"))
_SLOW_PROBE_INTERVAL_S = float(os.environ.get("AIDOT_DTLS_SLOW_PROBE_INTERVAL_S", "600"))
_SLOW_PROBE_LOG_EVERY = int(os.environ.get("AIDOT_DTLS_SLOW_PROBE_LOG_EVERY", "6"))
# Sleep increment for the slow-probe wait: never one blocking
# asyncio.sleep(interval) call, so stop() is not delayed by up to 10 minutes.
_SLOW_PROBE_SLEEP_CHUNK_S = float(os.environ.get("AIDOT_DTLS_SLOW_PROBE_CHUNK_S", "5"))


def _parse_env_float(name: str, default: float) -> float:
    """Parse a float env var, falling back to ``default`` on any missing or
    malformed value (matches the try/except idiom used by
    _get_webrtc_open_gate / _get_stream_slots below for AIDOT_MAX_CONCURRENT_*
    rather than raising at import time)."""
    try:
        return float(os.environ.get(name, str(default)))
    except (ValueError, TypeError):
        return default


# DTLS serve-open timeout: how long a single async_open_webrtc_stream() call
# in the serve loop is allowed to take before giving up. Tunable via
# AIDOT_DTLS_SERVE_OPEN_TIMEOUT_S for operators who want faster-failing
# retries against a known-dead camera.
#
# 75s, not the impl default of 30s. At 30s this cut the offer-resend short:
# _resend_webrtcreq (webrtc_open.py:2337) re-publishes the same offer at 15s
# and again at 30s, and the second resend died with the attempt that issued
# it. Measured on the live fleet 2026-08-18 16:35-17:29, 118 serve-loop opens:
# 40 answered inside 30s, 65 never answered, and 13 answered LATE at 30.7s to
# 99.5s - every one of them code=200, i.e. the camera accepted the offer and
# our timeout simply expired first. Ten of those thirteen land inside 75s, on
# the peer connection that made the offer, so the answer is directly usable.
#
# The cost is real: async_open_webrtc_stream holds the global
# _WEBRTC_OPEN_GATE (cap AIDOT_MAX_CONCURRENT_OPENS, default 2) for the whole
# open, so a slow open makes other cameras wait longer. It is worth paying
# because two thirds of opens were failing, so the gate was already being
# spent almost entirely on attempts that could not succeed.
_DTLS_SERVE_OPEN_TIMEOUT_S = _parse_env_float("AIDOT_DTLS_SERVE_OPEN_TIMEOUT_S", 75.0)

# ICE gets its OWN budget, and deliberately not the one above. The open runs two
# SEQUENTIAL waits - signalling (_init_deadline, webrtc_open.py:2467) then ICE
# (webrtc_open.py:3734) - and both used to read `timeout`, so raising the open
# timeout to 75s doubled the worst case to ~150s while holding the global open
# gate (cap AIDOT_MAX_CONCURRENT_OPENS, default 2).
#
# Nothing measured asked for that. Every late answer (30.7-99.5s, all code=200)
# was signalling latency. And ice_wait_timeout's own docstring says why a long
# ICE wait is actively wrong: 45s "is past the ~30 s deadline Home Assistant's
# stream worker allows, which is the failure this project already learned the
# hard way". So signalling gets the long wait; ICE keeps the 30s it always had.
_DTLS_SERVE_ICE_WAIT_S = _parse_env_float("AIDOT_DTLS_SERVE_ICE_WAIT_S", 30.0)

# Strong refs to fire-and-forget tasks: asyncio only keeps weak refs, so a
# discarded task can be garbage-collected mid-flight. Discarded on completion.
_BG_TASKS: set = set()

# Minimum gap between MQTT credential refetches after the broker refused one.
# One rotation is normal (another login happened); a second refusal that fast
# means refetching is not helping, so back off rather than loop.
_MQTT_CREDENTIAL_REFETCH_FLOOR = 30.0

# How often the "is anyone watching" question may actually reach go2rtc. The
# watchdog loops tick twice a second; asking that often opens a fresh HTTP
# session per camera per tick against the service that also has to serve the
# video. Idle release is measured in minutes, so seconds of staleness here costs
# nothing.
_VIEWER_CHECK_INTERVAL_S = 10.0


def _spawn_bg(coro):
    _t = asyncio.ensure_future(coro)
    _BG_TASKS.add(_t)

    def _done(task):
        _BG_TASKS.discard(task)
        # Retrieve the exception so a failing background task doesn't surface as
        # an unhandled "Task exception was never retrieved" at GC time; log it.
        if not task.cancelled():
            exc = task.exception()
            if exc is not None:
                _LOGGER.debug("aidot background task failed: %r", exc, exc_info=exc)

    _t.add_done_callback(_done)
    return _t


def _mqtt_publish_delivered(status) -> bool:
    """True if an MQTT command reached the broker (connection up, no error).

    Distinguishes a genuine fire-and-forget publish (broker connected, the device
    simply doesn't ACK) from a refused/failed connection - which returns an empty
    message list too, and must NOT be reported as "sent".
    """
    if not status:
        return True  # no status available: preserve prior best-effort behavior
    if status.get("error"):
        return False
    return status.get("connected", True) is not False


def _retry_policy(failure_kind: str, burst_attempt: int, *,
                  burst_delay: float = 3.0, burst_max: int = 4,
                  base_gate: float = 15.0) -> "tuple[float, bool]":
    """Return (delay_seconds, bypass_open_gate) for the DTLS serve retry.

    A clean 'not_ready' decline (camera awake but encoder still cold - a DC-only
    WebRTC answer) gets a bounded fast burst (burst_delay x burst_max) that
    bypasses the 15s inter-attempt gate, then falls back to the normal gate so a
    persistently-declining camera is not hammered.  Every other failure keeps
    the unchanged 15s behaviour."""
    if failure_kind == "not_ready" and burst_attempt <= burst_max:
        return (burst_delay, True)
    return (base_gate, False)


def _open_gate_delay(last_open_at: float, now: float, open_gate: float) -> float:
    """Seconds to wait before the next open to honour the inter-attempt gate.

    The DTLS serve loop spaces OPEN attempts >= open_gate apart, keyed to the
    PREVIOUS open's start (`last_open_at`).  Returns 0 when there is no prior
    open (`last_open_at` is the 0.0 sentinel - monotonic time is never 0) or the
    gate has already elapsed (e.g. after a long healthy session that just died,
    so it reopens immediately), else the remaining gate time.  This is the sole
    reconnect-spacing mechanism: a fast death still gets spaced a full gate from
    its open-start (anti-hammer), so no separate post-death delay is needed."""
    if not last_open_at:
        return 0.0
    remaining = open_gate - (now - last_open_at)
    return remaining if remaining > 0 else 0.0


def _in_slow_probe(attempt: int, threshold: int) -> bool:
    """True once `attempt` consecutive DTLS open failures have reached
    `threshold`: the serve loop should stop hammering an idle-but-cloud-online
    camera at the pacer's normal cadence and fall back to a slow probe."""
    return attempt >= threshold


#: RTP timestamps are 32 bits wide.
_TS_MODULO = 2 ** 32

#: A forward step larger than this is not a frame interval. Half the counter is
#: about 13 hours of a 90 kHz clock, so nothing legitimate comes near it.
_TS_BOGUS_UNWRAP = 2 ** 31


def _unwrap_state() -> dict:
    """Fresh timestamp-correction state for one video tap."""
    return {"prev_raw": None, "offset": 0}


def _correct_ts(state: dict, raw: int) -> int:
    """Undo unwraps that should not have happened, cumulatively.

    aiortc hands the tap an unwrapped, session-rebased timestamp, and it treats
    ANY backward step as the 32-bit counter wrapping - so a reordered or
    re-sent frame comes through as an advance of nearly 2**32, and every
    timestamp after it stays 2**32 too high. The error accumulates: probed on
    the live tap 2026-08-18, 1200 frames carried 22 such artifacts and spanned
    94,493,540,302 ticks, which is 22 x 2**32 on top of the real 7,061,580.

    Each artifact is 2**32 minus a plausible interval (4294961266 is
    2**32 - 6030), so the frame really moved backward a few thousand ticks.
    Holding a running offset restores the whole sequence; correcting one step
    in isolation would leave everything downstream of it shifted.

    The serve mux writes this straight into `pkt.pts`/`pkt.dts`, so uncorrected
    it puts jumps of about 47,721 seconds into a container whose PTS field is
    33 bits wide. The content underneath was always fine: those same 1200
    frames carry an honest 15.3 fps at 6030 ticks per frame, matching the wire.
    """
    _prev = state["prev_raw"]
    if _prev is not None and raw - _prev > _TS_BOGUS_UNWRAP:
        state["offset"] += _TS_MODULO
    state["prev_raw"] = raw
    return raw - state["offset"]


def _log_serve_canary(device_id: Optional[str], canary: dict) -> None:
    """One line per N tapped video frames, naming the camera it counts.

    The canary is the only video-rate measurement upstream of every queue, pipe
    and muxer, which makes it the number an investigation reaches for - and
    without the device id it cannot say which camera it describes on a
    multi-camera host.
    """
    _LOGGER.debug(
        "camera %s: serve h264 canary: frames=%d keyframes=%d"
        " max_keyframe_gap=%d cur_gap=%d unwrap_fixed=%d",
        device_id or "?", canary["frames"], canary["keyframes"],
        canary["max_gap"], canary["gap"], canary.get("unwrapped", 0),
    )


def _live_video_canary(pc, stored):
    """The canary that is actually being fed, not the one we happened to store.

    `_install_av_taps` records a reference to the canary of the first video
    receiver it taps. If the session ends up delivering on a DIFFERENT receiver
    - or the reference is cleared and not re-set - that stored dict stays at
    zero frames for the life of the session while another one fills up. The
    video-presence watchdog then reads "no video" from a session that is
    streaming perfectly and tears it down.

    Measured 2026-08-18: a camera serving at 0.993x wall clock, canary logging
    frames=3600 and climbing, and the watchdog firing "delivered no video in
    30s" every 35 seconds. Its sibling on the released build fired that warning
    zero times in two and a half hours.

    So prefer the stored reference when it has frames, and otherwise ask the
    peer connection directly. Best-effort: this must never be the reason a
    healthy session is judged dead.
    """
    if stored and stored.get("frames", 0) > 0:
        return stored
    _best = stored
    try:
        for _r in pc.getReceivers():
            _tr = getattr(_r, "track", None)
            if _tr is None or _tr.kind != "video":
                continue
            _qd = getattr(_r, "_RTCRtpReceiver__decoder_queue", None)
            _c = getattr(_qd, "_aidot_serve_canary", None)
            if _c and _c.get("frames", 0) > (
                _best.get("frames", 0) if _best else 0
            ):
                _best = _c
    except Exception:
        _LOGGER.debug("swallowed exception in _live_video_canary", exc_info=True)
    return _best


#: Consecutive dead attempts before a reused peer id is rotated. The SDES
#: keepalive loop reuses one peer id across the retries of a wake burst; a
#: fresh one registers another camera-side session, and the camera frees those
#: only slowly. Module-level so the loop and its tests share one number.
#:
#: Deliberately NOT applied to the DTLS serve loop. That loop builds a fresh
#: RTCPeerConnection per attempt, so reusing the peer id across attempts lets a
#: late answer generated against the PREVIOUS offer claim answer_fut (which
#: takes the FIRST answer to arrive, webrtc_open.py _deliver_webrtc_answer) and
#: become the remote description - carrying ICE credentials that cannot
#: authenticate, while the attempt's own correct answer is demoted to
#: candidate-scraping. Tried on 2026-08-18 and reverted; do not resurrect it.
_PEERID_MAX_REUSE = 3


def _video_presence_verdict(
    first_video_at: Optional[float],
    connected_at: Optional[float],
    now: float,
    grace: float,
) -> str:
    """Has this session produced video within `grace` seconds of connecting?

    The serve loop's only other liveness test is the ICE/peer-connection state,
    which a session receiving audio and no video passes forever.  Measured
    2026-08-17: an A000088 held one for hours - 62823 audio packets, zero video
    - while Home Assistant retried every 10-40 s and nothing ever re-opened.

    Returns "waiting" while the window is open (or the check is disabled with
    grace <= 0, or the connection has not completed), "ok" once any video frame
    has been seen, and "give-up" when the window closed with none.

    Deliberately one-shot: a session that delivered video and then stopped is a
    different failure with a different remedy, and this check must not claim it.
    """
    if first_video_at is not None:
        return "ok"
    if grace <= 0 or connected_at is None:
        return "waiting"
    return "give-up" if (now - connected_at) > grace else "waiting"


def _futile_video_limit(env: Optional[dict] = None) -> int:
    """Consecutive video-less DTLS sessions before the loop stops re-opening.

    Noticing is only half the fix.  The camera that prompted this answers the
    same way on every fresh open, and a video-less session is otherwise a CLEAN
    open - so a loop that simply re-opened would clear the backoff each time and
    wake the camera every 15 s indefinitely, which is not an improvement on
    staying quiet.

    ``AIDOT_DTLS_FUTILE_VIDEO_LIMIT=0`` disables the abandon.  Mirrors
    AIDOT_FUTILE_KEEPALIVE_LIMIT on the SDES path, which exists for the same
    reason.
    """
    _env = os.environ if env is None else env
    try:
        return int(_env.get("AIDOT_DTLS_FUTILE_VIDEO_LIMIT", "5"))
    except (TypeError, ValueError):
        return 5


def _probe_interval(attempt: int, threshold: int, normal_delay: float,
                     slow_interval: float) -> float:
    """Effective DTLS-open retry interval for a failed open.

    Below `threshold` consecutive failures this is just the pacer's own
    `normal_delay` (unchanged jittered-backoff behaviour). At/after `threshold`
    it widens to (at least) `slow_interval` - well beyond the pacer's own cap -
    so a camera that is cloud-online but never actually opens is probed
    roughly every `slow_interval` seconds instead of retried forever at the
    pacer's max cadence."""
    if _in_slow_probe(attempt, threshold):
        return max(normal_delay, slow_interval)
    return normal_delay


def _should_log_slow_probe(attempt: int, threshold: int, log_every: int) -> bool:
    """True when a slow-probe open failure should be logged: the moment
    slow-probe is entered, then every `log_every`th attempt after - so a
    camera stuck for hours doesn't drip a log line on every single probe."""
    if not _in_slow_probe(attempt, threshold):
        return False
    if log_every <= 0:
        return True
    return (attempt - threshold) % log_every == 0


_FFMPEG_MISSING_MSG = (
    "ffmpeg not found on PATH; install ffmpeg to enable recording/transcoding.\n"
    "  Ubuntu/Debian:    sudo apt install ffmpeg\n"
    "  macOS (Homebrew): brew install ffmpeg\n"
    "  Windows:          https://ffmpeg.org/download.html"
)


def _ffmpeg_path(binary: str = "ffmpeg") -> Optional[str]:
    """Return the resolved path to the ffmpeg binary, or None if not on PATH."""
    import shutil
    return shutil.which(binary)


# Runtime import: device_client defines these classes BEFORE importing this
# module (the package __init__ loads aidot.device_client first), so the
# partially-initialized module already exposes them here.
try:
    from ..device_client import DeviceStatusData
except ImportError as _exc:  # pragma: no cover - ordering contract violation
    raise ImportError(
        "aidot.camera.client must be imported via aidot.device_client "
        "(import aidot first); keep the camera import block in "
        "device_client.py below the DeviceStatusData/DeviceInformation "
        "definitions"
    ) from _exc






# --------------------------------------------------------------------------- #
# Camera / Leedarson smarthome API constants
# --------------------------------------------------------------------------- #



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

    # numpy ndarray path - try PIL then ffmpeg
    try:
        import numpy as _np
        if isinstance(image_data, _np.ndarray):
            try:
                from PIL import Image as _PILImage
                _PILImage.fromarray(image_data).save(output_path, "JPEG")
                return True
            except ImportError:
                pass
            # Pillow not available - pipe raw RGB to ffmpeg
            import subprocess as _sp
            if _ffmpeg_path() is None:
                _LOGGER.warning("async_snapshot: %s", _FFMPEG_MISSING_MSG)
                return False
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
                timeout=15,  # bound the hang; a wedged ffmpeg must not block forever
            )
            return r.returncode == 0
    except Exception as exc:
        _LOGGER.warning("async_snapshot: encode failed: %s", exc)

    return False


def _is_self_referential_source(source: str, stream_name: str) -> bool:
    """True when registering ``source`` under ``stream_name`` would loop.

    A go2rtc stream whose source is its own RTSP address becomes its own
    producer: the stream lists a producer, nothing feeds it, and every consumer
    gets a connection with no media.  That is exactly the shape of a PUSH URL,
    ``rtsp://host:8554/<stream name>`` - the address the keepalive publishes to.
    """
    if not source or not stream_name:
        return False
    if not source.lower().startswith(("rtsp://", "rtsps://")):
        return False
    path = urlparse(source).path.strip("/")
    return path == stream_name


#: Packets the serve's demuxer may hold while it waits for a gap to fill.  A
#: keyframe on an A001064 is 146-190 KB - roughly 130 packets - so anything
#: smaller than a few hundred cannot ride out a burst that arrives out of order.
#: Env-overridable because the right value depends on the link, not on us.
_SERVE_REORDER_QUEUE = int(os.environ.get("AIDOT_SERVE_REORDER_QUEUE", "500"))

#: How long (microseconds) the demuxer waits for a missing packet before moving
#: on.  Bounded on purpose: waiting forever turns loss into a stall, which is the
#: failure this is meant to prevent.
_SERVE_MAX_DELAY_US = int(os.environ.get("AIDOT_SERVE_MAX_DELAY_US", "500000"))

#: How long (seconds) the serve ffmpeg waits with NO packets on any RTP socket
#: before its SDP input errors out ("Error during demuxing: Operation timed
#: out") and the serve dies.  ffmpeg's own default is 10 s (READ_PACKET_TIMEOUT_S,
#: applied through the sdp demuxer's ``listen_timeout`` option).  Measured on an
#: A001064 (2026-08-24/25): the camera episodically stops transmitting for
#: >=10 s mid-session, and every reopen afterwards succeeds immediately, so the
#: link recovers on a 10-20 s scale.  A mains camera therefore gets 30 s to ride
#: the gap out; a battery camera keeps ffmpeg's 10 s default, because its stops
#: are real sleeps that only a reopen (with its wake) ends - waiting longer just
#: freezes the picture.  ``AIDOT_SERVE_INPUT_TIMEOUT_S`` overrides both.
_SERVE_INPUT_TIMEOUT_MAINS_S = 30
_SERVE_INPUT_TIMEOUT_BATTERY_S = 10


def _resolve_serve_input_timeout_s(is_battery: bool) -> int:
    """Seconds the serve's SDP input tolerates total silence before erroring.

    Pure policy (unit-testable): the env override wins for every camera; else
    mains rides out a transmit gap and battery keeps the fast default.
    """
    _env = os.environ.get("AIDOT_SERVE_INPUT_TIMEOUT_S")
    if _env:
        try:
            return max(1, int(_env))
        except ValueError:
            pass
    return (_SERVE_INPUT_TIMEOUT_BATTERY_S if is_battery
            else _SERVE_INPUT_TIMEOUT_MAINS_S)


#: How long to wait after a camera answers -50002 / -50015 ("no free session").
#: Both loops used to wait _MAX_DELAY (300s) on the belief that the camera
#: "releases slowly". Measured 2026-08-07 on an A001064: reopening 2s after a
#: close is refused, 8s reopens cleanly, every time - and that was minting a
#: fresh peerid each attempt, the case the old comment warned about. A camera
#: that clears in seconds paired with a five-minute refusal to retry is
#: indistinguishable from one that needs a long rest, which is the likeliest
#: origin of this project's "battery cameras need 30-45 minutes" rule.
#: Still a real wait: retrying instantly would hammer a camera that genuinely
#: has none free, and on a battery model risks a wake-then-sleep loop.
_BUSY_BACKOFF_S = float(os.environ.get("AIDOT_BUSY_BACKOFF_S", "20"))

#: Consecutive background sessions that deliver NO media before the keepalive
#: stops reopening a battery camera. Observed 2026-08-07 on an A001513: 22 opens
#: across ~8 hours, none of them delivering media, because the loop escalated
#: its backoff but had no condition under which it ever stopped. On a mains
#: camera that is wasteful; on a battery one it spends charge, and a unit has
#: already been drained to 5% that way.
#: 0 disables the ceiling entirely.
_FUTILE_KEEPALIVE_LIMIT = int(os.environ.get("AIDOT_FUTILE_KEEPALIVE_LIMIT", "5"))


def _next_no_media_streak(no_media_streak: int, healthy: bool) -> int:
    """The streak after a keepalive session that was (or was not) healthy.

    The ceiling counts CONSECUTIVE failures, so a session that delivered media
    resets it to zero. Without that reset the count is cumulative and a camera
    that merely fails occasionally - five scattered no-media sessions spread
    across a day, each one separated by sessions that worked - eventually trips
    a limit meant for cameras that never deliver anything at all, and has its
    background keepalive stopped for good.
    """
    if healthy:
        return 0
    return no_media_streak + 1


def _should_abandon_keepalive(no_media_streak: int, *, is_battery: bool,
                              limit: int = _FUTILE_KEEPALIVE_LIMIT) -> bool:
    """Should the background keepalive stop reopening this camera?

    Only for battery cameras. A mains camera has no charge to protect, and the
    same persistence is what recovers a stream after a router reboot or a
    power-cycle - there the loop is the feature.

    Scoped to the BACKGROUND loop. A view still opens a session on demand: the
    user asking to see the camera is new information, and a retry ceiling should
    not decide on their behalf that it cannot work.
    """
    if not is_battery or limit <= 0:
        return False
    return no_media_streak >= limit


def _build_sdes_serve_cmd(
    *,
    sdp_path: str,
    rtsp_push_url: Optional[str] = None,
    output_path: Optional[str] = None,
    max_seconds: Optional[float] = None,
    sdes_audio: bool = False,
    audio_gain_db: float = -8.0,
    push_video_only: bool = False,
    video_decoder: Optional[list] = None,
    input_timeout_s: Optional[int] = None,
) -> list:
    """Build the ffmpeg argv for the SDES bridge serve.

    Pure (no I/O - the caller creates any output directory and resolves
    ``sdes_audio`` / ``audio_gain_db`` from opts/env).  Four destinations:

    - ``rtsp_push_url`` is http(s)  -> PULL model: serve mpegts over an
      ``-listen`` socket so go2rtc / HA's stream integration pull it (no go2rtc
      pre-registration).
    - ``rtsp_push_url`` is anything else -> legacy PUSH model: publish to an RTSP
      server (``-f rtsp``), for callers running their own pre-registered go2rtc.
    - ``output_path`` -> record to file.
    - neither -> ``-f null`` (keep ffmpeg alive draining SRTP, write nothing).

    AUDIO (the http-listen serve and the RTSP push): the mpegts mux writes its PAT/PMT once
    every mapped stream has produced a packet.  Video is ``-c:v copy`` (parameters
    known from the SDP at once); the ``-c:a aac`` encoder needs PCM samples to emit
    a frame, and battery cameras send PCMA sparsely.  So we feed the encoder a
    continuous ``anullsrc`` silence base and ``amix`` the real PCMA over it
    (``normalize=0`` -> the 0-valued silence is a no-op whenever real audio is
    present): the encoder is fed from t=0 so the PMT writes promptly and any gaps
    are filled with silence.  go2rtc/HA pulls this mpegts the same way as the
    video-only serve, so the pull model + cold-start relay are unchanged.
    ``volume`` is the stateless hot-mic trim (dynamic normalizers regressed the
    pipe in testing).  The RTSP push uses the SAME silence-base mix, for a second
    reason as well as the sparse-battery one: it publishes G.711 otherwise, and
    fMP4/MSE cannot carry G.711, so browsers on the MSE path heard nothing.
    File recording (snapshots/diagnostics) is always -c copy."""
    time_args = ["-t", str(int(max_seconds))] if max_seconds else []

    if rtsp_push_url:
        _warn_lan_serve(_serve_host(rtsp_push_url), context="sdes-serve")

    if rtsp_push_url and rtsp_push_url.startswith("http"):
        if sdes_audio:
            dest_args = [
                # Silence-base mix: a continuous a-law-rate anullsrc keeps the AAC
                # encoder fed from t=0 so the mpegts PMT writes promptly on sparse
                # battery PCMA; real audio mixes over the 0-valued silence
                # (normalize=0 -> no-op when audio is present).
                "-f", "lavfi", "-i", "anullsrc=r=8000:cl=mono",
                "-filter_complex",
                ("[0:a]aresample=async=1[a0];"
                 "[a0][1:a]amix=inputs=2:duration=longest:normalize=0,"
                 f"volume={audio_gain_db}dB[aout]"),
                "-map", "0:v:0", "-map", "[aout]",
                "-c:v", "copy", "-c:a", "aac", "-ar", "48000", "-b:a", "128k",
                *time_args,
                "-f", "mpegts", "-listen", "1",
                rtsp_push_url,
            ]
        else:
            dest_args = [
                "-c:v", "copy", "-an",
                *time_args,
                "-f", "mpegts", "-listen", "1",
                rtsp_push_url,
            ]
    elif rtsp_push_url and sdes_audio and not push_video_only:
        # PUSH + audio: encode AAC rather than pass G.711 through.
        #
        # Passthrough was right for WebRTC, which carries PCMA natively - but
        # fMP4/MSE has no mapping for G.711, so every browser on the MSE path got
        # a silent stream. Measured on the live fleet 2026-08-21: producer
        # `audio, recvonly, PCMA/8000`, go2rtc sender `pcm_alaw`, and MSE
        # negotiated `avc1.*` alone with no audio codec at all. Encoding AAC here
        # makes one publish serve both consumers. Video stays `-c:v copy`; it is
        # never gated on audio.
        #
        # Battery cameras send PCMA sparsely, and an AAC encoder with no input
        # samples emits no frames - the same hazard the http-listen serve already
        # solves. Reuse its fix verbatim: a continuous anullsrc under
        # amix(normalize=0) feeds the encoder from t=0 and is a no-op wherever
        # real audio is present, so sparse audio cannot stall the publish.
        dest_args = [
            "-f", "lavfi", "-i", "anullsrc=r=8000:cl=mono",
            "-filter_complex",
            ("[0:a]aresample=async=1[a0];"
             "[a0][1:a]amix=inputs=2:duration=longest:normalize=0,"
             f"volume={audio_gain_db}dB[aout]"),
            "-map", "0:v:0", "-map", "[aout]",
            "-c:v", "copy", "-c:a", "aac", "-ar", "48000", "-b:a", "128k",
            *time_args,
            "-f", "rtsp", "-rtsp_transport", "tcp",
            rtsp_push_url,
        ]
    elif rtsp_push_url:
        # PUSH without usable audio: G.711 passthrough (-c copy) as always -
        # EXCEPT when the audio payload type was never observed
        # (push_video_only): announcing an un-narrowed audio line the server
        # cannot accept kills the whole publish with 400 Bad Request, so map
        # video only and announce clean. That guard outranks a request for
        # audio - a silent picture beats no picture.
        dest_args = [
            *(["-map", "0:v:0", "-c:v", "copy"] if push_video_only
              else ["-c", "copy"]),
            *time_args,
            "-f", "rtsp", "-rtsp_transport", "tcp",
            rtsp_push_url,
        ]
    elif output_path:
        # File recording (snapshots, diagnostics) is always a plain copy of the
        # narrowed SDP - the audio mix is for the live serve, not file capture.
        dest_args = ["-c", "copy", *time_args, output_path]
    else:
        dest_args = [*time_args, "-f", "null", "/dev/null"]

    # Decoder selection applies to the ``-f null`` drain alone - it is the only
    # destination that decodes; every other one is ``-c copy``.  The caller
    # passes ready-made input arguments, either ``["-hwaccel", m]`` or
    # ``["-c:v", name]``, and they must sit BEFORE ``-i``: after ``-i`` ffmpeg
    # reads ``-c:v`` as an ENCODER, and ``-hwaccel`` is an input option that has
    # no meaning there at all.  Empty or None means ffmpeg chooses, as always.  Keep the decode: it is what proves frames are not merely
    # arriving but decodable, which is what catches a parameter-set mismatch
    # that otherwise presents as a permanently black picture.
    decode_args = (
        list(video_decoder)
        if video_decoder and not rtsp_push_url and not output_path
        else []
    )
    return [
        "ffmpeg", "-y",
        "-loglevel", "warning",
        "-protocol_whitelist", "file,rtp,udp,srtp",
        *decode_args,
        # 2 s analyzeduration: the camera sends SPS+PPS+IDR in the first burst;
        # 15 s consumed nearly all packets during analysis.  PLI re-arms an IDR
        # every 5 s so parameters always re-arrive.
        #
        # ``discardcorrupt`` is the loss half of this: both ends of this path are
        # wireless (the camera, and typically the host), so RTP arrives with real
        # gaps.  Measured on the reference install: `RTP: missed N packets` with
        # ZERO drops on every socket in the path, which means the packets were
        # lost before they ever reached the box.  Without this ffmpeg passes the
        # damaged frame downstream and then backs its input queue up behind the
        # reordering it thinks it needs - "max delay reached. need to consume
        # packet" - and the serve eventually dies, taking every viewer with it.
        # A brief artefact is a far better outcome than a dropped stream.
        "-fflags", "+nobuffer+genpts+discardcorrupt",
        "-analyzeduration", "2000000",
        "-probesize", "500000",
        # Reordering headroom.  The default (-1) leaves the demuxer with almost
        # none, so a burst that arrives out of order reads as loss.  A keyframe
        # here is 146-190 KB - about 130 packets - so the queue has to be able to
        # hold more than one of them, and max_delay bounds how long it will wait
        # before giving up on a gap rather than stalling the pipeline.
        "-reorder_queue_size", str(_SERVE_REORDER_QUEUE),
        "-max_delay", str(_SERVE_MAX_DELAY_US),
        # Input silence tolerance: the sdp demuxer's ``listen_timeout`` doubles
        # as its packet-read timeout (READ_PACKET_TIMEOUT_S, ffmpeg default
        # 10 s).  See _resolve_serve_input_timeout_s for the mains/battery
        # policy.  Input option, so it must sit before -i; None keeps ffmpeg's
        # default (no behavior change for callers that do not opt in).
        *(["-listen_timeout", str(int(input_timeout_s))]
          if input_timeout_s is not None else []),
        "-i", sdp_path,
        *dest_args,
    ]


# --------------------------------------------------------------------------- #
# TCP binary framing helpers
# --------------------------------------------------------------------------- #











# Terminal webrtcResp ack codes - the camera/cloud refused the stream and retrying
# is futile. Source: decompiled AckBean.java; the official app treats both as terminal
# (LiveCameraView.java:765 - shows an error, does NOT retry).
#   -50002 = WEBRTC_ERROR_EN_RTC_ERR_CODE_SESSION_EXCEED (max concurrent streams)
#   -50015 = LIVE_SD_MAX_CONNECT_ERROR (SD-card / connection cap)








# Real-time camera alarm types - carried as a TRANSIENT `alarmType` field inside the
# setDevAttrNotif MQTT push (iot/v1/c/{userId}/#), NOT a separate event message.
# Source: decompiled NewLiveFragment.java:6934-6938 / props.alarmType parse :3654.
#   65 = motion, 66 = person. (Historical events with picUrl/videoUrl are a separate
#   cloud-REST poll - async_get_cloud_recordings.)






# --------------------------------------------------------------------------- #
# CloudPlaybackSession
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# TutkStreamSession
#
# TUTK IOTC P2P live-stream session for Leedarson/AiDot cameras.
# Use DeviceClient.async_open_live_stream() to obtain an instance.
#
# Protocol source: classes.jar.decompiled.zip / TutkManager.java
#   IOTC_Connect_ByUID_Parallel(uid, sid) -> nSID
#   avClientStart2(nSID, "admin", "admin123", ...) -> avIndex
#   avSendIOCtrl(avIndex, 511, ...) -> start video (IOTYPE_USER_IPCAM_START)
#   avRecvFrameData2(avIndex, ...) -> frame data loop
#
# Requires: libIOTCAPIs.so + libAVAPIs.so from the TUTK SDK.
# Obtain them from the TUTK SDK distribution or an extracted AiDot APK.
# --------------------------------------------------------------------------- #



# --------------------------------------------------------------------------- #
# LiveStreamSession
#
# Manages a single live-stream TCP session for a Leedarson/AiDot camera.
# Use DeviceClient.async_open_live_stream() to obtain an instance.
#
# Protocol source: iOS LDSXplayer startRealPlay -> LDSTCPManager
#   connectHost:port:sessionId:aesKey:heartbeat:msg:cmd:subCmd:cmdParam:tls:
#
# Wire format: same 37-byte header + payload as CloudPlaybackSession, but:
#   - TLS socket (server cert not verified -- IoT device)
#   - AES-256/ECB/PKCS7 encrypts outbound payloads; decrypts inbound payloads
#   - LOGIN payload carries sessionId from the MQTT connectipc response
#   - STREAM_REQ starts the live video feed (no taskId needed)
# --------------------------------------------------------------------------- #



# --------------------------------------------------------------------------- #
# WebRTCSession
#
# Manages a live WebRTC stream opened by DeviceClient.async_open_webrtc_stream.
# Call await session.stop() to tear down the peer connection and MQTT session.
# --------------------------------------------------------------------------- #





# Two-way-audio (talk) PCM format: signed-16-bit little-endian, 8 kHz mono, in
# 20 ms frames (PCMA/PT=8 on the wire). Exported so producers - e.g. the HA
# aidot.talk service - frame audio identically to what the talk track consumes.

# SDES two-way-audio timing.  SPEAKERSTART must be deferred ~0.6 s after the
# command channel is up: the camera ignores it if sent immediately after LIVING
# (no 851 ACK) but accepts it once its media pipeline is ready (~0.58 s observed).








# --------------------------------------------------------------------------- #
# MQTT helpers (playback provisioning + live-stream discovery)
#
# Uses paho-mqtt with WebSocket transport.  The synchronous paho loop runs in
# a thread-pool executor so it never blocks the asyncio event loop.
# Threading primitives (threading.Event, queue.Queue) replace the complex
# asyncio Future/call_soon_threadsafe bridge that had VERSION2 ReasonCode
# compatibility issues.
# --------------------------------------------------------------------------- #







_WEBRTC_OPEN_GATE: "Optional[asyncio.Semaphore]" = None


def _get_webrtc_open_gate() -> "asyncio.Semaphore":
    """Global gate that serializes WebRTC handshakes across ALL cameras.

    HA prefetches every camera's stream at once; 7 simultaneous handshakes drown
    the shared MQTT signaling channel and the cameras never answer
    ('no webrtcResp'). Limiting how many open concurrently lets them connect
    reliably. Tunable via AIDOT_MAX_CONCURRENT_OPENS (default 2).
    """
    global _WEBRTC_OPEN_GATE
    if _WEBRTC_OPEN_GATE is None:
        try:
            _n = max(1, int(os.environ.get("AIDOT_MAX_CONCURRENT_OPENS", "2")))
        except (ValueError, TypeError):
            _n = 2
        _WEBRTC_OPEN_GATE = asyncio.Semaphore(_n)
    return _WEBRTC_OPEN_GATE


_STREAM_SLOTS: "Optional[asyncio.Semaphore]" = None
_STREAM_SLOTS_CAP: int = 0


def _stream_slots_default() -> int:
    """The configured cap: an explicit env override, else the built-in default."""
    try:
        return max(1, int(os.environ.get("AIDOT_MAX_CONCURRENT_STREAMS", "3")))
    except (ValueError, TypeError):
        return 3


def configure_stream_limits(max_streams: int) -> int:
    """Raise the concurrent-serve cap to fit the fleet; return the cap in force.

    The default cap of 3 is a host-protection guard, but it silently STARVES an
    account with more cameras than that: a camera holds its slot for the life of
    its serve, so on a fleet of 4 DTLS cameras the fourth waits forever while the
    other three are kept alive - it simply never streams, with no error anywhere.
    Confirmed live on a 4-camera fleet, where the library logged "waiting for a
    stream slot (cap reached)" for the odd one out on every attempt.

    A consumer that knows how many cameras it is about to drive (the Home
    Assistant integration knows its camera count) should call this so the cap is
    never below the fleet size.

    ``AIDOT_MAX_CONCURRENT_STREAMS`` still wins when set: an operator who
    deliberately capped a small host means it, and would rather have cameras take
    turns than have the host fall over.  The cap only ever grows - shrinking it
    would strand a camera that already holds a slot.
    """
    global _STREAM_SLOTS, _STREAM_SLOTS_CAP
    if os.environ.get("AIDOT_MAX_CONCURRENT_STREAMS"):
        _get_stream_slots()          # ensure it exists so the cap is populated
        return _STREAM_SLOTS_CAP
    target = max(1, int(max_streams))
    slots = _get_stream_slots()
    if target > _STREAM_SLOTS_CAP:
        for _ in range(target - _STREAM_SLOTS_CAP):
            slots.release()          # grows the semaphore's permit count
        _LOGGER.info(
            "concurrent-serve cap raised from %d to %d to fit the camera fleet",
            _STREAM_SLOTS_CAP, target,
        )
        _STREAM_SLOTS_CAP = target
    return _STREAM_SLOTS_CAP


def _get_stream_slots() -> "asyncio.Semaphore":
    """Global cap on concurrently-ACTIVE camera serves (vs the open-gate, which
    only limits concurrent handshakes).  Each active DTLS serve runs an aiortc
    decode + a PyAV mux thread + an AAC encoder; on a small host (Raspberry Pi)
    too many at once overwhelm it.  A camera holds a slot for the lifetime of its
    serve and waits for one if the cap is reached.  Tunable via
    AIDOT_MAX_CONCURRENT_STREAMS (default 3).

    NOT an app-parity feature - the official app/web is single-live-view and has
    no concurrency cap of any kind (its only concurrency limit is the camera-side
    -50002 SESSION_EXCEED terminal error, which we mirror separately).  This cap
    is an HA-specific resource guard: HA dashboards can request N cameras at once,
    which a phone never does.  Deliberate divergence, kept for host protection."""
    global _STREAM_SLOTS, _STREAM_SLOTS_CAP
    if _STREAM_SLOTS is None:
        _STREAM_SLOTS_CAP = _stream_slots_default()
        _STREAM_SLOTS = asyncio.Semaphore(_STREAM_SLOTS_CAP)
    return _STREAM_SLOTS


# Where captured SPS/PPS are cached.  Override with AIDOT_SPROP_DIR so HA can
# point it at persistent storage (the core container's ~ is ephemeral; without a
# persistent dir the cache simply re-bootstraps from the first stream each boot).
# When AIDOT_SPROP_DIR is unset, honour the XDG base-directory spec: base the
# path on $XDG_CONFIG_HOME (falling back to ~/.config) so the cache lands in the
# user's configured config home rather than a hard-coded ~/.config.


































# --------------------------------------------------------------------------- #
# DeviceClient
# --------------------------------------------------------------------------- #





# Battery cameras re-sleep on their own low-power timer ~25 s after the last
# keep-alive, even mid-view. Renew setKeepAliveTime INSIDE that window so there
# is no sleep gap (the official app renews every 30 s, which leaves a ~5 s gap
# against the 25 s window). See CameraMixin._keepalive_renew_loop.
_KEEPALIVE_WINDOW_S = 25
_KEEPALIVE_RENEW_S = 20


def _ack_matches_seq(msg, seq):
    """Is ``msg`` the device's answer to the command we sent as ``seq``?

    ``True`` for our own 200, the integer response code for our own non-200,
    and ``False`` for anything that is not attributable to us - another
    command's ack, the battery wake response, a message with no seq at all.

    Correlating matters because several messages are in flight on the same four
    wildcard subscriptions: battery cameras get a ``lowPowerActiveStateReq``
    published alongside the write, and Home Assistant writes attributes in
    bursts. Accepting a stranger's 200 reports that one control landed on the
    evidence of a different one landing.
    """
    if not isinstance(msg, dict) or seq is None:
        return False
    got = msg.get("seq")
    if got is None:
        return False
    # We send a string; nothing obliges the camera to echo the same type.
    if str(got) != str(seq):
        return False
    code = (msg.get("ack") or {}).get("code")
    if code is None:
        code = msg.get("code")
    if code is None:
        inner = msg.get("payload") or {}
        if isinstance(inner, dict):
            code = inner.get("code")
    if code == 200:
        return True
    return code if isinstance(code, int) else False


_TERMINAL_ID: "Optional[str]" = None


def _stable_terminal_id(seed: "Optional[str]" = None, width: int = 6) -> str:
    """The six-hex terminal field of our peer ids.  Stable, not per-open random.

    The camera parses the peer id as ``<session>_<terminal_id>_%d_%d_%d`` and
    compares the terminal id against the sessions it already has -
    ``rtc_session_check_same_terminal_id`` / "rtc session terminal id is same",
    with paired ``new_terminal_id`` / ``old_terminal_id`` logs.  So the terminal
    id is how it recognises a client it has seen before.

    We were minting six fresh random hex digits per open: 329 distinct terminal
    ids across 836 opens in 19 hours, so every reconnect looked like a brand-new
    client and the camera's "same terminal" path could never fire for us.  A
    client that reconnects every couple of minutes should look like one client
    reconnecting.

    Stable for the life of the process.  ``seed`` makes it deterministic for
    tests and would allow deriving it from a durable identity later; without one
    it is random per process, which is already the property that matters.
    """
    global _TERMINAL_ID
    if seed is not None:
        import hashlib
        return hashlib.sha256(seed.encode()).hexdigest()[:width]
    if _TERMINAL_ID is None:
        import os
        _TERMINAL_ID = os.urandom(16).hex()
    return _TERMINAL_ID[:width]


#: Measurement scaffolding, OFF unless an operator names a file - see the note
#: on EXPT_CAP_FILE. A published library must not open a Home Assistant config
#: path on the event loop, and with no env var set this knob does no I/O at all.
EXPT_PEERID_FILE = os.environ.get("AIDOT_EXPT_PEERID_FILE")


#: Screening knob for the peer id's CLIENT CLASS only, off unless set.
#: `_expt_peer_id_fields` covers the same ground but reads a file, and the
#: live-validation harness can only pass environment variables - so an arm that
#: has to run there needs this route.
EXPT_PEERID_CLASS = "AIDOT_EXPT_PEERID_CLASS"


def _expt_peer_id_class():
    """One hex character to pin field 2's first character, or None.

    The camera takes its client class from that character
    (``client_type = field2[0] - '0'``). Pinning it to ``'0'`` (APP_ANDROID)
    was tried and reverted - it breaks the A000088, which accepts the session
    and then sends nothing. The vendor WEB app sends ``'2'``, and that arm has
    never been screened; this exists to screen it.

    **Pins the class character and nothing else.** The three trailing integers
    encode transport, and an SDES tail pushed at a DTLS camera is silently
    discarded - the failure mode an earlier unscoped knob produced. Those stay
    exactly as computed.

    Fails closed: anything that is not a single hex digit is ignored rather
    than applied, because a peer id of the wrong shape is rejected outright and
    would break every open rather than one arm of an experiment.
    """
    raw = (os.environ.get(EXPT_PEERID_CLASS) or "").strip()
    if len(raw) != 1 or raw not in "0123456789abcdef":
        return None
    return raw


def _expt_peer_id_fields(device_id=None, path=None):
    """Experiment override for one device's peer-id fields, or None.

    The camera parses the peer id with ``%[^_]_%[^_]_%d_%d_%d`` (`parse_peer_id`
    at 0x298ef8 in the A001064 image) and takes its client class from the FIRST
    CHARACTER of field 2: ``client_type = field2[0] - '0'``, against
    ``EN_WEBRTC_CLIENT_TYPE_{APP_ANDROID,APP_IOS,WEB,ALEXA,GOOGLE_HOME}`` = 0..4.
    The vendor app hard-codes a leading ``'0'`` there; we generate six random hex
    digits, so we announce a uniformly random class and an out-of-range one 11
    times in 16.  This exists to pin that character on the live camera.

    Scoped to ONE device, like ``_sdes_max_session_s``.  The scoping is not
    cosmetic: this override also sets the three trailing integers, and an
    unscoped file would push an SDES ``_2_0_1`` tail at the DTLS cameras, which
    silently discard a peer id with the wrong transport digit.  An earlier
    unscoped experiment knob hit a battery camera and forced it to ~30x its
    normal wake rate.

    File format, one line::

        <device_id>:[<terminal>_]<live_type>_<stream_id>_<version>

    Three integers set the integers only.  A leading terminal also pins field 2,
    the field that carries the client class, and comes in two widths:

      * **one hex character** - pins only field 2's FIRST character (the class)
        and leaves the other five random.  This is the arm you almost always
        want: it reproduces the observed condition, "class is 4, tail varies",
        without also making every session's peer id identical.
      * **six hex characters** - pins the whole of field 2.  Field 1 is already
        stable per process, so this makes every peer id byte-identical across
        opens, which is cross-session peer-id REUSE.  The camera has a
        session-dedup path keyed on the peer id, so a result obtained this way
        cannot separate the client class from the reuse.  Use it only when reuse
        is the thing under test.

    FAILS CLOSED on anything it cannot parse, on a device mismatch, and on a
    caller that passes no device id.  A malformed peer id is rejected by the
    camera outright, so a half-written override file must never reach the wire.
    """
    if not device_id:
        return None
    path = path if path is not None else EXPT_PEERID_FILE
    if not path:
        return None
    try:
        with open(path) as _fh:
            raw = _fh.read().strip()
    except OSError:
        return None
    head, sep, tail = raw.partition(":")
    if not sep or head.strip() != device_id:
        return None
    parts = tail.strip().split("_")
    # Three fields sets the integers only; four also pins the terminal id, so
    # that field can be screened as well.
    terminal = None
    if len(parts) == 4:
        terminal, parts = parts[0], parts[1:]
        # One hex character (pin the class, keep the tail random) or exactly six
        # (pin all of field 2). Any other width would change the peer id's shape,
        # and the camera rejects a malformed peer id outright.
        if len(terminal) not in (1, 6) or any(c not in "0123456789abcdef" for c in terminal):
            return None
    elif len(parts) != 3:
        return None
    out = []
    for q in parts:
        if not q.isdigit():
            return None
        out.append(int(q))
    return (terminal, out[0], out[1], out[2])


class CameraMixin(_CameraControlsMixin, _CameraSdMixin, _WebRTCOpenMixin, _SdesOpenMixin):
    """All camera/streaming methods, mixed into DeviceClient via inheritance."""

    # Devices without an aesKey never get this set by the core constructor;
    # default it so get_send_packet and friends see None instead of raising.
    aes_key = None

    # Optional LAN control client; when attached, attribute writes go local-first.
    _lan_client = None

    # MQTT credential state, defaulted at class level so the credential path is
    # safe on any client whose __init__ did not run to completion.
    _mqtt_credential_refresh_cb = None
    _mqtt_refused_at = 0.0

    def attach_lan_client(self, lan_client) -> None:
        """Route camera attribute writes through ``lan_client`` (local-first,
        cloud-fallback).  Pass an ``aidot.camera.lan_control.CameraLanClient``."""
        self._lan_client = lan_client

    def detach_lan_client(self) -> None:
        self._lan_client = None

    def _init_camera_state(self, device: dict, user_info: dict) -> None:
        """Camera-side state init, called once at the end of DeviceClient.__init__.

        Everything camera-specific that the upstream constructor does not set
        lives here, so the core __init__ body stays aligned with upstream.
        """
        # Swap in the camera-aware status/info supersets created by the core,
        # carrying forward anything the core constructor seeded into the
        # originals so upstream-added seeding cannot be lost silently.
        _core_status, _core_info = self.status, self.info
        self.status = CameraStatusData()
        self.status.__dict__.update(_core_status.__dict__)
        self.info = CameraDeviceInformation(device)
        for _k, _v in _core_info.__dict__.items():
            self.info.__dict__.setdefault(_k, _v)
        # livePlayReq dseq - app parity (Q0(): starts at 100, increments per
        # request).  Camera tracks the live-play sequence; 0 is not a valid seq.
        self._live_dseq = 100
        # Store full user_info for camera API calls
        self._user_info: dict[str, Any] = user_info
        # Region written to login_info by AidotClient.async_post_login()
        self._region: str = user_info.get("region", "us")
        # Cache slot for MQTT broker URL, fetched lazily on first playback call
        self._mqtt_url: Optional[str] = None
        # Cache slot for Leedarson smarthome auth (mqttUser, mqttPassword, userId)
        # Fetched lazily via _async_get_smarthome_auth()
        self._smarthome_auth: Optional[dict] = None
        # Cache for the HTTP ICE/TURN config.  Each TURN entry carries a server
        # ``ttl`` (Unix epoch), so caching until just before it is safe and saves
        # the ~2s fetch on repeat cold opens.  Reset on token refresh below
        # (credentials are bound to the access token).
        self._cached_ice_config: Optional[dict] = None
        self._ice_config_expiry: float = 0.0
        # Cache for batchGetDeviceUserInfo.  Unlike ICE config there is no server
        # ttl, so cap with a fixed TTL (see _DEVICE_USER_INFO_TTL): the extracted
        # numeric userId/uuid are account-static, and the LAN-IP field is vestigial
        # (a stale IP at worst skips one redundant user/connect).  On a warm reopen
        # this is the only otherwise-uncached HTTP round-trip.  Reset on token
        # refresh below (the request is access-token authenticated).
        self._cached_device_user_info: Optional[dict] = None
        self._device_user_info_expiry: float = 0.0
        # Async callback (set by AidotClient) that refreshes the access token and
        # updates the shared login_info in place, so camera HTTP calls can recover
        # from a 21026 "Please login again" instead of failing silently.
        self._token_refresh_cb: "Optional[Callable]" = None
        # Async callback (set by AidotClient) that fetches a fresh MQTT password
        # into the shared login_info.  The password is deliberately never
        # persisted (it rotates on every account login), so on a restart from a
        # stored token there is none until this runs - see
        # _async_get_smarthome_auth, which calls it before consulting login_info.
        self._mqtt_credential_refresh_cb: "Optional[Callable]" = None
        # Loop timestamp of the last broker credential refusal, for the refetch
        # floor in _async_refresh_mqtt_credential.
        self._mqtt_refused_at: float = 0.0
        # Raw device dict retained for transport-type detection (isDTLS field)
        self._raw_device: dict = device

        # Seed camera/diagnostic status from the cloud device "properties" payload
        # (Battery_remaining, Occupancy, SDcardStatus, MotionDetection_*, ...).  This
        # is the authoritative, always-current source the official app itself reads
        # - cameras do not push these reliably over MQTT - so sensors populate
        # immediately on load, before any poll.  No-op for devices without it.
        self.update_status_from_device(device)
        # Full list of device IDs for this account.  Used when calling
        # batchGetDeviceUserInfo so the server returns data for this device
        # (sending only one ID may yield an empty response).  Populated by
        # AidotClient after the full device list is fetched; falls back to
        # just this device's ID so standalone DeviceClient usage still works.
        self._all_device_ids: list = [self.device_id]
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
            # Guard against ASCII-encoded IPs (cloud stores a LAN IP's raw bytes
            # as the octets, e.g. "49.57.50.46" == ASCII of "192.").
            _ip_str = str(_dev_ip_init)
            if _ip_looks_ascii_garbled(_ip_str):
                # Benign, handled cloud quirk (not actionable by the user): the
                # camera's LAN IP comes from WebRTC signaling, not this field.
                # Debug, not warning, so it does not read as a problem in the log.
                _LOGGER.debug(
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
        # Last resolution asked for, re-sent when a session starts.
        self._desired_quality: Optional[str] = None
        self._stream_task: Optional["asyncio.Task[None]"] = None
        self._stream_mqtt_drain: Optional["asyncio.Future"] = None
        self._last_frame_time: float = 0.0
        self._keepalive_rtsp_url: Optional[str] = None  # local serve URL (go2rtc pulls)
        self._go2rtc_url: Optional[str] = None           # go2rtc API base (prefer-go2rtc)
        # Whether WE own this camera's go2rtc stream registration.  False when the
        # consumer registers the stream itself and passes the URL for viewer
        # queries only - in which case we must neither add nor REMOVE it.
        self._go2rtc_manages_stream: bool = True
        self._go2rtc_pull_url: Optional[str] = None      # go2rtc pull URL once registered
        self._go2rtc_task: "Optional[asyncio.Task[None]]" = None
        # Set by the DTLS serve loop once ffmpeg is bound + serving, so
        # camera.stream_source() can wait and hand HA a ready URL (avoids HA's
        # ~40s connection-refused retry gap on cold start).
        self._serve_ready: "asyncio.Event" = asyncio.Event()
        # Cold-start serve-port relay (holds the public port connectable through
        # the handshake so an eager go2rtc pull waits instead of being refused).
        self._serve_relay: "Optional[_ServeRelay]" = None
        # Cold-start instrumentation: monotonic at the start of an open, so any
        # thread (signaling, bridge, serve) can log elapsed-ms phase markers.
        self._cold_open_t0: "Optional[float]" = None
        # Motion/event polling (cloud event list). NOTE: the camera does NOT push motion
        # to a passive MQTT subscriber - alarmType is only emitted during an active live
        # view (decompiled NewLiveFragment) - so real-time-ish motion for HA comes from
        # polling the cloud event list, mirroring how the app surfaces background events.
        self._motion_active: bool = False
        self._motion_cb: Optional[Callable] = None
        self._motion_task: Optional["asyncio.Task[None]"] = None
        # Insertion-ordered set (dict keys) so the memory-bound trim can evict
        # the OLDEST uids deterministically rather than arbitrary ones.
        self._motion_seen: dict = {}
        self._motion_interval: float = 30.0

    # -- Pre-0.6 core API, kept for existing consumers ----------------------- #

    def set_status_fresh_cb(self, callback) -> None:
        self.on_status_update = callback

    async def read_status(self):
        return self.status

    # Camera models that report ``enableSdes: '1'`` but whose SDES-SRTP
    # implementation is non-functional on the wire.  Forced to the DTLS path.
    #
    # Models for which we should NOT include an SCTP data channel in the
    # WebRTC offer.  Most KVS-WebRTC firmware (LK.IPC.A000088, .A001513) sends
    # SCTP control messages over DTLS application_data after handshake; if the
    # client never set up an SCTP transport, the camera retransmits, then
    # tears DTLS down with close_notify after ~22 s - observed via byte-tap.
    # A001064 is the exception: across runs it answers our datachannel offer
    # with (a) no m=application section, (b) a different kind, or (c) extra
    # video sections - all of which break setRemoteDescription.  Keep it
    # data-channel-less; it's parked on the SDES/TUTK side anyway.
    _NO_DATACHANNEL_MODELS: frozenset = frozenset({"LK.IPC.A001064"})

    # A001064's role-reversal handshake (the camera echoes our offer back as its
    # own webrtcReq before doing ICE, and won't stream until it gets our
    # webrtcResp) needs the camera armed BEFORE our webrtcReq.  sdes_fast_liveplay
    # sends webrtcReq ~4.5 s earlier, which degrades A001064 media reliability
    # (2/2 -> 1/2 media in a live A/B; the flag was soak-validated only on the
    # A001513 battery cameras).  Exclude role-reversal models from the flag.
    _NO_FAST_LIVEPLAY_MODELS: frozenset = frozenset({"LK.IPC.A001064"})

    # Models confirmed (2026-05-02) to send TUTK-framed data instead of standard
    # SRTP: the camera announces an ASCII-printable fake SDES key and sends
    # packets with a TUTK SFrame header (0xC8 audio / 0xC9 video) and an SSRC
    # that differs from the one advertised in the SDP.  For these the ffmpeg SDP
    # uses plain RTP/AVP (no SRTP decryption attempt) and the bridge strips the
    # TUTK header before forwarding.  Matched by SUBSTRING (see _use_plain_rtp in
    # sdes_open) so a revision suffix is covered.
    _PLAIN_RTP_MODELS: frozenset = frozenset({"A001064", "A001513"})

    @property
    def _offer_should_include_datachannel(self) -> bool:
        model = getattr(getattr(self, "info", None), "model_id", None)
        return model not in self._NO_DATACHANNEL_MODELS

    @property
    def is_sdes_camera(self) -> bool:
        """True when ``properties.enableSdes == '1'`` in the device API response."""
        props = getattr(self, "_raw_device", {}).get("properties") or {}
        return str(props.get("enableSdes", "0")) == "1"

    # Battery / low-power camera models.  ONE list, consumed by
    # is_battery_camera and (through it) by every battery guard and by the
    # livePlayReq/webrtcReq ``powerType`` field - it used to be re-typed inline in
    # three files, which is how a guard drifts out of step with the wire payload.
    # Source: IpcServiceImpl.java B() - powerType=2 for these models, 1 for wired.
    # Substring-matched, so a firmware/hardware revision suffix
    # ("LK.IPC.A001513-1") is covered the way A000088-1 already is on the DTLS
    # side rather than silently reading as a different, mains-powered model.
    _BATTERY_MODELS: frozenset = frozenset({"A001513", "A001108", "A001360"})

    def _battery_evidence(self) -> "Optional[bool]":
        """Does this camera's OWN cloud data say it runs on a battery?

        True when the cloud reports a battery for it, else None ("no evidence" -
        NOT "mains", since the device-list payload may simply not carry the field
        yet).  Same signal ``lan_control.is_mains_powered`` inverts: a camera that
        reports a battery level has a battery.  Never raises - it is read from
        hot paths - and never returns False, so it can only ever ADD a camera to
        the battery set, never take a known model out of it.
        """
        _raw = getattr(self, "_raw_device", None)
        _props = _raw.get("properties") if isinstance(_raw, dict) else None
        if not isinstance(_props, dict):
            _props = {}
        # A reported battery level means there is a battery to report.
        for _key in ("Battery_remaining", "batteryRemaining", "batteryLevel"):
            if _as_int(_props.get(_key)) is not None:
                return True
        # The low-power flag, but ONLY when corroborated.  ``batteryMode=2`` on
        # its own is not evidence: measured against the live cloud payload, every
        # MAINS A000088 on this fleet reports ``batteryMode: '2'`` and nothing
        # else battery-related, while a real battery model reports it alongside
        # actual telemetry (``Battery_remaining``, ``lowPowerStatus``,
        # ``charging``).  Trusting it alone classified four mains cameras as
        # battery, which put powerType=2 on their wire payload and gave them the
        # battery idle window instead of the mains warm-hold.
        #
        # This is the same trap the paragraph below describes for ``powerType`` /
        # ``p2pCache`` - a field that reads 2 on every camera - so it gets the
        # same treatment rather than being taken at face value.  Corroboration is
        # kept (instead of dropping the flag) so a future battery model that
        # names its level differently is still caught by the flag plus any one
        # battery-only field.
        _BATTERY_TELEMETRY = (
            "Battery_remaining", "batteryRemaining", "batteryLevel",
            "lowPowerStatus", "charging",
        )
        if (_as_int(_props.get("batteryMode")) == 2
                and any(_props.get(k) is not None for k in _BATTERY_TELEMETRY)):
            return True
        # Already-parsed status, for a camera refreshed from an attribute push
        # rather than from a device-list dict.
        _status = getattr(self, "status", None)
        if _as_int(getattr(_status, "battery_remaining", None)) is not None:
            return True
        return None

    @property
    def is_battery_camera(self) -> bool:
        """True for battery/low-power cameras (powerType=2 in the app's B()).

        Resolved from the camera's own cloud data FIRST (see
        [[_battery_evidence]]), then from the known-model list
        ([[_BATTERY_MODELS]]).  Evidence leads because a hardcoded list can only
        ever name the revisions we have already seen, and a battery camera that
        is not recognized as one loses every battery protection at once: the SDES
        TURN relay pre-allocation (its ONLY return path - a camera woken through
        the cloud has no LAN host candidate), the cloud keep-alive renew, the
        HTTP wake, and the powerType=2 the camera is told to expect.

        That misdetection presents as "streams from a standalone run but never
        under Home Assistant", because HA is where the LAN-direct options that
        strip the relay actually get set - a one-off script leaves them at their
        (relay-keeping) defaults, so it never trips the guard it is missing.
        """
        if self._battery_evidence():
            return True
        model = getattr(getattr(self, "info", None), "model_id", None) or ""
        return any(m in model for m in self._BATTERY_MODELS)

    @property
    def live_power_type(self) -> int:
        """The ``powerType`` field for livePlayReq / webrtcReq: 2 battery, 1 wired.

        Source: IpcServiceImpl.java B().  Derived from [[is_battery_camera]] so
        the value on the wire and the battery guards can never disagree.
        """
        return 2 if self.is_battery_camera else 1

    def _note_live_play_resp(self, payload) -> None:
        """Record the camera's livePlayResp code for this open (loop thread).

        Called from the signaling dispatcher for every livePlayResp matched to
        this open, whether or not anything is waiting on the future - which
        matters because ``sdes_fast_liveplay`` is on by default and skips that
        wait, so this is the only place the code is seen on the SDES path.
        Best-effort: a malformed payload leaves the record untouched rather than
        raising into the dispatcher.
        """
        try:
            self._last_live_play_code = _as_int(payload.get("code"))
        except (AttributeError, TypeError):
            _LOGGER.debug("camera %s: unparseable livePlayResp payload",
                          getattr(self, "device_id", "?"), exc_info=True)

    def _live_play_not_ready(self) -> bool:
        """Did this open's livePlayResp say the camera is not ready to stream?

        ``-50019`` is NOT a refusal on its own - a camera emits it and then
        recovers via ICE, which is why 0.12.15 stopped treating it as fatal and
        why nothing here aborts an open on it.  Its value is post-hoc: pair it
        with "the session then delivered no media" and you have a waking battery
        camera that was not ready yet, as distinct from a generic failure.  Only
        the retry delay keys on it (see the SDES keepalive loop) - never the
        decision to proceed.
        """
        return getattr(self, "_last_live_play_code", None) == _LIVE_PLAY_NOT_READY

    def _next_dseq(self) -> int:
        """Next livePlayReq dseq (app parity: Q0() starts at 100, increments)."""
        d = self._live_dseq
        self._live_dseq += 1
        return d


    def update_status_from_device(self, device: dict) -> "DeviceStatusData":
        """Refresh camera/diagnostic status from a cloud device dict.

        The device-list payload carries every camera attribute under
        ``properties`` (battery, SD-card, occupancy, motion/night-vision
        settings, ...) plus a top-level ``online`` flag.  This is the reliable,
        always-current source the official app reads, so HA populates camera
        sensors and control-entity states from it instead of an MQTT push the
        camera never sends.  Returns the updated status.
        """
        if not isinstance(device, dict):
            return self.status
        self._raw_device = device
        props = device.get("properties")
        if isinstance(props, dict):
            self.status.update_from_camera_attributes(props)
        if device.get("online") is not None:
            self.status.online = bool(device.get("online"))
            # The cloud explicitly reported reachability - only then may the
            # keepalive loops trust an offline flag (see
            # _backoff_or_offline_pause; DeviceStatusData.online defaults to
            # False, which must not read as "offline").
            self._cloud_online_explicit = True
        return self.status

    def _open_fail_logger(self):
        """Pick the log level for a stream-open failure in the serve/keepalive
        loops: WARNING for a genuine failure, but DEBUG when the cloud has
        explicitly reported the device offline.  A dead/unpowered camera is
        already throttled to ~probe cadence by _backoff_or_offline_pause, so its
        expected open failures should not drip WARNINGs into the log every probe.
        """
        _offline = (not self.status.online) and getattr(self, "_cloud_online_explicit", False)
        return _LOGGER.debug if _offline else _LOGGER.warning

    async def _backoff_or_offline_pause(self, delay: float) -> None:
        """Sleep a reconnect backoff, extended while the device is cloud-offline.

        Normal case (device online, or the cloud never reported an online
        flag): plain ``asyncio.sleep(delay)`` - behavior unchanged.

        When an open just failed AND the cloud has explicitly reported the
        device offline (``update_status_from_device`` saw ``online: false``),
        hold here instead of retrying on the pacer cadence: re-check the flag
        every ``AIDOT_OFFLINE_RECHECK_S`` (default 30 s) and resume the moment
        it flips back on, or fall through after ``AIDOT_OFFLINE_PROBE_S``
        (default 600 s) so one probe open still runs in case the cloud flag is
        stale.  This keeps a dead/unpowered camera from consuming an open-gate
        slot every backoff cycle and starving live cameras' cold opens
        (observed live: two unpowered A000088s cycling 30 s open attempts
        pushed a healthy camera's cold open past two minutes).
        """
        if self.status.online or not getattr(self, "_cloud_online_explicit", False):
            await asyncio.sleep(delay)
            return
        _LOGGER.info(
            "keepalive[%s]: device is cloud-offline - pausing open retries "
            "(recheck %.0fs, probe %.0fs)",
            self.device_id, _OFFLINE_RECHECK_S, _OFFLINE_PROBE_S,
        )
        _t0 = time.monotonic()
        while (_elapsed := time.monotonic() - _t0) < _OFFLINE_PROBE_S:
            await asyncio.sleep(
                min(_OFFLINE_RECHECK_S, max(0.1, _OFFLINE_PROBE_S - _elapsed))
            )
            if not getattr(self, "_streaming_active", False):
                return
            if self.status.online:
                _LOGGER.info(
                    "keepalive[%s]: device back online - resuming opens",
                    self.device_id,
                )
                return
        _LOGGER.debug(
            "keepalive[%s]: offline probe interval elapsed - probing one open",
            self.device_id,
        )

    async def _slow_probe_sleep(self, interval: float) -> None:
        """Sleep `interval` seconds for the DTLS serve loop's slow-probe wait,
        in `_SLOW_PROBE_SLEEP_CHUNK_S` increments rather than one blocking
        `asyncio.sleep(interval)` call, re-checking `_streaming_active` each
        increment.  `interval` can be several minutes; without chunking,
        `stop()` would have to wait out the whole thing before the loop next
        checks whether it should keep running.
        """
        _t0 = time.monotonic()
        while True:
            if not getattr(self, "_streaming_active", False):
                return
            _remaining = interval - (time.monotonic() - _t0)
            if _remaining <= 0:
                return
            await asyncio.sleep(min(_SLOW_PROBE_SLEEP_CHUNK_S, _remaining))

    # -- Camera helpers ------------------------------------------------------ #

    @property
    def _smarthome_base(self) -> str:
        return smarthome_base(self._region)

    def set_token_refresh_cb(self, cb: "Callable") -> None:
        """Register the AidotClient coroutine that refreshes the access token."""
        self._token_refresh_cb = cb

    def set_mqtt_credential_refresh_cb(self, cb: "Callable") -> None:
        """Register the AidotClient coroutine that re-fetches the MQTT password."""
        self._mqtt_credential_refresh_cb = cb

    def _shared_mqtt_password(self) -> Optional[str]:
        """The account's current MQTT password, or None if it holds none.

        Read from the shared ``login_info`` dict, which is the single source of
        truth: it is what the fetch writes and what a broker refusal clears.
        """
        li = self._user_info if isinstance(self._user_info, dict) else {}
        for key in LOGIN_INFO_MQTT_PASSWORD_KEYS:
            val = li.get(key)
            if val:
                return val
        return None

    async def _async_refresh_mqtt_credential(self) -> None:
        """Ask the account client for a fresh MQTT password, if it can supply one.

        Never raises: every caller has fallback strategies, so a failed fetch
        should degrade rather than break a stream open.
        """
        cb = self._mqtt_credential_refresh_cb
        if cb is None:
            return
        # Floor between attempts.  If the freshly fetched password is refused too
        # - another login rotated again, or the endpoint hands back the same value
        # - every stream open would otherwise cost another credential request and
        # another refused connection.  Better to fail this open and let the next
        # one try than to hammer the vendor's endpoint.
        since = asyncio.get_running_loop().time() - self._mqtt_refused_at
        if self._mqtt_refused_at and since < _MQTT_CREDENTIAL_REFETCH_FLOOR:
            _LOGGER.debug(
                "skipping MQTT credential refetch: only %.1fs since the last "
                "refusal (floor %ss)", since, _MQTT_CREDENTIAL_REFETCH_FLOOR,
            )
            return
        try:
            await cb()
        except Exception as exc:
            _LOGGER.debug("MQTT credential refresh failed: %s", exc)

    @staticmethod
    def _is_auth_error(data: Any) -> bool:
        """True if a smarthome response means the token is stale (re-login)."""
        if not isinstance(data, dict):
            return False
        code = data.get("code")
        if code in (21026, 21027, 21041, "21026", "21027", "21041"):
            return True
        return "login again" in str(data.get("desc", "")).lower()

    async def _async_refresh_auth_token(self) -> bool:
        """Refresh the access token via the AidotClient callback (in place)."""
        cb = self._token_refresh_cb
        if cb is None:
            return False
        # A fresh token invalidates the cached smarthome auth / MQTT URL and
        # any cached ICE/TURN config (credentials are bound to the access token).
        self._smarthome_auth = None
        self._mqtt_url = None
        self._cached_ice_config = None
        self._ice_config_expiry = 0.0
        self._cached_device_user_info = None
        self._device_user_info_expiry = 0.0
        try:
            return bool(await cb())
        except Exception as exc:
            _LOGGER.debug("token refresh failed for %s: %s", self.device_id, exc)
            return False

    def _leedarson_headers(self) -> dict:
        # Headers from OkHttp interceptor (b.java): token, appId, terminal auto-injected.
        # NOTE: "owner" is intentionally omitted - the recording/playback endpoints
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

    def _owner_id(self) -> str:
        """The Leedarson ``owner`` (userId) header value some IPC endpoints require.

        ``_leedarson_headers`` deliberately omits ``owner`` (it breaks
        recording/playback); the wake and liveStreamParam endpoints need it.
        """
        return (
            self._user_info.get("owner")
            or self._user_info.get("id")
            or self._user_info.get("userId")
            or str(self.user_id)
        )

    async def _async_post_ok(
        self, url: str, headers: dict, body: str, *, timeout: float = 10.0,
        label: str = "ipc post",
    ) -> bool:
        """POST a JSON ``body`` string to a Leedarson IPC endpoint; True on success.

        Success = HTTP 200 with a ``code`` of 0/200/absent. Best-effort: any
        network/parse error returns False, never raises. Shared by the wake and
        liveStreamParam provisioning calls.
        """
        import aiohttp

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url, headers=headers, data=body,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as resp:
                    status = resp.status
                    data = await resp.json(content_type=None)
            code = data.get("code") if isinstance(data, dict) else None
            ok = status == 200 and (code in (None, 0, 200, "0", "200"))
            _LOGGER.debug("%s %s: status=%s code=%s ok=%s",
                          label, self.device_id, status, code, ok)
            return bool(ok)
        except Exception as exc:
            _LOGGER.debug("%s failed for %s: %s", label, self.device_id, exc)
            return False

    async def _async_http_wake(self) -> bool:
        """Wake a battery camera via the cloud HTTP low-power endpoint.

        Mirrors DeviceWakeUpRepos.j() in the official app (n.java): POST
        ``{smarthome}/api/ipc/devices/{id}/lowPowerActiveState`` with body
        ``{"deviceId": id, "status": "wakeup"}`` and owner+token headers.  The
        cloud forwards the wake to the camera's always-on low-power channel, so it
        reaches a deeply-sleeping camera that has dropped its MQTT session - unlike
        the MQTT ``lowPowerActiveStateReq``, which only lands if the camera is
        already connected.  Returns True if the request was accepted (HTTP 200).
        """
        # The wake endpoint (unlike recording/playback) DOES require owner (n.java:71).
        headers = self._leedarson_headers()
        headers["owner"] = self._owner_id()
        url = (f"{self._smarthome_base}/api/ipc/devices/"
               f"{self.device_id}/lowPowerActiveState")
        body = json.dumps({"deviceId": self.device_id, "status": "wakeup"})
        return await self._async_post_ok(url, headers, body, label="http wake")

    def _live_stream_param_request(self):
        """Build ``(url, headers, body)`` for the liveStreamParam provision call.

        Pure/deterministic - unit-tested in tests/test_live_stream_param.py.  The
        body MUST be a JSON array of device ids (object body -> HTTP 500) and the
        ``owner`` header is required (as on the wake endpoint).
        """
        headers = self._leedarson_headers()
        headers["owner"] = self._owner_id()
        url = f"{self._smarthome_base}/api/ipc/liveStream/liveStreamParam"
        return url, headers, json.dumps([self.device_id])

    async def _async_fetch_live_stream_param(self) -> bool:
        """Provision the camera's live-stream session via the cloud (app parity).

        **Not called** - [[_resolve_live_stream_param]] gates this and always says
        no; see there for why.  Kept, with its request shape locked down by
        tests/test_live_stream_param.py, so re-enabling it for a camera that
        demonstrably needs it is a one-line change rather than a rediscovery.

        The official app (``KVSPreConnectStrategy.fetchKvsParams``) POSTs the
        device id to ``/api/ipc/liveStream/liveStreamParam``; the cloud provisions
        the session (and brings the camera online) and returns AWS KVS
        credentials.  Only the provisioning side effect was ever wanted here - the
        library streams over the proprietary MQTT/SDES path, not AWS KVS - but
        that side effect is precisely the problem: the camera then sends its media
        toward KVS and our bridge receives no video RTP.  Best-effort: returns True
        on HTTP 200.
        """
        url, headers, body = self._live_stream_param_request()
        return await self._async_post_ok(url, headers, body, label="liveStreamParam")

    async def async_wake_camera(self, retries: int = 2) -> bool:
        """Wake a battery camera on demand via the cloud HTTP low-power endpoint.

        Mirrors the official app's wake (DeviceWakeUpRepos.k()), which fires the
        HTTP wake so a sleeping camera (no live MQTT session) still gets the signal
        through the cloud, and retries on failure (n.java onError "retrying").  The
        MQTT ``lowPowerActiveStateReq`` is also published by the streaming /
        attribute paths; this adds the reliable cloud-side channel.  Non-battery
        cameras are always reachable, so this is a no-op for them.
        """
        if not self.is_battery_camera:
            return True
        for _attempt in range(max(1, retries)):
            if await self._async_http_wake():
                return True
            await asyncio.sleep(1.0)
        return False

    async def _async_get_mqtt_url(self) -> Optional[str]:
        # Fetch and cache the WSS MQTT broker URL (and MQTT credentials) from
        # getServerUrlConfig.  The full response is stored in self._smarthome_auth
        # so mqttUser / mqttPassword are captured in the same call.
        if self._mqtt_url:
            return self._mqtt_url

        # Test seam: point the whole client at a local broker without any cloud
        # call (paho derives ws-vs-wss and the port from the scheme, so a plain
        # "ws://127.0.0.1:PORT/mqtt" needs nothing else).  Unset in production.
        _env_mqtt = os.environ.get("AIDOT_MQTT_URL")
        if _env_mqtt:
            _LOGGER.debug("AIDOT_MQTT_URL override in effect: %s", _env_mqtt)
            self._mqtt_url = _env_mqtt
            return self._mqtt_url

        import aiohttp

        async def _fetch():
            _hdrs = {k: v for k, v in self._leedarson_headers().items()
                     if k != "Content-Type"}
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self._smarthome_base}/commonController/getServerUrlConfig",
                    headers=_hdrs,
                    params={"version": "1.0.1", "clientId": f"app-{self.user_id}"},
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    return await resp.json(content_type=None)

        try:
            body = await _fetch()
            if self._is_auth_error(body) and await self._async_refresh_auth_token():
                body = await _fetch()  # retry once with the refreshed token

            data = body.get("data") or {}
            _LOGGER.debug("getServerUrlConfig: mqtt=%s ip=%s", data.get("mqttServerUrl"), data.get("ip"))

            mqtt_host = data.get("mqttServerUrl") or ""
            if not mqtt_host:
                # Fall back to the regional MQTT broker URL known to work from
                # the AiDot web client: wss://{region}-mqtt.arnoo.com:8443/mqtt
                # Redacted: `data`/`body` carries mqttPassword; log only the
                # non-sensitive key names present, mirroring the hasPwd-style
                # redaction of the debug log below.
                _LOGGER.warning(
                    "getServerUrlConfig returned no mqttServerUrl; "
                    "using regional fallback. keys=%s", sorted(data)
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

        Strategy order - stops at first success:
          0. Already cached, and still agreeing with the account-shared login_info
          1. mqttPassword in AiDot login_info, fetching it first if absent
          2. GET /user/getUser  <- documented SDK step (reqUserAuthInfoWithCallback)
             Returns LDSAuthInfo {userId, mqttUser, mqttPassword, ...}
          3. getServerUrlConfig response side-effect (if MQTT URL not yet fetched)
          4. accessToken as MQTT password (Arnoo broker fallback)
        """
        # Strategy 0.  This cache is per device client but the credential is per
        # account, so the shared login_info wins any disagreement: when a broker
        # refusal cleared or replaced the account's password, a sibling camera's
        # cache still holds the dead one, and trusting it would refuse again on
        # every camera in turn.  Treating the cache as cold whenever it disagrees
        # makes login_info the single source of truth.
        _cached_pwd = (self._smarthome_auth or {}).get("mqttPassword")
        if _cached_pwd and _cached_pwd == self._shared_mqtt_password():
            return self._smarthome_auth
        # An empty login_info is not automatically "nothing to disagree with": it
        # is exactly the post-invalidation state, since a refusal pops the shared
        # password but can only null the cache on the ONE client whose connection
        # was refused.  So a cache that CAME from login_info is stale here, while
        # one from /user/getUser or the accessToken fallback is per client and has
        # no shared counterpart to compare against.  Strategy 1 stamps its source
        # precisely so the two can be told apart.
        _cached_src = ((self._smarthome_auth or {}).get("raw") or {}).get("source") or ""
        _from_shared = _cached_src.startswith("login_info.")
        if _cached_pwd and self._shared_mqtt_password() is None and not _from_shared:
            return self._smarthome_auth
        if _cached_pwd:
            self._smarthome_auth = None

        import aiohttp

        # Smarthome userId - 'id' in AiDot login_info is the Leedarson userId
        _mqtt_id = (
            self._user_info.get("id")
            or self._user_info.get("userId")
            or str(self.user_id)
        )

        # --- Strategy 1: mqttPassword in AiDot login_info, fetched if absent ---
        # The password is never persisted (it rotates on every account login), so
        # login_info has none after a restart from a stored token, and a broker
        # refusal clears it deliberately.  Fetch before reading, or the strategies
        # below shadow the absence: strategy 4 always "succeeds" with the access
        # token, which the broker then refuses, and the retry loops forever.
        if self._shared_mqtt_password() is None:
            await self._async_refresh_mqtt_credential()
        for key in LOGIN_INFO_MQTT_PASSWORD_KEYS:
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
        return f"{aidot_api_base(self._region)}/v21"

    @property
    def _aidot_v32_base(self) -> str:
        return f"{aidot_api_base(self._region)}/v32/api/ipc"

    def _aidot_headers(self) -> dict:
        # Auth headers for the AiDot platform API (prod-{region}-api.arnoo.com).
        # Matches AidotClient.async_session_get(): CONF_APP_ID="Appid", APP_ID,
        # CONF_TOKEN="Token", CONF_TERMINAL="Terminal" (see login_const.py/const.py).
        token = (self._user_info.get("accessToken")
                 or self._user_info.get("access_token") or "")
        return {
            "Appid":        _AIDOT_APP_ID,
            "Token":        token,
            "Terminal":     "app",
            "Content-Type": "application/json",
        }

    _DEVICE_USER_INFO_TTL = 300.0  # seconds; no server ttl, so a fixed cap

    def _store_device_user_info(self, item: "Optional[dict]") -> "Optional[dict]":
        """Cache the extracted per-device user info and return it (pass-through).

        Used at every success return of [[async_get_device_user_info]] so caching
        happens at one site.  A falsy/None item is NOT cached (fail-safe to a
        re-fetch next open).  TTL-bounded by `_DEVICE_USER_INFO_TTL` since there
        is no server-provided ttl."""
        if item:
            self._cached_device_user_info = item
            self._device_user_info_expiry = time.time() + self._DEVICE_USER_INFO_TTL
        return item

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
        if (self._cached_device_user_info is not None
                and time.time() < self._device_user_info_expiry):
            _LOGGER.debug("device_user_info: cache hit (%.0fs left)",
                          self._device_user_info_expiry - time.time())
            return self._cached_device_user_info
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

            # Server may return a bare JSON array OR {"data": [...]} / {"data": {}}
            if isinstance(body, list):
                data = body
                _LOGGER.debug("batchGetDeviceUserInfo bare-list response for %s: %d items",
                              self.device_id, len(data))
            elif isinstance(body, dict):
                data = body.get("data") or {}
                # Keys, never values: this response can carry the per-device
                # streaming credentials (tutkAccount / tutkPassword - see
                # docs/DEFERRED_FEATURES.md), and the warning below is logged
                # at default level, so a whole-body dump lands in every user's
                # home-assistant.log.  The matched-device log further down
                # already prints keys only; these two did not.
                if data:
                    _LOGGER.debug(
                        "batchGetDeviceUserInfo response for %s (status=%d):"
                        " keys=%s, %d item(s)",
                        self.device_id, status, sorted(body.keys()), len(data),
                    )
                else:
                    _LOGGER.warning(
                        "batchGetDeviceUserInfo no data for %s (status=%d): keys=%s",
                        self.device_id, status, sorted(body.keys()),
                    )
            else:
                data = {}

            # Find the entry for this device
            if isinstance(data, dict):
                item = data.get(self.device_id) or next(iter(data.values()), None)
                return self._store_device_user_info(item)
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
                        return self._store_device_user_info(item)
                # No exact match found - log which device IDs were present so
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
                    " - falling back to data[0].  Device IDs in response: %s"
                    "  (wrong userId will cause broken MQTT topics and missing"
                    " TURN credentials)",
                    self.device_id, _found_ids,
                )
                return self._store_device_user_info(data[0] if data else None)
        except Exception as exc:
            _LOGGER.error("async_get_device_user_info failed for %s: %s",
                          self.device_id, exc)
        return None

    async def async_get_p2p_uid(self) -> Optional[str]:
        """Fetch the TUTK P2P UID for this camera.

        Tries several sources in order:
          1. POST /v21/devices/batchGetDeviceUserInfo       (AiDot platform API)
          2. POST /v5/deviceController/getP2pId?deviceId=...  (Leedarson smarthome)
          3. AiDot v32 IPC device detail                    (fallback)
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

        # --- Source 2: Leedarson smarthome /v5/deviceController/getP2pId ---
        # The Android app (MutiCameraActivity) calls
        #   POST {base}/v5/deviceController/getP2pId?deviceId={deviceId}
        # with the deviceId as a URL QUERY param and an EMPTY body (GET is
        # rejected "method not supported"; a JSON body is rejected "deviceId not
        # present"). The UID comes back as data.p2pId / data. NOTE: observed to
        # return code=200 data=null when the camera is idle - the cloud appears
        # to only hand out the p2pId in some session/provisioning state we have
        # not yet reproduced; left as a best-effort source.
        headers = {k: v for k, v in self._leedarson_headers().items()
                   if k != "Content-Type"}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self._smarthome_base}/v5/deviceController/getP2pId"
                    f"?deviceId={self.device_id}",
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    body = await resp.json(content_type=None)

            data = body.get("data") if isinstance(body, dict) else None
            uid = None
            if isinstance(data, dict):
                uid = data.get("p2pId") or data.get("uid")
            elif isinstance(data, str):
                uid = data
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
        seq: "Optional[str]" = None,
        expect_ack: bool = True,
    ) -> bool:
        """Connect MQTT, optionally wake battery camera, publish command, wait for ack.

        ``expect_ack=False`` reports whether the command was PUBLISHED, not
        whether the camera answered. That is the honest result for an action
        whose success removes the camera from the network -- a reboot acks by
        going away, so waiting for one turns a working command into a False.

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
        # Payload from DeviceWakeUpRepos.java - no srcAddr/seq/tst.
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

        if self._resolve_persistent_mqtt():
            pm = await self._get_persistent_mqtt()
        else:
            pm = None
        if pm is not None:
            messages, _st = await pm.request(
                publish_items=publish_items,
                subscribe_topics=sub_topics,
                timeout=timeout,
            )
            if _st and _st.get("error"):
                # Persistent connection unavailable - fall back to a fresh per-op
                # connect so the command isn't silently dropped (and isn't falsely
                # reported as sent on the empty result the persistent path returns).
                _LOGGER.debug(
                    "_mqtt_device_cmd: persistent MQTT failed (%s); falling back "
                    "to a per-op session for %s", _st.get("error"), device_id,
                )
                messages, _st = await _mqtt_session_with_status(
                    mqtt_url, mqtt_user, mqtt_pwd, client_id,
                    subscribe_topics=sub_topics,
                    publish_items=publish_items,
                    duration=timeout,
                )
        else:
            messages, _st = await _mqtt_session_with_status(
                mqtt_url, mqtt_user, mqtt_pwd, client_id,
                subscribe_topics=sub_topics,
                publish_items=publish_items,
                duration=timeout,
            )

        # A fire-and-forget caller only needs to know the publish left the host.
        # `_st` separates that from "no ack came back", which the ack scan below
        # cannot: it returns False for a failed publish and for a camera that
        # rebooted before answering.
        if not expect_ack:
            _published = not (_st and _st.get("error"))
            _LOGGER.info(
                "_mqtt_device_cmd: published without waiting for an ack "
                "(topic=%s published=%s)", pub_topic, _published)
            return _published

        # Two passes, because being sure is worth more than being quick. A
        # response carrying OUR seq is proof; anything else on these topics is
        # only evidence that SOMETHING was acked - and several things are in
        # flight here (the battery wake goes out alongside the write, and Home
        # Assistant writes attributes in bursts).
        for topic, raw in messages:
            if ack_keyword and ack_keyword not in topic:
                continue
            try:
                msg = _json.loads(raw)
            except Exception:
                continue
            mine = _ack_matches_seq(msg, seq)
            if mine is True:
                _LOGGER.debug("device cmd ack 200 for seq=%s: topic=%s", seq, topic)
                return True
            if mine is not False:
                # The camera answered OUR command with a non-200. Logged, not
                # acted on: whether this firmware ever sends one is unknown, and
                # turning it into a failure on a guess would report every
                # working write as broken the moment the guess is wrong. If
                # these show up in the wild, that is the evidence needed to make
                # it a real error.
                _LOGGER.warning(
                    "device cmd for %s answered with code %s (seq=%s, topic=%s) "
                    "- reporting the command as sent anyway; please report this "
                    "log line, it is the evidence needed to handle it properly",
                    device_id, mine, seq, topic,
                )

        for topic, raw in messages:
            if ack_keyword and ack_keyword not in topic:
                continue
            try:
                msg = _json.loads(raw)
            except Exception:
                continue
            if _ack_matches_seq(msg, seq) is not False:
                continue  # already considered above
            code = (msg.get("ack") or {}).get("code") or msg.get("code")
            if code == 200:
                _LOGGER.debug("device cmd ack 200 (unattributed): topic=%s", topic)
                return True
            # Some firmware ACKs with code in payload.payload
            inner = msg.get("payload") or {}
            if isinstance(inner, dict) and inner.get("code") == 200:
                _LOGGER.debug(
                    "device cmd ack 200 (inner, unattributed): topic=%s", topic)
                return True

        # Fire-and-forget fallback: the official app uses a delivery callback,
        # not a device response, so a published command with no 200-ack is
        # normal. But only treat it as success if the broker connection actually
        # succeeded - a refused/failed connection returns an empty message list
        # too, and reporting that as "sent" makes HA show a state change that
        # never reached the camera.
        if messages is not None and _mqtt_publish_delivered(_st):
            _LOGGER.debug(
                "device cmd: sent (no explicit 200-ack on %s, %d msgs total) "
                "- treating as sent-ok (official app is fire-and-forget)",
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
        Local-first: if a LAN control client is attached (see
        :meth:`attach_lan_client`) and reachable, the attribute is set over the
        LAN and the cloud round-trip is skipped; any LAN failure falls through to
        the MQTT path below.
        """
        import json as _json
        import random as _random
        import time as _time

        lan = getattr(self, "_lan_client", None)
        if lan is not None:
            try:
                if await lan.async_set_attributes({attr: value}):
                    return True
            except Exception as _exc:
                _LOGGER.debug("LAN set %s failed (%s); falling back to cloud", attr, _exc)

        device_id = self.device_id
        user_id   = self.user_id
        # camera's local password (from device API dict 'password' field)
        cam_pwd   = getattr(getattr(self, "info", None), "device_password", "") or ""
        seq = f"ap{_random.randint(1000000, 9999999)}"
        # Web app JS (app-beautified.js:26551) includes userId + password in payload;
        # b6.java does not - camera accepts both, but web format is more complete.
        inner: dict = {"devId": device_id, "attr": {attr: value}}
        if user_id:
            inner["userId"] = str(user_id)
        if cam_pwd:
            inner["password"] = cam_pwd
        # `tst` matches the app, which stamps every setDevAttrReq and
        # devActionReq it builds. The camera accepts the message without it --
        # this path is proven and reads back within one poll -- so this is
        # parity rather than a fix; it costs nothing and removes one more way
        # our traffic differs from the vendor's.
        payload = _json.dumps({
            "id":      device_id,
            "method":  "setDevAttrReq",
            "service": "device",
            "seq":     seq,
            "tst":     int(_time.time() * 1000),
            "payload": inner,
        })
        pub_topic = f"iot/v1/c/{device_id}/device/setDevAttrReq"
        _LOGGER.info("setDevAttrReq: %s=%s -> %s  seq=%s", attr, value, device_id, seq)
        ok = await self._mqtt_device_cmd(
            pub_topic, payload, timeout=timeout, ack_keyword="setDevAttr",
            seq=seq)
        if ok:
            # Reflect the change in local status right away (optimistic), so HA
            # control entities show the new value immediately instead of waiting
            # for the next 5-min cloud-properties poll.  Cameras don't push
            # setDevAttrNotif, so the poll is the only confirmation; it
            # re-validates this on its next run.  Uses the same parser as the
            # poll, so only known attributes update (others are no-ops).
            try:
                self.status.update_from_camera_attributes({attr: value})
            except Exception:
                _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), 'async_set_device_attribute', exc_info=True)
        return ok

    async def async_query_device_action(
        self,
        action: str,
        params=None,
        *,
        timeout: float = 8.0,
    ):
        """Send a read-only devActionReq and return the camera's ``out`` payload.

        :meth:`async_trigger_device_action` answers "did it go", which is all a
        control needs. But the camera *answers* its ``get`` actions with real
        data -- wifi details, SD capacity, which sound algorithms are armed --
        and none of that was reachable while the only helper returned a bool.

        Returns the decoded ``out`` exactly as the camera sent it (list or
        dict), or ``None`` when nothing came back. ``None`` means UNKNOWN, not
        "off": several of these actions answer with ``out: null`` on models that
        do not implement them, and a caller that reads that as a disabled
        feature will report a camera as having something switched off when it
        simply cannot say.

        Deliberately built on the module-level session helper rather than on
        :meth:`_mqtt_device_cmd`: that method reduces a reply to a bool and is
        the proven control path, so it is left alone.
        """
        import json as _json
        import random as _random
        import time as _time

        user_id   = self.user_id
        device_id = self.device_id
        smarthome_auth = await self._async_get_smarthome_auth()
        mqtt_url = await self._async_get_mqtt_url()
        if not mqtt_url:
            _LOGGER.debug("async_query_device_action: no MQTT URL for %s", device_id)
            return None
        mqtt_user = (smarthome_auth or {}).get("mqttUser") or str(user_id)
        mqtt_pwd  = (smarthome_auth or {}).get("mqttPassword") or ""
        client_id = (self._user_info.get("mqttClientId") or f"app-{mqtt_user}")

        _dev = self._camera_properties() or {}
        parent_id = (getattr(getattr(self, "info", None), "direct_id", None)
                     or _dev.get("directId") or _dev.get("parentId") or device_id)
        seq = f"ap{_random.randint(1000000, 9999999)}"
        payload = _json.dumps({
            "method":  "devActionReq",
            "service": "device",
            "seq":     seq,
            "tst":     int(_time.time() * 1000),
            "payload": {
                "devId":    device_id,
                "parentId": parent_id,
                "action":   action,
                "in":       params if params is not None else [],
            },
        })
        publish_items = [
            (f"iot/v1/s/{user_id}/device/devActionReq", payload),
        ]
        sub_topics = [f"iot/v1/c/{user_id}/#", f"iot/v1/cb/{user_id}/#"]

        # Use the PERSISTENT connection when there is one, exactly as
        # `_mqtt_device_cmd` does. Opening a fresh session here instead looked
        # harmless and is not: it connects with the same `mqttClientId` the
        # long-lived connection is already using, and a broker evicts the older
        # session on a duplicate client id. Inside Home Assistant that means the
        # query and the integration's own connection knock each other off, and
        # the reply never arrives -- the request appears to work and simply
        # returns nothing. It only "worked" when tested with the integration
        # stopped, which is the one condition that hides the conflict.
        messages = []
        pm = await self._get_persistent_mqtt() if self._resolve_persistent_mqtt() else None
        if pm is not None:
            messages, _st = await pm.request(
                publish_items=publish_items,
                subscribe_topics=sub_topics,
                timeout=timeout,
            )
            if _st and _st.get("error"):
                _LOGGER.debug(
                    "async_query_device_action: persistent MQTT failed (%s); "
                    "falling back for %s", _st.get("error"), device_id)
                pm = None
        if pm is None:
            messages, _st = await _mqtt_session_with_status(
                mqtt_url, mqtt_user, mqtt_pwd, client_id,
                subscribe_topics=sub_topics,
                publish_items=publish_items,
                duration=timeout,
            )
        # Several devAction messages can be in flight on a shared connection,
        # and some carry no `out` at all (a bare acknowledgement). Taking the
        # first match therefore loses data: a camera reporting six sound
        # detectors surfaced only the two from whichever reply arrived first.
        # So prefer a reply that actually carries a payload, and only fall back
        # to an empty one when nothing better arrived.
        # Two passes' worth of preference, resolved in one:
        #   best  - right device, right action, our seq, and a payload
        #   good  - right device, right action, a payload
        # `seq` is a PREFERENCE, never a filter. Requiring it looked tidy and
        # was wrong: a camera that does not echo our seq has every one of its
        # replies discarded, and the call then reports "no reply" for a camera
        # that answered. Observed live as `no reply from <device> (4 messages
        # seen)` -- four candidates rejected on the seq alone.
        best = good = None
        _empty_seen = False
        for topic, raw in messages:
            if "devAction" not in topic:
                continue
            try:
                msg = _json.loads(raw)
            except Exception:
                continue
            body = msg.get("payload") or {}
            if body.get("action") != action:
                continue
            # Match the DEVICE too. The persistent connection is subscribed to
            # the whole account (`iot/v1/c/{userId}/#`), so replies for every
            # camera arrive here -- matching on the action alone lets one
            # camera read another's answer. Observed live: four cameras all
            # reported the same SD figures, which belonged to whichever camera
            # answered first.
            # The device match IS a filter: the persistent connection carries
            # the whole account, and without this one camera reads another's
            # answer (observed live as four cameras reporting identical SD
            # figures).
            _rid = body.get("devId") or msg.get("id")
            if _rid and _rid != device_id:
                continue
            out = body.get("out")
            if out is None:
                _empty_seen = True
                continue
            if msg.get("seq") == seq:
                best = out
                break
            if good is None:
                good = out
        if best is not None:
            return best
        if good is not None:
            _LOGGER.debug(
                "devActionReq %s: accepted a reply for %s without a seq match",
                action, device_id)
            return good
        if _empty_seen:
            _LOGGER.debug("devActionReq %s: only empty replies from %s",
                          action, device_id)
            return None
        # Never return None silently: a caller cannot tell "unsupported" from
        # "the reply never came back", and a silent None is what made this
        # failure invisible for an entire debugging session.
        _LOGGER.info("devActionReq %s: no reply from %s (%d messages seen)",
                     action, device_id, len(messages))
        return None

    async def async_trigger_device_action(
        self,
        action: str,
        params,
        *,
        timeout: float = 4.0,
        expect_ack: bool = True,
    ) -> bool:
        """Send a devActionReq (e.g. siren/alarm trigger).

        Correct format from decompiled APK (b6.java h0()):
          Topic:   iot/v1/s/{userId}/device/devActionReq
          Payload: {"method": "devActionReq", "service": "device",
                    "payload": {"devId": deviceId, "action": action, "in": params}}
        """
        import json as _json
        import random as _random
        import time as _time

        user_id   = self.user_id
        device_id = self.device_id

        # The app's own builder (main chunk, DeviceControl) sends five things we
        # did not: `seq`, `tst`, and a `parentId` alongside `devId`. The camera
        # answers nothing at all to a devActionReq without them -- a RebootFunc
        # sent in the short form drew zero replies and did not reboot, while the
        # same action with these fields is what the settings page uses.
        #
        # `password` is deliberately NOT sent: the H5 passes it to its wrapper,
        # but the wrapper does not put it on the wire, and a read-only
        # `WifiBaseInfo` acks without it.
        _dev = self._camera_properties() or {}
        parent_id = (getattr(getattr(self, "info", None), "direct_id", None)
                     or _dev.get("directId") or _dev.get("parentId") or device_id)
        seq = f"ap{_random.randint(1000000, 9999999)}"
        payload = _json.dumps({
            "method":  "devActionReq",
            "service": "device",
            "seq":     seq,
            "tst":     int(_time.time() * 1000),
            "payload": {
                "devId":    device_id,
                "parentId": parent_id,
                "action":   action,
                "in":       params,
            },
        })
        pub_topic = f"iot/v1/s/{user_id}/device/devActionReq"
        _LOGGER.info("devActionReq: %s %s -> %s", action, params, device_id)
        return await self._mqtt_device_cmd(
            pub_topic, payload, timeout=timeout, ack_keyword="devAction",
            seq=seq, expect_ack=expect_ack)

    # Convenience wrappers - confirmed attribute names/types from APK source











    def _camera_properties(self) -> "Optional[dict]":
        """This camera's `properties` dict from the cloud device list.

        The same source the reference integration reads to populate every
        entity, and the one path proven to reflect writes on every model - a
        control set through it reads back within one poll on an A000088, an
        A001064 and an A001513. Used as the fallback when a camera does not
        answer the presence announce.
        """
        # The device client holds its own raw device dict; it does NOT have the
        # account-wide async_get_all_device, which is on AidotClient. Reading
        # the local copy also avoids a cloud round-trip on a path that has
        # already spent its timeout waiting for a push.
        raw = getattr(self, "_raw_device", None)
        if isinstance(raw, dict):
            return raw.get("properties") or None
        return None

    async def async_get_camera_attributes(
        self,
        *,
        timeout: float = 8.0,
    ) -> Optional[dict]:
        """Read camera attributes via the camera's own push (setDevAttrNotif).

        **Returns attributes on every model.** A battery camera answers the
        presence announce and its push is returned as-is - that is what the
        wake-then-read sequence below exists for, so a sleeping camera reports
        battery, SD-card and occupancy. Mains cameras answer with nothing at
        all (measured on an A000088 and an A001064), so rather than report
        failure for a reason that has nothing to do with the caller, this falls
        back to the device's own ``properties`` dict - the same source that
        populates every entity in the reference integration, and the one path
        proven to reflect writes on all three model families.

        Note the two sources differ in shape: a push carries only what changed
        (often a single key), while the fallback carries the device's full
        property set (99 keys on an A000088, 87 on an A001064). Treat the
        result as "what this camera reports", not as a fixed schema.

        This did not work at all until 2026-08-15. It appended ``-cmd`` to the
        registered ``mqttClientId``, and the broker binds the credential to
        that exact string: the connect was refused outright with CONNACK rc=4,
        "Bad user name or password", so there was no session, no subscription
        and nothing to receive. Three separate readings blamed the camera
        before anyone asked the transport, because the helper in use returns
        messages and drops the status behind a suppressed warning.

        The suffix was presumably there to avoid evicting whoever legitimately
        holds that id, since a duplicate connect displaces it. The answer to
        that is the shared persistent connection, now preferred unconditionally
        - same identity, no second connect. The one-off fallback uses the exact
        id and declines outright while a stream is active, because losing
        someone's video to read a settings dict is a bad trade.

        **Caveat worth knowing:** that guard only sees streams on *this*
        client. Calling the fallback path from a second process while a Home
        Assistant instance is connected will displace HA's MQTT session,
        because there is one authorized client id per account and a duplicate
        connect wins. In-process there is no issue - the persistent connection
        is shared and no second connect happens.

        Mirrors the official app flow (l.java + IpcServiceImpl.java):
          1. Subscribe iot/v1/c/{userId}/# and iot/v1/cb/{deviceId}/#
          2. Publish iot/v1/cb/{userId}/user/connect  (triggers camera to push state)
          3. For battery cameras: publish lowPowerActiveStateReq to wake from deep sleep
          4. Wait for camera-pushed setDevAttrNotif

        Returns the ``attr`` dict on success, else None.
        """
        import json as _json
        import time as _time

        # Wake battery cameras via the cloud HTTP low-power endpoint first, so a
        # deeply-sleeping camera (no live MQTT session) actually pushes its
        # setDevAttrNotif (battery / SD-card / occupancy) - otherwise those sensors
        # stay "unknown".  The MQTT lowPowerActiveStateReq below is the second
        # channel.  No-op for non-battery / already-awake cameras.
        if self.is_battery_camera:
            try:
                await self.async_wake_camera()
            except Exception:
                _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), 'async_get_camera_attributes', exc_info=True)

        smarthome_auth = await self._async_get_smarthome_auth()
        mqtt_user = (smarthome_auth or {}).get("mqttUser") or str(self.user_id)
        mqtt_pwd  = (smarthome_auth or {}).get("mqttPassword") or ""
        _base_cid = (self._user_info.get("mqttClientId") or f"app-{mqtt_user}")
        # The broker binds the credential to the EXACT registered mqttClientId.
        # A suffixed connect is refused outright with CONNACK rc=4, "Bad user
        # name or password" - so the "-cmd" id this used to build could never
        # establish a session, subscribe to anything, or receive a reply.  It
        # was not a subtly wrong id; it was no session at all.  (Measured
        # 2026-08-14 with Home Assistant disabled so nothing competed: suffixed
        # refused, exact accepted.)
        #
        # The suffix was presumably there to avoid evicting the connection that
        # legitimately holds this id, since a duplicate connect displaces it.
        # The right answer to that is the shared persistent connection below -
        # same identity, no second connect - which is why it is now preferred
        # unconditionally rather than only under AIDOT_PERSISTENT_MQTT.
        client_id = _base_cid
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

        # Announce user presence - triggers online cameras to push setDevAttrNotif.
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
        # exits deep sleep and responds.  Payload from DeviceWakeUpRepos.java -
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

        _sess_st = None          # transport status, when a per-op session ran
        # Prefer the shared connection whatever the env var says: it already
        # holds the only client id this broker accepts, so riding it avoids
        # both the refused connect and the eviction the fallback risks.
        try:
            pm = await self._get_persistent_mqtt()
        except Exception:
            _LOGGER.debug("camera %s: persistent MQTT unavailable for attribute read",
                          getattr(self, "device_id", "?"), exc_info=True)
            pm = None
        if pm is not None:
            messages, _st = await pm.request(
                publish_items=publish_items,
                subscribe_topics=sub_topics,
                timeout=timeout,
            )
            if _st and _st.get("error"):
                # Persistent connection unavailable - fall back to a fresh per-op
                # connect so a transient outage doesn't masquerade as "no attrs".
                _LOGGER.debug(
                    "async_get_camera_attributes: persistent MQTT failed (%s); "
                    "falling back to a per-op session for %s",
                    _st.get("error"), device_id,
                )
                if getattr(self, "_streaming_active", False):
                    # The fallback connects with the id a live stream is using,
                    # and a duplicate connect evicts it. Losing someone's video
                    # to read a settings dict is a bad trade, so decline.
                    _LOGGER.info(
                        "async_get_camera_attributes: %s is streaming and the "
                        "persistent connection is unavailable; declining rather "
                        "than evicting the stream's MQTT session.",
                        device_id,
                    )
                    return None
                messages, _sess_st = await _mqtt_session_with_status(
                    mqtt_url, mqtt_user, mqtt_pwd, client_id,
                    subscribe_topics=sub_topics,
                    publish_items=publish_items,
                    duration=timeout,
                )
        else:
            # Status-bearing on purpose. The plain wrapper returns messages and
            # drops the transport status, so "the broker refused our connect"
            # and "the camera stayed quiet" both arrive as an empty list. That
            # ambiguity is what let a client id the broker rejects outright go
            # unnoticed through three investigations.
            messages, _sess_st = await _mqtt_session_with_status(
                mqtt_url, mqtt_user, mqtt_pwd, client_id,
                subscribe_topics=sub_topics,
                publish_items=publish_items,
                duration=timeout,
            )
        if _sess_st and not _sess_st.get("connected"):
            _LOGGER.warning(
                "async_get_camera_attributes: no MQTT session for %s (rc=%s %s) - "
                "this is a transport failure, not the camera staying quiet.",
                device_id, _sess_st.get("rc"), _sess_st.get("rc_str"),
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

        # No push. Mains cameras never answer the announce - measured on an
        # A000088, while an A001513 answers - so returning None would make this
        # useless on half the fleet for a reason that has nothing to do with
        # the caller. The cloud device list carries the same attributes and is
        # what populates every entity in the reference integration, so fall
        # back to it rather than reporting failure.
        try:
            _props = self._camera_properties()
        except Exception:
            _props = None
            _LOGGER.debug("camera %s: property fallback failed", device_id, exc_info=True)
        if _props:
            _LOGGER.debug(
                "async_get_camera_attributes: %s pushed nothing; returning %d "
                "attributes from the device list instead.", device_id, len(_props),
            )
            return _props
        _LOGGER.info(
            "async_get_camera_attributes: %s pushed no setDevAttrNotif and the "
            "device list carried no properties either.", device_id,
        )
        return None

    async def async_get_recent_recordings(self, total: int = 10) -> "List[dict]":
        """The camera's most recent cloud event recordings.

        A second listing API, and the one the vendor app actually uses on its
        event page. Captured 2026-04-05:

            POST /api/ipc/playback/getRecentEventRecordingList
                 {"deviceIds": [...], "total": 3}

        **Both listings work; the zeros were the account** (measured
        2026-08-11). Every fleet run had reported zero events from every camera
        through this call AND through `async_get_cloud_recordings`, which read
        as two broken listings. On the OWNER account, on the same fleet, ninety
        minutes after a run that reported zero: this call returns the full count
        it asks for on six of seven cameras, and the range query returns a full
        first page against server totals of 121-1517 over thirty days. The
        seventh camera has no events by any method.

        The fleet runs use a shared-home member. The same runs report no cloud
        thumbnail either, and the owner/member thumbnail split was measured
        separately on 2026-08-09 - so an account seeing neither is behaving as
        the member, not meeting a defect. Read a zero from this method as a
        question about the account before reading it as a fault.

        Two shape differences from every other call in this class, and both
        would break the usual handling:

        * the response is a BARE JSON ARRAY, not the ``{"code": ..., "data":
          ...}`` envelope, so there is no code to check and no ``data`` to
          unwrap;
        * there is no pagination - ``total`` is "how many do you want", not a
          page size.

        Each item carries ``eventUuid``, ``eventTime`` (epoch ms), ``deviceId``,
        ``deviceName``, ``eventCodeList``, ``eventDescList`` and ``picUrl``.
        Filtered to THIS camera, because the app asks for a whole house at once
        and the reply is not per-device.
        """
        import aiohttp

        body = {"deviceIds": [self.device_id], "total": max(1, int(total))}

        async def _fetch():
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self._aidot_v32_base}/playback/getRecentEventRecordingList",
                    json=body,
                    headers=self._aidot_headers(),
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    return await resp.json(content_type=None)

        try:
            data = await _fetch()
            # The auth check reads a dict; a list is already a success here.
            if isinstance(data, dict):
                if self._is_auth_error(data) and await self._async_refresh_auth_token():
                    data = await _fetch()
            if isinstance(data, dict):
                # An envelope means an error, since success is a bare array.
                _LOGGER.warning(
                    "getRecentEventRecordingList code=%s msg=%s for %s",
                    data.get("code"), data.get("desc") or data.get("msg"),
                    self.device_id,
                )
                return []
            if not isinstance(data, list):
                return []
            mine = [e for e in data
                    if isinstance(e, dict)
                    and e.get("deviceId") in (None, self.device_id)]
            _LOGGER.info(
                "getRecentEventRecordingList for %s: %d of %d event(s)",
                self.device_id, len(mine), len(data),
            )
            return mine
        except Exception as exc:
            _LOGGER.warning(
                "getRecentEventRecordingList failed for %s: %s",
                self.device_id, exc)
            return []

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
        The server caps a page at 10 items whatever ``page_size`` says -
        measured 2026-08-11 across seven cameras, and the vendor's own client
        hard-overwrites the field to 10 (5 for a multi-device request), so it
        is the server's rule rather than a quirk of one account. A caller that
        asks for 30 gets 10 and no indication that it was truncated, which is
        how the Home Assistant browser came to show 10 events out of 1517.
        Page; do not raise ``page_size``. ``data.total`` in the reply is the
        true count for the window, and is correct even on a one-item page.
        Returns list of dicts from the server (each has eventUuid, eventDesc, picUrl, etc.).

        Uses /api/ipc/playback/eventRecordingList (confirmed from EventListRepos.java).
        Body format from EventListRequestParamsBean: deviceIds (list), recordSta, recordEnd,
        eventCodes (list), areaIds (list), pageNum, pageSize.
        """
        import aiohttp

        _body = {
            "deviceIds": [self.device_id],
            "pageNum":   page,
            "pageSize":  page_size,
            "recordSta": start_ts,
            "recordEnd": end_ts,
        }
        _LOGGER.debug("eventRecordingList request for %s: %s", self.device_id, _body)
        async def _fetch():
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self._aidot_v32_base}/playback/eventRecordingList",
                    json=_body,
                    headers=self._aidot_headers(),
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    return await resp.json(content_type=None)

        try:
            body = await _fetch()
            if self._is_auth_error(body) and await self._async_refresh_auth_token():
                body = await _fetch()  # retry once with the refreshed token

            _LOGGER.debug("eventRecordingList raw response for %s: %s", self.device_id, body)
            if body.get("code") != 200:
                _LOGGER.warning(
                    "eventRecordingList code=%s msg=%s for %s",
                    body.get("code"), body.get("desc") or body.get("msg"), self.device_id,
                )
                return []

            data = body.get("data") or {}
            items = data.get("list") or []
            # One line per motion poll - _motion_poll_loop calls this every
            # 30 s per camera, so on a 7-camera account it is 14 lines a minute
            # forever.  That cadence is deliberate (the app gets motion by FCM
            # push, which a server-side integration cannot receive); only the
            # severity was wrong.
            _LOGGER.debug(
                "eventRecordingList for %s: total=%s returned=%d",
                self.device_id, data.get("total"), len(items),
            )
            return items

        except Exception as exc:
            _LOGGER.error(
                "async_get_cloud_recordings failed for %s: %s", self.device_id, exc
            )
            return []

    async def async_count_cloud_recordings(
        self, start_ts: int, end_ts: int
    ) -> Optional[int]:
        """How many cloud events a window holds, in one request.

        The listing endpoint reports the window's true ``total`` alongside
        whatever page it serves, and that total is correct even on a one-item
        page - measured 2026-08-11 across seven cameras. So a count costs one
        request, where counting by paging costs one per ten events: a day
        holding 1517 events is 152 requests, and a seven-day view that counts
        by paging fires hundreds every time it is opened.

        Returns None when the call fails. A caller must not read that as zero -
        "the server did not answer" and "the window is empty" lead to opposite
        conclusions in a UI, and collapsing them is a defect this project has
        had to fix before.
        """
        import aiohttp

        _body = {
            "deviceIds": [self.device_id],
            "pageNum":   1,
            "pageSize":  1,
            "recordSta": start_ts,
            "recordEnd": end_ts,
        }

        async def _fetch():
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self._aidot_v32_base}/playback/eventRecordingList",
                    json=_body,
                    headers=self._aidot_headers(),
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    return await resp.json(content_type=None)

        try:
            body = await _fetch()
            if self._is_auth_error(body) and await self._async_refresh_auth_token():
                body = await _fetch()
            if not isinstance(body, dict) or body.get("code") != 200:
                _LOGGER.debug(
                    "eventRecordingList count for %s: %s", self.device_id, body)
                return None
            total = (body.get("data") or {}).get("total")
            return int(total) if isinstance(total, int) else None
        except Exception as exc:
            _LOGGER.debug(
                "eventRecordingList count failed for %s: %s", self.device_id, exc)
            return None

    async def async_get_cloud_plan(self) -> Optional[dict]:
        """The camera's cloud recording subscription, or None.

        Answers the question an empty event list cannot: whether there are no
        events, or no longer a plan under which events would be kept. Measured
        2026-08-11 on seven cameras - an active plan reads

            {"packageName": "AI Protection ", "packageType": 1,
             "subscribeStatus": 1, "startTime": <ms>, "endTime": <ms>,
             "expiredDays": 15, "videoLength": 60}

        Times are epoch milliseconds. ``videoLength`` is the clip length in
        seconds.

        Returns None on any failure rather than an empty dict: the caller's
        question is "is there a plan", and {} answers it wrong.

        Source: the vendor app's own JS bundle -
        GET /api/ipc/recordPlanController/getPackageInfoByDevId?deviceId=
        """
        import aiohttp

        async def _fetch():
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self._aidot_v32_base}/recordPlanController"
                    "/getPackageInfoByDevId",
                    params={"deviceId": self.device_id},
                    headers=self._aidot_headers(),
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    return await resp.json(content_type=None)

        try:
            body = await _fetch()
            if self._is_auth_error(body) and await self._async_refresh_auth_token():
                body = await _fetch()
            if not isinstance(body, dict) or body.get("code") != 200:
                _LOGGER.debug(
                    "getPackageInfoByDevId for %s: %s", self.device_id, body)
                return None
            data = body.get("data")
            return data if isinstance(data, dict) and data else None
        except Exception as exc:
            _LOGGER.debug(
                "getPackageInfoByDevId failed for %s: %s", self.device_id, exc)
            return None

    async def async_get_event_video_media(
        self, event_uuid: str
    ) -> Optional[tuple[str, str]]:
        """Return (url, mime_type) for a specific cloud recording.

        Prefers MP4 (type=1) over M3U8 (type=2) because HA's media player and
        most browsers handle direct MP4 more reliably than HLS with signed CDN
        segments.  Falls back to whatever is available.

        **That preference has never once been exercised.** Measured 2026-08-11
        on the owner account, three cameras across three model families
        (A001064, A001513, A000088): every reply carried exactly ONE entry, and
        it was type 2. So playback here is HLS in practice, and anything built
        on it should be designed for HLS rather than for the MP4 this docstring
        would lead a reader to expect. The branch is kept because it costs
        nothing and the field exists in the app's own decoder.

        From CloudPlaybackFragment.java / EventListRepos.java:
          POST /api/ipc/playback/getEventVideoUrl
          body: {deviceId, eventList: [{eventUuid}]}
          response: data.eventUrlList[0].videoUrlList[]
          each item: {url, type}  (type 1=MP4, type 2=M3U8)
        """
        import aiohttp

        _MIME = {1: "video/mp4", 2: "application/x-mpegURL"}

        async def _fetch():
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self._aidot_v32_base}/playback/getEventVideoUrl",
                    json={
                        "deviceId":  self.device_id,
                        "eventList": [{"eventUuid": event_uuid}],
                    },
                    headers=self._aidot_headers(),
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    return await resp.json(content_type=None)

        try:
            body = await _fetch()
            if self._is_auth_error(body) and await self._async_refresh_auth_token():
                body = await _fetch()  # retry once with the refreshed token

            _LOGGER.debug("getEventVideoUrl raw for %s uuid=%s: %s", self.device_id, event_uuid, body)

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

            # Prefer MP4 (type=1), fall back to first available entry
            mp4 = next((v for v in video_url_list if v.get("type") == 1), None)
            entry = mp4 or video_url_list[0]
            url = entry.get("url")
            if not url:
                return None
            mime = _MIME.get(entry.get("type"), "video/mp4")
            _LOGGER.debug(
                "getEventVideoUrl resolved for %s: type=%s mime=%s url=%.100s",
                self.device_id, entry.get("type"), mime, url,
            )
            return url, mime

        except Exception as exc:
            _LOGGER.error(
                "async_get_event_video_media failed for %s uuid=%s: %s",
                self.device_id, event_uuid, exc,
            )
            return None

    async def async_get_event_video_url(self, event_uuid: str) -> Optional[str]:
        """Return the video URL for a cloud recording (URL only, no MIME type).

        Prefer async_get_event_video_media() when you also need the MIME type.
        """
        result = await self.async_get_event_video_media(event_uuid)
        return result[0] if result else None

    async def async_get_latest_thumbnail(self) -> Optional[str]:
        """Return the URL of the most recent event/motion thumbnail for this camera.

        Uses /api/ipc/playback/eventRecordingList (pageNum=1, pageSize=1) and extracts
        the picUrl CDN field from the first result.  This endpoint works without an
        "owner" header (unlike the videoController paths which return 560073 with owner).

        Returns the CDN URL string, or None if no events exist.
        """
        import aiohttp
        import time

        end_ts = int(time.time() * 1000)
        start_ts = end_ts - 30 * 86_400_000  # look back 30 days

        async def _fetch():
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self._aidot_v32_base}/playback/eventRecordingList",
                    json={
                        "deviceIds": [self.device_id],
                        "pageNum":   1,
                        "pageSize":  1,
                        "recordSta": start_ts,
                        "recordEnd": end_ts,
                    },
                    headers=self._aidot_headers(),
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    return await resp.json(content_type=None)

        try:
            body = await _fetch()
            if self._is_auth_error(body) and await self._async_refresh_auth_token():
                body = await _fetch()  # retry once with the refreshed token

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
            _LOGGER.debug("Latest thumbnail for %s: %.100s", self.device_id, url)
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

        # -- SDES path: stream briefly to a temp TS file, extract one JPEG ---- #
        if self.is_sdes_camera:
            import os as _os
            import tempfile as _tf

            with _tf.NamedTemporaryFile(suffix=".ts", delete=False) as _tmpf:
                _tmp_ts = _tmpf.name
            try:
                # SDES cameras require a full SCTP/DCEP handshake before streaming.
                # The bridge thread (STUN+SCTP+DCEP) takes 25-35s; LIVING is sent
                # only after DCEP_OPEN + 300ms.  PLI forces an IDR every 5s once
                # streaming starts, so 10s of recording is always enough for a still.
                # Battery cameras (A001513) can take up to 17s to wake and send their
                # SDP answer - use a 45s cap so answer_fut does not expire first.
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
                except _asyncio.CancelledError:
                    # Not the same event as a timeout.  A timeout means the
                    # camera was slow and whatever landed in the temp file is
                    # worth salvaging; a cancellation means the caller is gone,
                    # so salvaging it (another ffmpeg, up to 15s) is work nobody
                    # is waiting for and it stops shutdown from completing.
                    raise
                except TimeoutError:
                    pass
                finally:
                    await _session.stop()

                if _os.path.getsize(_tmp_ts) == 0:
                    _LOGGER.warning(
                        "async_snapshot SDES: stream produced no data for %s",
                        self.device_id,
                    )
                    return False

                if _ffmpeg_path() is None:
                    _LOGGER.error("async_snapshot SDES: %s", _FFMPEG_MISSING_MSG)
                    return False
                # Async subprocess (not subprocess.run): a synchronous ffmpeg
                # here blocks the whole event loop - every camera, keepalive and
                # MQTT drain - for up to the timeout.
                _snap_proc = await _asyncio.create_subprocess_exec(
                    "ffmpeg", "-y", "-i", _tmp_ts,
                    "-frames:v", "1", "-f", "image2", output_path,
                    stdout=_asyncio.subprocess.DEVNULL,
                    stderr=_asyncio.subprocess.PIPE,
                )
                try:
                    _, _snap_err = await _asyncio.wait_for(
                        _snap_proc.communicate(), timeout=15
                    )
                except TimeoutError:
                    _snap_proc.kill()
                    await _snap_proc.communicate()
                    _LOGGER.warning(
                        "async_snapshot SDES: ffmpeg frame extract timed out for %s",
                        self.device_id,
                    )
                    return False
                if _snap_proc.returncode == 0 and _os.path.exists(output_path):
                    return True
                _LOGGER.warning(
                    "async_snapshot SDES: ffmpeg frame extract failed for %s: %s",
                    self.device_id,
                    (_snap_err or b"").decode(errors="replace")[-200:],
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
                    _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), 'async_snapshot', exc_info=True)

        # -- DTLS path: on_frame callback delivers frames from aiortc ------- #
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

        try:
            session = await self.async_open_webrtc_stream(
                on_frame=_on_frame,
                timeout=timeout,
                status_callback=status_callback,
            )
        except Exception as _snap_exc:
            _LOGGER.error(
                "async_snapshot DTLS failed for %s: %s", self.device_id, _snap_exc)
            return False
        try:
            try:
                await _asyncio.wait_for(frame_event.wait(), timeout=timeout)
            except TimeoutError:
                _LOGGER.warning(
                    "async_snapshot: no keyframe received within %.0fs for %s",
                    timeout, self.device_id,
                )
                return False
        finally:
            await session.stop()

        if captured[0] is None:
            return False
        # _save_frame_as_jpeg does a blocking PIL encode (or a blocking ffmpeg
        # fallback); run it off the event loop so it can't stall other cameras.
        return await _asyncio.get_running_loop().run_in_executor(
            None, _save_frame_as_jpeg, captured[0], output_path
        )

    async def async_start_streaming(self) -> None:
        """Start a persistent background WebRTC stream that updates latest_jpeg.

        DTLS cameras (A000088): frames delivered via on_frame callback, latest_jpeg updated.
        SDES cameras (A001064/A001513): on_frame not available (ffmpeg writes TS directly),
        so latest_jpeg stays None. HA camera entity falls back to cloud thumbnail in that case.
        Safe to call multiple times - does nothing if already running.
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
        self._start_keepalive_renew()   # battery: renew keep-alive on this path too
        self._stream_task = asyncio.ensure_future(self._streaming_loop())

    async def async_stop_streaming(self) -> None:
        """Stop the persistent background WebRTC stream."""
        self._streaming_active = False
        self._serve_ready.clear()
        g_task, self._go2rtc_task = self._go2rtc_task, None
        if g_task is not None and not g_task.done():
            g_task.cancel()
            try:
                await g_task
            except (asyncio.CancelledError, Exception):
                _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), 'async_stop_streaming', exc_info=True)
        await self._deregister_go2rtc()
        session, self._stream_session = self._stream_session, None
        if session is not None:
            try:
                await session.stop()
            except Exception:
                _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), 'async_stop_streaming', exc_info=True)
        task, self._stream_task = self._stream_task, None
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), 'async_stop_streaming', exc_info=True)
        ka_task, self._keepalive_task = getattr(self, "_keepalive_task", None), None
        if ka_task is not None and not ka_task.done():
            ka_task.cancel()
            try:
                await ka_task
            except (asyncio.CancelledError, Exception):
                _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), 'async_stop_streaming', exc_info=True)
        # Reap a persistent-MQTT stream drain that no session stopped (e.g. an
        # open cancelled mid-handshake) so its handler is removed from the shared
        # connection and its blocked executor thread is released.
        await self._reap_stream_drain()

    async def _reap_stream_drain(self):
        """Stop and reap the persistent-MQTT stream drain task, if any.

        The drain blocks an executor thread on ``outgoing_q.get`` until a ``None``
        sentinel arrives. A normal stop pushes that sentinel from the
        WebRTCSession/SdesSession; but if no session took ownership (open
        cancelled mid-handshake) or a new open replaced this one, we must push it
        ourselves - cancelling the future alone cannot interrupt the blocked
        thread, leaking it (and its handler on the shared connection) forever."""
        drain = getattr(self, "_stream_mqtt_drain", None)
        outq = getattr(self, "_stream_mqtt_outq", None)
        self._stream_mqtt_drain = None
        self._stream_mqtt_outq = None
        if drain is None:
            return
        if outq is not None:
            try:
                outq.put_nowait(None)   # release the executor thread in outgoing_q.get
            except Exception:
                _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_reap_stream_drain', exc_info=True)
        if not drain.done():
            drain.cancel()
        try:
            await drain
        except (asyncio.CancelledError, Exception):
            _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_reap_stream_drain', exc_info=True)

    def _release_stream_drain_to_session(self):
        """Hand ownership of the persistent-MQTT signaling drain to the session
        that just opened successfully.

        The returned WebRTCSession/SdesSession reaps its own outgoing_q + mqtt_fut
        on stop(); ``_stream_mqtt_drain``/``_stream_mqtt_outq`` are only a backstop
        for a drain whose open was cancelled *before* a session took ownership.
        Clearing the slot on hand-off means a concurrent open on this same camera
        (e.g. a snapshot taken during a live view) no longer reaps - and so no
        longer kills - the live session's drain; the slot from then on only ever
        holds a genuinely orphaned (cancelled mid-handshake) drain."""
        self._stream_mqtt_drain = None
        self._stream_mqtt_outq = None

    async def async_start_motion_polling(
        self, callback: Callable, interval: float = 30.0, lookback_s: int = 600,
    ) -> None:
        """Start polling the cloud event list and invoke ``callback(event)`` for each NEW
        motion/event clip the camera records.

        This is the working motion path for HA. The official app does NOT poll the event
        list on a timer (it's pull-to-refresh) - it gets background motion via FCM push and
        live ``alarmType`` only during an active view (both unavailable to a server-side
        integration). So polling is HA-necessary, and ``interval`` is OUR latency/load
        tradeoff, NOT an app value (there is none to match). 30 s is a sensible default
        (typical for HA cloud cameras). NOTE: depends on the camera recording events to the
        cloud - if there's no cloud event history, the list stays empty.
        ``event`` is the raw server item (``eventUuid``, ``eventCode``, ``eventTime``,
        ``picUrl``, ``eventDesc``, ...). The callback may be sync or a coroutine.

        ``interval`` = seconds between polls; ``lookback_s`` = how far back each poll
        queries. The first poll PRIMES (marks the existing backlog as seen without firing)
        so the callback only fires on events recorded after start. Idempotent.
        """
        self._motion_cb = callback
        self._motion_interval = max(5.0, float(interval))
        if self._motion_task is not None and not self._motion_task.done():
            return
        self._motion_active = True
        self._motion_seen = {}
        self._motion_task = asyncio.ensure_future(self._motion_poll_loop(lookback_s))

    async def async_stop_motion_polling(self) -> None:
        """Stop the motion-event polling started by ``async_start_motion_polling``."""
        self._motion_active = False
        self._motion_cb = None
        task, self._motion_task = self._motion_task, None
        if task is not None:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), 'async_stop_motion_polling', exc_info=True)

    async def _motion_poll_loop(self, lookback_s: int) -> None:
        """Background: poll the cloud event list; fire callback on newly-recorded events."""
        import time as _time
        primed = False
        while self._motion_active:
            try:
                now = int(_time.time() * 1000)
                items = await self.async_get_cloud_recordings(
                    now - lookback_s * 1000, now, page=1, page_size=20
                )
                fresh = []
                for it in items:
                    uid = it.get("eventUuid") or it.get("eventId") or it.get("recordId")
                    if not uid or uid in self._motion_seen:
                        continue
                    self._motion_seen[uid] = None
                    fresh.append(it)
                if primed and fresh and self._motion_cb is not None:
                    for it in sorted(fresh, key=lambda x: x.get("eventTime") or 0):
                        try:
                            res = self._motion_cb(it)
                            if asyncio.iscoroutine(res):
                                _spawn_bg(res)
                        except Exception:
                            _LOGGER.debug("motion callback raised", exc_info=True)
                primed = True
                if len(self._motion_seen) > 1000:  # bound memory
                    # Keep the 400 most-recent uids (insertion order), evicting
                    # the oldest so still-in-window events stay deduplicated.
                    self._motion_seen = dict.fromkeys(list(self._motion_seen)[-400:])
            except asyncio.CancelledError:
                return
            except Exception as exc:
                _LOGGER.debug("motion poll error for %s: %s", self.device_id, exc)
            try:
                await asyncio.sleep(self._motion_interval)
            except asyncio.CancelledError:
                return

    async def _async_set_keep_alive(self, keep_alive_s: int = _KEEPALIVE_WINDOW_S) -> None:
        """POST setKeepAliveTime so a battery camera stays awake for keep_alive_s
        seconds. Best-effort (errors swallowed). Wire format matches the app
        (n.java: keepAliveTime=25)."""
        try:
            import aiohttp as _aiohttp
            async with _aiohttp.ClientSession() as _s:
                async with _s.post(
                    f"{self._aidot_v32_base}/devices/{self.device_id}/setKeepAliveTime",
                    json={"keepAliveTime": keep_alive_s},
                    headers=self._aidot_headers(),
                    timeout=_aiohttp.ClientTimeout(total=8),
                ) as _r:
                    _LOGGER.debug(
                        "setKeepAliveTime HTTP %d for %s", _r.status, self.device_id
                    )
        except Exception as _exc:
            _LOGGER.debug(
                "setKeepAliveTime HTTP failed for %s: %s", self.device_id, _exc
            )

    def _start_keepalive_renew(self) -> None:
        """Start the battery keep-alive renew loop - battery-only and
        single-instance: cancel any prior loop first so a re-view within the
        renew sleep window can't orphan one (an orphan keeps POSTing
        setKeepAliveTime until _streaming_active next clears). No-op for mains
        cameras, which never sleep."""
        if not self.is_battery_camera:
            return
        prev = getattr(self, "_keepalive_task", None)
        if prev is not None and not prev.done():
            prev.cancel()
        self._keepalive_task = asyncio.ensure_future(self._keepalive_renew_loop())

    def _cancel_keepalive_renew(self) -> None:
        """Cancel the battery keep-alive renew loop if running (fire-and-forget)."""
        task, self._keepalive_task = getattr(self, "_keepalive_task", None), None
        if task is not None and not task.done():
            task.cancel()

    async def _keepalive_renew_loop(self) -> None:
        """Renew setKeepAliveTime while a BATTERY camera is streaming (app parity).

        The camera's own low-power timer returns it to sleep ~25 s after the last
        keep-alive even mid-view, so a one-shot keep-alive at open lets the stream
        drop partway through. The official app renews it throughout a live view;
        we renew every _KEEPALIVE_RENEW_S seconds (inside the 25 s window, so no
        sleep gap). Mains cameras never sleep, so this is battery-only."""
        if not self.is_battery_camera:
            return
        try:
            while self._streaming_active:
                await asyncio.sleep(_KEEPALIVE_RENEW_S)
                if not self._streaming_active:
                    break
                await self._async_set_keep_alive()
        except asyncio.CancelledError:
            pass

    async def start_keepalive(
        self,
        rtsp_push_url: Optional[str] = None,
        fast_connect: Optional[bool] = None,
        sdes_audio: Optional[bool] = None,
        go2rtc_url: Optional[str] = None,
        go2rtc_register: bool = True,
        live_stream_param: Optional[bool] = None,
        serve_relay: Optional[bool] = None,
        stream_idle_s: Optional[float] = None,
        sdes_fast_liveplay: Optional[bool] = None,
        sdes_skip_turn: Optional[bool] = None,
        sdes_connection_mode: Optional[str] = None,
        sdes_adaptive: Optional[bool] = None,
        sdes_audio_gain_db: Optional[float] = None,
    ) -> None:
        """Start a persistent stream that keeps the camera session alive.

        For SDES cameras (A001064/A001513): opens an indefinite ffmpeg stream and
        optionally pushes it to an RTSP server (e.g. go2rtc at rtsp://127.0.0.1:8554).
        This avoids the 25-70s cold-start SCTP handshake on every viewer connection.

        For DTLS cameras (A000088) with an http(s) serve URL: taps aiortc's
        encoded H.264 and -c copy's it to an mpegts HTTP-listen socket go2rtc
        pulls (real play/pause video, no decode/re-encode). Without a serve URL
        it falls back to the on_frame keepalive loop (latest_jpeg / MJPEG).

        ``fast_connect`` enables LAN-direct mode (skip the ~2.5s livePlay/ICE-config
        waits + TURN relay; see _async_open_webrtc_stream_impl).  ``None`` leaves it
        to the ``AIDOT_FAST_CONNECT`` env var; ``True``/``False`` override it (e.g.
        from a Home Assistant config-entry option, since HA OS can't set env vars).

        ``live_stream_param`` is **accepted but ignored** (a no-op kept so an
        existing caller doesn't break; it logs one warning if set).  It used to
        request the battery-camera cloud pre-connect, which provisions the camera
        toward AWS KVS so its media goes there instead of to the SDES bridge - the
        session negotiates and then serves no video at all.  Battery cameras were
        the only ones it applied to, i.e. exactly the ones it breaks, so the
        decision is now made once in ``_resolve_live_stream_param`` and is "no".
        Stop passing it; live video does not depend on it.

        ``serve_relay`` toggles the cold-start serve-port relay (holds the public
        serve port connectable through the WebRTC handshake so an eager go2rtc
        pull waits instead of getting connection-refused).  Overrides the
        ``AIDOT_SERVE_RELAY`` env var (default on); set False to serve ffmpeg
        directly on the public port (the pre-0.7.18 behaviour).

        ``go2rtc_url`` points at a go2rtc API base.  It does two things: register
        the local serve with go2rtc (exposing its low-latency pull URL), and let
        the idle-release logic ask go2rtc **who is watching**.

        ``go2rtc_register=False`` keeps the second and drops the first, for a
        consumer that registers the stream itself - registering it twice
        re-points the source mid-stream and was observed leaving DTLS cameras
        producing nothing at all.  Such a consumer must still pass ``go2rtc_url``:
        withholding it does not merely lose a nicety, it silently disables viewer
        detection, and in SDES **push** mode that is the only viewer signal there
        is (the serve port is go2rtc's shared RTSP port, where every camera's own
        publisher is connected, so a socket check would report a viewer for every
        camera forever).  With no signal ``_viewer_present`` answers "unknown",
        ``_idle_release_due`` correctly never releases on unknown, and a battery
        camera's keepalive renews forever against a camera nobody is watching.

        ``stream_idle_s`` sets the no-viewer idle-release window in seconds,
        overriding the ``AIDOT_STREAM_IDLE_S`` env default (120).  ``0`` (or
        negative) keeps the warm WebRTC session forever so re-views are instant
        (app-like) - sensible for mains cameras (no battery cost), but it holds a
        concurrent-stream slot for the camera's lifetime, so don't pin more
        cameras than ``AIDOT_MAX_CONCURRENT_STREAMS`` allows.  Leave None for
        battery cameras (motion-prewarm + idle-release preserves battery).

        Safe to call multiple times - does nothing if already running.
        """
        if fast_connect is not None:
            self._fast_connect_opt = fast_connect
        if sdes_audio is not None:
            self._sdes_audio_opt = sdes_audio
        if sdes_audio_gain_db is not None:
            self._sdes_audio_gain_opt = sdes_audio_gain_db
        if live_stream_param is not None:
            self._live_stream_param_opt = live_stream_param
        if serve_relay is not None:
            self._serve_relay_opt = serve_relay
        if stream_idle_s is not None:
            self._stream_idle_opt = stream_idle_s
        if sdes_fast_liveplay is not None:
            self._sdes_fast_liveplay_opt = sdes_fast_liveplay
        if sdes_skip_turn is not None:
            self._sdes_skip_turn_opt = sdes_skip_turn
        if sdes_connection_mode is not None:
            self._sdes_connection_mode_opt = sdes_connection_mode
        if sdes_adaptive is not None:
            self._sdes_adaptive_opt = sdes_adaptive
        if self._stream_task is not None and not self._stream_task.done():
            return
        self._keepalive_rtsp_url = rtsp_push_url
        self._go2rtc_url = go2rtc_url
        self._go2rtc_manages_stream = bool(go2rtc_register)
        self._streaming_active = True
        # App parity: keep a battery camera awake for the whole view (mains cams
        # never sleep, so this is a no-op there). Single-instance; cancelled in
        # stop / idle-release.
        self._start_keepalive_renew()
        if self.is_sdes_camera:
            self._stream_task = asyncio.ensure_future(self._sdes_keepalive_loop())
        elif rtsp_push_url and (rtsp_push_url.startswith("http")
                                or rtsp_push_url.startswith("rtsp")
                                or rtsp_push_url == "-"):
            # "-" is the stdout producer (go2rtc exec: source).  It belongs to
            # the serve loop exactly as an http listen URL does; leaving it out
            # of this gate sent it to the JPEG keepalive loop instead, which
            # opens a healthy WebRTC session and writes nothing to stdout.  The
            # spawn helper had supported "-" the whole time - nothing ever
            # called it with "-".
            self._stream_task = asyncio.ensure_future(self._dtls_serve_loop())
        else:
            self._stream_task = asyncio.ensure_future(self._streaming_loop())
        # Prefer-go2rtc: if a go2rtc server is configured, register the local
        # serve with it once ready and expose its pull URL (ffmpeg fallback
        # otherwise). Opt-in: with no go2rtc_url, behaviour is unchanged.
        #
        # ``go2rtc_register=False`` stores the URL for QUERIES ONLY and skips
        # registration.  That exists for a consumer that registers the stream
        # itself: registering it twice re-points the source while a stream is
        # mid-flight, which was observed leaving DTLS cameras producing nothing
        # at all.  Such a consumer previously had to withhold go2rtc_url
        # entirely, which silently disabled viewer detection - and in SDES push
        # mode that means a battery camera can never idle-release, because
        # ``_viewer_present`` answers "unknown" and ``_idle_release_due``
        # (correctly) never releases on unknown.  The keepalive then renews
        # forever against a camera nobody is watching.
        if go2rtc_url and go2rtc_register:
            self._go2rtc_task = asyncio.ensure_future(self._register_with_go2rtc())

    @property
    def stream_rtsp_url(self) -> Optional[str]:
        """RTSP pull URL for the live keepalive stream, or None if not running.

        When keepalive is active with an RTSP push URL of the form
        ``rtsp://HOST:PORT/NAME``, go2rtc makes the stream available at the same
        address for HA's stream integration to pull.
        """
        if self._streaming_active:
            # Prefer the go2rtc pull URL (low-latency WebRTC / native codec)
            # when registered; else the direct local serve URL (ffmpeg fallback,
            # e.g. HA built-in HLS).
            if self._go2rtc_pull_url:
                return self._go2rtc_pull_url
            if self._keepalive_rtsp_url:
                return self._keepalive_rtsp_url
        return None

    async def _register_with_go2rtc(self) -> None:
        """Prefer go2rtc: once the local serve is ready, register it with the
        configured go2rtc server and expose its low-latency pull URL via
        ``stream_rtsp_url``.  Best-effort - on any failure the direct serve URL
        remains the fallback (ffmpeg / HA HLS).
        """
        import aiohttp
        from .go2rtc import prefer_go2rtc
        try:
            await self.async_wait_serve_ready(timeout=40.0)
        except Exception:
            _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_register_with_go2rtc', exc_info=True)
        if not (self._streaming_active and self._go2rtc_url and self._keepalive_rtsp_url):
            return
        name = self._go2rtc_stream_name()
        if _is_self_referential_source(self._keepalive_rtsp_url, name):
            # PUSH mode: the keepalive publishes INTO go2rtc, so this URL is
            # go2rtc's own address for this very stream.  Registering it as the
            # stream's source makes go2rtc its own producer - a loop that yields
            # a stream with a producer attached and no media coming out of it.
            # In push mode the publisher already feeds the stream; there is
            # nothing to register.
            _LOGGER.debug(
                "camera %s: not registering %s with go2rtc - the push URL is that "
                "stream's own address", self.device_id, name,
            )
            return
        try:
            async with aiohttp.ClientSession() as _s2:
                url = await prefer_go2rtc(
                    _s2, name, self._keepalive_rtsp_url, base_url=self._go2rtc_url)
            if url:
                self._go2rtc_pull_url = url
                _LOGGER.info(
                    "camera %s: preferring go2rtc stream -> %s", self.device_id, url)
        except Exception:
            _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_register_with_go2rtc', exc_info=True)

    async def _deregister_go2rtc(self) -> None:
        """Remove this camera's stream from go2rtc (best-effort).

        Only ever removes a registration this client created.  With
        ``go2rtc_register=False`` the consumer owns the stream and merely lent us
        the URL to ask who is watching; deleting its stream on stop or
        idle-release would tear down the very thing it is serving from.
        """
        base = self._go2rtc_url
        self._go2rtc_pull_url = None
        if not self._go2rtc_manages_stream:
            return
        # Deliberately NOT gated on `pull`: go2rtc answers the register call with
        # 400 when it cannot immediately validate the source (a camera that has
        # not started producing yet), yet it still keeps the stream registered.
        # ensure_stream reports that as failure, so pull stays None - and gating
        # on it here leaked one dead stream per attempt, which then sat in go2rtc
        # with a producer nothing was feeding.
        if not base:
            return
        import aiohttp
        from .go2rtc import Go2rtcClient
        name = self._go2rtc_stream_name()
        try:
            async with aiohttp.ClientSession() as _s2:
                await Go2rtcClient(_s2, base).remove_stream(name)
        except Exception:
            _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_deregister_go2rtc', exc_info=True)

    async def async_wait_serve_ready(self, timeout: float = 20.0) -> bool:
        """Wait until the DTLS serve is bound + serving (or ``timeout``).

        Lets camera.stream_source() hand HA a URL only once the serve actually
        exists, so HA connects on its first try instead of getting
        "Connection refused" and waiting out its ~40s reconnect interval.
        Returns immediately if a warm session is already serving.  No-op (False)
        for paths that don't signal readiness (e.g. SDES - its ffmpeg serve has
        its own cold-start and never sets this event, so don't block on it).
        """
        if self.is_sdes_camera:
            return False
        ev = self._serve_ready
        if ev is None:
            return False
        try:
            await asyncio.wait_for(ev.wait(), timeout=timeout)
            return True
        except TimeoutError:
            return False

    async def async_speak(
        self,
        pcm_provider: "Callable[[], Optional[bytes]]",
        *,
        max_seconds: float = 30.0,
        open_timeout: float = 30.0,
        retries: int = 3,
    ) -> bool:
        """Play viewer->camera (push-to-talk / announce) audio through the speaker.

        ``pcm_provider()`` is polled every 20 ms and must return 320 bytes of s16le
        PCM @ 8 kHz mono (a short/empty frame is padded to silence) and ``None``
        once the clip is finished. Reuses the warm keepalive session if one is open
        and talk-capable, otherwise opens a temporary session (with retries) and
        closes it afterwards. Returns True if talk ran end-to-end, False if no
        session could carry talk. Works for both DTLS and SDES cameras (same
        WebRTC audio path).
        """
        session = self._stream_session
        own_session = False
        if session is None or not getattr(session, "talk_supported", False):
            session = None
            for attempt in range(max(1, retries)):
                try:
                    # talk=True so the SDES offer advertises sendrecv + a=ssrc and
                    # the camera builds a receive path for our audio (no-op for the
                    # DTLS path, which already negotiates a sendrecv audio sender).
                    session = await self.async_open_webrtc_stream(
                        timeout=open_timeout, talk=True)
                    own_session = True
                    break
                except Exception as exc:
                    _LOGGER.debug(
                        "async_speak: connect attempt %d/%d failed: %s",
                        attempt + 1, retries, exc,
                    )
                    session = None
                    await asyncio.sleep(3)
            if session is None or not getattr(session, "talk_supported", False):
                if own_session and session is not None:
                    await session.stop()
                return False

        # Signal completion when the provider is exhausted (returns None).
        done = asyncio.Event()
        loop = asyncio.get_running_loop()

        def _provider():
            frame = pcm_provider()
            if frame is None:
                loop.call_soon_threadsafe(done.set)
                return None
            return frame

        if not await session.async_start_talk(_provider):
            if own_session:
                await session.stop()
            return False
        try:
            await asyncio.wait_for(done.wait(), timeout=max_seconds)
        except TimeoutError:
            pass
        try:
            await session.async_stop_talk()
        finally:
            if own_session:
                await session.stop()
        return True

    def _sdes_serve_consumer_present(self, port: int) -> "Optional[bool]":
        """True if a TCP client is connected to the SDES serve ``port`` (a viewer
        is pulling), False if none, None if the TCP table can't be read (non-Linux
        / sandboxed host).  The caller MUST treat None as 'unknown' and NOT release
        - failing safe to the current always-reconnect behaviour."""
        read_any = False
        found = False
        for _path in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                with open(_path) as _fh:
                    _txt = _fh.read()
            except OSError:
                continue
            read_any = True
            if _tcp_table_has_established_on_port(_txt, port):
                found = True
        return found if read_any else None

    def _go2rtc_stream_name(self) -> str:
        """The go2rtc stream name for this camera - one definition, so the
        register, deregister and viewer-count paths cannot drift apart."""
        return f"aidot_{self.device_id[:12]}"

    # Cached answer to "is anyone watching", so the watchdog loops can ask on
    # every tick without hammering go2rtc.
    _viewer_cache: "tuple[float, Optional[bool]]" = (0.0, None)

    async def _viewer_present(self, port: int) -> "Optional[bool]":
        """Is anyone ACTUALLY watching?  True / False / None (unknown).

        Ask go2rtc first when the stream is registered with it, because the serve
        socket cannot answer this question: go2rtc attaches to the serve as its
        producer and stays attached for as long as the stream exists, viewer or
        no viewer.  A TCP peer is therefore always present, idle-release never
        fires, and every camera keeps streaming indefinitely after a single view -
        which is what "why are all my cameras streaming?" looks like from outside.
        Confirmed live: five cameras, no viewers, still producing after 7 minutes
        against a 5 minute idle window.

        Falls back to the TCP-table check when go2rtc is not in use, and returns
        None (never release) if neither can answer.
        """
        # THROTTLE FIRST.  The DTLS watchdog calls this every 0.5s and the SDES
        # one on a similar cadence, and the go2rtc query below opens a fresh HTTP
        # session each time - so an unthrottled check is two requests per second
        # per camera, forever, against the very service that has to serve the
        # video.  On a small fleet that is enough load to stop go2rtc answering
        # at all, which looks exactly like "no video anywhere".
        _now_mono = time.monotonic()
        _last, _cached = self._viewer_cache
        if _now_mono - _last < _VIEWER_CHECK_INTERVAL_S:
            return _cached

        name = self._go2rtc_stream_name()
        base = self._go2rtc_url

        # In PUSH mode the "serve port" is go2rtc's SHARED RTSP port (8554),
        # where every camera's own publisher is connected - so the socket
        # fallback below is not merely unavailable, it is WRONG: it would report
        # a viewer for every camera forever and nothing would ever release.
        # Tracked separately from `base` because it must gate the fallback even
        # when go2rtc IS configured but the query fails.
        push_mode = bool(self._keepalive_rtsp_url) and not str(
            self._keepalive_rtsp_url).startswith("http")

        # Ask go2rtc when we can. This is the only viewer signal that works in
        # push mode, which is why a consumer that registers its own stream
        # should still pass go2rtc_url with go2rtc_register=False rather than
        # withholding it (withholding it silently pins push-mode cameras to
        # "unknown", and unknown never releases).
        if base and name:
            try:
                import aiohttp

                from .go2rtc import Go2rtcClient
                async with aiohttp.ClientSession() as _s:
                    viewers = await Go2rtcClient(_s, base).viewer_count(name)
                if viewers is not None:
                    _answer = viewers > 0
                    self._viewer_cache = (_now_mono, _answer)
                    return _answer
            except Exception as exc:
                _LOGGER.debug("go2rtc viewer check failed: %s", exc)

        if push_mode:
            # Answer "unknown" instead of a confident lie - the caller then holds
            # the stream rather than tearing down a live view.
            _LOGGER.debug(
                "cannot tell whether anyone is watching: the serve is an RTSP "
                "push to a shared port and go2rtc %s",
                "did not answer" if base else "was not configured",
            )
            self._viewer_cache = (_now_mono, None)
            return None

        _answer = self._sdes_serve_consumer_present(port)
        self._viewer_cache = (_now_mono, _answer)
        return _answer

    async def _sdes_keepalive_loop(self) -> None:
        """Keep the cold-start serve relay alive around the SDES keepalive loop.

        The relay holds the public serve port connectable through every (re)open
        so an eager go2rtc pull waits instead of getting connection-refused while
        the SDES handshake runs (the same race fixed for the DTLS serve)."""
        self._serve_relay = self._maybe_start_serve_relay(self._keepalive_rtsp_url)
        try:
            await self._sdes_keepalive_loop_inner()
        finally:
            _relay = self._serve_relay
            self._serve_relay = None
            if _relay is not None:
                _relay.close()

    async def _sdes_keepalive_loop_inner(self) -> None:
        """Background task: keep SDES stream alive; push to go2rtc via RTSP."""
        _MIN_DELAY = 10.0
        _MAX_DELAY = 300.0
        # Jittered-backoff pacer: escalates on failed/no-media opens so a degraded
        # camera (or a fleet reconnecting at once) isn't hammered into further
        # degradation / cloud rate-limiting; resets after a session that delivered
        # media (see end of loop).
        _no_media_streak = 0
        _pacer = ReconnectPacer(_MIN_DELAY, _MAX_DELAY)

        # Adaptive fast-with-fallback (default on): the first open tries the fast
        # path (skip livePlay waits + TURN relay pre-allocation) with a SHORT
        # timeout/grace so a non-LAN camera fails quickly; on no media we latch
        # _fast_failed and the remaining opens this loop use the full, patient
        # relay path.  Makes fast-by-default safe regardless of camera reachability.
        _adaptive = self._resolve_sdes_adaptive()
        _FAST_OPEN_TIMEOUT = 45.0
        _FAST_GRACE = 40.0
        # Per-device cache: once a fast attempt has failed for this camera (e.g. a
        # strict-NAT / non-LAN camera that genuinely needs the relay), remember it
        # so later views skip the fast attempt entirely instead of re-paying the
        # ~40s fast timeout on every fresh keepalive loop. Latches for the client's
        # lifetime; an integration reload / restart re-probes the fast path.
        _fast_failed = bool(getattr(self, "_fast_path_unavailable", False))

        # Reuse ONE peerid across the retries of this loop instead of minting a
        # fresh one per attempt. A fresh peerid = a new camera-side session, and
        # the camera frees old ones only slowly, so mint-per-retry stacks up
        # sessions on a failing battery camera faster than they drain (measured:
        # this is how the L2 wedged into a wake-then-sleep loop). Mirrors the
        # official app, which resends within one session. Rotate to a fresh
        # peerid after a session that actually delivered media (so the next view
        # is a clean session) or after _PEERID_MAX_REUSE consecutive dead
        # attempts (so a poisoned peerid can't wedge us permanently).  The bound
        # is the module-level _PEERID_MAX_REUSE so this loop and its tests share
        # one number.  Safe HERE and not in the DTLS serve loop because this
        # loop re-offers within one open attempt on one peer connection, so a
        # late answer still belongs to the offer in flight.
        _loop_peer_id = self.generate_webrtc_peer_id(live_type=2, stream_id=0,
                                                     sdes=True,
                                                     device_id=self.device_id)
        _peer_reuses = 0

        # Wake-readiness retries.  A battery camera that answers livePlayResp with
        # -50019 and then sends no media was not refusing - it had not finished
        # waking.  The pacer cannot tell that apart from a degraded camera, so it
        # escalated the backoff (10s -> 300s) on a camera that would have been
        # ready seconds later; under a consumer that re-opens per view, that is the
        # difference between a slow first frame and a live view that never fills
        # in.  Give it the same bounded fast burst the DTLS serve loop already has
        # (_retry_policy), then fall back to the pacer so a persistently-cold
        # camera is still not hammered.  Bounded to _PEERID_MAX_REUSE so the whole
        # burst stays on ONE peerid: a fresh peerid registers another camera-side
        # session, which is what wedged the L2 in the first place (0.12.16).
        _not_ready_burst = 0

        while self._streaming_active:
            if self._serve_relay is not None:
                # Clear any stale backend from a prior session; the open below
                # points the relay at this session's fresh internal ffmpeg port.
                self._serve_relay.set_backend(None)
            if _peer_reuses >= _PEERID_MAX_REUSE:
                _loop_peer_id = self.generate_webrtc_peer_id(
                    live_type=2, stream_id=0, sdes=True,
                    device_id=self.device_id)
                _peer_reuses = 0
            _peer_reuses += 1
            _use_fast = self._adaptive_next_fast(_adaptive, _fast_failed)
            if _adaptive:
                self._fast_attempt_override = _use_fast
            try:
                session = await self.async_open_webrtc_stream(
                    rtsp_push_url=self._keepalive_rtsp_url,
                    timeout=(_FAST_OPEN_TIMEOUT if _use_fast else 120.0),
                    reuse_peer_id=_loop_peer_id,
                    # Ask for talk so THIS session can carry it. async_speak
                    # reuses _stream_session only when it is talk-capable, and
                    # an SDES session that did not ask never gets a return audio
                    # track - so without this every press-to-talk opened a
                    # second camera session alongside the live view, and the
                    # camera holds a viewer slot for about 120 s after one ends.
                    #
                    # This changes the SDP offer on the path every SDES live
                    # view takes, which is the kind of change that has caused
                    # fleet-wide blackouts here, so it rests on evidence rather
                    # than reasoning: the release harness has opened all seven
                    # cameras talk-capable across three fleet runs with no
                    # streaming regression. The flag reaches only the offer
                    # (audio sendrecv + a=ssrc) and the shared talk state; it
                    # does not touch the rtsp_push branch this loop uses.
                    talk=True,
                )
            except asyncio.CancelledError:
                self._fast_attempt_override = None
                return
            except AidotCameraBusy as busy:
                # The camera itself said it has no free session (-50002 max
                # concurrent streams / -50015). Each retry mints a NEW peerid and
                # so registers ANOTHER camera-side session, which the camera only
                # releases slowly - so retrying on the short backoff makes the
                # shortage worse and can wedge a battery camera into a
                # wake-then-sleep loop that serves nothing. Wait out the release
                # window instead. (The DTLS loops have always done this; the SDES
                # loop silently did not.)
                #
                # That release window is now measured rather than assumed: 8s is
                # enough, 2s is not. See _BUSY_BACKOFF_S.
                self._fast_attempt_override = None
                _LOGGER.warning(
                    "SDES keepalive: camera %s refused the stream (%s) - "
                    "backing off %.0fs so its sessions can be released",
                    self.device_id, busy, _BUSY_BACKOFF_S,
                )
                try:
                    await asyncio.sleep(_BUSY_BACKOFF_S)
                except asyncio.CancelledError:
                    return
                continue
            except AidotCameraNoMedia as _nomedia:
                # The camera answered and then sent nothing, so the open was
                # abandoned rather than serving a stream with no media on it.
                # This IS a session that ended without media - it just ended
                # before the serve rather than after - so it takes the same
                # pacing and, crucially, the same accounting.
                #
                # The accounting is not optional. Skipping straight to the next
                # attempt bypasses the futile-keepalive circuit breaker at the
                # bottom of the loop, and that guard exists because "a unit has
                # already been drained to 5% that way": without it a battery
                # camera that answers and never streams is woken forever.
                #
                # On pacing, said accurately: session_end_delay(healthy=False)
                # escalates the same shared attempt counter that fail_delay()
                # does - marginally sooner, in fact. That is deliberate here. A
                # camera that never delivers should back off, not hammer; the
                # fast not-ready burst below is what keeps a merely-slow camera
                # responsive.
                self._fast_attempt_override = None
                _no_media_streak = _next_no_media_streak(_no_media_streak, False)
                if _should_abandon_keepalive(
                        _no_media_streak, is_battery=self.is_battery_camera):
                    _LOGGER.warning(
                        "camera %s: %d consecutive keepalive attempts delivered "
                        "no media - stopping the background keepalive to stop "
                        "waking it. A live view will still open a session; set "
                        "AIDOT_FUTILE_KEEPALIVE_LIMIT=0 to keep retrying.",
                        self.device_id, _no_media_streak,
                    )
                    self._streaming_active = False
                    self._cancel_keepalive_renew()
                    try:
                        await self._deregister_go2rtc()
                    except Exception:
                        _LOGGER.debug("camera %s: go2rtc deregister after "
                                      "abandon failed", self.device_id,
                                      exc_info=True)
                    return
                # An adaptive fast attempt that reaches here delivered no media,
                # so it must latch the fallback exactly as the bottom of the
                # loop would; otherwise every retry re-uses the fast path on a
                # camera that needs the relay.
                if _use_fast and not _fast_failed:
                    _fast_failed = True
                    self._fast_path_unavailable = True
                    _LOGGER.info(
                        "SDES adaptive[%s]: fast attempt delivered no media - "
                        "falling back to the full relay path", self.device_id)
                _not_ready_burst = self._next_not_ready_burst(
                    False, _not_ready_burst)
                _delay, _fast_retry = self._not_ready_retry_delay(
                    _not_ready_burst, burst_max=_PEERID_MAX_REUSE)
                if not _fast_retry:
                    _delay = _pacer.session_end_delay(healthy=False)
                _LOGGER.info(
                    "SDES %s: %s - retrying in %.0fs%s",
                    self.device_id, _nomedia, _delay,
                    f" [{_not_ready_burst}/{_PEERID_MAX_REUSE}]"
                    if _fast_retry else "",
                )
                try:
                    await self._backoff_or_offline_pause(_delay)
                except asyncio.CancelledError:
                    return
                continue
            except Exception as exc:
                self._fast_attempt_override = None
                if _use_fast:
                    _fast_failed = self._adaptive_after_attempt(True, False, _fast_failed)
                    self._fast_path_unavailable = True  # cache across views
                    _LOGGER.info(
                        "SDES adaptive[%s]: fast open failed (%.0fs) - "
                        "falling back to full relay path", self.device_id,
                        _FAST_OPEN_TIMEOUT)
                _delay = _pacer.fail_delay()
                self._open_fail_logger()(
                    "SDES keepalive: stream open failed for %s (retry in %.0fs): %s",
                    self.device_id, _delay, exc,
                )
                try:
                    await self._backoff_or_offline_pause(_delay)
                except asyncio.CancelledError:
                    return
                continue

            self._fast_attempt_override = None
            self._stream_session = session
            # A remembered resolution is only deliverable once a session exists.
            self._apply_pending_resolution()
            # Don't block solely on wait_done(): the SDES ffmpeg reads RTP over a
            # UDP socket with no input timeout, so when a battery camera tears the
            # session down (~49-72s) ffmpeg keeps waiting on dead sockets forever
            # and never exits.  Race wait_done() against a media-liveness watchdog
            # (mirrors the JPEG _streaming_loop) so a stalled session reconnects.
            _started_at = time.monotonic()
            _done = asyncio.ensure_future(session.wait_done())
            _stalled = False
            _ice_dead = False
            # Measurement scaffolding, off by default and device-scoped: end a
            # session after its allotted media time so a pass costs the same
            # wall clock as a stall and a RATE can be sampled.  Anchored on
            # media, never on the open.
            _cap_s = _sdes_max_session_s(self.device_id)
            _first_media_at = None
            _capped = False
            _idle_release = False
            # No-viewer release.  Unlike the DTLS serve (which idle-releases when
            # its mux pipe goes stale), an SDES keepalive otherwise reconnects
            # FOREVER even with zero HA consumers - a battery-draining orphan that
            # also holds a stream slot and TURN-relay bandwidth.  SDES has no mux
            # pipe to watch, so detect "nobody is pulling" via an ESTABLISHED TCP
            # connection on the -listen serve port and release after the same idle
            # window as DTLS; the next view re-runs camera.stream_source().  Fail
            # safe: unknown (non-Linux /proc) never releases.  Escape hatch:
            # AIDOT_SDES_IDLE_RELEASE=0.
            # stream_idle_s / AIDOT_STREAM_IDLE_S override; <= 0 = never release.
            _idle_secs = self._resolve_idle_secs()
            _idle_on = (os.environ.get("AIDOT_SDES_IDLE_RELEASE", "1") != "0"
                        and _idle_secs > 0)
            _serve_port = _sdes_serve_port(self._keepalive_rtsp_url)
            _last_consumer = _started_at  # grace: count idle from session open
            try:
                while True:
                    _fin, _ = await asyncio.wait({_done}, timeout=5.0)
                    if _done in _fin:
                        break  # ffmpeg exited on its own (consumer gone, error)
                    if session.is_stalled(
                        session.last_media_monotonic,
                        _started_at,
                        time.monotonic(),
                        grace=(_FAST_GRACE if _use_fast else 60.0),
                    ):
                        _stalled = True
                        break
                    if _cap_s:
                        if _first_media_at is None:
                            _first_media_at = session.last_media_monotonic
                        if _session_cap_reached(_first_media_at,
                                                time.monotonic(), _cap_s):
                            _capped = True
                            _stalled = True
                            break
                    if sdes_ice_teardown(
                        session.last_media_monotonic,
                        session.last_ice_answer_monotonic,
                        time.monotonic(),
                    ):
                        # Media gone AND the camera's STUN answers gone: its ICE
                        # agent has dropped the transport. Nudging cannot recover
                        # that, so reopen now instead of serving ~25 s more of
                        # nothing while the media watchdog runs down.
                        _ice_dead = True
                        _stalled = True
                        break
                    if _idle_on and _serve_port is not None:
                        _present = await self._viewer_present(_serve_port)
                        if _present:  # True -> a viewer is pulling; stay alive
                            _last_consumer = time.monotonic()
                        elif _idle_release_due(_present, _last_consumer,
                                               time.monotonic(), _idle_secs):
                            _idle_release = True
                            break
                        # _present is None (unreadable table) -> don't release
            except asyncio.CancelledError:
                _done.cancel()
                self._stream_session = None
                await session.stop()
                return
            finally:
                self._stream_session = None

            if _idle_release:
                # No HA consumer for the idle window: go dormant instead of
                # reconnecting forever.  camera.stream_source() restarts us (and
                # the camera.py stale-stream watchdog evicts HA's cached stream
                # once stream_rtsp_url is None) when someone opens the view again.
                _done.cancel()
                try:
                    await session.stop()
                except Exception:
                    _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_sdes_keepalive_loop', exc_info=True)
                self._streaming_active = False
                self._cancel_keepalive_renew()
                self._keepalive_rtsp_url = None
                self._serve_ready.clear()
                # Take the stream out of go2rtc too. Leaving it registered
                # points go2rtc at a source that no longer exists, so a viewer
                # attaching while the camera is dormant gets a hard refusal
                # ("connection refused" on the serve port) instead of a clean
                # "no such stream" - and in push mode that source was never
                # dialable in the first place. stream_source() re-registers on
                # the next view.
                try:
                    await self._deregister_go2rtc()
                except Exception:
                    _LOGGER.debug("camera %s: swallowed exception in %s",
                                  getattr(self, "device_id", "?"),
                                  "_deregister_go2rtc", exc_info=True)
                _LOGGER.debug(
                    "SDES serve: %s idle (no viewer) - released until next view",
                    self.device_id,
                )
                return

            if _capped:
                _LOGGER.info(
                    "SDES %s: session cap %.0fs reached - ending session"
                    " (measurement scaffolding; this session PASSED the"
                    " 80.2s gate)", self.device_id, _cap_s)
            if _ice_dead:
                _LOGGER.info(
                    "SDES %s: camera ICE transport gone (media and STUN answers"
                    " both stopped) - reopening now rather than waiting out the"
                    " media watchdog", self.device_id)
            if _stalled:
                # Say whether this will repeat forever.  With idle-release off
                # (<=0 idle window) the loop never asks whether a viewer is
                # present, so a camera that stops sending when nobody is
                # watching is restarted every couple of minutes for the life of
                # the integration.  Measured on the reference A001064 with
                # mains_idle_s=0: a fresh session every ~2 min, round the clock,
                # with no consumer.  "Keep the warm session for instant
                # re-views" cannot work on a camera like that, and the repeated
                # restarts read as a defect when they are a setting.
                _LOGGER.info(
                    "SDES %s: no media in watchdog window - restarting stream%s",
                    self.device_id,
                    "" if _idle_on else
                    " (idle-release is OFF for this camera, so this will repeat"
                    " indefinitely; a camera that stops sending when unwatched"
                    " cannot be held warm - set a positive idle window to let"
                    " it go dormant between views)",
                )
                _done.cancel()

            try:
                await session.stop()
            except Exception:
                _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_sdes_keepalive_loop', exc_info=True)

            # Adaptive bookkeeping: a fast attempt that never delivered media
            # latches the loop onto the full relay path for its remaining opens.
            _healthy = session.last_media_monotonic > 0.0
            _no_media_streak = _next_no_media_streak(_no_media_streak, _healthy)
            if _healthy:
                # A session that delivered media is a real, cleanly-used session;
                # the next open should be a fresh one rather than re-offering on a
                # peerid the camera has already finished with.
                _loop_peer_id = self.generate_webrtc_peer_id(
                    live_type=2, stream_id=0, sdes=True,
                    device_id=self.device_id)
                _peer_reuses = 0
            else:
                if _should_abandon_keepalive(
                        _no_media_streak, is_battery=self.is_battery_camera):
                    # Every open so far has cost the camera a wake and returned
                    # nothing. Continuing spends charge to learn the same thing
                    # again; a view will still open a session on demand.
                    _LOGGER.warning(
                        "camera %s: %d consecutive keepalive sessions delivered no "
                        "media - stopping the background keepalive to stop waking "
                        "it. A live view will still open a session; set "
                        "AIDOT_FUTILE_KEEPALIVE_LIMIT=0 to keep retrying.",
                        self.device_id, _no_media_streak,
                    )
                    self._streaming_active = False
                    # Same teardown the idle-release exit does. Leaving the
                    # go2rtc stream registered points it at a serve port with
                    # nothing listening, so a viewer attaching to a dormant
                    # camera gets "connection refused" instead of a clean miss -
                    # exactly what the idle-release path exists to avoid.
                    self._cancel_keepalive_renew()
                    try:
                        await self._deregister_go2rtc()
                    except Exception:
                        _LOGGER.debug("camera %s: go2rtc deregister after "
                                      "abandon failed", self.device_id,
                                      exc_info=True)
                    return
            if _use_fast and not _healthy and not _fast_failed:
                _LOGGER.info(
                    "SDES adaptive[%s]: fast attempt delivered no media - "
                    "falling back to full relay path", self.device_id)
            _fast_failed = self._adaptive_after_attempt(_use_fast, _healthy, _fast_failed)
            if _use_fast and not _healthy:
                self._fast_path_unavailable = True  # cache across views

            if self._streaming_active:
                # Escalate backoff only when the session never delivered media
                # (camera refused / degraded on a rapid reconnect); a session
                # that streamed fine and then ended (battery teardown, consumer
                # gone) is a normal lifecycle event and resets to the base interval.
                # Exception: a battery camera that answered -50019 and then sent
                # nothing was still waking, not degraded - retry it fast instead.
                _not_ready_burst = self._next_not_ready_burst(
                    _healthy, _not_ready_burst)
                _delay, _fast_retry = self._not_ready_retry_delay(
                    _not_ready_burst, burst_max=_PEERID_MAX_REUSE)
                if _fast_retry:
                    _LOGGER.info(
                        "SDES %s: camera not ready (waking, livePlayResp %d) and "
                        "sent no media - fast retry in %.0fs [%d/%d]",
                        self.device_id, _LIVE_PLAY_NOT_READY, _delay,
                        _not_ready_burst, _PEERID_MAX_REUSE,
                    )
                else:
                    _delay = _pacer.session_end_delay(healthy=_healthy)
                try:
                    await asyncio.sleep(_delay)
                except asyncio.CancelledError:
                    return

    async def _streaming_loop(self) -> None:
        """Background task: open WebRTC stream and update latest_jpeg; reconnect on drop."""
        import io as _io

        _WATCHDOG = 30.0
        # Reconnect backoff starts at 5 s (exponential ->300 s).  This is an
        # INTENTIONAL divergence from the app, which uses a fixed 15 s reconnect
        # + a 15 s gate (f0.java I1=15000).  We favour faster HA recovery; an A/B
        # of 15 s showed no measurable benefit and only slowed reconnects.  Raise
        # to 15 s here (+ the SDES/serve loops) if strict app parity is wanted.
        _MIN_DELAY = 5.0
        _MAX_DELAY = 300.0
        # Jittered-backoff pacer: escalates on failed/frameless opens, resets after
        # a session that produced frames.
        _pacer = ReconnectPacer(_MIN_DELAY, _MAX_DELAY)

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
                self._last_frame_time = asyncio.get_running_loop().time()
            except Exception as enc_exc:
                _LOGGER.debug("Streaming encode failed for %s: %s", self.device_id, enc_exc)

        while self._streaming_active:
            _open_time = asyncio.get_running_loop().time()
            try:
                session = await self.async_open_webrtc_stream(on_frame=_on_frame)
            except asyncio.CancelledError:
                return
            except AidotCameraBusy as busy:
                # GAP D: the camera refused (e.g. another viewer holds the single
                # stream slot). Retrying fast cannot help; wait out a long backoff
                # before trying again rather than hammering it.
                _LOGGER.warning(
                    "Stream refused for %s (%s) - backing off %.0fs before retry",
                    self.device_id, busy, _BUSY_BACKOFF_S,
                )
                try:
                    await asyncio.sleep(_BUSY_BACKOFF_S)
                except asyncio.CancelledError:
                    return
                continue
            except Exception as exc:
                _delay = _pacer.fail_delay()
                self._open_fail_logger()(
                    "Stream open failed for %s (retry in %.0fs): %s",
                    self.device_id, _delay, exc,
                )
                try:
                    await self._backoff_or_offline_pause(_delay)
                except asyncio.CancelledError:
                    return
                continue

            self._stream_session = session
            self._apply_pending_resolution()
            try:
                while self._streaming_active:
                    await asyncio.sleep(5.0)
                    elapsed = asyncio.get_running_loop().time() - self._last_frame_time
                    if self._last_frame_time > 0 and elapsed > _WATCHDOG:
                        _LOGGER.warning(
                            "No frames from %s in %.0fs - restarting stream",
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
                _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_on_frame', exc_info=True)

            if self._streaming_active:
                # Reset backoff if this session produced frames (a normal drop
                # after good streaming); escalate with jitter if it never did
                # (the camera-degradation case).
                _produced = self._last_frame_time > _open_time
                try:
                    await asyncio.sleep(_pacer.session_end_delay(healthy=_produced))
                except asyncio.CancelledError:
                    return

    @staticmethod
    async def _send_video_pli(pc) -> None:
        """Ask the camera for an IDR keyframe (RTCP PLI) on the video receiver."""
        try:
            for _r in pc.getReceivers():
                _tr = getattr(_r, "track", None)
                if _tr is not None and _tr.kind == "video":
                    _ssrcs = [s.source for s in _r.getSynchronizationSources()]
                    for _ssrc in _ssrcs:
                        await _r._send_rtcp_pli(_ssrc)
                    return
        except Exception as _pli_exc:
            _LOGGER.debug("PLI request failed: %s", _pli_exc)

    @staticmethod
    def _install_encoded_tap(
        receiver, out_q, is_video: bool, serve: bool = False,
        device_id: Optional[str] = None,
    ) -> bool:
        """Tee aiortc's depacketized encoded frames (+ RTP timestamp) into a
        thread-safe queue before decode.  Video frames go as
        ``(bytes, timestamp, is_keyframe)``, audio as ``(bytes, timestamp)``.
        ``out_q`` is a ``queue.Queue`` (the mux runs in a worker thread).

        When ``serve`` is set, the served H.264 is muxed as ``-c copy`` straight
        from this tap, so the vendored decoder's output is discarded (the serve
        loop uses a no-op on_frame).  In that mode we STOP feeding the decoder
        queue for video DATA frames: decoding them is pure wasted CPU and the
        sole source of the per-packet decode-failure warning flood.  The None
        terminator is STILL forwarded so the decoder thread exits cleanly, and
        audio is left untouched (drained separately).  We must not instead pass
        ``on_frame=None`` at the receiver level - the decoder thread would keep
        running and fill the unbounded track queue with nothing draining it.

        Because decode was the only signal that the served H.264 was corrupt, a
        cheap keyframe-based canary (no decoding) is kept: it counts frames and
        keyframes, tracks the longest run with no keyframe, and emits a periodic
        DEBUG summary.  It is O(1) per frame and stays at DEBUG so a corrupt
        camera can't recreate the very flood this removes."""
        _qd = getattr(receiver, "_RTCRtpReceiver__decoder_queue", None)
        if _qd is None:
            return False
        # Idempotent: _install_av_taps is retried until the video tap lands, so a
        # receiver that's already tapped must not be wrapped again (that would
        # layer the tap N times and flood the queue).
        if getattr(_qd, "_aidot_tapped", False):
            return True
        _orig_put = _qd.put
        _skip_decode = bool(serve and is_video)
        # Served-stream health canary (video-only): observed without decoding.
        _canary = ({"frames": 0, "keyframes": 0, "gap": 0, "max_gap": 0,
                    "unwrapped": 0} if _skip_decode else None)
        if _canary is not None:
            _qd._aidot_serve_canary = _canary
        # Serve path only: this is the stream we timestamp by hand. The
        # live-view path hands frames to aiortc's own decoder, which does not
        # use these values the same way.
        _unwrap = _unwrap_state() if _skip_decode else None
        _CANARY_LOG_EVERY = 300  # frames (~10-20s of H.264); DEBUG summary cadence

        def _tap_put(task, *a, **k):
            try:
                if task is not None:
                    _enc = task[1]
                    _d = getattr(_enc, "data", None)
                    _ts = getattr(_enc, "timestamp", None)
                    if _d and _ts is not None:
                        if _unwrap is not None:
                            # Count ARTIFACTS, not frames carrying the running
                            # offset - once the offset is non-zero every frame
                            # differs from its raw value, which made the first
                            # reading say 6853 of 6900 and told me nothing.
                            _before = _unwrap["offset"]
                            _ts = _correct_ts(_unwrap, int(_ts))
                            if _canary is not None and _unwrap["offset"] != _before:
                                _canary["unwrapped"] = (
                                    _canary.get("unwrapped", 0) + 1)
                        _b = bytes(_d)
                        _kf = _h264_has_keyframe(_b) if is_video else False
                        _item = (_b, int(_ts), _kf) if is_video else (_b, int(_ts))
                        try:
                            out_q.put_nowait(_item)
                        except Exception:
                            pass  # full -> drop (PLI re-arms a GOP)
                        if _canary is not None:
                            _canary["frames"] += 1
                            if _kf:
                                _canary["keyframes"] += 1
                                _canary["gap"] = 0
                            else:
                                _canary["gap"] += 1
                                if _canary["gap"] > _canary["max_gap"]:
                                    _canary["max_gap"] = _canary["gap"]
                            if _canary["frames"] % _CANARY_LOG_EVERY == 0:
                                _log_serve_canary(device_id, _canary)
                    if _skip_decode:
                        # Discarded decode: don't feed the decoder for served
                        # video data frames (see docstring).  Terminator (task
                        # is None) still falls through to _orig_put below.
                        return None
            except Exception:
                _LOGGER.debug("swallowed exception in %s", '_tap_put', exc_info=True)
            return _orig_put(task, *a, **k)

        _qd.put = _tap_put
        _qd._aidot_tapped = True
        return True

    def _install_av_taps(self, pc, vq, aq) -> bool:
        """Install the video tap (required) and audio tap (best-effort).

        Called repeatedly until the video tap lands; _install_encoded_tap is
        idempotent per receiver, so audio isn't re-wrapped across retries.

        This runs only from the DTLS serve loop, whose on_frame is a no-op and
        whose output is muxed as H.264 copy from the video tap - so the video
        tap is installed with serve=True to skip the discarded decode (see
        _install_encoded_tap).  Audio keeps feeding its decoder (drained
        separately).
        """
        got_v = False
        got_a = False
        # Drop the previous session's canary before looking for this session's
        # tap. It is read by the serve loop as "has this session delivered
        # video", and a stale dict with a non-zero frame count would answer yes
        # for a session that has produced nothing.
        self._serve_video_canary = None
        for _r in pc.getReceivers():
            _tr = getattr(_r, "track", None)
            if _tr is None:
                continue
            if _tr.kind == "video" and not got_v:
                got_v = self._install_encoded_tap(
                    _r, vq, True, serve=True, device_id=self.device_id
                )
                if got_v:
                    # Keep the canary reachable from the serve loop: it counts
                    # frames at the tap, which is the only place that knows
                    # whether the camera is delivering video at all.  Read off
                    # the queue rather than set here, so the idempotent
                    # already-tapped path finds the same dict.
                    _qd_v = getattr(_r, "_RTCRtpReceiver__decoder_queue", None)
                    self._serve_video_canary = getattr(
                        _qd_v, "_aidot_serve_canary", None
                    )
            elif _tr.kind == "audio" and not got_a:
                got_a = self._install_encoded_tap(
                    _r, aq, False, device_id=self.device_id
                )
        return got_v

    def _cold_phase(self, label: str) -> None:
        """Log elapsed-ms since the open began (cold-start instrumentation).

        Defensive + best-effort: never raises, no-op if no open is in flight.
        Emits a single greppable INFO line per phase so a cold connect's timeline
        (open -> webrtcReq -> first-media -> serving) can be measured without a
        debugger or ad-hoc log scraping.  Grep ``cold-start[``."""
        try:
            t0 = self._cold_open_t0
            if t0 is None:
                return
            _LOGGER.info(
                "cold-start[%s] %s +%dms",
                self.device_id, label, int((time.monotonic() - t0) * 1000),
            )
        except Exception:
            pass

    def _resolve_idle_secs(self) -> float:
        """Serve idle-release window (seconds). A per-camera ``stream_idle_s``
        (set via start_keepalive) overrides the ``AIDOT_STREAM_IDLE_S`` env
        default of 120 s.  <= 0 means *never* idle-release (keep the warm session
        for instant re-views - sensible for mains cameras, which have no battery
        cost; note it holds a concurrent-stream slot for the camera's lifetime)."""
        opt = getattr(self, "_stream_idle_opt", None)
        if opt is not None:
            return float(opt)
        try:
            return float(os.environ.get("AIDOT_STREAM_IDLE_S", "120"))
        except (TypeError, ValueError):
            return 120.0

    def _resolve_sdes_fast_liveplay(self) -> bool:
        """Whether to use SDES fast-liveplay: don't block on the always-timing-out
        echo/livePlayResp signaling, go straight to webrtcReq/ICE.

        **Default ON** - this is exactly what the official app does (it never waits
        for/parses livePlayResp; fire-and-forget). Disable via
        ``AIDOT_SDES_FAST_LIVEPLAY`` in {0,false,no,off} or per-camera
        ``_sdes_fast_liveplay_opt=False`` (the explicit opt always wins).

        Role-reversal models (``_NO_FAST_LIVEPLAY_MODELS``, e.g. A001064) are ALWAYS
        excluded regardless of the flag - their handshake needs the camera armed
        before our webrtcReq, so the early webrtcReq degrades their media (a
        correctness exclusion, not a default choice). Only consulted for SDES
        cameras (the caller gates on is_sdes_camera)."""
        model = getattr(getattr(self, "info", None), "model_id", None)
        if model in self._NO_FAST_LIVEPLAY_MODELS:
            return False
        opt = getattr(self, "_sdes_fast_liveplay_opt", None)
        if opt is not None:
            return bool(opt)
        ov = getattr(self, "_fast_attempt_override", None)
        if ov is not None:
            return bool(ov)
        return os.environ.get("AIDOT_SDES_FAST_LIVEPLAY", "").strip().lower() not in (
            "0", "false", "no", "off")

    def _resolve_dtls_fast_liveplay(self) -> bool:
        """Whether to skip the DTLS path's livePlayReq-echo + livePlayResp waits.

        The targeted analogue of [[_resolve_sdes_fast_liveplay]] for DTLS
        (A000088) cameras.  Consumed by [[_skip_dtls_signaling_wait]], which gates
        BOTH the ~0.5 s livePlayReq-echo wait and the ~2 s livePlayResp
        accept/reject wait, while keeping the full ICE/TURN/DTLS handshake (so
        remote/relay viewing is unaffected, unlike the broader ``_fast_connect``
        which also strips TURN).

        **Default ON** - the official app never waits for/parses livePlayResp,
        and the wait was measured as the dominant LAN cold-start cost (~2 s, paid
        in full on the common timeout). The only thing lost is fast-fail on an
        outright camera refusal (livePlay=0), which is rare and then surfaces as
        an ICE failure instead. Disable via ``AIDOT_DTLS_FAST_LIVEPLAY`` in
        {0,false,no,off} or per-camera ``_dtls_fast_liveplay_opt`` (opt wins)."""
        opt = getattr(self, "_dtls_fast_liveplay_opt", None)
        if opt is not None:
            return bool(opt)
        return os.environ.get("AIDOT_DTLS_FAST_LIVEPLAY", "").strip().lower() not in (
            "0", "false", "no", "off")

    def _skip_dtls_signaling_wait(self, fast_connect: bool) -> bool:
        """Whether the DTLS open skips its livePlayReq-echo AND livePlayResp waits.

        Both waits proceed to SDP/ICE on timeout anyway, so they are skipped
        together under one predicate (keeping them in lock-step): the broad
        ``fast_connect`` mode, or the targeted default-on
        [[_resolve_dtls_fast_liveplay]] (app-parity).  Unifying the condition
        fixes a drift where the 0.5s echo wait skipped only on ``fast_connect``
        while the 2s livePlayResp wait below it also honoured dtls_fast_liveplay,
        so the default path still paid the 0.5s echo wait that usually times out."""
        return bool(fast_connect) or self._resolve_dtls_fast_liveplay()

    def _resolve_sdes_serve_audio(self) -> bool:
        """Whether to include audio in the SDES camera serve.

        **Default ON** for app-parity (the official app plays camera audio).

        This was briefly defaulted off, because mapping audio used to serve no
        video at all: the SDP advertises two payload types per media line and
        ffmpeg binds the first, so the synthesised PCMA (pt 8) was discarded in
        favour of the advertised PCMU (pt 0) - and since the mpegts mux withholds
        its PAT/PMT until every mapped stream has produced a packet, the consumer
        got zero bytes and lost the picture too.  The audio line is now narrowed to
        the payload type actually in use, the same way the video line already was,
        and the serve falls back to video-only if the audio payload type cannot be
        characterised in time.  So audio can no longer cost the video.

        Per-camera ``sdes_audio`` (via ``start_keepalive``) wins; else the
        ``AIDOT_SDES_SERVE_AUDIO`` env (falsy = 0/false/no/off disables)."""
        opt = getattr(self, "_sdes_audio_opt", None)
        if opt is not None:
            return bool(opt)
        return os.environ.get("AIDOT_SDES_SERVE_AUDIO", "").strip().lower() not in (
            "0", "false", "no", "off")

    def _resolve_sdes_audio_gain_db(self) -> float:
        """Gain (dB) applied to the served SDES audio (the camera mic runs hot).

        Per-camera ``sdes_audio_gain_db`` (via ``start_keepalive``) wins; else the
        ``AIDOT_SDES_AUDIO_GAIN_DB`` env; else ``-8``.  A bad value falls back to
        the default rather than raising."""
        opt = getattr(self, "_sdes_audio_gain_opt", None)
        src = opt if opt is not None else os.environ.get("AIDOT_SDES_AUDIO_GAIN_DB", "-8")
        try:
            return float(src)
        except (ValueError, TypeError):
            return -8.0

    def _resolve_live_stream_param(self) -> bool:
        """Whether to make the cloud ``liveStreamParam`` KVS pre-connect before
        signaling.  **Always False** - see below; the flag survives only so an
        existing caller doesn't break.

        The call provisions the camera's live session toward AWS KVS, and the
        camera then sends its media THERE instead of to our SDES bridge: the
        session negotiates, the bridge binds, and no video RTP ever arrives.  It
        is also made for battery cameras ONLY, so the set of cameras it can
        affect is exactly the set it is known to break.  It was added to cure a
        ``-50019`` ("not ready") livePlayResp, which 0.12.15 established is
        benign - mains cameras emit it too and recover via ICE.

        0.12.15 turned it off by default but left the option/env able to turn it
        back on, which is a foot-gun aimed at one foot: a consumer that surfaces
        it as a setting (the Home Assistant integration surfaces these options
        because HA OS cannot set env vars) can re-break every battery camera on
        the account, and the symptom - a live view that negotiates and then shows
        nothing, forever - looks nothing like a settings problem.  A standalone
        run never passes the option, which is exactly why the same library
        streams an L2 from the CLI and not under HA.

        So the decision now lives here, in one place, and is "no".  Re-enabling
        it needs a code change plus fresh on-hardware evidence that some camera
        actually requires it - not a flag flip.  A caller that still asks gets
        one warning naming the camera, so a stuck install says why in the log
        instead of silently serving nothing.
        """
        if not self.is_battery_camera:
            # The pre-connect was never made for a mains camera in the first
            # place; nothing to decide.
            return False
        asked = getattr(self, "_live_stream_param_opt", None)
        if asked is None:
            asked = os.environ.get("AIDOT_LIVESTREAM_PARAM", "0") != "0"
        if asked and not getattr(self, "_live_stream_param_warned", False):
            self._live_stream_param_warned = True
            _LOGGER.warning(
                "camera %s: ignoring the liveStreamParam pre-connect request "
                "(live_stream_param / AIDOT_LIVESTREAM_PARAM).  On a battery "
                "camera it provisions the session toward AWS KVS and the camera "
                "sends its media there instead of to this library, so the live "
                "view negotiates and then serves no video at all.  The setting "
                "is a no-op - remove it; live video does not depend on it.",
                self.device_id,
            )
        return False

    def _resolve_sdes_connection_mode(self) -> str:
        """Which media path the session should offer: auto, lan, or relay.

        ``auto`` (default) offers every reachable candidate and lets ICE
        priority prefer the LAN, with the relay as last resort - the shipped
        behaviour, verified on the full fleet (six of seven direct, only the
        unreachable unit relayed).  ``lan`` drops the relay entirely (routed
        through _resolve_sdes_skip_turn so the battery force-keep applies).
        ``relay`` offers only the relay candidate and force-keeps the
        pre-allocation.

        Per-open ``sdes_connection_mode`` wins; else AIDOT_SDES_CONNECTION_MODE;
        else auto.  Anything unrecognised is auto - this is read while opening
        a stream, and a typo must not stop video.
        """
        for raw in (getattr(self, "_sdes_connection_mode_opt", None),
                    os.environ.get("AIDOT_SDES_CONNECTION_MODE")):
            if raw is None:
                continue
            mode = str(raw).strip().lower()
            if mode in ("auto", "lan", "relay"):
                return mode
            _LOGGER.warning(
                "camera %s: unknown sdes_connection_mode %r; using auto",
                getattr(self, "device_id", "?"), raw)
        return "auto"

    def _resolve_sdes_skip_turn(self) -> bool:
        """EXPERIMENTAL (opt-in, default off): skip the blocking SDES TURN relay
        pre-allocation, for cameras reachable LAN-direct.

        Before building the offer the SDES path does two synchronous RFC-5766
        Allocate round-trips (audio + video) to the cloud TURN server so the
        offer's c=/m= can carry a relay address - ~2-3 s of pure cold-start
        latency.  On a LAN the camera's host candidate wins and that relay is
        never used, so skipping it shaves the latency - at the cost of no relay
        fallback for a camera on a different segment / behind strict NAT (the
        same trade-off ``AIDOT_FAST_CONNECT`` already makes for DTLS, and which
        is force-disabled for SDES because it *also* skips the SCTP-arming
        waits; this flag skips ONLY the relay pre-allocation, leaving the rest
        of the SDES handshake intact).

        Per-camera ``sdes_skip_turn`` (set via start_keepalive) wins; else the
        ``AIDOT_SDES_SKIP_TURN_PREALLOC`` env (truthy = 1/true/yes/on), default
        off.  Only consulted for SDES cameras.

        NEVER skipped for a battery camera, whatever the opt/env say: a battery
        camera sleeps and is woken through the cloud, so it is reached over the
        TURN relay rather than a host-direct LAN path.  Skipping the relay
        pre-allocation there means the camera has no reachable path back and
        sends no media at all (validated live on an A001513: with the relay it
        streams h264 1280x960, with skip_turn it serves nothing).  The LAN-direct
        latency win only applies to a mains camera that actually has a host
        candidate on the HA segment."""
        if getattr(self, "is_battery_camera", False):
            return False
        # The connection mode composes here rather than in a parallel path, so
        # everything hanging off this resolver (instrumentation, the adaptive
        # interplay) sees one answer.  relay force-keeps the pre-allocation -
        # forcing the relay while skipping its allocation would offer nothing.
        _mode = self._resolve_sdes_connection_mode()
        if _mode == "lan":
            return True
        if _mode == "relay":
            return False
        opt = getattr(self, "_sdes_skip_turn_opt", None)
        if opt is not None:
            return bool(opt)
        ov = getattr(self, "_fast_attempt_override", None)
        if ov is not None:
            return bool(ov)
        return os.environ.get("AIDOT_SDES_SKIP_TURN_PREALLOC", "").strip().lower() in (
            "1", "true", "yes", "on")

    def _resolve_sdes_adaptive(self) -> bool:
        """Whether the SDES keepalive loop drives the fast path adaptively
        (opt-in, default OFF): try fast-first (skip the livePlay waits + TURN
        relay pre-allocation, with a short timeout), and fall back to the full,
        patient relay path if the fast attempt delivers no media.

        This makes "fast by default" safe for cameras of unknown reachability:
        a LAN-direct camera gets the fast connect; a remote / strict-NAT camera
        loses one short fast attempt, then connects via the full relay path.

        Default OFF pending real-world fast-failure-rate data: a fast *failure*
        costs ~40 s (the grace) before fallback while success saves only ~7 s, so
        until the failure rate is known on real fleets this stays opt-in.

        Per-camera ``sdes_adaptive`` (via start_keepalive) wins; else the
        ``AIDOT_SDES_ADAPTIVE`` env (truthy = 1/true/yes/on), default off. When
        off, the per-attempt override is never set, so the explicit
        ``sdes_fast_liveplay`` / ``sdes_skip_turn`` opts (or their envs) decide -
        exactly the pre-adaptive behaviour.

        NEVER on for a battery camera, whatever the opt/env say - for those it is
        all cost and no benefit.  The saving adaptive chases is the TURN relay
        pre-allocation, and [[_resolve_sdes_skip_turn]] force-KEEPS that for a
        battery camera (it is the only return path to a cloud-woken camera), while
        fast-liveplay is already on by default.  So a battery "fast" attempt runs
        the very same handshake as the patient one and differs only in being given
        45 s to open and a 40 s media grace - inside the documented 25-70 s battery
        cold-start window.  A slow-but-healthy wake is then scored as a fast-path
        failure: it latches ``_fast_path_unavailable``, escalates the backoff, and
        burns a camera-side session on a device that frees them slowly."""
        if getattr(self, "is_battery_camera", False):
            return False
        opt = getattr(self, "_sdes_adaptive_opt", None)
        if opt is not None:
            return bool(opt)
        return os.environ.get("AIDOT_SDES_ADAPTIVE", "").strip().lower() in (
            "1", "true", "yes", "on")

    def _resolve_persistent_mqtt(self) -> bool:
        """Whether commands, attribute fetches, AND stream-open signaling reuse ONE
        account-level persistent MQTT connection (matching the app's
        LDSBaseMqttServiceImpl) instead of connecting per op.

        **Default ON** (2026-06-17): this is exactly how the official app behaves -
        one persistent connection per login session - and a live soak showed it
        cuts SDES NO_MEDIA from ~57% to ~19% (no regression). It is also safer
        than connect-per-op, which can collide on the single authorized client_id.
        Disable via ``AIDOT_PERSISTENT_MQTT`` in {0,false,no,off} or per-camera
        ``_persistent_mqtt_opt=False`` (the explicit opt always wins)."""
        opt = getattr(self, "_persistent_mqtt_opt", None)
        if opt is not None:
            return bool(opt)
        return os.environ.get("AIDOT_PERSISTENT_MQTT", "").strip().lower() not in (
            "0", "false", "no", "off")

    async def _get_persistent_mqtt(self):
        """Get-or-create the account-shared ``_PersistentMqtt`` (one per account,
        keyed on the shared ``login_info``).  The broker binds auth to the single
        authorized client_id, so there must be exactly one.  Returns None if it
        can't be built (caller falls back to per-op ``_mqtt_session``)."""
        # _user_info is the shared account dict (same object across the account's
        # DeviceClients, and the same object as AidotClient.login_info) - the right
        # place to cache one connection per account.
        li = self._user_info if isinstance(getattr(self, "_user_info", None), dict) else None
        if li is None:
            return None
        # These two keys are deliberately live runtime objects (a connection,
        # its guarding lock), NOT persistable state - see
        # RUNTIME_ONLY_LOGIN_INFO_KEYS and AidotClient.serializable_login_info(),
        # which strips them before this shared dict is ever written to
        # disk/config storage.
        pm = li.get(LOGIN_INFO_PERSISTENT_MQTT_KEY)
        if pm is not None:
            return pm
        # Serialize get-or-create. Without this, two concurrent first-callers
        # (e.g. a command publish racing a stream open) both pass the None-check
        # above, both await below, and both build a _PersistentMqtt - the second
        # clobbering the first and orphaning a connection on the single-client_id
        # broker. dict.setdefault is atomic (no await between create and insert),
        # so every caller for this account shares the one lock.
        lock = li.setdefault(LOGIN_INFO_PERSISTENT_MQTT_LOCK_KEY, asyncio.Lock())
        async with lock:
            pm = li.get(LOGIN_INFO_PERSISTENT_MQTT_KEY)  # re-check under the lock
            if pm is not None:
                return pm
            smarthome_auth = await self._async_get_smarthome_auth()
            mqtt_user = (smarthome_auth or {}).get("mqttUser") or str(self.user_id)
            mqtt_pwd  = (smarthome_auth or {}).get("mqttPassword") or ""
            client_id = (self._user_info.get("mqttClientId") or f"app-{mqtt_user}")
            mqtt_url = await self._async_get_mqtt_url()
            if not mqtt_url:
                return None
            from .protocol import _PersistentMqtt

            # paho fires on_connect on its own network thread; every mutation
            # below has to be ordered against the get-or-create above, so it is
            # hopped onto this loop and taken under the same account lock.
            _loop = asyncio.get_running_loop()

            def _invalidate_mqtt_credentials(rc) -> None:
                """Retire the refused client and drop the credential it used.

                The broker rotates this password on every account login and
                allows one connection at a time, so any other login (the phone
                app, a second Home Assistant, a script) invalidates ours.  The
                cached copy lives in login_info, where it short-circuits the
                credential fetch, so it has to be cleared or every retry reuses
                the dead password.

                Runs on paho's network thread, so it only schedules the work: the
                mutations must be ordered against a concurrent get-or-create, and
                ``retire()`` calls ``loop_stop()``, which raises if called from
                the very thread it would join.
                """
                _loop.call_soon_threadsafe(_spawn_bg, _retire_and_invalidate(rc))

            async def _retire_and_invalidate(rc) -> None:
                # Deliberately outside the lock.  These are plain dict writes with
                # no ordering requirement, and a sibling can be holding the lock
                # across an HTTP credential fetch - taking it here would stall the
                # invalidation behind that request's timeout for no benefit.
                for key in LOGIN_INFO_MQTT_PASSWORD_KEYS:
                    if li.pop(key, None) is not None:
                        _LOGGER.warning(
                            "cleared the cached MQTT password after the broker "
                            "rejected it (rc=%s); it will be re-fetched", rc,
                        )
                self._smarthome_auth = None
                # The URL response is the one that can carry a server-issued
                # password (strategy 3); leaving it cached would skip that
                # fallback entirely on the recovery path.
                self._mqtt_url = None
                # Note the refusal so a second failure in quick succession backs
                # off instead of hammering the credential endpoint.
                self._mqtt_refused_at = _loop.time()
                # This one DOES need the lock: it is a compare-and-pop against the
                # get-or-create above, and without it a rebuild that already read
                # the slot could have its replacement removed instead of ours.
                async with lock:
                    if li.get(LOGIN_INFO_PERSISTENT_MQTT_KEY) is pm:
                        li.pop(LOGIN_INFO_PERSISTENT_MQTT_KEY, None)
                # Outside the lock: retire() blocks briefly joining paho's thread.
                await _loop.run_in_executor(None, pm.retire)

            pm = _PersistentMqtt(mqtt_url, mqtt_user, mqtt_pwd, client_id,
                                 on_auth_failure=_invalidate_mqtt_credentials)
            li[LOGIN_INFO_PERSISTENT_MQTT_KEY] = pm
            return pm

    @staticmethod
    def _adaptive_next_fast(adaptive: bool, fast_failed: bool) -> bool:
        """Whether the next SDES open attempt should use the fast path: only when
        adaptive mode is on and the fast path has not already failed this loop."""
        return bool(adaptive) and not bool(fast_failed)

    def _next_not_ready_burst(self, healthy: bool, burst: int) -> int:
        """Updated wake-readiness burst counter after a session ended.

        Counts up only while a BATTERY camera keeps answering ``-50019`` and then
        delivering no media; any other outcome resets it to 0.  Scoped to battery
        cameras because they are the only ones with a wake-readiness state - on a
        mains camera ``-50019`` is transient noise and the pacer's judgement
        (something is degraded) is the right one.
        """
        if healthy or not self.is_battery_camera:
            return 0
        return burst + 1 if self._live_play_not_ready() else 0

    @staticmethod
    def _not_ready_retry_delay(burst: int, *,
                               burst_max: int = 3) -> "tuple[float, bool]":
        """``(delay, is_fast_retry)`` for a wake-readiness retry.

        Shares [[_retry_policy]] with the DTLS serve loop so both paths agree on
        what "the camera is still warming up" is worth waiting.  Returns
        ``(0.0, False)`` when the counter is 0 (not a wake-readiness failure) and
        ``(_, False)`` once the burst is spent, in both cases handing the decision
        back to the caller's normal pacer.
        """
        if burst <= 0:
            return (0.0, False)
        delay, fast = _retry_policy("not_ready", burst, burst_max=burst_max)
        return (delay, bool(fast))

    @staticmethod
    def _adaptive_after_attempt(use_fast: bool, healthy: bool, fast_failed: bool) -> bool:
        """Updated ``fast_failed`` after an attempt: latch it once a fast attempt
        delivers no media, so the loop stays on the full relay path (no
        oscillation) until it restarts fresh on the next view."""
        return bool(fast_failed) or (bool(use_fast) and not bool(healthy))

    def _maybe_start_serve_relay(self, serve_url: Optional[str]) -> "Optional[_ServeRelay]":
        """Hold the public serve port via a _ServeRelay so an eager go2rtc pull
        connects-and-waits instead of hitting ECONNREFUSED during the ~16-25s
        cold handshake (ffmpeg only binds its -listen socket after input frames).

        Returns the started relay, or None when disabled / not an http serve /
        the bind fails - in which case the caller serves ffmpeg directly on the
        public port (the pre-relay behaviour, so a bind clash never breaks
        streaming)."""
        if not (serve_url and serve_url.startswith("http")):
            return None
        opt = getattr(self, "_serve_relay_opt", None)
        if opt is None:
            opt = os.environ.get("AIDOT_SERVE_RELAY", "1") != "0"
        if not opt:
            return None
        port = _sdes_serve_port(serve_url)
        if port is None:
            return None
        relay = _ServeRelay(port)
        try:
            relay.start()
        except OSError as exc:
            _LOGGER.warning(
                "serve relay: bind :%s failed (%s) - serving ffmpeg directly",
                port, exc,
            )
            return None
        _LOGGER.debug(
            "serve relay: holding public port :%s for %s", port, self.device_id)
        return relay

    async def _dtls_serve_loop(self) -> None:
        """Acquire a concurrent-stream slot, then run the serve loop.

        Caps how many cameras stream at once (AIDOT_MAX_CONCURRENT_STREAMS) so a
        small host isn't overwhelmed by N decodes + mux threads at once.  Holds
        the slot for the serve's lifetime; waits for one if the cap is reached.
        """
        slots = _get_stream_slots()
        if slots.locked():
            _LOGGER.info(
                "DTLS serve: %s waiting for a stream slot (cap reached)",
                self.device_id,
            )
        await slots.acquire()
        try:
            # Inside the try on purpose: _maybe_start_serve_relay catches OSError
            # but Thread.start() raises RuntimeError when the host is out of
            # threads, and escaping here would skip slots.release() and burn a
            # permit for the life of the process - the cap would silently shrink
            # until nothing could stream at all.
            self._serve_relay = self._maybe_start_serve_relay(
                self._keepalive_rtsp_url)
            await self._dtls_serve_loop_inner()
        finally:
            _relay = self._serve_relay
            self._serve_relay = None
            if _relay is not None:
                _relay.close()
            slots.release()

    async def _dtls_serve_loop_inner(self) -> None:
        """Serve a DTLS camera's live H.264 to go2rtc over an HTTP-listen socket.

        Powered (A000088) cameras have no local API and aiortc owns the
        DTLS/SRTP keys, so we can't point ffmpeg at the socket like the SDES
        path.  Instead aiortc does ICE/DTLS/SRTP-decrypt/depacketize and we tap
        the *encoded* H.264 frames and ``-c copy`` them to ``ffmpeg -f mpegts
        -listen 1`` - no decode, no re-encode (viable on a Raspberry Pi).  The
        WebRTC session is held warm; only the local ffmpeg serve is restarted
        when go2rtc disconnects/reconnects, so reconnects need no camera
        re-handshake.
        """
        import threading as _threading
        import queue as _queue
        serve_url = self._keepalive_rtsp_url
        # APK parity: the official app gates re-connects to ~15 s (f0.java I1=15000)
        # and never hammers.  We previously floored at 5 s and a partial-success ->
        # reset path could drop the effective spacing even lower, pounding a flaky
        # A000088 camera fast enough to wedge its DTLS stack (ICE completes but DTLS
        # never fires until a power-cycle).  Floor the backoff at the 15 s gate and,
        # independently, enforce a hard minimum wall-clock spacing between OPEN
        # attempts so no code path (reset bug, fast PC-death) can pound the camera.
        _MIN_DELAY, _MAX_DELAY = 15.0, 300.0
        _open_gate = float(os.environ.get("AIDOT_DTLS_RETRY_GATE_S", "15"))
        # Jittered-backoff pacer for failed opens. Unlike the SDES/JPEG loops this
        # serve loop resets on any successful open (it has the _open_gate spacing
        # below) rather than escalating on no-media - hence reset() not
        # session_end_delay().
        _pacer = ReconnectPacer(_MIN_DELAY, _MAX_DELAY)
        _last_open_at = 0.0  # monotonic of the previous open attempt (0 = none yet)
        _not_ready_burst = 0  # consecutive DC-only (encoder-cold) declines
        loop = asyncio.get_running_loop()
        while self._streaming_active:
            # Thread-safe queues: taps run on the loop, the A/V mux in a thread.
            vq: "_queue.Queue" = _queue.Queue(maxsize=600)
            aq: "_queue.Queue" = _queue.Queue(maxsize=600)
            self._serve_ready.clear()  # fresh (cold) session: not ready until bound
            # Hard inter-attempt gate (APK parity): never start an open within
            # _open_gate seconds of the previous one, regardless of the backoff.
            # This is the SOLE reconnect-spacing mechanism (no separate post-death
            # sleep) - after a healthy session it has long elapsed, so a clean
            # death reopens immediately; a fast death still owes the full gate.
            _gate_wait = _open_gate_delay(_last_open_at, loop.time(), _open_gate)
            if _gate_wait:
                try:
                    await asyncio.sleep(_gate_wait)
                except asyncio.CancelledError:
                    return
            _last_open_at = loop.time()
            try:
                session = await self.async_open_webrtc_stream(
                    on_frame=lambda _f: None, timeout=_DTLS_SERVE_OPEN_TIMEOUT_S,
                    _ice_wait_timeout_s=_DTLS_SERVE_ICE_WAIT_S,
                )
            except asyncio.CancelledError:
                return
            except AidotCameraBusy as busy:
                # Another viewer holds the camera's single slot. Retry on a short
                # interval (not the 5-min backoff) so it reconnects promptly once
                # the slot frees (e.g. the user closes the app / reboots the cam).
                busy_retry = float(os.environ.get("AIDOT_BUSY_RETRY_S", "45"))
                _LOGGER.warning(
                    "DTLS serve: camera %s busy (%s) - retrying in %.0fs",
                    self.device_id, busy, busy_retry,
                )
                try:
                    await asyncio.sleep(busy_retry)
                except asyncio.CancelledError:
                    return
                continue
            except AidotCameraNotReady:
                # Camera answered cleanly but declined media (DC-only answer):
                # its encoder is still cold and warming up.  Fast-retry in a
                # bounded burst (3s x4) that bypasses the 15s inter-attempt gate
                # so we catch the encoder the moment it comes up, then fall back
                # to the gate so a persistently-cold camera isn't hammered.  The
                # burst counter resets only on a successful open (below).
                _not_ready_burst += 1
                _delay, _bypass = _retry_policy("not_ready", _not_ready_burst)
                if _bypass:
                    _last_open_at = 0.0  # clear the gate for the fast burst
                _LOGGER.info(
                    "DTLS serve: camera %s not ready (encoder cold) -"
                    " retry %.0fs [%s]",
                    self.device_id, _delay, "burst" if _bypass else "gate",
                )
                try:
                    await asyncio.sleep(_delay)
                except asyncio.CancelledError:
                    return
                continue
            except Exception as exc:
                _delay = _pacer.fail_delay()
                _attempt = _pacer.attempt
                _cloud_offline = (
                    (not self.status.online)
                    and getattr(self, "_cloud_online_explicit", False)
                )
                # Slow-probe throttle: an idle-but-cloud-online camera never
                # sets _cloud_offline (the cloud keeps reporting it reachable),
                # so without this it would retry forever at the pacer's cap.
                # Keyed purely on the pacer's consecutive-failure count, not
                # the offline flag - a genuinely offline camera already gets a
                # comparable slow cadence (with early-resume) from
                # _backoff_or_offline_pause below, so this only engages the
                # part of the space that pause doesn't already cover.
                if _in_slow_probe(_attempt, _SLOW_PROBE_THRESHOLD) and not _cloud_offline:
                    _delay = _probe_interval(
                        _attempt, _SLOW_PROBE_THRESHOLD, _delay, _SLOW_PROBE_INTERVAL_S)
                    if _should_log_slow_probe(
                        _attempt, _SLOW_PROBE_THRESHOLD, _SLOW_PROBE_LOG_EVERY
                    ):
                        _LOGGER.info(
                            "DTLS serve: %s still failing to open after %d"
                            " attempts - slow-probing every %.0fs (last error: %s)",
                            self.device_id, _attempt, _delay, exc,
                        )
                    try:
                        await self._slow_probe_sleep(_delay)
                    except asyncio.CancelledError:
                        return
                    continue
                self._open_fail_logger()(
                    "DTLS serve: open failed for %s (retry %.0fs): %s",
                    self.device_id, _delay, exc,
                )
                try:
                    await self._backoff_or_offline_pause(_delay)
                except asyncio.CancelledError:
                    return
                continue

            # Resetting the pacer's attempt count also clears slow-probe state:
            # it derives purely from _pacer.attempt, so _in_slow_probe reads
            # false again on the very next failure sequence.
            _pacer.reset()
            _not_ready_burst = 0  # clean open: reset the encoder-cold burst
            self._stream_session = session
            pc = session._pc
            # PC-dead test for the serve loop.  closed/failed are terminal at
            # once; a transient ICE "disconnected" is debounced - aiortc reports
            # it on a brief consent/path blip that often self-recovers, so we only
            # treat a SUSTAINED disconnect as dead and force a fresh session
            # (matching the app, which reconnects on ICE FAILED/CLOSED/DISCONNECTED
            # - f0.java:2495).  Previously a stuck "disconnected" was only caught
            # ~120 s later by the idle-progress timer.
            _disc_since = [None]
            _DISC_DEBOUNCE = float(os.environ.get("AIDOT_ICE_DISCONNECT_S", "8"))

            def _pc_dead(pc=pc, _disc_since=_disc_since, _DISC_DEBOUNCE=_DISC_DEBOUNCE) -> bool:
                _st = getattr(pc, "connectionState", "closed")
                if _st in ("closed", "failed"):
                    return True
                if _st == "disconnected":
                    _t = loop.time()
                    if _disc_since[0] is None:
                        _disc_since[0] = _t
                    elif _t - _disc_since[0] >= _DISC_DEBOUNCE:
                        return True
                else:
                    _disc_since[0] = None  # connected/connecting -> reset debounce
                return False

            for _ in range(40):  # ~12s for the receiver/track(s) to exist
                if self._install_av_taps(pc, vq, aq):
                    break
                await asyncio.sleep(0.3)

            # Must exceed HA's stream-worker reconnect interval (~40s) or the serve
            # is torn down between a viewer's retries -> "Connection refused". 120s
            # survives several retries while still releasing an unviewed camera.
            # stream_idle_s / AIDOT_STREAM_IDLE_S override; <= 0 = never release
            # (keep warm for instant re-views; mains cameras only - see P1).
            idle_secs = self._resolve_idle_secs()
            if serve_url == "-":
                # Stdout mode: the parent (go2rtc) owns our lifecycle and kills
                # us when the last viewer leaves, so releasing ourselves is at
                # best redundant.  It is also unsafe here: there is no serve
                # port to ask about viewers, so _viewer_present can only answer
                # "unknown" and the pipe-staleness fallback decides.  A go2rtc
                # that pauses reading for longer than the window would push us
                # dormant while it still holds the process - a live producer
                # that has quietly stopped producing.
                idle_secs = 0.0
            proc = wfile = stop_flag = mux_thread = None
            cancelled = idle_release = False
            try:
                # (Re)start the ffmpeg serve whenever go2rtc (re)connects, while
                # the warm WebRTC session keeps delivering encoded frames.
                while self._streaming_active and not _pc_dead():
                    # Drain any backlog so a (re)connect starts on a fresh GOP.
                    for _q2 in (vq, aq):
                        try:
                            while True:
                                _q2.get_nowait()
                        except _queue.Empty:
                            pass
                    await self._send_video_pli(pc)  # request a clean keyframe
                    # With the relay holding the public port, ffmpeg listens on a
                    # fresh internal port each cycle and the relay splices to it;
                    # without it, ffmpeg owns the public port directly (old path).
                    _relay = self._serve_relay
                    if _relay is not None:
                        _ff_port = _grab_free_port()
                        _ff_url = _rewrite_serve_port(serve_url, _ff_port)
                    else:
                        _ff_port = None
                        _ff_url = serve_url
                    # Opt-in: serve the muxed TS straight to the consumer.
                    # The `-c copy` ffmpeg hop re-packetizes MPEG-TS this mux
                    # already wrote in the form go2rtc wants, and measured
                    # 2026-08-20 it is the one component that LOSES timestamps
                    # (64,981 PES leave the mux with both, 8 of ffmpeg's 12,729
                    # carry none) - which go2rtc renders as RTP timestamp 0 and
                    # HA reports as a negative DTS. See _DirectTsServer.
                    _direct = None
                    if _direct_serve_enabled():
                        # Bind the port the consumer was TOLD about. `_ff_port`
                        # is only set on the relay branch, so `_ff_port or 0`
                        # bound a random ephemeral port whenever no relay was
                        # running - go2rtc dialled the advertised port, found
                        # nothing, and answered DESCRIBE with 404 while the
                        # server itself was working.
                        _direct_port = _ff_port or _serve_port(serve_url) or 0
                        _direct = _DirectTsServer(_direct_port)
                        try:
                            _direct.start()
                        except OSError as _exc:
                            _LOGGER.warning(
                                "camera %s: direct serve could not bind (%s)"
                                " - falling back to the ffmpeg hop",
                                getattr(self, "device_id", "?"), _exc)
                            _direct = None
                    if _direct is not None:
                        proc = None
                        wfile = _direct
                        if _relay is not None:
                            _relay.set_backend(_direct.port)
                        _LOGGER.info(
                            "camera %s: serving TS directly on port %d"
                            " (no ffmpeg hop)",
                            getattr(self, "device_id", "?"), _direct.port)
                    else:
                        rfd, wfd = os.pipe()
                        proc = await self._spawn_dtls_serve_ffmpeg(_ff_url, rfd)
                        os.close(rfd)
                        if proc is None:
                            os.close(wfd)
                            break
                        if _relay is not None:
                            _relay.set_backend(_ff_port)
                        wfile = os.fdopen(wfd, "wb", buffering=0)
                    progress = [loop.time()]
                    stop_flag = _threading.Event()
                    mux_thread = _threading.Thread(
                        target=_dtls_av_mux_run,
                        args=(vq, aq, wfile, progress, stop_flag),
                        daemon=True,
                    )
                    mux_thread.start()
                    # Once the mux is feeding and ffmpeg has had a moment to bind
                    # its -listen socket, signal "serve ready" so stream_source can
                    # hand HA a working URL (no 40s connection-refused retry gap).
                    if not self._serve_ready.is_set():
                        _p0 = progress[0]
                        for _ in range(40):  # up to ~8s for the first muxed frames
                            await asyncio.sleep(0.2)
                            if progress[0] > _p0:
                                break
                        # ffmpeg binds its -listen socket at startup, so by the time
                        # the mux has written a frame (progress moved above) the
                        # socket is long bound.  A short margin is plenty; the old
                        # 2.0s blind wait was pure cold-start latency.  (Don't probe
                        # the port - `-listen 1` would consume our probe as its one
                        # client and tear down before go2rtc connects.)
                        await asyncio.sleep(0.3)
                        self._serve_ready.set()
                        self._cold_phase("serving (dtls)")
                    # Periodic keyframe request shortens the camera's GOP so HA's
                    # HLS segmenter (which cuts on keyframes) produces short
                    # segments -> far less player buffering (the ~20s HLS lag is
                    # dominated by long native GOPs).  0 disables; raising it
                    # lowers bitrate at the cost of latency.  Mains DTLS cameras
                    # only; the SDES path has its own PLI cadence.
                    _gop_pli_s = float(os.environ.get("AIDOT_GOP_PLI_S", "2.0"))
                    # Stall-triggered keyframe: if muxed frames stop for
                    # _stall_pli_s (a dropped GOP on a jittery link, e.g. a weak-
                    # RSSI camera), ask for an IDR immediately instead of waiting
                    # out the full cadence, so playback recovers sooner.  Fires
                    # at most ONCE per stall episode (re-armed only when frames
                    # resume) so a no-consumer stall - which also freezes progress
                    # - can't spam the camera with PLIs.  0 disables.
                    _stall_pli_s = float(os.environ.get("AIDOT_STALL_PLI_S", "1.0"))
                    _last_gop_pli = loop.time()
                    _stall_pli_armed = True
                    _last_viewer_dtls = loop.time()
                    _serve_port_dtls = _sdes_serve_port(serve_url) or 0
                    # Video-presence check.  The only other liveness test here is
                    # _pc_dead(), which reads the ICE/PC state - and a session
                    # receiving audio and no video passes it forever (measured
                    # 2026-08-17: hours of it, while HA retried every 10-40s).
                    _vid_grace = float(
                        os.environ.get("AIDOT_DTLS_VIDEO_GRACE_S", "30")
                    )
                    _connected_at = loop.time()
                    _first_video_at = None
                    _no_video = False
                    # Wait for ffmpeg to exit (go2rtc disconnect) or idle
                    # release. On the direct path there is no ffmpeg to exit, so
                    # the cycle runs until the peer connection dies or the view
                    # is released. `proc` is None there, and dereferencing it
                    # here threw an AttributeError the instant the mux started -
                    # which made two live trials of the direct serve look like a
                    # go2rtc DESCRIBE failure when the serve cycle had simply
                    # died on its first iteration.
                    while (self._streaming_active
                           and (proc is None or proc.returncode is None)):
                        await asyncio.sleep(0.5)
                        if _pc_dead():
                            break
                        _now = loop.time()
                        if _first_video_at is None:
                            _canary_v = _live_video_canary(
                                pc, getattr(self, "_serve_video_canary", None))
                            if _canary_v and _canary_v.get("frames", 0) > 0:
                                _first_video_at = _now
                                # Keep the one that is actually filling, so the
                                # canary log line describes the live session.
                                self._serve_video_canary = _canary_v
                        if _video_presence_verdict(
                            _first_video_at, _connected_at, _now, _vid_grace
                        ) == "give-up":
                            _no_video = True
                            self._futile_video_runs = (
                                getattr(self, "_futile_video_runs", 0) + 1
                            )
                            _LOGGER.warning(
                                "camera %s: DTLS session connected but delivered "
                                "no video in %.0fs (audio may be flowing) - "
                                "re-opening [%d consecutive]",
                                self.device_id, _vid_grace,
                                self._futile_video_runs,
                            )
                            break
                        _stall = _now - progress[0]
                        if _stall < 0.5:
                            _stall_pli_armed = True       # frames flowing; re-arm
                        if _gop_pli_s > 0 and _now - _last_gop_pli >= _gop_pli_s:
                            await self._send_video_pli(pc)
                            _last_gop_pli = _now
                        elif (_stall_pli_s > 0 and _stall_pli_armed
                              and _stall >= _stall_pli_s):
                            await self._send_video_pli(pc)
                            _last_gop_pli = _now           # also satisfies cadence
                            _stall_pli_armed = False       # one shot per stall
                        # Whether anyone is WATCHING.  Pipe-progress staleness
                        # cannot answer that: the pipe only backs up when nothing
                        # drains the serve socket, and go2rtc drains it forever as
                        # the stream's producer, viewer or not.  So progress never
                        # goes stale, the release never fires, and every DTLS
                        # camera streams for the life of the process - the same
                        # defect fixed for the SDES loop, in the other loop.
                        # Ask go2rtc, and only fall back to staleness when it
                        # cannot answer.
                        if idle_secs > 0:
                            _watching = await self._viewer_present(_serve_port_dtls)
                            if _watching:
                                _last_viewer_dtls = _now
                            elif _watching is False:
                                if _now - _last_viewer_dtls > idle_secs:
                                    idle_release = True
                            elif _now - progress[0] > idle_secs:
                                # Unknown: keep the old staleness heuristic rather
                                # than holding the stream open forever.
                                idle_release = True
                            # Only an actual idle release ends this serve cycle.
                            # (This break was unconditional - any idle_secs > 0
                            # tore down a HEALTHY ffmpeg after one 0.5s tick,
                            # respawning it forever: ffmpeg died at output-open
                            # with "Immediate exit requested" and every DTLS
                            # camera served nothing. stream_idle_s=0 masked it,
                            # which is why never-release fleets still worked.)
                            if idle_release:
                                break
                    # Tear down this ffmpeg+mux cycle before the next.
                    stop_flag.set()
                    try:
                        wfile.close()
                    except Exception:
                        _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_pc_dead', exc_info=True)
                    wfile = None
                    mux_thread.join(timeout=2.0)
                    mux_thread = stop_flag = None
                    if _relay is not None:
                        _relay.set_backend(None)  # no backend until next ffmpeg
                    _terminate_proc(proc)
                    proc = None
                    if _first_video_at is not None:
                        # A session that delivered video clears the futile run:
                        # the count is about CONSECUTIVE video-less sessions.
                        self._futile_video_runs = 0
                    if _no_video:
                        # Do not let a video-less session look like a clean open.
                        # It reached "connected", so the pacer was reset when it
                        # opened; escalate here instead, or the loop re-opens on
                        # the bare 15s gate for as long as the camera keeps
                        # answering this way (it answered the same way on every
                        # open measured 2026-08-17).  The returned delay is not
                        # slept on here - the loop's own inter-attempt gate does
                        # the spacing; what matters is the escalated attempt
                        # count it leaves behind.
                        _pacer.session_end_delay(healthy=False)
                        _limit = _futile_video_limit()
                        if _limit and self._futile_video_runs >= _limit:
                            _LOGGER.warning(
                                "camera %s: %d consecutive DTLS sessions "
                                "delivered no video - stopping the background "
                                "serve. The session connects and the camera "
                                "sends audio only; re-opening cannot fix that "
                                "and keeps the camera busy. A live view will "
                                "still open a session; set "
                                "AIDOT_DTLS_FUTILE_VIDEO_LIMIT=0 to keep "
                                "retrying.",
                                self.device_id, self._futile_video_runs,
                            )
                            # Same teardown the SDES abandon does. Leaving the
                            # keepalive marked active and the go2rtc stream
                            # registered points a viewer at a serve port with
                            # nothing listening - "connection refused" instead
                            # of a clean miss - and stops the integration's
                            # stale-stream watchdog, which keys on the
                            # keepalive having ended.
                            self._streaming_active = False
                            self._cancel_keepalive_renew()
                            try:
                                await self._deregister_go2rtc()
                            except Exception:
                                _LOGGER.debug(
                                    "camera %s: go2rtc deregister after video "
                                    "abandon failed", self.device_id,
                                    exc_info=True,
                                )
                            return
                        break
                    if idle_release:
                        break
            except asyncio.CancelledError:
                cancelled = True
            finally:
                if stop_flag is not None:
                    stop_flag.set()
                if wfile is not None:
                    try:
                        wfile.close()
                    except Exception:
                        _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_pc_dead', exc_info=True)
                if mux_thread is not None and mux_thread.is_alive():
                    # is_alive() guards the never-started case: if Thread.start()
                    # itself raised, join() raises "cannot join thread before it
                    # is started", which would replace the real exception AND skip
                    # the ffmpeg terminate plus session stop below - orphaning the
                    # process on its serve port and leaking the camera's session.
                    mux_thread.join(timeout=2.0)
                _terminate_proc(proc)  # never orphan ffmpeg on teardown
                self._stream_session = None
                try:
                    await session.stop()
                except Exception:
                    _LOGGER.debug("camera %s: swallowed exception in %s", getattr(self, "device_id", "?"), '_pc_dead', exc_info=True)

            if cancelled:
                return
            if idle_release:
                # No viewer - go dormant; camera.stream_source() restarts us when
                # someone opens the live view again.
                self._streaming_active = False
                self._cancel_keepalive_renew()
                self._keepalive_rtsp_url = None
                self._serve_ready.clear()
                # Same as the SDES path: do not leave go2rtc holding a stream
                # whose source no longer exists.
                try:
                    await self._deregister_go2rtc()
                except Exception:
                    _LOGGER.debug("camera %s: swallowed exception in %s",
                                  getattr(self, "device_id", "?"),
                                  "_deregister_go2rtc", exc_info=True)
                _LOGGER.debug(
                    "DTLS serve: %s idle (no viewer) - released until next view",
                    self.device_id,
                )
                return
            # No separate post-death delay: loop back to the top open-gate, which
            # spaces attempts from the previous open-start.  After a healthy
            # session the gate has elapsed (immediate reopen); a fast death still
            # owes the full gate there.  (Was a hardcoded 15s sleep that ignored
            # AIDOT_DTLS_RETRY_GATE_S and added dead latency after healthy drops.)

    async def _spawn_dtls_serve_ffmpeg(self, serve_url: Optional[str], stdin_fd: int):
        """Launch ffmpeg to serve the mux thread's MPEG-TS (read from ``stdin_fd``).

        The stream is already cleanly timestamped + AAC-muxed (with the
        gain/limiter applied) by PyAV, so ffmpeg just copies and serves -
        re-encoding here dropped the live audio (mpegts PMT-timing on the
        real-time pipe).  Returns the process, or None.

        Three destinations:

        - ``serve_url == "-"`` -> STDOUT model: write MPEG-TS to this process's
          own stdout (``pipe:1``), so a parent that spawned us - go2rtc's
          ``exec:`` source - consumes the camera directly and owns the process
          lifecycle (spawn on first viewer, kill on idle).  No listen port and
          no cold-start relay, which is the DTLS analogue of the SDES
          ``{output}`` RTSP push.  Logging already goes to stderr, so stdout
          carries nothing but media.
        - ``rtsp://`` -> PUSH model: publish to an RTSP server the caller
          already runs, the same shape the SDES path has always had.  This is
          not a protocol difference finally overcome - the media reaching this
          point is identical whichever transport decrypted it, and the only
          reason DTLS had no push was that nobody wired the destination.  TCP
          interleave, because a UDP publish of a 720p keyframe fragments and
          the first loss takes the GOP with it.
        - anything else -> HTTP-listen model, unchanged: serve on a ``-listen``
          socket that go2rtc pulls.
        """
        if not serve_url:
            return None
        if _ffmpeg_path() is None:
            _LOGGER.error("DTLS serve: %s", _FFMPEG_MISSING_MSG)
            return None
        codec_args = ["-c", "copy"]
        if serve_url == "-":
            out_args = ["-f", "mpegts", "pipe:1"]
            out_target = 1               # this process's real stdout
        elif serve_url.startswith("rtsp"):
            # Audio cannot be copied here, and that is not a preference.  The
            # mux upstream writes AAC into MPEG-TS, which carries it as ADTS
            # with no global headers; ffmpeg's RTSP muxer refuses that outright
            # - "AAC with no global headers is currently not supported" at
            # header-write, so the publish never starts and video dies with it.
            # `-bsf:a aac_adtstoasc` does not save it: the header is written
            # before the filter has produced extradata.  So transcode to G.711
            # A-law, which is RTP-native, costs almost nothing at 8 kHz mono,
            # and was what the SDES push carried until that path moved to AAC
            # (fMP4/MSE has no G.711 mapping, so browsers got silence there).
            codec_args = ["-c:v", "copy", "-c:a", "pcm_alaw", "-ar", "8000", "-ac", "1"]
            out_args = ["-f", "rtsp", "-rtsp_transport", "tcp", serve_url]
            out_target = asyncio.subprocess.DEVNULL
        else:
            out_args = ["-f", "mpegts", "-listen", "1", serve_url]
            out_target = asyncio.subprocess.DEVNULL
        cmd = [
            "ffmpeg", "-y", "-loglevel", "warning",
            # Suppress input-side buffering: the PyAV mux already writes
            # correctly-interleaved, timestamped MPEG-TS to the pipe every
            # ~20ms.  Without +nobuffer ffmpeg's mpegts demuxer accumulates a
            # read-ahead window (and the output mpegts muxer defaults to 700ms
            # of A/V interleave delay) before flushing to go2rtc - exactly the
            # bursty/choppy audio pattern.  Matches the SDES serve's approach.
            "-fflags", "+nobuffer",
            "-i", "pipe:0",
            *codec_args, *out_args,
        ]
        try:
            return await asyncio.create_subprocess_exec(
                *cmd,
                stdin=stdin_fd,
                stdout=out_target,
                stderr=asyncio.subprocess.DEVNULL,
            )
        except FileNotFoundError:
            _LOGGER.error("DTLS serve: ffmpeg not found")
            return None
        except Exception as exc:
            _LOGGER.warning("DTLS serve: ffmpeg launch failed: %s", exc)
            return None

    # -- PTZ physical pan/tilt (A001064) ----------------------------------- #
    # Uses IOCtrl cmd=4097 (IOTYPE_USER_IPCAM_PTZ_COMMAND) - NOT MQTT.
    # DTLS path: sent via WebRTC DataChannel. SDES path: sent via encrypted
    # SCTP cmd_chan. Requires an active stream session (_stream_session).




    async def async_open_cloud_playback(
        self,
        start_ts: int,
        end_ts: int,
        on_frame: Callable[[VideoFrame], None],
    ) -> Optional[CloudPlaybackSession]:
        """DEPRECATED and non-functional. Use ``async_get_event_video_media``.

        Measured 2026-08-14 on the owner account against an A001064 with ten
        cloud clips in the last seven days: step 1 (the MQTT
        ``getPlaybackServerInfoReq``) returns an empty response, so this method
        returns None before a session is ever opened.

        **RESOLVED: the cloud does not serve this request.** Proven by pairing
        it, in one session, with a request that IS answered -
        ``lowPowerActiveStateReq``, the battery wake handshake this library
        relies on in production. Same connection, same subscription, same
        client id, Home Assistant disabled so nothing competed:

            CONTROL wake answered: True    (lowPowerActiveStateResp,
                                            wakeupStatus, keepAliveState,
                                            devEventNotif x3, sleepStatus)
            playback answered:     False   (nothing, 40 s)

        Eleven messages arrived on that subscription. So the transport,
        credentials, client id and topics are all fine, and every earlier
        "zero messages" here was a genuine non-answer rather than us failing to
        listen. ``getPlaybackServerInfoReq`` is simply not served on this
        account.

        Ruled out along the way, each by measurement rather than argument: the
        suffixed-client-id defect (this method never had it), contention for
        the id (HA disabled), and the ``srcAddr`` form - all four variants
        including the terminalIndex session form drew no reply.

        There is nothing left to fix on this side. The deprecation stands, and
        removal at 1.0.0 is the right end for it.  Nothing in this library,
        its tests, its CI or the reference integration calls it, which is why
        that went unnoticed - the README named it as the retrieval path for
        cloud recordings while it did not work.

        The path that does work, and that the reference integration actually
        uses, is ``async_get_cloud_recordings`` to list plus
        ``async_get_event_video_media(event_uuid)`` for a playable HLS URL.
        This method is scheduled for removal in 1.0.0 and is kept only so an
        importer gets a warning rather than an AttributeError.
        """
        warnings.warn(
            "async_open_cloud_playback is deprecated and does not work: its "
            "MQTT handshake returns an empty response (measured 2026-08-14). "
            "Use async_get_cloud_recordings + async_get_event_video_media. "
            "It will be removed in 1.0.0.",
            DeprecationWarning,
            stacklevel=2,
        )
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
        """Open a TUTK IOTC P2P live-stream session, delivering frames to on_frame.

        **Not usable on any camera seen so far, and not for want of code.** It
        needs two things this package cannot supply: a ``p2pId`` (the TUTK UID),
        which came back None for every device on the reference account, and the
        proprietary ``libIOTCAPIs.so`` / ``libAVAPIs.so`` from the TUTK SDK,
        which are not redistributable here. See ``docs/DEFERRED_FEATURES.md``.
        Live video on every supported model goes through
        ``async_open_webrtc_stream``; this exists because the protocol was
        worked out, not because anything reaches it.
        """
        # Open a TUTK IOTC P2P live-stream session.
        # on_frame: called from the receive thread for each decoded VideoFrame.
        # Returns a running TutkStreamSession, or None on failure.
        #
        # Protocol: TUTK IOTC P2P (confirmed from classes.jar.decompiled.zip).
        #   p2pId (TUTK UID) <- POST /v21/devices/batchGetDeviceUserInfo
        #   IOTC_Connect_ByUID_Parallel(uid) -> nSID
        #   avClientStart2(nSID, "admin", "admin123") -> avIndex
        #   avSendIOCtrl(avIndex, 511, ...) -> start video stream
        #   avRecvFrameData2(avIndex, ...) -> frame loop
        #
        # Requires libIOTCAPIs.so + libAVAPIs.so from the TUTK SDK.

        uid = await self.async_get_p2p_uid()
        if not uid:
            props = getattr(self, "_raw_device", {}).get("properties") or {}
            is_webrtc = (str(props.get("enableSdes", "0")) == "1"
                         or str(props.get("liveType", "0")) == "2")
            if is_webrtc:
                _LOGGER.error(
                    "async_open_live_stream: p2pId not available for %s - "
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
        except TimeoutError:
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
        # Use the server-assigned authorised clientId - the broker rejects
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
                    if (isinstance(inner, dict) and ("app" in inner or "dev" in inner)) or (isinstance(inner, dict) and "data" not in result):
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

        Cached between cold opens until just before the server-provided ttl, so
        a re-open (after the warm-hold lapses) skips this ~2s fetch.
        """
        import aiohttp

        if self._cached_ice_config is not None and time.time() < self._ice_config_expiry:
            _LOGGER.debug(
                "async_get_ice_config_http: cached config (%.0fs left)",
                self._ice_config_expiry - time.time())
            return self._cached_ice_config

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
            f"{aidot_api_base(self._region)}"
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
                    cfg = await resp.json(content_type=None)
                    self._cache_ice_config(cfg)
                    return cfg
        except Exception as exc:
            _LOGGER.warning("async_get_ice_config_http failed: %s", exc)
            return None

    def _cache_ice_config(self, cfg: "Any") -> None:
        """Cache the ICE config until just before the soonest TURN ``ttl``.

        Each entry carries a ``ttl`` Unix epoch; cache until ``min(ttl) - 60s``,
        capped at +1h so any mid-life server-side credential rotation is still
        picked up promptly.  No usable ttl -> don't cache (fail safe to the prior
        always-fetch behaviour).  Never caches an already-expired config."""
        ttls: "list[float]" = []

        def _walk(o: "Any") -> None:
            if isinstance(o, dict):
                v = o.get("ttl")
                if isinstance(v, (int, float)) and not isinstance(v, bool) and v > 1_000_000_000:
                    ttls.append(float(v))
                for x in o.values():
                    _walk(x)
            elif isinstance(o, list):
                for x in o:
                    _walk(x)

        _walk(cfg)
        if not ttls:
            return
        now = time.time()
        expiry = min(min(ttls) - 60.0, now + 3600.0)
        if expiry <= now:
            return
        self._cached_ice_config = cfg
        self._ice_config_expiry = expiry
        _LOGGER.debug("async_get_ice_config_http: cached for %.0fs", expiry - now)

    @staticmethod
    def generate_webrtc_peer_id(
        live_type: int = 2, stream_id: int = 0, *, sdes: bool = False,
        device_id: "Optional[str]" = None
    ) -> str:
        """Generate a peerId for a WebRTC connection.

        Format observed in iOS app telemetry:
        ``{32-hex-session}_{6-hex-random}_{liveType}_{streamId}_{version}``

        The trailing digit is set per transport - ``1`` for SDES-SRTP cameras,
        ``2`` for DTLS-SRTP ones - and empirically the cameras want it that way:
        an SDES camera silently discards a webrtcReq ending ``_2``.

        The NAME is wrong and the 2025-03 telemetry reading behind it does not
        survive the decompiled app.  ``KVSWebRTCChannel`` builds this field as
        ``streamID = !isDefaultHD``, i.e. a stream index in {0, 1} derived from
        the quality setting - HD is 0, SD is 1.  It is not a transport version
        and the app can never emit a ``2`` here.  Field 3 is ``playCmd``
        (LIVE=0, SDCARD=1, PRE_LINK=2) and we send 2 = PRE_LINK for a live view;
        field 4 is a literal 0 in the app.  All three are left alone for now:
        they are demonstrably not what the camera classifies a client by (that
        is field 2's first character - see ``_expt_peer_id_fields``), and
        changing a digit the cameras currently accept, on a guess, is how the
        stream stops working.
        """
        import os
        # Field 1 is the install identity - the vendor app puts
        # DeviceIdUtils.getDeviceId(app) here and it is stable for the life of
        # the install. Field 2 is per-open random ("0" + 5 random chars in the
        # app), so it must NOT be pinned.
        session = _stable_terminal_id(width=32)
        # Field 2's first character is the client class on the A001064:
        # `parse_peer_id` (0x298ef8 in that image) does
        # `client_type = field2[0] - '0'` against
        # EN_WEBRTC_CLIENT_TYPE_{APP_ANDROID,APP_IOS,WEB,ALEXA,GOOGLE_HOME}=0..4,
        # the vendor Android app hard-codes '0' there and the vendor web app
        # sends '2'. That is all verified.
        #
        # **Pinning it to '0' breaks the A000088. Pinning it to '2' does not.**
        # The two are not interchangeable and the earlier note here said only
        # "pinning it breaks the A000088", which over-generalised one arm.
        #
        # Setting this character to '0' (APP_ANDROID) for every camera was
        # tried and reverted on 2026-08-31. Against a drained fleet with Home
        # Assistant stopped, three A000088 cameras went 0 for 3 over nine
        # attempts - each one completing its DTLS handshake in under two seconds
        # and then receiving no media at all - while the same build streamed the
        # A001064 on the first attempt. Reverting THIS LINE ALONE, with every
        # other change of that release left in place, restored 3 of 3.
        #
        # The A000088 is a different SoC (Realtek Ameba, FreeRTOS/KM4) whose
        # image has never been disassembled. A finding from the A001064's
        # firmware does not transfer to it, and this camera does not merely
        # ignore the byte - announcing APP_ANDROID makes it accept the session
        # and send nothing, which is worse than the random value it replaced.
        #
        # Class '2' (WEB) - what the vendor web app sends - was screened on
        # 2026-09-07 and does NOT break it: 6 of 6 A000088 cameras PASS across
        # two independent live-validation runs, nearly all on the first
        # attempt, against 0 of 9 attempts for class '0'. For reference the
        # random character's own baseline is 29/30 over ten runs, so the 0/9
        # was never background flakiness.
        #
        # The character nonetheless stays random by default: shipping a pinned
        # class is a behaviour change on a byte that has already caused a
        # silent whole-model outage once, and nothing currently needs it - the
        # 80.2 s cliff this was found while chasing is fixed in the SCTP
        # receiver (see `_sctp_sack_chunk`), not here. Class 2 is the arm to
        # ship if one is ever wanted; screen with `_expt_peer_id_class` (env)
        # or `_expt_peer_id_fields` (file, per device) and get evidence from
        # EACH model.
        rand6   = os.urandom(3).hex()           # 6 hex chars, fresh per open
        version = 1 if sdes else 2
        # Experiment override (off by default, fails closed, scoped to one
        # device): the camera reads its client class from field 2's first
        # character - see _expt_peer_id_fields.  Without a device id the
        # override never applies.
        # Class-only screening knob (env), applied before the file override so
        # a file naming this device still wins.
        _cls = _expt_peer_id_class()
        if _cls:
            rand6 = _cls + rand6[1:]
        _fields = _expt_peer_id_fields(device_id)
        if _fields is not None:
            _term, live_type, stream_id, version = _fields
            if _term:
                # One character pins the class and keeps the tail random; six
                # pins the whole field. Never let the id change length.
                rand6 = _term if len(_term) == 6 else _term + rand6[1:]
        return f"{session}_{rand6}_{live_type}_{stream_id}_{version}"

    async def async_open_webrtc_stream(
        self,
        on_frame: "Optional[Callable[[AvVideoFrame], None]]" = None,
        *,
        stream_id: int = 0,
        timeout: float = 30.0,
        output_path: Optional[str] = None,
        max_seconds: Optional[float] = None,
        status_callback: Optional[Callable[[str], None]] = None,
        force_sdes: Optional[bool] = None,
        rtsp_push_url: Optional[str] = None,
        talk_pcm_provider: "Optional[Callable[[], Optional[bytes]]]" = None,
        talk: bool = False,
        reuse_peer_id: Optional[str] = None,
        **kwargs: Any,
    ) -> "Union[WebRTCSession, SdesSession]":
        """Serialized entry point for opening a WebRTC stream.

        Holds the global open-gate during the handshake so concurrent camera
        opens don't drown the shared MQTT signaling channel (see
        _get_webrtc_open_gate); the gate is released as soon as the session is
        established (or fails), so established streams run concurrently.

        The parameters are spelled out rather than forwarded as ``*args,
        **kwargs`` because this package ships ``py.typed``: an untyped wrapper
        made ``help()``, IDE completion and downstream type checkers see a
        function that accepts anything. ``**kwargs`` remains only to carry the
        underscore-prefixed internals the impl accepts, which are not part of
        the public surface and are deliberately not named here.

        Returns an ``SdesSession`` on SDES cameras and a ``WebRTCSession`` on
        DTLS ones. They are not interchangeable - see docs/API-STABILITY.md for
        the four methods both are promised to have.
        """
        async with _get_webrtc_open_gate():
            return await self._async_open_webrtc_stream_impl(
                on_frame,
                stream_id=stream_id,
                timeout=timeout,
                output_path=output_path,
                max_seconds=max_seconds,
                status_callback=status_callback,
                force_sdes=force_sdes,
                rtsp_push_url=rtsp_push_url,
                talk_pcm_provider=talk_pcm_provider,
                talk=talk,
                reuse_peer_id=reuse_peer_id,
                **kwargs,
            )

    async def async_open_kvs_stream(self, *args: Any, **kwargs: Any):
        """Deprecated alias for :meth:`async_open_webrtc_stream`.

        The name predates the rename and is used by nothing in this project, in
        its tests, or in the reference integration. It was never listed in
        docs/API-STABILITY.md, so it was never promised - but it has been
        importable, so it gets a release of warning rather than vanishing.
        Scheduled for removal in 1.0.0.
        """
        warnings.warn(
            "async_open_kvs_stream is deprecated and will be removed in 1.0.0; "
            "use async_open_webrtc_stream instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return await self.async_open_webrtc_stream(*args, **kwargs)

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


